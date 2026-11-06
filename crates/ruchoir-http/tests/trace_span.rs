//! The trace middleware runs the handler, and the layers below it, inside a span carrying the
//! trace id.
//!
//! This test installs a `tracing` subscriber, so it has a test binary of its own: `tracing` caches
//! per call site whether anything listens, and a unit test running at the same time on another
//! thread, with no subscriber, could cache "nobody" for the call sites this test relies on.

use std::fmt;
use std::sync::{Arc, Mutex};

use axum::body::Body;
use axum::http::Request;
use axum::http::{Method, StatusCode};
use axum::routing::get;
use axum::Router;
use ruchoir_http::trace::{TraceContext, TraceContextLayer, TRACEPARENT};
use ruchoir_http::SameSiteGuard;
use tower::ServiceExt;
use tracing::field::{Field, Visit};
use tracing::span::{Attributes, Id};
use tracing::{Event, Subscriber};
use tracing_subscriber::layer::{Context, SubscriberExt};
use tracing_subscriber::registry::LookupSpan;

/// The `trace_id` field of a span, kept in the span's extensions by [`Recorder`].
struct TraceIdField(String);

/// Records, for each event, the `trace_id` of the span it happened in.
#[derive(Clone, Default)]
struct Recorder(Arc<Mutex<Vec<Option<String>>>>);

struct FindTraceId(Option<String>);

impl Visit for FindTraceId {
    fn record_debug(&mut self, field: &Field, value: &dyn fmt::Debug) {
        if field.name() == "trace_id" {
            self.0 = Some(format!("{value:?}"));
        }
    }
}

impl<S> tracing_subscriber::Layer<S> for Recorder
where
    S: Subscriber + for<'a> LookupSpan<'a>,
{
    fn on_new_span(&self, attrs: &Attributes<'_>, id: &Id, ctx: Context<'_, S>) {
        let mut found = FindTraceId(None);
        attrs.record(&mut found);
        if let (Some(trace_id), Some(span)) = (found.0, ctx.span(id)) {
            span.extensions_mut().insert(TraceIdField(trace_id));
        }
    }

    fn on_event(&self, event: &Event<'_>, ctx: Context<'_, S>) {
        let trace_id = ctx.event_scope(event).and_then(|scope| {
            scope
                .from_root()
                .find_map(|span| span.extensions().get::<TraceIdField>().map(|f| f.0.clone()))
        });
        self.0.lock().unwrap().push(trace_id);
    }
}

const TRACE_ID: &str = "4bf92f3577b34da6a3ce929d0e0e4736";

/// Send a request carrying a known trace, and return what the response echoed.
async fn send(app: Router, method: Method, headers: &[(&str, &str)]) -> (StatusCode, TraceContext) {
    let mut request = Request::builder()
        .method(method)
        .uri("/")
        .header(TRACEPARENT, format!("00-{TRACE_ID}-00f067aa0ba902b7-01"));
    for (name, value) in headers {
        request = request.header(*name, *value);
    }
    let response = app
        .oneshot(request.body(Body::empty()).unwrap())
        .await
        .unwrap();
    let echoed = TraceContext::parse(response.headers()[TRACEPARENT].to_str().unwrap()).unwrap();
    (response.status(), echoed)
}

// One test only: the two checks share the subscriber (see the module documentation).
#[tokio::test]
async fn log_lines_of_a_request_carry_its_trace_id() {
    let recorder = Recorder::default();
    let subscriber = tracing_subscriber::registry().with(recorder.clone());
    let _guard = tracing::subscriber::set_default(subscriber);

    let app = Router::new()
        .route(
            "/",
            get(|| async {
                tracing::info!("handled");
            })
            .post(|| async {}),
        )
        .layer(SameSiteGuard::new("https://chat.example.org"))
        .layer(TraceContextLayer::new());

    // What the handler logs.
    let (status, echoed) = send(app.clone(), Method::GET, &[]).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(echoed.trace_id(), TRACE_ID);
    assert_eq!(
        std::mem::take(&mut *recorder.0.lock().unwrap()),
        vec![Some(TRACE_ID.to_owned())]
    );

    // What a layer below logs while refusing, before any handler runs.
    let (status, echoed) = send(app, Method::POST, &[("sec-fetch-site", "cross-site")]).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(echoed.trace_id(), TRACE_ID);
    assert_eq!(
        std::mem::take(&mut *recorder.0.lock().unwrap()),
        vec![Some(TRACE_ID.to_owned())]
    );
}
