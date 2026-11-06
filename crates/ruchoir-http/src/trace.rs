//! Following a request across services: W3C Trace Context (`traceparent`).
//!
//! A person's action often crosses several services (the chat asks Propolis who someone is, the drive
//! asks the hub to notify). When something goes wrong, the logs of each service have to be read as
//! one story. Every request therefore carries a **trace id**, shared by everything done for it, in
//! the `traceparent` header the W3C standardised (<https://www.w3.org/TR/trace-context/>):
//!
//! ```text
//! traceparent: 00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01
//!              |  |                                |                |
//!              |  trace id (16 bytes)              span id (8)      flags (sampled)
//!              version
//! ```
//!
//! [`TraceContextLayer`] reads it on the way in. A valid one keeps its trace id; an absent or invalid
//! one is replaced by a new trace. Either way the request gets a span id of its own (this service's
//! part of the work), and:
//!
//! - the handling runs inside a `tracing` span named `request` with `trace_id` and `span_id` fields
//!   (and `parent_span_id` when the caller sent one), so every log line of the request carries them;
//! - the request's [`TraceContext`] is put in its extensions, for a handler that calls another
//!   service to send on (`Extension<TraceContext>`, then [`TraceContext::to_header_value`]);
//! - the response echoes `traceparent`, so a client or a reverse proxy can log the trace id next to
//!   the error it saw.
//!
//! The parsing is written here rather than taken from OpenTelemetry: the format is a few fixed-width
//! hex fields, and the whole OpenTelemetry stack would be a large dependency for what Ruchoir needs,
//! correlating its own logs. `tracestate`, which carries the state of vendor tracing systems, is
//! neither read nor written, since none is used.
//!
//! A trace id is a correlation aid, never an authority: a client choosing its own can only mislabel
//! its own requests, and nothing decides anything on it.

use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::str::FromStr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::task::{Context, Poll};

use axum::http::{HeaderName, HeaderValue, Request, Response};
use tower::{Layer, Service};
use tracing::Instrument;

/// The name of the header, lower-case as HTTP/2 writes it.
pub const TRACEPARENT: &str = "traceparent";

/// The only version this crate writes, and the one whose format it knows exactly.
const VERSION: u8 = 0x00;

/// The `sampled` flag: the caller may have recorded what it did for this trace.
const SAMPLED: u8 = 0x01;

/// The length of a version `00` value: `vv-` + 32 + `-` + 16 + `-` + `ff`.
const LENGTH: usize = 55;

/// Where a request stands in its trace: the trace it belongs to, the span that sent it, and the
/// flags. Parsed from a `traceparent` value ([`TraceContext::parse`]) or made new
/// ([`TraceContext::generate`]); written back with its [`fmt::Display`] or
/// [`TraceContext::to_header_value`], always as version `00`.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct TraceContext {
    trace_id: [u8; 16],
    span_id: [u8; 8],
    flags: u8,
}

impl TraceContext {
    /// Read a `traceparent` value, as the W3C specification says a receiver does. `None` when it is
    /// not a valid one, whatever the reason:
    ///
    /// - fields in lower-case hex only, separated by `-`, of the fixed widths above;
    /// - version `ff` is invalid; version `00` is exactly 55 characters; a later version may be
    ///   longer, with a `-` after the four known fields, which are read the same way;
    /// - a trace id or a span id of all zeros is invalid.
    ///
    /// The flags of a version `00` value are kept as they are. Of a later version's flags, only
    /// `sampled` is kept, since what the others mean there is not known.
    pub fn parse(value: &str) -> Option<Self> {
        let value = value.trim_matches(|c| c == ' ' || c == '\t').as_bytes();
        if value.len() < LENGTH {
            return None;
        }
        let version = hex_byte(&value[0..2])?;
        if version == 0xff
            || (version == VERSION && value.len() != LENGTH)
            || (value.len() > LENGTH && value[LENGTH] != b'-')
            || value[2] != b'-'
            || value[35] != b'-'
            || value[52] != b'-'
        {
            return None;
        }
        let mut trace_id = [0u8; 16];
        let mut span_id = [0u8; 8];
        hex_into(&value[3..35], &mut trace_id)?;
        hex_into(&value[36..52], &mut span_id)?;
        let flags = hex_byte(&value[53..55])?;
        if trace_id == [0; 16] || span_id == [0; 8] {
            return None;
        }
        let flags = if version == VERSION {
            flags
        } else {
            flags & SAMPLED
        };
        Some(Self {
            trace_id,
            span_id,
            flags,
        })
    }

    /// A new trace, with a random trace id and span id and no flag set: nothing is sampled into a
    /// tracing system, the trace only ties log lines together.
    pub fn generate() -> Self {
        let mut trace_id = [0u8; 16];
        let mut span_id = [0u8; 8];
        random_nonzero(&mut trace_id);
        random_nonzero(&mut span_id);
        Self {
            trace_id,
            span_id,
            flags: 0,
        }
    }

    /// The context of a new span of the same trace, as this service's part of the work below the
    /// span that sent the request: same trace id and flags, a new random span id.
    pub fn child(&self) -> Self {
        let mut span_id = [0u8; 8];
        random_nonzero(&mut span_id);
        Self { span_id, ..*self }
    }

    /// The trace id, as 32 lower-case hex digits.
    pub fn trace_id(&self) -> String {
        hex(&self.trace_id)
    }

    /// The span id, as 16 lower-case hex digits.
    pub fn span_id(&self) -> String {
        hex(&self.span_id)
    }

    /// The trace flags byte.
    pub fn flags(&self) -> u8 {
        self.flags
    }

    /// Whether the `sampled` flag is set.
    pub fn sampled(&self) -> bool {
        self.flags & SAMPLED != 0
    }

    /// The `traceparent` value of this context, to send on to another service or back to a client.
    pub fn to_header_value(&self) -> HeaderValue {
        HeaderValue::from_str(&self.to_string()).expect("hex digits and dashes are a valid header")
    }
}

impl fmt::Display for TraceContext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{VERSION:02x}-{}-{}-{:02x}",
            self.trace_id(),
            self.span_id(),
            self.flags
        )
    }
}

impl fmt::Debug for TraceContext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "TraceContext({self})")
    }
}

/// The error of parsing an invalid `traceparent` with [`str::parse`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InvalidTraceparent;

impl fmt::Display for InvalidTraceparent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("not a valid traceparent value")
    }
}

impl std::error::Error for InvalidTraceparent {}

impl FromStr for TraceContext {
    type Err = InvalidTraceparent;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::parse(value).ok_or(InvalidTraceparent)
    }
}

/// The value of a single hex digit, lower-case only as the specification requires.
fn hex_digit(digit: u8) -> Option<u8> {
    match digit {
        b'0'..=b'9' => Some(digit - b'0'),
        b'a'..=b'f' => Some(digit - b'a' + 10),
        _ => None,
    }
}

/// Two hex digits as a byte.
fn hex_byte(pair: &[u8]) -> Option<u8> {
    Some((hex_digit(pair[0])? << 4) | hex_digit(pair[1])?)
}

/// Decode `digits` (twice as long as `out`) into `out`.
fn hex_into(digits: &[u8], out: &mut [u8]) -> Option<()> {
    for (byte, pair) in out.iter_mut().zip(digits.chunks_exact(2)) {
        *byte = hex_byte(pair)?;
    }
    Some(())
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(DIGITS[usize::from(byte >> 4)] as char);
        out.push(DIGITS[usize::from(byte & 0x0f)] as char);
    }
    out
}

/// Fill `bytes` with random bytes, never all zeros (which the specification reserves as invalid).
///
/// The bytes come from the operating system. If it cannot give any, which in practice never
/// happens, a request must not fail for its trace id: the clock and a counter stand in, unique
/// enough to tell traces apart, which is all they are for.
fn random_nonzero(bytes: &mut [u8]) {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    if getrandom::fill(bytes).is_err() {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |elapsed| elapsed.as_nanos() as u64);
        let mut state = nanos ^ COUNTER.fetch_add(1, Ordering::Relaxed).rotate_left(32);
        for chunk in bytes.chunks_mut(8) {
            // splitmix64: spreads consecutive states over the whole range.
            state = state.wrapping_add(0x9e37_79b9_7f4a_7c15);
            let mut mixed = state;
            mixed = (mixed ^ (mixed >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
            mixed = (mixed ^ (mixed >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
            mixed ^= mixed >> 31;
            chunk.copy_from_slice(&mixed.to_le_bytes()[..chunk.len()]);
        }
    }
    if bytes.iter().all(|&byte| byte == 0) {
        bytes[bytes.len() - 1] = 1;
    }
}

/// The trace context middleware (see the module documentation). Apply it with `Router::layer`,
/// outermost, so that every log line of a request, a refusal by another layer included, is inside
/// its span.
///
/// ```
/// use axum::{routing::get, Extension, Router};
/// use ruchoir_http::trace::{TraceContext, TraceContextLayer};
///
/// let app: Router = Router::new()
///     .route(
///         "/",
///         get(|Extension(trace): Extension<TraceContext>| async move {
///             // Sent on as `traceparent` to any service this handler calls.
///             trace.to_header_value();
///             "ok"
///         }),
///     )
///     .layer(TraceContextLayer::new());
/// ```
#[derive(Debug, Clone, Copy, Default)]
pub struct TraceContextLayer {
    _private: (),
}

impl TraceContextLayer {
    /// The layer. It has nothing to configure: the format is the standard's.
    pub fn new() -> Self {
        Self::default()
    }
}

impl<S> Layer<S> for TraceContextLayer {
    type Service = TraceContextService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        TraceContextService { inner }
    }
}

/// The service [`TraceContextLayer`] wraps a route in.
#[derive(Debug, Clone)]
pub struct TraceContextService<S> {
    inner: S,
}

impl<S, B, ResBody> Service<Request<B>> for TraceContextService<S>
where
    S: Service<Request<B>, Response = Response<ResBody>>,
    S::Future: Send + 'static,
    S::Error: Send + 'static,
    ResBody: Send + 'static,
{
    type Response = Response<ResBody>;
    type Error = S::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Response<ResBody>, S::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, mut req: Request<B>) -> Self::Future {
        // Exactly one valid value is trusted: several are as good as none, since there is no telling
        // which one the caller meant.
        let mut values = req.headers().get_all(TRACEPARENT).iter();
        let parent = match (values.next(), values.next()) {
            (Some(value), None) => value.to_str().ok().and_then(TraceContext::parse),
            _ => None,
        };
        let context = parent.map_or_else(TraceContext::generate, |parent| parent.child());
        let span = tracing::info_span!(
            "request",
            trace_id = %context.trace_id(),
            span_id = %context.span_id(),
            parent_span_id = tracing::field::Empty,
        );
        if let Some(parent) = parent {
            span.record("parent_span_id", tracing::field::display(parent.span_id()));
        }
        req.extensions_mut().insert(context);
        // Inside the span from the start: a service below may work, and log, in `call` itself,
        // before its future is polled. (Inside an axum router it does not, routes call lazily, but
        // the layer does not count on it.)
        let future = {
            let _entered = span.enter();
            self.inner.call(req)
        };
        let future = future.instrument(span);
        Box::pin(async move {
            let mut response = future.await?;
            response.headers_mut().insert(
                HeaderName::from_static(TRACEPARENT),
                context.to_header_value(),
            );
            Ok(response)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::{to_bytes, Body};
    use axum::routing::get;
    use axum::{Extension, Router};
    use tower::ServiceExt;

    const VALID: &str = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01";

    #[test]
    fn a_valid_value_is_read_field_by_field() {
        let context = TraceContext::parse(VALID).expect("valid");
        assert_eq!(context.trace_id(), "4bf92f3577b34da6a3ce929d0e0e4736");
        assert_eq!(context.span_id(), "00f067aa0ba902b7");
        assert!(context.sampled());
        assert_eq!(context.to_string(), VALID);
        assert_eq!(VALID.parse::<TraceContext>(), Ok(context));
    }

    #[test]
    fn invalid_values_are_refused() {
        let invalid = [
            "",
            "garbage",
            // Upper-case hex.
            "00-4BF92F3577B34DA6A3CE929D0E0E4736-00f067aa0ba902b7-01",
            // A trace id or a span id of all zeros.
            "00-00000000000000000000000000000000-00f067aa0ba902b7-01",
            "00-4bf92f3577b34da6a3ce929d0e0e4736-0000000000000000-01",
            // Version ff, and version 00 with anything after it.
            "ff-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
            "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01-extra",
            // A field too short, a wrong separator, a non-hex digit.
            "00-4bf92f3577b34da6a3ce929d0e0e473-00f067aa0ba902b7-01",
            "00_4bf92f3577b34da6a3ce929d0e0e4736_00f067aa0ba902b7_01",
            "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902bz-01",
            // A later version must separate what follows with a dash.
            "01-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01x",
        ];
        for value in invalid {
            assert_eq!(TraceContext::parse(value), None, "{value:?}");
        }
    }

    #[test]
    fn a_later_version_is_read_for_its_known_fields() {
        let context = TraceContext::parse(
            "cc-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-03-what-next",
        )
        .expect("valid");
        assert_eq!(context.trace_id(), "4bf92f3577b34da6a3ce929d0e0e4736");
        // Only `sampled` is kept, and it is written back as version 00.
        assert_eq!(context.flags(), 0x01);
        assert!(context.to_string().starts_with("00-"));
    }

    #[test]
    fn a_new_context_is_valid_and_unique() {
        let a = TraceContext::generate();
        let b = TraceContext::generate();
        assert_ne!(a.trace_id(), b.trace_id());
        assert!(!a.sampled());
        assert_eq!(TraceContext::parse(&a.to_string()), Some(a));
        let child = a.child();
        assert_eq!(child.trace_id(), a.trace_id());
        assert_ne!(child.span_id(), a.span_id());
    }

    fn app() -> Router {
        Router::new()
            .route(
                "/",
                get(|Extension(context): Extension<TraceContext>| async move {
                    context.to_string()
                }),
            )
            .layer(TraceContextLayer::new())
    }

    /// The `traceparent` of the response, and the context the handler saw.
    async fn send(traceparent: &[&str]) -> (TraceContext, String) {
        let mut request = Request::builder().uri("/");
        for value in traceparent {
            request = request.header(TRACEPARENT, *value);
        }
        let response = app()
            .oneshot(request.body(Body::empty()).unwrap())
            .await
            .unwrap();
        let echoed = response.headers()[TRACEPARENT].to_str().unwrap().to_owned();
        let seen = to_bytes(response.into_body(), 1024).await.unwrap();
        let echoed = TraceContext::parse(&echoed).expect("a valid traceparent is echoed");
        (echoed, String::from_utf8(seen.to_vec()).unwrap())
    }

    #[tokio::test]
    async fn a_valid_traceparent_keeps_its_trace() {
        let (echoed, seen) = send(&[VALID]).await;
        assert_eq!(echoed.trace_id(), "4bf92f3577b34da6a3ce929d0e0e4736");
        assert_ne!(
            echoed.span_id(),
            "00f067aa0ba902b7",
            "this service's own span"
        );
        assert!(echoed.sampled());
        assert_eq!(seen, echoed.to_string(), "the handler sees what is echoed");
    }

    #[tokio::test]
    async fn without_a_traceparent_a_new_trace_starts() {
        let (echoed, seen) = send(&[]).await;
        assert_eq!(seen, echoed.to_string());
        assert!(!echoed.sampled());
    }

    #[tokio::test]
    async fn a_malformed_traceparent_is_replaced() {
        let upper = "00-4BF92F3577B34DA6A3CE929D0E0E4736-00F067AA0BA902B7-01";
        let (echoed, _) = send(&[upper]).await;
        assert_ne!(echoed.trace_id(), "4bf92f3577b34da6a3ce929d0e0e4736");
        let (echoed, _) = send(&["not a trace"]).await;
        assert_ne!(echoed.trace_id(), "4bf92f3577b34da6a3ce929d0e0e4736");
    }

    #[tokio::test]
    async fn several_traceparents_are_as_good_as_none() {
        let other = "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01";
        let (echoed, _) = send(&[VALID, other]).await;
        assert_ne!(echoed.trace_id(), "4bf92f3577b34da6a3ce929d0e0e4736");
        assert_ne!(echoed.trace_id(), "0af7651916cd43dd8448eb211c80319c");
    }
}
