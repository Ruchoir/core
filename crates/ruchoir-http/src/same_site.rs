//! Refuse a state-changing request that a browser sent from another site.
//!
//! A session cookie marked `SameSite=Lax` stays off cross-site writes, but not off **same-site**
//! ones, and the services of an instance all live on hostnames of one site
//! (`chat.example.org`, `drive.example.org`, `office.example.org`). Script running on any of them,
//! a flaw in an embedded engine or a crafted document, could otherwise post to another service with
//! the person's cookie. A service accepts writes from its own origin only.
//!
//! Browsers say where a request comes from in `Sec-Fetch-Site`; older ones only in `Origin`, which
//! then has to be the service's own. A client that is not a browser (a phone app, another service, a
//! script) sends neither and is unaffected; so are reads (`GET`, `HEAD`, `OPTIONS`), which change
//! nothing and which a page legitimately embeds from elsewhere.
//!
//! What is refused:
//!
//! | Method | `Sec-Fetch-Site` | `Origin` | |
//! |---|---|---|---|
//! | `GET`, `HEAD`, `OPTIONS` | any | any | allowed |
//! | any other | `same-origin` or `none` | any | allowed |
//! | any other | `same-site` or `cross-site` | any | **refused** |
//! | any other | absent | absent | allowed |
//! | any other | absent | the service's own | allowed |
//! | any other | absent | another one, or `null` | **refused** |
//!
//! A refusal is a [`Problem::forbidden`] (`403 forbidden`), logged with the method and path.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use axum::http::{header, HeaderMap, Method, Request};
use axum::response::{IntoResponse, Response};
use tower::{Layer, Service};

use crate::origin::{origin_of, public_origin};
use crate::Problem;

/// The guard, built with the service's public origin. It is a [`Layer`]: apply it with
/// `Router::layer`, around every route that may change something.
///
/// ```
/// use axum::{routing::post, Router};
/// use ruchoir_http::SameSiteGuard;
///
/// let app: Router = Router::new()
///     .route("/api/v1/things", post(|| async { "created" }))
///     .layer(SameSiteGuard::new("https://chat.example.org/"));
/// ```
#[derive(Debug, Clone)]
pub struct SameSiteGuard {
    origin: Arc<str>,
}

impl SameSiteGuard {
    /// A guard accepting writes from `public_base_url`'s origin only. Any absolute URL of the service
    /// will do (`https://chat.example.org/`): only its origin is kept, as [`public_origin`] gives it.
    pub fn new(public_base_url: &str) -> Self {
        Self {
            origin: public_origin(public_base_url).into(),
        }
    }

    /// The origin writes are accepted from.
    pub fn origin(&self) -> &str {
        &self.origin
    }

    /// Whether a request with this method and these headers may go on. The whole rule, without the
    /// HTTP plumbing (see the module documentation for the table).
    pub fn allows(&self, method: &Method, headers: &HeaderMap) -> bool {
        if matches!(*method, Method::GET | Method::HEAD | Method::OPTIONS) {
            return true;
        }
        match headers.get("sec-fetch-site").and_then(|v| v.to_str().ok()) {
            Some(site) => {
                !(site.eq_ignore_ascii_case("same-site") || site.eq_ignore_ascii_case("cross-site"))
            }
            None => headers
                .get(header::ORIGIN)
                .and_then(|v| v.to_str().ok())
                .is_none_or(|origin| origin_of(origin).as_deref() == Some(&*self.origin)),
        }
    }
}

impl<S> Layer<S> for SameSiteGuard {
    type Service = SameSiteGuardService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        SameSiteGuardService {
            guard: self.clone(),
            inner,
        }
    }
}

/// The service [`SameSiteGuard`] wraps a route in.
#[derive(Debug, Clone)]
pub struct SameSiteGuardService<S> {
    guard: SameSiteGuard,
    inner: S,
}

impl<S, B> Service<Request<B>> for SameSiteGuardService<S>
where
    S: Service<Request<B>, Response = Response>,
    S::Future: Send + 'static,
    S::Error: Send + 'static,
{
    type Response = Response;
    type Error = S::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Response, S::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: Request<B>) -> Self::Future {
        if !self.guard.allows(req.method(), req.headers()) {
            tracing::warn!(
                method = %req.method(),
                path = %req.uri().path(),
                "write from another site refused"
            );
            return Box::pin(std::future::ready(Ok(Problem::forbidden().into_response())));
        }
        Box::pin(self.inner.call(req))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::{to_bytes, Body};
    use axum::http::StatusCode;
    use axum::routing::get;
    use axum::Router;
    use tower::ServiceExt;

    const ORIGIN: &str = "https://chat.example.org";

    fn app() -> Router {
        Router::new()
            .route(
                "/things",
                get(|| async { "read" }).post(|| async { "written" }),
            )
            .layer(SameSiteGuard::new("https://chat.example.org/"))
    }

    async fn send(method: Method, headers: &[(&str, &str)]) -> StatusCode {
        let mut request = Request::builder().method(method).uri("/things");
        for (name, value) in headers {
            request = request.header(*name, *value);
        }
        app()
            .oneshot(request.body(Body::empty()).unwrap())
            .await
            .unwrap()
            .status()
    }

    #[tokio::test]
    async fn a_cross_site_write_is_refused_as_a_problem() {
        let response = app()
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/things")
                    .header("sec-fetch-site", "cross-site")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert_eq!(
            response.headers()[header::CONTENT_TYPE],
            "application/problem+json"
        );
        let body = to_bytes(response.into_body(), 4096).await.unwrap();
        let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(body["code"], "forbidden");
    }

    #[tokio::test]
    async fn a_same_site_write_is_refused() {
        // Another service of the same instance, or the office editor's hostname.
        let status = send(Method::POST, &[("sec-fetch-site", "same-site")]).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        let status = send(Method::DELETE, &[("sec-fetch-site", "Same-Site")]).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn a_same_origin_write_is_allowed() {
        let status = send(Method::POST, &[("sec-fetch-site", "same-origin")]).await;
        assert_eq!(status, StatusCode::OK);
        // Typed or bookmarked by the person: no other site involved.
        let status = send(Method::POST, &[("sec-fetch-site", "none")]).await;
        assert_eq!(status, StatusCode::OK);
    }

    #[tokio::test]
    async fn reads_are_always_allowed() {
        for site in ["cross-site", "same-site"] {
            let status = send(Method::GET, &[("sec-fetch-site", site)]).await;
            assert_eq!(status, StatusCode::OK);
        }
        let status = send(Method::GET, &[("origin", "https://elsewhere.example")]).await;
        assert_eq!(status, StatusCode::OK);
    }

    #[tokio::test]
    async fn a_client_that_is_not_a_browser_is_unaffected() {
        assert_eq!(send(Method::POST, &[]).await, StatusCode::OK);
    }

    #[tokio::test]
    async fn without_sec_fetch_site_the_origin_decides() {
        let status = send(Method::POST, &[("origin", ORIGIN)]).await;
        assert_eq!(status, StatusCode::OK);
        let status = send(Method::POST, &[("origin", "HTTPS://Chat.Example.org")]).await;
        assert_eq!(status, StatusCode::OK);
        let status = send(Method::POST, &[("origin", "https://office.example.org")]).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        // Another port is another origin.
        let status = send(Method::POST, &[("origin", "https://chat.example.org:8443")]).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        // An opaque origin (a sandboxed frame) is nobody's.
        let status = send(Method::POST, &[("origin", "null")]).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn sec_fetch_site_wins_over_origin() {
        // A browser that sends `Sec-Fetch-Site` is trusted on it, as in the current API.
        let status = send(
            Method::POST,
            &[
                ("sec-fetch-site", "same-origin"),
                ("origin", "https://elsewhere.example"),
            ],
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let status = send(
            Method::POST,
            &[("sec-fetch-site", "cross-site"), ("origin", ORIGIN)],
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
    }

    #[test]
    fn the_guard_keeps_the_origin_of_the_base_url() {
        assert_eq!(
            SameSiteGuard::new("https://Chat.Example.org/app/").origin(),
            ORIGIN
        );
    }
}
