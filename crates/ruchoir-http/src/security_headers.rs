//! The security headers every response of a Ruchoir service carries.
//!
//! The baseline is the current API's, aligned with the "self-hosted, no external origin" posture:
//!
//! - `Content-Security-Policy`: the service's own policy, given by the service because only it knows
//!   what it embeds (an office editor's frame, say). Set **only when the handler set none**: a
//!   handler that serves something with stricter needs (an inline file preview, sandboxed) sends its
//!   own and keeps it.
//! - `X-Content-Type-Options: nosniff`: a browser trusts the `Content-Type` and never guesses a
//!   script out of an upload.
//! - `Referrer-Policy: no-referrer`: no address (which can hold an id or a token) leaks to another
//!   site through a link.
//! - `Permissions-Policy: geolocation=(), camera=(), microphone=()`: no page of the service, nor
//!   anything it frames, may ask for these.
//!
//! The last three replace whatever a handler set, so no route can weaken them by mistake.
//! `Strict-Transport-Security` is not set here: TLS is terminated by the reverse proxy in front of
//! the service, which is where HSTS belongs.

use axum::http::{header, HeaderName, HeaderValue};
use tower::layer::util::Stack;
use tower::Layer;
use tower_http::set_header::SetResponseHeaderLayer;

/// `X-Content-Type-Options`.
pub const NOSNIFF: &str = "nosniff";
/// `Referrer-Policy`.
pub const REFERRER_POLICY: &str = "no-referrer";
/// `Permissions-Policy`.
pub const PERMISSIONS_POLICY: &str = "geolocation=(), camera=(), microphone=()";

type HeaderLayer = SetResponseHeaderLayer<HeaderValue>;

/// The layer [`security_headers`] returns. Apply it with `Router::layer`, around every route of the
/// service, its fallback included.
#[derive(Debug, Clone)]
pub struct SecurityHeadersLayer {
    /// The CSP innermost, so it sees what the handler set; the overriding headers around it.
    layers: Stack<HeaderLayer, Stack<HeaderLayer, Stack<HeaderLayer, HeaderLayer>>>,
}

impl<S> Layer<S> for SecurityHeadersLayer {
    type Service =
        <Stack<HeaderLayer, Stack<HeaderLayer, Stack<HeaderLayer, HeaderLayer>>> as Layer<S>>::Service;

    fn layer(&self, inner: S) -> Self::Service {
        self.layers.layer(inner)
    }
}

/// The security headers of every response, with `csp` as the content security policy when the
/// handler set none (see the module documentation for each header and why).
///
/// ```
/// use axum::http::HeaderValue;
/// use axum::{routing::get, Router};
/// use ruchoir_http::security_headers;
///
/// let csp = HeaderValue::from_static("default-src 'self'; frame-ancestors 'none'");
/// let app: Router = Router::new()
///     .route("/", get(|| async { "hello" }))
///     .layer(security_headers(csp));
/// ```
pub fn security_headers(csp: HeaderValue) -> SecurityHeadersLayer {
    let overriding = |name: HeaderName, value: &'static str| {
        SetResponseHeaderLayer::overriding(name, HeaderValue::from_static(value))
    };
    let csp = SetResponseHeaderLayer::if_not_present(header::CONTENT_SECURITY_POLICY, csp);
    let nosniff = overriding(header::X_CONTENT_TYPE_OPTIONS, NOSNIFF);
    let referrer = overriding(header::REFERRER_POLICY, REFERRER_POLICY);
    let permissions = overriding(
        HeaderName::from_static("permissions-policy"),
        PERMISSIONS_POLICY,
    );
    // `Stack::new(inner, outer)`: the first layer given is the one closest to the handler.
    SecurityHeadersLayer {
        layers: Stack::new(csp, Stack::new(nosniff, Stack::new(referrer, permissions))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::{HeaderMap, Request, StatusCode};
    use axum::response::IntoResponse;
    use axum::routing::get;
    use axum::Router;
    use tower::ServiceExt;

    const CSP: &str = "default-src 'self'";

    fn app() -> Router {
        Router::new()
            .route("/", get(|| async { "plain" }))
            .route(
                "/preview",
                get(|| async {
                    (
                        [(header::CONTENT_SECURITY_POLICY, "sandbox")],
                        "a preview with its own policy",
                    )
                }),
            )
            .route(
                "/weakened",
                get(|| async {
                    (
                        [
                            (header::X_CONTENT_TYPE_OPTIONS, "sniff-away"),
                            (header::REFERRER_POLICY, "unsafe-url"),
                        ],
                        "a handler trying to weaken the baseline",
                    )
                }),
            )
            .fallback(|| async { StatusCode::NOT_FOUND.into_response() })
            .layer(security_headers(HeaderValue::from_static(CSP)))
    }

    async fn headers(path: &str) -> HeaderMap {
        let response = app()
            .oneshot(Request::builder().uri(path).body(Body::empty()).unwrap())
            .await
            .unwrap();
        response.headers().clone()
    }

    #[tokio::test]
    async fn every_header_is_set_with_the_current_values() {
        let headers = headers("/").await;
        assert_eq!(headers[header::CONTENT_SECURITY_POLICY], CSP);
        assert_eq!(headers[header::X_CONTENT_TYPE_OPTIONS], "nosniff");
        assert_eq!(headers[header::REFERRER_POLICY], "no-referrer");
        assert_eq!(
            headers["permissions-policy"],
            "geolocation=(), camera=(), microphone=()"
        );
    }

    #[tokio::test]
    async fn a_handler_csp_is_left_as_it_is() {
        let headers = headers("/preview").await;
        assert_eq!(headers[header::CONTENT_SECURITY_POLICY], "sandbox");
        assert_eq!(
            headers
                .get_all(header::CONTENT_SECURITY_POLICY)
                .iter()
                .count(),
            1
        );
    }

    #[tokio::test]
    async fn a_handler_cannot_weaken_the_other_headers() {
        let headers = headers("/weakened").await;
        assert_eq!(headers[header::X_CONTENT_TYPE_OPTIONS], "nosniff");
        assert_eq!(headers[header::REFERRER_POLICY], "no-referrer");
    }

    #[tokio::test]
    async fn the_fallback_carries_them_too() {
        let headers = headers("/nowhere").await;
        assert_eq!(headers[header::CONTENT_SECURITY_POLICY], CSP);
        assert_eq!(headers[header::X_CONTENT_TYPE_OPTIONS], "nosniff");
    }
}
