//! The generic HTTP layer every Ruchoir service puts in front of its routes.
//!
//! Each service answers on its own subdomain and owns its routes, but what surrounds those routes is
//! the same everywhere: how an error looks, which security headers every response carries, which
//! writes a browser may send from another site, how static files are cached, how a request is
//! followed across services, and which address a request comes from. That part lives here, so a
//! hardening made once reaches every service with the next version of this crate.
//!
//! Nothing here knows a product, a session, a store or an edition. What depends on them (the
//! session-keyed rate limit buckets, the permission checks, the edition's routes) stays in each
//! service, built on the pieces below.
//!
//! - [`Problem`]: the error every route answers with (RFC 9457 Problem Details).
//! - [`security_headers()`]: the headers set on every response (CSP, `nosniff`, referrer and
//!   permissions policies).
//! - [`SameSiteGuard`]: refuses a write a browser sent from another site, before any handler.
//! - [`cache_control`]: the caching policy of static files.
//! - [`trace`]: W3C Trace Context (`traceparent`), so a request is followed from service to service.
//! - [`client_ip`]: the client's address behind trusted reverse proxies, the key of a rate limit.
//!
//! A service usually stacks them as below. Each `layer` call wraps everything above it, so the last
//! one is the outermost:
//!
//! ```
//! use axum::http::HeaderValue;
//! use axum::routing::get;
//! use axum::Router;
//! use ruchoir_http::{security_headers, trace::TraceContextLayer, SameSiteGuard};
//!
//! let csp = HeaderValue::from_static("default-src 'self'");
//! let app: Router = Router::new()
//!     .route("/api/v1/things", get(|| async { "things" }))
//!     .layer(SameSiteGuard::new("https://chat.example.org"))
//!     .layer(security_headers(csp))
//!     .layer(TraceContextLayer::new());
//! ```
//!
//! The trace layer is outermost so that every log line of the request, the guard's refusals
//! included, carries its trace id.

pub mod cache_control;
pub mod client_ip;
pub mod origin;
pub mod problem;
pub mod same_site;
pub mod security_headers;
pub mod trace;

pub use problem::Problem;
pub use same_site::SameSiteGuard;
pub use security_headers::security_headers;
