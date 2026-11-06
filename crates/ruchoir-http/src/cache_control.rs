//! How the static files a service serves (its web bundle) are cached by browsers.
//!
//! Two kinds of files, two policies:
//!
//! - **Content-hashed assets** (`/_next/static/...`): the name carries a hash of the content, so a
//!   change produces a new name and the old one can be kept for ever without asking again:
//!   [`IMMUTABLE`].
//! - **Everything else**, the app shell (`index.html`) first: revalidated on every load,
//!   [`REVALIDATE`]. Without a `Cache-Control`, a browser applies heuristic caching to a page that
//!   carries only `Last-Modified`, and keeps serving it for a while without any request: a
//!   deployment then reaches nobody until their cache decides otherwise, and a fix that is live on
//!   the server is still absent from the screen of the person who reported the bug. `no-cache` is not
//!   "do not store": the copy is kept and revalidated, so an unchanged shell answers `304` and costs
//!   nothing.
//!
//! Which files are hashed is known by where the build puts them, not by guessing from a name: a
//! service mounts its hashed directory with [`layer`]`(IMMUTABLE)` and the rest with
//! [`layer`]`(REVALIDATE)`.
//!
//! ```
//! use axum::{routing::get, Router};
//! use ruchoir_http::cache_control;
//!
//! let assets: Router = Router::new()
//!     .route("/app.3f2a1c.js", get(|| async { "console.log(1)" }))
//!     .layer(cache_control::layer(cache_control::IMMUTABLE));
//! let shell: Router = Router::new()
//!     .route("/", get(|| async { "<!doctype html>" }))
//!     .layer(cache_control::layer(cache_control::REVALIDATE));
//! let app = shell.nest("/_next/static", assets);
//! ```

use axum::http::{header, HeaderValue};
use tower_http::set_header::SetResponseHeaderLayer;

/// For the app shell and every file whose name does not change with its content: keep it, but ask
/// the server whether it changed before each use.
pub const REVALIDATE: &str = "no-cache";

/// For a content-hashed asset: kept for a year (the longest value a browser honours) and never
/// revalidated, since its name changes with its content.
pub const IMMUTABLE: &str = "public, max-age=31536000, immutable";

/// A layer setting `Cache-Control` to `policy` on every response of what it wraps. It replaces a
/// value the inner service set, so a file service's own default never decides.
pub fn layer(policy: &'static str) -> SetResponseHeaderLayer<HeaderValue> {
    SetResponseHeaderLayer::overriding(header::CACHE_CONTROL, HeaderValue::from_static(policy))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    use axum::routing::get;
    use axum::Router;
    use tower::ServiceExt;

    fn app() -> Router {
        let assets = Router::new()
            .route("/app.3f2a1c.js", get(|| async { "console.log(1)" }))
            .layer(layer(IMMUTABLE));
        Router::new()
            .route("/", get(|| async { "<!doctype html>" }))
            .route(
                "/manifest.json",
                get(|| async { ([(header::CACHE_CONTROL, "max-age=600")], "{}") }),
            )
            .layer(layer(REVALIDATE))
            .nest("/_next/static", assets)
    }

    async fn cache_control(path: &str) -> String {
        let response = app()
            .oneshot(Request::builder().uri(path).body(Body::empty()).unwrap())
            .await
            .unwrap();
        response.headers()[header::CACHE_CONTROL]
            .to_str()
            .unwrap()
            .to_owned()
    }

    #[tokio::test]
    async fn the_shell_is_revalidated() {
        assert_eq!(cache_control("/").await, "no-cache");
    }

    #[tokio::test]
    async fn a_hashed_asset_is_kept_for_a_year() {
        assert_eq!(
            cache_control("/_next/static/app.3f2a1c.js").await,
            "public, max-age=31536000, immutable"
        );
    }

    #[tokio::test]
    async fn the_policy_replaces_what_the_inner_service_set() {
        assert_eq!(cache_control("/manifest.json").await, "no-cache");
    }
}
