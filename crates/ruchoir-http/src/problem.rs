//! The error every Ruchoir route answers with: Problem Details (RFC 9457).
//!
//! The API style guide of `Ruchoir/.github` fixes the shape: a JSON object sent as
//! `application/problem+json`, whose `code` is stable and is what a client decides on. `title` and
//! `detail` are for whoever reads a log or a network trace; the words a person sees come from the
//! clients' dictionaries, keyed by `code` (and `reason` when there is one), never from the server.
//!
//! ```json
//! {
//!   "type": "about:blank",
//!   "title": "Forbidden",
//!   "status": 403,
//!   "code": "forbidden",
//!   "reason": "permission_not_held"
//! }
//! ```
//!
//! Like the errors of the current API, a problem never carries internals: no database error, no
//! stack, nothing a caller sent. An authorization failure is a flat `403 forbidden` that does not tell
//! "does not exist" from "not allowed to see it", so the API never confirms that a resource exists
//! to someone who cannot reach it; [`Problem::not_found`] is only for what the caller may address.

use std::borrow::Cow;
use std::fmt;

use axum::http::{header, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

/// The media type of a problem (RFC 9457, section 3).
pub const CONTENT_TYPE: &str = "application/problem+json";

/// The `type` of every problem until the API documentation has a page per error. RFC 9457 defines
/// `about:blank` as "no more than the status code says", which is what a client may assume of it.
pub const ABOUT_BLANK: &str = "about:blank";

/// The stable codes of the common problems, as the current API already sends them in its `error`
/// field. A client compares `code` against these, never `title` or `detail`.
pub mod code {
    /// `400`: the request is malformed or breaks a simple rule.
    pub const BAD_REQUEST: &str = "bad_request";
    /// `401`: no valid session or token.
    pub const UNAUTHORIZED: &str = "unauthorized";
    /// `403`: the caller may not do or see this, whether or not it exists.
    pub const FORBIDDEN: &str = "forbidden";
    /// `404`: the resource does not exist, said only to a caller allowed to know.
    pub const NOT_FOUND: &str = "not_found";
    /// `409`: the request is fine, the current state refuses it.
    pub const CONFLICT: &str = "conflict";
    /// `500`: anything unexpected on the server's side.
    pub const INTERNAL_ERROR: &str = "internal_error";
}

/// The members RFC 9457 and the style guide define, which an extension member may not replace.
const RESERVED: [&str; 7] = [
    "type", "title", "status", "code", "reason", "detail", "instance",
];

/// An error as a route answers it: RFC 9457 Problem Details, with the `code` extension of the API
/// style guide.
///
/// Build one with a constructor for the common cases ([`Problem::forbidden`],
/// [`Problem::not_found`], ...) or [`Problem::new`] for a code of the service's own, then refine it
/// with the `with_*` methods. Returning it from a handler sends it: it implements [`IntoResponse`].
///
/// It also deserializes, so a service reading another one's error gets the same type back.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Problem {
    /// A URI naming the kind of problem. Always [`ABOUT_BLANK`] for now; it will point to the error's
    /// page once the API documentation is published.
    #[serde(rename = "type", default = "about_blank")]
    type_uri: Cow<'static, str>,
    /// A short summary of the kind of problem, the same for every occurrence of it.
    title: Cow<'static, str>,
    /// The HTTP status, repeated in the body for whoever only has the body (a log, a queue).
    status: u16,
    /// The stable code a client decides on.
    code: Cow<'static, str>,
    /// Which of several rules refused the request, when there were several (`role_above_you`,
    /// `permission_not_held`), as the current API's `reason`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    reason: Option<Cow<'static, str>>,
    /// What went wrong with this occurrence, for a developer. Never built from what a caller sent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    detail: Option<Cow<'static, str>>,
    /// Further members a service adds (`retry_after`, `used_in`), at the top level of the object as
    /// RFC 9457 has them.
    #[serde(flatten)]
    extensions: Map<String, Value>,
}

fn about_blank() -> Cow<'static, str> {
    Cow::Borrowed(ABOUT_BLANK)
}

impl Problem {
    /// A problem with `status` and `code`, titled with the status's reason phrase (`Forbidden` for a
    /// `403`). RFC 9457 asks for that phrase as the title of an `about:blank` problem; a service
    /// whose code deserves its own summary sets one with [`Problem::with_title`].
    pub fn new(status: StatusCode, code: impl Into<Cow<'static, str>>) -> Self {
        Self {
            type_uri: about_blank(),
            title: Cow::Borrowed(status.canonical_reason().unwrap_or("Error")),
            status: status.as_u16(),
            code: code.into(),
            reason: None,
            detail: None,
            extensions: Map::new(),
        }
    }

    /// `400 bad_request`: the request is malformed or breaks a simple rule. Say which in
    /// [`Problem::with_detail`].
    pub fn bad_request() -> Self {
        Self::new(StatusCode::BAD_REQUEST, code::BAD_REQUEST)
    }

    /// `401 unauthorized`: no valid session or token, the same answer whatever was wrong with it.
    pub fn unauthorized() -> Self {
        Self::new(StatusCode::UNAUTHORIZED, code::UNAUTHORIZED)
    }

    /// `403 forbidden`: the caller may not do or see this. Also the answer for something that does
    /// not exist, when the caller is not allowed to know whether it does.
    pub fn forbidden() -> Self {
        Self::new(StatusCode::FORBIDDEN, code::FORBIDDEN)
    }

    /// `404 not_found`: only for a resource the caller is already allowed to address (see
    /// [`Problem::forbidden`]).
    pub fn not_found() -> Self {
        Self::new(StatusCode::NOT_FOUND, code::NOT_FOUND)
    }

    /// `409 conflict`: the request is well formed and allowed, but the current state refuses it.
    /// Nothing about the request needs fixing: something has to change first (a last owner asking to
    /// leave has to hand ownership over).
    pub fn conflict() -> Self {
        Self::new(StatusCode::CONFLICT, code::CONFLICT)
    }

    /// `500 internal_error`: anything unexpected. Log the cause where it happened; the answer never
    /// carries it.
    pub fn internal() -> Self {
        Self::new(StatusCode::INTERNAL_SERVER_ERROR, code::INTERNAL_ERROR)
    }

    /// Replace the title, for a code whose summary says more than the status phrase.
    pub fn with_title(mut self, title: impl Into<Cow<'static, str>>) -> Self {
        self.title = title.into();
        self
    }

    /// Say which rule refused the request, as a code a client can explain (`role_above_you`). The
    /// `code` does not change, so a client that does not know the reason reads the problem as before.
    pub fn with_reason(mut self, reason: impl Into<Cow<'static, str>>) -> Self {
        self.reason = Some(reason.into());
        self
    }

    /// Explain this occurrence, for a developer. Only ever text the service wrote (which file, which
    /// line of an archive), never something a caller sent.
    pub fn with_detail(mut self, detail: impl Into<Cow<'static, str>>) -> Self {
        self.detail = Some(detail.into());
        self
    }

    /// Add an extension member at the top level of the object (`retry_after`, `used_in`).
    ///
    /// The members RFC 9457 and the style guide define (`type`, `title`, `status`, `code`,
    /// `reason`, `detail`, `instance`) cannot be replaced this way: such a name is ignored, and a
    /// debug build panics, since it can only be a mistake in the service.
    pub fn with_extension(mut self, name: impl Into<String>, value: impl Into<Value>) -> Self {
        let name = name.into();
        if RESERVED.contains(&name.as_str()) {
            debug_assert!(false, "`{name}` is a reserved member of a problem");
            return self;
        }
        self.extensions.insert(name, value.into());
        self
    }

    /// The `type` member: [`ABOUT_BLANK`] for every problem this crate builds.
    pub fn type_uri(&self) -> &str {
        &self.type_uri
    }

    /// The short summary of the kind of problem.
    pub fn title(&self) -> &str {
        &self.title
    }

    /// The HTTP status. A deserialized problem whose `status` is not one answers `500`.
    pub fn status(&self) -> StatusCode {
        StatusCode::from_u16(self.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR)
    }

    /// The stable code a client decides on.
    pub fn code(&self) -> &str {
        &self.code
    }

    /// Which rule refused the request, when the service said.
    pub fn reason(&self) -> Option<&str> {
        self.reason.as_deref()
    }

    /// The explanation of this occurrence, when there is one.
    pub fn detail(&self) -> Option<&str> {
        self.detail.as_deref()
    }

    /// An extension member, by name.
    pub fn extension(&self, name: &str) -> Option<&Value> {
        self.extensions.get(name)
    }
}

impl fmt::Display for Problem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {}", self.status, self.code)?;
        if let Some(reason) = &self.reason {
            write!(f, " ({reason})")?;
        }
        Ok(())
    }
}

impl std::error::Error for Problem {}

impl IntoResponse for Problem {
    fn into_response(self) -> Response {
        let status = self.status();
        match serde_json::to_vec(&self) {
            Ok(body) => (
                status,
                [(header::CONTENT_TYPE, HeaderValue::from_static(CONTENT_TYPE))],
                body,
            )
                .into_response(),
            // Only an extension value could fail to serialize, and no `Value` does: the status alone
            // is still a truthful answer.
            Err(_) => status.into_response(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::{to_bytes, Body};
    use axum::http::Request;
    use axum::routing::get;
    use axum::Router;
    use tower::ServiceExt;

    async fn answer(problem: Problem) -> (StatusCode, Option<String>, Value) {
        let app = Router::new().route(
            "/",
            get(move || {
                let problem = problem.clone();
                async move { Err::<(), _>(problem) }
            }),
        );
        let response = app
            .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
            .await
            .unwrap();
        let status = response.status();
        let content_type = response
            .headers()
            .get(header::CONTENT_TYPE)
            .map(|v| v.to_str().unwrap().to_owned());
        let body = to_bytes(response.into_body(), 4096).await.unwrap();
        (status, content_type, serde_json::from_slice(&body).unwrap())
    }

    #[tokio::test]
    async fn a_problem_is_sent_as_problem_json() {
        let (status, content_type, body) = answer(Problem::forbidden()).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(content_type.as_deref(), Some("application/problem+json"));
        assert_eq!(
            body,
            serde_json::json!({
                "type": "about:blank",
                "title": "Forbidden",
                "status": 403,
                "code": "forbidden",
            })
        );
    }

    #[tokio::test]
    async fn reason_detail_and_extensions_are_sent_when_set() {
        let problem = Problem::forbidden()
            .with_reason("permission_not_held")
            .with_detail("files.share is not held in this space")
            .with_extension("retry_after", 3);
        let (_, _, body) = answer(problem).await;
        assert_eq!(body["code"], "forbidden");
        assert_eq!(body["reason"], "permission_not_held");
        assert_eq!(body["detail"], "files.share is not held in this space");
        assert_eq!(body["retry_after"], 3);
    }

    #[tokio::test]
    async fn the_common_constructors_keep_the_current_codes() {
        let cases = [
            (Problem::bad_request(), 400, "bad_request"),
            (Problem::unauthorized(), 401, "unauthorized"),
            (Problem::forbidden(), 403, "forbidden"),
            (Problem::not_found(), 404, "not_found"),
            (Problem::conflict(), 409, "conflict"),
            (Problem::internal(), 500, "internal_error"),
        ];
        for (problem, status, code) in cases {
            let (sent, _, body) = answer(problem).await;
            assert_eq!(sent.as_u16(), status);
            assert_eq!(body["status"], status);
            assert_eq!(body["code"], code);
            assert_eq!(body["type"], "about:blank");
        }
    }

    #[test]
    fn a_service_code_keeps_the_status_phrase_until_given_a_title() {
        let problem = Problem::new(StatusCode::PAYMENT_REQUIRED, "licence_required");
        assert_eq!(problem.title(), "Payment Required");
        let problem = problem.with_title("A licence is required");
        assert_eq!(problem.title(), "A licence is required");
        assert_eq!(problem.code(), "licence_required");
    }

    #[test]
    #[should_panic(expected = "reserved member")]
    fn an_extension_cannot_replace_a_defined_member() {
        let _ = Problem::forbidden().with_extension("code", "allowed");
    }

    #[test]
    fn a_problem_reads_back_from_another_service() {
        let sent = Problem::conflict()
            .with_reason("group_has_rules")
            .with_extension("used_in", serde_json::json!(["a channel"]));
        let read: Problem = serde_json::from_slice(&serde_json::to_vec(&sent).unwrap()).unwrap();
        assert_eq!(read, sent);
        assert_eq!(read.status(), StatusCode::CONFLICT);
        assert_eq!(read.reason(), Some("group_has_rules"));
        assert_eq!(
            read.extension("used_in"),
            Some(&serde_json::json!(["a channel"]))
        );
    }

    #[test]
    fn display_names_the_status_code_and_reason() {
        assert_eq!(Problem::forbidden().to_string(), "403 forbidden");
        assert_eq!(
            Problem::forbidden()
                .with_reason("role_above_you")
                .to_string(),
            "403 forbidden (role_above_you)"
        );
    }
}
