//! A server-to-server event: what one service tells the others happened.
//!
//! An [`Event`] is an envelope around a payload the emitting product defines. The envelope says
//! enough for a consumer to route, deduplicate and order it without understanding the payload:
//!
//! - `id` is the idempotency key. Delivery is at least once, so a consumer records the ids it has
//!   handled and does nothing the second time (ADR 0006 of `Ruchoir/.github`).
//! - `kind` names what happened, as dotted lowercase segments (`drive.file.deleted`). A consumer
//!   matches on it, so it is validated on the way in as well as on the way out (see [`Kind`]).
//! - `version` is the schema version of the payload *for that kind*: a breaking change to the
//!   payload of `drive.file.deleted` bumps it, and consumers that only read version 1 can refuse a
//!   version 2 cleanly instead of misreading it. It is independent of the version of this envelope,
//!   which this crate's own version carries.
//! - `occurred_at` is when it happened according to the emitter, in RFC 3339 (UTC when built here).
//! - `source` is the emitting service's name (`drive`, `propolis`), for logs and routing. It is
//!   not a proof of origin by itself: a consumer accepts it only when it names the service that
//!   owns the signing key (see [`crate::signature`]).
//! - `organisation` is the organisation the event concerns, when there is one.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

/// The longest [`Kind`] accepted, in bytes. Generous for `product.object.verb`, and short enough that
/// a kind is never a way to smuggle a payload into logs or routing tables.
pub const MAX_KIND_LEN: usize = 128;

/// A server-to-server event around a payload of type `T`.
///
/// Serialized with its fields in declaration order, `organisation` written as `null` when absent:
///
/// ```json
/// {"id":"…","kind":"drive.file.deleted","version":1,"occurred_at":"2026-11-06T10:00:00Z",
///  "source":"drive","organisation":null,"payload":{…}}
/// ```
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Event<T> {
    /// The idempotency key: handling the same id twice must change nothing.
    pub id: Uuid,
    /// What happened, as dotted lowercase segments (`drive.file.deleted`).
    pub kind: Kind,
    /// The schema version of `payload` for this `kind`.
    pub version: u16,
    /// When it happened, according to the emitter.
    #[serde(with = "time::serde::rfc3339")]
    pub occurred_at: OffsetDateTime,
    /// The emitting service's name, for logs and routing (not a proof of origin).
    pub source: String,
    /// The organisation the event concerns, when there is one.
    pub organisation: Option<Uuid>,
    /// What the emitting product says about it; its shape is defined by `kind` and `version`.
    pub payload: T,
}

impl<T> Event<T> {
    /// A new event that happens now: a fresh random `id` and `occurred_at` set to the current UTC
    /// time. The other fields are the emitter's.
    pub fn new(
        kind: Kind,
        version: u16,
        source: impl Into<String>,
        organisation: Option<Uuid>,
        payload: T,
    ) -> Self {
        Self {
            id: Uuid::new_v4(),
            kind,
            version,
            occurred_at: OffsetDateTime::now_utc(),
            source: source.into(),
            organisation,
            payload,
        }
    }
}

/// The name of what happened: dotted lowercase segments, such as `drive.file.deleted`.
///
/// The rules, checked when a kind is built and when one is read from JSON:
///
/// - at least two segments separated by `.`: the emitting product's namespace first, then what
///   happened, so two products can never claim the same kind by accident;
/// - each segment starts with a lowercase ASCII letter, followed by lowercase ASCII letters, digits
///   or `_` (`member.role_changed`), so a kind reads the same in every log and never needs escaping;
/// - at most [`MAX_KIND_LEN`] bytes.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct Kind(String);

impl Kind {
    /// Validates `kind` against the rules above.
    pub fn new(kind: impl Into<String>) -> Result<Self, KindError> {
        let kind = kind.into();
        validate_kind(&kind)?;
        Ok(Self(kind))
    }

    /// The kind as written on the wire.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

fn validate_kind(kind: &str) -> Result<(), KindError> {
    if kind.is_empty() {
        return Err(KindError::Empty);
    }
    if kind.len() > MAX_KIND_LEN {
        return Err(KindError::TooLong);
    }
    let mut segments = 0;
    for segment in kind.split('.') {
        segments += 1;
        let mut chars = segment.chars();
        match chars.next() {
            None => return Err(KindError::EmptySegment),
            Some(first) if !first.is_ascii_lowercase() => return Err(KindError::InvalidSegment),
            Some(_) => {}
        }
        if !chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_') {
            return Err(KindError::InvalidSegment);
        }
    }
    if segments < 2 {
        return Err(KindError::TooFewSegments);
    }
    Ok(())
}

impl fmt::Display for Kind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl AsRef<str> for Kind {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl FromStr for Kind {
    type Err = KindError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::new(s)
    }
}

impl TryFrom<String> for Kind {
    type Error = KindError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl TryFrom<&str> for Kind {
    type Error = KindError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl From<Kind> for String {
    fn from(kind: Kind) -> Self {
        kind.0
    }
}

/// Why a string is not a valid [`Kind`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KindError {
    /// The kind is empty.
    Empty,
    /// The kind is longer than [`MAX_KIND_LEN`] bytes.
    TooLong,
    /// The kind has a single segment: the product namespace or what happened is missing.
    TooFewSegments,
    /// Two dots follow each other, or the kind starts or ends with one.
    EmptySegment,
    /// A segment does not start with a lowercase letter, or holds something other than lowercase
    /// letters, digits and `_`.
    InvalidSegment,
}

impl fmt::Display for KindError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Empty => "event kind is empty",
            Self::TooLong => "event kind is too long",
            Self::TooFewSegments => "event kind needs at least two dotted segments",
            Self::EmptySegment => "event kind has an empty segment",
            Self::InvalidSegment => {
                "event kind segments are lowercase letters, digits and '_', starting with a letter"
            }
        })
    }
}

impl std::error::Error for KindError {}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use time::format_description::well_known::Rfc3339;

    #[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
    struct FileDeleted {
        file_id: Uuid,
        purged: bool,
    }

    fn at(text: &str) -> OffsetDateTime {
        OffsetDateTime::parse(text, &Rfc3339).unwrap()
    }

    fn fixed_event(organisation: Option<Uuid>) -> Event<FileDeleted> {
        Event {
            id: Uuid::parse_str("0b6f3c1e-5d2a-4c8e-9f10-2a3b4c5d6e7f").unwrap(),
            kind: Kind::new("drive.file.deleted").unwrap(),
            version: 1,
            occurred_at: at("2026-11-06T10:00:00Z"),
            source: "drive".to_owned(),
            organisation,
            payload: FileDeleted {
                file_id: Uuid::parse_str("7c9e6679-7425-40de-944b-e07fc1f90ae7").unwrap(),
                purged: true,
            },
        }
    }

    #[test]
    fn an_event_serializes_with_its_exact_field_names_and_order() {
        let org = Uuid::parse_str("3f2504e0-4f89-41d3-9a0c-0305e82c3301").unwrap();
        let text = serde_json::to_string(&fixed_event(Some(org))).unwrap();
        assert_eq!(
            text,
            concat!(
                r#"{"id":"0b6f3c1e-5d2a-4c8e-9f10-2a3b4c5d6e7f","kind":"drive.file.deleted","#,
                r#""version":1,"occurred_at":"2026-11-06T10:00:00Z","source":"drive","#,
                r#""organisation":"3f2504e0-4f89-41d3-9a0c-0305e82c3301","#,
                r#""payload":{"file_id":"7c9e6679-7425-40de-944b-e07fc1f90ae7","purged":true}}"#
            )
        );
    }

    #[test]
    fn an_event_round_trips_through_json() {
        for organisation in [None, Some(Uuid::new_v4())] {
            let event = fixed_event(organisation);
            let back: Event<FileDeleted> =
                serde_json::from_slice(&serde_json::to_vec(&event).unwrap()).unwrap();
            assert_eq!(back, event);
        }
    }

    #[test]
    fn an_absent_organisation_is_written_as_null() {
        let value = serde_json::to_value(fixed_event(None)).unwrap();
        assert_eq!(value["organisation"], serde_json::Value::Null);
    }

    #[test]
    fn a_new_event_has_a_fresh_id_and_the_current_time() {
        let before = OffsetDateTime::now_utc();
        let a = Event::new(
            Kind::new("propolis.account.deleted").unwrap(),
            1,
            "propolis",
            None,
            json!({}),
        );
        let b = Event::new(a.kind.clone(), 1, "propolis", None, json!({}));
        assert_ne!(a.id, b.id);
        assert!(a.occurred_at >= before && a.occurred_at <= OffsetDateTime::now_utc());
        assert_eq!(a.occurred_at.offset(), time::UtcOffset::UTC);
        assert_eq!(a.source, "propolis");
    }

    #[test]
    fn a_fractional_timestamp_round_trips() {
        let mut event = fixed_event(None);
        event.occurred_at = at("2026-11-06T10:00:00.123456789+01:00");
        let back: Event<FileDeleted> =
            serde_json::from_str(&serde_json::to_string(&event).unwrap()).unwrap();
        assert_eq!(back.occurred_at, event.occurred_at);
    }

    #[test]
    fn valid_kinds_are_accepted() {
        for kind in [
            "drive.file.deleted",
            "propolis.account.deleted",
            "chat.member.role_changed",
            "calendar.event2.created",
            "a.b",
        ] {
            assert_eq!(Kind::new(kind).unwrap().as_str(), kind, "{kind}");
        }
    }

    #[test]
    fn invalid_kinds_are_refused_with_the_reason() {
        let long = format!("drive.{}", "a".repeat(MAX_KIND_LEN));
        for (kind, reason) in [
            ("", KindError::Empty),
            (long.as_str(), KindError::TooLong),
            ("deleted", KindError::TooFewSegments),
            ("drive..deleted", KindError::EmptySegment),
            (".drive.deleted", KindError::EmptySegment),
            ("drive.deleted.", KindError::EmptySegment),
            ("Drive.file.deleted", KindError::InvalidSegment),
            ("drive.File.deleted", KindError::InvalidSegment),
            ("drive.file-deleted", KindError::InvalidSegment),
            ("drive.2file.deleted", KindError::InvalidSegment),
            ("drive._file", KindError::InvalidSegment),
            ("drive.file deleted", KindError::InvalidSegment),
            ("drive.fichier.supprimé", KindError::InvalidSegment),
        ] {
            assert_eq!(Kind::new(kind), Err(reason), "{kind:?}");
        }
    }

    #[test]
    fn an_invalid_kind_is_refused_when_read_from_json() {
        let mut value = serde_json::to_value(fixed_event(None)).unwrap();
        value["kind"] = json!("Drive.File.Deleted");
        let error = serde_json::from_value::<Event<FileDeleted>>(value).unwrap_err();
        assert!(error.to_string().contains("event kind"), "{error}");
    }
}
