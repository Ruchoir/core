//! The frame the hub pushes to connected clients, and what a product hands the hub to push one.
//!
//! Every server-to-client push, whichever product it comes from, is a [`ClientFrame`]: a
//! versioned, self-describing frame a client can switch on without guessing. It is the generic form
//! of the monolith's `RealtimeEnvelope`, with two differences:
//!
//! - it lists no event types: each product keeps the constructors of its own frames, so the `type`
//!   strings stay in one place next to the payloads they describe, and the hub forwards a frame
//!   without understanding it;
//! - `scope` replaces `conversation_id`. The hub does not know what a conversation, a folder or a
//!   calendar is (ADR 0003 of `Ruchoir/.github`); a product gives an opaque scope its own clients
//!   know how to read, or none for a frame about the person as a whole (presence, preferences).
//!
//! A product hands the hub a [`Publication`]: the frame and the audience it computed. The hub never
//! decides who may see what: that stays with the product that owns the object. The audience is
//! computed once, at publish time, so delivery never asks the product again on the hot path, and it
//! is stripped before delivery: a client only ever receives the inner [`ClientFrame`]. How a
//! product reaches the hub is defined with the hub itself.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use uuid::Uuid;

/// The current frame schema version.
///
/// Bumped only on a breaking change to the shape of [`ClientFrame`] itself (not to a payload, which
/// its product versions), so that an old client can detect a frame it cannot parse and refuse it
/// instead of misreading it. A field that only adds to the frame does not bump it.
pub const FRAME_VERSION: u8 = 1;

/// A single server-to-client frame.
///
/// Serialized as `{"v":1,"type":"message.created","scope":"…","payload":{…}}`, with `scope`
/// left out when there is none.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ClientFrame {
    /// Frame schema version (see [`FRAME_VERSION`]).
    pub v: u8,
    /// The discriminator a client switches on, such as `message.created`. Chosen by the product;
    /// the hub treats it as opaque.
    #[serde(rename = "type")]
    pub frame_type: String,
    /// What the frame is about, in terms only the product and its clients understand (a
    /// conversation id, a folder id). `None` for a frame about the person as a whole.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    /// The frame body; its shape depends on `type` and is defined by the product.
    pub payload: Value,
}

impl ClientFrame {
    /// A frame of the current version without a scope, from any serializable payload.
    ///
    /// Fails only when `payload` cannot be represented as JSON (a map with non-string keys, a
    /// failing `Serialize` implementation). The monolith turned that into a `null` payload; it is
    /// returned here instead, so a bug in a payload never reaches a client as an empty frame.
    pub fn new(
        frame_type: impl Into<String>,
        payload: impl Serialize,
    ) -> Result<Self, serde_json::Error> {
        Ok(Self {
            v: FRAME_VERSION,
            frame_type: frame_type.into(),
            scope: None,
            payload: serde_json::to_value(payload)?,
        })
    }

    /// The same frame, scoped to `scope`.
    pub fn with_scope(mut self, scope: impl Into<String>) -> Self {
        self.scope = Some(scope.into());
        self
    }
}

/// What a product hands the hub: a frame, and who may receive it.
///
/// The product computes `audience` from what it knows (membership, sharing, rights) at publish
/// time; the hub delivers `frame` to the connections of those people and to no one else, and never
/// forwards `audience` itself to a client. The product-to-hub counterpart of the monolith's
/// `FanoutMessage`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Publication {
    /// The ids of the people allowed to receive `frame`, computed by the product.
    pub audience: Vec<Uuid>,
    /// The frame to deliver to each connected member of `audience`.
    pub frame: ClientFrame,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn a_scoped_frame_serializes_with_its_exact_field_names() {
        let frame = ClientFrame::new("message.created", json!({ "id": 7 }))
            .unwrap()
            .with_scope("c-42");
        assert_eq!(
            serde_json::to_string(&frame).unwrap(),
            r#"{"v":1,"type":"message.created","scope":"c-42","payload":{"id":7}}"#
        );
    }

    #[test]
    fn a_frame_without_scope_leaves_the_field_out() {
        let frame = ClientFrame::new("presence", json!({ "status": "away" })).unwrap();
        assert_eq!(frame.v, FRAME_VERSION);
        assert_eq!(
            serde_json::to_string(&frame).unwrap(),
            r#"{"v":1,"type":"presence","payload":{"status":"away"}}"#
        );
    }

    #[test]
    fn frames_round_trip_through_json_and_a_missing_scope_reads_as_none() {
        for frame in [
            ClientFrame::new("presence", json!(null)).unwrap(),
            ClientFrame::new("files.updated", json!([1, 2]))
                .unwrap()
                .with_scope("folder-1"),
        ] {
            let back: ClientFrame =
                serde_json::from_str(&serde_json::to_string(&frame).unwrap()).unwrap();
            assert_eq!(back, frame);
        }
        let read: ClientFrame =
            serde_json::from_str(r#"{"v":1,"type":"presence","payload":{}}"#).unwrap();
        assert_eq!(read.scope, None);
    }

    #[test]
    fn a_payload_that_is_not_json_is_an_error_not_a_null_frame() {
        let mut map = std::collections::BTreeMap::new();
        map.insert((1, 2), "a tuple key has no JSON form");
        assert!(ClientFrame::new("broken.payload", map).is_err());
    }

    #[test]
    fn a_publication_serializes_with_its_exact_field_names_and_round_trips() {
        let person = Uuid::parse_str("3f2504e0-4f89-41d3-9a0c-0305e82c3301").unwrap();
        let publication = Publication {
            audience: vec![person],
            frame: ClientFrame::new("message.created", json!({}))
                .unwrap()
                .with_scope("c-1"),
        };
        let text = serde_json::to_string(&publication).unwrap();
        assert_eq!(
            text,
            concat!(
                r#"{"audience":["3f2504e0-4f89-41d3-9a0c-0305e82c3301"],"#,
                r#""frame":{"v":1,"type":"message.created","scope":"c-1","payload":{}}}"#
            )
        );
        assert_eq!(
            serde_json::from_str::<Publication>(&text).unwrap(),
            publication
        );
    }
}
