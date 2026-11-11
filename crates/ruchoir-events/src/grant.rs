//! A product's short grant over a file another product keeps for it (the drive's design for the
//! files of other applications).
//!
//! The chat keeps its attachments in the drive, but only the chat knows who may read one. Rather
//! than the drive asking the chat at every download, the chat hands the person a grant: a small
//! JSON document saying who may do what with which file, until when, signed with the chat's event
//! key. The drive checks it against the event keys Propolis publishes, and asks nobody.
//!
//! # The compact form
//!
//! ```text
//! <key id>.<base64url of the JSON bytes>.<base64url of the Ed25519 signature of those bytes>
//! ```
//!
//! The signature covers the exact bytes carried, as for events ([`crate::signature`]): nothing is
//! re-serialised to verify, and the JSON is parsed only once the bytes are known to come from the
//! key's owner. Base64url without padding, so the grant fits in a header or a query string.
//!
//! # What is checked
//!
//! [`verify`] checks the signature against a trusted key, that the key's owner is the grant's
//! issuer (`iss`), that the grant is for `audience`, and that it has not expired. What the grant
//! allows (the action, the file, the person) is the verifier's to compare with the request.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use serde::{Deserialize, Serialize};

use crate::signature::{self, PublicKeys, SignatureHeader, SigningKey};

/// The longest a grant may live, in seconds.
pub const MAX_LIFETIME_SECS: u64 = 5 * 60;

/// What a grant allows.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Grant {
    /// The product that grants (`chat`), the owner of the signing key.
    pub iss: String,
    /// The product the grant is for (`drive`).
    pub aud: String,
    /// The person it is for: their account id.
    pub sub: String,
    /// What they may do: `read`, `upload`.
    pub act: String,
    /// The file, when the grant is about one (none for an upload).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub file: Option<String>,
    /// The organisation the file belongs to.
    pub org: String,
    /// The issuer's own reference for the object the file belongs to (a conversation), opaque to
    /// the verifier.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub r#ref: Option<String>,
    /// When it ends, in Unix seconds.
    pub exp: u64,
}

/// Why a grant is refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GrantError {
    /// Not three parts, or not base64url, or not a grant.
    Malformed,
    /// No trusted key under its id.
    UnknownKey,
    /// The signature does not match.
    BadSignature,
    /// The key's owner is not the grant's issuer.
    WrongIssuer,
    /// Meant for another product.
    WrongAudience,
    /// Past its end, or meant to live longer than [`MAX_LIFETIME_SECS`].
    Expired,
}

impl std::fmt::Display for GrantError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            GrantError::Malformed => "malformed grant",
            GrantError::UnknownKey => "unknown key",
            GrantError::BadSignature => "bad signature",
            GrantError::WrongIssuer => "the key is not the issuer's",
            GrantError::WrongAudience => "meant for another product",
            GrantError::Expired => "expired",
        })
    }
}

impl std::error::Error for GrantError {}

/// Sign `grant` with `key`, the issuer's event key: the compact form.
pub fn sign(grant: &Grant, key: &SigningKey) -> Result<String, serde_json::Error> {
    let bytes = serde_json::to_vec(grant)?;
    let header = signature::sign(&bytes, key);
    Ok(format!(
        "{}.{}.{}",
        key.key_id(),
        URL_SAFE_NO_PAD.encode(&bytes),
        URL_SAFE_NO_PAD.encode(header.signature())
    ))
}

/// Check a compact grant for `audience`, at `now` (Unix seconds), against `keys`.
pub fn verify(
    compact: &str,
    keys: &PublicKeys,
    audience: &str,
    now: u64,
) -> Result<Grant, GrantError> {
    let mut parts = compact.split('.');
    let (Some(key_id), Some(body), Some(sig), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(GrantError::Malformed);
    };
    let bytes = URL_SAFE_NO_PAD
        .decode(body)
        .map_err(|_| GrantError::Malformed)?;
    let header = SignatureHeader::parse(&format!("keyid={key_id}, sig={sig}"))
        .map_err(|_| GrantError::Malformed)?;
    let owner = signature::verify(&bytes, &header, keys).map_err(|error| match error {
        signature::VerifyError::UnknownKey(_) => GrantError::UnknownKey,
        _ => GrantError::BadSignature,
    })?;
    // Parsed only once the bytes are known to be the owner's.
    let grant: Grant = serde_json::from_slice(&bytes).map_err(|_| GrantError::Malformed)?;
    if grant.iss != owner {
        return Err(GrantError::WrongIssuer);
    }
    if grant.aud != audience {
        return Err(GrantError::WrongAudience);
    }
    if grant.exp <= now || grant.exp > now + MAX_LIFETIME_SECS {
        return Err(GrantError::Expired);
    }
    Ok(grant)
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: u64 = 1_800_000_000;

    fn setup() -> (SigningKey, PublicKeys) {
        let (key, _) = SigningKey::generate("chat-events-1").unwrap();
        let mut keys = PublicKeys::new();
        keys.insert("chat-events-1", "chat", key.public_key())
            .unwrap();
        (key, keys)
    }

    fn grant() -> Grant {
        Grant {
            iss: "chat".into(),
            aud: "drive".into(),
            sub: "a1".into(),
            act: "read".into(),
            file: Some("f1".into()),
            org: "o1".into(),
            r#ref: Some("conversation:c1".into()),
            exp: NOW + 60,
        }
    }

    #[test]
    fn a_grant_reads_back_as_it_was_signed() {
        let (key, keys) = setup();
        let compact = sign(&grant(), &key).unwrap();
        assert!(compact.starts_with("chat-events-1."));
        assert_eq!(verify(&compact, &keys, "drive", NOW).unwrap(), grant());
    }

    #[test]
    fn a_changed_or_misdirected_grant_is_refused() {
        let (key, keys) = setup();
        let compact = sign(&grant(), &key).unwrap();
        // Another file, same signature.
        let mut forged = grant();
        forged.file = Some("f2".into());
        let parts: Vec<&str> = compact.split('.').collect();
        let swapped = format!(
            "{}.{}.{}",
            parts[0],
            URL_SAFE_NO_PAD.encode(serde_json::to_vec(&forged).unwrap()),
            parts[2]
        );
        assert_eq!(
            verify(&swapped, &keys, "drive", NOW),
            Err(GrantError::BadSignature)
        );
        assert_eq!(
            verify(&compact, &keys, "calendar", NOW),
            Err(GrantError::WrongAudience)
        );
        assert_eq!(
            verify(&compact, &keys, "drive", NOW + 61),
            Err(GrantError::Expired)
        );
        assert_eq!(
            verify("a.b", &keys, "drive", NOW),
            Err(GrantError::Malformed)
        );
        assert_eq!(
            verify(&compact, &PublicKeys::new(), "drive", NOW),
            Err(GrantError::UnknownKey)
        );
    }

    #[test]
    fn a_product_cannot_grant_in_another_ones_name() {
        let (key, keys) = setup();
        let mut calendar = grant();
        calendar.iss = "calendar".into();
        let compact = sign(&calendar, &key).unwrap();
        assert_eq!(
            verify(&compact, &keys, "drive", NOW),
            Err(GrantError::WrongIssuer)
        );
    }

    #[test]
    fn a_grant_lives_five_minutes_at_most() {
        let (key, keys) = setup();
        let mut long = grant();
        long.exp = NOW + MAX_LIFETIME_SECS + 1;
        let compact = sign(&long, &key).unwrap();
        assert_eq!(
            verify(&compact, &keys, "drive", NOW),
            Err(GrantError::Expired)
        );
    }
}
