//! Checking a back-channel logout token (OpenID Connect Back-Channel Logout 1.0; design, section
//! 6.6).
//!
//! Propolis posts one to a product's back-channel URI when a session ends: with `sid`, the product
//! ends its sessions of that Propolis session; with `sub` alone, every session of that person. The
//! token is checked like an access token, but as a logout token (`typ: logout+jwt`) for this client,
//! with the logout event, without a `nonce`, and recent. Its `jti` is returned so the product can
//! refuse to act on the same token twice; acting twice ends nothing more, so a product may also
//! simply act again.

use std::collections::HashSet;

use jwt_simple::prelude::*;
use serde_json::Value;

use crate::access::Rejected;
use crate::keys::KeySet;
use crate::SKEW_SECS;

/// The event a logout token carries.
pub const BACKCHANNEL_EVENT: &str = "http://schemas.openid.net/event/backchannel-logout";

/// How old a logout token may be: Propolis signs it right before sending, for two minutes.
pub const MAX_AGE_SECS: u64 = 120;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct LogoutClaims {
    #[serde(default)]
    sid: Option<String>,
    #[serde(default)]
    events: Value,
}

/// Who signed out, as a checked logout token says it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogoutNotice {
    /// The person, as this client knows them.
    pub sub: String,
    /// One Propolis session; `None` means every session of the person.
    pub sid: Option<String>,
    pub jti: String,
}

/// Check a logout token Propolis at `issuer` sent to `client_id`.
pub async fn verify(
    keys: &KeySet,
    issuer: &str,
    client_id: &str,
    token: &str,
) -> Result<LogoutNotice, Rejected> {
    let metadata = Token::decode_metadata(token).map_err(|_| Rejected::Malformed)?;
    let kid = metadata.key_id().ok_or(Rejected::Malformed)?;
    if metadata.algorithm() != "ES256" {
        return Err(Rejected::Invalid);
    }
    let key = keys.get(kid).await.ok_or(Rejected::UnknownKey)?;
    let options = VerificationOptions {
        allowed_issuers: Some(HashSet::from([issuer.to_owned()])),
        allowed_audiences: Some(HashSet::from([client_id.to_owned()])),
        required_signature_type: Some("logout+jwt".to_owned()),
        time_tolerance: Some(Duration::from_secs(SKEW_SECS)),
        max_validity: Some(Duration::from_secs(MAX_AGE_SECS + SKEW_SECS)),
        ..Default::default()
    };
    let claims = key
        .verify_token::<LogoutClaims>(token, Some(options))
        .map_err(|_| Rejected::Invalid)?;
    // A logout token is never an ID token (section 2.4 of the specification).
    if claims.nonce.is_some() || claims.custom.events.get(BACKCHANNEL_EVENT).is_none() {
        return Err(Rejected::Invalid);
    }
    let jti = claims.jwt_id.ok_or(Rejected::Invalid)?;
    let sub = claims.subject.ok_or(Rejected::Invalid)?;
    Ok(LogoutNotice {
        sub,
        sid: claims.custom.sid,
        jti,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const ISSUER: &str = "https://id.example.org";

    fn keyed() -> (ES256KeyPair, KeySet) {
        let key = ES256KeyPair::generate().with_key_id("k1");
        let mut jwk: Value = serde_json::from_str(&key.public_key().to_jwk()).unwrap();
        jwk["kid"] = "k1".into();
        (key, KeySet::fixed(&json!({ "keys": [jwk] })))
    }

    fn token(key: &ES256KeyPair, events: Value, typ: &str, nonce: bool) -> String {
        let custom = LogoutClaims {
            sid: Some("s1".into()),
            events,
        };
        let mut claims = Claims::with_custom_claims(custom, Duration::from_secs(120))
            .with_issuer(ISSUER)
            .with_audience("drive")
            .with_subject("person")
            .with_jwt_id("j1");
        if nonce {
            claims = claims.with_nonce("n");
        }
        let options = HeaderOptions {
            signature_type: Some(typ.to_owned()),
            ..Default::default()
        };
        key.sign_with_options(claims, &options).unwrap()
    }

    #[tokio::test]
    async fn a_logout_token_names_who_signed_out() {
        let (key, keys) = keyed();
        let event = json!({ BACKCHANNEL_EVENT: {} });
        let notice = verify(
            &keys,
            ISSUER,
            "drive",
            &token(&key, event.clone(), "logout+jwt", false),
        )
        .await
        .unwrap();
        assert_eq!(
            notice,
            LogoutNotice {
                sub: "person".into(),
                sid: Some("s1".into()),
                jti: "j1".into()
            }
        );
        for (refused, client) in [
            (token(&key, event.clone(), "logout+jwt", false), "chat"),
            (token(&key, event.clone(), "at+jwt", false), "drive"),
            (token(&key, event.clone(), "logout+jwt", true), "drive"),
            (token(&key, json!({}), "logout+jwt", false), "drive"),
        ] {
            assert_eq!(
                verify(&keys, ISSUER, client, &refused).await,
                Err(Rejected::Invalid)
            );
        }
    }
}
