//! Checking the access token a request carries (design, sections 7.1 to 7.3; RFC 9068).
//!
//! A token passes when Propolis signed it with a key it publishes, for this resource (`aud`), as an
//! access token (`typ: at+jwt`, so an ID or logout token never passes for one), and it has not
//! expired, with a minute of skew. What it carries is then the caller: a person (`auth_time` is
//! there) or a service acting in its own name (`client_credentials`: `sub` is its client id), and
//! the product that acts for the person when the token was exchanged (`act`).
//!
//! A product decides what the caller may do from its own rules and the organisation's data, never
//! from the token alone: scopes only narrow what a client may do on a person's behalf.

use std::collections::HashSet;

use jwt_simple::prelude::*;
use serde_json::Value;

use crate::keys::KeySet;
use crate::SKEW_SECS;

/// The claims of a Propolis access token beyond the registered ones.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct AccessClaims {
    pub client_id: String,
    #[serde(default)]
    pub scope: Option<String>,
    #[serde(default)]
    pub auth_time: Option<i64>,
    #[serde(default)]
    pub acr: Option<String>,
    #[serde(default)]
    pub amr: Option<Vec<String>>,
    #[serde(default)]
    pub sid: Option<String>,
    #[serde(default)]
    pub act: Option<Value>,
    #[serde(default)]
    pub instance_admin: Option<bool>,
}

/// A checked access token.
#[derive(Debug, Clone, PartialEq)]
pub struct AccessToken {
    /// The person (as this resource knows them), or the client id of a service in its own name.
    pub sub: String,
    /// The client the token was issued to.
    pub client_id: String,
    pub scopes: Vec<String>,
    /// When the person last authenticated; `None` for a service.
    pub auth_time: Option<i64>,
    pub acr: Option<String>,
    pub amr: Vec<String>,
    /// The Propolis session, for a token of an online grant.
    pub sid: Option<String>,
    /// For an exchanged token: the product acting for the person.
    pub actor: Option<String>,
    /// The person administers the instance (only in tokens for the instance's own resources).
    pub instance_admin: bool,
    pub jti: Option<String>,
    /// Expiry, in seconds since the epoch.
    pub expires_at: u64,
}

impl AccessToken {
    /// Whether a person is behind the token (rather than a service in its own name).
    pub fn is_person(&self) -> bool {
        self.auth_time.is_some()
    }

    pub fn has_scope(&self, scope: &str) -> bool {
        self.scopes.iter().any(|s| s == scope)
    }

    /// Whether the person authenticated at least as strongly as `acr` (`urn:ruchoir:acr:1` <
    /// `urn:ruchoir:acr:2` < `phr`) within `max_age` seconds of `now`, for a step-up decision (RFC
    /// 9470).
    pub fn authenticated(&self, acr: &str, max_age: Option<u64>, now: u64) -> bool {
        let rank = |value: &str| match value {
            "urn:ruchoir:acr:1" => 1,
            "urn:ruchoir:acr:2" => 2,
            "phr" => 3,
            _ => 0,
        };
        let strong = self.acr.as_deref().map(rank).unwrap_or(0) >= rank(acr).max(1);
        let recent = match (max_age, self.auth_time) {
            (None, _) => true,
            (Some(max), Some(at)) => now.saturating_sub(u64::try_from(at).unwrap_or(0)) <= max,
            (Some(_), None) => false,
        };
        strong && recent
    }
}

/// Why a token is refused. Every variant answers `401` with `error="invalid_token"` (RFC 6750); the
/// distinction is for logs, never for the caller.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Rejected {
    /// Not a JWT, or no `kid`.
    Malformed,
    /// Signed with a key Propolis does not publish.
    UnknownKey,
    /// The signature, issuer, audience, type or lifetime does not hold.
    Invalid,
}

impl Rejected {
    /// The `WWW-Authenticate` value of a refusal.
    pub fn challenge(self) -> &'static str {
        "Bearer error=\"invalid_token\""
    }
}

impl std::fmt::Display for Rejected {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Rejected::Malformed => "malformed token",
            Rejected::UnknownKey => "unknown signing key",
            Rejected::Invalid => "invalid token",
        })
    }
}

impl std::error::Error for Rejected {}

/// The `Bearer` token of an `Authorization` header value.
pub fn bearer(header: &str) -> Option<&str> {
    let (scheme, token) = header.split_once(' ')?;
    scheme
        .eq_ignore_ascii_case("bearer")
        .then(|| token.trim())
        .filter(|t| !t.is_empty())
}

/// Checks access tokens for one resource.
#[derive(Clone)]
pub struct Verifier {
    issuer: String,
    audience: String,
    keys: KeySet,
}

impl Verifier {
    /// Tokens Propolis at `issuer` issues for `audience`, this product's resource identifier.
    pub fn new(issuer: impl Into<String>, audience: impl Into<String>, keys: KeySet) -> Self {
        Self {
            issuer: issuer.into(),
            audience: audience.into(),
            keys,
        }
    }

    pub fn issuer(&self) -> &str {
        &self.issuer
    }

    pub fn keys(&self) -> &KeySet {
        &self.keys
    }

    /// Check `token`.
    pub async fn verify(&self, token: &str) -> Result<AccessToken, Rejected> {
        let metadata = Token::decode_metadata(token).map_err(|_| Rejected::Malformed)?;
        let kid = metadata.key_id().ok_or(Rejected::Malformed)?;
        // The key decides the algorithm: an ES256 key verifies ES256 only.
        if metadata.algorithm() != "ES256" {
            return Err(Rejected::Invalid);
        }
        let key = self.keys.get(kid).await.ok_or(Rejected::UnknownKey)?;
        let options = VerificationOptions {
            allowed_issuers: Some(HashSet::from([self.issuer.clone()])),
            allowed_audiences: Some(HashSet::from([self.audience.clone()])),
            required_signature_type: Some("at+jwt".to_owned()),
            time_tolerance: Some(Duration::from_secs(SKEW_SECS)),
            ..Default::default()
        };
        let claims = key
            .verify_token::<AccessClaims>(token, Some(options))
            .map_err(|_| Rejected::Invalid)?;
        let sub = claims.subject.ok_or(Rejected::Invalid)?;
        let expires_at = claims.expires_at.ok_or(Rejected::Invalid)?.as_secs();
        let custom = claims.custom;
        Ok(AccessToken {
            sub,
            client_id: custom.client_id,
            scopes: custom
                .scope
                .unwrap_or_default()
                .split_ascii_whitespace()
                .map(str::to_owned)
                .collect(),
            auth_time: custom.auth_time,
            acr: custom.acr,
            amr: custom.amr.unwrap_or_default(),
            sid: custom.sid,
            actor: custom
                .act
                .as_ref()
                .and_then(|a| a["sub"].as_str())
                .map(str::to_owned),
            instance_admin: custom.instance_admin == Some(true),
            jti: claims.jwt_id,
            expires_at,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const ISSUER: &str = "https://id.example.org";
    const DRIVE: &str = "https://drive.example.org";

    fn setup() -> (ES256KeyPair, Verifier) {
        let key = ES256KeyPair::generate().with_key_id("k1");
        let mut jwk: Value = serde_json::from_str(&key.public_key().to_jwk()).unwrap();
        jwk["kid"] = "k1".into();
        let verifier = Verifier::new(ISSUER, DRIVE, KeySet::fixed(&json!({ "keys": [jwk] })));
        (key, verifier)
    }

    fn sign(
        key: &ES256KeyPair,
        custom: AccessClaims,
        audience: &str,
        typ: &str,
        secs: u64,
    ) -> String {
        let claims = Claims::with_custom_claims(custom, Duration::from_secs(secs))
            .with_issuer(ISSUER)
            .with_audience(audience)
            .with_subject("person")
            .with_jwt_id("j1");
        let options = HeaderOptions {
            signature_type: Some(typ.to_owned()),
            ..Default::default()
        };
        key.sign_with_options(claims, &options).unwrap()
    }

    fn person() -> AccessClaims {
        AccessClaims {
            client_id: "chat".into(),
            scope: Some("drive:files.read drive:attachments.write".into()),
            auth_time: Some(1_700_000_000),
            acr: Some("urn:ruchoir:acr:2".into()),
            amr: Some(vec!["pwd".into(), "otp".into(), "mfa".into()]),
            act: Some(json!({ "sub": "chat" })),
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn a_token_for_this_resource_tells_who_calls() {
        let (key, verifier) = setup();
        let token = verifier
            .verify(&sign(&key, person(), DRIVE, "at+jwt", 300))
            .await
            .unwrap();
        assert_eq!(token.sub, "person");
        assert!(token.is_person());
        assert!(token.has_scope("drive:files.read"));
        assert_eq!(token.actor.as_deref(), Some("chat"));
        assert!(token.authenticated("urn:ruchoir:acr:2", None, 0));
        assert!(!token.authenticated("phr", None, 0));
        assert!(!token.authenticated("urn:ruchoir:acr:1", Some(600), 1_700_001_000));
    }

    #[tokio::test]
    async fn anything_else_is_refused() {
        let (key, verifier) = setup();
        let other = ES256KeyPair::generate().with_key_id("k1");
        let stranger = ES256KeyPair::generate().with_key_id("k9");
        for (token, why) in [
            (
                sign(&key, person(), "https://chat.example.org", "at+jwt", 300),
                Rejected::Invalid,
            ),
            (sign(&key, person(), DRIVE, "JWT", 300), Rejected::Invalid),
            (
                sign(&other, person(), DRIVE, "at+jwt", 300),
                Rejected::Invalid,
            ),
            (
                sign(&stranger, person(), DRIVE, "at+jwt", 300),
                Rejected::UnknownKey,
            ),
            ("not.a.token".to_owned(), Rejected::Malformed),
        ] {
            assert_eq!(verifier.verify(&token).await, Err(why));
        }
        // An HMAC token naming the published key is not checked with it.
        let hmac = HS256Key::generate().with_key_id("k1");
        let forged = hmac
            .authenticate(Claims::create(Duration::from_mins(5)))
            .unwrap();
        assert_eq!(verifier.verify(&forged).await, Err(Rejected::Invalid));
    }

    #[test]
    fn the_bearer_is_read_from_its_header() {
        assert_eq!(bearer("Bearer abc"), Some("abc"));
        assert_eq!(bearer("bearer abc"), Some("abc"));
        assert_eq!(bearer("Basic abc"), None);
        assert_eq!(bearer("Bearer "), None);
    }
}
