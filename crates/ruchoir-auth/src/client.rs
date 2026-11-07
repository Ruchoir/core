//! The product as Propolis's client (design, sections 6.4, 6.5 and 9.4).
//!
//! - [`Credentials`]: the product's client id and its Ed25519 key, which the installer generated
//!   and whose public half it registered with Propolis. Each request to Propolis carries a fresh
//!   `private_key_jwt` assertion: the issuer as its only audience, two minutes, a new `jti`.
//! - [`Client::client_credentials`]: a token in the product's own name, for one resource. Kept until
//!   a minute before it expires, so a product does not ask one per call.
//! - [`Client::exchange`]: a token for another product, for the person who called this one, from
//!   the access token they called with (RFC 8693). Never kept: it is for one call or a short burst.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration as StdDuration, SystemTime, UNIX_EPOCH};

use jwt_simple::prelude::*;
use serde::Deserialize;
use tokio::sync::Mutex;
use uuid::Uuid;

/// The assertion type of RFC 7523.
pub const JWT_BEARER: &str = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";
/// The token type of an access token (RFC 8693, section 3).
pub const ACCESS_TOKEN_TYPE: &str = "urn:ietf:params:oauth:token-type:access_token";
/// How long an assertion lives.
pub const ASSERTION_SECS: u64 = 120;
/// A kept token is asked again this long before it expires.
const RENEW_BEFORE: StdDuration = StdDuration::from_secs(60);

/// The product's identity at Propolis.
#[derive(Clone)]
pub struct Credentials {
    client_id: String,
    key: Arc<Ed25519KeyPair>,
}

impl std::fmt::Debug for Credentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never the key.
        f.debug_struct("Credentials")
            .field("client_id", &self.client_id)
            .finish_non_exhaustive()
    }
}

impl Credentials {
    /// The client `client_id`, signing with `key`, whose registered key id is `kid`.
    pub fn new(client_id: impl Into<String>, key: Ed25519KeyPair, kid: &str) -> Self {
        Self {
            client_id: client_id.into(),
            key: Arc::new(key.with_key_id(kid)),
        }
    }

    /// The same, from the key as the installer writes it: PEM (PKCS#8).
    pub fn from_pem(
        client_id: impl Into<String>,
        pem: &str,
        kid: &str,
    ) -> Result<Self, ClientError> {
        let key = Ed25519KeyPair::from_pem(pem).map_err(|_| ClientError::Key)?;
        Ok(Self::new(client_id, key, kid))
    }

    pub fn client_id(&self) -> &str {
        &self.client_id
    }

    /// A fresh `private_key_jwt` assertion for `issuer`.
    pub fn assertion(&self, issuer: &str) -> Result<String, ClientError> {
        let claims = Claims::create(Duration::from_secs(ASSERTION_SECS))
            .with_issuer(&self.client_id)
            .with_subject(&self.client_id)
            .with_audience(issuer)
            .with_jwt_id(Uuid::new_v4().to_string());
        let options = HeaderOptions {
            signature_type: Some("client-authentication+jwt".to_owned()),
            ..Default::default()
        };
        self.key
            .sign_with_options(claims, &options)
            .map_err(|_| ClientError::Key)
    }
}

/// What the token endpoint answered.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct TokenSet {
    pub access_token: String,
    #[serde(default)]
    pub expires_in: u64,
    #[serde(default)]
    pub scope: Option<String>,
    #[serde(default)]
    pub refresh_token: Option<String>,
    #[serde(default)]
    pub id_token: Option<String>,
}

/// Why Propolis gave no token.
#[derive(Debug)]
pub enum ClientError {
    /// The product's key cannot be read or cannot sign.
    Key,
    /// Propolis could not be reached, or answered something unreadable.
    Transport(reqwest::Error),
    /// Propolis refused, with the error code of RFC 6749 (`invalid_target`, `invalid_scope`...).
    Refused { status: u16, error: String },
}

impl std::fmt::Display for ClientError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ClientError::Key => f.write_str("the client key cannot sign"),
            ClientError::Transport(error) => {
                write!(f, "Propolis unreachable: {error}")
            }
            ClientError::Refused { status, error } => {
                write!(f, "Propolis refused ({status}): {error}")
            }
        }
    }
}

impl std::error::Error for ClientError {}

#[derive(Deserialize)]
struct OAuthError {
    error: String,
}

fn now() -> StdDuration {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
}

/// Service tokens by resource and scope, with when each expires.
type Kept = HashMap<(String, String), (TokenSet, StdDuration)>;

/// Propolis's token endpoint, as one product calls it.
#[derive(Clone)]
pub struct Client {
    issuer: String,
    token_endpoint: String,
    credentials: Credentials,
    http: reqwest::Client,
    /// Service tokens, by resource and scope, with when they expire.
    kept: Arc<Mutex<Kept>>,
}

impl Client {
    /// The client of Propolis at `issuer`, its token endpoint at `<issuer>/oauth/token`.
    pub fn new(issuer: impl Into<String>, credentials: Credentials, http: reqwest::Client) -> Self {
        let issuer: String = issuer.into();
        let issuer = issuer.trim_end_matches('/').to_owned();
        Self {
            token_endpoint: format!("{issuer}/oauth/token"),
            issuer,
            credentials,
            http,
            kept: Arc::default(),
        }
    }

    pub fn credentials(&self) -> &Credentials {
        &self.credentials
    }

    /// Post a token request, authenticated with a fresh assertion.
    pub async fn request(&self, form: &[(&str, &str)]) -> Result<TokenSet, ClientError> {
        let assertion = self.credentials.assertion(&self.issuer)?;
        let mut body = form_urlencoded::Serializer::new(String::new());
        for (name, value) in form {
            body.append_pair(name, value);
        }
        body.append_pair("client_assertion_type", JWT_BEARER)
            .append_pair("client_assertion", &assertion);
        let response = self
            .http
            .post(&self.token_endpoint)
            .header("content-type", "application/x-www-form-urlencoded")
            .body(body.finish())
            .send()
            .await
            .map_err(ClientError::Transport)?;
        let status = response.status();
        if !status.is_success() {
            let error = response
                .json::<OAuthError>()
                .await
                .map(|e| e.error)
                .unwrap_or_else(|_| "unreadable".to_owned());
            return Err(ClientError::Refused {
                status: status.as_u16(),
                error,
            });
        }
        response.json().await.map_err(ClientError::Transport)
    }

    /// A token in the product's own name for `resource` (Propolis itself when `None`), with these
    /// scopes (all those of its registration when empty).
    pub async fn client_credentials(
        &self,
        resource: Option<&str>,
        scopes: &[&str],
    ) -> Result<TokenSet, ClientError> {
        let scope = scopes.join(" ");
        let key = (resource.unwrap_or_default().to_owned(), scope.clone());
        if let Some((tokens, until)) = self.kept.lock().await.get(&key) {
            if now() + RENEW_BEFORE < *until {
                return Ok(tokens.clone());
            }
        }
        let mut form = vec![("grant_type", "client_credentials")];
        if let Some(resource) = resource {
            form.push(("resource", resource));
        }
        if !scope.is_empty() {
            form.push(("scope", &scope));
        }
        let tokens = self.request(&form).await?;
        let until = now() + StdDuration::from_secs(tokens.expires_in);
        self.kept.lock().await.insert(key, (tokens.clone(), until));
        Ok(tokens)
    }

    /// A token for `audience`, another product registered for this one, for the person whose access
    /// token (`subject_token`, for this product) the request came with.
    pub async fn exchange(
        &self,
        subject_token: &str,
        audience: &str,
        scopes: &[&str],
    ) -> Result<TokenSet, ClientError> {
        let scope = scopes.join(" ");
        let mut form = vec![
            (
                "grant_type",
                "urn:ietf:params:oauth:grant-type:token-exchange",
            ),
            ("subject_token", subject_token),
            ("subject_token_type", ACCESS_TOKEN_TYPE),
            ("resource", audience),
        ];
        if !scope.is_empty() {
            form.push(("scope", &scope));
        }
        self.request(&form).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_assertion_names_the_client_for_the_issuer_alone() {
        let key = Ed25519KeyPair::generate();
        let public = key.public_key();
        let credentials = Credentials::new("drive", key, "drive-auth-1");
        let assertion = credentials.assertion("https://id.example.org").unwrap();
        let metadata = Token::decode_metadata(&assertion).unwrap();
        assert_eq!(metadata.key_id(), Some("drive-auth-1"));
        assert_eq!(metadata.signature_type(), Some("client-authentication+jwt"));
        let claims = public
            .verify_token::<NoCustomClaims>(&assertion, None)
            .unwrap();
        assert_eq!(claims.issuer.as_deref(), Some("drive"));
        assert_eq!(claims.subject.as_deref(), Some("drive"));
        assert!(claims.jwt_id.is_some());
        assert!(claims
            .audiences
            .unwrap()
            .contains(&HashSet::from(["https://id.example.org".to_owned()])));
        assert!(
            !format!("{credentials:?}").contains("key:"),
            "never the key"
        );
    }
}
