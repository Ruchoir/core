//! Sign-in and tokens of the desktop app (RFC 8252, Propolis's design, section 11).
//!
//! - **Signing in**: an authorization request with an `S256` challenge, `state`, `nonce` and the
//!   products as `resource` (RFC 8707), opened in the system browser; the response's `iss` (RFC
//!   9207) and `state` checked; the code traded at the token endpoint as a public client (`none`);
//!   the ID token checked against Propolis's key set.
//! - **One grant per issuer**: its refresh token in the keychain, replaced at each rotation before
//!   the new access token is handed out. A refresh token Propolis refuses ends the grant.
//! - **One access token per product**, its `resource`, in memory only, refreshed a minute before it
//!   expires. The refreshes of one issuer run one at a time, so a rotation is never raced.
//! - **Signing out** revokes the refresh token (RFC 7009) and forgets the grant.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use base64::Engine;
use jwt_simple::prelude::{ECDSAP256PublicKeyLike, Token, VerificationOptions};
use ruchoir_auth::KeySet;
use serde::{Deserialize, Serialize};

use crate::discovery::{discover_issuer, Instance, IssuerMetadata};
use crate::redirect::{Browser, Redirect};
use crate::storage::Storage;

/// How long before its expiry an access token is refreshed.
pub const REFRESH_MARGIN: Duration = Duration::from_secs(60);

/// The scopes asked by default: `offline_access` brings the refresh token.
pub const DEFAULT_SCOPES: &[&str] = &["openid", "profile", "email", "offline_access"];

/// Why a step failed. A message never holds a token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NativeError {
    /// A manifest, product description or discovery document is missing or unreadable.
    Discovery(String),
    /// The server could not be reached. Nothing was lost: try again.
    Network(String),
    /// The authorization response does not carry the `state` the sign-in left with, or came back
    /// to another address.
    State,
    /// The authorization response names another issuer, or none (RFC 9207).
    Issuer,
    /// Propolis answered the authorization request with this `error`.
    Denied(String),
    /// The token endpoint refused a request with this `error`.
    Token(String),
    /// The ID token failed a check.
    IdToken,
    /// The refresh token was spent or revoked: the person signs in again.
    SessionEnded,
    /// No grant is kept for this issuer.
    SignedOut,
    /// The keychain failed.
    Storage(String),
    /// The browser could not be opened, or did not come back.
    Browser(String),
    /// The extra certificate authority (see [`crate::http_client`]) could not be read or parsed.
    Certificate(String),
}

impl std::fmt::Display for NativeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Discovery(why) => write!(f, "discovery failed: {why}"),
            Self::Network(why) => write!(f, "network error: {why}"),
            Self::State => f.write_str("the authorization response carries another state"),
            Self::Issuer => f.write_str("the authorization response names another issuer"),
            Self::Denied(error) => write!(f, "sign-in refused: {error}"),
            Self::Token(error) => write!(f, "token request refused: {error}"),
            Self::IdToken => f.write_str("the ID token was refused"),
            Self::SessionEnded => f.write_str("the session ended"),
            Self::SignedOut => f.write_str("no grant for this issuer"),
            Self::Storage(why) => write!(f, "storage error: {why}"),
            Self::Browser(why) => write!(f, "browser error: {why}"),
            Self::Certificate(why) => write!(f, "extra certificate authority: {why}"),
        }
    }
}

impl std::error::Error for NativeError {}

/// What to sign in to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignInTarget {
    pub issuer: String,
    /// The resources asked (RFC 8707): the products' origins.
    pub resources: Vec<String>,
}

impl From<&Instance> for SignInTarget {
    fn from(instance: &Instance) -> Self {
        Self {
            issuer: instance.issuer.clone(),
            resources: instance.products.iter().map(|p| p.url.clone()).collect(),
        }
    }
}

/// A signed-in person on one instance.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Account {
    pub issuer: String,
    pub subject: String,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub email: Option<String>,
}

/// A sign-in under way: open [`url`](Self::url), then give the address the browser came back to
/// to [`NativeClient::finish_sign_in`]. It holds the PKCE verifier: keep it in memory only.
pub struct PendingSignIn {
    /// The authorization request to open in the browser.
    pub url: String,
    metadata: IssuerMetadata,
    redirect_uri: String,
    state: String,
    nonce: String,
    verifier: String,
    resources: Vec<String>,
}

/// What the keychain keeps for one issuer.
#[derive(Clone, Serialize, Deserialize)]
struct Grant {
    #[serde(flatten)]
    account: Account,
    client_id: String,
    refresh_token: String,
    token_endpoint: String,
    #[serde(default)]
    revocation_endpoint: Option<String>,
}

struct Cached {
    token: String,
    expires_at: Instant,
}

#[derive(Default, Deserialize)]
struct TokenAnswer {
    access_token: Option<String>,
    expires_in: Option<u64>,
    refresh_token: Option<String>,
    id_token: Option<String>,
    error: Option<String>,
}

#[derive(Deserialize, Serialize)]
struct IdClaims {
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    email: Option<String>,
}

fn random() -> Result<String, NativeError> {
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes).map_err(|e| NativeError::Storage(e.to_string()))?;
    Ok(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes))
}

fn without_query(address: &str) -> &str {
    address.split(['?', '#']).next().unwrap_or_default()
}

/// The first value of each parameter of an address's query.
fn query_of(address: &str) -> HashMap<String, String> {
    let query = address
        .split('#')
        .next()
        .and_then(|a| a.split_once('?'))
        .map(|(_, q)| q)
        .unwrap_or_default();
    let mut params = HashMap::new();
    for (name, value) in form_urlencoded::parse(query.as_bytes()) {
        params
            .entry(name.into_owned())
            .or_insert_with(|| value.into_owned());
    }
    params
}

/// The client of one app, for every instance it is signed in to.
pub struct NativeClient<S> {
    http: reqwest::Client,
    client_id: String,
    scopes: Vec<String>,
    prefix: String,
    storage: S,
    /// Access tokens by issuer and resource. Never stored.
    tokens: Mutex<HashMap<(String, String), Cached>>,
    /// One lock per issuer, held across a refresh and its rotation.
    locks: Mutex<HashMap<String, Arc<tokio::sync::Mutex<()>>>>,
}

impl<S: Storage> NativeClient<S> {
    /// A client registered at Propolis as `client_id` (`ruchoir-desktop`), its grants in `storage`.
    pub fn new(http: reqwest::Client, client_id: impl Into<String>, storage: S) -> Self {
        Self {
            http,
            client_id: client_id.into(),
            scopes: DEFAULT_SCOPES.iter().map(|s| (*s).to_owned()).collect(),
            prefix: "ruchoir".to_owned(),
            storage,
            tokens: Mutex::default(),
            locks: Mutex::default(),
        }
    }

    /// Other scopes than [`DEFAULT_SCOPES`].
    pub fn with_scopes(mut self, scopes: &[&str]) -> Self {
        self.scopes = scopes.iter().map(|s| (*s).to_owned()).collect();
        self
    }

    /// Another prefix of the storage keys than `ruchoir`.
    pub fn with_storage_prefix(mut self, prefix: impl Into<String>) -> Self {
        self.prefix = prefix.into();
        self
    }

    /// The storage the grants are kept in.
    pub fn storage(&self) -> &S {
        &self.storage
    }

    fn grant_key(&self, issuer: &str) -> String {
        let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(issuer);
        format!("{}.grant.{encoded}", self.prefix)
    }

    fn index_key(&self) -> String {
        format!("{}.issuers", self.prefix)
    }

    fn lock(&self, issuer: &str) -> Arc<tokio::sync::Mutex<()>> {
        let mut locks = self.locks.lock().unwrap_or_else(|e| e.into_inner());
        locks.entry(issuer.to_owned()).or_default().clone()
    }

    fn cached(&self, issuer: &str, resource: &str) -> Option<String> {
        let tokens = self.tokens.lock().unwrap_or_else(|e| e.into_inner());
        tokens
            .get(&(issuer.to_owned(), resource.to_owned()))
            .filter(|c| Instant::now() + REFRESH_MARGIN < c.expires_at)
            .map(|c| c.token.clone())
    }

    fn cache(
        &self,
        issuer: &str,
        resource: &str,
        answer: &TokenAnswer,
    ) -> Result<String, NativeError> {
        let token = answer
            .access_token
            .clone()
            .ok_or_else(|| NativeError::Token("no access token".into()))?;
        let lifetime = Duration::from_secs(answer.expires_in.unwrap_or(300));
        let mut tokens = self.tokens.lock().unwrap_or_else(|e| e.into_inner());
        tokens.insert(
            (issuer.to_owned(), resource.to_owned()),
            Cached {
                token: token.clone(),
                expires_at: Instant::now() + lifetime,
            },
        );
        Ok(token)
    }

    fn drop_tokens(&self, issuer: &str) {
        let mut tokens = self.tokens.lock().unwrap_or_else(|e| e.into_inner());
        tokens.retain(|(i, _), _| i != issuer);
    }

    /// The issuers a grant is kept for, in the order they were signed in.
    pub async fn issuers(&self) -> Result<Vec<String>, NativeError> {
        let raw = self
            .storage
            .get(&self.index_key())
            .await
            .map_err(NativeError::Storage)?;
        Ok(raw
            .and_then(|r| serde_json::from_str(&r).ok())
            .unwrap_or_default())
    }

    async fn grant(&self, issuer: &str) -> Result<Option<Grant>, NativeError> {
        let raw = self
            .storage
            .get(&self.grant_key(issuer))
            .await
            .map_err(NativeError::Storage)?;
        Ok(raw.and_then(|r| serde_json::from_str(&r).ok()))
    }

    async fn keep(&self, grant: &Grant) -> Result<(), NativeError> {
        let value =
            serde_json::to_string(grant).map_err(|e| NativeError::Storage(e.to_string()))?;
        let issuer = &grant.account.issuer;
        self.storage
            .set(&self.grant_key(issuer), &value)
            .await
            .map_err(NativeError::Storage)?;
        let mut issuers = self.issuers().await?;
        if !issuers.contains(issuer) {
            issuers.push(issuer.clone());
            self.write_index(&issuers).await?;
        }
        Ok(())
    }

    async fn write_index(&self, issuers: &[String]) -> Result<(), NativeError> {
        let value =
            serde_json::to_string(issuers).map_err(|e| NativeError::Storage(e.to_string()))?;
        self.storage
            .set(&self.index_key(), &value)
            .await
            .map_err(NativeError::Storage)
    }

    async fn forget(&self, issuer: &str) -> Result<(), NativeError> {
        self.drop_tokens(issuer);
        self.storage
            .delete(&self.grant_key(issuer))
            .await
            .map_err(NativeError::Storage)?;
        let mut issuers = self.issuers().await?;
        issuers.retain(|i| i != issuer);
        self.write_index(&issuers).await
    }

    async fn post(
        &self,
        endpoint: &str,
        pairs: &[(&str, &str)],
    ) -> Result<(bool, TokenAnswer), NativeError> {
        let body = form_urlencoded::Serializer::new(String::new())
            .extend_pairs(pairs)
            .finish();
        let response = self
            .http
            .post(endpoint)
            .header("content-type", "application/x-www-form-urlencoded")
            .header("accept", "application/json")
            .body(body)
            .send()
            .await
            .map_err(|e| NativeError::Network(e.to_string()))?;
        let ok = response.status().is_success();
        let status = response.status().as_u16();
        let mut answer: TokenAnswer = response.json().await.unwrap_or_default();
        if !ok && answer.error.is_none() {
            answer.error = Some(status.to_string());
        }
        Ok((ok, answer))
    }

    /// Start a sign-in: the authorization request to open, sending the browser back to
    /// `redirect_uri`.
    pub async fn begin_sign_in(
        &self,
        target: &SignInTarget,
        redirect_uri: &str,
    ) -> Result<PendingSignIn, NativeError> {
        let metadata = discover_issuer(&self.http, &target.issuer).await?;
        let verifier = random()?;
        let state = random()?;
        let nonce = random()?;
        let challenge = ruchoir_auth::session::challenge(&verifier);
        let scope = self.scopes.join(" ");
        let mut query = form_urlencoded::Serializer::new(String::new());
        query.extend_pairs([
            ("response_type", "code"),
            ("client_id", self.client_id.as_str()),
            ("redirect_uri", redirect_uri),
            ("scope", scope.as_str()),
            ("state", state.as_str()),
            ("nonce", nonce.as_str()),
            ("code_challenge", challenge.as_str()),
            ("code_challenge_method", "S256"),
        ]);
        for resource in &target.resources {
            query.append_pair("resource", resource);
        }
        let separator = if metadata.authorization_endpoint.contains('?') {
            '&'
        } else {
            '?'
        };
        Ok(PendingSignIn {
            url: format!(
                "{}{separator}{}",
                metadata.authorization_endpoint,
                query.finish()
            ),
            metadata,
            redirect_uri: redirect_uri.to_owned(),
            state,
            nonce,
            verifier,
            resources: target.resources.clone(),
        })
    }

    /// End a sign-in with the address the browser came back to, and keep the grant.
    pub async fn finish_sign_in(
        &self,
        pending: PendingSignIn,
        callback: &str,
    ) -> Result<Account, NativeError> {
        if without_query(callback) != without_query(&pending.redirect_uri) {
            return Err(NativeError::State);
        }
        let answer = query_of(callback);
        let issuer = pending.metadata.issuer.clone();
        // The issuer first: an answer from another instance is not read any further (RFC 9207).
        if answer.get("iss") != Some(&issuer) {
            return Err(NativeError::Issuer);
        }
        if answer.get("state") != Some(&pending.state) {
            return Err(NativeError::State);
        }
        if let Some(error) = answer.get("error") {
            return Err(NativeError::Denied(error.clone()));
        }
        let code = answer
            .get("code")
            .ok_or_else(|| NativeError::Denied("no code".into()))?;

        let (ok, body) = self
            .post(
                &pending.metadata.token_endpoint,
                &[
                    ("grant_type", "authorization_code"),
                    ("code", code),
                    ("redirect_uri", &pending.redirect_uri),
                    ("client_id", &self.client_id),
                    ("code_verifier", &pending.verifier),
                ],
            )
            .await?;
        if !ok {
            return Err(NativeError::Token(body.error.unwrap_or_default()));
        }
        let refresh_token = body
            .refresh_token
            .clone()
            .ok_or_else(|| NativeError::Token("no refresh token (offline_access)".into()))?;
        let id_token = body
            .id_token
            .as_deref()
            .ok_or_else(|| NativeError::Token("no ID token (openid)".into()))?;
        let account = self.check_id_token(id_token, &pending).await?;

        let grant = Grant {
            account: account.clone(),
            client_id: self.client_id.clone(),
            refresh_token,
            token_endpoint: pending.metadata.token_endpoint.clone(),
            revocation_endpoint: pending.metadata.revocation_endpoint.clone(),
        };
        let lock = self.lock(&issuer);
        let _held = lock.lock().await;
        let previous = self.grant(&issuer).await?;
        self.drop_tokens(&issuer);
        self.keep(&grant).await?;
        // A new sign-in replaces the earlier grant: Propolis forgets it too.
        if let Some(previous) = previous.filter(|p| p.refresh_token != grant.refresh_token) {
            self.revoke(&previous).await;
        }
        // Without `resource`, the code's access token is for the first resource asked, or Propolis.
        let resource = pending.resources.first().unwrap_or(&issuer);
        self.cache(&issuer, resource, &body)?;
        Ok(account)
    }

    /// Check an ID token: ES256 with a key of Propolis's set, the issuer, this app as audience,
    /// expiry and the nonce the sign-in left with.
    async fn check_id_token(
        &self,
        token: &str,
        pending: &PendingSignIn,
    ) -> Result<Account, NativeError> {
        let metadata = Token::decode_metadata(token).map_err(|_| NativeError::IdToken)?;
        if metadata.algorithm() != "ES256" {
            return Err(NativeError::IdToken);
        }
        let kid = metadata.key_id().ok_or(NativeError::IdToken)?;
        let keys = KeySet::new(pending.metadata.jwks_uri.clone(), self.http.clone());
        let key = keys.get(kid).await.ok_or(NativeError::IdToken)?;
        let options = VerificationOptions {
            allowed_issuers: Some(HashSet::from([pending.metadata.issuer.clone()])),
            allowed_audiences: Some(HashSet::from([self.client_id.clone()])),
            required_nonce: Some(pending.nonce.clone()),
            time_tolerance: Some(jwt_simple::prelude::Duration::from_secs(
                ruchoir_auth::SKEW_SECS,
            )),
            ..Default::default()
        };
        let claims = key
            .verify_token::<IdClaims>(token, Some(options))
            .map_err(|_| NativeError::IdToken)?;
        let subject = claims.subject.ok_or(NativeError::IdToken)?;
        Ok(Account {
            issuer: pending.metadata.issuer.clone(),
            subject,
            name: claims.custom.name,
            email: claims.custom.email,
        })
    }

    /// Sign in to `target`: listen with `redirect`, open the request with `browser`, wait for the
    /// browser to come back, and keep the grant.
    pub async fn sign_in(
        &self,
        target: &SignInTarget,
        browser: &impl Browser,
        redirect: impl Redirect,
    ) -> Result<Account, NativeError> {
        let pending = self.begin_sign_in(target, &redirect.redirect_uri()).await?;
        browser.open(&pending.url).map_err(NativeError::Browser)?;
        let callback = redirect.receive().await.map_err(NativeError::Browser)?;
        self.finish_sign_in(pending, &callback).await
    }

    /// The person signed in at `issuer`, if any.
    pub async fn account(&self, issuer: &str) -> Result<Option<Account>, NativeError> {
        Ok(self.grant(issuer).await?.map(|g| g.account))
    }

    /// An access token for `resource` (a product's origin) at `issuer`, from memory while it has
    /// more than a minute left, else refreshed. [`NativeError::SessionEnded`] when Propolis refused
    /// the refresh token: the grant is gone and the person signs in again.
    pub async fn access_token(&self, issuer: &str, resource: &str) -> Result<String, NativeError> {
        if let Some(token) = self.cached(issuer, resource) {
            return Ok(token);
        }
        let lock = self.lock(issuer);
        let _held = lock.lock().await;
        if let Some(token) = self.cached(issuer, resource) {
            return Ok(token);
        }
        let grant = self.grant(issuer).await?.ok_or(NativeError::SignedOut)?;
        let (ok, body) = self
            .post(
                &grant.token_endpoint,
                &[
                    ("grant_type", "refresh_token"),
                    ("refresh_token", &grant.refresh_token),
                    ("client_id", &grant.client_id),
                    ("resource", resource),
                ],
            )
            .await?;
        if !ok {
            let error = body.error.unwrap_or_default();
            if error == "invalid_grant" {
                self.forget(issuer).await?;
                return Err(NativeError::SessionEnded);
            }
            return Err(NativeError::Token(error));
        }
        // The rotated refresh token is kept before the access token is handed out: the old one is
        // spent, and using it again would end the grant.
        if let Some(next) = body
            .refresh_token
            .as_ref()
            .filter(|t| **t != grant.refresh_token)
        {
            let rotated = Grant {
                refresh_token: next.clone(),
                ..grant
            };
            self.keep(&rotated).await?;
        }
        self.cache(issuer, resource, &body)
    }

    /// Best effort: the grant is forgotten on the device whatever Propolis answers.
    async fn revoke(&self, grant: &Grant) {
        if let Some(endpoint) = &grant.revocation_endpoint {
            let _ = self
                .post(
                    endpoint,
                    &[
                        ("token", &grant.refresh_token),
                        ("token_type_hint", "refresh_token"),
                        ("client_id", &grant.client_id),
                    ],
                )
                .await;
        }
    }

    /// Revoke the grant of `issuer` (RFC 7009) and forget it, with its access tokens.
    pub async fn sign_out(&self, issuer: &str) -> Result<(), NativeError> {
        let lock = self.lock(issuer);
        let _held = lock.lock().await;
        let grant = self.grant(issuer).await?;
        self.forget(issuer).await?;
        if let Some(grant) = grant {
            self.revoke(&grant).await;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_query_keeps_the_first_value_and_ignores_the_fragment() {
        let params = query_of("http://127.0.0.1:1/callback?a=1&b=two+words&a=2#x=3");
        assert_eq!(params["a"], "1");
        assert_eq!(params["b"], "two words");
        assert!(!params.contains_key("x"));
        assert_eq!(
            without_query("com.ruchoir.app:/oauth/callback?code=1"),
            "com.ruchoir.app:/oauth/callback"
        );
    }

    #[test]
    fn the_grant_never_names_an_access_token() {
        let grant = Grant {
            account: Account {
                issuer: "https://id.example.org".into(),
                subject: "p".into(),
                name: None,
                email: None,
            },
            client_id: "ruchoir-desktop".into(),
            refresh_token: "r".into(),
            token_endpoint: "https://id.example.org/oauth/token".into(),
            revocation_endpoint: None,
        };
        let stored = serde_json::to_string(&grant).unwrap();
        assert!(!stored.contains("access"));
    }
}
