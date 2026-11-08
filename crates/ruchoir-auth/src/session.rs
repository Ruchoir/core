//! A product's browser session: the product as a backend-for-frontend of Propolis (design
//! `docs/design/openid-connect.md` of `Ruchoir/propolis`, sections 6.2, 6.3, 6.6 and 10).
//!
//! - **Signing in**: [`Bff::begin`] sends the browser to Propolis with `state`, `nonce` and an `S256`
//!   code challenge, and [`Bff::finish`] trades the code for the person's tokens, checks the ID
//!   token, and opens the product's session.
//! - **The browser holds an opaque id**, in the product's own `__Host-` cookie (`HttpOnly`,
//!   `Secure`, `SameSite=Lax`, no `Domain`). The tokens stay in the product's store and never reach
//!   the page.
//! - **While the session lives**, [`Bff::session`] hands the person's access token, refreshed when it
//!   is about to expire. Refreshes are serialised per session: Propolis revokes a whole grant when a
//!   spent refresh token comes back.
//! - **Signing out**: [`Bff::end`] drops the session and answers where to send the browser
//!   (RP-Initiated Logout), and [`Bff::back_channel`] drops the sessions a Propolis logout token
//!   names.
//!
//! The store is the product's (its Valkey, [`ValkeyStore`] with the `valkey` feature), behind
//! [`Store`]; [`MemoryStore`] serves tests and a single process.

use std::collections::{HashMap, HashSet};
use std::future::Future;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use jwt_simple::prelude::*;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::client::{Client, ClientError, TokenSet};
use crate::keys::KeySet;
use crate::{logout, Rejected, SKEW_SECS};

/// How long a sign-in may take, from leaving the product to coming back with a code.
pub const LOGIN_SECS: u64 = 10 * 60;
/// An access token is refreshed when it has less than this left.
pub const REFRESH_MARGIN_SECS: u64 = 60;
/// A session unused this long ends (Propolis's own idle window by default).
pub const IDLE_SECS: u64 = 14 * 24 * 60 * 60;
/// A session ends this long after it opened, whatever its use.
pub const ABSOLUTE_SECS: u64 = 30 * 24 * 60 * 60;
/// How long one process holds a session's refresh before another may try.
const REFRESH_LOCK_SECS: u64 = 30;

/// Where a product keeps its sessions: keys with a lifetime, and sets of keys, as Valkey holds
/// them. Every method answers `Err` with a reason when the store cannot be reached.
pub trait Store: Send + Sync {
    /// Set `key` to `value` for `ttl`.
    fn put(
        &self,
        key: &str,
        value: &str,
        ttl: Duration,
    ) -> impl Future<Output = Result<(), String>> + Send;
    /// Set `key` only when it is absent; `true` when it was set.
    fn put_new(
        &self,
        key: &str,
        value: &str,
        ttl: Duration,
    ) -> impl Future<Output = Result<bool, String>> + Send;
    fn get(&self, key: &str) -> impl Future<Output = Result<Option<String>, String>> + Send;
    /// Read and delete `key` in one step.
    fn take(&self, key: &str) -> impl Future<Output = Result<Option<String>, String>> + Send;
    fn delete(&self, key: &str) -> impl Future<Output = Result<(), String>> + Send;
    /// Add `member` to the set at `key`, which lives `ttl` from now.
    fn add(
        &self,
        key: &str,
        member: &str,
        ttl: Duration,
    ) -> impl Future<Output = Result<(), String>> + Send;
    fn members(&self, key: &str) -> impl Future<Output = Result<Vec<String>, String>> + Send;
}

/// Values by key, each with when it expires.
type Expiring<T> = Arc<Mutex<HashMap<String, (T, SystemTime)>>>;

/// A store in this process's memory, for tests and a product running as one process.
#[derive(Clone, Default)]
pub struct MemoryStore {
    values: Expiring<String>,
    sets: Expiring<HashSet<String>>,
}

impl MemoryStore {
    fn live<T: Clone>(map: &HashMap<String, (T, SystemTime)>, key: &str) -> Option<T> {
        map.get(key)
            .filter(|(_, until)| *until > SystemTime::now())
            .map(|(value, _)| value.clone())
    }
}

impl Store for MemoryStore {
    async fn put(&self, key: &str, value: &str, ttl: Duration) -> Result<(), String> {
        let mut values = self.values.lock().map_err(|e| e.to_string())?;
        values.insert(key.to_owned(), (value.to_owned(), SystemTime::now() + ttl));
        Ok(())
    }

    async fn put_new(&self, key: &str, value: &str, ttl: Duration) -> Result<bool, String> {
        let mut values = self.values.lock().map_err(|e| e.to_string())?;
        if Self::live(&values, key).is_some() {
            return Ok(false);
        }
        values.insert(key.to_owned(), (value.to_owned(), SystemTime::now() + ttl));
        Ok(true)
    }

    async fn get(&self, key: &str) -> Result<Option<String>, String> {
        let values = self.values.lock().map_err(|e| e.to_string())?;
        Ok(Self::live(&values, key))
    }

    async fn take(&self, key: &str) -> Result<Option<String>, String> {
        let mut values = self.values.lock().map_err(|e| e.to_string())?;
        let value = Self::live(&values, key);
        values.remove(key);
        Ok(value)
    }

    async fn delete(&self, key: &str) -> Result<(), String> {
        self.values.lock().map_err(|e| e.to_string())?.remove(key);
        self.sets.lock().map_err(|e| e.to_string())?.remove(key);
        Ok(())
    }

    async fn add(&self, key: &str, member: &str, ttl: Duration) -> Result<(), String> {
        let mut sets = self.sets.lock().map_err(|e| e.to_string())?;
        let until = SystemTime::now() + ttl;
        let entry = sets
            .entry(key.to_owned())
            .or_insert_with(|| (HashSet::new(), until));
        entry.0.insert(member.to_owned());
        entry.1 = until;
        Ok(())
    }

    async fn members(&self, key: &str) -> Result<Vec<String>, String> {
        let sets = self.sets.lock().map_err(|e| e.to_string())?;
        Ok(Self::live(&sets, key)
            .map(|set| set.into_iter().collect())
            .unwrap_or_default())
    }
}

/// A store in the product's Valkey (fred).
#[cfg(feature = "valkey")]
#[derive(Clone)]
pub struct ValkeyStore {
    pool: fred::prelude::Pool,
    /// Every key starts with it, so sessions never meet the product's other keys.
    prefix: String,
}

#[cfg(feature = "valkey")]
impl ValkeyStore {
    pub fn new(pool: fred::prelude::Pool, prefix: impl Into<String>) -> Self {
        Self {
            pool,
            prefix: prefix.into(),
        }
    }

    fn key(&self, key: &str) -> String {
        format!("{}{key}", self.prefix)
    }
}

#[cfg(feature = "valkey")]
impl Store for ValkeyStore {
    async fn put(&self, key: &str, value: &str, ttl: Duration) -> Result<(), String> {
        use fred::prelude::*;
        let secs = ttl.as_secs().max(1) as i64;
        self.pool
            .set::<(), _, _>(
                self.key(key),
                value,
                Some(Expiration::EX(secs)),
                None,
                false,
            )
            .await
            .map_err(|e| e.to_string())
    }

    async fn put_new(&self, key: &str, value: &str, ttl: Duration) -> Result<bool, String> {
        use fred::prelude::*;
        let secs = ttl.as_secs().max(1) as i64;
        let set: Option<String> = self
            .pool
            .set(
                self.key(key),
                value,
                Some(Expiration::EX(secs)),
                Some(SetOptions::NX),
                false,
            )
            .await
            .map_err(|e| e.to_string())?;
        Ok(set.is_some())
    }

    async fn get(&self, key: &str) -> Result<Option<String>, String> {
        use fred::prelude::*;
        self.pool
            .get(self.key(key))
            .await
            .map_err(|e| e.to_string())
    }

    async fn take(&self, key: &str) -> Result<Option<String>, String> {
        use fred::prelude::*;
        self.pool
            .getdel(self.key(key))
            .await
            .map_err(|e| e.to_string())
    }

    async fn delete(&self, key: &str) -> Result<(), String> {
        use fred::prelude::*;
        self.pool
            .del::<(), _>(self.key(key))
            .await
            .map_err(|e| e.to_string())
    }

    async fn add(&self, key: &str, member: &str, ttl: Duration) -> Result<(), String> {
        use fred::prelude::*;
        let key = self.key(key);
        self.pool
            .sadd::<(), _, _>(&key, member)
            .await
            .map_err(|e| e.to_string())?;
        self.pool
            .expire::<(), _>(&key, ttl.as_secs().max(1) as i64, None)
            .await
            .map_err(|e| e.to_string())
    }

    async fn members(&self, key: &str) -> Result<Vec<String>, String> {
        use fred::prelude::*;
        self.pool
            .smembers(self.key(key))
            .await
            .map_err(|e| e.to_string())
    }
}

/// How a product signs people in.
#[derive(Debug, Clone)]
pub struct BffConfig {
    /// Propolis (`https://id.example.org`).
    pub issuer: String,
    /// The product's client id at Propolis (`drive`).
    pub client_id: String,
    /// Where Propolis sends the browser back with a code: the product's own
    /// `https://drive.example.org/auth/callback`, registered as is.
    pub redirect_uri: String,
    /// Where Propolis sends the browser after signing out, registered as is.
    pub post_logout_redirect_uri: String,
    /// The product's resource identifier: the audience of the access tokens it receives.
    pub resource: String,
    /// What the product asks for (`openid` is always added).
    pub scopes: Vec<String>,
    /// The cookie's name, `__Host-` and the product's (`__Host-drive_session`).
    pub cookie: String,
}

impl BffConfig {
    /// The usual settings of an instance product at `origin` (`https://drive.example.org`), named
    /// `product` (`drive`) at Propolis.
    pub fn for_product(issuer: &str, product: &str, origin: &str) -> Self {
        let origin = origin.trim_end_matches('/');
        Self {
            issuer: issuer.trim_end_matches('/').to_owned(),
            client_id: product.to_owned(),
            redirect_uri: format!("{origin}/auth/callback"),
            post_logout_redirect_uri: format!("{origin}/"),
            resource: origin.to_owned(),
            scopes: ["openid", "profile", "email", "organizations"]
                .map(str::to_owned)
                .to_vec(),
            cookie: format!("__Host-{product}_session"),
        }
    }
}

/// Why a sign-in or a session failed.
#[derive(Debug)]
pub enum BffError {
    /// No session, or it ended: sign in again.
    NoSession,
    /// The sign-in came back without what it left with (a forged or replayed `state`, another
    /// issuer, an ID token that does not match).
    Invalid(&'static str),
    /// Propolis answered `login_required` to a `prompt=none` sign-in: show a "Sign in" button.
    LoginRequired { return_to: String },
    /// Propolis said no, with the error of RFC 6749.
    Refused(String),
    /// Propolis or the store could not be reached.
    Unavailable(String),
}

impl std::fmt::Display for BffError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BffError::NoSession => f.write_str("no session"),
            BffError::Invalid(what) => write!(f, "invalid sign-in: {what}"),
            BffError::LoginRequired { .. } => f.write_str("login required"),
            BffError::Refused(error) => write!(f, "Propolis refused: {error}"),
            BffError::Unavailable(why) => write!(f, "unavailable: {why}"),
        }
    }
}

impl std::error::Error for BffError {}

impl From<ClientError> for BffError {
    fn from(error: ClientError) -> Self {
        match error {
            ClientError::Refused { error, .. } => BffError::Refused(error),
            other => BffError::Unavailable(other.to_string()),
        }
    }
}

/// What a sign-in left with, kept until it comes back.
#[derive(Serialize, Deserialize)]
struct Pending {
    nonce: String,
    verifier: String,
    return_to: String,
}

/// A session, as the store keeps it.
#[derive(Clone, Serialize, Deserialize)]
struct Record {
    sub: String,
    sid: Option<String>,
    id_token: String,
    access_token: String,
    /// Unix seconds.
    access_expires_at: u64,
    refresh_token: Option<String>,
    opened_at: u64,
    seen_at: u64,
}

/// A live session, as a product's handler uses it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Active {
    /// The person, as the instance's services know them (Propolis's public subject).
    pub sub: String,
    /// Their Propolis session.
    pub sid: Option<String>,
    /// A valid access token for the product, to call its own API in the person's name or to
    /// exchange for another product's (RFC 8693).
    pub access_token: String,
}

/// Where a finished sign-in leads.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finished {
    /// The `Set-Cookie` value opening the session.
    pub set_cookie: String,
    /// The product's own path the person was on.
    pub return_to: String,
}

/// What Propolis's callback carries (RFC 6749 section 4.1.2, RFC 9207).
#[derive(Debug, Clone, Default, Deserialize)]
pub struct Callback {
    pub code: Option<String>,
    pub state: Option<String>,
    pub iss: Option<String>,
    pub error: Option<String>,
}

/// The claims of an ID token this module reads.
#[derive(Serialize, Deserialize)]
struct IdClaims {
    #[serde(default)]
    sid: Option<String>,
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// 256 random bits, base64url.
fn random() -> Result<String, BffError> {
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes).map_err(|e| BffError::Unavailable(e.to_string()))?;
    Ok(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes))
}

/// The `S256` challenge of a verifier (RFC 7636, section 4.2).
pub fn challenge(verifier: &str) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()))
}

/// A path of the product, or `/`: never another host (`//evil.test`, `https://...`, `/\evil`).
fn safe_return(path: &str) -> String {
    let local = path.starts_with('/')
        && !path.starts_with("//")
        && !path.starts_with("/\\")
        && !path.chars().any(|c| c.is_control())
        && path.len() <= 2000;
    if local {
        path.to_owned()
    } else {
        "/".to_owned()
    }
}

fn unavailable(why: String) -> BffError {
    BffError::Unavailable(why)
}

/// A product signing people in through Propolis.
pub struct Bff<S: Store> {
    config: BffConfig,
    client: Client,
    keys: KeySet,
    store: S,
}

impl<S: Store> Bff<S> {
    pub fn new(config: BffConfig, client: Client, keys: KeySet, store: S) -> Self {
        Self {
            config,
            client,
            keys,
            store,
        }
    }

    pub fn config(&self) -> &BffConfig {
        &self.config
    }

    /// Start a sign-in: the address of Propolis's authorization endpoint to send the browser to.
    /// `return_to` is the product's path to come back to; `silent` asks Propolis to show nothing
    /// (`prompt=none`).
    pub async fn begin(&self, return_to: &str, silent: bool) -> Result<String, BffError> {
        let state = random()?;
        let pending = Pending {
            nonce: random()?,
            verifier: random()?,
            return_to: safe_return(return_to),
        };
        let kept = serde_json::to_string(&pending).map_err(|e| unavailable(e.to_string()))?;
        self.store
            .put(
                &format!("login:{state}"),
                &kept,
                Duration::from_secs(LOGIN_SECS),
            )
            .await
            .map_err(unavailable)?;
        let mut scopes = vec!["openid".to_owned()];
        scopes.extend(
            self.config
                .scopes
                .iter()
                .filter(|s| *s != "openid")
                .cloned(),
        );
        let mut query = form_urlencoded::Serializer::new(String::new());
        query
            .append_pair("response_type", "code")
            .append_pair("client_id", &self.config.client_id)
            .append_pair("redirect_uri", &self.config.redirect_uri)
            .append_pair("scope", &scopes.join(" "))
            .append_pair("state", &state)
            .append_pair("nonce", &pending.nonce)
            .append_pair("code_challenge", &challenge(&pending.verifier))
            .append_pair("code_challenge_method", "S256")
            .append_pair("resource", &self.config.resource);
        if silent {
            query.append_pair("prompt", "none");
        }
        Ok(format!(
            "{}/oauth/authorize?{}",
            self.config.issuer,
            query.finish()
        ))
    }

    /// Finish a sign-in from Propolis's callback: the session's cookie and where to go.
    pub async fn finish(&self, callback: &Callback) -> Result<Finished, BffError> {
        let state = callback
            .state
            .as_deref()
            .ok_or(BffError::Invalid("state"))?;
        // Taken once: a replayed callback finds nothing.
        let pending = self
            .store
            .take(&format!("login:{state}"))
            .await
            .map_err(unavailable)?
            .ok_or(BffError::Invalid("state"))?;
        let pending: Pending =
            serde_json::from_str(&pending).map_err(|_| BffError::Invalid("state"))?;
        if let Some(error) = &callback.error {
            if matches!(
                error.as_str(),
                "login_required" | "interaction_required" | "consent_required"
            ) {
                return Err(BffError::LoginRequired {
                    return_to: pending.return_to,
                });
            }
            return Err(BffError::Refused(error.clone()));
        }
        // RFC 9207: the answer comes from the issuer the product asked.
        if callback.iss.as_deref() != Some(self.config.issuer.as_str()) {
            return Err(BffError::Invalid("iss"));
        }
        let code = callback.code.as_deref().ok_or(BffError::Invalid("code"))?;
        let tokens = self
            .client
            .request(&[
                ("grant_type", "authorization_code"),
                ("code", code),
                ("redirect_uri", &self.config.redirect_uri),
                ("code_verifier", &pending.verifier),
                ("resource", &self.config.resource),
            ])
            .await?;
        let id_token = tokens
            .id_token
            .clone()
            .ok_or(BffError::Invalid("id_token"))?;
        let (sub, sid) = self.check_id_token(&id_token, &pending.nonce).await?;
        let at = now();
        let record = Record {
            sub: sub.clone(),
            sid: sid.clone(),
            id_token,
            access_expires_at: at + tokens.expires_in,
            access_token: tokens.access_token,
            refresh_token: tokens.refresh_token,
            opened_at: at,
            seen_at: at,
        };
        let id = random()?;
        self.keep(&id, &record).await?;
        let ttl = Duration::from_secs(ABSOLUTE_SECS);
        if let Some(sid) = &sid {
            self.store
                .add(&format!("sid:{sid}"), &id, ttl)
                .await
                .map_err(unavailable)?;
        }
        self.store
            .add(&format!("sub:{sub}"), &id, ttl)
            .await
            .map_err(unavailable)?;
        Ok(Finished {
            set_cookie: self.cookie(&id),
            return_to: pending.return_to,
        })
    }

    /// Check an ID token from the token endpoint: Propolis's key, its algorithm, issuer, this
    /// client as audience, expiry, and the nonce the sign-in left with.
    async fn check_id_token(
        &self,
        token: &str,
        nonce: &str,
    ) -> Result<(String, Option<String>), BffError> {
        let metadata = Token::decode_metadata(token).map_err(|_| BffError::Invalid("id_token"))?;
        let kid = metadata.key_id().ok_or(BffError::Invalid("id_token"))?;
        if metadata.algorithm() != "ES256" {
            return Err(BffError::Invalid("id_token"));
        }
        let key = self
            .keys
            .get(kid)
            .await
            .ok_or(BffError::Invalid("id_token"))?;
        let options = VerificationOptions {
            allowed_issuers: Some(HashSet::from([self.config.issuer.clone()])),
            allowed_audiences: Some(HashSet::from([self.config.client_id.clone()])),
            required_nonce: Some(nonce.to_owned()),
            time_tolerance: Some(jwt_simple::prelude::Duration::from_secs(SKEW_SECS)),
            ..Default::default()
        };
        let claims = key
            .verify_token::<IdClaims>(token, Some(options))
            .map_err(|_| BffError::Invalid("id_token"))?;
        let sub = claims.subject.ok_or(BffError::Invalid("id_token"))?;
        Ok((sub, claims.custom.sid))
    }

    /// Store a session for what is left of its idle and absolute windows.
    async fn keep(&self, id: &str, record: &Record) -> Result<(), BffError> {
        let left = (record.opened_at + ABSOLUTE_SECS).saturating_sub(now());
        let ttl = IDLE_SECS.min(left);
        if ttl == 0 {
            return Err(BffError::NoSession);
        }
        let text = serde_json::to_string(record).map_err(|e| unavailable(e.to_string()))?;
        self.store
            .put(&format!("session:{id}"), &text, Duration::from_secs(ttl))
            .await
            .map_err(unavailable)
    }

    async fn record(&self, id: &str) -> Result<Record, BffError> {
        let text = self
            .store
            .get(&format!("session:{id}"))
            .await
            .map_err(unavailable)?
            .ok_or(BffError::NoSession)?;
        serde_json::from_str(&text).map_err(|_| BffError::NoSession)
    }

    /// The live session behind a cookie, its access token refreshed when it is about to expire.
    pub async fn session(&self, id: &str) -> Result<Active, BffError> {
        let mut record = self.record(id).await?;
        let at = now();
        if record.access_expires_at <= at + REFRESH_MARGIN_SECS {
            record = self.refresh(id, record).await?;
        } else if at.saturating_sub(record.seen_at) >= 60 * 60 {
            // Use slides the idle window, written at most once an hour.
            record.seen_at = at;
            self.keep(id, &record).await?;
        }
        Ok(Active {
            sub: record.sub,
            sid: record.sid,
            access_token: record.access_token,
        })
    }

    /// Refresh a session's tokens, once across every process of the product.
    async fn refresh(&self, id: &str, record: Record) -> Result<Record, BffError> {
        let lock = format!("refresh:{id}");
        let mut record = record;
        for _ in 0..50 {
            let held = self
                .store
                .put_new(&lock, "1", Duration::from_secs(REFRESH_LOCK_SECS))
                .await
                .map_err(unavailable)?;
            if held {
                break;
            }
            // Another process is refreshing: use its result.
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            record = self.record(id).await?;
            if record.access_expires_at > now() + REFRESH_MARGIN_SECS {
                return Ok(record);
            }
        }
        let outcome = self.refresh_held(id, record).await;
        let _ = self.store.delete(&lock).await;
        outcome
    }

    async fn refresh_held(&self, id: &str, record: Record) -> Result<Record, BffError> {
        // Read again under the lock: another process may have refreshed in the meantime.
        let mut record = match self.record(id).await {
            Ok(fresh) if fresh.access_expires_at > now() + REFRESH_MARGIN_SECS => return Ok(fresh),
            Ok(fresh) => fresh,
            Err(_) => record,
        };
        let Some(refresh_token) = record.refresh_token.clone() else {
            self.drop_session(id).await;
            return Err(BffError::NoSession);
        };
        let tokens: TokenSet = match self
            .client
            .request(&[
                ("grant_type", "refresh_token"),
                ("refresh_token", &refresh_token),
                ("resource", &self.config.resource),
            ])
            .await
        {
            Ok(tokens) => tokens,
            // The grant ended (signed out, revoked, Propolis session gone): so does this session.
            Err(ClientError::Refused { error, .. }) if error == "invalid_grant" => {
                self.drop_session(id).await;
                return Err(BffError::NoSession);
            }
            Err(error) => return Err(error.into()),
        };
        let at = now();
        record.access_token = tokens.access_token;
        record.access_expires_at = at + tokens.expires_in;
        if tokens.refresh_token.is_some() {
            record.refresh_token = tokens.refresh_token;
        }
        record.seen_at = at;
        self.keep(id, &record).await?;
        Ok(record)
    }

    async fn drop_session(&self, id: &str) {
        let _ = self.store.delete(&format!("session:{id}")).await;
    }

    /// End the session behind a cookie: where to send the browser so Propolis ends its own (RP-
    /// Initiated Logout), with the `Set-Cookie` that clears the product's.
    pub async fn end(&self, id: &str) -> (String, String) {
        let hint = self.record(id).await.ok().map(|r| r.id_token);
        self.drop_session(id).await;
        let mut query = form_urlencoded::Serializer::new(String::new());
        query
            .append_pair("client_id", &self.config.client_id)
            .append_pair(
                "post_logout_redirect_uri",
                &self.config.post_logout_redirect_uri,
            );
        if let Some(hint) = &hint {
            query.append_pair("id_token_hint", hint);
        }
        (
            format!("{}/oauth/logout?{}", self.config.issuer, query.finish()),
            self.clear_cookie(),
        )
    }

    /// End the sessions a back-channel logout token names: one Propolis session (`sid`), or all of a
    /// person's (`sub` alone). Returns how many ended.
    pub async fn back_channel(&self, token: &str) -> Result<usize, Rejected> {
        let notice = logout::verify(
            &self.keys,
            &self.config.issuer,
            &self.config.client_id,
            token,
        )
        .await?;
        let index = match &notice.sid {
            Some(sid) => format!("sid:{sid}"),
            None => format!("sub:{}", notice.sub),
        };
        let ids = self.store.members(&index).await.unwrap_or_default();
        for id in &ids {
            self.drop_session(id).await;
        }
        let _ = self.store.delete(&index).await;
        Ok(ids.len())
    }

    /// The `Set-Cookie` value holding a session id.
    pub fn cookie(&self, id: &str) -> String {
        format!(
            "{}={id}; HttpOnly; Secure; SameSite=Lax; Path=/",
            self.config.cookie
        )
    }

    /// The `Set-Cookie` value that clears the session cookie.
    pub fn clear_cookie(&self) -> String {
        format!(
            "{}=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0",
            self.config.cookie
        )
    }

    /// The session id in a `Cookie` header, if it carries this product's.
    pub fn session_id<'a>(&self, cookie_header: &'a str) -> Option<&'a str> {
        cookie_header
            .split(';')
            .filter_map(|pair| pair.trim().split_once('='))
            .find(|(name, _)| *name == self.config.cookie)
            .map(|(_, value)| value)
            .filter(|value| !value.is_empty())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_challenge_is_the_verifiers_sha256_in_base64url() {
        // Computed apart, with Python's hashlib and base64.
        assert_eq!(
            challenge("dBjftJeZ4CVP-mJ92K9qxn9s5XNhw5Cs5Xj7HYPkRZE"),
            "vPq8NrjaaRAOkYI8zpvKhtvVGqHHtmbk0tx5OcndBlY"
        );
    }

    #[test]
    fn a_sign_in_comes_back_to_the_product_only() {
        assert_eq!(safe_return("/files/42?view=grid"), "/files/42?view=grid");
        for elsewhere in [
            "//evil.test/x",
            "/\\evil.test",
            "https://evil.test/",
            "files",
            "/a\nb",
        ] {
            assert_eq!(safe_return(elsewhere), "/", "{elsewhere}");
        }
    }

    #[test]
    fn the_settings_of_a_product_follow_the_design() {
        let config = BffConfig::for_product(
            "https://id.example.org/",
            "drive",
            "https://drive.example.org/",
        );
        assert_eq!(
            config.redirect_uri,
            "https://drive.example.org/auth/callback"
        );
        assert_eq!(config.resource, "https://drive.example.org");
        assert_eq!(config.cookie, "__Host-drive_session");
        assert_eq!(config.issuer, "https://id.example.org");
    }
}
