//! Propolis's token signing keys (design, section 7.2).
//!
//! Propolis publishes every key that signs, will sign or signed a token still alive at
//! `/oauth/jwks`, and keeps a new key published a day before it signs. So a verifier that caches
//! the set an hour never misses a scheduled rotation, and one that meets an unknown `kid` (an
//! emergency rotation) fetches the set again, at most once a minute so a stream of forged tokens
//! cannot make it hammer Propolis.
//!
//! Only ES256 keys are kept: they are what Propolis signs tokens with. A key of another type in the
//! set is ignored, never trusted with a weaker algorithm.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use jwt_simple::prelude::ES256PublicKey;
use serde_json::Value;
use tokio::sync::RwLock;
use tokio::time::Instant;

/// How long a fetched set is used before it is fetched again.
pub const MAX_AGE: Duration = Duration::from_secs(3600);
/// The shortest wait between two fetches.
pub const MIN_INTERVAL: Duration = Duration::from_secs(60);

#[derive(Default)]
struct Cache {
    keys: HashMap<String, ES256PublicKey>,
    fetched_at: Option<Instant>,
}

/// The keys of one issuer, shared by every request of a process.
#[derive(Clone)]
pub struct KeySet {
    jwks_uri: String,
    /// `None` for a fixed set, which never fetches.
    http: Option<reqwest::Client>,
    min_interval: Duration,
    cache: Arc<RwLock<Cache>>,
}

/// The ES256 keys of a JWK set, by `kid`.
pub fn parse(set: &Value) -> HashMap<String, ES256PublicKey> {
    let mut keys = HashMap::new();
    for jwk in set["keys"].as_array().into_iter().flatten() {
        let usable = jwk["kty"] == "EC"
            && jwk["crv"] == "P-256"
            && jwk.get("alg").is_none_or(|a| a == "ES256")
            && jwk.get("use").is_none_or(|u| u == "sig");
        let Some(kid) = jwk["kid"].as_str().filter(|_| usable) else {
            continue;
        };
        if let Ok(key) = ES256PublicKey::from_jwk(&jwk.to_string()) {
            keys.insert(kid.to_owned(), key);
        }
    }
    keys
}

impl KeySet {
    /// The keys published at `jwks_uri` (Propolis's is `<issuer>/oauth/jwks`).
    pub fn new(jwks_uri: impl Into<String>, http: reqwest::Client) -> Self {
        Self {
            jwks_uri: jwks_uri.into(),
            http: Some(http),
            min_interval: MIN_INTERVAL,
            cache: Arc::default(),
        }
    }

    /// The same, with another shortest wait between two fetches than a minute (tests use none).
    pub fn with_min_interval(mut self, min_interval: Duration) -> Self {
        self.min_interval = min_interval;
        self
    }

    /// The keys of `issuer`, at the address Propolis publishes them.
    pub fn of_issuer(issuer: &str, http: reqwest::Client) -> Self {
        Self::new(format!("{}/oauth/jwks", issuer.trim_end_matches('/')), http)
    }

    /// A set that never fetches, holding these keys: for tests, and for a product that receives the
    /// set another way.
    pub fn fixed(set: &Value) -> Self {
        let cache = Cache {
            keys: parse(set),
            fetched_at: Some(Instant::now()),
        };
        Self {
            jwks_uri: String::new(),
            http: None,
            min_interval: MIN_INTERVAL,
            cache: Arc::new(RwLock::new(cache)),
        }
    }

    async fn fetch(&self) -> Option<HashMap<String, ES256PublicKey>> {
        let set: Value = self
            .http
            .as_ref()?
            .get(&self.jwks_uri)
            .send()
            .await
            .ok()?
            .error_for_status()
            .ok()?
            .json()
            .await
            .ok()?;
        Some(parse(&set))
    }

    /// The key `kid` names, fetching the set when it is stale or does not have it, at most once a
    /// minute. `None` when Propolis does not publish such a key, or cannot be reached.
    pub async fn get(&self, kid: &str) -> Option<ES256PublicKey> {
        {
            let cache = self.cache.read().await;
            let fresh = cache
                .fetched_at
                .is_some_and(|at| at.elapsed() < MAX_AGE || self.http.is_none());
            if let Some(key) = cache.keys.get(kid).filter(|_| fresh) {
                return Some(key.clone());
            }
            // A fixed set has nothing to fetch.
            self.http.as_ref()?;
            if cache
                .fetched_at
                .is_some_and(|at| at.elapsed() < self.min_interval)
            {
                return cache.keys.get(kid).cloned();
            }
        }
        let mut cache = self.cache.write().await;
        // Another request may have fetched while this one waited for the lock.
        let recent = cache
            .fetched_at
            .is_some_and(|at| at.elapsed() < self.min_interval);
        if !recent {
            // On failure, keep what was known: Propolis being down must not reject every token.
            if let Some(keys) = self.fetch().await {
                cache.keys = keys;
            }
            cache.fetched_at = Some(Instant::now());
        }
        cache.keys.get(kid).cloned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use jwt_simple::prelude::*;
    use serde_json::json;

    fn jwk(key: &ES256KeyPair, kid: &str) -> Value {
        let mut jwk: Value = serde_json::from_str(&key.public_key().to_jwk()).unwrap();
        jwk["kid"] = kid.into();
        jwk
    }

    #[tokio::test]
    async fn only_es256_signing_keys_are_kept() {
        let key = ES256KeyPair::generate();
        let mut encryption = jwk(&key, "enc");
        encryption["use"] = "enc".into();
        let mut other = jwk(&key, "rs");
        other["alg"] = "RS256".into();
        let set = KeySet::fixed(&json!({ "keys": [
            jwk(&key, "a"),
            encryption,
            other,
            { "kty": "OKP", "crv": "Ed25519", "x": "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo", "kid": "ed" },
        ] }));
        assert!(set.get("a").await.is_some());
        for kid in ["enc", "rs", "ed", "missing"] {
            assert!(set.get(kid).await.is_none(), "{kid}");
        }
    }
}
