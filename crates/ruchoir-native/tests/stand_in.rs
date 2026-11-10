//! The crate against a stand-in instance: the hub's manifest, a product's description, and a
//! Propolis with its discovery document, key set, token and revocation endpoints. The browser is a
//! task that plays the person signing in and comes back to the loopback listener.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};

use axum::extract::State;
use axum::http::StatusCode;
use axum::routing::{get, post};
use axum::{Json, Router};
use jwt_simple::prelude::*;
use ruchoir_native::discovery::discover_instance;
use ruchoir_native::{Browser, Loopback, MemoryStorage, NativeClient, NativeError, SignInTarget};
use serde_json::{json, Value};

type Form = HashMap<String, String>;

struct Code {
    challenge: String,
    nonce: String,
    resources: Vec<String>,
}

#[derive(Clone)]
struct Propolis {
    issuer: Arc<Mutex<String>>,
    key: Arc<ES256KeyPair>,
    codes: Arc<Mutex<HashMap<String, Code>>>,
    live: Arc<Mutex<HashSet<String>>>,
    revoked: Arc<Mutex<Vec<String>>>,
    requests: Arc<Mutex<Vec<Form>>>,
    expires_in: Arc<Mutex<u64>>,
    counter: Arc<Mutex<u64>>,
    /// A nonce to put in the ID token instead of the right one.
    wrong_nonce: Arc<Mutex<bool>>,
}

impl Propolis {
    fn issuer(&self) -> String {
        self.issuer.lock().unwrap().clone()
    }

    fn next(&self) -> u64 {
        let mut counter = self.counter.lock().unwrap();
        *counter += 1;
        *counter
    }

    fn refresh_token(&self) -> String {
        let token = format!("r{}", self.next());
        self.live.lock().unwrap().insert(token.clone());
        token
    }
}

fn read_form(body: &str) -> Form {
    form_urlencoded::parse(body.as_bytes())
        .map(|(k, v)| (k.into_owned(), v.into_owned()))
        .collect()
}

async fn manifest(State(p): State<Propolis>) -> Json<Value> {
    let issuer = p.issuer();
    Json(json!({
        "version": 1,
        "domain": "example.org",
        "services": {
            "propolis": { "url": issuer },
            "drive": { "url": format!("{issuer}/drive") },
            "calendar": { "url": format!("{issuer}/calendar") },
        }
    }))
}

async fn drive() -> Json<Value> {
    Json(json!({ "name": "drive", "version": "0.3.0", "api": ["v1"], "features": ["versions"] }))
}

async fn configuration(State(p): State<Propolis>) -> Json<Value> {
    let issuer = p.issuer();
    Json(json!({
        "issuer": issuer,
        "authorization_endpoint": format!("{issuer}/oauth/authorize"),
        "token_endpoint": format!("{issuer}/oauth/token"),
        "jwks_uri": format!("{issuer}/oauth/jwks"),
        "revocation_endpoint": format!("{issuer}/oauth/revoke"),
        "authorization_response_iss_parameter_supported": true,
    }))
}

async fn jwks(State(p): State<Propolis>) -> Json<Value> {
    let mut jwk: Value = serde_json::from_str(&p.key.public_key().to_jwk()).unwrap();
    jwk["kid"] = "k1".into();
    jwk["alg"] = "ES256".into();
    Json(json!({ "keys": [jwk] }))
}

async fn revoke(State(p): State<Propolis>, body: String) -> StatusCode {
    let form = read_form(&body);
    p.live.lock().unwrap().remove(&form["token"]);
    p.revoked.lock().unwrap().push(form["token"].clone());
    StatusCode::OK
}

async fn token(State(p): State<Propolis>, body: String) -> (StatusCode, Json<Value>) {
    let form = read_form(&body);
    p.requests.lock().unwrap().push(form.clone());
    let refused = |error: &str| (StatusCode::BAD_REQUEST, Json(json!({ "error": error })));
    let n = p.next();
    let expires_in = *p.expires_in.lock().unwrap();
    match form.get("grant_type").map(String::as_str) {
        Some("authorization_code") => {
            let Some(code) = p.codes.lock().unwrap().remove(&form["code"]) else {
                return refused("invalid_grant");
            };
            if ruchoir_auth::session::challenge(&form["code_verifier"]) != code.challenge {
                return refused("invalid_grant");
            }
            let nonce = if *p.wrong_nonce.lock().unwrap() {
                "other".to_owned()
            } else {
                code.nonce
            };
            let claims =
                Claims::with_custom_claims(json!({ "name": "Ada" }), Duration::from_mins(5))
                    .with_issuer(p.issuer())
                    .with_audience(&form["client_id"])
                    .with_subject("person-1")
                    .with_nonce(nonce);
            let id_token = p.key.sign(claims).unwrap();
            let resource = code
                .resources
                .first()
                .cloned()
                .unwrap_or_else(|| p.issuer());
            (
                StatusCode::OK,
                Json(json!({
                    "access_token": format!("a{n}@{resource}"),
                    "token_type": "Bearer",
                    "expires_in": expires_in,
                    "refresh_token": p.refresh_token(),
                    "id_token": id_token,
                })),
            )
        }
        Some("refresh_token") => {
            if !p.live.lock().unwrap().remove(&form["refresh_token"]) {
                return refused("invalid_grant");
            }
            (
                StatusCode::OK,
                Json(json!({
                    "access_token": format!("a{n}@{}", form["resource"]),
                    "token_type": "Bearer",
                    "expires_in": expires_in,
                    "refresh_token": p.refresh_token(),
                })),
            )
        }
        _ => refused("unsupported_grant_type"),
    }
}

async fn stand_in() -> Propolis {
    let propolis = Propolis {
        issuer: Arc::default(),
        key: Arc::new(ES256KeyPair::generate().with_key_id("k1")),
        codes: Arc::default(),
        live: Arc::default(),
        revoked: Arc::default(),
        requests: Arc::default(),
        expires_in: Arc::new(Mutex::new(300)),
        counter: Arc::default(),
        wrong_nonce: Arc::default(),
    };
    let router = Router::new()
        .route("/.well-known/ruchoir-manifest", get(manifest))
        .route("/drive/.well-known/ruchoir-product", get(drive))
        .route("/.well-known/openid-configuration", get(configuration))
        .route("/oauth/jwks", get(jwks))
        .route("/oauth/token", post(token))
        .route("/oauth/revoke", post(revoke))
        .with_state(propolis.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    *propolis.issuer.lock().unwrap() = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move { axum::serve(listener, router).await });
    propolis
}

/// The person's browser: Propolis signs them in and sends the browser back to the redirect URI.
struct FakeBrowser {
    propolis: Propolis,
    /// The `iss` the response carries.
    iss: String,
    /// A `state` to send back instead of the right one.
    state: Option<String>,
}

impl FakeBrowser {
    fn honest(propolis: &Propolis) -> Self {
        Self {
            propolis: propolis.clone(),
            iss: propolis.issuer(),
            state: None,
        }
    }
}

impl Browser for FakeBrowser {
    fn open(&self, url: &str) -> Result<(), String> {
        let (_, query) = url.split_once('?').ok_or("no query")?;
        let pairs: Vec<(String, String)> = form_urlencoded::parse(query.as_bytes())
            .map(|(k, v)| (k.into_owned(), v.into_owned()))
            .collect();
        let get = |name: &str| {
            pairs
                .iter()
                .find(|(k, _)| k == name)
                .map(|(_, v)| v.clone())
                .unwrap_or_default()
        };
        assert_eq!(get("code_challenge_method"), "S256");
        assert_eq!(get("response_type"), "code");
        let code = format!("c{}", self.propolis.next());
        self.propolis.codes.lock().unwrap().insert(
            code.clone(),
            Code {
                challenge: get("code_challenge"),
                nonce: get("nonce"),
                resources: pairs
                    .iter()
                    .filter(|(k, _)| k == "resource")
                    .map(|(_, v)| v.clone())
                    .collect(),
            },
        );
        let back = form_urlencoded::Serializer::new(String::new())
            .append_pair("code", &code)
            .append_pair("state", self.state.as_deref().unwrap_or(&get("state")))
            .append_pair("iss", &self.iss)
            .finish();
        let target = format!("{}?{back}", get("redirect_uri"));
        tokio::spawn(async move {
            // A stray request first, which the listener answers and ignores.
            let http = reqwest::Client::new();
            let favicon = target.replace("/callback?", "/favicon.ico?");
            let _ = http.get(favicon).send().await;
            let _ = http.get(target).send().await;
        });
        Ok(())
    }
}

async fn loopback() -> Loopback {
    Loopback::bind("<p>Done</p>", std::time::Duration::from_secs(10))
        .await
        .unwrap()
}

fn client() -> NativeClient<MemoryStorage> {
    NativeClient::new(
        ruchoir_native::http_client().unwrap(),
        "ruchoir-desktop",
        MemoryStorage::default(),
    )
}

#[tokio::test]
async fn an_instance_is_discovered_and_signed_in_through_the_loopback() {
    let propolis = stand_in().await;
    let issuer = propolis.issuer();
    let http = ruchoir_native::http_client().unwrap();
    let instance = discover_instance(&http, &format!("{issuer}/.well-known/ruchoir-manifest"))
        .await
        .unwrap();
    assert_eq!(instance.issuer, issuer);
    let drive = format!("{issuer}/drive");
    let names: Vec<_> = instance
        .products
        .iter()
        .map(|p| {
            (
                p.name.as_str(),
                p.description.as_ref().map(|d| d.version.as_str()),
            )
        })
        .collect();
    // A product that does not answer is still listed, without a description.
    assert_eq!(names, [("calendar", None), ("drive", Some("0.3.0"))]);

    let app = client();
    let account = app
        .sign_in(
            &SignInTarget::from(&instance),
            &FakeBrowser::honest(&propolis),
            loopback().await,
        )
        .await
        .unwrap();
    assert_eq!(account.subject, "person-1");
    assert_eq!(account.name.as_deref(), Some("Ada"));
    assert_eq!(app.issuers().await.unwrap(), vec![issuer.clone()]);

    let exchange = propolis.requests.lock().unwrap()[0].clone();
    assert_eq!(exchange["grant_type"], "authorization_code");
    assert!(exchange["redirect_uri"].starts_with("http://127.0.0.1:"));
    assert!(!exchange.contains_key("client_secret"));

    // The code's access token is the first resource's, and is kept in memory.
    let calendar = format!("{issuer}/calendar");
    let first = app.access_token(&issuer, &calendar).await.unwrap();
    assert!(first.ends_with(&format!("@{calendar}")));
    assert_eq!(propolis.requests.lock().unwrap().len(), 1);
    // Another product: two calls at once make one refresh.
    let (a, b) = tokio::join!(
        app.access_token(&issuer, &drive),
        app.access_token(&issuer, &drive)
    );
    assert_eq!(a.as_ref().unwrap(), b.as_ref().unwrap());
    assert!(a.unwrap().ends_with(&format!("@{drive}")));
    assert_eq!(propolis.requests.lock().unwrap().len(), 2);
    let stored = app.storage().values();
    assert!(stored.iter().any(|v| v.contains("refresh_token")));
    assert!(
        stored.iter().all(|v| !v.contains("@http")),
        "access tokens are never stored"
    );
}

#[tokio::test]
async fn tokens_with_less_than_a_minute_left_are_refreshed_and_rotated() {
    let propolis = stand_in().await;
    let issuer = propolis.issuer();
    *propolis.expires_in.lock().unwrap() = 30;
    let storage = MemoryStorage::default();
    let app = NativeClient::new(
        ruchoir_native::http_client().unwrap(),
        "ruchoir-desktop",
        storage,
    );
    let target = SignInTarget {
        issuer: issuer.clone(),
        resources: vec![format!("{issuer}/drive")],
    };
    app.sign_in(&target, &FakeBrowser::honest(&propolis), loopback().await)
        .await
        .unwrap();
    let drive = format!("{issuer}/drive");
    let one = app.access_token(&issuer, &drive).await.unwrap();
    let two = app.access_token(&issuer, &drive).await.unwrap();
    assert_ne!(one, two, "thirty seconds left is less than the margin");
    let requests = propolis.requests.lock().unwrap().clone();
    assert_eq!(requests.len(), 3);
    assert_ne!(requests[1]["refresh_token"], requests[2]["refresh_token"]);
    assert_eq!(requests[2]["resource"], drive);
    assert_eq!(
        propolis.live.lock().unwrap().len(),
        1,
        "one live refresh token"
    );
}

#[tokio::test]
async fn the_response_must_name_the_issuer_and_the_state() {
    let propolis = stand_in().await;
    let issuer = propolis.issuer();
    let target = SignInTarget {
        issuer: issuer.clone(),
        resources: vec![],
    };
    let app = client();

    let mut browser = FakeBrowser::honest(&propolis);
    browser.iss = "https://id.other.example".into();
    let result = app.sign_in(&target, &browser, loopback().await).await;
    assert_eq!(result, Err(NativeError::Issuer));

    let mut browser = FakeBrowser::honest(&propolis);
    browser.state = Some("forged".into());
    let result = app.sign_in(&target, &browser, loopback().await).await;
    assert_eq!(result, Err(NativeError::State));

    *propolis.wrong_nonce.lock().unwrap() = true;
    let result = app
        .sign_in(&target, &FakeBrowser::honest(&propolis), loopback().await)
        .await;
    assert_eq!(result, Err(NativeError::IdToken));
    assert!(app.issuers().await.unwrap().is_empty());
}

#[tokio::test]
async fn a_refused_refresh_token_ends_the_session_and_sign_out_revokes() {
    let propolis = stand_in().await;
    let issuer = propolis.issuer();
    let target = SignInTarget {
        issuer: issuer.clone(),
        resources: vec![],
    };
    let app = client();
    app.sign_in(&target, &FakeBrowser::honest(&propolis), loopback().await)
        .await
        .unwrap();
    propolis.live.lock().unwrap().clear();
    let drive = format!("{issuer}/drive");
    assert_eq!(
        app.access_token(&issuer, &drive).await,
        Err(NativeError::SessionEnded)
    );
    assert!(app.account(&issuer).await.unwrap().is_none());
    assert_eq!(
        app.access_token(&issuer, &drive).await,
        Err(NativeError::SignedOut)
    );

    app.sign_in(&target, &FakeBrowser::honest(&propolis), loopback().await)
        .await
        .unwrap();
    let live: Vec<String> = propolis.live.lock().unwrap().iter().cloned().collect();
    app.sign_out(&issuer).await.unwrap();
    assert_eq!(*propolis.revoked.lock().unwrap(), live);
    assert!(app.issuers().await.unwrap().is_empty());
}
