//! A product's browser session against a stand-in Propolis: a sign-in from the authorization
//! request to the cookie, the access token refreshed once, a replayed or misdirected callback
//! refused, a silent sign-in that needs the person, and both logouts.

use std::sync::{Arc, Mutex};

use axum::extract::State;
use axum::http::StatusCode;
use axum::routing::post;
use axum::{Json, Router};
use jwt_simple::prelude::*;
use ruchoir_auth::session::challenge;
use ruchoir_auth::{Bff, BffConfig, BffError, Callback, Client, Credentials, KeySet, MemoryStore};
use serde_json::{json, Value};

/// A token request as the stand-in received it.
type Form = Vec<(String, String)>;

/// What the stand-in Propolis knows of the sign-in in progress, and what it was asked.
#[derive(Clone, Default)]
struct Propolis {
    issuer: Arc<Mutex<String>>,
    key: Arc<Mutex<Option<ES256KeyPair>>>,
    /// The nonce and challenge of the authorization request.
    pending: Arc<Mutex<Option<(String, String)>>>,
    forms: Arc<Mutex<Vec<Form>>>,
}

fn reply(status: StatusCode, body: Value) -> (StatusCode, Json<Value>) {
    (status, Json(body))
}

async fn token(State(p): State<Propolis>, body: String) -> (StatusCode, Json<Value>) {
    let form: Vec<(String, String)> = form_urlencoded::parse(body.as_bytes())
        .map(|(k, v)| (k.into_owned(), v.into_owned()))
        .collect();
    p.forms.lock().unwrap().push(form.clone());
    let get = |name: &str| form.iter().find(|(k, _)| k == name).map(|(_, v)| v.clone());
    let issuer = p.issuer.lock().unwrap().clone();
    let refused = |error: &str| reply(StatusCode::BAD_REQUEST, json!({ "error": error }));
    match get("grant_type").as_deref() {
        Some("authorization_code") => {
            let Some((nonce, expected)) = p.pending.lock().unwrap().take() else {
                return refused("invalid_grant");
            };
            // PKCE: the verifier must be the one behind the challenge.
            let verifier = get("code_verifier").unwrap_or_default();
            if get("code").as_deref() != Some("c1") || challenge(&verifier) != expected {
                return refused("invalid_grant");
            }
            let claims = Claims::with_custom_claims(
                json!({ "sid": "s1", "name": "Ada Lovelace", "locale": "en-GB", "zoneinfo": "Europe/London" }),
                Duration::from_mins(5),
            )
                .with_issuer(&issuer)
                .with_audience("drive")
                .with_subject("person-1")
                .with_nonce(nonce);
            let id_token = p
                .key
                .lock()
                .unwrap()
                .as_ref()
                .unwrap()
                .sign(claims)
                .unwrap();
            // Thirty seconds left: the first use refreshes it.
            reply(
                StatusCode::OK,
                json!({ "access_token": "a1", "expires_in": 30, "refresh_token": "r1", "id_token": id_token, "token_type": "Bearer" }),
            )
        }
        Some("refresh_token") if get("refresh_token").as_deref() == Some("r1") => reply(
            StatusCode::OK,
            json!({ "access_token": "a2", "expires_in": 300, "refresh_token": "r2", "token_type": "Bearer" }),
        ),
        _ => refused("invalid_grant"),
    }
}

struct Setup {
    bff: Bff<MemoryStore>,
    propolis: Propolis,
    key: ES256KeyPair,
    issuer: String,
}

async fn setup() -> Setup {
    let propolis = Propolis::default();
    let router = Router::new()
        .route("/oauth/token", post(token))
        .with_state(propolis.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let issuer = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move { axum::serve(listener, router).await });

    let key = ES256KeyPair::generate().with_key_id("k1");
    let mut jwk: Value = serde_json::from_str(&key.public_key().to_jwk()).unwrap();
    jwk["kid"] = "k1".into();
    *propolis.issuer.lock().unwrap() = issuer.clone();
    *propolis.key.lock().unwrap() = Some(
        ES256KeyPair::from_bytes(&key.to_bytes())
            .unwrap()
            .with_key_id("k1"),
    );

    let config = BffConfig::for_product(&issuer, "drive", "https://drive.example.org");
    let credentials = Credentials::new("drive", Ed25519KeyPair::generate(), "drive-auth-1");
    let client = Client::new(&issuer, credentials, ruchoir_auth::http_client().unwrap());
    let bff = Bff::new(
        config,
        client,
        KeySet::fixed(&json!({ "keys": [jwk] })),
        MemoryStore::default(),
    );
    Setup {
        bff,
        propolis,
        key,
        issuer,
    }
}

/// The query of the authorization request a sign-in sends the browser to.
fn query(url: &str) -> Vec<(String, String)> {
    let (_, query) = url.split_once('?').unwrap();
    form_urlencoded::parse(query.as_bytes())
        .map(|(k, v)| (k.into_owned(), v.into_owned()))
        .collect()
}

fn param(query: &[(String, String)], name: &str) -> Option<String> {
    query
        .iter()
        .find(|(k, _)| k == name)
        .map(|(_, v)| v.clone())
}

/// Leave for Propolis and come back with code `c1`: the authorization request's query.
async fn sign_in(s: &Setup, return_to: &str) -> Vec<(String, String)> {
    let url = s.bff.begin(return_to, false).await.unwrap();
    assert!(url.starts_with(&format!("{}/oauth/authorize?", s.issuer)));
    let q = query(&url);
    *s.propolis.pending.lock().unwrap() = Some((
        param(&q, "nonce").unwrap(),
        param(&q, "code_challenge").unwrap(),
    ));
    q
}

fn callback(s: &Setup, state: &str) -> Callback {
    Callback {
        code: Some("c1".to_owned()),
        state: Some(state.to_owned()),
        iss: Some(s.issuer.clone()),
        error: None,
    }
}

#[tokio::test]
async fn a_person_signs_in_and_the_token_is_refreshed_once() {
    let s = setup().await;
    let q = sign_in(&s, "/files/7?view=grid").await;
    assert_eq!(param(&q, "response_type").as_deref(), Some("code"));
    assert_eq!(param(&q, "client_id").as_deref(), Some("drive"));
    assert_eq!(param(&q, "code_challenge_method").as_deref(), Some("S256"));
    assert_eq!(
        param(&q, "resource").as_deref(),
        Some("https://drive.example.org")
    );
    assert_eq!(
        param(&q, "redirect_uri").as_deref(),
        Some("https://drive.example.org/auth/callback")
    );
    assert_eq!(
        param(&q, "scope").as_deref(),
        Some("openid profile email organizations")
    );
    assert!(param(&q, "prompt").is_none());

    let state = param(&q, "state").unwrap();
    let finished = s.bff.finish(&callback(&s, &state)).await.unwrap();
    assert_eq!(finished.return_to, "/files/7?view=grid");
    assert!(finished.set_cookie.starts_with("__Host-drive_session="));
    assert!(finished
        .set_cookie
        .ends_with("; HttpOnly; Secure; SameSite=Lax; Path=/"));
    let header = finished.set_cookie.split(';').next().unwrap().to_owned();
    let id = s
        .bff
        .session_id(&format!("theme=dark; {header}"))
        .unwrap()
        .to_owned();

    // The callback is taken once.
    assert!(matches!(
        s.bff.finish(&callback(&s, &state)).await,
        Err(BffError::Invalid("state"))
    ));

    let first = s.bff.session(&id).await.unwrap();
    assert_eq!(first.sub, "person-1");
    assert_eq!(first.sid.as_deref(), Some("s1"));
    // What the ID token said of the person stays with the session.
    assert_eq!(first.profile.name.as_deref(), Some("Ada Lovelace"));
    assert_eq!(first.profile.locale.as_deref(), Some("en-GB"));
    assert_eq!(first.profile.zoneinfo.as_deref(), Some("Europe/London"));
    assert_eq!(first.access_token, "a2", "thirty seconds left: refreshed");
    let second = s.bff.session(&id).await.unwrap();
    assert_eq!(second.access_token, "a2");
    let refreshes = s
        .propolis
        .forms
        .lock()
        .unwrap()
        .iter()
        .filter(|f| {
            f.iter()
                .any(|(k, v)| k == "grant_type" && v == "refresh_token")
        })
        .count();
    assert_eq!(refreshes, 1);

    // Signing out: the session is gone, and Propolis is told which one with the ID token.
    let (url, clear) = s.bff.end(&id).await;
    assert!(url.starts_with(&format!("{}/oauth/logout?", s.issuer)));
    let q = query(&url);
    assert!(param(&q, "id_token_hint").is_some());
    assert_eq!(
        param(&q, "post_logout_redirect_uri").as_deref(),
        Some("https://drive.example.org/")
    );
    assert!(clear.contains("Max-Age=0"));
    assert!(matches!(s.bff.session(&id).await, Err(BffError::NoSession)));
}

#[tokio::test]
async fn a_misdirected_or_forged_callback_opens_nothing() {
    let s = setup().await;
    let q = sign_in(&s, "https://evil.test/").await;
    let state = param(&q, "state").unwrap();
    // Another issuer answered (RFC 9207).
    let mut forged = callback(&s, &state);
    forged.iss = Some("https://id.evil.test".to_owned());
    assert!(matches!(
        s.bff.finish(&forged).await,
        Err(BffError::Invalid("iss"))
    ));
    // A state the product never issued.
    assert!(matches!(
        s.bff.finish(&callback(&s, "made-up")).await,
        Err(BffError::Invalid("state"))
    ));

    // A verifier that does not match the challenge: Propolis refuses the code.
    let q = sign_in(&s, "https://evil.test/").await;
    s.propolis.pending.lock().unwrap().as_mut().unwrap().1 = "another".to_owned();
    let state = param(&q, "state").unwrap();
    assert!(matches!(
        s.bff.finish(&callback(&s, &state)).await,
        Err(BffError::Refused(e)) if e == "invalid_grant"
    ));
}

#[tokio::test]
async fn a_silent_sign_in_that_needs_the_person_says_so() {
    let s = setup().await;
    let url = s.bff.begin("/files", true).await.unwrap();
    let q = query(&url);
    assert_eq!(param(&q, "prompt").as_deref(), Some("none"));
    let answer = Callback {
        state: param(&q, "state"),
        iss: Some(s.issuer.clone()),
        error: Some("login_required".to_owned()),
        code: None,
    };
    assert!(matches!(
        s.bff.finish(&answer).await,
        Err(BffError::LoginRequired { return_to }) if return_to == "/files"
    ));
}

#[tokio::test]
async fn propolis_ends_a_session_through_the_back_channel() {
    let s = setup().await;
    let q = sign_in(&s, "/").await;
    let finished = s
        .bff
        .finish(&callback(&s, &param(&q, "state").unwrap()))
        .await
        .unwrap();
    let header = finished.set_cookie.split(';').next().unwrap().to_owned();
    let id = s.bff.session_id(&header).unwrap().to_owned();

    let claims = Claims::with_custom_claims(
        json!({ "sid": "s1", "events": { "http://schemas.openid.net/event/backchannel-logout": {} } }),
        Duration::from_mins(2),
    )
    .with_issuer(&s.issuer)
    .with_audience("drive")
    .with_subject("person-1")
    .with_jwt_id("j1");
    let options = HeaderOptions {
        signature_type: Some("logout+jwt".to_owned()),
        ..Default::default()
    };
    let token = s.key.sign_with_options(claims, &options).unwrap();
    assert_eq!(s.bff.back_channel(&token).await.unwrap(), 1);
    assert!(matches!(s.bff.session(&id).await, Err(BffError::NoSession)));
    // A token that is not Propolis's ends nothing.
    assert!(s.bff.back_channel("not.a.token").await.is_err());
}
