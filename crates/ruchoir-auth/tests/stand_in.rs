//! The crate against a stand-in Propolis: its key set, fetched and refreshed, and its token
//! endpoint.

use std::sync::{Arc, Mutex};
use std::time::Duration as StdDuration;

use axum::extract::State;
use axum::routing::{get, post};
use axum::{Json, Router};
use jwt_simple::prelude::*;
use ruchoir_auth::{Client, ClientError, Credentials, KeySet, Verifier};
use serde_json::{json, Value};

/// A token request as the stand-in received it.
type Form = Vec<(String, String)>;

#[derive(Clone, Default)]
struct Propolis {
    keys: Arc<Mutex<Vec<Value>>>,
    fetches: Arc<Mutex<usize>>,
    forms: Arc<Mutex<Vec<Form>>>,
}

async fn jwks(State(p): State<Propolis>) -> Json<Value> {
    *p.fetches.lock().unwrap() += 1;
    Json(json!({ "keys": p.keys.lock().unwrap().clone() }))
}

async fn token(State(p): State<Propolis>, body: String) -> (axum::http::StatusCode, Json<Value>) {
    let form: Form = form_urlencoded::parse(body.as_bytes())
        .map(|(k, v)| (k.into_owned(), v.into_owned()))
        .collect();
    let get = |name: &str| form.iter().find(|(k, _)| k == name).map(|(_, v)| v.clone());
    let n = {
        let mut forms = p.forms.lock().unwrap();
        forms.push(form.clone());
        forms.len()
    };
    if get("resource").as_deref() == Some("https://nowhere.example.org") {
        return (
            axum::http::StatusCode::BAD_REQUEST,
            Json(json!({ "error": "invalid_target" })),
        );
    }
    (
        axum::http::StatusCode::OK,
        Json(json!({ "access_token": format!("t{n}"), "token_type": "Bearer", "expires_in": 300 })),
    )
}

async fn stand_in() -> (String, Propolis) {
    let propolis = Propolis::default();
    let router = Router::new()
        .route("/oauth/jwks", get(jwks))
        .route("/oauth/token", post(token))
        .with_state(propolis.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, router).await });
    (format!("http://{address}"), propolis)
}

fn publish(propolis: &Propolis, key: &ES256KeyPair, kid: &str) {
    let mut jwk: Value = serde_json::from_str(&key.public_key().to_jwk()).unwrap();
    jwk["kid"] = kid.into();
    jwk["alg"] = "ES256".into();
    propolis.keys.lock().unwrap().push(jwk);
}

fn access(key: &ES256KeyPair, issuer: &str) -> String {
    let claims = Claims::with_custom_claims(json!({ "client_id": "chat" }), Duration::from_mins(5))
        .with_issuer(issuer)
        .with_audience("https://drive.example.org")
        .with_subject("person");
    let options = HeaderOptions {
        signature_type: Some("at+jwt".to_owned()),
        ..Default::default()
    };
    key.sign_with_options(claims, &options).unwrap()
}

#[tokio::test]
async fn a_new_key_is_fetched_once_a_minute_at_most() {
    let (issuer, propolis) = stand_in().await;
    let http = ruchoir_auth::http_client().unwrap();
    let first = ES256KeyPair::generate().with_key_id("k1");
    publish(&propolis, &first, "k1");
    let verifier = Verifier::new(
        &issuer,
        "https://drive.example.org",
        KeySet::of_issuer(&issuer, http.clone()),
    );
    assert!(verifier.verify(&access(&first, &issuer)).await.is_ok());
    assert!(verifier.verify(&access(&first, &issuer)).await.is_ok());
    assert_eq!(*propolis.fetches.lock().unwrap(), 1, "cached");

    // An emergency rotation: within the minute the new key is not fetched, a forged stream cannot
    // make the verifier hammer Propolis.
    let second = ES256KeyPair::generate().with_key_id("k2");
    publish(&propolis, &second, "k2");
    assert!(verifier.verify(&access(&second, &issuer)).await.is_err());
    assert_eq!(*propolis.fetches.lock().unwrap(), 1);

    // Past the wait, an unknown key fetches the set again.
    let eager = Verifier::new(
        &issuer,
        "https://drive.example.org",
        KeySet::of_issuer(&issuer, http).with_min_interval(StdDuration::ZERO),
    );
    assert!(eager.verify(&access(&first, &issuer)).await.is_ok());
    assert!(eager.verify(&access(&second, &issuer)).await.is_ok());
}

#[tokio::test]
async fn service_tokens_are_kept_and_exchanges_are_not() {
    let (issuer, propolis) = stand_in().await;
    let credentials = Credentials::new("drive", Ed25519KeyPair::generate(), "drive-auth");
    let client = Client::new(&issuer, credentials, ruchoir_auth::http_client().unwrap());

    let one = client
        .client_credentials(None, &["propolis:organizations.read"])
        .await
        .unwrap();
    let again = client
        .client_credentials(None, &["propolis:organizations.read"])
        .await
        .unwrap();
    assert_eq!(one, again, "kept until shortly before it expires");
    let other = client
        .client_credentials(Some("https://chat.example.org"), &[])
        .await
        .unwrap();
    assert_ne!(one, other);

    let a = client
        .exchange("subject", "https://chat.example.org", &[])
        .await
        .unwrap();
    let b = client
        .exchange("subject", "https://chat.example.org", &[])
        .await
        .unwrap();
    assert_ne!(a, b, "an exchange is asked each time");

    let forms = propolis.forms.lock().unwrap().clone();
    let last = forms.last().unwrap();
    let get = |name: &str| {
        last.iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
    };
    assert_eq!(
        get("grant_type"),
        Some("urn:ietf:params:oauth:grant-type:token-exchange")
    );
    assert_eq!(
        get("subject_token_type"),
        Some("urn:ietf:params:oauth:token-type:access_token")
    );
    assert_eq!(
        get("client_assertion_type"),
        Some("urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
    );
    assert!(get("client_assertion").is_some());

    match client
        .exchange("subject", "https://nowhere.example.org", &[])
        .await
    {
        Err(ClientError::Refused { status: 400, error }) => assert_eq!(error, "invalid_target"),
        other => panic!("{other:?}"),
    }
}
