//! Discovery of an instance: the hub serves its manifest at
//! `https://hub.<domain>/.well-known/ruchoir-manifest` (the file the installer writes), each product
//! describes itself at `/.well-known/ruchoir-product`, and Propolis at
//! `/.well-known/openid-configuration`.

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::client::NativeError;
use crate::secure;

/// What a product says about itself (ADR 0004 of Ruchoir/.github).
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct ProductDescription {
    pub name: String,
    pub version: String,
    /// The API majors served, each under `/api/<major>/`.
    pub api: Vec<String>,
    /// The features served: an app decides from these, never from `version`.
    pub features: Vec<String>,
}

/// A product of the instance.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Product {
    /// The name the manifest lists it under: `drive`, `calendar`, `chat`, `hub`.
    pub name: String,
    /// Its origin, which is also the `resource` of its access tokens (RFC 8707).
    pub url: String,
    /// `None` when the product did not answer: the rest of the instance still works.
    pub description: Option<ProductDescription>,
}

/// An instance, as its manifest describes it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Instance {
    pub domain: String,
    /// Propolis's origin, the issuer of the instance's tokens.
    pub issuer: String,
    /// Every service of the manifest but Propolis, by name.
    pub products: Vec<Product>,
}

/// The part of Propolis's discovery document the client reads.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct IssuerMetadata {
    pub issuer: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub jwks_uri: String,
    #[serde(default)]
    pub revocation_endpoint: Option<String>,
}

/// The manifest's address for a domain (`example.org`), or the address itself when given one.
pub fn manifest_url(domain_or_url: &str) -> String {
    if domain_or_url.contains("://") {
        return domain_or_url.to_owned();
    }
    format!(
        "https://hub.{}/.well-known/ruchoir-manifest",
        domain_or_url.trim_end_matches('/')
    )
}

async fn get_json(http: &reqwest::Client, url: &str) -> Result<Value, NativeError> {
    if !secure(url) {
        return Err(NativeError::Discovery(format!(
            "not a secure address: {url}"
        )));
    }
    let response = http
        .get(url)
        .header("accept", "application/json")
        .send()
        .await
        .map_err(|e| NativeError::Network(e.to_string()))?;
    if !response.status().is_success() {
        return Err(NativeError::Discovery(format!(
            "{url} answered {}",
            response.status().as_u16()
        )));
    }
    response
        .json::<Value>()
        .await
        .ok()
        .filter(Value::is_object)
        .ok_or_else(|| NativeError::Discovery(format!("{url}: not a JSON object")))
}

/// The instance a domain or a manifest address names, and the description of each product.
pub async fn discover_instance(
    http: &reqwest::Client,
    domain_or_url: &str,
) -> Result<Instance, NativeError> {
    let manifest = get_json(http, &manifest_url(domain_or_url)).await?;
    let unreadable = || NativeError::Discovery("the manifest is not one this client reads".into());
    let issuer = manifest["services"]["propolis"]["url"]
        .as_str()
        .filter(|u| secure(u))
        .ok_or_else(unreadable)?;
    let domain = manifest["domain"].as_str().ok_or_else(unreadable)?;
    if manifest["version"] != 1 {
        return Err(unreadable());
    }
    let mut products = Vec::new();
    for (name, service) in manifest["services"].as_object().into_iter().flatten() {
        let Some(url) = service["url"].as_str().filter(|u| secure(u)) else {
            continue;
        };
        if name == "propolis" {
            continue;
        }
        let url = url.trim_end_matches('/').to_owned();
        let description = get_json(http, &format!("{url}/.well-known/ruchoir-product"))
            .await
            .ok()
            .and_then(|d| serde_json::from_value(d).ok());
        products.push(Product {
            name: name.clone(),
            url,
            description,
        });
    }
    Ok(Instance {
        domain: domain.to_owned(),
        issuer: issuer.trim_end_matches('/').to_owned(),
        products,
    })
}

/// Propolis's discovery document, which must name `issuer` exactly (OpenID Connect Discovery, 4.3).
pub async fn discover_issuer(
    http: &reqwest::Client,
    issuer: &str,
) -> Result<IssuerMetadata, NativeError> {
    let url = format!(
        "{}/.well-known/openid-configuration",
        issuer.trim_end_matches('/')
    );
    let document = get_json(http, &url).await?;
    let mut metadata: IssuerMetadata = serde_json::from_value(document)
        .map_err(|_| NativeError::Discovery("an endpoint is missing".into()))?;
    if metadata.issuer != issuer {
        return Err(NativeError::Discovery(
            "the discovery document names another issuer".into(),
        ));
    }
    let endpoints = [
        &metadata.authorization_endpoint,
        &metadata.token_endpoint,
        &metadata.jwks_uri,
    ];
    if endpoints.iter().any(|e| !secure(e)) {
        return Err(NativeError::Discovery("an endpoint is not secure".into()));
    }
    metadata.revocation_endpoint = metadata.revocation_endpoint.filter(|e| secure(e));
    Ok(metadata)
}
