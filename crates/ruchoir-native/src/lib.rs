//! How the Ruchoir desktop's core signs in with Propolis, following OAuth 2.0 for Native Apps
//! (RFC 8252) and Propolis's design (`docs/design/openid-connect.md` of `Ruchoir/propolis`, section
//! 11). The `@ruchoir/native-client` package holds the same logic in TypeScript for the mobile app.
//!
//! - [`discovery`]: the instance from its domain (the hub's `/.well-known/ruchoir-manifest`, each
//!   product's `/.well-known/ruchoir-product`) and Propolis's discovery document.
//! - [`redirect`]: what the app provides around the browser: [`Browser`] opens the authorization
//!   request, [`Redirect`] receives the browser back; [`Loopback`] is the loopback listener of RFC
//!   8252, section 7.3.
//! - [`storage`]: [`Storage`], the system keychain as the app gives it, and [`MemoryStorage`].
//! - [`client`]: [`NativeClient`]: sign-in by code and `S256` PKCE with `state`, `nonce`, `iss`
//!   (RFC 9207) and `resource` (RFC 8707); one refresh token per issuer in the keychain, rotated;
//!   one access token per product in memory, refreshed a minute before expiry, one refresh at a
//!   time per issuer; sign-out by revocation (RFC 7009).
//!
//! The interface never sees a token: it asks the core, which calls the products with them.

pub mod client;
pub mod discovery;
pub mod redirect;
pub mod storage;

pub use client::{Account, NativeClient, NativeError, PendingSignIn, SignInTarget};
pub use discovery::{Instance, IssuerMetadata, Product, ProductDescription};
pub use redirect::{Browser, Loopback, Redirect};
pub use storage::{MemoryStorage, Storage};

/// The environment variable naming a PEM file of extra certificate authorities, trusted besides
/// the system's: a development instance's own authority (`ruchoir-install dev`), which the system
/// store does not hold.
pub const EXTRA_CA_ENV: &str = "RUCHOIR_EXTRA_CA";

/// The HTTP client of the crate: rustls with the ring provider, certificates checked by the
/// platform verifier (the system store), no redirect followed, a short timeout.
///
/// When [`EXTRA_CA_ENV`] names a PEM file, its authorities are trusted as well as the system's;
/// an unreadable or empty file is an error rather than a silent fallback.
pub fn http_client() -> Result<reqwest::Client, NativeError> {
    match std::env::var_os(EXTRA_CA_ENV).filter(|path| !path.is_empty()) {
        None => http_client_with_extra_ca(None),
        Some(path) => {
            let pem = std::fs::read(&path).map_err(|e| {
                NativeError::Certificate(format!("{}: {e}", std::path::Path::new(&path).display()))
            })?;
            http_client_with_extra_ca(Some(&pem))
        }
    }
}

/// [`http_client`] with the extra authorities given as a PEM bundle instead of read from the
/// environment, for an app that keeps the authority itself. `None` trusts the system store only.
pub fn http_client_with_extra_ca(pem: Option<&[u8]>) -> Result<reqwest::Client, NativeError> {
    // Installed once for the process; a second install changes nothing.
    let _ = rustls::crypto::ring::default_provider().install_default();
    let mut builder = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(std::time::Duration::from_secs(10))
        .user_agent(concat!("ruchoir-native/", env!("CARGO_PKG_VERSION")));
    if let Some(pem) = pem {
        let certs = reqwest::Certificate::from_pem_bundle(pem)
            .map_err(|e| NativeError::Certificate(e.to_string()))?;
        if certs.is_empty() {
            return Err(NativeError::Certificate(
                "no certificate in the PEM bundle".into(),
            ));
        }
        // Merged with the platform verifier's roots, not replacing them.
        builder = builder.tls_certs_merge(certs);
    }
    builder
        .build()
        .map_err(|e| NativeError::Certificate(e.to_string()))
}

/// Whether an address may carry tokens: `https`, or `http` to this device's loopback.
pub fn secure(address: &str) -> bool {
    if let Some(rest) = address.strip_prefix("https://") {
        return rest
            .split(['/', '?', '#'])
            .next()
            .is_some_and(|h| !h.is_empty());
    }
    let Some(rest) = address.strip_prefix("http://") else {
        return false;
    };
    let host = rest.split(['/', '?', '#']).next().unwrap_or_default();
    let name = match host.strip_prefix("[::1]") {
        Some(port) => return port.is_empty() || port.starts_with(':'),
        None => host.split(':').next().unwrap_or_default(),
    };
    matches!(name, "127.0.0.1" | "localhost")
}

#[cfg(test)]
mod tests {
    #[test]
    fn extra_ca_must_hold_a_certificate() {
        assert!(super::http_client_with_extra_ca(None).is_ok());
        assert!(matches!(
            super::http_client_with_extra_ca(Some(b"not a certificate")),
            Err(super::NativeError::Certificate(_))
        ));
    }

    #[test]
    fn only_https_and_loopback_are_secure() {
        assert!(super::secure("https://id.example.org"));
        assert!(super::secure("http://127.0.0.1:8123/callback"));
        assert!(super::secure("http://[::1]:80/"));
        assert!(!super::secure("http://id.example.org"));
        assert!(!super::secure("http://127.0.0.1.evil.test/"));
        assert!(!super::secure("https://"));
    }
}
