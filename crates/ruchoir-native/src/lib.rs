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

/// The HTTP client of the crate: rustls with the ring provider, no redirect followed, a short
/// timeout.
pub fn http_client() -> reqwest::Result<reqwest::Client> {
    // Installed once for the process; a second install changes nothing.
    let _ = rustls::crypto::ring::default_provider().install_default();
    reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(std::time::Duration::from_secs(10))
        .user_agent(concat!("ruchoir-native/", env!("CARGO_PKG_VERSION")))
        .build()
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
    fn only_https_and_loopback_are_secure() {
        assert!(super::secure("https://id.example.org"));
        assert!(super::secure("http://127.0.0.1:8123/callback"));
        assert!(super::secure("http://[::1]:80/"));
        assert!(!super::secure("http://id.example.org"));
        assert!(!super::secure("http://127.0.0.1.evil.test/"));
        assert!(!super::secure("https://"));
    }
}
