//! What a Ruchoir product needs from Propolis, the identity provider of every instance (design
//! `docs/design/openid-connect.md` of `Ruchoir/propolis`, sections 6, 7 and 15).
//!
//! - [`keys`]: Propolis's token signing keys, fetched from its JWK set and cached; an unknown key
//!   fetches the set again, at most once a minute.
//! - [`access`]: checking an access token a request carries: issuer, audience, `typ: at+jwt`,
//!   expiry, and the algorithm of the key that signed it, never the one the token names (RFC 8725).
//! - [`logout`]: checking a back-channel logout token, to end the sessions it names.
//! - [`client`]: the product as Propolis's client: its `private_key_jwt` assertions, and the tokens
//!   it asks in its own name (`client_credentials`) or for the person who called it (the token
//!   exchange, RFC 8693).
//!
//! - [`session`]: a product's browser session, as a backend-for-frontend of Propolis: sign-in by
//!   code and PKCE, an opaque `__Host-` cookie, tokens kept and refreshed in the product's store,
//!   RP-Initiated and back-channel logout.
//!
//! Every check is done here once, so no product writes its own: a product that verifies a token
//! with this crate verifies it as every other product does.

pub mod access;
pub mod client;
pub mod keys;
pub mod logout;
pub mod session;

pub use access::{AccessToken, Rejected, Verifier};
pub use client::{Client, ClientError, Credentials, TokenSet};
pub use keys::KeySet;
pub use logout::LogoutNotice;
#[cfg(feature = "valkey")]
pub use session::ValkeyStore;
pub use session::{Active, Bff, BffConfig, BffError, Callback, Finished, MemoryStore, Store};

/// The clock skew every check accepts, as Propolis does.
pub const SKEW_SECS: u64 = 60;

/// The HTTP client of the crate: rustls with the ring provider, no redirect followed, a short
/// timeout. A product may build its own and hand it to [`KeySet::new`] and [`Client::new`].
pub fn http_client() -> reqwest::Result<reqwest::Client> {
    // Installed once for the process; a second install changes nothing.
    let _ = rustls::crypto::ring::default_provider().install_default();
    reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(std::time::Duration::from_secs(10))
        .user_agent(concat!("ruchoir-auth/", env!("CARGO_PKG_VERSION")))
        .build()
}
