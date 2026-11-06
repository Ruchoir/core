//! The address a request comes from, as the reverse proxies in front of the service saw it.
//!
//! It is what a service keys an anonymous rate limit on (a sign-in attempt, a public link). The
//! buckets of a signed-in person, keyed by session, stay in each service: only it knows what a
//! session is.
//!
//! A service is reached through a reverse proxy, so the connection's peer is the proxy, and the
//! client's address is in `X-Forwarded-For`. That header is a list each proxy **appends** the address
//! it saw to: the entries a client cannot choose are the ones on the right, written by proxies the
//! service trusts, and everything left of them is whatever the client sent. So the list is read from
//! the right, past the trusted proxies, and the first address that is not one of them is the client:
//!
//! ```text
//! client 203.0.113.9 sends   X-Forwarded-For: 198.51.100.1          (forged)
//! the proxy 10.0.0.2 makes   X-Forwarded-For: 198.51.100.1, 203.0.113.9
//! the service sees peer 10.0.0.2 (trusted): from the right, 203.0.113.9 is not trusted: the client
//! ```
//!
//! Taking the **first** entry instead, as many libraries do, would let a client rotate a made-up one
//! and get a fresh bucket on every request. `X-Real-IP` and `Forwarded` are not read at all: a proxy
//! that does not overwrite them would pass the client's own through.
//!
//! The header is only read when the peer itself is a trusted proxy ([`TrustedProxies`]). A request
//! that reached the service directly, past the proxy, is keyed by its peer, whatever it claims.
//! List the proxies' own addresses, never a range clients live in: a client inside a trusted range
//! is taken for a proxy, and the entry left of it, which it chose, for the client.
//!
//! With one trusted proxy this gives what the current API does (the last entry of the header, or
//! the peer without one), and it also holds behind a chain of proxies (a load balancer, then nginx).
//!
//! The peer is the axum `ConnectInfo<SocketAddr>` of the connection: serve the router with
//! `into_make_service_with_connect_info::<SocketAddr>()`.

use std::fmt;
use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;
use std::sync::Arc;

use axum::extract::{ConnectInfo, FromRef, FromRequestParts, OptionalFromRequestParts};
use axum::http::request::Parts;
use axum::http::{Extensions, HeaderMap, Request};

use crate::Problem;

/// The header the proxies append the address they saw to.
pub const X_FORWARDED_FOR: &str = "x-forwarded-for";

/// One trusted proxy, or a range of them: an address (`10.0.0.2`, `::1`) or a network in CIDR
/// notation (`10.0.0.0/24`, `fd00::/8`).
///
/// An IPv4 address seen through an IPv6 socket (`::ffff:10.0.0.2`) is the IPv4 address it maps, on
/// both sides of the comparison.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProxyRange {
    network: IpAddr,
    prefix: u8,
}

impl ProxyRange {
    /// Whether `ip` is in this range.
    pub fn contains(&self, ip: IpAddr) -> bool {
        match (self.network, ip.to_canonical()) {
            (IpAddr::V4(network), IpAddr::V4(ip)) => {
                let mask = u32::MAX
                    .checked_shl(32 - u32::from(self.prefix))
                    .unwrap_or(0);
                u32::from(network) & mask == u32::from(ip) & mask
            }
            (IpAddr::V6(network), IpAddr::V6(ip)) => {
                let mask = u128::MAX
                    .checked_shl(128 - u32::from(self.prefix))
                    .unwrap_or(0);
                u128::from(network) & mask == u128::from(ip) & mask
            }
            _ => false,
        }
    }
}

/// A proxy address or range that could not be read, with the text as it was given.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InvalidProxyRange(pub String);

impl fmt::Display for InvalidProxyRange {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "not an address or a CIDR range of trusted proxies: {:?}",
            self.0
        )
    }
}

impl std::error::Error for InvalidProxyRange {}

impl FromStr for ProxyRange {
    type Err = InvalidProxyRange;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        let invalid = || InvalidProxyRange(text.to_owned());
        let (address, prefix) = match text.trim().split_once('/') {
            Some((address, prefix)) => (address, Some(prefix)),
            None => (text.trim(), None),
        };
        let network = address
            .parse::<IpAddr>()
            .map_err(|_| invalid())?
            .to_canonical();
        let width = if network.is_ipv4() { 32 } else { 128 };
        let prefix = match prefix {
            Some(prefix) => prefix
                .parse::<u8>()
                .ok()
                .filter(|&prefix| prefix <= width)
                .ok_or_else(invalid)?,
            None => width,
        };
        Ok(Self { network, prefix })
    }
}

/// The reverse proxies whose `X-Forwarded-For` a service believes. Empty by default: a service
/// reached directly reads no forwarding header at all.
///
/// It is cheap to clone, and usually read from the service's configuration as a comma-separated
/// list:
///
/// ```
/// use ruchoir_http::client_ip::TrustedProxies;
///
/// let trusted: TrustedProxies = "10.0.0.2, fd00::/8".parse().unwrap();
/// assert!(trusted.trusts("10.0.0.2".parse().unwrap()));
/// assert!(!trusted.trusts("10.0.0.3".parse().unwrap()));
/// assert!("".parse::<TrustedProxies>().unwrap().is_empty());
/// ```
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TrustedProxies {
    ranges: Arc<[ProxyRange]>,
}

impl TrustedProxies {
    /// No trusted proxy: every request is keyed by its peer.
    pub fn none() -> Self {
        Self::default()
    }

    /// These proxies and ranges.
    pub fn new(ranges: impl IntoIterator<Item = ProxyRange>) -> Self {
        Self {
            ranges: ranges.into_iter().collect(),
        }
    }

    /// Whether no proxy is trusted.
    pub fn is_empty(&self) -> bool {
        self.ranges.is_empty()
    }

    /// Whether `ip` is a trusted proxy.
    pub fn trusts(&self, ip: IpAddr) -> bool {
        self.ranges.iter().any(|range| range.contains(ip))
    }
}

impl FromStr for TrustedProxies {
    type Err = InvalidProxyRange;

    /// A comma-separated list of addresses and CIDR ranges; empty entries are skipped, so an empty
    /// text is no proxy at all.
    fn from_str(list: &str) -> Result<Self, Self::Err> {
        let ranges = list
            .split(',')
            .map(str::trim)
            .filter(|entry| !entry.is_empty())
            .map(str::parse)
            .collect::<Result<Vec<ProxyRange>, _>>()?;
        Ok(Self::new(ranges))
    }
}

/// One entry of `X-Forwarded-For`: an address, possibly with a port (`203.0.113.9:4711`,
/// `[2001:db8::1]:4711`) or in brackets, as some proxies write it.
fn forwarded_entry(entry: &str) -> Option<IpAddr> {
    let ip = entry
        .parse::<IpAddr>()
        .ok()
        .or_else(|| entry.parse::<SocketAddr>().ok().map(|socket| socket.ip()))
        .or_else(|| {
            entry
                .strip_prefix('[')
                .and_then(|rest| rest.strip_suffix(']'))
                .and_then(|inner| inner.parse::<IpAddr>().ok())
        })?;
    Some(ip.to_canonical())
}

/// The client's address: from `X-Forwarded-For` when `peer` is a trusted proxy, read from the right
/// past the trusted proxies, otherwise `peer` itself (see the module documentation).
///
/// Reading stops at an entry that is not an address, since no trusted proxy writes one: everything
/// from there on came from the client, and the last trusted address before it is the best that is
/// known. When every entry is a trusted proxy, the leftmost one is the answer.
pub fn client_ip(headers: &HeaderMap, peer: IpAddr, trusted: &TrustedProxies) -> IpAddr {
    let mut client = peer.to_canonical();
    if !trusted.trusts(client) {
        return client;
    }
    // Several headers are one list, in order: the last header holds the rightmost entries.
    for value in headers.get_all(X_FORWARDED_FOR).iter().rev() {
        let Ok(value) = value.to_str() else {
            return client;
        };
        for entry in value.rsplit(',').map(str::trim) {
            if entry.is_empty() {
                continue;
            }
            let Some(ip) = forwarded_entry(entry) else {
                return client;
            };
            client = ip;
            if !trusted.trusts(ip) {
                return ip;
            }
        }
    }
    client
}

/// The connection's peer, as axum's `ConnectInfo` gives it (or a bare `SocketAddr` some servers
/// and tests insert instead).
fn peer_of(extensions: &Extensions) -> Option<IpAddr> {
    extensions
        .get::<ConnectInfo<SocketAddr>>()
        .map(|ConnectInfo(peer)| peer.ip())
        .or_else(|| extensions.get::<SocketAddr>().map(SocketAddr::ip))
}

/// [`client_ip`] for a whole request: `None` when the request carries no peer address, which happens
/// only when the server was not set up with connect info.
pub fn client_ip_of<B>(request: &Request<B>, trusted: &TrustedProxies) -> Option<IpAddr> {
    peer_of(request.extensions()).map(|peer| client_ip(request.headers(), peer, trusted))
}

/// The client's address as an extractor, with the [`TrustedProxies`] taken from the router's state
/// (`FromRef`).
///
/// Without a peer address (a server not set up with connect info) it refuses the request with a
/// `500`: a rate limit that cannot tell clients apart is a mistake to fix, not a case to run with.
/// `Option<ClientIp>` gives `None` instead, for a caller that has a fallback.
///
/// ```
/// use axum::{routing::post, Router};
/// use ruchoir_http::client_ip::{ClientIp, TrustedProxies};
///
/// let app: Router = Router::new()
///     .route("/api/v1/sign-in", post(|ClientIp(ip): ClientIp| async move { ip.to_string() }))
///     .with_state("10.0.0.2".parse::<TrustedProxies>().unwrap());
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ClientIp(pub IpAddr);

impl fmt::Display for ClientIp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl<S> FromRequestParts<S> for ClientIp
where
    TrustedProxies: FromRef<S>,
    S: Send + Sync,
{
    type Rejection = Problem;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let trusted = TrustedProxies::from_ref(state);
        match peer_of(&parts.extensions) {
            Some(peer) => Ok(Self(client_ip(&parts.headers, peer, &trusted))),
            None => {
                tracing::error!(
                    "no peer address: serve the router with `into_make_service_with_connect_info`"
                );
                Err(Problem::internal())
            }
        }
    }
}

impl<S> OptionalFromRequestParts<S> for ClientIp
where
    TrustedProxies: FromRef<S>,
    S: Send + Sync,
{
    type Rejection = std::convert::Infallible;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &S,
    ) -> Result<Option<Self>, Self::Rejection> {
        let trusted = TrustedProxies::from_ref(state);
        Ok(peer_of(&parts.extensions).map(|peer| Self(client_ip(&parts.headers, peer, &trusted))))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::{to_bytes, Body};
    use axum::http::{HeaderValue, StatusCode};
    use axum::routing::get;
    use axum::Router;
    use tower::ServiceExt;

    const PROXY: &str = "10.0.0.2";

    fn ip(text: &str) -> IpAddr {
        text.parse().unwrap()
    }

    fn trusted(list: &str) -> TrustedProxies {
        list.parse().unwrap()
    }

    fn headers(forwarded: &[&str]) -> HeaderMap {
        let mut headers = HeaderMap::new();
        for value in forwarded {
            headers.append(X_FORWARDED_FOR, HeaderValue::from_str(value).unwrap());
        }
        headers
    }

    fn behind_proxy(forwarded: &[&str]) -> IpAddr {
        client_ip(&headers(forwarded), ip(PROXY), &trusted(PROXY))
    }

    #[test]
    fn forged_first_entries_with_the_same_last_one_give_the_same_client() {
        assert_eq!(
            behind_proxy(&["198.51.100.1, 203.0.113.9"]),
            ip("203.0.113.9")
        );
        assert_eq!(
            behind_proxy(&["198.51.100.2, 203.0.113.9"]),
            ip("203.0.113.9")
        );
    }

    #[test]
    fn the_last_entry_wins_across_repeated_headers() {
        assert_eq!(
            behind_proxy(&["198.51.100.1", "203.0.113.9"]),
            ip("203.0.113.9")
        );
    }

    #[test]
    fn without_a_forwarded_header_the_peer_is_the_client() {
        assert_eq!(behind_proxy(&[]), ip(PROXY));
    }

    #[test]
    fn a_real_ip_header_is_ignored() {
        let mut headers = headers(&[]);
        headers.insert("x-real-ip", HeaderValue::from_static("198.51.100.1"));
        let client = client_ip(&headers, ip(PROXY), &trusted(PROXY));
        assert_eq!(client, ip(PROXY));
    }

    #[test]
    fn a_peer_that_is_not_a_trusted_proxy_cannot_claim_an_address() {
        // Reached directly, past the proxy: the header is the client's own words.
        let forwarded = headers(&["198.51.100.1"]);
        let peer = ip("203.0.113.9");
        assert_eq!(client_ip(&forwarded, peer, &trusted(PROXY)), peer);
        assert_eq!(client_ip(&forwarded, peer, &TrustedProxies::none()), peer);
    }

    #[test]
    fn a_chain_of_trusted_proxies_is_walked_past() {
        // A load balancer (10.0.0.1) in front of nginx (10.0.0.2).
        let forwarded = headers(&["198.51.100.1, 203.0.113.9, 10.0.0.1"]);
        let client = client_ip(&forwarded, ip(PROXY), &trusted("10.0.0.0/24"));
        assert_eq!(client, ip("203.0.113.9"));
    }

    #[test]
    fn reading_stops_at_an_entry_that_is_not_an_address() {
        let forwarded = headers(&["198.51.100.1, unknown, 10.0.0.1"]);
        let client = client_ip(&forwarded, ip(PROXY), &trusted("10.0.0.0/24"));
        assert_eq!(client, ip("10.0.0.1"));
    }

    #[test]
    fn entries_with_ports_or_brackets_are_read() {
        assert_eq!(behind_proxy(&["203.0.113.9:4711"]), ip("203.0.113.9"));
        assert_eq!(behind_proxy(&["[2001:db8::1]:4711"]), ip("2001:db8::1"));
        assert_eq!(behind_proxy(&["[2001:db8::1]"]), ip("2001:db8::1"));
    }

    #[test]
    fn a_mapped_ipv4_peer_is_its_ipv4_address() {
        let forwarded = headers(&["203.0.113.9"]);
        let client = client_ip(&forwarded, ip("::ffff:10.0.0.2"), &trusted(PROXY));
        assert_eq!(client, ip("203.0.113.9"));
    }

    #[test]
    fn ranges_hold_what_they_say() {
        let range: ProxyRange = "10.0.0.0/8".parse().unwrap();
        assert!(range.contains(ip("10.255.0.1")));
        assert!(!range.contains(ip("11.0.0.1")));
        assert!(!range.contains(ip("::1")));
        let everything: ProxyRange = "0.0.0.0/0".parse().unwrap();
        assert!(everything.contains(ip("203.0.113.9")));
        let v6: ProxyRange = "fd00::/8".parse().unwrap();
        assert!(v6.contains(ip("fd12::1")));
        assert!(!v6.contains(ip("fe80::1")));
        let single: ProxyRange = "::1".parse().unwrap();
        assert!(single.contains(ip("::1")));
        assert!(!single.contains(ip("::2")));
    }

    #[test]
    fn a_wrong_range_is_refused_with_its_text() {
        for text in [
            "10.0.0.0/33",
            "fd00::/129",
            "proxy",
            "10.0.0.0/x",
            "10.0.0.0/",
        ] {
            assert_eq!(
                text.parse::<ProxyRange>(),
                Err(InvalidProxyRange(text.to_owned())),
                "{text}"
            );
        }
        assert!("10.0.0.2, nope".parse::<TrustedProxies>().is_err());
    }

    fn app() -> Router {
        Router::new()
            .route(
                "/",
                get(|ClientIp(ip): ClientIp| async move { ip.to_string() }),
            )
            .route(
                "/optional",
                get(|ip: Option<ClientIp>| async move {
                    ip.map_or_else(|| "unknown".to_owned(), |ip| ip.to_string())
                }),
            )
            .with_state(trusted(PROXY))
    }

    async fn send(path: &str, peer: Option<&str>, forwarded: &[&str]) -> (StatusCode, String) {
        let mut request = Request::builder().uri(path);
        for value in forwarded {
            request = request.header(X_FORWARDED_FOR, *value);
        }
        let mut request = request.body(Body::empty()).unwrap();
        if let Some(peer) = peer {
            let peer: SocketAddr = format!("{peer}:4000").parse().unwrap();
            request.extensions_mut().insert(ConnectInfo(peer));
        }
        let response = app().oneshot(request).await.unwrap();
        let status = response.status();
        let body = to_bytes(response.into_body(), 1024).await.unwrap();
        (status, String::from_utf8(body.to_vec()).unwrap())
    }

    #[tokio::test]
    async fn the_extractor_reads_through_the_trusted_proxy() {
        let (status, body) = send("/", Some(PROXY), &["198.51.100.1, 203.0.113.9"]).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body, "203.0.113.9");
    }

    #[tokio::test]
    async fn the_extractor_keys_a_direct_request_by_its_peer() {
        let (_, body) = send("/", Some("203.0.113.7"), &["198.51.100.1"]).await;
        assert_eq!(body, "203.0.113.7");
    }

    #[tokio::test]
    async fn without_connect_info_the_extractor_refuses() {
        let (status, body) = send("/", None, &["203.0.113.9"]).await;
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        assert!(body.contains("internal_error"));
        let (status, body) = send("/optional", None, &["203.0.113.9"]).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body, "unknown");
    }

    #[test]
    fn a_request_is_read_from_its_extensions() {
        let mut request = Request::builder()
            .header(X_FORWARDED_FOR, "203.0.113.9")
            .body(())
            .unwrap();
        assert_eq!(client_ip_of(&request, &trusted(PROXY)), None);
        request
            .extensions_mut()
            .insert("10.0.0.2:4000".parse::<SocketAddr>().unwrap());
        assert_eq!(
            client_ip_of(&request, &trusted(PROXY)),
            Some(ip("203.0.113.9"))
        );
    }
}
