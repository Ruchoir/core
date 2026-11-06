//! Origins, as a browser writes them in `Origin` and as a service compares them.
//!
//! An origin is `scheme://host[:port]`, lower-cased, with no path and no trailing slash. A service
//! knows its own from its public base URL (`https://chat.example.org/`), and compares it with what a
//! browser sends ([`crate::SameSiteGuard`]), or writes it where a policy names it (`frame-ancestors`).

/// The origin of an absolute URL (`scheme://host[:port]`, lower-cased, no path, query, fragment or
/// trailing slash), as a browser writes it in `Origin`. `None` when the text has no scheme or no
/// host, which includes the `null` a browser sends for an opaque origin (a sandboxed frame, a
/// `file:` page).
///
/// ```
/// use ruchoir_http::origin::origin_of;
///
/// assert_eq!(
///     origin_of("HTTPS://Chat.Example.org:8443/api/v1?x#y").as_deref(),
///     Some("https://chat.example.org:8443")
/// );
/// assert_eq!(origin_of("null"), None);
/// ```
pub fn origin_of(url: &str) -> Option<String> {
    let (scheme, rest) = url.split_once("://")?;
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    (!scheme.is_empty() && !authority.is_empty()).then(|| {
        format!(
            "{}://{}",
            scheme.to_ascii_lowercase(),
            authority.to_ascii_lowercase()
        )
    })
}

/// A service's own origin, from its public base URL. A trailing slash or a path is dropped; a value
/// that is not an absolute URL is kept as written, without its trailing slashes, so a
/// misconfiguration shows in what is compared rather than silently matching nothing in particular.
///
/// ```
/// use ruchoir_http::origin::public_origin;
///
/// assert_eq!(public_origin("https://chat.example.org/"), "https://chat.example.org");
/// assert_eq!(public_origin("https://chat.example.org/app"), "https://chat.example.org");
/// ```
pub fn public_origin(public_base_url: &str) -> String {
    origin_of(public_base_url).unwrap_or_else(|| public_base_url.trim_end_matches('/').to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_origin_keeps_scheme_host_and_port_only() {
        assert_eq!(
            origin_of("https://chat.example.org").as_deref(),
            Some("https://chat.example.org")
        );
        assert_eq!(
            origin_of("http://localhost:3000/path").as_deref(),
            Some("http://localhost:3000")
        );
        assert_eq!(
            origin_of("https://[::1]:8443/").as_deref(),
            Some("https://[::1]:8443")
        );
    }

    #[test]
    fn text_without_scheme_or_host_has_no_origin() {
        assert_eq!(origin_of("null"), None);
        assert_eq!(origin_of("chat.example.org"), None);
        assert_eq!(origin_of("https://"), None);
        assert_eq!(origin_of("://chat.example.org"), None);
    }

    #[test]
    fn a_public_origin_drops_the_path_and_trailing_slash() {
        assert_eq!(
            public_origin("https://Chat.Example.org/"),
            "https://chat.example.org"
        );
        assert_eq!(public_origin("not a url/"), "not a url");
    }
}
