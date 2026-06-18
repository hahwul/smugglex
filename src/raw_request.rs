//! Parsing of raw HTTP requests supplied via `--raw-request <FILE>`.
//!
//! A raw request file is the kind of artifact you get from "Copy to file" in
//! Burp Suite or a captured proxy log: a request line, a block of headers, an
//! empty line, and an optional body. smugglex uses such a file as a *template*
//! for the request it crafts — method, request-target, Host and the remaining
//! headers (cookies, auth tokens, content-type, ...) are reused, while the body
//! is discarded because the smuggling payloads generate their own body and
//! manage `Content-Length` / `Transfer-Encoding` themselves.

use crate::error::{Result, SmugglexError};

/// Headers that the smuggling payload generators add or control on their own.
/// They are stripped from a raw request so we never emit duplicates or fight
/// the crafted `Content-Length` / `Transfer-Encoding` desync vectors.
const MANAGED_HEADERS: [&str; 4] = ["host", "content-length", "transfer-encoding", "connection"];

/// A raw HTTP request parsed from a file, reduced to the pieces smugglex reuses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawRequest {
    /// HTTP method from the request line (e.g. `GET`, `POST`).
    pub method: String,
    /// Request-target including any query string (e.g. `/search?q=1`).
    pub target: String,
    /// Connection host (from the Host header, or from an absolute-form request line).
    pub host: String,
    /// Connection port, when explicitly present; otherwise derived from the scheme.
    pub port: Option<u16>,
    /// Scheme override for absolute-form request lines (`http`/`https`).
    /// `None` for origin-form requests, where the caller applies `--raw-request-proto`.
    pub scheme: Option<String>,
    /// Exact `Host` header value to emit, preserving any `:port` suffix.
    pub host_header: String,
    /// Remaining headers as `Name: Value`, with [`MANAGED_HEADERS`] stripped out.
    pub headers: Vec<String>,
    /// Whether the file carried a (non-empty) message body after the header block.
    /// The body itself is discarded — the smuggling payloads generate their own —
    /// but the flag lets the CLI note the discard in verbose mode.
    pub had_body: bool,
}

impl RawRequest {
    /// Build the synthetic URL used purely to derive the *connection* target
    /// (scheme, host, port) — its path is always `/`.
    ///
    /// The real request-target ([`RawRequest::target`]) is applied separately and
    /// verbatim downstream, so embedding it here is intentionally avoided: routing
    /// it through `Url::parse` would normalize dot-segments (`/a/../b` → `/b`) and
    /// drop anything after a `#`, mangling path-based smuggling payloads.
    ///
    /// `proto_default` (from `--raw-request-proto`) supplies the scheme for
    /// origin-form requests, which carry none of their own.
    pub fn connect_url(&self, proto_default: &str) -> String {
        let scheme = self.scheme.as_deref().unwrap_or(proto_default);
        let use_tls = scheme == "https";
        let port = self.port.unwrap_or(if use_tls { 443 } else { 80 });
        format!("{}://{}:{}/", scheme, self.host, port)
    }
}

/// Merge captured headers with user-supplied `-H` headers.
///
/// Captured headers come first (preserving the template order), then the user's
/// `-H` headers are appended so an explicit `-H` is *additive* and never silently
/// dropped. Overlapping names are intentionally kept as duplicates rather than
/// de-duplicated: smuggling tests sometimes rely on header repetition, and we
/// want to exercise the origin server's own first/last precedence.
pub fn merge_headers(mut captured: Vec<String>, user: &[String]) -> Vec<String> {
    captured.extend(user.iter().cloned());
    captured
}

/// Parse the textual contents of a raw HTTP request file.
///
/// Accepts both `\r\n` and bare `\n` line endings. The request body (anything
/// after the first blank line) is intentionally ignored. Origin-form requests
/// require a `Host` header to determine the target; absolute-form request lines
/// (`GET https://host/path HTTP/1.1`) derive the host, port and scheme from the
/// line itself.
pub fn parse_raw_request(content: &str) -> Result<RawRequest> {
    let mut lines = content.split('\n').map(|l| l.trim_end_matches('\r'));

    let request_line = lines
        .by_ref()
        .find(|l| !l.trim().is_empty())
        .ok_or_else(|| SmugglexError::InvalidInput("raw request file is empty".to_string()))?;

    let mut parts = request_line.split_whitespace();
    let method = parts
        .next()
        .ok_or_else(|| SmugglexError::InvalidInput("raw request missing method".to_string()))?
        .to_string();
    // Guard against pointing `--raw-request` at a non-HTTP file (e.g. an accidental
    // JSON or HTML document): a valid method is an RFC 7230 token, so anything with
    // quotes/braces/colons gives a clear error instead of a baffling downstream one.
    if method.is_empty() || !method.bytes().all(is_tchar) {
        return Err(SmugglexError::InvalidInput(format!(
            "'{}' is not a valid HTTP method; the first line does not look like an HTTP request line (expected e.g. 'GET /path HTTP/1.1')",
            method
        )));
    }
    let target_raw = parts
        .next()
        .ok_or_else(|| {
            SmugglexError::InvalidInput("raw request missing request target".to_string())
        })?
        .to_string();

    // Headers run until the first blank line; everything after is the body.
    let mut headers: Vec<String> = Vec::new();
    let mut host_header: Option<String> = None;
    let mut had_body = false;
    while let Some(line) = lines.next() {
        if line.trim().is_empty() {
            // Header section ends at the blank line; any non-empty line after it is
            // the message body (discarded, but recorded so the CLI can note it).
            had_body = lines.any(|l| !l.trim().is_empty());
            break;
        }
        let Some((name, value)) = line.split_once(':') else {
            // Not a well-formed header line (e.g. an obsolete folded continuation);
            // skip it rather than emitting something malformed.
            continue;
        };
        let name = name.trim();
        let value = value.trim();
        if name.eq_ignore_ascii_case("host") {
            host_header = Some(value.to_string());
            continue;
        }
        if is_managed_header(name) {
            continue;
        }
        headers.push(format!("{}: {}", name, value));
    }

    let mut request = if is_absolute_form(&target_raw) {
        parse_absolute_form(method, &target_raw, host_header, headers)?
    } else {
        parse_origin_form(method, target_raw, host_header, headers)?
    };
    request.had_body = had_body;
    Ok(request)
}

/// Build a [`RawRequest`] from an origin-form request line (`/path?query`),
/// taking the target host from the mandatory `Host` header.
fn parse_origin_form(
    method: String,
    target: String,
    host_header: Option<String>,
    headers: Vec<String>,
) -> Result<RawRequest> {
    // Only origin-form targets (`/path?query`) are usable as a smuggling
    // template. Reject authority-form (`CONNECT host:port`) and asterisk-form
    // (`OPTIONS *`) request lines, which would otherwise be concatenated into an
    // invalid synthetic URL downstream.
    if !target.starts_with('/') {
        return Err(SmugglexError::InvalidInput(format!(
            "unsupported request target '{}' (expected an absolute path like '/path' or an absolute URL)",
            target
        )));
    }
    let host_header = host_header.ok_or_else(|| {
        SmugglexError::InvalidInput(
            "raw request is missing a Host header (required to determine the target)".to_string(),
        )
    })?;
    let (host, port) = split_host_port(&host_header)?;
    // A present-but-empty Host (`Host:` or `Host:   `) leaves no connection
    // target; rejecting it here fails fast with a clear message instead of a
    // confusing downstream "URL parse error: empty host" against the synthetic
    // connect URL.
    if host.is_empty() {
        return Err(SmugglexError::InvalidInput(
            "raw request Host header is empty (required to determine the target)".to_string(),
        ));
    }
    Ok(RawRequest {
        method,
        target,
        host,
        port,
        scheme: None,
        host_header,
        headers,
        had_body: false,
    })
}

/// Build a [`RawRequest`] from an absolute-form request line
/// (`http(s)://host[:port]/path?query`), deriving host, port and scheme from it.
fn parse_absolute_form(
    method: String,
    target_raw: &str,
    host_header: Option<String>,
    headers: Vec<String>,
) -> Result<RawRequest> {
    let url = url::Url::parse(target_raw)
        .map_err(|e| SmugglexError::InvalidInput(format!("invalid request target: {}", e)))?;
    // Use `host()` (not `host_str()`) so IPv6 literals keep their brackets
    // (`[::1]`); the unbracketed form would build invalid URLs and Host headers.
    let host = url
        .host()
        .ok_or_else(|| SmugglexError::InvalidInput("request target has no host".to_string()))?
        .to_string();
    let port = url.port();

    // Preserve the literal request-target (path + query + any fragment) verbatim
    // rather than reading `url.path()`/`url.query()`, which normalize dot-segments
    // (`/a/../b` → `/b`) and drop everything after `#`. Slice the original string
    // from where the authority ends — the first `/`, `?` or `#` after the
    // `scheme://` prefix — none of which can appear unescaped in the authority.
    // `url.scheme()` is lowercased but the same length as the captured scheme, so
    // the byte offset is correct even for `HTTP://`.
    let after_scheme = &target_raw[url.scheme().len() + 3..];
    let target = match after_scheme.find(['/', '?', '#']) {
        // A real path: take it (and everything after) as-is.
        Some(i) if after_scheme.as_bytes()[i] == b'/' => after_scheme[i..].to_string(),
        // Query/fragment but no path (`http://host?q`): synthesize a root path so
        // the request-target stays valid origin-form (`/?q`).
        Some(i) => format!("/{}", &after_scheme[i..]),
        // Authority only (`http://host`): default to root.
        None => "/".to_string(),
    };

    // Prefer an explicit Host header; otherwise reconstruct it from the URL.
    let host_header = host_header.unwrap_or_else(|| match port {
        Some(p) => format!("{}:{}", host, p),
        None => host.clone(),
    });

    Ok(RawRequest {
        method,
        target,
        host,
        port,
        scheme: Some(url.scheme().to_string()),
        host_header,
        headers,
        had_body: false,
    })
}

/// Whether a request-target is absolute-form (carries its own scheme).
fn is_absolute_form(target: &str) -> bool {
    let starts_with_ci = |prefix: &str| {
        target
            .get(..prefix.len())
            .is_some_and(|head| head.eq_ignore_ascii_case(prefix))
    };
    starts_with_ci("http://") || starts_with_ci("https://")
}

/// Whether a header is one smugglex sets/controls itself for smuggling payloads.
fn is_managed_header(name: &str) -> bool {
    MANAGED_HEADERS
        .iter()
        .any(|managed| name.eq_ignore_ascii_case(managed))
}

/// Whether a byte is an RFC 7230 token character (`tchar`), the set a valid HTTP
/// method is built from. Used to sanity-check the request line's method.
fn is_tchar(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b)
}

/// Split a `Host` header value into host and optional port.
///
/// Only a trailing all-numeric segment is treated as a port, so unbracketed
/// values are not mistaken for ports. Bracketed IPv6 literals such as
/// `[::1]:8080` are split correctly; the brackets are preserved on the host.
///
/// A trailing all-digit segment that overflows `u16` (e.g. `:99999`) is a clear
/// authoring mistake, so it errors instead of being silently dropped to the
/// scheme's default port.
fn split_host_port(host_value: &str) -> Result<(String, Option<u16>)> {
    match host_value.rsplit_once(':') {
        Some((host, port))
            if !host.is_empty()
                && !port.is_empty()
                && port.chars().all(|c| c.is_ascii_digit())
                // Only split off a port when the host part is unambiguous: a
                // bracketed IPv6 literal (`[::1]`) or a host with no embedded
                // colon. An unbracketed IPv6 literal like `::1` would otherwise
                // be mis-split into host ":" + port "1"; return it whole instead.
                && (host.ends_with(']') || !host.contains(':')) =>
        {
            let parsed = port.parse::<u16>().map_err(|_| {
                SmugglexError::InvalidInput(format!(
                    "invalid port '{}' in Host header '{}' (must be 0-65535)",
                    port, host_value
                ))
            })?;
            Ok((host.to_string(), Some(parsed)))
        }
        _ => Ok((host_value.to_string(), None)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_origin_form_post() {
        let raw = "POST /search HTTP/1.1\r\n\
                   Host: example.com\r\n\
                   User-Agent: curl/8.0\r\n\
                   Content-Type: application/x-www-form-urlencoded\r\n\
                   Content-Length: 6\r\n\
                   \r\n\
                   q=test";
        let parsed = parse_raw_request(raw).unwrap();
        assert_eq!(parsed.method, "POST");
        assert_eq!(parsed.target, "/search");
        assert_eq!(parsed.host, "example.com");
        assert_eq!(parsed.port, None);
        assert_eq!(parsed.scheme, None);
        assert_eq!(parsed.host_header, "example.com");
        // Host and Content-Length are stripped; the rest is preserved in order.
        assert_eq!(
            parsed.headers,
            vec![
                "User-Agent: curl/8.0".to_string(),
                "Content-Type: application/x-www-form-urlencoded".to_string(),
            ]
        );
    }

    #[test]
    fn preserves_query_string() {
        let raw = "GET /a/b?x=1&y=2 HTTP/1.1\nHost: example.com\n\n";
        let parsed = parse_raw_request(raw).unwrap();
        assert_eq!(parsed.method, "GET");
        assert_eq!(parsed.target, "/a/b?x=1&y=2");
    }

    #[test]
    fn handles_bare_lf_line_endings() {
        let raw = "GET / HTTP/1.1\nHost: example.com\nAccept: */*\n\n";
        let parsed = parse_raw_request(raw).unwrap();
        assert_eq!(parsed.headers, vec!["Accept: */*".to_string()]);
    }

    #[test]
    fn extracts_host_with_port() {
        let raw = "GET / HTTP/1.1\r\nHost: example.com:8443\r\n\r\n";
        let parsed = parse_raw_request(raw).unwrap();
        assert_eq!(parsed.host, "example.com");
        assert_eq!(parsed.port, Some(8443));
        // The emitted Host header keeps the port intact.
        assert_eq!(parsed.host_header, "example.com:8443");
    }

    #[test]
    fn extracts_bracketed_ipv6_host_from_origin_form() {
        let raw = "GET /status HTTP/1.1\r\nHost: [::1]:8080\r\n\r\n";
        let parsed = parse_raw_request(raw).unwrap();
        // Brackets are preserved so the synthetic URL `https://[::1]:8080/...`
        // and the emitted Host header stay valid.
        assert_eq!(parsed.host, "[::1]");
        assert_eq!(parsed.port, Some(8080));
        assert_eq!(parsed.host_header, "[::1]:8080");
    }

    #[test]
    fn strips_managed_headers_case_insensitively() {
        let raw = "POST / HTTP/1.1\r\n\
                   Host: example.com\r\n\
                   connection: close\r\n\
                   TRANSFER-ENCODING: chunked\r\n\
                   content-length: 0\r\n\
                   X-Real: keep\r\n\
                   \r\n";
        let parsed = parse_raw_request(raw).unwrap();
        assert_eq!(parsed.headers, vec!["X-Real: keep".to_string()]);
    }

    #[test]
    fn keeps_cookie_and_authorization_headers() {
        let raw = "GET / HTTP/1.1\r\n\
                   Host: example.com\r\n\
                   Cookie: session=abc; theme=dark\r\n\
                   Authorization: Bearer t0ken\r\n\
                   \r\n";
        let parsed = parse_raw_request(raw).unwrap();
        assert_eq!(
            parsed.headers,
            vec![
                "Cookie: session=abc; theme=dark".to_string(),
                "Authorization: Bearer t0ken".to_string(),
            ]
        );
    }

    #[test]
    fn parses_absolute_form_request_line() {
        let raw = "GET https://api.example.com:8443/v1/users?id=7 HTTP/1.1\r\n\
                   Accept: application/json\r\n\
                   \r\n";
        let parsed = parse_raw_request(raw).unwrap();
        assert_eq!(parsed.host, "api.example.com");
        assert_eq!(parsed.port, Some(8443));
        assert_eq!(parsed.scheme, Some("https".to_string()));
        assert_eq!(parsed.target, "/v1/users?id=7");
        assert_eq!(parsed.host_header, "api.example.com:8443");
    }

    #[test]
    fn absolute_form_preserves_dot_segments_and_fragment() {
        // url.path()/url.query() would collapse `/../` and drop `#frag`; the literal
        // slice must keep the request-target byte-for-byte.
        let raw = "GET https://h.test/a/../b?x=1#frag HTTP/1.1\r\nAccept: */*\r\n\r\n";
        let parsed = parse_raw_request(raw).unwrap();
        assert_eq!(parsed.host, "h.test");
        assert_eq!(parsed.target, "/a/../b?x=1#frag");
    }

    #[test]
    fn absolute_form_preserves_encoded_and_matrix_params() {
        let raw = "GET http://h/api/..%2fadmin/x;y=1/../z?q=a%20b HTTP/1.1\r\nAccept: */*\r\n\r\n";
        let parsed = parse_raw_request(raw).unwrap();
        assert_eq!(parsed.target, "/api/..%2fadmin/x;y=1/../z?q=a%20b");
    }

    #[test]
    fn absolute_form_ipv6_preserves_dot_segments() {
        let raw = "GET http://[::1]:8080/a/../b HTTP/1.1\r\nAccept: */*\r\n\r\n";
        let parsed = parse_raw_request(raw).unwrap();
        assert_eq!(parsed.host, "[::1]");
        assert_eq!(parsed.port, Some(8080));
        assert_eq!(parsed.target, "/a/../b");
    }

    #[test]
    fn absolute_form_query_only_synthesizes_root_path() {
        let raw = "GET http://h?q=1 HTTP/1.1\r\nAccept: */*\r\n\r\n";
        let parsed = parse_raw_request(raw).unwrap();
        assert_eq!(parsed.host, "h");
        assert_eq!(parsed.target, "/?q=1");
    }

    #[test]
    fn absolute_form_authority_only_defaults_to_root() {
        let raw = "GET https://h HTTP/1.1\r\nAccept: */*\r\n\r\n";
        let parsed = parse_raw_request(raw).unwrap();
        assert_eq!(parsed.target, "/");
    }

    #[test]
    fn absolute_form_with_userinfo_keeps_path_and_host() {
        // Userinfo precedes the host but can't contain '/', so the first '/' still
        // marks the request-target. The host (not the userinfo) is used downstream.
        let raw = "GET http://user:pw@h.test/a/../b HTTP/1.1\r\nAccept: */*\r\n\r\n";
        let parsed = parse_raw_request(raw).unwrap();
        assert_eq!(parsed.host, "h.test");
        assert_eq!(parsed.target, "/a/../b");
    }

    #[test]
    fn parses_absolute_form_ipv6_request_line() {
        let raw = "GET http://[::1]:8080/health?ok=1 HTTP/1.1\r\n\
                   Accept: */*\r\n\
                   \r\n";
        let parsed = parse_raw_request(raw).unwrap();
        // IPv6 literals keep their brackets so the synthetic URL and emitted
        // Host header are valid.
        assert_eq!(parsed.host, "[::1]");
        assert_eq!(parsed.port, Some(8080));
        assert_eq!(parsed.scheme, Some("http".to_string()));
        assert_eq!(parsed.target, "/health?ok=1");
        assert_eq!(parsed.host_header, "[::1]:8080");
    }

    #[test]
    fn errors_on_authority_form_target() {
        let raw = "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let err = parse_raw_request(raw).unwrap_err();
        assert!(matches!(err, SmugglexError::InvalidInput(_)));
    }

    #[test]
    fn errors_on_asterisk_form_target() {
        let raw = "OPTIONS * HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let err = parse_raw_request(raw).unwrap_err();
        assert!(matches!(err, SmugglexError::InvalidInput(_)));
    }

    #[test]
    fn absolute_form_prefers_explicit_host_header() {
        let raw = "GET http://backend.internal/admin HTTP/1.1\r\n\
                   Host: frontend.example.com\r\n\
                   \r\n";
        let parsed = parse_raw_request(raw).unwrap();
        assert_eq!(parsed.host, "backend.internal");
        assert_eq!(parsed.scheme, Some("http".to_string()));
        assert_eq!(parsed.host_header, "frontend.example.com");
    }

    #[test]
    fn errors_on_empty_input() {
        let err = parse_raw_request("\n\n   \n").unwrap_err();
        assert!(matches!(err, SmugglexError::InvalidInput(_)));
    }

    #[test]
    fn errors_when_origin_form_missing_host() {
        let raw = "GET / HTTP/1.1\r\nAccept: */*\r\n\r\n";
        let err = parse_raw_request(raw).unwrap_err();
        assert!(matches!(err, SmugglexError::InvalidInput(_)));
    }

    #[test]
    fn errors_on_empty_host_header() {
        // A present-but-empty (or whitespace-only) Host value must be rejected,
        // not silently accepted as an empty connection host.
        for raw in [
            "GET / HTTP/1.1\r\nHost:\r\n\r\n",
            "GET / HTTP/1.1\r\nHost:    \r\n\r\n",
        ] {
            let err = parse_raw_request(raw).unwrap_err();
            assert!(
                matches!(err, SmugglexError::InvalidInput(_)),
                "empty Host should be InvalidInput, raw = {raw:?}"
            );
        }
    }

    #[test]
    fn split_host_port_does_not_split_unbracketed_ipv6() {
        // `::1` is a malformed (unbracketed) IPv6 Host; it must NOT be mis-split
        // into host ":" + port 1. Return the whole value with no port instead.
        assert_eq!(split_host_port("::1").unwrap(), ("::1".to_string(), None));
        assert_eq!(
            split_host_port("fe80::1").unwrap(),
            ("fe80::1".to_string(), None)
        );
        // Bracketed IPv6 with an explicit port still splits correctly.
        assert_eq!(
            split_host_port("[::1]:8080").unwrap(),
            ("[::1]".to_string(), Some(8080))
        );
    }

    #[test]
    fn merge_headers_appends_user_after_captured() {
        let captured = vec!["Cookie: a=1".to_string(), "Accept: */*".to_string()];
        let user = vec!["X-Collab: marker".to_string()];
        assert_eq!(
            merge_headers(captured, &user),
            vec![
                "Cookie: a=1".to_string(),
                "Accept: */*".to_string(),
                "X-Collab: marker".to_string(),
            ]
        );
    }

    #[test]
    fn merge_headers_no_user_headers_is_identity() {
        let captured = vec!["Cookie: a=1".to_string()];
        assert_eq!(merge_headers(captured.clone(), &[]), captured);
    }

    #[test]
    fn merge_headers_keeps_overlapping_names_as_duplicates() {
        // An explicit -H that overlaps a captured header must NOT replace it;
        // both are emitted so header-repetition tests still work.
        let captured = vec!["User-Agent: captured".to_string()];
        let user = vec!["User-Agent: override".to_string()];
        assert_eq!(
            merge_headers(captured, &user),
            vec![
                "User-Agent: captured".to_string(),
                "User-Agent: override".to_string(),
            ]
        );
    }

    #[test]
    fn connect_url_origin_form_uses_default_proto_and_port() {
        let raw = parse_raw_request("GET /a HTTP/1.1\r\nHost: example.com\r\n\r\n").unwrap();
        // Origin-form carries no scheme: --raw-request-proto decides it (and the port).
        assert_eq!(raw.connect_url("https"), "https://example.com:443/");
        assert_eq!(raw.connect_url("http"), "http://example.com:80/");
    }

    #[test]
    fn connect_url_keeps_explicit_port() {
        let raw = parse_raw_request("GET /a HTTP/1.1\r\nHost: example.com:8443\r\n\r\n").unwrap();
        assert_eq!(raw.connect_url("https"), "https://example.com:8443/");
    }

    #[test]
    fn connect_url_absolute_form_scheme_wins_over_default() {
        let raw = parse_raw_request("GET http://api.example.com/x HTTP/1.1\r\nAccept: */*\r\n\r\n")
            .unwrap();
        // Absolute-form carries its own scheme; the proto default is ignored.
        assert_eq!(raw.connect_url("https"), "http://api.example.com:80/");
    }

    #[test]
    fn connect_url_path_is_always_root() {
        // The real request-target lives in `target`; connect_url must never embed it,
        // so dot-segments and fragments can't be normalized away by URL re-parsing.
        let raw =
            parse_raw_request("GET /a/../b#frag?x=1 HTTP/1.1\r\nHost: h.test\r\n\r\n").unwrap();
        assert_eq!(raw.connect_url("https"), "https://h.test:443/");
        assert_eq!(raw.target, "/a/../b#frag?x=1");
    }

    #[test]
    fn connect_url_bracketed_ipv6() {
        let raw = parse_raw_request("GET /a HTTP/1.1\r\nHost: [::1]:8080\r\n\r\n").unwrap();
        assert_eq!(raw.connect_url("http"), "http://[::1]:8080/");
    }

    #[test]
    fn split_host_port_ignores_non_numeric() {
        assert_eq!(
            split_host_port("example.com").unwrap(),
            ("example.com".to_string(), None)
        );
        assert_eq!(
            split_host_port("example.com:443").unwrap(),
            ("example.com".to_string(), Some(443))
        );
        assert_eq!(
            split_host_port("[::1]:8080").unwrap(),
            ("[::1]".to_string(), Some(8080))
        );
    }

    #[test]
    fn split_host_port_errors_on_out_of_range_port() {
        // All-digit but > 65535: a clear authoring mistake, not "no port".
        let err = split_host_port("example.com:99999").unwrap_err();
        assert!(matches!(err, SmugglexError::InvalidInput(_)));
        // And it surfaces through the full parse path.
        let raw = "GET /x HTTP/1.1\r\nHost: example.com:99999\r\n\r\n";
        assert!(matches!(
            parse_raw_request(raw).unwrap_err(),
            SmugglexError::InvalidInput(_)
        ));
    }

    #[test]
    fn errors_on_non_http_first_line() {
        // Pointing --raw-request at an accidental JSON/HTML file must fail fast with
        // a clear message rather than scanning a garbage method/target.
        for junk in [
            "{\"foo\": \"bar\"}\r\n\r\n",
            "<!DOCTYPE html>\r\n<html></html>\r\n",
        ] {
            let err = parse_raw_request(junk).unwrap_err();
            assert!(
                matches!(err, SmugglexError::InvalidInput(_)),
                "junk: {}",
                junk
            );
        }
    }

    #[test]
    fn accepts_uncommon_but_valid_method_tokens() {
        // Custom/WebDAV methods are valid RFC 7230 tokens and must still parse.
        for m in ["PROPFIND", "MKCOL", "X-CUSTOM"] {
            let raw = format!("{} /x HTTP/1.1\r\nHost: h\r\n\r\n", m);
            assert_eq!(parse_raw_request(&raw).unwrap().method, m);
        }
    }

    #[test]
    fn records_presence_of_message_body() {
        let with_body = "POST /x HTTP/1.1\r\nHost: h\r\nContent-Length: 3\r\n\r\nabc";
        assert!(parse_raw_request(with_body).unwrap().had_body);

        // No body, or only a trailing blank line, is not counted as a body.
        let no_body = "GET /x HTTP/1.1\r\nHost: h\r\n\r\n";
        assert!(!parse_raw_request(no_body).unwrap().had_body);
        let trailing_blank = "GET /x HTTP/1.1\r\nHost: h\r\n\r\n\r\n";
        assert!(!parse_raw_request(trailing_blank).unwrap().had_body);
    }
}
