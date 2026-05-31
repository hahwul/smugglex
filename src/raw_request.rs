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
    let target_raw = parts
        .next()
        .ok_or_else(|| {
            SmugglexError::InvalidInput("raw request missing request target".to_string())
        })?
        .to_string();

    // Headers run until the first blank line; everything after is the body.
    let mut headers: Vec<String> = Vec::new();
    let mut host_header: Option<String> = None;
    for line in lines {
        if line.trim().is_empty() {
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

    if is_absolute_form(&target_raw) {
        parse_absolute_form(method, &target_raw, host_header, headers)
    } else {
        parse_origin_form(method, target_raw, host_header, headers)
    }
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
    let (host, port) = split_host_port(&host_header);
    Ok(RawRequest {
        method,
        target,
        host,
        port,
        scheme: None,
        host_header,
        headers,
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

    let mut target = url.path().to_string();
    if let Some(query) = url.query() {
        target.push('?');
        target.push_str(query);
    }

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
    })
}

/// Whether a request-target is absolute-form (carries its own scheme).
fn is_absolute_form(target: &str) -> bool {
    let lower = target.to_ascii_lowercase();
    lower.starts_with("http://") || lower.starts_with("https://")
}

/// Whether a header is one smugglex sets/controls itself for smuggling payloads.
fn is_managed_header(name: &str) -> bool {
    MANAGED_HEADERS
        .iter()
        .any(|managed| name.eq_ignore_ascii_case(managed))
}

/// Split a `Host` header value into host and optional port.
///
/// Only a trailing all-numeric segment is treated as a port, so unbracketed
/// values are not mistaken for ports. Bracketed IPv6 literals such as
/// `[::1]:8080` are split correctly; the brackets are preserved on the host.
fn split_host_port(host_value: &str) -> (String, Option<u16>) {
    match host_value.rsplit_once(':') {
        Some((host, port))
            if !host.is_empty() && !port.is_empty() && port.chars().all(|c| c.is_ascii_digit()) =>
        {
            (host.to_string(), port.parse::<u16>().ok())
        }
        _ => (host_value.to_string(), None),
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
    fn split_host_port_ignores_non_numeric() {
        assert_eq!(
            split_host_port("example.com"),
            ("example.com".to_string(), None)
        );
        assert_eq!(
            split_host_port("example.com:443"),
            ("example.com".to_string(), Some(443))
        );
        assert_eq!(
            split_host_port("[::1]:8080"),
            ("[::1]".to_string(), Some(8080))
        );
    }
}
