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

use smugglex::payloads::*;
use smugglex::model::CheckResult;
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
    let result = format_custom_headers(&headers);
    assert_eq!(result, "X-Custom: value\r\n");
}

#[test]
fn test_format_custom_headers_multiple() {
    let headers = vec![
        "X-Custom-1: value1".to_string(),
        "X-Custom-2: value2".to_string(),
        "Authorization: Bearer token".to_string(),
    ];
    let result = format_custom_headers(&headers);
    assert_eq!(
        result,
        "X-Custom-1: value1\r\nX-Custom-2: value2\r\nAuthorization: Bearer token\r\n"
    );
}

#[test]
fn test_format_cookies_single() {
    let cookies = vec!["session=abc123".to_string()];
    let result = format_cookies(&cookies);
    assert_eq!(result, "Cookie: session=abc123\r\n");
}

#[test]
fn test_format_cookies_multiple() {
    let cookies = vec![
        "session=abc123".to_string(),
        "user=test".to_string(),
        "preferences=dark".to_string(),
    ];
    let result = format_cookies(&cookies);
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
