//! Tests for data models and serialization
//!
//! This module contains tests for:
//! - CheckResult creation and validation
//! - ScanResults aggregation
//! - JSON serialization and deserialization
//! - Edge cases (large durations, special characters)
//! - Different check types and status codes
//! - Clone implementation

use smugglex::model::{CheckResult, ScanResults};

/// Helper function to create a test CheckResult
fn create_test_check_result(
    check_type: &str,
    vulnerable: bool,
    payload_index: Option<usize>,
    attack_status: Option<&str>,
    attack_duration_ms: Option<u64>,
) -> CheckResult {
    CheckResult {
        check_type: check_type.to_string(),
        vulnerable,
        payload_index,
        normal_status: "HTTP/1.1 200 OK".to_string(),
        attack_status: attack_status.map(|s| s.to_string()),
        normal_duration_ms: 150,
        attack_duration_ms,
        timestamp: "2024-01-01T12:00:00Z".to_string(),
        payload: None,
    }
}

#[test]
fn test_check_result_creation_vulnerable() {
    let result = create_test_check_result(
        "CL.TE",
        true,
        Some(3),
        Some("HTTP/1.1 504 Gateway Timeout"),
        Some(5000),
    );

    assert_eq!(result.check_type, "CL.TE");
    assert!(result.vulnerable);
    assert_eq!(result.payload_index, Some(3));
    assert_eq!(result.normal_status, "HTTP/1.1 200 OK");
    assert_eq!(
        result.attack_status,
        Some("HTTP/1.1 504 Gateway Timeout".to_string())
    );
    assert_eq!(result.normal_duration_ms, 150);
    assert_eq!(result.attack_duration_ms, Some(5000));
}

#[test]
fn test_check_result_creation_not_vulnerable() {
    let result = create_test_check_result("TE.CL", false, None, None, None);

    assert_eq!(result.check_type, "TE.CL");
    assert!(!result.vulnerable);
    assert_eq!(result.payload_index, None);
    assert_eq!(result.attack_status, None);
    assert_eq!(result.attack_duration_ms, None);
}

// Table-driven test for different check types
#[test]
fn test_check_result_all_check_types() {
    let check_types = vec!["CL.TE", "TE.CL", "TE.TE"];

    for check_type in check_types {
        let result = create_test_check_result(check_type, false, None, None, None);
        assert_eq!(
            result.check_type, check_type,
            "Check type should match for {}",
            check_type
        );
        assert!(
            !result.vulnerable,
            "{} should not be vulnerable",
            check_type
        );
    }
}

// Table-driven test for different HTTP status codes
#[test]
fn test_check_result_various_status_codes() {
    let status_codes = vec![
        ("HTTP/1.1 200 OK", false),
        ("HTTP/1.1 408 Request Timeout", true),
        ("HTTP/1.1 500 Internal Server Error", false),
        ("HTTP/1.1 502 Bad Gateway", false),
        ("HTTP/1.1 503 Service Unavailable", false),
        ("HTTP/1.1 504 Gateway Timeout", true),
    ];

    for (status, should_be_timeout) in status_codes {
        let result = if should_be_timeout {
            create_test_check_result("CL.TE", true, Some(0), Some(status), Some(5000))
        } else {
            create_test_check_result("CL.TE", false, None, Some(status), None)
        };

        assert!(
            result.attack_status.is_some(),
            "Attack status should be set for {}",
            status
        );
        assert_eq!(
            result.attack_status.as_deref(),
            Some(status),
            "Status code should match"
        );
    }
}

// Edge case: Test with very long durations
#[test]
fn test_check_result_large_duration() {
    let result = create_test_check_result(
        "TE.TE",
        true,
        Some(0),
        Some("Connection Timeout"),
        Some(u64::MAX),
    );

    assert_eq!(result.attack_duration_ms, Some(u64::MAX));
    assert!(result.vulnerable);
}

// Edge case: Test with zero duration
#[test]
fn test_check_result_zero_duration() {
    let result = CheckResult {
        check_type: "CL.TE".to_string(),
        vulnerable: false,
        payload_index: None,
        normal_status: "HTTP/1.1 200 OK".to_string(),
        attack_status: None,
        normal_duration_ms: 0,
        attack_duration_ms: Some(0),
        timestamp: "2024-01-01T12:00:00Z".to_string(),
        payload: None,
    };

    assert_eq!(result.normal_duration_ms, 0);
    assert_eq!(result.attack_duration_ms, Some(0));
}

// Test with special characters in strings
#[test]
fn test_check_result_special_characters() {
    let result = CheckResult {
        check_type: "CL.TE".to_string(),
        vulnerable: true,
        payload_index: Some(0),
        normal_status: "HTTP/1.1 200 OK".to_string(),
        attack_status: Some("HTTP/1.1 504 \"Gateway\" Timeout".to_string()),
        normal_duration_ms: 100,
        attack_duration_ms: Some(5000),
        timestamp: "2024-01-01T12:00:00+00:00".to_string(),
        payload: None,
    };

    let json = serde_json::to_string(&result).expect("Should serialize");
    let deserialized: CheckResult = serde_json::from_str(&json).expect("Should deserialize");

    assert_eq!(result.attack_status, deserialized.attack_status);
    assert_eq!(result.timestamp, deserialized.timestamp);
}

#[test]
fn test_check_result_serialization_vulnerable() {
    let result = CheckResult {
        check_type: "TE.TE".to_string(),
        vulnerable: true,
        payload_index: Some(1),
        normal_status: "HTTP/1.1 200 OK".to_string(),
        attack_status: Some("HTTP/1.1 408 Request Timeout".to_string()),
        normal_duration_ms: 100,
        attack_duration_ms: Some(10000),
        timestamp: "2024-01-01T12:00:00Z".to_string(),
        payload: None,
    };

    let json = serde_json::to_string(&result).expect("Failed to serialize");

    // Verify JSON contains expected fields
    assert!(json.contains("\"check_type\":\"TE.TE\""));
    assert!(json.contains("\"vulnerable\":true"));
    assert!(json.contains("\"payload_index\":1"));
    assert!(json.contains("\"attack_duration_ms\":10000"));
}

#[test]
fn test_check_result_deserialization() {
    let json = r#"{
        "check_type": "CL.TE",
        "vulnerable": true,
        "payload_index": 2,
        "normal_status": "HTTP/1.1 200 OK",
        "attack_status": "HTTP/1.1 504 Gateway Timeout",
        "normal_duration_ms": 150,
        "attack_duration_ms": 4500,
        "timestamp": "2024-01-01T12:00:00Z"
    }"#;

    let result: CheckResult = serde_json::from_str(json).expect("Failed to deserialize");

    assert_eq!(result.check_type, "CL.TE");
    assert!(result.vulnerable);
    assert_eq!(result.payload_index, Some(2));
    assert_eq!(result.normal_duration_ms, 150);
    assert_eq!(result.attack_duration_ms, Some(4500));
}

#[test]
fn test_check_result_clone() {
    let result = CheckResult {
        check_type: "CL.TE".to_string(),
        vulnerable: true,
        payload_index: Some(0),
        normal_status: "HTTP/1.1 200 OK".to_string(),
        attack_status: Some("HTTP/1.1 504 Gateway Timeout".to_string()),
        normal_duration_ms: 200,
        attack_duration_ms: Some(3000),
        timestamp: "2024-01-01T12:00:00Z".to_string(),
        payload: None,
    };

    let cloned = result.clone();

    assert_eq!(result.check_type, cloned.check_type);
    assert_eq!(result.vulnerable, cloned.vulnerable);
    assert_eq!(result.payload_index, cloned.payload_index);
}

#[test]
fn test_scan_results_creation() {
    let check1 = CheckResult {
        check_type: "CL.TE".to_string(),
        vulnerable: true,
        payload_index: Some(1),
        normal_status: "HTTP/1.1 200 OK".to_string(),
        attack_status: Some("HTTP/1.1 504 Gateway Timeout".to_string()),
        normal_duration_ms: 200,
        attack_duration_ms: Some(5000),
        timestamp: "2024-01-01T12:00:00Z".to_string(),
        payload: None,
    };

    let check2 = CheckResult {
        check_type: "TE.CL".to_string(),
        vulnerable: false,
        payload_index: None,
        normal_status: "HTTP/1.1 200 OK".to_string(),
        attack_status: None,
        normal_duration_ms: 150,
        attack_duration_ms: None,
        timestamp: "2024-01-01T12:00:01Z".to_string(),
        payload: None,
    };

    let scan_results = ScanResults {
        target: "https://example.com".to_string(),
        method: "POST".to_string(),
        timestamp: "2024-01-01T12:00:00Z".to_string(),
        checks: vec![check1, check2],
    };

    assert_eq!(scan_results.target, "https://example.com");
    assert_eq!(scan_results.method, "POST");
    assert_eq!(scan_results.checks.len(), 2);
    assert!(scan_results.checks[0].vulnerable);
    assert!(!scan_results.checks[1].vulnerable);
}

#[test]
fn test_scan_results_serialization() {
    let check = CheckResult {
        check_type: "CL.TE".to_string(),
        vulnerable: true,
        payload_index: Some(0),
        normal_status: "HTTP/1.1 200 OK".to_string(),
        attack_status: Some("HTTP/1.1 504 Gateway Timeout".to_string()),
        normal_duration_ms: 200,
        attack_duration_ms: Some(4000),
        timestamp: "2024-01-01T12:00:00Z".to_string(),
        payload: None,
    };

    let scan_results = ScanResults {
        target: "https://api.example.com/test".to_string(),
        method: "GET".to_string(),
        timestamp: "2024-01-01T12:00:00Z".to_string(),
        checks: vec![check],
    };

    let json = serde_json::to_string_pretty(&scan_results).expect("Failed to serialize");

    assert!(json.contains("\"target\":"));
    assert!(json.contains("\"method\":"));
    assert!(json.contains("\"timestamp\":"));
    assert!(json.contains("\"checks\":"));
    assert!(json.contains("https://api.example.com/test"));
}

#[test]
fn test_scan_results_deserialization() {
    let json = r#"{
        "target": "http://test.com",
        "method": "POST",
        "timestamp": "2024-01-01T12:00:00Z",
        "checks": [
            {
                "check_type": "CL.TE",
                "vulnerable": false,
                "payload_index": null,
                "normal_status": "HTTP/1.1 200 OK",
                "attack_status": null,
                "normal_duration_ms": 100,
                "attack_duration_ms": null,
                "timestamp": "2024-01-01T12:00:00Z"
            }
        ]
    }"#;

    let scan_results: ScanResults = serde_json::from_str(json).expect("Failed to deserialize");

    assert_eq!(scan_results.target, "http://test.com");
    assert_eq!(scan_results.method, "POST");
    assert_eq!(scan_results.checks.len(), 1);
    assert!(!scan_results.checks[0].vulnerable);
}

#[test]
fn test_scan_results_empty_checks() {
    let scan_results = ScanResults {
        target: "http://test.com".to_string(),
        method: "GET".to_string(),
        timestamp: "2024-01-01T12:00:00Z".to_string(),
        checks: vec![],
    };

    assert_eq!(scan_results.checks.len(), 0);

    let json = serde_json::to_string(&scan_results).expect("Failed to serialize");
    let deserialized: ScanResults = serde_json::from_str(&json).expect("Failed to deserialize");

    assert_eq!(deserialized.checks.len(), 0);
}

#[test]
fn test_scan_results_multiple_checks() {
    let checks = vec![
        CheckResult {
            check_type: "CL.TE".to_string(),
            vulnerable: true,
            payload_index: Some(0),
            normal_status: "HTTP/1.1 200 OK".to_string(),
            attack_status: Some("HTTP/1.1 504 Gateway Timeout".to_string()),
            normal_duration_ms: 150,
            attack_duration_ms: Some(3000),
            timestamp: "2024-01-01T12:00:00Z".to_string(),
            payload: None,
        },
        CheckResult {
            check_type: "TE.CL".to_string(),
            vulnerable: false,
            payload_index: None,
            normal_status: "HTTP/1.1 200 OK".to_string(),
            attack_status: None,
            normal_duration_ms: 160,
            attack_duration_ms: None,
            timestamp: "2024-01-01T12:00:01Z".to_string(),
            payload: None,
        },
        CheckResult {
            check_type: "TE.TE".to_string(),
            vulnerable: true,
            payload_index: Some(2),
            normal_status: "HTTP/1.1 200 OK".to_string(),
            attack_status: Some("Connection Timeout".to_string()),
            normal_duration_ms: 140,
            attack_duration_ms: Some(10000),
            timestamp: "2024-01-01T12:00:02Z".to_string(),
            payload: None,
        },
    ];

    let scan_results = ScanResults {
        target: "https://vulnerable.example.com".to_string(),
        method: "POST".to_string(),
        timestamp: "2024-01-01T12:00:00Z".to_string(),
        checks: checks.clone(),
    };

    assert_eq!(scan_results.checks.len(), 3);

    let vulnerable_count = scan_results.checks.iter().filter(|c| c.vulnerable).count();
    assert_eq!(vulnerable_count, 2);
}

#[test]
fn test_check_result_different_check_types() {
    let check_types = vec!["CL.TE", "TE.CL", "TE.TE"];

    for check_type in check_types {
        let result = CheckResult {
            check_type: check_type.to_string(),
            vulnerable: false,
            payload_index: None,
            normal_status: "HTTP/1.1 200 OK".to_string(),
            attack_status: None,
            normal_duration_ms: 100,
            attack_duration_ms: None,
            timestamp: "2024-01-01T12:00:00Z".to_string(),
            payload: None,
        };

        assert_eq!(result.check_type, check_type);
    }
}

#[test]
fn test_check_result_timeout_scenarios() {
    // Scenario 1: Timeout via status code
    let result1 = CheckResult {
        check_type: "CL.TE".to_string(),
        vulnerable: true,
        payload_index: Some(0),
        normal_status: "HTTP/1.1 200 OK".to_string(),
        attack_status: Some("HTTP/1.1 504 Gateway Timeout".to_string()),
        normal_duration_ms: 100,
        attack_duration_ms: Some(15000),
        timestamp: "2024-01-01T12:00:00Z".to_string(),
        payload: None,
    };

    assert!(result1.attack_status.as_ref().unwrap().contains("504"));

    // Scenario 2: Connection timeout
    let result2 = CheckResult {
        check_type: "TE.CL".to_string(),
        vulnerable: true,
        payload_index: Some(1),
        normal_status: "HTTP/1.1 200 OK".to_string(),
        attack_status: Some("Connection Timeout".to_string()),
        normal_duration_ms: 100,
        attack_duration_ms: Some(10000),
        timestamp: "2024-01-01T12:00:00Z".to_string(),
        payload: None,
    };

    assert_eq!(
        result2.attack_status,
        Some("Connection Timeout".to_string())
    );
}

#[test]
fn test_payload_stored_in_vulnerable_result() {
    // Test that payload is properly stored when vulnerability is detected
    let payload_content =
        "POST / HTTP/1.1\r\nHost: test.com\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n";
    let result = CheckResult {
        check_type: "CL.TE".to_string(),
        vulnerable: true,
        payload_index: Some(0),
        normal_status: "HTTP/1.1 200 OK".to_string(),
        attack_status: Some("Connection Timeout".to_string()),
        normal_duration_ms: 100,
        attack_duration_ms: Some(5000),
        timestamp: "2024-01-01T12:00:00Z".to_string(),
        payload: Some(payload_content.to_string()),
    };

    assert!(result.vulnerable);
    assert!(result.payload.is_some());
    assert_eq!(result.payload.as_ref().unwrap(), payload_content);
}

#[test]
fn test_payload_is_none_for_non_vulnerable() {
    // Test that non-vulnerable results don't store payloads
    let result = CheckResult {
        check_type: "TE.CL".to_string(),
        vulnerable: false,
        payload_index: None,
        normal_status: "HTTP/1.1 200 OK".to_string(),
        attack_status: None,
        normal_duration_ms: 100,
        attack_duration_ms: None,
        timestamp: "2024-01-01T12:00:00Z".to_string(),
        payload: None,
    };

    assert!(!result.vulnerable);
    assert!(result.payload.is_none());
}

#[test]
fn test_payload_serialization_with_payload() {
    // Test that payload field is properly serialized
    let result = CheckResult {
        check_type: "TE.TE".to_string(),
        vulnerable: true,
        payload_index: Some(1),
        normal_status: "HTTP/1.1 200 OK".to_string(),
        attack_status: Some("Connection Timeout".to_string()),
        normal_duration_ms: 100,
        attack_duration_ms: Some(10000),
        timestamp: "2024-01-01T12:00:00Z".to_string(),
        payload: Some("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n".to_string()),
    };

    let json = serde_json::to_string(&result).expect("Failed to serialize");

    // Verify JSON contains payload field
    assert!(json.contains("\"payload\":"));
    assert!(json.contains("GET / HTTP/1.1"));
}

#[test]
fn test_payload_serialization_without_payload() {
    // Test that payload field is skipped when None
    let result = CheckResult {
        check_type: "CL.TE".to_string(),
        vulnerable: false,
        payload_index: None,
        normal_status: "HTTP/1.1 200 OK".to_string(),
        attack_status: None,
        normal_duration_ms: 100,
        attack_duration_ms: None,
        timestamp: "2024-01-01T12:00:00Z".to_string(),
        payload: None,
    };

    let json = serde_json::to_string(&result).expect("Failed to serialize");

    // Verify JSON does NOT contain payload field when it's None
    assert!(!json.contains("\"payload\":"));
}
