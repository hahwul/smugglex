//! Tests for SARIF output format
//!
//! This module contains tests for:
//! - SARIF format conversion from ScanResults
//! - SARIF structure validation
//! - Multiple vulnerabilities in SARIF format
//! - Non-vulnerable results filtering

use smugglex::model::{CheckResult, ScanResults};
use smugglex::sarif::convert_to_sarif;

/// Helper function to create a test CheckResult
fn create_test_check_result(
    check_type: &str,
    vulnerable: bool,
    payload_index: Option<usize>,
    attack_status: Option<&str>,
    attack_duration_ms: Option<u64>,
    payload: Option<String>,
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
        payload,
    }
}

#[test]
fn test_sarif_format_with_single_vulnerability() {
    let checks = vec![create_test_check_result(
        "cl-te",
        true,
        Some(0),
        Some("HTTP/1.1 504 Gateway Timeout"),
        Some(5000),
        Some("POST / HTTP/1.1\r\nHost: example.com\r\n\r\n".to_string()),
    )];

    let scan_results = ScanResults {
        target: "https://example.com".to_string(),
        method: "POST".to_string(),
        timestamp: "2024-01-01T12:00:00Z".to_string(),
        checks,
    };

    let sarif = convert_to_sarif(&scan_results);

    // Verify SARIF version
    assert_eq!(sarif.version, "2.1.0");

    // Verify runs exist
    assert_eq!(sarif.runs.len(), 1);

    let run = &sarif.runs[0];

    // Verify tool information
    assert_eq!(run.tool.driver.name, "SmuggleX");
    assert!(run.tool.driver.semantic_version.is_some());
    assert!(run.tool.driver.information_uri.is_some());

    // Verify results
    let results = run.results.as_ref().expect("Results should be present");
    assert_eq!(results.len(), 1);

    let result = &results[0];
    assert_eq!(result.rule_id.as_deref(), Some("cl-te"));
    let message_text = result
        .message
        .text
        .as_deref()
        .expect("Message text should be present");
    assert!(message_text.contains("cl-te"));
    assert!(result.locations.is_some());
    assert!(result.locations.as_ref().unwrap().len() > 0);
}

#[test]
fn test_sarif_format_with_no_vulnerabilities() {
    let checks = vec![
        create_test_check_result("cl-te", false, None, None, None, None),
        create_test_check_result("te-cl", false, None, None, None, None),
    ];

    let scan_results = ScanResults {
        target: "https://safe.example.com".to_string(),
        method: "POST".to_string(),
        timestamp: "2024-01-01T12:00:00Z".to_string(),
        checks,
    };

    let sarif = convert_to_sarif(&scan_results);

    // Should have no results when there are no vulnerabilities
    let results = sarif.runs[0].results.as_ref().expect("Results should be present");
    assert_eq!(results.len(), 0);
}

#[test]
fn test_sarif_format_with_multiple_vulnerabilities() {
    let checks = vec![
        create_test_check_result(
            "cl-te",
            true,
            Some(0),
            Some("HTTP/1.1 504 Gateway Timeout"),
            Some(5000),
            None,
        ),
        create_test_check_result("te-cl", false, None, None, None, None),
        create_test_check_result(
            "te-te",
            true,
            Some(2),
            Some("Connection Timeout"),
            Some(10000),
            None,
        ),
        create_test_check_result(
            "h2c",
            true,
            Some(1),
            Some("HTTP/1.1 408 Request Timeout"),
            Some(8000),
            None,
        ),
    ];

    let scan_results = ScanResults {
        target: "https://vulnerable.example.com".to_string(),
        method: "POST".to_string(),
        timestamp: "2024-01-01T12:00:00Z".to_string(),
        checks,
    };

    let sarif = convert_to_sarif(&scan_results);

    // Should have 3 results (only vulnerable checks)
    let results = sarif.runs[0]
        .results
        .as_ref()
        .expect("Results should be present");
    assert_eq!(results.len(), 3);

    // Verify rule IDs
    assert_eq!(results[0].rule_id.as_deref(), Some("cl-te"));
    assert_eq!(results[1].rule_id.as_deref(), Some("te-te"));
    assert_eq!(results[2].rule_id.as_deref(), Some("h2c"));
}

#[test]
fn test_sarif_serialization() {
    let checks = vec![create_test_check_result(
        "cl-te",
        true,
        Some(0),
        Some("HTTP/1.1 504 Gateway Timeout"),
        Some(5000),
        None,
    )];

    let scan_results = ScanResults {
        target: "https://example.com".to_string(),
        method: "POST".to_string(),
        timestamp: "2024-01-01T12:00:00Z".to_string(),
        checks,
    };

    let sarif = convert_to_sarif(&scan_results);
    let json = serde_json::to_string_pretty(&sarif);

    assert!(json.is_ok());

    let json_str = json.unwrap();
    println!("SARIF JSON:\n{}", json_str);

    // Verify SARIF format markers - version might be in different case/format
    assert!(json_str.contains("2.1.0"));
    assert!(json_str.contains("runs"));
    assert!(json_str.contains("tool"));
}

#[test]
fn test_sarif_contains_rules() {
    let checks = vec![create_test_check_result(
        "cl-te",
        true,
        Some(0),
        Some("HTTP/1.1 504 Gateway Timeout"),
        Some(5000),
        None,
    )];

    let scan_results = ScanResults {
        target: "https://example.com".to_string(),
        method: "POST".to_string(),
        timestamp: "2024-01-01T12:00:00Z".to_string(),
        checks,
    };

    let sarif = convert_to_sarif(&scan_results);

    // Verify rules are defined
    assert!(sarif.runs[0].tool.driver.rules.is_some());

    let rules = sarif.runs[0].tool.driver.rules.as_ref().unwrap();

    // Should have rules for all check types
    assert!(rules.len() >= 5);

    // Verify cl-te rule exists
    let cl_te_rule = rules.iter().find(|r| r.id == "cl-te");
    assert!(cl_te_rule.is_some());

    let rule = cl_te_rule.unwrap();
    let rule_name = rule.name.as_deref().expect("Rule name should be present");
    assert!(rule_name.contains("Content-Length"));
    assert!(rule.short_description.is_some());
    assert!(rule.help.is_some());
}

#[test]
fn test_sarif_with_payload_included() {
    let payload = "POST / HTTP/1.1\r\nHost: test.com\r\nContent-Length: 0\r\n\r\n";
    let checks = vec![create_test_check_result(
        "te-cl",
        true,
        Some(1),
        Some("Connection Timeout"),
        Some(7000),
        Some(payload.to_string()),
    )];

    let scan_results = ScanResults {
        target: "https://test.example.com".to_string(),
        method: "POST".to_string(),
        timestamp: "2024-01-01T12:00:00Z".to_string(),
        checks,
    };

    let sarif = convert_to_sarif(&scan_results);

    // Verify payload is stored in properties
    let results = sarif.runs[0]
        .results
        .as_ref()
        .expect("Results should be present");
    let result = &results[0];
    assert!(result.properties.is_some());

    let properties = result.properties.as_ref().unwrap();
    assert!(properties
        .additional_properties
        .contains_key("payload"));
}

#[test]
fn test_sarif_locations() {
    let checks = vec![create_test_check_result(
        "h2",
        true,
        Some(0),
        Some("HTTP/1.1 504 Gateway Timeout"),
        Some(5000),
        None,
    )];

    let target = "https://api.example.com/v1/test";
    let scan_results = ScanResults {
        target: target.to_string(),
        method: "GET".to_string(),
        timestamp: "2024-01-01T12:00:00Z".to_string(),
        checks,
    };

    let sarif = convert_to_sarif(&scan_results);

    let results = sarif.runs[0]
        .results
        .as_ref()
        .expect("Results should be present");
    let result = &results[0];

    // Verify location is set
    let locations = result.locations.as_ref().expect("Locations should be present");
    assert_eq!(locations.len(), 1);

    let location = &locations[0];
    assert!(location.physical_location.is_some());

    let physical_location = location.physical_location.as_ref().unwrap();
    assert!(physical_location.artifact_location.is_some());

    let artifact_location = physical_location.artifact_location.as_ref().unwrap();
    assert_eq!(artifact_location.uri.as_deref(), Some(target));
}

#[test]
fn test_sarif_artifacts() {
    let checks = vec![create_test_check_result(
        "cl-te",
        true,
        Some(0),
        Some("HTTP/1.1 504 Gateway Timeout"),
        Some(5000),
        None,
    )];

    let target = "https://example.com/api";
    let scan_results = ScanResults {
        target: target.to_string(),
        method: "POST".to_string(),
        timestamp: "2024-01-01T12:00:00Z".to_string(),
        checks,
    };

    let sarif = convert_to_sarif(&scan_results);

    // Verify artifacts are defined
    assert!(sarif.runs[0].artifacts.is_some());

    let artifacts = sarif.runs[0].artifacts.as_ref().unwrap();
    assert_eq!(artifacts.len(), 1);

    let artifact = &artifacts[0];
    assert!(artifact.location.is_some());

    let location = artifact.location.as_ref().unwrap();
    assert_eq!(location.uri.as_deref(), Some(target));
}

#[test]
fn test_sarif_all_check_types() {
    let check_types = vec!["cl-te", "te-cl", "te-te", "h2c", "h2"];

    for check_type in check_types {
        let checks = vec![create_test_check_result(
            check_type,
            true,
            Some(0),
            Some("Timeout"),
            Some(5000),
            None,
        )];

        let scan_results = ScanResults {
            target: "https://example.com".to_string(),
            method: "POST".to_string(),
            timestamp: "2024-01-01T12:00:00Z".to_string(),
            checks,
        };

        let sarif = convert_to_sarif(&scan_results);

        // Each check type should produce a result
        let results = sarif.runs[0]
            .results
            .as_ref()
            .expect("Results should be present");
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].rule_id.as_deref(), Some(check_type));
    }
}
