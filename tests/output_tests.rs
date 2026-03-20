//! Tests for output module
//!
//! This module tests result formatting and file saving logic.

use smugglex::model::{CheckResult, FingerprintInfo, ScanResults};
use smugglex::output::save_results_to_file;
use std::fs;

#[test]
fn test_save_results_to_file_creates_json() {
    let temp_dir = std::env::temp_dir();
    let output_file = temp_dir.join("smugglex_test_output.json");
    let output_path = output_file.to_str().unwrap();

    let results = vec![CheckResult {
        check_type: "cl-te".to_string(),
        vulnerable: true,
        payload_index: Some(0),
        normal_status: "HTTP/1.1 200 OK".to_string(),
        attack_status: Some("HTTP/1.1 504 Gateway Timeout".to_string()),
        normal_duration_ms: 100,
        attack_duration_ms: Some(5000),
        timestamp: "2024-01-01T00:00:00Z".to_string(),
        payload: Some("test payload".to_string()),
        confidence: None,
    }];

    let result = save_results_to_file(output_path, "http://example.com", "GET", results, &None);
    assert!(result.is_ok());

    // Verify the file was created and contains valid JSON
    let content = fs::read_to_string(output_path).unwrap();
    let parsed: ScanResults = serde_json::from_str(&content).unwrap();
    assert_eq!(parsed.target, "http://example.com");
    assert_eq!(parsed.method, "GET");
    assert_eq!(parsed.checks.len(), 1);
    assert!(parsed.checks[0].vulnerable);

    // Cleanup
    fs::remove_file(output_path).ok();
}

#[test]
fn test_save_results_to_file_with_fingerprint() {
    let temp_dir = std::env::temp_dir();
    let output_file = temp_dir.join("smugglex_test_output_fp.json");
    let output_path = output_file.to_str().unwrap();

    let fingerprint = Some(FingerprintInfo {
        detected_proxy: "nginx".to_string(),
        server_header: Some("nginx/1.24.0".to_string()),
        via_header: None,
        powered_by: None,
    });

    let results = vec![CheckResult {
        check_type: "te-cl".to_string(),
        vulnerable: false,
        payload_index: None,
        normal_status: "HTTP/1.1 200 OK".to_string(),
        attack_status: None,
        normal_duration_ms: 50,
        attack_duration_ms: None,
        timestamp: "2024-01-01T00:00:00Z".to_string(),
        payload: None,
        confidence: None,
    }];

    let result = save_results_to_file(
        output_path,
        "https://test.com",
        "POST",
        results,
        &fingerprint,
    );
    assert!(result.is_ok());

    let content = fs::read_to_string(output_path).unwrap();
    let parsed: ScanResults = serde_json::from_str(&content).unwrap();
    assert!(parsed.fingerprint.is_some());
    let fp = parsed.fingerprint.unwrap();
    assert_eq!(fp.detected_proxy, "nginx");
    assert_eq!(fp.server_header, Some("nginx/1.24.0".to_string()));

    // Cleanup
    fs::remove_file(output_path).ok();
}

#[test]
fn test_save_results_to_file_empty_results() {
    let temp_dir = std::env::temp_dir();
    let output_file = temp_dir.join("smugglex_test_output_empty.json");
    let output_path = output_file.to_str().unwrap();

    let result =
        save_results_to_file(output_path, "http://example.com", "GET", Vec::new(), &None);
    assert!(result.is_ok());

    let content = fs::read_to_string(output_path).unwrap();
    let parsed: ScanResults = serde_json::from_str(&content).unwrap();
    assert!(parsed.checks.is_empty());

    // Cleanup
    fs::remove_file(output_path).ok();
}

#[test]
fn test_save_results_to_file_invalid_path() {
    let result = save_results_to_file(
        "/nonexistent/directory/file.json",
        "http://example.com",
        "GET",
        Vec::new(),
        &None,
    );
    assert!(result.is_err());
}
