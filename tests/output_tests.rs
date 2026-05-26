//! Tests for output module
//!
//! This module tests result formatting and file saving logic.

use smugglex::model::{BatchScanResults, CheckResult, FingerprintInfo, ScanResults};
use smugglex::output::{build_batch_results, save_batch_to_file, save_results_to_file};
use std::fs;

fn sample_check_result(check_type: &str, vulnerable: bool) -> CheckResult {
    CheckResult {
        check_type: check_type.to_string(),
        vulnerable,
        payload_index: Some(0),
        normal_status: "HTTP/1.1 200 OK".to_string(),
        attack_status: vulnerable.then_some("HTTP/1.1 504 Gateway Timeout".to_string()),
        normal_duration_ms: 100,
        attack_duration_ms: vulnerable.then_some(5000),
        timestamp: "2024-01-01T00:00:00Z".to_string(),
        payload: Some("test payload".to_string()),
        confidence: None,
        detection_signals: Vec::new(),
        diagnostics: Vec::new(),
    }
}

#[test]
fn test_save_results_to_file_creates_json() {
    let temp_dir = std::env::temp_dir();
    let output_file = temp_dir.join("smugglex_test_output.json");
    let output_path = output_file.to_str().unwrap();

    let results = vec![sample_check_result("cl-te", true)];

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

    let mut result = sample_check_result("te-cl", false);
    result.payload_index = None;
    result.payload = None;
    result.normal_duration_ms = 50;
    let results = vec![result];

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

    let result = save_results_to_file(output_path, "http://example.com", "GET", Vec::new(), &None);
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

#[test]
fn test_build_batch_results_summary_counts_failures_and_vulnerabilities() {
    let results = vec![
        ScanResults {
            target: "http://one.example".to_string(),
            method: "GET".to_string(),
            timestamp: "2024-01-01T00:00:00Z".to_string(),
            fingerprint: None,
            checks: vec![
                sample_check_result("cl-te", true),
                sample_check_result("te-cl", false),
            ],
            error: None,
        },
        ScanResults {
            target: "http://two.example".to_string(),
            method: "GET".to_string(),
            timestamp: "2024-01-01T00:00:00Z".to_string(),
            fingerprint: None,
            checks: vec![],
            error: Some("URL parse error".to_string()),
        },
    ];

    let batch = build_batch_results(results, Some("0.2.0"));

    assert_eq!(batch.summary.total_targets, 2);
    assert_eq!(batch.summary.vulnerable_targets, 1);
    assert_eq!(batch.summary.total_checks, 2);
    assert_eq!(batch.summary.vulnerable_checks, 1);
}

#[test]
fn test_save_batch_to_file_creates_parseable_json() {
    let temp_dir = std::env::temp_dir();
    let output_file = temp_dir.join("smugglex_test_batch_output.json");
    let output_path = output_file.to_str().unwrap();

    let batch = build_batch_results(
        vec![ScanResults {
            target: "http://example.com".to_string(),
            method: "GET".to_string(),
            timestamp: "2024-01-01T00:00:00Z".to_string(),
            fingerprint: None,
            checks: vec![sample_check_result("cl-te", false)],
            error: None,
        }],
        Some("0.2.0"),
    );

    let result = save_batch_to_file(&batch, output_path);
    assert!(result.is_ok());

    let content = fs::read_to_string(output_path).unwrap();
    let parsed: BatchScanResults = serde_json::from_str(&content).unwrap();
    assert_eq!(parsed.summary.total_targets, 1);
    assert_eq!(parsed.results.len(), 1);
    assert_eq!(parsed.results[0].target, "http://example.com");

    fs::remove_file(output_path).ok();
}
