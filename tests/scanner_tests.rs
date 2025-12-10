//! Tests for smuggling detection scanner logic
//!
//! This module contains tests for:
//! - Timing-based detection thresholds and constants
//! - Timing multiplier and minimum delay validation
//! - Vulnerability detection logic for different scenarios
//! - HTTP status code parsing (408, 504 timeout codes)
//! - Edge cases for timing thresholds
//! - CheckResult state validation
//! - Progress message formatting showing current check number vs total checks (e.g., [1/4])

use smugglex::scanner::{TIMING_MULTIPLIER, MIN_DELAY_MS};
use smugglex::model::CheckResult;
use std::time::Duration;
use chrono::Utc;

// ========== Constants Tests ==========

#[test]
fn test_timing_multiplier_constant() {
    assert_eq!(TIMING_MULTIPLIER, 3, "Timing multiplier should be 3x");
}

#[test]
fn test_min_delay_constant() {
    assert_eq!(
        MIN_DELAY_MS, 1000,
        "Minimum delay should be 1000ms (1 second)"
    );
}

// ========== Progress Message Format Tests ==========

#[test]
fn test_progress_message_format_initial() {
    let current_check = 1;
    let total_checks = 4;
    let check_name = "CL.TE";
    let total_requests = 10;

    let message = format!(
        "[{}/{}] checking {} (0/{})",
        current_check, total_checks, check_name, total_requests
    );

    assert_eq!(message, "[1/4] checking CL.TE (0/10)");
}

#[test]
fn test_progress_message_format_with_percentage() {
    let current_check = 2;
    let total_checks = 4;
    let check_name = "TE.CL";
    let current = 5;
    let total_requests = 10;
    let percentage = (current as f64 / total_requests as f64 * 100.0) as u32;

    let message = format!(
        "[{}/{}] checking {} ({}/{} - {}%)",
        current_check, total_checks, check_name, current, total_requests, percentage
    );

    assert_eq!(message, "[2/4] checking TE.CL (5/10 - 50%)");
}

#[test]
fn test_progress_message_all_check_types() {
    let check_types = vec![("CL.TE", 1), ("TE.CL", 2), ("TE.TE", 3), ("H2C", 4)];
    let total_checks = 4;

    for (check_name, current_check) in check_types {
        let message = format!(
            "[{}/{}] checking {} (0/10)",
            current_check, total_checks, check_name
        );

        assert!(message.starts_with(&format!("[{}/{}]", current_check, total_checks)));
        assert!(message.contains(check_name));
    }
}

// ========== Timing Calculation Tests ==========

#[test]
fn test_timing_threshold_calculation() {
    let normal_duration = Duration::from_millis(200);
    let threshold = normal_duration.as_millis() * TIMING_MULTIPLIER;
    assert_eq!(threshold, 600, "Threshold should be 3x the normal duration");
}

#[test]
fn test_timing_threshold_various_durations() {
    // Table-driven test for different base durations
    let test_cases = vec![
        (100, 300),   // 100ms -> 300ms threshold
        (200, 600),   // 200ms -> 600ms threshold
        (500, 1500),  // 500ms -> 1500ms threshold
        (1000, 3000), // 1000ms -> 3000ms threshold
    ];

    for (base_ms, expected_threshold) in test_cases {
        let duration = Duration::from_millis(base_ms);
        let threshold = duration.as_millis() * TIMING_MULTIPLIER;
        assert_eq!(
            threshold, expected_threshold,
            "For base duration {}ms, threshold should be {}ms",
            base_ms, expected_threshold
        );
    }
}

// ========== Timing Detection Logic Tests ==========

#[test]
fn test_timing_detection_logic_vulnerable() {
    let normal_duration_ms = 200_u128;
    let attack_duration_ms = 1500_u128; // 7.5x slower
    let threshold = normal_duration_ms * TIMING_MULTIPLIER; // 600ms

    // Should be detected as vulnerable (exceeds threshold AND min delay)
    assert!(
        attack_duration_ms > threshold,
        "Attack duration should exceed threshold"
    );
    assert!(
        attack_duration_ms > MIN_DELAY_MS,
        "Attack duration should exceed minimum delay"
    );
}

#[test]
fn test_timing_detection_logic_not_vulnerable_below_threshold() {
    let normal_duration_ms = 300_u128;
    let attack_duration_ms = 800_u128; // 2.67x slower
    let threshold = normal_duration_ms * TIMING_MULTIPLIER; // 900ms

    // Should NOT be detected (below threshold even though exceeds min delay)
    assert!(
        attack_duration_ms < threshold,
        "Attack duration should be below threshold"
    );
}

#[test]
fn test_timing_detection_logic_not_vulnerable_below_min_delay() {
    let normal_duration_ms = 100_u128;
    let attack_duration_ms = 500_u128; // 5x slower
    let threshold = normal_duration_ms * TIMING_MULTIPLIER; // 300ms

    // Should NOT be detected (below min delay even though exceeds threshold)
    assert!(
        attack_duration_ms > threshold,
        "Attack duration exceeds threshold but is too fast"
    );
    assert!(
        attack_duration_ms < MIN_DELAY_MS,
        "Attack duration should be below minimum delay"
    );
}

// Table-driven test for timing detection scenarios
#[test]
fn test_timing_detection_scenarios() {
    struct TestCase {
        name: &'static str,
        normal_ms: u128,
        attack_ms: u128,
        should_detect: bool,
    }

    let test_cases = vec![
        TestCase {
            name: "Clearly vulnerable - 10x slower",
            normal_ms: 200,
            attack_ms: 2000,
            should_detect: true,
        },
        TestCase {
            name: "Just above threshold and min delay",
            normal_ms: 400,
            attack_ms: 1201, // > 1200 (3x) and > 1000
            should_detect: true,
        },
        TestCase {
            name: "Below threshold",
            normal_ms: 500,
            attack_ms: 1400, // < 1500 (3x)
            should_detect: false,
        },
        TestCase {
            name: "Above threshold but below min delay",
            normal_ms: 100,
            attack_ms: 400, // > 300 (3x) but < 1000
            should_detect: false,
        },
        TestCase {
            name: "Edge case - exactly at min delay",
            normal_ms: 200,
            attack_ms: 1000,      // = MIN_DELAY_MS
            should_detect: false, // Not greater than MIN_DELAY_MS
        },
    ];

    for tc in test_cases {
        let threshold = tc.normal_ms * TIMING_MULTIPLIER;
        let exceeds_threshold = tc.attack_ms > threshold;
        let exceeds_min_delay = tc.attack_ms > MIN_DELAY_MS;
        let detected = exceeds_threshold && exceeds_min_delay;

        assert_eq!(
            detected, tc.should_detect,
            "Test case '{}' failed: normal={}ms, attack={}ms, threshold={}ms, detected={}, expected={}",
            tc.name, tc.normal_ms, tc.attack_ms, threshold, detected, tc.should_detect
        );
    }
}

// ========== HTTP Status Code Parsing Tests ==========

#[test]
fn test_status_code_parsing_valid_http11() {
    let status_line = "HTTP/1.1 504 Gateway Timeout";
    let parts: Vec<&str> = status_line.split_whitespace().collect();
    // "HTTP/1.1", "504", "Gateway", "Timeout" = 4 parts
    assert_eq!(parts.len(), 4, "Status line should have 4 parts");
    assert!(
        parts[0].starts_with("HTTP/1."),
        "Should be HTTP/1.x protocol"
    );
    let status_code = parts[1].parse::<u16>().ok();
    assert_eq!(status_code, Some(504), "Status code should be 504");
}

#[test]
fn test_status_code_parsing_valid_http2() {
    let status_line = "HTTP/2 408 Request Timeout";
    let parts: Vec<&str> = status_line.split_whitespace().collect();
    assert!(parts[0].starts_with("HTTP/2"), "Should be HTTP/2 protocol");
    let status_code = parts[1].parse::<u16>().ok();
    assert_eq!(status_code, Some(408), "Status code should be 408");
}

// Table-driven test for various status codes
#[test]
fn test_status_code_parsing_various_codes() {
    let test_cases = vec![
        ("HTTP/1.1 200 OK", Some(200)),
        ("HTTP/1.1 404 Not Found", Some(404)),
        ("HTTP/1.1 500 Internal Server Error", Some(500)),
        ("HTTP/1.1 502 Bad Gateway", Some(502)),
        ("HTTP/1.1 503 Service Unavailable", Some(503)),
        ("HTTP/2 200 OK", Some(200)),
        ("HTTP/2.0 404 Not Found", Some(404)),
    ];

    for (status_line, expected_code) in test_cases {
        let parts: Vec<&str> = status_line.split_whitespace().collect();
        let status_code = if parts.len() >= 2
            && (parts[0].starts_with("HTTP/1.") || parts[0].starts_with("HTTP/2"))
        {
            parts[1].parse::<u16>().ok()
        } else {
            None
        };
        assert_eq!(
            status_code, expected_code,
            "Status code should match for '{}'",
            status_line
        );
    }
}

#[test]
fn test_status_code_parsing_invalid_format() {
    let status_line = "Invalid response";
    let parts: Vec<&str> = status_line.split_whitespace().collect();
    let status_code = if parts.len() >= 2
        && (parts[0].starts_with("HTTP/1.") || parts[0].starts_with("HTTP/2"))
    {
        parts[1].parse::<u16>().ok()
    } else {
        None
    };
    assert_eq!(status_code, None);
}

#[test]
fn test_timeout_status_codes() {
    let timeout_codes = [408_u16, 504_u16];
    for code in timeout_codes {
        assert!(matches!(Some(code), Some(408) | Some(504)));
    }
}

#[test]
fn test_non_timeout_status_codes() {
    let normal_codes = [200_u16, 404_u16, 500_u16, 502_u16, 503_u16];
    for code in normal_codes {
        assert!(!matches!(Some(code), Some(408) | Some(504)));
    }
}

#[test]
fn test_check_result_vulnerable_state() {
    let result = CheckResult {
        check_type: "CL.TE".to_string(),
        vulnerable: true,
        payload_index: Some(2),
        normal_status: "HTTP/1.1 200 OK".to_string(),
        attack_status: Some("HTTP/1.1 504 Gateway Timeout".to_string()),
        normal_duration_ms: 150,
        attack_duration_ms: Some(5000),
        timestamp: Utc::now().to_rfc3339(),
        payload: None,
    };

    assert!(result.vulnerable);
    assert_eq!(result.payload_index, Some(2));
    assert!(result.attack_status.is_some());
    assert!(result.attack_duration_ms.is_some());
}

#[test]
fn test_check_result_not_vulnerable_state() {
    let result = CheckResult {
        check_type: "TE.CL".to_string(),
        vulnerable: false,
        payload_index: None,
        normal_status: "HTTP/1.1 200 OK".to_string(),
        attack_status: None,
        normal_duration_ms: 150,
        attack_duration_ms: None,
        timestamp: Utc::now().to_rfc3339(),
        payload: None,
    };

    assert!(!result.vulnerable);
    assert_eq!(result.payload_index, None);
    assert!(result.attack_status.is_none());
}

#[test]
fn test_duration_conversion() {
    let duration = Duration::from_millis(1500);
    let millis = duration.as_millis() as u64;
    assert_eq!(millis, 1500);
}

#[test]
fn test_edge_case_exact_threshold() {
    let normal_duration_ms = 500_u128;
    let threshold = normal_duration_ms * TIMING_MULTIPLIER; // 1500ms
    let attack_duration_ms = 1500_u128; // Exactly at threshold

    // At exact threshold, should NOT be detected (needs to exceed, not equal)
    assert_eq!(attack_duration_ms, threshold);
    assert!(!(attack_duration_ms > threshold));
}

#[test]
fn test_edge_case_just_above_threshold() {
    let normal_duration_ms = 500_u128;
    let threshold = normal_duration_ms * TIMING_MULTIPLIER; // 1500ms
    let attack_duration_ms = 1501_u128; // Just above threshold

    // Should be detected (exceeds threshold AND min delay)
    assert!(attack_duration_ms > threshold);
    assert!(attack_duration_ms > MIN_DELAY_MS);
}
