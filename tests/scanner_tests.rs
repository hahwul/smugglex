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
//! - Integration tests for run_checks_for_type function
//! - False positive reduction: multi-baseline, confirmation retries, baseline status code context

use smugglex::scanner::{run_checks_for_type, CheckParams, TIMING_MULTIPLIER, MIN_DELAY_MS, BASELINE_COUNT, CONFIRMATION_RETRIES};
use smugglex::model::CheckResult;
use std::time::Duration;
use chrono::Utc;
use indicatif::ProgressBar;
use tokio::net::TcpListener;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

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

#[test]
fn test_baseline_count_constant() {
    assert_eq!(BASELINE_COUNT, 3, "Baseline count should be 3");
}

#[test]
fn test_confirmation_retries_constant() {
    assert_eq!(CONFIRMATION_RETRIES, 2, "Confirmation retries should be 2");
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
        confidence: None,
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
        confidence: None,
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
    assert!(attack_duration_ms <= threshold);
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

// ========== Integration Tests for run_checks_for_type ==========

/// Helper function to start a mock HTTP server that responds normally
async fn start_normal_server() -> (String, u16, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let host = addr.ip().to_string();
    let port = addr.port();

    let handle = tokio::spawn(async move {
        loop {
            if let Ok((mut socket, _)) = listener.accept().await {
                tokio::spawn(async move {
                    let mut buf = vec![0u8; 4096];
                    let _ = socket.read(&mut buf).await;
                    let response = "HTTP/1.1 200 OK\r\nContent-Length: 13\r\n\r\nHello, World!";
                    let _ = socket.write_all(response.as_bytes()).await;
                });
            }
        }
    });

    (host, port, handle)
}

/// Helper function to start a mock HTTP server that responds with timeout status
/// after BASELINE_COUNT normal requests. Also responds with 504 on confirmation retries.
async fn start_timeout_server() -> (String, u16, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let host = addr.ip().to_string();
    let port = addr.port();

    let handle = tokio::spawn(async move {
        let request_count = Arc::new(AtomicUsize::new(0));
        loop {
            if let Ok((mut socket, _)) = listener.accept().await {
                let count = request_count.clone();
                tokio::spawn(async move {
                    let mut buf = vec![0u8; 4096];
                    let _ = socket.read(&mut buf).await;

                    let n = count.fetch_add(1, Ordering::SeqCst) + 1;

                    // First BASELINE_COUNT requests (baseline) return 200 OK
                    // Subsequent requests (attack + confirmation) return 504
                    let response = if n <= BASELINE_COUNT {
                        "HTTP/1.1 200 OK\r\nContent-Length: 13\r\n\r\nHello, World!"
                    } else {
                        "HTTP/1.1 504 Gateway Timeout\r\nContent-Length: 0\r\n\r\n"
                    };
                    let _ = socket.write_all(response.as_bytes()).await;
                });
            }
        }
    });

    (host, port, handle)
}

/// Helper function to start a mock HTTP server that responds slowly
/// after BASELINE_COUNT normal requests. Also delays on confirmation retries.
async fn start_slow_server() -> (String, u16, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let host = addr.ip().to_string();
    let port = addr.port();

    let handle = tokio::spawn(async move {
        let request_count = Arc::new(AtomicUsize::new(0));
        loop {
            if let Ok((mut socket, _)) = listener.accept().await {
                let count = request_count.clone();
                tokio::spawn(async move {
                    let mut buf = vec![0u8; 4096];
                    let _ = socket.read(&mut buf).await;

                    let n = count.fetch_add(1, Ordering::SeqCst) + 1;

                    // First BASELINE_COUNT requests (baseline) return immediately
                    // Subsequent requests (attack + confirmation) delay for 2 seconds
                    if n > BASELINE_COUNT {
                        tokio::time::sleep(Duration::from_millis(2000)).await;
                    }

                    let response = "HTTP/1.1 200 OK\r\nContent-Length: 13\r\n\r\nHello, World!";
                    let _ = socket.write_all(response.as_bytes()).await;
                });
            }
        }
    });

    (host, port, handle)
}

#[tokio::test]
async fn test_run_checks_for_type_not_vulnerable() {
    let (host, port, handle) = start_normal_server().await;

    let pb = ProgressBar::new_spinner();
    pb.finish_and_clear();

    let attack_requests = vec![
        format!("GET / HTTP/1.1\r\nHost: {}\r\nContent-Length: 5\r\n\r\ntest1", host),
    ];

    let result = run_checks_for_type(CheckParams {
        pb: &pb,
        check_name: "TEST",
        host: &host,
        port,
        path: "/",
        attack_requests,
        timeout: 5,
        verbose: false,
        use_tls: false,
        export_dir: None,
        current_check: 1,
        total_checks: 1,
    })
    .await;

    handle.abort();

    assert!(result.is_ok());
    let check_result = result.unwrap();
    assert!(!check_result.vulnerable);
    assert_eq!(check_result.check_type, "TEST");
    assert_eq!(check_result.payload_index, None);
    assert_eq!(check_result.confidence, None);
}

#[tokio::test]
async fn test_run_checks_for_type_vulnerable_timeout_status() {
    let (host, port, handle) = start_timeout_server().await;

    let pb = ProgressBar::new_spinner();
    pb.finish_and_clear();

    let attack_requests = vec![
        format!("GET / HTTP/1.1\r\nHost: {}\r\nContent-Length: 5\r\n\r\ntest1", host),
    ];

    let result = run_checks_for_type(CheckParams {
        pb: &pb,
        check_name: "CL.TE",
        host: &host,
        port,
        path: "/",
        attack_requests,
        timeout: 5,
        verbose: false,
        use_tls: false,
        export_dir: None,
        current_check: 1,
        total_checks: 1,
    })
    .await;

    handle.abort();

    assert!(result.is_ok());
    let check_result = result.unwrap();
    assert!(check_result.vulnerable);
    assert_eq!(check_result.check_type, "CL.TE");
    assert_eq!(check_result.payload_index, Some(0));
    assert!(check_result.attack_status.is_some());
    assert!(check_result.confidence.is_some());
}

#[tokio::test]
async fn test_run_checks_for_type_vulnerable_timing() {
    let (host, port, handle) = start_slow_server().await;

    let pb = ProgressBar::new_spinner();
    pb.finish_and_clear();

    let attack_requests = vec![
        format!("GET / HTTP/1.1\r\nHost: {}\r\nContent-Length: 5\r\n\r\ntest1", host),
    ];

    let result = run_checks_for_type(CheckParams {
        pb: &pb,
        check_name: "TE.CL",
        host: &host,
        port,
        path: "/",
        attack_requests,
        timeout: 5,
        verbose: false,
        use_tls: false,
        export_dir: None,
        current_check: 1,
        total_checks: 1,
    })
    .await;

    handle.abort();

    assert!(result.is_ok());
    let check_result = result.unwrap();
    assert!(check_result.vulnerable);
    assert_eq!(check_result.check_type, "TE.CL");
    assert_eq!(check_result.payload_index, Some(0));
    assert!(check_result.confidence.is_some());
}

#[tokio::test]
async fn test_run_checks_for_type_multiple_payloads() {
    let (host, port, handle) = start_timeout_server().await;

    let pb = ProgressBar::new_spinner();
    pb.finish_and_clear();

    // Multiple attack requests - first one should trigger vulnerability
    let attack_requests = vec![
        format!("GET / HTTP/1.1\r\nHost: {}\r\nContent-Length: 5\r\n\r\ntest1", host),
        format!("GET / HTTP/1.1\r\nHost: {}\r\nContent-Length: 5\r\n\r\ntest2", host),
    ];

    let result = run_checks_for_type(CheckParams {
        pb: &pb,
        check_name: "H2C",
        host: &host,
        port,
        path: "/test",
        attack_requests,
        timeout: 5,
        verbose: false,
        use_tls: false,
        export_dir: None,
        current_check: 2,
        total_checks: 5,
    })
    .await;

    handle.abort();

    assert!(result.is_ok());
    let check_result = result.unwrap();
    assert!(check_result.vulnerable);
    assert_eq!(check_result.payload_index, Some(0));
}

#[tokio::test]
async fn test_run_checks_for_type_with_export_dir() {
    let (host, port, handle) = start_timeout_server().await;

    let pb = ProgressBar::new_spinner();
    pb.finish_and_clear();

    let temp_dir = std::env::temp_dir().join("smugglex_test_export");
    std::fs::create_dir_all(&temp_dir).unwrap();

    let attack_requests = vec![
        format!("GET / HTTP/1.1\r\nHost: {}\r\nContent-Length: 5\r\n\r\ntest1", host),
    ];

    let result = run_checks_for_type(CheckParams {
        pb: &pb,
        check_name: "TE.TE",
        host: &host,
        port,
        path: "/",
        attack_requests,
        timeout: 5,
        verbose: false,
        use_tls: false,
        export_dir: Some(temp_dir.to_str().unwrap()),
        current_check: 1,
        total_checks: 1,
    })
    .await;

    handle.abort();

    assert!(result.is_ok());
    let check_result = result.unwrap();
    assert!(check_result.vulnerable);

    // Clean up
    let _ = std::fs::remove_dir_all(&temp_dir);
}

#[tokio::test]
async fn test_run_checks_for_type_verbose_mode() {
    let (host, port, handle) = start_normal_server().await;

    let pb = ProgressBar::new_spinner();
    pb.finish_and_clear();

    let attack_requests = vec![
        format!("GET / HTTP/1.1\r\nHost: {}\r\nContent-Length: 5\r\n\r\ntest1", host),
    ];

    let result = run_checks_for_type(CheckParams {
        pb: &pb,
        check_name: "H2",
        host: &host,
        port,
        path: "/",
        attack_requests,
        timeout: 5,
        verbose: true, // Test verbose mode
        use_tls: false,
        export_dir: None,
        current_check: 5,
        total_checks: 5,
    })
    .await;

    handle.abort();

    assert!(result.is_ok());
    let check_result = result.unwrap();
    assert!(!check_result.vulnerable);
}

#[tokio::test]
async fn test_run_checks_for_type_with_custom_path() {
    let (host, port, handle) = start_normal_server().await;

    let pb = ProgressBar::new_spinner();
    pb.finish_and_clear();

    let attack_requests = vec![
        format!("GET /api/v1/test HTTP/1.1\r\nHost: {}\r\nContent-Length: 5\r\n\r\ntest1", host),
    ];

    let result = run_checks_for_type(CheckParams {
        pb: &pb,
        check_name: "CL.TE",
        host: &host,
        port,
        path: "/api/v1/test",
        attack_requests,
        timeout: 5,
        verbose: false,
        use_tls: false,
        export_dir: None,
        current_check: 1,
        total_checks: 1,
    })
    .await;

    handle.abort();

    assert!(result.is_ok());
}

#[tokio::test]
async fn test_run_checks_for_type_empty_payloads() {
    let (host, port, handle) = start_normal_server().await;

    let pb = ProgressBar::new_spinner();
    pb.finish_and_clear();

    let attack_requests: Vec<String> = vec![]; // Empty payload list

    let result = run_checks_for_type(CheckParams {
        pb: &pb,
        check_name: "TEST",
        host: &host,
        port,
        path: "/",
        attack_requests,
        timeout: 5,
        verbose: false,
        use_tls: false,
        export_dir: None,
        current_check: 1,
        total_checks: 1,
    })
    .await;

    handle.abort();

    assert!(result.is_ok());
    let check_result = result.unwrap();
    assert!(!check_result.vulnerable);
}

#[tokio::test]
async fn test_run_checks_for_type_different_check_names() {
    let (host, port, handle) = start_normal_server().await;

    let pb = ProgressBar::new_spinner();
    pb.finish_and_clear();

    let check_names = vec!["CL.TE", "TE.CL", "TE.TE", "H2C", "H2"];

    for check_name in check_names {
        let attack_requests = vec![
            format!("GET / HTTP/1.1\r\nHost: {}\r\n\r\n", host),
        ];

        let result = run_checks_for_type(CheckParams {
            pb: &pb,
            check_name,
            host: &host,
            port,
            path: "/",
            attack_requests,
            timeout: 5,
            verbose: false,
            use_tls: false,
            export_dir: None,
            current_check: 1,
            total_checks: 1,
        })
        .await;

        assert!(result.is_ok());
        let check_result = result.unwrap();
        assert_eq!(check_result.check_type, check_name);
    }

    handle.abort();
}

#[tokio::test]
async fn test_run_checks_for_type_408_status_code() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let host = addr.ip().to_string();
    let port = addr.port();

    let handle = tokio::spawn(async move {
        let request_count = Arc::new(AtomicUsize::new(0));
        loop {
            if let Ok((mut socket, _)) = listener.accept().await {
                let count = request_count.clone();
                tokio::spawn(async move {
                    let mut buf = vec![0u8; 4096];
                    let _ = socket.read(&mut buf).await;

                    let n = count.fetch_add(1, Ordering::SeqCst) + 1;

                    // First BASELINE_COUNT requests return 200, rest return 408
                    let response = if n <= BASELINE_COUNT {
                        "HTTP/1.1 200 OK\r\nContent-Length: 13\r\n\r\nHello, World!"
                    } else {
                        "HTTP/1.1 408 Request Timeout\r\nContent-Length: 0\r\n\r\n"
                    };
                    let _ = socket.write_all(response.as_bytes()).await;
                });
            }
        }
    });

    let pb = ProgressBar::new_spinner();
    pb.finish_and_clear();

    let attack_requests = vec![
        format!("GET / HTTP/1.1\r\nHost: {}\r\n\r\n", host),
    ];

    let result = run_checks_for_type(CheckParams {
        pb: &pb,
        check_name: "CL.TE",
        host: &host,
        port,
        path: "/",
        attack_requests,
        timeout: 5,
        verbose: false,
        use_tls: false,
        export_dir: None,
        current_check: 1,
        total_checks: 1,
    })
    .await;

    handle.abort();

    assert!(result.is_ok());
    let check_result = result.unwrap();
    assert!(check_result.vulnerable);
}

#[tokio::test]
async fn test_progress_bar_integration() {
    use indicatif::ProgressStyle;

    let pb = ProgressBar::new_spinner();
    pb.set_style(
        ProgressStyle::with_template("{spinner:.cyan} {msg}")
            .unwrap()
            .tick_strings(&["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]),
    );

    pb.set_message("Testing progress");
    pb.inc(1);
    pb.finish_and_clear();

    // Progress bar created and used successfully
}

// ========== False Positive Reduction Tests ==========

/// Test: flaky 504 that only appears once but not on confirmation retries -> not vulnerable
#[tokio::test]
async fn test_flaky_504_not_confirmed() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let host = addr.ip().to_string();
    let port = addr.port();

    let handle = tokio::spawn(async move {
        let request_count = Arc::new(AtomicUsize::new(0));
        loop {
            if let Ok((mut socket, _)) = listener.accept().await {
                let count = request_count.clone();
                tokio::spawn(async move {
                    let mut buf = vec![0u8; 4096];
                    let _ = socket.read(&mut buf).await;

                    let n = count.fetch_add(1, Ordering::SeqCst) + 1;

                    // Baseline (1-3): 200 OK
                    // First attack (4): 504 (triggers initial detection)
                    // Confirmation retries (5+): 200 OK (not reproduced)
                    let response = if n <= BASELINE_COUNT {
                        "HTTP/1.1 200 OK\r\nContent-Length: 13\r\n\r\nHello, World!"
                    } else if n == BASELINE_COUNT + 1 {
                        "HTTP/1.1 504 Gateway Timeout\r\nContent-Length: 0\r\n\r\n"
                    } else {
                        "HTTP/1.1 200 OK\r\nContent-Length: 13\r\n\r\nHello, World!"
                    };
                    let _ = socket.write_all(response.as_bytes()).await;
                });
            }
        }
    });

    let pb = ProgressBar::new_spinner();
    pb.finish_and_clear();

    let attack_requests = vec![
        format!("GET / HTTP/1.1\r\nHost: {}\r\nContent-Length: 5\r\n\r\ntest1", host),
    ];

    let result = run_checks_for_type(CheckParams {
        pb: &pb,
        check_name: "CL.TE",
        host: &host,
        port,
        path: "/",
        attack_requests,
        timeout: 5,
        verbose: false,
        use_tls: false,
        export_dir: None,
        current_check: 1,
        total_checks: 1,
    })
    .await;

    handle.abort();

    assert!(result.is_ok());
    let check_result = result.unwrap();
    // Should NOT be vulnerable because confirmation retries returned 200
    assert!(!check_result.vulnerable, "Flaky 504 should not be flagged as vulnerable");
    assert_eq!(check_result.confidence, None);
}

/// Test: baseline itself returns 504 -> should not flag 504 as smuggling signal
#[tokio::test]
async fn test_baseline_504_not_flagged() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let host = addr.ip().to_string();
    let port = addr.port();

    let handle = tokio::spawn(async move {
        // All requests return 504 (server is just slow/overloaded)
        loop {
            if let Ok((mut socket, _)) = listener.accept().await {
                tokio::spawn(async move {
                    let mut buf = vec![0u8; 4096];
                    let _ = socket.read(&mut buf).await;
                    let response = "HTTP/1.1 504 Gateway Timeout\r\nContent-Length: 0\r\n\r\n";
                    let _ = socket.write_all(response.as_bytes()).await;
                });
            }
        }
    });

    let pb = ProgressBar::new_spinner();
    pb.finish_and_clear();

    let attack_requests = vec![
        format!("GET / HTTP/1.1\r\nHost: {}\r\nContent-Length: 5\r\n\r\ntest1", host),
    ];

    let result = run_checks_for_type(CheckParams {
        pb: &pb,
        check_name: "CL.TE",
        host: &host,
        port,
        path: "/",
        attack_requests,
        timeout: 5,
        verbose: false,
        use_tls: false,
        export_dir: None,
        current_check: 1,
        total_checks: 1,
    })
    .await;

    handle.abort();

    assert!(result.is_ok());
    let check_result = result.unwrap();
    // Should NOT be vulnerable because baseline also had 504
    assert!(!check_result.vulnerable, "Baseline 504 should not be flagged as smuggling");
}

/// Test: connection timeout on first attack but normal on retries -> not vulnerable (strict confirmation)
#[tokio::test]
async fn test_connection_timeout_strict_confirmation() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let host = addr.ip().to_string();
    let port = addr.port();

    let handle = tokio::spawn(async move {
        let request_count = Arc::new(AtomicUsize::new(0));
        loop {
            if let Ok((mut socket, _)) = listener.accept().await {
                let count = request_count.clone();
                tokio::spawn(async move {
                    let mut buf = vec![0u8; 4096];
                    let _ = socket.read(&mut buf).await;

                    let n = count.fetch_add(1, Ordering::SeqCst) + 1;

                    // Baseline (1-3): normal response
                    // First attack (4): delay 6 seconds (will cause timeout with 5s timeout)
                    // Confirmation retries (5+): normal response
                    if n == BASELINE_COUNT + 1 {
                        tokio::time::sleep(Duration::from_secs(6)).await;
                    }

                    let response = "HTTP/1.1 200 OK\r\nContent-Length: 13\r\n\r\nHello, World!";
                    let _ = socket.write_all(response.as_bytes()).await;
                });
            }
        }
    });

    let pb = ProgressBar::new_spinner();
    pb.finish_and_clear();

    let attack_requests = vec![
        format!("GET / HTTP/1.1\r\nHost: {}\r\nContent-Length: 5\r\n\r\ntest1", host),
    ];

    let result = run_checks_for_type(CheckParams {
        pb: &pb,
        check_name: "TE.CL",
        host: &host,
        port,
        path: "/",
        attack_requests,
        timeout: 5,
        verbose: false,
        use_tls: false,
        export_dir: None,
        current_check: 1,
        total_checks: 1,
    })
    .await;

    handle.abort();

    assert!(result.is_ok());
    let check_result = result.unwrap();
    // Should NOT be vulnerable because connection timeout not reproduced on ALL retries
    assert!(!check_result.vulnerable, "Unreproduced connection timeout should not be flagged");
}

/// Test: confirmed vulnerability with both status code + timing -> High confidence
#[tokio::test]
async fn test_confirmed_vulnerability_high_confidence() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let host = addr.ip().to_string();
    let port = addr.port();

    let handle = tokio::spawn(async move {
        let request_count = Arc::new(AtomicUsize::new(0));
        loop {
            if let Ok((mut socket, _)) = listener.accept().await {
                let count = request_count.clone();
                tokio::spawn(async move {
                    let mut buf = vec![0u8; 4096];
                    let _ = socket.read(&mut buf).await;

                    let n = count.fetch_add(1, Ordering::SeqCst) + 1;

                    if n <= BASELINE_COUNT {
                        // Baseline: fast 200 OK
                        let response = "HTTP/1.1 200 OK\r\nContent-Length: 13\r\n\r\nHello, World!";
                        let _ = socket.write_all(response.as_bytes()).await;
                    } else {
                        // Attack + confirmation: 504 with delay (both status code + timing anomaly)
                        tokio::time::sleep(Duration::from_millis(2000)).await;
                        let response = "HTTP/1.1 504 Gateway Timeout\r\nContent-Length: 0\r\n\r\n";
                        let _ = socket.write_all(response.as_bytes()).await;
                    }
                });
            }
        }
    });

    let pb = ProgressBar::new_spinner();
    pb.finish_and_clear();

    let attack_requests = vec![
        format!("GET / HTTP/1.1\r\nHost: {}\r\nContent-Length: 5\r\n\r\ntest1", host),
    ];

    let result = run_checks_for_type(CheckParams {
        pb: &pb,
        check_name: "CL.TE",
        host: &host,
        port,
        path: "/",
        attack_requests,
        timeout: 5,
        verbose: false,
        use_tls: false,
        export_dir: None,
        current_check: 1,
        total_checks: 1,
    })
    .await;

    handle.abort();

    assert!(result.is_ok());
    let check_result = result.unwrap();
    assert!(check_result.vulnerable, "Should be detected as vulnerable");
    assert_eq!(
        check_result.confidence,
        Some(smugglex::model::Confidence::High),
        "Status code + timing anomaly should yield High confidence"
    );
}

/// Test: confirmed vulnerability with timing only -> Medium confidence
/// Baseline has ~400ms latency so 2s attack delay is >3x but <6x threshold
#[tokio::test]
async fn test_confirmed_vulnerability_medium_confidence() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let host = addr.ip().to_string();
    let port = addr.port();

    let handle = tokio::spawn(async move {
        let request_count = Arc::new(AtomicUsize::new(0));
        loop {
            if let Ok((mut socket, _)) = listener.accept().await {
                let count = request_count.clone();
                tokio::spawn(async move {
                    let mut buf = vec![0u8; 4096];
                    let _ = socket.read(&mut buf).await;

                    let n = count.fetch_add(1, Ordering::SeqCst) + 1;

                    // Baseline: 400ms delay (threshold = 1200ms, 6x = 2400ms)
                    // Attack + confirmation: 2000ms delay (>1200ms but <2400ms -> Medium)
                    if n > BASELINE_COUNT {
                        tokio::time::sleep(Duration::from_millis(2000)).await;
                    } else {
                        tokio::time::sleep(Duration::from_millis(400)).await;
                    }

                    let response = "HTTP/1.1 200 OK\r\nContent-Length: 13\r\n\r\nHello, World!";
                    let _ = socket.write_all(response.as_bytes()).await;
                });
            }
        }
    });

    let pb = ProgressBar::new_spinner();
    pb.finish_and_clear();

    let attack_requests = vec![
        format!("GET / HTTP/1.1\r\nHost: {}\r\nContent-Length: 5\r\n\r\ntest1", host),
    ];

    let result = run_checks_for_type(CheckParams {
        pb: &pb,
        check_name: "TE.CL",
        host: &host,
        port,
        path: "/",
        attack_requests,
        timeout: 5,
        verbose: false,
        use_tls: false,
        export_dir: None,
        current_check: 1,
        total_checks: 1,
    })
    .await;

    handle.abort();

    assert!(result.is_ok());
    let check_result = result.unwrap();
    assert!(check_result.vulnerable, "Should be detected as vulnerable");
    assert_eq!(
        check_result.confidence,
        Some(smugglex::model::Confidence::Medium),
        "Timing-only anomaly should yield Medium confidence"
    );
}
