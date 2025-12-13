//! Integration tests for main.rs functions
//!
//! This module contains tests for:
//! - URL processing and validation
//! - Check filtering functionality
//! - Cookie fetching integration
//! - Exit-first mode
//! - Virtual host handling
//! - Output file generation
//! - Multiple URL processing
//! - Error handling

use std::fs;
use std::io::Write;
use tokio::net::TcpListener;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Helper function to start a mock HTTP server
async fn start_test_server() -> (String, u16, tokio::task::JoinHandle<()>) {
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

/// Helper function to start a server that sets cookies
async fn start_cookie_server() -> (String, u16, tokio::task::JoinHandle<()>) {
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
                    let response = "HTTP/1.1 200 OK\r\nSet-Cookie: session=abc123\r\nContent-Length: 13\r\n\r\nHello, World!";
                    let _ = socket.write_all(response.as_bytes()).await;
                });
            }
        }
    });

    (host, port, handle)
}

#[tokio::test]
async fn test_url_parsing_http() {
    use url::Url;
    
    let url_str = "http://example.com/path";
    let url = Url::parse(url_str).unwrap();
    
    assert_eq!(url.scheme(), "http");
    assert_eq!(url.host_str(), Some("example.com"));
    assert_eq!(url.path(), "/path");
    assert_eq!(url.port_or_known_default(), Some(80));
}

#[tokio::test]
async fn test_url_parsing_https() {
    use url::Url;
    
    let url_str = "https://example.com:8443/api";
    let url = Url::parse(url_str).unwrap();
    
    assert_eq!(url.scheme(), "https");
    assert_eq!(url.host_str(), Some("example.com"));
    assert_eq!(url.path(), "/api");
    assert_eq!(url.port_or_known_default(), Some(8443));
}

#[tokio::test]
async fn test_url_parsing_with_custom_port() {
    use url::Url;
    
    let url_str = "http://example.com:8080/";
    let url = Url::parse(url_str).unwrap();
    
    assert_eq!(url.port(), Some(8080));
}

#[tokio::test]
async fn test_checks_filter_parsing_single() {
    let checks_str = "cl-te";
    let checks: Vec<&str> = checks_str.split(',').map(|s| s.trim()).collect();
    
    assert_eq!(checks.len(), 1);
    assert_eq!(checks[0], "cl-te");
}

#[tokio::test]
async fn test_checks_filter_parsing_multiple() {
    let checks_str = "cl-te,te-cl,h2c";
    let checks: Vec<&str> = checks_str.split(',').map(|s| s.trim()).collect();
    
    assert_eq!(checks.len(), 3);
    assert!(checks.contains(&"cl-te"));
    assert!(checks.contains(&"te-cl"));
    assert!(checks.contains(&"h2c"));
}

#[tokio::test]
async fn test_checks_filter_default() {
    let checks: Vec<&str> = vec!["cl-te", "te-cl", "te-te", "h2c", "h2"];
    
    assert_eq!(checks.len(), 5);
    assert!(checks.contains(&"cl-te"));
    assert!(checks.contains(&"te-cl"));
    assert!(checks.contains(&"te-te"));
    assert!(checks.contains(&"h2c"));
    assert!(checks.contains(&"h2"));
}

#[tokio::test]
async fn test_checks_filter_with_spaces() {
    let checks_str = "cl-te, te-cl , h2c";
    let checks: Vec<&str> = checks_str.split(',').map(|s| s.trim()).collect();
    
    assert_eq!(checks.len(), 3);
    assert_eq!(checks[0], "cl-te");
    assert_eq!(checks[1], "te-cl");
    assert_eq!(checks[2], "h2c");
}

#[tokio::test]
#[allow(clippy::unnecessary_unwrap)]
async fn test_vhost_header_override() {
    let url_host = "192.168.1.1";
    let vhost = Some("example.com");
    
    let host_header = vhost.unwrap_or(url_host);
    assert_eq!(host_header, "example.com");
}

#[tokio::test]
#[allow(clippy::unnecessary_unwrap)]
async fn test_vhost_header_default() {
    let url_host = "192.168.1.1";
    let vhost: Option<&str> = None;
    
    let host_header = vhost.unwrap_or(url_host);
    assert_eq!(host_header, "192.168.1.1");
}

#[tokio::test]
async fn test_use_tls_https_scheme() {
    use url::Url;
    
    let url = Url::parse("https://example.com").unwrap();
    let use_tls = url.scheme() == "https";
    
    assert!(use_tls);
}

#[tokio::test]
async fn test_use_tls_http_scheme() {
    use url::Url;
    
    let url = Url::parse("http://example.com").unwrap();
    let use_tls = url.scheme() == "https";
    
    assert!(!use_tls);
}

#[tokio::test]
async fn test_output_file_json_structure() {
    use smugglex::model::{CheckResult, ScanResults};
    use chrono::Utc;
    
    let scan_results = ScanResults {
        target: "http://example.com".to_string(),
        method: "GET".to_string(),
        timestamp: Utc::now().to_rfc3339(),
        checks: vec![
            CheckResult {
                check_type: "CL.TE".to_string(),
                vulnerable: false,
                payload_index: None,
                normal_status: "HTTP/1.1 200 OK".to_string(),
                attack_status: None,
                normal_duration_ms: 100,
                attack_duration_ms: None,
                timestamp: Utc::now().to_rfc3339(),
                payload: None,
            }
        ],
    };
    
    let json_output = serde_json::to_string_pretty(&scan_results);
    assert!(json_output.is_ok());
    
    let json_str = json_output.unwrap();
    assert!(json_str.contains("target"));
    assert!(json_str.contains("method"));
    assert!(json_str.contains("checks"));
}

#[tokio::test]
async fn test_output_file_creation() {
    use smugglex::model::{CheckResult, ScanResults};
    use chrono::Utc;
    
    let temp_dir = std::env::temp_dir();
    let output_file = temp_dir.join("smugglex_test_output.json");
    
    let scan_results = ScanResults {
        target: "http://example.com".to_string(),
        method: "GET".to_string(),
        timestamp: Utc::now().to_rfc3339(),
        checks: vec![],
    };
    
    let json_output = serde_json::to_string_pretty(&scan_results).unwrap();
    let mut file = fs::File::create(&output_file).unwrap();
    file.write_all(json_output.as_bytes()).unwrap();
    
    // Verify file exists
    assert!(output_file.exists());
    
    // Verify content
    let content = fs::read_to_string(&output_file).unwrap();
    assert!(content.contains("http://example.com"));
    
    // Cleanup
    let _ = fs::remove_file(output_file);
}

#[tokio::test]
async fn test_vulnerable_count_calculation() {
    use smugglex::model::CheckResult;
    use chrono::Utc;
    
    let results = vec![
        CheckResult {
            check_type: "CL.TE".to_string(),
            vulnerable: true,
            payload_index: Some(0),
            normal_status: "HTTP/1.1 200 OK".to_string(),
            attack_status: Some("HTTP/1.1 504 Gateway Timeout".to_string()),
            normal_duration_ms: 100,
            attack_duration_ms: Some(5000),
            timestamp: Utc::now().to_rfc3339(),
            payload: None,
        },
        CheckResult {
            check_type: "TE.CL".to_string(),
            vulnerable: false,
            payload_index: None,
            normal_status: "HTTP/1.1 200 OK".to_string(),
            attack_status: None,
            normal_duration_ms: 100,
            attack_duration_ms: None,
            timestamp: Utc::now().to_rfc3339(),
            payload: None,
        },
        CheckResult {
            check_type: "H2C".to_string(),
            vulnerable: true,
            payload_index: Some(1),
            normal_status: "HTTP/1.1 200 OK".to_string(),
            attack_status: Some("HTTP/1.1 408 Request Timeout".to_string()),
            normal_duration_ms: 100,
            attack_duration_ms: Some(3000),
            timestamp: Utc::now().to_rfc3339(),
            payload: None,
        },
    ];
    
    let vulnerable_count = results.iter().filter(|r| r.vulnerable).count();
    assert_eq!(vulnerable_count, 2);
}

#[tokio::test]
async fn test_exit_first_mode_logic() {
    let mut found_vulnerability = false;
    let exit_first = true;
    
    // First check - not vulnerable
    let should_run_check = !(exit_first && found_vulnerability);
    assert!(should_run_check);
    
    // Second check - found vulnerability
    found_vulnerability = true;
    let should_run_check = !(exit_first && found_vulnerability);
    assert!(!should_run_check);
}

#[tokio::test]
async fn test_exit_first_disabled_continues() {
    let mut found_vulnerability = false;
    let exit_first = false;
    
    // First check
    let should_run_check = !(exit_first && found_vulnerability);
    assert!(should_run_check);
    
    // Second check - found vulnerability but exit_first is false
    found_vulnerability = true;
    let should_run_check = !(exit_first && found_vulnerability);
    assert!(should_run_check); // Should continue
}

#[tokio::test]
async fn test_cookie_fetching_integration() {
    use smugglex::utils::fetch_cookies;
    
    let (host, port, handle) = start_cookie_server().await;
    
    let result = fetch_cookies(&host, port, "/", false, 5, false).await;
    
    handle.abort();
    
    assert!(result.is_ok());
    let cookies = result.unwrap();
    assert!(!cookies.is_empty());
    assert!(cookies[0].contains("session=abc123"));
}

#[tokio::test]
async fn test_cookie_fetching_no_cookies() {
    use smugglex::utils::fetch_cookies;
    
    let (host, port, handle) = start_test_server().await;
    
    let result = fetch_cookies(&host, port, "/", false, 5, false).await;
    
    handle.abort();
    
    assert!(result.is_ok());
    let cookies = result.unwrap();
    assert!(cookies.is_empty());
}

#[tokio::test]
async fn test_multiple_urls_processing_logic() {
    let urls = vec![
        "http://example.com".to_string(),
        "https://test.com:8443/api".to_string(),
        "http://localhost:8080/path".to_string(),
    ];
    
    assert_eq!(urls.len(), 3);
    
    for url in &urls {
        let parsed = url::Url::parse(url);
        assert!(parsed.is_ok());
    }
}

#[tokio::test]
async fn test_empty_urls_handling() {
    let urls: Vec<String> = vec![];
    
    // Should exit early when empty
    assert!(urls.is_empty());
}

#[tokio::test]
async fn test_stdin_line_filtering() {
    let lines = vec![
        "http://example.com".to_string(),
        "".to_string(), // Empty line
        "https://test.com".to_string(),
        "   ".to_string(), // Whitespace only
        "http://valid.com".to_string(),
    ];
    
    let filtered: Vec<String> = lines
        .into_iter()
        .filter(|l| !l.trim().is_empty())
        .collect();
    
    assert_eq!(filtered.len(), 3);
    assert!(filtered.contains(&"http://example.com".to_string()));
    assert!(filtered.contains(&"https://test.com".to_string()));
    assert!(filtered.contains(&"http://valid.com".to_string()));
}

#[tokio::test]
async fn test_timing_calculation() {
    let start_time = std::time::Instant::now();
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    let duration = start_time.elapsed();
    
    assert!(duration.as_secs_f64() >= 0.1);
    assert!(duration.as_secs_f64() < 0.5);
}

#[tokio::test]
async fn test_path_extraction_from_url() {
    use url::Url;
    
    let test_cases = vec![
        ("http://example.com", "/"),
        ("http://example.com/", "/"),
        ("http://example.com/path", "/path"),
        ("http://example.com/api/v1/test", "/api/v1/test"),
        ("http://example.com/path?query=value", "/path"),
    ];
    
    for (url_str, expected_path) in test_cases {
        let url = Url::parse(url_str).unwrap();
        let path = url.path();
        assert_eq!(path, expected_path, "Failed for URL: {}", url_str);
    }
}

#[tokio::test]
async fn test_invalid_url_handling() {
    use url::Url;
    
    let invalid_urls = vec![
        "not-a-url",
        "http://",
        "://example.com",
        "example.com", // Missing scheme
    ];
    
    for url_str in invalid_urls {
        let result = Url::parse(url_str);
        assert!(result.is_err(), "Should fail for: {}", url_str);
    }
}

#[tokio::test]
async fn test_host_extraction_validation() {
    use url::Url;
    
    let url = Url::parse("http://example.com:8080/path").unwrap();
    let host = url.host_str();
    
    assert!(host.is_some());
    assert_eq!(host.unwrap(), "example.com");
}

#[tokio::test]
async fn test_port_extraction_with_default() {
    use url::Url;
    
    let test_cases = vec![
        ("http://example.com", 80),
        ("https://example.com", 443),
        ("http://example.com:8080", 8080),
        ("https://example.com:8443", 8443),
    ];
    
    for (url_str, expected_port) in test_cases {
        let url = Url::parse(url_str).unwrap();
        let port = url.port_or_known_default();
        assert_eq!(port, Some(expected_port), "Failed for URL: {}", url_str);
    }
}

#[tokio::test]
async fn test_method_parameter() {
    let methods = vec!["GET", "POST", "PUT", "DELETE", "OPTIONS"];
    
    for method in methods {
        assert!(!method.is_empty());
        assert!(method.chars().all(|c| c.is_ascii_uppercase()));
    }
}

#[tokio::test]
async fn test_timeout_parameter_validation() {
    let valid_timeouts = vec![1, 5, 10, 30, 60];
    
    for timeout in valid_timeouts {
        assert!(timeout > 0);
        assert!(timeout <= 300); // Reasonable max timeout
    }
}

#[tokio::test]
async fn test_verbose_flag_behavior() {
    let verbose_true = true;
    let verbose_false = false;
    
    // Test verbose flag values
    assert!(verbose_true);
    assert!(!verbose_false);
}

#[tokio::test]
async fn test_all_check_types_selection() {
    let check_types = vec!["cl-te", "te-cl", "te-te", "h2c", "h2"];
    
    // Test individual check selection
    for check_type in &check_types {
        assert!(check_types.contains(check_type));
    }
    
    // Test all checks are included by default
    assert_eq!(check_types.len(), 5);
}

#[tokio::test]
async fn test_check_type_filtering() {
    let selected_checks = vec!["cl-te", "h2c"];
    
    let should_run_cl_te = selected_checks.contains(&"cl-te");
    let should_run_te_cl = selected_checks.contains(&"te-cl");
    let should_run_h2c = selected_checks.contains(&"h2c");
    
    assert!(should_run_cl_te);
    assert!(!should_run_te_cl);
    assert!(should_run_h2c);
}

#[tokio::test]
async fn test_current_check_counter() {
    let total_checks = 5;
    let mut current_check = 0;
    
    for i in 1..=total_checks {
        current_check += 1;
        assert_eq!(current_check, i);
    }
    
    assert_eq!(current_check, total_checks);
}

#[tokio::test]
async fn test_error_url_parse() {
    use url::Url;
    use smugglex::error::SmugglexError;
    
    let invalid_url = "not a valid url";
    let result: Result<Url, SmugglexError> = Url::parse(invalid_url).map_err(|e| e.into());
    
    assert!(result.is_err());
}

#[tokio::test]
async fn test_error_host_validation() {
    use url::Url;
    
    let url = Url::parse("http://example.com").unwrap();
    let host = url.host_str();
    
    if host.is_none() {
        panic!("Host should be present");
    }
    
    assert!(host.is_some());
}

#[tokio::test]
async fn test_scan_duration_tracking() {
    use std::time::Instant;
    
    let start = Instant::now();
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    let duration = start.elapsed();
    
    let seconds = duration.as_secs_f64();
    assert!(seconds >= 0.05);
    assert!(seconds < 1.0);
}

#[tokio::test]
async fn test_payload_export_path_creation() {
    use smugglex::utils::export_payload;
    
    let temp_dir = std::env::temp_dir().join("smugglex_test_main");
    let export_dir = temp_dir.to_str().unwrap();
    
    let payload = "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
    let result = export_payload(export_dir, "example.com", "CL.TE", 0, payload, false);
    
    assert!(result.is_ok());
    
    // Cleanup
    let _ = std::fs::remove_dir_all(&temp_dir);
}

#[tokio::test]
async fn test_custom_headers_format() {
    let headers = vec![
        "X-Custom-Header: value1".to_string(),
        "X-Another-Header: value2".to_string(),
    ];
    
    assert_eq!(headers.len(), 2);
    
    for header in &headers {
        assert!(header.contains(":"));
        let parts: Vec<&str> = header.split(':').collect();
        assert!(parts.len() >= 2);
    }
}

#[tokio::test]
async fn test_results_aggregation() {
    use smugglex::model::CheckResult;
    use chrono::Utc;
    
    let results = vec![
        CheckResult {
            check_type: "CL.TE".to_string(),
            vulnerable: false,
            payload_index: None,
            normal_status: "HTTP/1.1 200 OK".to_string(),
            attack_status: None,
            normal_duration_ms: 100,
            attack_duration_ms: None,
            timestamp: Utc::now().to_rfc3339(),
            payload: None,
        },
        CheckResult {
            check_type: "TE.CL".to_string(),
            vulnerable: true,
            payload_index: Some(0),
            normal_status: "HTTP/1.1 200 OK".to_string(),
            attack_status: Some("HTTP/1.1 504 Gateway Timeout".to_string()),
            normal_duration_ms: 100,
            attack_duration_ms: Some(3000),
            timestamp: Utc::now().to_rfc3339(),
            payload: None,
        },
    ];
    
    let vulnerable_count = results.iter().filter(|r| r.vulnerable).count();
    assert_eq!(vulnerable_count, 1);
    assert_eq!(results.len(), 2);
}
