//! Tests for utility functions
//!
//! This module contains tests for:
//! - Payload export functionality
//! - Hostname sanitization for file names
//! - Directory creation and file management
//! - Multiple file exports
//! - Protocol handling (HTTP/HTTPS)

use smugglex::utils::{export_payload, parse_status_code, sanitize_hostname};
use std::env;
use std::fs;
use std::path::Path;

/// Helper function to create a temporary test directory
fn create_test_dir(name: &str) -> String {
    let temp_dir = env::temp_dir().join(format!("smugglex_test_{}", name));
    let temp_dir_str = temp_dir.to_str().unwrap().to_string();
    let _ = fs::remove_dir_all(&temp_dir_str); // Clean up if exists
    temp_dir_str
}

/// Helper function to cleanup test directory
fn cleanup_test_dir(dir: &str) {
    let _ = fs::remove_dir_all(dir);
}
#[test]
fn test_export_payload_creates_file() {
    let temp_dir = create_test_dir("export");

    let payload = "POST / HTTP/1.1\r\nHost: example.com\r\n\r\n";
    let result = export_payload(&temp_dir, "example.com", "CLTE", 0, payload, true);

    assert!(result.is_ok(), "export_payload should succeed");
    let filename = result.unwrap();
    assert!(
        Path::new(&filename).exists(),
        "Exported file should exist at {}",
        filename
    );

    let content = fs::read_to_string(&filename).unwrap();
    assert_eq!(
        content, payload,
        "File content should match the payload exactly"
    );

    cleanup_test_dir(&temp_dir);
}

#[test]
fn test_export_payload_sanitizes_hostname() {
    let temp_dir = create_test_dir("sanitize");

    let result = export_payload(&temp_dir, "sub.example.com:8080", "TECL", 1, "test", false);

    assert!(result.is_ok(), "export_payload should succeed");
    let filename = result.unwrap();

    // Verify filename contains sanitized components
    assert!(
        filename.contains("sub_example_com_8080"),
        "Filename should sanitize dots and colons to underscores"
    );
    assert!(
        filename.contains("http_"),
        "Filename should indicate HTTP protocol"
    );
    assert!(
        filename.contains("TECL"),
        "Filename should include check type"
    );
    assert!(
        filename.contains("_1.txt"),
        "Filename should include payload index"
    );

    cleanup_test_dir(&temp_dir);
}

#[test]
fn test_sanitize_hostname_dots() {
    let result = sanitize_hostname("example.com");
    assert_eq!(
        result, "example_com",
        "Dots should be replaced with underscores"
    );
}

#[test]
fn test_sanitize_hostname_colons() {
    let result = sanitize_hostname("example.com:8080");
    assert_eq!(
        result, "example_com_8080",
        "Colons should be replaced with underscores"
    );
}

#[test]
fn test_sanitize_hostname_slashes() {
    let result = sanitize_hostname("example.com/path");
    assert_eq!(
        result, "example_com_path",
        "Slashes should be replaced with underscores"
    );
}

#[test]
fn test_sanitize_hostname_multiple_special_chars() {
    let result = sanitize_hostname("sub.example.com:8080/path");
    assert_eq!(
        result, "sub_example_com_8080_path",
        "All special characters should be replaced with underscores"
    );
}

#[test]
fn test_sanitize_hostname_no_special_chars() {
    let result = sanitize_hostname("localhost");
    assert_eq!(
        result, "localhost",
        "Should remain unchanged if no special chars"
    );
}

#[test]
fn test_export_payload_with_https() {
    let temp_dir = create_test_dir("https");

    let result = export_payload(&temp_dir, "secure.example.com", "CL.TE", 0, "payload", true);

    assert!(result.is_ok(), "export_payload should succeed");
    let filename = result.unwrap();
    assert!(
        filename.contains("https_"),
        "Filename should indicate HTTPS protocol"
    );

    cleanup_test_dir(&temp_dir);
}

#[test]
fn test_export_payload_multiple_files() {
    let temp_dir = create_test_dir("multiple");

    // Export multiple payloads
    let result1 = export_payload(&temp_dir, "example.com", "CL.TE", 0, "payload1", true);
    let result2 = export_payload(&temp_dir, "example.com", "CL.TE", 1, "payload2", true);
    let result3 = export_payload(&temp_dir, "example.com", "TE.CL", 0, "payload3", true);

    assert!(result1.is_ok(), "First export should succeed");
    assert!(result2.is_ok(), "Second export should succeed");
    assert!(result3.is_ok(), "Third export should succeed");

    let file1 = result1.unwrap();
    let file2 = result2.unwrap();
    let file3 = result3.unwrap();

    // Verify all files exist and are different
    assert!(Path::new(&file1).exists(), "First file should exist");
    assert!(Path::new(&file2).exists(), "Second file should exist");
    assert!(Path::new(&file3).exists(), "Third file should exist");
    assert_ne!(file1, file2, "Files should have different names");
    assert_ne!(file1, file3, "Files should have different names");
    assert_ne!(file2, file3, "Files should have different names");

    cleanup_test_dir(&temp_dir);
}

#[test]
fn test_export_payload_creates_directory_if_not_exists() {
    let temp_dir = env::temp_dir().join("smugglex_test_new_dir");
    let temp_dir_str = temp_dir.to_str().unwrap();

    // Ensure directory doesn't exist
    let _ = fs::remove_dir_all(temp_dir_str);

    let result = export_payload(temp_dir_str, "example.com", "CL.TE", 0, "test", true);

    assert!(result.is_ok(), "export_payload should create directory");
    assert!(
        Path::new(temp_dir_str).exists(),
        "Directory should be created"
    );

    cleanup_test_dir(temp_dir_str);
}

#[test]
fn test_parse_status_code_http11_200() {
    assert_eq!(parse_status_code("HTTP/1.1 200 OK"), Some(200));
}

#[test]
fn test_parse_status_code_http10_404() {
    assert_eq!(parse_status_code("HTTP/1.0 404 Not Found"), Some(404));
}

#[test]
fn test_parse_status_code_http2() {
    assert_eq!(parse_status_code("HTTP/2 301 Moved Permanently"), Some(301));
}

#[test]
fn test_parse_status_code_invalid() {
    assert_eq!(parse_status_code("not a status line"), None);
}

#[test]
fn test_parse_status_code_empty() {
    assert_eq!(parse_status_code(""), None);
}

#[test]
fn test_parse_status_code_partial() {
    assert_eq!(parse_status_code("HTTP/1.1"), None);
}
