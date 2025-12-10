//! Tests for error handling module
//!
//! This module contains tests for:
//! - Display trait implementation for SmugglexError
//! - From trait implementations for converting external errors
//! - Error trait implementation

use smugglex::error::SmugglexError;
use std::error::Error;
use std::io;

/// Test Display implementation for HttpRequest variant
#[test]
fn test_display_http_request_error() {
    let err = SmugglexError::HttpRequest("connection failed".to_string());
    assert_eq!(format!("{}", err), "HTTP request error: connection failed");
}

/// Test Display implementation for Tls variant
#[test]
fn test_display_tls_error() {
    let err = SmugglexError::Tls("certificate invalid".to_string());
    assert_eq!(format!("{}", err), "TLS error: certificate invalid");
}

/// Test Display implementation for UrlParse variant
#[test]
fn test_display_url_parse_error() {
    let err = SmugglexError::UrlParse("invalid URL".to_string());
    assert_eq!(format!("{}", err), "URL parsing error: invalid URL");
}

/// Test Display implementation for Io variant
#[test]
fn test_display_io_error() {
    let err = SmugglexError::Io("file not found".to_string());
    assert_eq!(format!("{}", err), "I/O error: file not found");
}

/// Test Display implementation for Json variant
#[test]
fn test_display_json_error() {
    let err = SmugglexError::Json("invalid JSON".to_string());
    assert_eq!(format!("{}", err), "JSON error: invalid JSON");
}

/// Test Display implementation for Timeout variant
#[test]
fn test_display_timeout_error() {
    let err = SmugglexError::Timeout("request timed out".to_string());
    assert_eq!(format!("{}", err), "Timeout error: request timed out");
}

/// Test Display implementation for InvalidInput variant
#[test]
fn test_display_invalid_input_error() {
    let err = SmugglexError::InvalidInput("bad argument".to_string());
    assert_eq!(format!("{}", err), "Invalid input: bad argument");
}

/// Test From<std::io::Error> implementation
#[test]
fn test_from_io_error() {
    let io_err = io::Error::new(io::ErrorKind::NotFound, "file not found");
    let smugglex_err: SmugglexError = io_err.into();
    match smugglex_err {
        SmugglexError::Io(msg) => assert!(msg.contains("file not found")),
        _ => panic!("Expected Io error variant"),
    }
}

/// Test From<serde_json::Error> implementation
#[test]
fn test_from_serde_json_error() {
    let json_str = "{ invalid json";
    let json_err: serde_json::Error =
        serde_json::from_str::<serde_json::Value>(json_str).unwrap_err();
    let smugglex_err: SmugglexError = json_err.into();
    match smugglex_err {
        SmugglexError::Json(msg) => {
            assert!(
                msg.contains("key must be a string")
                    || msg.contains("expected")
                    || msg.contains("invalid")
            );
        }
        _ => panic!("Expected Json error variant"),
    }
}

/// Test From<url::ParseError> implementation
#[test]
fn test_from_url_parse_error() {
    let url_err = url::Url::parse("http://[::1").unwrap_err();
    let smugglex_err: SmugglexError = url_err.into();
    match smugglex_err {
        SmugglexError::UrlParse(msg) => assert!(msg.contains("invalid") || msg.contains("port")),
        _ => panic!("Expected UrlParse error variant"),
    }
}

/// Test From<&str> implementation
#[test]
fn test_from_str() {
    let smugglex_err: SmugglexError = "test error message".into();
    match smugglex_err {
        SmugglexError::InvalidInput(msg) => assert_eq!(msg, "test error message"),
        _ => panic!("Expected InvalidInput error variant"),
    }
}

/// Test Error trait implementation - source method
#[test]
fn test_error_trait_source() {
    let err = SmugglexError::HttpRequest("test".to_string());
    // Since SmugglexError doesn't implement source (no underlying cause), it should return None
    assert!(err.source().is_none());
}

/// Test that SmugglexError implements std::error::Error
#[test]
fn test_error_trait_implementation() {
    let err = SmugglexError::InvalidInput("test".to_string());
    // Just ensure it implements Error trait by calling methods
    let _description = err.to_string();
    assert!(err.source().is_none());
}

/// Test error conversion chain
#[test]
fn test_error_conversion_chain() {
    // Test that we can convert through multiple layers if needed
    let io_err = io::Error::new(io::ErrorKind::Other, "underlying error");
    let smugglex_err: SmugglexError = io_err.into();

    // Ensure it's the correct variant
    match smugglex_err {
        SmugglexError::Io(_) => {}
        _ => panic!("Expected Io variant"),
    }
}
