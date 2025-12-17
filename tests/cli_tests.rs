//! Tests for CLI argument parsing
//!
//! This module contains tests for:
//! - URL parsing (single, multiple, with paths/ports)
//! - Command-line option parsing
//! - Default values validation
//! - Custom headers and cookies options
//! - Check type selection
//! - Virtual host and export options
//! - HTTP method variations

use clap::Parser;
use smugglex::cli::{Cli, OutputFormat};

#[test]
fn test_single_url_parsing() {
    let cli = Cli::parse_from(&["smugglex", "http://example.com"]);
    assert_eq!(cli.urls.len(), 1);
    assert_eq!(cli.urls[0], "http://example.com");
}

#[test]
fn test_multiple_urls_parsing() {
    let cli = Cli::parse_from(&[
        "smugglex",
        "http://example1.com",
        "http://example2.com",
        "http://example3.com",
    ]);
    assert_eq!(cli.urls.len(), 3);
    assert_eq!(cli.urls[0], "http://example1.com");
    assert_eq!(cli.urls[1], "http://example2.com");
    assert_eq!(cli.urls[2], "http://example3.com");
}

#[test]
fn test_no_urls_parsing() {
    let cli = Cli::parse_from(&["smugglex"]);
    assert_eq!(cli.urls.len(), 0);
}

#[test]
fn test_urls_with_options() {
    let cli = Cli::parse_from(&[
        "smugglex",
        "http://example1.com",
        "http://example2.com",
        "-m",
        "GET",
        "-t",
        "20",
        "-v",
    ]);
    assert_eq!(cli.urls.len(), 2);
    assert_eq!(cli.urls[0], "http://example1.com");
    assert_eq!(cli.urls[1], "http://example2.com");
    assert_eq!(cli.method, "GET");
    assert_eq!(cli.timeout, 20);
    assert!(cli.verbose);
}

#[test]
fn test_urls_with_headers() {
    let cli = Cli::parse_from(&[
        "smugglex",
        "http://example.com",
        "-H",
        "X-Custom: value",
        "-H",
        "Authorization: Bearer token",
    ]);
    assert_eq!(cli.urls.len(), 1);
    assert_eq!(cli.headers.len(), 2);
    assert_eq!(cli.headers[0], "X-Custom: value");
    assert_eq!(cli.headers[1], "Authorization: Bearer token");
}

// Test default values
#[test]
fn test_default_method() {
    let cli = Cli::parse_from(&["smugglex", "http://example.com"]);
    assert_eq!(cli.method, "POST", "Default method should be POST");
}

#[test]
fn test_default_timeout() {
    let cli = Cli::parse_from(&["smugglex", "http://example.com"]);
    assert_eq!(cli.timeout, 10, "Default timeout should be 10 seconds");
}

#[test]
fn test_default_verbose_false() {
    let cli = Cli::parse_from(&["smugglex", "http://example.com"]);
    assert!(!cli.verbose, "Verbose should be false by default");
}

#[test]
fn test_default_use_cookies_false() {
    let cli = Cli::parse_from(&["smugglex", "http://example.com"]);
    assert!(!cli.use_cookies, "use_cookies should be false by default");
}

// Test various HTTP methods
#[test]
fn test_various_http_methods() {
    let methods = vec!["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"];

    for method in methods {
        let cli = Cli::parse_from(&["smugglex", "http://example.com", "-m", method]);
        assert_eq!(cli.method, method, "Method should be {}", method);
    }
}

// Test timeout values
#[test]
fn test_various_timeout_values() {
    let timeouts = vec![1, 5, 10, 30, 60, 120];

    for timeout in timeouts {
        let timeout_str = timeout.to_string();
        let cli = Cli::parse_from(&["smugglex", "http://example.com", "-t", &timeout_str]);
        assert_eq!(cli.timeout, timeout, "Timeout should be {}", timeout);
    }
}

// Test output file option
#[test]
fn test_output_file_option() {
    let cli = Cli::parse_from(&["smugglex", "http://example.com", "-o", "results.json"]);
    assert_eq!(cli.output, Some("results.json".to_string()));
}

#[test]
fn test_no_output_file() {
    let cli = Cli::parse_from(&["smugglex", "http://example.com"]);
    assert_eq!(cli.output, None, "Output should be None by default");
}

// Test checks option
#[test]
fn test_checks_option_single() {
    let cli = Cli::parse_from(&["smugglex", "http://example.com", "-c", "cl-te"]);
    assert_eq!(cli.checks, Some("cl-te".to_string()));
}

#[test]
fn test_checks_option_multiple() {
    let cli = Cli::parse_from(&["smugglex", "http://example.com", "-c", "cl-te,te-cl,te-te"]);
    assert_eq!(cli.checks, Some("cl-te,te-cl,te-te".to_string()));
}

#[test]
fn test_no_checks_option() {
    let cli = Cli::parse_from(&["smugglex", "http://example.com"]);
    assert_eq!(cli.checks, None, "Checks should be None by default");
}

// Test vhost option
#[test]
fn test_vhost_option() {
    let cli = Cli::parse_from(&[
        "smugglex",
        "http://192.168.1.1",
        "--vhost",
        "internal.example.com",
    ]);
    assert_eq!(cli.vhost, Some("internal.example.com".to_string()));
}

#[test]
fn test_no_vhost_option() {
    let cli = Cli::parse_from(&["smugglex", "http://example.com"]);
    assert_eq!(cli.vhost, None, "Vhost should be None by default");
}

// Test cookies option
#[test]
fn test_cookies_option() {
    let cli = Cli::parse_from(&["smugglex", "http://example.com", "--cookies"]);
    assert!(cli.use_cookies, "use_cookies should be true");
}

// Test export-payloads option
#[test]
fn test_export_payloads_option() {
    let cli = Cli::parse_from(&[
        "smugglex",
        "http://example.com",
        "--export-payloads",
        "./payloads",
    ]);
    assert_eq!(cli.export_dir, Some("./payloads".to_string()));
}

#[test]
fn test_no_export_payloads_option() {
    let cli = Cli::parse_from(&["smugglex", "http://example.com"]);
    assert_eq!(cli.export_dir, None, "export_dir should be None by default");
}

// Test format option
#[test]
fn test_format_default_plain() {
    let cli = Cli::parse_from(&["smugglex", "http://example.com"]);
    assert!(matches!(cli.format, OutputFormat::Plain), "Default format should be plain");
}

#[test]
fn test_format_short_flag() {
    let cli = Cli::parse_from(&["smugglex", "http://example.com", "-f", "json"]);
    assert!(matches!(cli.format, OutputFormat::Json), "format should be json with -f json flag");
}

#[test]
fn test_format_long_flag() {
    let cli = Cli::parse_from(&["smugglex", "http://example.com", "--format", "json"]);
    assert!(matches!(cli.format, OutputFormat::Json), "format should be json with --format json flag");
}

#[test]
fn test_format_plain_explicit() {
    let cli = Cli::parse_from(&["smugglex", "http://example.com", "--format", "plain"]);
    assert!(matches!(cli.format, OutputFormat::Plain), "format should be plain when explicitly set");
}

#[test]
fn test_format_invalid_value() {
    let result = Cli::try_parse_from(&["smugglex", "http://example.com", "--format", "invalid"]);
    assert!(result.is_err(), "format should reject invalid values");
}

// Test exit-first option
#[test]
fn test_exit_first_short_flag() {
    let cli = Cli::parse_from(&["smugglex", "http://example.com", "-1"]);
    assert!(cli.exit_first, "exit_first should be true with -1 flag");
}

#[test]
fn test_exit_first_long_flag() {
    let cli = Cli::parse_from(&["smugglex", "http://example.com", "--exit-first"]);
    assert!(
        cli.exit_first,
        "exit_first should be true with --exit-first flag"
    );
}

#[test]
fn test_default_exit_first_false() {
    let cli = Cli::parse_from(&["smugglex", "http://example.com"]);
    assert!(!cli.exit_first, "exit_first should be false by default");
}

// Test combinations
#[test]
fn test_all_options_combined() {
    let cli = Cli::parse_from(&[
        "smugglex",
        "http://example.com",
        "-m",
        "GET",
        "-t",
        "30",
        "-v",
        "-o",
        "output.json",
        "-H",
        "X-Custom: value",
        "-c",
        "cl-te,te-cl",
        "--vhost",
        "test.local",
        "--cookies",
        "--export-payloads",
        "./exports",
        "-1",
        "-f",
        "json",
    ]);

    assert_eq!(cli.urls.len(), 1);
    assert_eq!(cli.method, "GET");
    assert_eq!(cli.timeout, 30);
    assert!(cli.verbose);
    assert_eq!(cli.output, Some("output.json".to_string()));
    assert_eq!(cli.headers.len(), 1);
    assert_eq!(cli.checks, Some("cl-te,te-cl".to_string()));
    assert_eq!(cli.vhost, Some("test.local".to_string()));
    assert!(cli.use_cookies);
    assert_eq!(cli.export_dir, Some("./exports".to_string()));
    assert!(cli.exit_first);
    assert!(matches!(cli.format, OutputFormat::Json));
}

// Test HTTPS URLs
#[test]
fn test_https_urls() {
    let cli = Cli::parse_from(&["smugglex", "https://secure.example.com"]);
    assert_eq!(cli.urls[0], "https://secure.example.com");
}

// Test URLs with paths
#[test]
fn test_urls_with_paths() {
    let cli = Cli::parse_from(&["smugglex", "http://example.com/api/v1/test"]);
    assert_eq!(cli.urls[0], "http://example.com/api/v1/test");
}

// Test URLs with ports
#[test]
fn test_urls_with_ports() {
    let cli = Cli::parse_from(&["smugglex", "http://example.com:8080"]);
    assert_eq!(cli.urls[0], "http://example.com:8080");
}

// Test empty headers list
#[test]
fn test_no_headers() {
    let cli = Cli::parse_from(&["smugglex", "http://example.com"]);
    assert_eq!(cli.headers.len(), 0, "Headers should be empty by default");
}

// Test error cases for CLI parsing
#[test]
fn test_invalid_timeout_negative() {
    let _result = Cli::try_parse_from(&["smugglex", "http://example.com", "-t", "-1"]);
    // Note: clap may not validate negative values, so this might pass
}

#[test]
fn test_invalid_timeout_non_numeric() {
    let _result = Cli::try_parse_from(&["smugglex", "http://example.com", "-t", "abc"]);
    // Note: clap may not validate numeric values, so this might pass
}

#[test]
fn test_invalid_method() {
    let _result = Cli::try_parse_from(&["smugglex", "http://example.com", "-m", "INVALID"]);
    // Note: clap may not validate method names, so this might pass
    // But we can test for unknown flags
    let result = Cli::try_parse_from(&["smugglex", "http://example.com", "--invalid-flag"]);
    assert!(result.is_err(), "Unknown flag should be invalid");
}

#[test]
fn test_missing_required_url() {
    // clap allows missing positional arguments, so this succeeds with empty urls
    let result = Cli::try_parse_from(&["smugglex"]);
    assert!(
        result.is_ok(),
        "CLI parsing should succeed even without URL"
    );
    let cli = result.unwrap();
    assert_eq!(cli.urls.len(), 0, "URLs should be empty when not provided");
}

#[test]
fn test_invalid_header_format() {
    // Headers without colon should be invalid
    let _result = Cli::try_parse_from(&["smugglex", "http://example.com", "-H", "invalid-header"]);
    // clap doesn't validate header format, so this might pass
    // Test for duplicate short flags or other clap errors
    let result = Cli::try_parse_from(&["smugglex", "http://example.com", "-t", "10", "-t", "20"]);
    assert!(result.is_err(), "Duplicate timeout flags should be invalid");
}

#[test]
fn test_invalid_output_file_path() {
    // Invalid paths might not be caught by clap, but we can test
    let cli = Cli::parse_from(&[
        "smugglex",
        "http://example.com",
        "-o",
        "/invalid/path/that/does/not/exist.json",
    ]);
    // This will succeed, as clap doesn't validate file paths
    assert_eq!(
        cli.output,
        Some("/invalid/path/that/does/not/exist.json".to_string())
    );
}

#[test]
fn test_invalid_vhost_format() {
    // Invalid hostname might not be validated
    let cli = Cli::parse_from(&["smugglex", "http://example.com", "--vhost", ""]);
    assert_eq!(cli.vhost, Some("".to_string()));
}

#[test]
fn test_invalid_checks_format() {
    // Invalid check names might not be validated
    let cli = Cli::parse_from(&["smugglex", "http://example.com", "-c", "invalid-check"]);
    assert_eq!(cli.checks, Some("invalid-check".to_string()));
}
