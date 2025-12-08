use clap::Parser;

/// HTTP Request Smuggling tester
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
pub struct Cli {
    /// Target URLs
    pub urls: Vec<String>,

    /// Custom method for the attack request
    #[arg(short, long, default_value = "POST")]
    pub method: String,

    /// Socket timeout in seconds
    #[arg(short, long, default_value_t = 10)]
    pub timeout: u64,

    /// Verbose mode
    #[arg(short, long, action = clap::ArgAction::SetTrue)]
    pub verbose: bool,

    /// Output file for results (JSON format)
    #[arg(short, long)]
    pub output: Option<String>,

    /// Custom headers (format: "Header: Value")
    #[arg(short = 'H', long = "header")]
    pub headers: Vec<String>,

    /// Specify which checks to run (comma-separated: cl-te,te-cl,te-te)
    #[arg(short = 'c', long = "checks")]
    pub checks: Option<String>,

    /// Virtual host to use in Host header (overrides URL hostname)
    #[arg(long = "vhost")]
    pub vhost: Option<String>,

    /// Fetch and append cookies from initial request
    #[arg(long = "cookies", action = clap::ArgAction::SetTrue)]
    pub use_cookies: bool,

    /// Export payloads to directory when vulnerabilities are found
    #[arg(long = "export-payloads")]
    pub export_dir: Option<String>,
}

#[cfg(test)]
mod tests {
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

    use super::*;

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
        let cli = Cli::parse_from(&[
            "smugglex",
            "http://example.com",
            "-o",
            "results.json",
        ]);
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
}
