use clap::Parser;

/// HTTP Request Smuggling tester
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
pub struct Cli {
    /// Target URLs (supports multiple URLs)
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
}
