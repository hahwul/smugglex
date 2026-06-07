use clap::{Parser, ValueEnum};
use colored::control;
use std::fmt;

/// Default method for the attack request. Kept as a named constant so the
/// `--raw-request` override can tell whether the user explicitly set `--method`
/// (anything other than this default) before warning about a conflict.
pub const DEFAULT_METHOD: &str = "POST";

/// Output format type
#[derive(Debug, Clone, ValueEnum)]
pub enum OutputFormat {
    /// Plain text output (human-readable)
    Plain,
    /// JSON output (structured)
    Json,
}

impl fmt::Display for OutputFormat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            OutputFormat::Plain => write!(f, "plain"),
            OutputFormat::Json => write!(f, "json"),
        }
    }
}

impl OutputFormat {
    /// Check if format is JSON
    pub fn is_json(&self) -> bool {
        matches!(self, OutputFormat::Json)
    }
}

/// A powerful HTTP Request Smuggling testing tool for detecting CL.TE, TE.CL, TE.TE, H2C, and H2 smuggling vulnerabilities
#[derive(Parser, Debug, Clone)]
#[command(author, version, about, long_about = None, disable_version_flag = true, before_help = r#"

        ████
       ██   █
       ██   █
        ██ █████               < SmuggleX >
    ████ ██   ██   Rust-powered HTTP Request Smuggling Scanner.
   ███   ███   ██
    ███  ███ ███
      █   █  ██
"#)]
pub struct Cli {
    /// Target URLs (supports multiple URLs and stdin input)
    #[arg(help_heading = "TARGET")]
    pub urls: Vec<String>,

    /// Custom method for the attack request
    #[arg(help_heading = "REQUEST", short, long, default_value = DEFAULT_METHOD)]
    pub method: String,

    /// Socket timeout in seconds
    #[arg(help_heading = "REQUEST", short, long, default_value_t = 10)]
    pub timeout: u64,

    /// Custom headers (format: "Header: Value")
    #[arg(help_heading = "REQUEST", short = 'H', long = "header")]
    pub headers: Vec<String>,

    /// Virtual host to use in Host header (overrides URL hostname)
    #[arg(help_heading = "REQUEST", long = "vhost")]
    pub vhost: Option<String>,

    /// Read a raw HTTP request from a file and use it as the request template
    #[arg(help_heading = "REQUEST", long = "raw-request", value_name = "FILE")]
    pub raw_request: Option<String>,

    /// Scheme for --raw-request when the request line is origin-form (http or https)
    #[arg(
        help_heading = "REQUEST",
        long = "raw-request-proto",
        value_name = "SCHEME",
        default_value = "https",
        requires = "raw_request",
        value_parser = ["http", "https"]
    )]
    pub raw_request_proto: String,

    /// Literal request-target captured from `--raw-request`, applied verbatim so the
    /// exact bytes (dot-segments, `#`, params) survive instead of being normalized by
    /// re-parsing a synthetic URL. Not a user-facing flag; populated by the raw-request
    /// pipeline.
    #[arg(skip)]
    pub raw_target: Option<String>,

    /// Fetch and append cookies from initial request
    #[arg(help_heading = "REQUEST", long = "cookies", action = clap::ArgAction::SetTrue)]
    pub use_cookies: bool,

    /// Output file for results (JSON format)
    #[arg(help_heading = "OUTPUT", short, long)]
    pub output: Option<String>,

    /// Output format (plain or json)
    #[arg(help_heading = "OUTPUT", short = 'f', long = "format", default_value_t = OutputFormat::Plain)]
    pub format: OutputFormat,

    /// Shorthand for --format json (machine-readable output for scripts and AI agents)
    #[arg(help_heading = "OUTPUT", long = "json", action = clap::ArgAction::SetTrue)]
    pub json: bool,

    /// Export payloads to directory when vulnerabilities are found
    #[arg(help_heading = "OUTPUT", long = "export-payloads")]
    pub export_dir: Option<String>,

    /// Verbose mode
    #[arg(help_heading = "OUTPUT", short = 'V', long, action = clap::ArgAction::SetTrue)]
    pub verbose: bool,

    /// Specify which checks to run (comma-separated: cl-te,te-cl,te-te,h2c,h2,cl-edge,h2-downgrade).
    /// h2-downgrade speaks real HTTP/2 (ALPN h2) to detect H2.CL/H2.TE and runs only on https targets.
    #[arg(help_heading = "DETECT", short = 'c', long = "checks")]
    pub checks: Option<String>,

    /// Exit quickly after finding the first vulnerability
    #[arg(help_heading = "DETECT", short = '1', long = "exit-first", action = clap::ArgAction::SetTrue)]
    pub exit_first: bool,

    /// Enable proxy fingerprinting before scan
    #[arg(help_heading = "DETECT", long = "fingerprint", action = clap::ArgAction::SetTrue)]
    pub fingerprint: bool,

    /// Enable mutation-based fuzzing
    #[arg(help_heading = "DETECT", long = "fuzz", action = clap::ArgAction::SetTrue)]
    pub fuzz: bool,

    /// Mutation seed for reproducibility (default: 42)
    #[arg(help_heading = "DETECT", long = "fuzz-seed", default_value_t = 42)]
    pub fuzz_seed: u64,

    /// Exploit types to run after detection (comma-separated: localhost-access,path-fuzz,smuggle)
    #[arg(help_heading = "EXPLOIT", short = 'e', long = "exploit")]
    pub exploit: Option<String>,

    /// Inner request to smuggle to the back-end for the `smuggle` exploit
    /// (raw request line + headers; use \r\n for line breaks). Defaults to a
    /// request that makes the back-end process the method GPOST.
    #[arg(help_heading = "EXPLOIT", long = "smuggle-request")]
    pub smuggle_request: Option<String>,

    /// Ports to test for localhost access exploit (comma-separated)
    #[arg(
        help_heading = "EXPLOIT",
        long = "exploit-ports",
        default_value = "22,80,443,8080,3306"
    )]
    pub exploit_ports: String,

    /// Wordlist file for path-fuzz exploit (one path per line)
    #[arg(help_heading = "EXPLOIT", long = "exploit-wordlist")]
    pub exploit_wordlist: Option<String>,

    /// Print version information
    #[arg(short = 'v', long = "version", action = clap::ArgAction::SetTrue)]
    pub version: bool,

    /// Delay between requests in milliseconds (rate limiting)
    #[arg(
        help_heading = "REQUEST",
        short = 'd',
        long = "delay",
        default_value_t = 0
    )]
    pub delay: u64,

    /// Quiet mode (only show vulnerabilities)
    #[arg(help_heading = "OUTPUT", short = 'q', long, action = clap::ArgAction::SetTrue)]
    pub quiet: bool,

    /// Disable colored output
    #[arg(help_heading = "OUTPUT", long = "no-color", action = clap::ArgAction::SetTrue)]
    pub no_color: bool,

    /// Number of URLs to scan concurrently
    #[arg(
        help_heading = "REQUEST",
        short = 'j',
        long = "concurrency",
        default_value_t = 1
    )]
    pub concurrency: usize,

    /// HTTP/SOCKS proxy URL (e.g., http://127.0.0.1:8080)
    #[arg(help_heading = "REQUEST", short = 'x', long = "proxy")]
    pub proxy: Option<String>,

    /// Maximum number of payloads to test per check type
    #[arg(help_heading = "DETECT", long = "max-payloads")]
    pub max_payloads: Option<usize>,

    /// Number of baseline requests for timing measurement
    #[arg(help_heading = "DETECT", long = "baseline-count", default_value_t = 3)]
    pub baseline_count: usize,
}

impl Cli {
    /// Apply global settings like no-color mode
    pub fn apply_global_settings(&self) {
        if self.no_color {
            control::set_override(false);
        }
        if self.quiet {
            crate::utils::set_quiet(true);
        }
        if let Some(ref proxy) = self.proxy {
            crate::http::set_proxy(proxy.clone());
        }
    }

    /// Returns the effective output format, honoring both --format and the --json shorthand.
    /// --json takes precedence for convenience in scripting/AI usage.
    pub fn effective_format(&self) -> OutputFormat {
        if self.json {
            OutputFormat::Json
        } else {
            self.format.clone()
        }
    }
}
