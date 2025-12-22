use clap::{Parser, ValueEnum};
use std::fmt;

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
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None, before_help = r#"

        ████
       ██   █
       ██   █
        ██ █████         SmuggleX
    ████ ██   ██   HTTP Request Smuggler
   ███   ███   ██
    ███  ███ ███
      █   █  ██
"#)]
pub struct Cli {
    /// Target URLs (supports multiple URLs and stdin input)
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

    /// Specify which checks to run (comma-separated: cl-te,te-cl,te-te,h2c,h2)
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

    /// Exit quickly after finding the first vulnerability
    #[arg(short = '1', long = "exit-first", action = clap::ArgAction::SetTrue)]
    pub exit_first: bool,

    /// Output format (plain or json)
    #[arg(short = 'f', long = "format", default_value_t = OutputFormat::Plain)]
    pub format: OutputFormat,
}
