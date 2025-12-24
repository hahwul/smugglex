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
#[command(author, version, about, long_about = None, disable_version_flag = true, before_help = r#"

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
    #[arg(help_heading = "TARGET")]
    pub urls: Vec<String>,

    /// Custom method for the attack request
    #[arg(help_heading = "REQUEST", short, long, default_value = "POST")]
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

    /// Fetch and append cookies from initial request
    #[arg(help_heading = "REQUEST", long = "cookies", action = clap::ArgAction::SetTrue)]
    pub use_cookies: bool,

    /// Output file for results (JSON format)
    #[arg(help_heading = "OUTPUT", short, long)]
    pub output: Option<String>,

    /// Output format (plain or json)
    #[arg(help_heading = "OUTPUT", short = 'f', long = "format", default_value_t = OutputFormat::Plain)]
    pub format: OutputFormat,

    /// Export payloads to directory when vulnerabilities are found
    #[arg(help_heading = "OUTPUT", long = "export-payloads")]
    pub export_dir: Option<String>,

    /// Verbose mode
    #[arg(help_heading = "OUTPUT", short = 'V', long, action = clap::ArgAction::SetTrue)]
    pub verbose: bool,

    /// Specify which checks to run (comma-separated: cl-te,te-cl,te-te,h2c,h2)
    #[arg(help_heading = "DETECT", short = 'c', long = "checks")]
    pub checks: Option<String>,

    /// Exit quickly after finding the first vulnerability
    #[arg(help_heading = "DETECT", short = '1', long = "exit-first", action = clap::ArgAction::SetTrue)]
    pub exit_first: bool,

    /// Exploit types to run after detection (comma-separated: localhost-access)
    #[arg(help_heading = "EXPLOIT", short = 'e', long = "exploit")]
    pub exploit: Option<String>,

    /// Ports to test for localhost access exploit (comma-separated)
    #[arg(
        help_heading = "EXPLOIT",
        long = "exploit-ports",
        default_value = "22,80,443,8080,3306"
    )]
    pub exploit_ports: String,
}
