use clap::Parser;

/// HTTP Request Smuggling tester
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
    #[arg(short = 'f', long = "format", default_value = "plain", value_parser = ["plain", "json"])]
    pub format: String,
}
