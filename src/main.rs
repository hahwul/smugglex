mod cli;
mod error;
mod http;
mod model;
mod payloads;
mod scanner;
mod utils;

use chrono::Utc;
use clap::Parser;
use colored::*;
use indicatif::{ProgressBar, ProgressStyle};
use std::fs;
use std::io::{self, BufRead, IsTerminal, Write};
use std::time::Duration;
use url::Url;

use crate::cli::Cli;
use crate::error::Result;
use crate::model::ScanResults;
use crate::payloads::{get_cl_te_payloads, get_te_cl_payloads, get_te_te_payloads};
use crate::scanner::{CheckParams, run_checks_for_type};
use crate::utils::fetch_cookies;

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    // Determine URLs to scan
    let urls: Vec<String> = if let Some(ref url) = cli.url {
        // URL provided via command line
        vec![url.clone()]
    } else if !io::stdin().is_terminal() {
        // Read URLs from stdin (pipeline)
        let stdin = io::stdin();
        stdin.lock().lines()
            .filter_map(|line| match line {
                Ok(l) if !l.trim().is_empty() => Some(l),
                Err(e) => {
                    eprintln!("{} Error reading from stdin: {}", "[!]".yellow().bold(), e);
                    None
                }
                _ => None,
            })
            .collect()
    } else {
        // No URL and no stdin - print help and exit
        Cli::parse_from(&["smugglex", "--help"]);
        return Ok(());
    };

    // If no valid URLs were found, exit
    if urls.is_empty() {
        eprintln!("{} No valid URLs provided", "[!]".yellow().bold());
        return Ok(());
    }

    // Process each URL
    for target_url in urls {
        if let Err(e) = process_url(&target_url, &cli).await {
            eprintln!("{} Error processing {}: {}", "[!]".red().bold(), target_url, e);
            // Continue processing remaining URLs
        }
    }

    Ok(())
}

async fn process_url(target_url: &str, cli: &Cli) -> Result<()> {
    let url = Url::parse(target_url)?;
    let host = url.host_str().ok_or("Invalid host")?;
    let port = url.port_or_known_default().ok_or("Invalid port")?;
    let path = url.path();
    let method = &cli.method;
    let timeout = cli.timeout;
    let verbose = cli.verbose;
    let use_tls = url.scheme() == "https";
    
    // Determine the actual host header to use (vhost overrides URL hostname)
    let host_header = cli.vhost.as_deref().unwrap_or(host);

    // Parse checks filter
    let checks_to_run: Vec<&str> = if let Some(ref checks_str) = cli.checks {
        checks_str.split(',').map(|s| s.trim()).collect()
    } else {
        vec!["cl-te", "te-cl", "te-te"]
    };

    // Display banner
    println!();
    println!("{}", "╔═══════════════════════════════════════════╗".cyan());
    println!(
        "{}",
        "║  SmuggLeX - HTTP Request Smuggling Tool  ║".cyan().bold()
    );
    println!("{}", "╚═══════════════════════════════════════════╝".cyan());
    println!();
    println!("{} {}", "Target:".bold(), host.cyan());
    if cli.vhost.is_some() {
        println!("{} {}", "Virtual Host:".bold(), host_header.cyan());
    }
    println!("{}   {}", "Method:".bold(), method.cyan());
    println!("{} {}", "Timeout:".bold(), format!("{}s", timeout).cyan());
    println!(
        "{} {}",
        "Protocol:".bold(),
        if use_tls {
            "HTTPS".cyan()
        } else {
            "HTTP".cyan()
        }
    );
    if !cli.headers.is_empty() {
        println!(
            "{} {}",
            "Custom Headers:".bold(),
            cli.headers.len().to_string().cyan()
        );
    }
    if verbose {
        println!("{} {}", "Verbose:".bold(), "Enabled".cyan());
    }
    if let Some(ref output_file) = cli.output {
        println!("{} {}", "Output:".bold(), output_file.cyan());
    }
    if let Some(ref export_dir) = cli.export_dir {
        println!("{} {}", "Export Dir:".bold(), export_dir.cyan());
    }
    println!(
        "{} {}",
        "Checks:".bold(),
        checks_to_run.join(", ").to_uppercase().cyan()
    );
    
    // Fetch cookies if requested
    let cookies = if cli.use_cookies {
        println!("\n{} Fetching cookies...", "[*]".yellow().bold());
        match fetch_cookies(host, port, path, use_tls, timeout, verbose).await {
            Ok(fetched_cookies) if !fetched_cookies.is_empty() => {
                println!(
                    "{} Found {} cookie(s)",
                    "[+]".green().bold(),
                    fetched_cookies.len()
                );
                fetched_cookies
            }
            Ok(_) => {
                println!("{} No cookies found", "[!]".yellow().bold());
                Vec::new()
            }
            Err(e) => {
                println!("{} Failed to fetch cookies: {}", "[!]".yellow().bold(), e);
                Vec::new()
            }
        }
    } else {
        Vec::new()
    };
    
    println!();

    let pb = ProgressBar::new_spinner();
    if !verbose {
        pb.enable_steady_tick(Duration::from_millis(120));
        pb.set_style(
            ProgressStyle::with_template("{spinner:.blue} {msg}")
                .unwrap()
                .tick_strings(&["▸▹▹▹▹", "▹▸▹▹▹", "▹▹▸▹▹", "▹▹▹▸▹", "▹▹▹▹▸"]),
        );
    } else {
        pb.finish_and_clear();
    }

    let mut results = Vec::new();

    // Run CL.TE check if enabled
    if checks_to_run.contains(&"cl-te") {
        let cl_te_payloads = get_cl_te_payloads(path, host_header, method, &cli.headers, &cookies);
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
            export_dir: cli.export_dir.as_deref(),
        })
        .await?;
        results.push(result);
        pb.inc(1);
    }

    // Run TE.CL check if enabled
    if checks_to_run.contains(&"te-cl") {
        let te_cl_payloads = get_te_cl_payloads(path, host_header, method, &cli.headers, &cookies);
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
            export_dir: cli.export_dir.as_deref(),
        })
        .await?;
        results.push(result);
        pb.inc(1);
    }

    // Run TE.TE check if enabled
    if checks_to_run.contains(&"te-te") {
        let te_te_payloads = get_te_te_payloads(path, host_header, method, &cli.headers, &cookies);
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
            export_dir: cli.export_dir.as_deref(),
        })
        .await?;
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
        println!(
            "{} {} vulnerability(ies) found!",
            "⚠".red().bold(),
            vulnerable_count
        );
        for result in &results {
            if result.vulnerable {
                println!(
                    "  {} {}: {}",
                    "•".red(),
                    result.check_type,
                    "VULNERABLE".red().bold()
                );
            }
        }
    } else {
        println!("{} No vulnerabilities detected", "✔".green().bold());
    }
    println!("{} {} checks completed", "✔".green(), results.len());

    // Save results to file if requested
    if let Some(ref output_file) = cli.output {
        let scan_results = ScanResults {
            target: target_url.to_string(),
            method: method.clone(),
            timestamp: Utc::now().to_rfc3339(),
            checks: results,
        };

        let json_output = serde_json::to_string_pretty(&scan_results)?;
        let mut file = fs::File::create(output_file)?;
        file.write_all(json_output.as_bytes())?;

        println!(
            "\n{} Results saved to: {}",
            "✔".green().bold(),
            output_file.cyan()
        );
    }

    Ok(())
}
