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
use crate::utils::{LogLevel, fetch_cookies, log};

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    // Determine URLs to scan
    let urls: Vec<String> = if !cli.urls.is_empty() {
        // URLs provided via command line
        cli.urls.clone()
    } else if !io::stdin().is_terminal() {
        // Read URLs from stdin (pipeline)
        let stdin = io::stdin();
        stdin
            .lock()
            .lines()
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
        Cli::parse_from(["smugglex", "--help"]);
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
            log(
                LogLevel::Error,
                &format!("error processing {}: {}", target_url, e),
            );
            // Continue processing remaining URLs
        }
    }

    Ok(())
}

async fn process_url(target_url: &str, cli: &Cli) -> Result<()> {
    let start_time = std::time::Instant::now();

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

    // Start scan log
    log(LogLevel::Info, &format!("start scan to {}", target_url));

    // Fetch cookies if requested
    let cookies = if cli.use_cookies {
        match fetch_cookies(host, port, path, use_tls, timeout, verbose).await {
            Ok(fetched_cookies) if !fetched_cookies.is_empty() => {
                log(
                    LogLevel::Info,
                    &format!("found {} cookie(s)", fetched_cookies.len()),
                );
                fetched_cookies
            }
            Ok(_) => {
                if verbose {
                    log(LogLevel::Info, "no cookies found");
                }
                Vec::new()
            }
            Err(e) => {
                log(
                    LogLevel::Warning,
                    &format!("failed to fetch cookies: {}", e),
                );
                Vec::new()
            }
        }
    } else {
        Vec::new()
    };

    let pb = ProgressBar::new_spinner();
    if !verbose {
        pb.enable_steady_tick(Duration::from_millis(120));
        pb.set_style(
            ProgressStyle::with_template("{spinner:.cyan} {msg}")
                .unwrap()
                .tick_strings(&["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]),
        );
    } else {
        pb.finish_and_clear();
    }

    let mut results = Vec::new();
    let mut found_vulnerability = false;

    // Run CL.TE check if enabled
    if checks_to_run.contains(&"cl-te") && !(cli.exit_first && found_vulnerability) {
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
        found_vulnerability |= result.vulnerable;
        results.push(result);
        pb.inc(1);
    }

    // Run TE.CL check if enabled
    if checks_to_run.contains(&"te-cl") && !(cli.exit_first && found_vulnerability) {
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
        found_vulnerability |= result.vulnerable;
        results.push(result);
        pb.inc(1);
    }

    // Run TE.TE check if enabled
    if checks_to_run.contains(&"te-te") && !(cli.exit_first && found_vulnerability) {
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
        found_vulnerability |= result.vulnerable;
        results.push(result);
        pb.inc(1);
    }

    if !verbose {
        pb.finish_and_clear();
    }

    // Count vulnerabilities found
    let vulnerable_count = results.iter().filter(|r| r.vulnerable).count();

    // Log results
    if vulnerable_count > 0 {
        log(
            LogLevel::Warning,
            &format!("smuggling found {} vulnerability(ies)", vulnerable_count),
        );

        // Show detailed information for each vulnerability
        println!();
        for result in &results {
            if result.vulnerable {
                println!(
                    "{}",
                    format!("=== {} Vulnerability Details ===", result.check_type).bold()
                );
                println!("{} {}", "Status:".bold(), "VULNERABLE".red().bold());

                if let Some(idx) = result.payload_index {
                    println!("{} {}", "Payload Index:".bold(), idx);
                }

                if let Some(ref attack_status) = result.attack_status {
                    println!("{} {}", "Attack Response:".bold(), attack_status);
                }

                if let Some(attack_duration_ms) = result.attack_duration_ms {
                    println!(
                        "{} Normal: {}ms, Attack: {}ms",
                        "Timing:".bold(),
                        result.normal_duration_ms,
                        attack_duration_ms
                    );
                }

                // Show HTTP raw request payload
                if let Some(ref payload) = result.payload {
                    println!("\n{}", "HTTP Raw Request:".bold());
                    println!("{}", "─".repeat(60).dimmed());
                    // Display payload with color highlighting
                    println!("{}", payload.cyan());
                    println!("{}", "─".repeat(60).dimmed());
                }

                println!();
            }
        }
    } else {
        log(
            LogLevel::Info,
            &format!("smuggling found {} vulnerabilities", vulnerable_count),
        );
    }

    // Log scan completion with duration
    let duration = start_time.elapsed();
    log(
        LogLevel::Info,
        &format!("scan completed in {:.3} seconds", duration.as_secs_f64()),
    );

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

        log(LogLevel::Info, &format!("results saved to {}", output_file));
    }

    Ok(())
}
