use chrono::Utc;
use clap::Parser;
use colored::*;
use indicatif::{ProgressBar, ProgressStyle};
use std::fs;
use std::io::{self, BufRead, IsTerminal, Write};
use std::time::Duration;
use url::Url;

use smugglex::cli::{Cli, OutputFormat};
use smugglex::error::Result;
use smugglex::exploit::{
    extract_vulnerability_context, get_fuzz_paths, print_localhost_results, print_path_fuzz_results,
    test_localhost_access, test_path_fuzz,
};
use smugglex::model::{CheckResult, ScanResults};
use smugglex::payloads::{
    get_cl_te_payloads, get_h2_payloads, get_h2c_payloads, get_te_cl_payloads, get_te_te_payloads,
};
use smugglex::scanner::{run_checks_for_type, CheckParams};
use smugglex::utils::{fetch_cookies, log, LogLevel};

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    let urls = resolve_urls(&cli)?;
    if urls.is_empty() {
        eprintln!("{} No valid URLs provided", "[!]".yellow().bold());
        return Ok(());
    }

    for target_url in urls {
        if let Err(e) = process_url(&target_url, &cli).await {
            log(
                LogLevel::Error,
                &format!("error processing {}: {}", target_url, e),
            );
        }
    }

    Ok(())
}

fn resolve_urls(cli: &Cli) -> Result<Vec<String>> {
    if !cli.urls.is_empty() {
        Ok(cli.urls.clone())
    } else if !io::stdin().is_terminal() {
        Ok(io::stdin()
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
            .collect())
    } else {
        Cli::parse_from(["smugglex", "--help"]);
        Ok(Vec::new())
    }
}

async fn process_url(target_url: &str, cli: &Cli) -> Result<()> {
    let start_time = std::time::Instant::now();

    let url = Url::parse(target_url)?;
    let host = url.host_str().ok_or("Invalid host")?;
    let port = url.port_or_known_default().ok_or("Invalid port")?;
    let path = url.path();
    let use_tls = url.scheme() == "https";
    let host_header = cli.vhost.as_deref().unwrap_or(host);

    log(LogLevel::Info, &format!("start scan to {}", target_url));

    let cookies = if cli.use_cookies {
        fetch_cookies(host, port, path, use_tls, cli.timeout, cli.verbose).await?
    } else {
        Vec::new()
    };
    if !cookies.is_empty() {
        log(LogLevel::Info, &format!("found {} cookie(s)", cookies.len()));
    }

    let pb = setup_progress_bar(cli.verbose);

    let all_checks = [
        ("cl-te", get_cl_te_payloads as fn(&str, &str, &str, &[String], &[String]) -> Vec<String>),
        ("te-cl", get_te_cl_payloads),
        ("te-te", get_te_te_payloads),
        ("h2c", get_h2c_payloads),
        ("h2", get_h2_payloads),
    ];

    let checks_to_run: Vec<_> = if let Some(ref checks_str) = cli.checks {
        let selected_checks: Vec<&str> = checks_str.split(',').map(|s| s.trim()).collect();
        all_checks
            .into_iter()
            .filter(|(name, _)| selected_checks.contains(name))
            .collect()
    } else {
        all_checks.to_vec()
    };

    let mut results = Vec::new();
    let mut found_vulnerability = false;
    let total_checks = checks_to_run.len();

    for (i, (check_name, payload_fn)) in checks_to_run.iter().enumerate() {
        if cli.exit_first && found_vulnerability {
            break;
        }

        let payloads = payload_fn(path, host_header, &cli.method, &cli.headers, &cookies);
        let params = CheckParams {
            pb: &pb,
            check_name,
            host,
            port,
            path,
            attack_requests: payloads,
            timeout: cli.timeout,
            verbose: cli.verbose,
            use_tls,
            export_dir: cli.export_dir.as_deref(),
            current_check: i + 1,
            total_checks,
        };

        let result = run_checks_for_type(params).await?;
        found_vulnerability |= result.vulnerable;
        results.push(result);
        pb.inc(1);
    }

    if !cli.verbose {
        pb.finish_and_clear();
    }

    log_scan_results(&results, &cli.format, target_url, &cli.method);

    // Run exploits if requested and vulnerabilities were found
    if let Some(ref exploit_str) = cli.exploit {
        if found_vulnerability {
            run_exploits(
                exploit_str,
                &results,
                host,
                port,
                path,
                use_tls,
                cli.timeout,
                cli.verbose,
                target_url,
                &cli.exploit_ports,
                cli.exploit_wordlist.as_deref(),
            )
            .await?;
        } else {
            log(
                LogLevel::Warning,
                "exploit requested but no vulnerabilities found to exploit",
            );
        }
    }

    if let Some(ref output_file) = cli.output {
        save_results_to_file(output_file, target_url, &cli.method, results)?;
    }

    let duration = start_time.elapsed();
    log(
        LogLevel::Info,
        &format!("scan completed in {:.3} seconds", duration.as_secs_f64()),
    );

    Ok(())
}

fn setup_progress_bar(verbose: bool) -> ProgressBar {
    if verbose {
        ProgressBar::hidden()
    } else {
        let pb = ProgressBar::new_spinner();
        pb.enable_steady_tick(Duration::from_millis(120));
        pb.set_style(
            ProgressStyle::with_template("{spinner:.cyan} {msg}")
                .unwrap()
                .tick_strings(&["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]),
        );
        pb
    }
}

fn log_scan_results(results: &[CheckResult], format: &OutputFormat, target_url: &str, method: &str) {
    let vulnerable_count = results.iter().filter(|r| r.vulnerable).count();

    if format.is_json() {
        let scan_results = ScanResults {
            target: target_url.to_string(),
            method: method.to_string(),
            timestamp: Utc::now().to_rfc3339(),
            checks: results.to_vec(),
        };
        match serde_json::to_string_pretty(&scan_results) {
            Ok(json_output) => println!("{}", json_output),
            Err(e) => {
                log(LogLevel::Error, &format!("failed to serialize results to JSON: {}", e));
                log(LogLevel::Info, "falling back to plain text output");
                log_plain_results(results, vulnerable_count);
            }
        }
    } else {
        log_plain_results(results, vulnerable_count);
    }
}

fn log_plain_results(results: &[CheckResult], vulnerable_count: usize) {
    if vulnerable_count > 0 {
            log(
                LogLevel::Warning,
                &format!("smuggling found {} vulnerability(ies)", vulnerable_count),
            );
            println!();
            for result in results.iter().filter(|r| r.vulnerable) {
                println!(
                    "{}",
                    format!("=== {} Vulnerability Details ===", result.check_type).bold()
                );
                println!("{} {}", "Status:".bold(), "VULNERABLE".red().bold());
                if let Some(idx) = result.payload_index {
                    println!("{} {}", "Payload Index:".bold(), idx);
                }
                if let Some(ref status) = result.attack_status {
                    println!("{} {}", "Attack Response:".bold(), status);
                }
                if let Some(attack_ms) = result.attack_duration_ms {
                    println!(
                        "{} Normal: {}ms, Attack: {}ms",
                        "Timing:".bold(),
                        result.normal_duration_ms,
                        attack_ms
                    );
                }
                if let Some(ref payload) = result.payload {
                    println!("\n{}", "HTTP Raw Request:".bold());
                    println!("{}", "─".repeat(60).dimmed());
                    println!("{}", payload.cyan());
                    println!("{}", "─".repeat(60).dimmed());
                }
                println!();
            }
    } else {
        log(LogLevel::Info, "smuggling found 0 vulnerabilities");
    }
}

async fn run_exploits(
    exploit_str: &str,
    results: &[CheckResult],
    host: &str,
    port: u16,
    path: &str,
    use_tls: bool,
    timeout: u64,
    verbose: bool,
    target_url: &str,
    ports_str: &str,
    wordlist_path: Option<&str>,
) -> Result<()> {
    let exploits: Vec<&str> = exploit_str.split(',').map(|s| s.trim()).collect();

    for exploit_type in exploits {
        match exploit_type {
            "localhost-access" => {
                log(LogLevel::Info, "running localhost-access exploit");

                // Extract vulnerability context from results
                let vuln_ctx = match extract_vulnerability_context(results) {
                    Some(ctx) => ctx,
                    None => {
                        log(
                            LogLevel::Error,
                            "cannot extract vulnerability context for exploitation",
                        );
                        continue;
                    }
                };

                if verbose {
                    println!(
                        "\n{} Using detected {} vulnerability for exploitation",
                        "[*]".cyan(),
                        vuln_ctx.vuln_type.yellow().bold()
                    );
                }

                // Parse target ports
                let localhost_ports: Vec<u16> = ports_str
                    .split(',')
                    .filter_map(|s| s.trim().parse::<u16>().ok())
                    .collect();

                if localhost_ports.is_empty() {
                    log(LogLevel::Error, "no valid ports specified for localhost-access");
                    continue;
                }

                if verbose {
                    println!(
                        "  {} Testing ports: {}",
                        "[*]".cyan(),
                        localhost_ports
                            .iter()
                            .map(|p| p.to_string())
                            .collect::<Vec<_>>()
                            .join(", ")
                    );
                }

                // Run localhost access test
                match test_localhost_access(
                    host,
                    port,
                    path,
                    use_tls,
                    timeout,
                    verbose,
                    &vuln_ctx,
                    &localhost_ports,
                )
                .await
                {
                    Ok(localhost_results) => {
                        print_localhost_results(&localhost_results, target_url);
                    }
                    Err(e) => {
                        log(
                            LogLevel::Error,
                            &format!("localhost-access exploit failed: {}", e),
                        );
                    }
                }
            }
            "path-fuzz" => {
                log(LogLevel::Info, "running path-fuzz exploit");

                // Extract vulnerability context from results
                let vuln_ctx = match extract_vulnerability_context(results) {
                    Some(ctx) => ctx,
                    None => {
                        log(
                            LogLevel::Error,
                            "cannot extract vulnerability context for exploitation",
                        );
                        continue;
                    }
                };

                if verbose {
                    println!(
                        "\n{} Using detected {} vulnerability for exploitation",
                        "[*]".cyan(),
                        vuln_ctx.vuln_type.yellow().bold()
                    );
                }

                // Get paths to fuzz
                let fuzz_paths = match get_fuzz_paths(wordlist_path) {
                    Ok(paths) => paths,
                    Err(e) => {
                        log(
                            LogLevel::Error,
                            &format!("failed to get fuzz paths: {}", e),
                        );
                        continue;
                    }
                };

                if verbose {
                    println!(
                        "  {} Testing {} paths{}",
                        "[*]".cyan(),
                        fuzz_paths.len(),
                        wordlist_path.map_or("".to_string(), |p| format!(" from {}", p))
                    );
                }

                // Run path fuzz test
                match test_path_fuzz(
                    host,
                    port,
                    path,
                    use_tls,
                    timeout,
                    verbose,
                    &vuln_ctx,
                    &fuzz_paths,
                )
                .await
                {
                    Ok(path_fuzz_results) => {
                        print_path_fuzz_results(&path_fuzz_results, target_url);
                    }
                    Err(e) => {
                        log(
                            LogLevel::Error,
                            &format!("path-fuzz exploit failed: {}", e),
                        );
                    }
                }
            }
            _ => {
                log(
                    LogLevel::Warning,
                    &format!("unknown exploit type: {}", exploit_type),
                );
            }
        }
    }

    Ok(())
}

fn save_results_to_file(
    output_file: &str,
    target_url: &str,
    method: &str,
    results: Vec<CheckResult>,
) -> Result<()> {
    let scan_results = ScanResults {
        target: target_url.to_string(),
        method: method.to_string(),
        timestamp: Utc::now().to_rfc3339(),
        checks: results,
    };
    let json_output = serde_json::to_string_pretty(&scan_results)?;
    let mut file = fs::File::create(output_file)?;
    file.write_all(json_output.as_bytes())?;
    log(LogLevel::Info, &format!("results saved to {}", output_file));
    Ok(())
}
