use clap::Parser;
use colored::*;
use indicatif::{ProgressBar, ProgressStyle};
use std::io::{self, BufRead, IsTerminal};
use std::time::Duration;
use url::Url;

use smugglex::cli::Cli;
use smugglex::error::Result;
use smugglex::exploit::{
    LocalhostAccessParams, PathFuzzParams, VulnerabilityContext, extract_vulnerability_context,
    get_fuzz_paths, print_localhost_results, print_path_fuzz_results, test_localhost_access,
    test_path_fuzz,
};
use smugglex::fingerprint::{fingerprint_target, suggest_checks};
use smugglex::model::{CheckResult, FingerprintInfo};
use smugglex::mutator::{Mutator, MutatorConfig};
use smugglex::output::{log_scan_results, save_results_to_file};
use smugglex::payloads::{
    get_cl_edge_case_payloads, get_cl_te_payloads, get_h2_payloads, get_h2c_payloads,
    get_te_cl_payloads, get_te_te_payloads,
};
use smugglex::scanner::{CheckParams, run_checks_for_type};
use smugglex::utils::{LogLevel, fetch_cookies, log};

#[derive(Debug)]
struct ExploitParams<'a> {
    exploit_str: &'a str,
    results: &'a [CheckResult],
    host: &'a str,
    port: u16,
    path: &'a str,
    use_tls: bool,
    timeout: u64,
    verbose: bool,
    target_url: &'a str,
    ports_str: &'a str,
    wordlist_path: Option<&'a str>,
    delay: u64,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    cli.apply_global_settings();

    if cli.version {
        println!("smugglex {}", env!("CARGO_PKG_VERSION"));
        return Ok(());
    }

    let urls = resolve_urls(&cli)?;
    if urls.is_empty() {
        eprintln!("{} No valid URLs provided", "[!]".yellow().bold());
        return Ok(());
    }

    if cli.concurrency > 1 {
        // Process URLs concurrently in chunks
        for chunk in urls.chunks(cli.concurrency) {
            let mut handles = Vec::new();
            for target_url in chunk {
                let url = target_url.clone();
                let cli_ref = cli.clone();
                handles.push(tokio::spawn(async move {
                    if let Err(e) = process_url(&url, &cli_ref).await {
                        log(LogLevel::Error, &format!("error processing {}: {}", url, e));
                    }
                }));
            }
            for handle in handles {
                let _ = handle.await;
            }
        }
    } else {
        for target_url in urls {
            if let Err(e) = process_url(&target_url, &cli).await {
                log(
                    LogLevel::Error,
                    &format!("error processing {}: {}", target_url, e),
                );
            }
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
        log(
            LogLevel::Info,
            &format!("found {} cookie(s)", cookies.len()),
        );
    }

    let pb = setup_progress_bar(cli.verbose);

    // Fingerprinting pre-step
    let mut fingerprint_info: Option<FingerprintInfo> = None;
    let mut suggested_order: Option<Vec<&str>> = None;

    if cli.fingerprint {
        log(LogLevel::Info, "running proxy fingerprint probe");
        match fingerprint_target(host, port, path, cli.timeout, cli.verbose, use_tls).await {
            Ok(fp) => {
                log(
                    LogLevel::Info,
                    &format!("detected proxy: {}", fp.detected_proxy),
                );
                if let Some(ref server) = fp.server_header {
                    log(LogLevel::Info, &format!("server header: {}", server));
                }
                if cli.format.is_json() {
                    fingerprint_info = Some(FingerprintInfo {
                        detected_proxy: fp.detected_proxy.to_string(),
                        server_header: fp.server_header.clone(),
                        via_header: fp.via_header.clone(),
                        powered_by: fp.powered_by.clone(),
                    });
                }
                suggested_order = Some(suggest_checks(&fp));
            }
            Err(e) => {
                log(
                    LogLevel::Warning,
                    &format!("fingerprint probe failed: {}", e),
                );
            }
        }
    }

    let all_checks = [
        (
            "cl-te",
            get_cl_te_payloads as fn(&str, &str, &str, &[String], &[String]) -> Vec<String>,
        ),
        ("te-cl", get_te_cl_payloads),
        ("te-te", get_te_te_payloads),
        ("h2c", get_h2c_payloads),
        ("h2", get_h2_payloads),
        ("cl-edge", get_cl_edge_case_payloads),
    ];

    let checks_to_run: Vec<_> = if let Some(ref checks_str) = cli.checks {
        let selected_checks: Vec<&str> = checks_str.split(',').map(|s| s.trim()).collect();
        all_checks
            .into_iter()
            .filter(|(name, _)| selected_checks.contains(name))
            .collect()
    } else if let Some(ref order) = suggested_order {
        // Reorder checks based on fingerprint suggestion
        let mut ordered = Vec::new();
        for name in order {
            if let Some(entry) = all_checks.iter().find(|(n, _)| n == name) {
                ordered.push(*entry);
            }
        }
        ordered
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

        let mut payloads = payload_fn(path, host_header, &cli.method, &cli.headers, &cookies);

        if cli.fuzz {
            let config = MutatorConfig {
                seed: cli.fuzz_seed,
                mutations_per_payload: 5,
            };
            let mut mutator = Mutator::new(config);
            payloads = mutator.mutate_payloads(&payloads);
        }

        if let Some(max) = cli.max_payloads {
            payloads.truncate(max);
        }

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
            delay: cli.delay,
            baseline_count: cli.baseline_count,
        };

        let result = run_checks_for_type(params).await?;
        found_vulnerability |= result.vulnerable;
        results.push(result);
        pb.inc(1);
    }

    if !cli.verbose {
        pb.finish_and_clear();
    }

    log_scan_results(
        &results,
        &cli.format,
        target_url,
        &cli.method,
        &fingerprint_info,
    );

    // Run exploits if requested and vulnerabilities were found
    if let Some(ref exploit_str) = cli.exploit {
        if found_vulnerability {
            let exploit_params = ExploitParams {
                exploit_str,
                results: &results,
                host,
                port,
                path,
                use_tls,
                timeout: cli.timeout,
                verbose: cli.verbose,
                target_url,
                ports_str: &cli.exploit_ports,
                wordlist_path: cli.exploit_wordlist.as_deref(),
                delay: cli.delay,
            };
            run_exploits(&exploit_params).await?;
        } else {
            log(
                LogLevel::Warning,
                "exploit requested but no vulnerabilities found to exploit",
            );
        }
    }

    if let Some(ref output_file) = cli.output {
        save_results_to_file(
            output_file,
            target_url,
            &cli.method,
            results,
            &fingerprint_info,
        )?;
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

/// Extract vulnerability context and log it, returning None (with log) if unavailable.
fn prepare_exploit_context(results: &[CheckResult], verbose: bool) -> Option<VulnerabilityContext> {
    let vuln_ctx = extract_vulnerability_context(results);
    match &vuln_ctx {
        Some(ctx) if verbose => {
            println!(
                "\n{} Using detected {} vulnerability for exploitation",
                "[*]".cyan(),
                ctx.vuln_type.yellow().bold()
            );
        }
        None => {
            log(
                LogLevel::Error,
                "cannot extract vulnerability context for exploitation",
            );
        }
        _ => {}
    }
    vuln_ctx
}

async fn run_exploits(params: &ExploitParams<'_>) -> Result<()> {
    let exploits: Vec<&str> = params.exploit_str.split(',').map(|s| s.trim()).collect();

    for exploit_type in exploits {
        match exploit_type {
            "localhost-access" => {
                log(LogLevel::Info, "running localhost-access exploit");

                let vuln_ctx = match prepare_exploit_context(params.results, params.verbose) {
                    Some(ctx) => ctx,
                    None => continue,
                };

                // Parse target ports
                let localhost_ports: Vec<u16> = params
                    .ports_str
                    .split(',')
                    .filter_map(|s| s.trim().parse::<u16>().ok())
                    .collect();

                if localhost_ports.is_empty() {
                    log(
                        LogLevel::Error,
                        "no valid ports specified for localhost-access",
                    );
                    continue;
                }

                if params.verbose {
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
                let localhost_params = LocalhostAccessParams {
                    host: params.host,
                    port: params.port,
                    path: params.path,
                    use_tls: params.use_tls,
                    timeout: params.timeout,
                    verbose: params.verbose,
                    vuln_ctx: &vuln_ctx,
                    localhost_ports: &localhost_ports,
                    delay: params.delay,
                };
                match test_localhost_access(&localhost_params).await {
                    Ok(localhost_results) => {
                        print_localhost_results(&localhost_results, params.target_url);
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

                let vuln_ctx = match prepare_exploit_context(params.results, params.verbose) {
                    Some(ctx) => ctx,
                    None => continue,
                };

                // Get paths to fuzz
                let fuzz_paths = match get_fuzz_paths(params.wordlist_path) {
                    Ok(paths) => paths,
                    Err(e) => {
                        log(LogLevel::Error, &format!("failed to get fuzz paths: {}", e));
                        continue;
                    }
                };

                if params.verbose {
                    println!(
                        "  {} Testing {} paths{}",
                        "[*]".cyan(),
                        fuzz_paths.len(),
                        params
                            .wordlist_path
                            .map_or("".to_string(), |p| format!(" from {}", p))
                    );
                }

                // Run path fuzz test
                let path_fuzz_params = PathFuzzParams {
                    host: params.host,
                    port: params.port,
                    path: params.path,
                    use_tls: params.use_tls,
                    timeout: params.timeout,
                    verbose: params.verbose,
                    vuln_ctx: &vuln_ctx,
                    fuzz_paths: &fuzz_paths,
                    delay: params.delay,
                };
                match test_path_fuzz(&path_fuzz_params).await {
                    Ok(path_fuzz_results) => {
                        print_path_fuzz_results(&path_fuzz_results, params.target_url);
                    }
                    Err(e) => {
                        log(LogLevel::Error, &format!("path-fuzz exploit failed: {}", e));
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
