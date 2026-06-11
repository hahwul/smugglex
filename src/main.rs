use clap::Parser;
use colored::*;
use indicatif::{ProgressBar, ProgressStyle};
use std::io::{self, BufRead, IsTerminal};
use std::time::Duration;
use url::Url;

use smugglex::cli::Cli;
use smugglex::error::{Result, SmugglexError};
use smugglex::exploit::{
    LocalhostAccessParams, PathFuzzParams, VulnerabilityContext, extract_vulnerability_context,
    get_fuzz_paths, print_localhost_results, print_path_fuzz_results, test_localhost_access,
    test_path_fuzz,
};
use smugglex::fingerprint::{fingerprint_target, suggest_checks};
use smugglex::model::{CheckResult, FingerprintInfo, ScanResults};
use smugglex::mutator::{Mutator, MutatorConfig};
use smugglex::output::{
    build_batch_results, log_scan_results, print_batch_json, save_batch_to_file,
    save_results_to_file,
};
use smugglex::payloads::{
    get_cl_edge_case_payloads, get_cl_te_payloads, get_h2_payloads, get_h2c_payloads,
    get_te_cl_payloads, get_te_te_payloads,
};
use smugglex::raw_request::{merge_headers, parse_raw_request};
use smugglex::scanner::{CheckParams, run_checks_for_type};
use smugglex::utils::{LogLevel, fetch_cookies, is_machine, log, set_machine};

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
    smuggle_request: Option<&'a str>,
    reveal_endpoint: Option<&'a str>,
    reveal_param: &'a str,
}

/// Outcome of scanning a single target. Used to collect results for batch JSON output
/// and to determine the final exit code (0 = clean, 1 = vulnerable found).
#[derive(Debug)]
#[allow(dead_code)]
enum ScanOutcome {
    Success {
        target: String,
        scan_results: ScanResults,
        found_vulnerability: bool,
    },
    Failure {
        target: String,
        error: String,
    },
}

#[allow(dead_code)]
impl ScanOutcome {
    fn target(&self) -> &str {
        match self {
            ScanOutcome::Success { target, .. } => target,
            ScanOutcome::Failure { target, .. } => target,
        }
    }

    fn is_vulnerable(&self) -> bool {
        matches!(
            self,
            ScanOutcome::Success {
                found_vulnerability: true,
                ..
            }
        )
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let mut cli = Cli::parse();
    cli.apply_global_settings();

    // Activate machine mode for clean structured output (used by AI agents, scripts, CI).
    // When active, stdout will contain *only* JSON; all chatter goes to stderr or is suppressed.
    if cli.effective_format().is_json() {
        set_machine(true);
        // In pure machine mode we also want to suppress most progress noise.
        // (progress bar creation below already respects verbose, we additionally hide it for json)
    }

    if cli.version {
        println!("smugglex {}", env!("CARGO_PKG_VERSION"));
        return Ok(());
    }

    let urls = match resolve_urls(&mut cli) {
        Ok(urls) => urls,
        Err(e) => {
            emit_input_error(&cli, &e.to_string());
            // Usage/input error → exit 2 (common convention for CLI tools)
            std::process::exit(2);
        }
    };
    if urls.is_empty() {
        emit_input_error(&cli, "No valid URLs provided");
        // Usage/input error → exit 2 (common convention for CLI tools)
        std::process::exit(2);
    }

    // Collect outcomes from all targets. This enables:
    // - Clean single JSON document for batch scans (critical for AI / jq / scripts)
    // - Correct exit code (0 = clean, 1 = vulnerable found)
    let mut outcomes: Vec<ScanOutcome> = Vec::with_capacity(urls.len());

    if cli.concurrency > 1 {
        // Concurrent processing in chunks (preserves previous backpressure behavior)
        for chunk in urls.chunks(cli.concurrency) {
            let mut handles = Vec::new();
            for target_url in chunk {
                let url = target_url.clone();
                let cli_ref = cli.clone();
                handles.push((
                    url.clone(),
                    tokio::spawn(async move { scan_one_target(url, cli_ref).await }),
                ));
            }
            for (target, handle) in handles {
                match handle.await {
                    Ok(outcome) => outcomes.push(outcome),
                    Err(join_err) => {
                        if !is_machine() {
                            log(
                                LogLevel::Error,
                                &format!("worker task failed for {}: {}", target, join_err),
                            );
                        }
                        outcomes.push(ScanOutcome::Failure {
                            target,
                            error: format!("worker task failed: {}", join_err),
                        });
                    }
                }
            }
        }
    } else {
        for target_url in urls {
            let outcome = scan_one_target(target_url, cli.clone()).await;
            outcomes.push(outcome);
        }
    }

    // Compute overall vulnerability status for exit code
    let any_vulnerable = outcomes.iter().any(|o| o.is_vulnerable());
    let any_failures = outcomes
        .iter()
        .any(|o| matches!(o, ScanOutcome::Failure { .. }));

    // Emit results
    let json_mode = cli.effective_format().is_json();
    if json_mode {
        // Convert outcomes to ScanResults (synthesize minimal entry for failures so every
        // requested target appears in the output).
        let scan_results: Vec<ScanResults> = outcomes
            .into_iter()
            .map(|o| match o {
                ScanOutcome::Success { scan_results, .. } => scan_results,
                ScanOutcome::Failure { target, error } => ScanResults {
                    target,
                    method: cli.method.clone(),
                    timestamp: chrono::Utc::now().to_rfc3339(),
                    fingerprint: None,
                    checks: Vec::new(),
                    error: Some(error),
                },
            })
            .collect();

        let batch = build_batch_results(scan_results, Some(env!("CARGO_PKG_VERSION")));
        print_batch_json(&batch);

        if let Some(ref output_file) = cli.output
            && let Err(e) = save_batch_to_file(&batch, output_file)
        {
            log(
                LogLevel::Error,
                &format!("failed to write batch output file: {}", e),
            );
        }
    } else {
        // Plain text mode: preserve previous per-target human output behavior.
        // We already printed inside scan_one_target for the non-json path.
        // (scan_one_target calls log_scan_results when not in machine mode.)
        // Nothing more to do here for output.
    }

    // Final timing is intentionally omitted in machine mode to keep stdout pure.
    // In plain mode the per-target "scan completed in" messages were already emitted by the old path.

    if any_vulnerable {
        std::process::exit(1);
    }

    if any_failures {
        std::process::exit(2);
    }

    Ok(())
}

/// Emit an input/usage error consistently with the selected output format:
/// a pure (empty) JSON envelope in machine mode so AI agents can parse uniformly,
/// or a human-readable message otherwise. Callers exit with code 2 afterward.
fn emit_input_error(cli: &Cli, message: &str) {
    if cli.effective_format().is_json() {
        let empty_batch = build_batch_results(Vec::new(), Some(env!("CARGO_PKG_VERSION")));
        match serde_json::to_string_pretty(&empty_batch) {
            Ok(json) => println!("{}", json),
            Err(e) => {
                log(
                    LogLevel::Error,
                    &format!("failed to serialize empty batch results: {}", e),
                );
                println!(
                    "{}",
                    serde_json::json!({
                        "results": [],
                        "summary": {
                            "total_targets": 0,
                            "vulnerable_targets": 0,
                            "total_checks": 0,
                            "vulnerable_checks": 0
                        }
                    })
                );
            }
        }
    } else {
        eprintln!("{} {}", "[!]".yellow().bold(), message);
    }
}

/// Load a `--raw-request` file and apply it as the request template: parse it,
/// override the request fields the payload generators read (method, headers,
/// Host), and return the synthetic target URL the scan pipeline consumes.
fn apply_raw_request(cli: &mut Cli) -> Result<String> {
    let path = cli
        .raw_request
        .clone()
        .expect("apply_raw_request called without --raw-request");
    let content = std::fs::read_to_string(&path).map_err(|e| {
        SmugglexError::Io(format!("failed to read raw request file '{}': {}", path, e))
    })?;
    let raw = parse_raw_request(&content)?;

    // Connection target only (scheme/host/port). The request-target is applied
    // separately and verbatim via cli.raw_target so its exact bytes survive.
    let connect_url = raw.connect_url(&cli.raw_request_proto);

    // The captured body is intentionally discarded (the payloads craft their own);
    // note it in verbose mode so the user isn't surprised it had no effect.
    if raw.had_body && cli.verbose && !is_machine() {
        log(
            LogLevel::Info,
            "captured request body ignored; smuggling payloads generate their own body",
        );
    }

    // The captured request's method wins, so warn if the user also passed an
    // explicit --method (anything other than the default) that we're discarding.
    let user_set_method = cli.method != smugglex::cli::DEFAULT_METHOD;
    if user_set_method && cli.method != raw.method && !is_machine() {
        log(
            LogLevel::Warning,
            &format!(
                "--method {} is ignored; the captured request method {} (from --raw-request) is used instead",
                cli.method, raw.method
            ),
        );
    }

    // Feed the captured request into the same fields the payload builders read.
    cli.method = raw.method;
    // Merge headers additively: captured headers first, then any user-supplied -H,
    // so an explicit -H (e.g. a collaborator marker) is never silently dropped.
    let user_headers = std::mem::take(&mut cli.headers);
    cli.headers = merge_headers(raw.headers, &user_headers);
    // Apply the request-target verbatim downstream (no URL normalization).
    cli.raw_target = Some(raw.target);
    // Preserve the exact Host header (including any :port) unless --vhost was set explicitly.
    if cli.vhost.is_none() {
        cli.vhost = Some(raw.host_header);
    }

    Ok(connect_url)
}

fn resolve_urls(cli: &mut Cli) -> Result<Vec<String>> {
    if cli.raw_request.is_some() {
        if !cli.urls.is_empty() {
            return Err(SmugglexError::InvalidInput(
                "--raw-request cannot be combined with target URLs; the target is taken from the request file".to_string(),
            ));
        }
        let target = apply_raw_request(cli)?;
        return Ok(vec![target]);
    }

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

/// Core scan routine for one target. Returns a ScanOutcome (Success with full ScanResults
/// or Failure with error string).
///
/// In non-machine (plain text) mode it performs the same human-readable logging as before.
/// In machine/JSON mode it suppresses all human chatter and progress output so that the
/// only thing on stdout is the final structured JSON (emitted by the caller).
async fn scan_one_target(target: String, cli: Cli) -> ScanOutcome {
    let start_time = std::time::Instant::now();
    let target_url = target.as_str();
    let network_verbose = cli.verbose && !is_machine();

    let scan_failure = |message: String| {
        if !is_machine() {
            log(
                LogLevel::Error,
                &format!("failed to scan {}: {}", target_url, message),
            );
        }
        ScanOutcome::Failure {
            target: target_url.to_string(),
            error: message,
        }
    };

    let url = match Url::parse(target_url) {
        Ok(u) => u,
        Err(e) => return scan_failure(format!("URL parse error: {}", e)),
    };

    let host = match url.host_str() {
        Some(h) => h,
        None => return scan_failure("Invalid host in URL".to_string()),
    };
    let port = match url.port_or_known_default() {
        Some(p) => p,
        None => return scan_failure("Invalid port in URL".to_string()),
    };
    // Preserve any query string so raw-request templates (and normal URLs) keep
    // their full request-target, not just the path. A --raw-request capture carries
    // its literal request-target in cli.raw_target so the exact bytes (dot-segments,
    // `#`, matrix params) bypass the URL normalization the synthetic connect URL went
    // through.
    let path_with_query;
    let path = if let Some(ref raw_target) = cli.raw_target {
        raw_target.as_str()
    } else if let Some(query) = url.query() {
        path_with_query = format!("{}?{}", url.path(), query);
        path_with_query.as_str()
    } else {
        url.path()
    };
    let use_tls = url.scheme() == "https";
    let host_header = cli.vhost.as_deref().unwrap_or(host);

    // What we report to the user/agent (logs, JSON `target`, output filenames).
    // For a --raw-request capture, `target_url` is only the root-path connect URL,
    // so reports would otherwise hide the actual endpoint; rebuild it from the
    // literal request-target by concatenation (no URL re-parse, so the exact bytes
    // survive). Normal URLs report `target_url` unchanged.
    let display_target_owned;
    let display_target: &str = if cli.raw_target.is_some() {
        display_target_owned = format!("{}://{}:{}{}", url.scheme(), host, port, path);
        &display_target_owned
    } else {
        target_url
    };

    // Human logs only in plain mode
    if !is_machine() {
        log(LogLevel::Info, &format!("start scan to {}", display_target));
    }

    let cookies = if cli.use_cookies {
        match fetch_cookies(host, port, path, use_tls, cli.timeout, network_verbose).await {
            Ok(c) => {
                if !c.is_empty() && !is_machine() {
                    log(LogLevel::Info, &format!("found {} cookie(s)", c.len()));
                }
                c
            }
            Err(e) => {
                // Cookie fetch failure is non-fatal for the scan itself
                if !is_machine() {
                    log(LogLevel::Warning, &format!("cookie fetch failed: {}", e));
                }
                Vec::new()
            }
        }
    } else {
        Vec::new()
    };

    // Progress bar is hidden in machine mode or when verbose (old behavior)
    let pb = setup_progress_bar(cli.verbose || is_machine());

    // Fingerprinting pre-step
    let mut fingerprint_info: Option<FingerprintInfo> = None;
    let mut suggested_order: Option<Vec<&str>> = None;

    if cli.fingerprint {
        if !is_machine() {
            log(LogLevel::Info, "running proxy fingerprint probe");
        }
        match fingerprint_target(host, port, path, cli.timeout, network_verbose, use_tls).await {
            Ok(fp) => {
                if !is_machine() {
                    log(
                        LogLevel::Info,
                        &format!("detected proxy: {}", fp.detected_proxy),
                    );
                    if let Some(ref server) = fp.server_header {
                        log(LogLevel::Info, &format!("server header: {}", server));
                    }
                }
                if cli.effective_format().is_json() {
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
                if !is_machine() {
                    log(
                        LogLevel::Warning,
                        &format!("fingerprint probe failed: {}", e),
                    );
                }
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

    // The real-HTTP/2 downgrade check (H2.CL / H2.TE) speaks ALPN h2, so it only
    // applies to https targets. It is not a payload-string check, so it lives
    // outside `all_checks`; honour it when checks are unspecified or it is named.
    let h2_explicitly_requested = matches!(
        cli.checks,
        Some(ref s) if s.split(',').any(|x| x.trim() == "h2-downgrade")
    );
    let h2_downgrade_selected = use_tls && (cli.checks.is_none() || h2_explicitly_requested);
    if !is_machine() {
        if h2_explicitly_requested && !use_tls {
            log(
                LogLevel::Warning,
                "h2-downgrade requires an https target (ALPN h2); skipping it for this non-TLS URL",
            );
        }
        if h2_downgrade_selected && cli.proxy.is_some() {
            log(
                LogLevel::Warning,
                "h2-downgrade connects directly and does not route through --proxy",
            );
        }
    }
    let total_checks = checks_to_run.len() + h2_downgrade_selected as usize;

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
            verbose: network_verbose,
            use_tls,
            export_dir: cli.export_dir.as_deref(),
            current_check: i + 1,
            total_checks,
            delay: cli.delay,
            baseline_count: cli.baseline_count,
        };

        match run_checks_for_type(params).await {
            Ok(result) => {
                found_vulnerability |= result.vulnerable;
                results.push(result);
                pb.inc(1);
            }
            Err(e) => {
                // Record as diagnostic but continue with other checks
                if !is_machine() {
                    log(
                        LogLevel::Warning,
                        &format!("{} check failed: {}", check_name, e),
                    );
                }
                results.push(CheckResult {
                    check_type: check_name.to_string(),
                    vulnerable: false,
                    payload_index: None,
                    normal_status: "CHECK_FAILED".to_string(),
                    attack_status: None,
                    normal_duration_ms: 0,
                    attack_duration_ms: None,
                    timestamp: chrono::Utc::now().to_rfc3339(),
                    payload: None,
                    confidence: None,
                    detection_signals: Vec::new(),
                    diagnostics: vec![format!("check_failed: {}", e)],
                });
                pb.inc(1);
            }
        }
    }

    // Real HTTP/2 downgrade smuggling (H2.CL / H2.TE) over ALPN h2. Runs after
    // the HTTP/1.1 checks because it uses a genuine HTTP/2 client rather than a
    // payload string.
    if h2_downgrade_selected && !(cli.exit_first && found_vulnerability) {
        if !cli.verbose && !is_machine() {
            pb.set_message(format!(
                "[{}/{}] checking h2-downgrade",
                total_checks, total_checks
            ));
        }
        let result = smugglex::http2::run_h2_downgrade_check(
            host,
            port,
            host_header,
            path,
            cli.timeout,
            network_verbose,
        )
        .await;
        found_vulnerability |= result.vulnerable;
        results.push(result);
        pb.inc(1);
    }

    if !cli.verbose && !is_machine() {
        pb.finish_and_clear();
    }

    // In machine mode we never call log_scan_results here — the caller will emit one clean JSON document.
    if !is_machine() {
        log_scan_results(
            &results,
            &cli.effective_format(),
            display_target,
            &cli.method,
            &fingerprint_info,
        );
    }

    // Run exploits only in plain mode (their output is human-oriented).
    // In machine/JSON mode we still allow payload export via the check phase, but skip exploit execution
    // to keep stdout clean and because exploit details are better consumed interactively.
    if let Some(ref exploit_str) = cli.exploit {
        // The `smuggle`/`capture`/`reveal` exploits fire their payload directly
        // and do not depend on a prior detection, so allow them to run even when
        // the scan was quiet.
        let direct_exploit = exploit_str
            .split(',')
            .any(|x| matches!(x.trim(), "smuggle" | "capture" | "reveal"));
        if (found_vulnerability || direct_exploit) && !is_machine() {
            let exploit_params = ExploitParams {
                exploit_str,
                results: &results,
                host,
                port,
                path,
                use_tls,
                timeout: cli.timeout,
                verbose: cli.verbose,
                target_url: display_target,
                ports_str: &cli.exploit_ports,
                wordlist_path: cli.exploit_wordlist.as_deref(),
                delay: cli.delay,
                smuggle_request: cli.smuggle_request.as_deref(),
                reveal_endpoint: cli.reveal_endpoint.as_deref(),
                reveal_param: &cli.reveal_param,
            };
            if let Err(e) = run_exploits(&exploit_params).await {
                log(LogLevel::Error, &format!("exploit phase failed: {}", e));
            }
        } else if found_vulnerability && is_machine() {
            log(
                LogLevel::Warning,
                "exploit requested in JSON mode; skipping (re-run without --json/-f json for exploit output)",
            );
        } else if !is_machine() {
            log(
                LogLevel::Warning,
                "exploit requested but no vulnerabilities found to exploit",
            );
        }
    }

    // Per-target file output (-o) is only done for plain mode here.
    // For JSON batch the caller writes the full envelope once at the end.
    if !is_machine()
        && let Some(ref output_file) = cli.output
        && let Err(e) = save_results_to_file(
            output_file,
            display_target,
            &cli.method,
            results.clone(),
            &fingerprint_info,
        )
    {
        log(
            LogLevel::Error,
            &format!("failed to write output file: {}", e),
        );
    }

    let duration = start_time.elapsed();
    if !is_machine() {
        log(
            LogLevel::Info,
            &format!("scan completed in {:.3} seconds", duration.as_secs_f64()),
        );
    }

    // Build the structured result for the outcome (always produced, used for JSON batch or exit code)
    let scan_results = ScanResults {
        target: display_target.to_string(),
        method: cli.method.clone(),
        timestamp: chrono::Utc::now().to_rfc3339(),
        fingerprint: fingerprint_info,
        checks: results,
        error: None,
    };

    ScanOutcome::Success {
        target: display_target.to_string(),
        scan_results,
        found_vulnerability,
    }
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
            "smuggle" => {
                log(LogLevel::Info, "running smuggle exploit");

                // Unlike the other exploits, this one does not require a prior
                // detection — it just fires the smuggle (trying both CL.TE and
                // TE.CL wrappers), so it can directly solve/confirm a target.

                // Interpret \r\n / \n escapes so the inner request can be passed
                // on one CLI line; fall back to the GPOST-solving default.
                let inner_request = params
                    .smuggle_request
                    .map(|s| s.replace("\\r\\n", "\r\n").replace("\\n", "\n"))
                    .unwrap_or_else(|| smugglex::exploit::DEFAULT_SMUGGLE_REQUEST.to_string());

                let smuggle_params = smugglex::exploit::SmuggleParams {
                    host: params.host,
                    port: params.port,
                    path: params.path,
                    use_tls: params.use_tls,
                    timeout: params.timeout,
                    verbose: params.verbose,
                    inner_request: inner_request.clone(),
                    rounds: 6,
                    delay: params.delay,
                };
                match smugglex::exploit::test_smuggle(&smuggle_params).await {
                    Ok(result) => smugglex::exploit::print_smuggle_results(
                        &result,
                        params.target_url,
                        &inner_request,
                    ),
                    Err(e) => log(LogLevel::Error, &format!("smuggle exploit failed: {}", e)),
                }
            }
            "capture" => {
                log(LogLevel::Info, "running capture exploit");

                // The request to smuggle and capture. Defaults to GET /admin (the
                // recon step the access-control labs need); must be complete.
                let smuggled = params
                    .smuggle_request
                    .map(|s| s.replace("\\r\\n", "\r\n").replace("\\n", "\n"))
                    .unwrap_or_else(|| {
                        format!("GET /admin HTTP/1.1\r\nHost: {}\r\n\r\n", params.host)
                    });

                let capture_params = smugglex::exploit::CaptureParams {
                    host: params.host,
                    port: params.port,
                    path: params.path,
                    use_tls: params.use_tls,
                    timeout: params.timeout,
                    verbose: params.verbose,
                    smuggled_request: smuggled.clone(),
                    follow_ups: 3,
                };
                match smugglex::exploit::test_capture(&capture_params).await {
                    Ok(result) => smugglex::exploit::print_capture_results(
                        &result,
                        params.target_url,
                        &smuggled,
                    ),
                    Err(e) => log(LogLevel::Error, &format!("capture exploit failed: {}", e)),
                }
            }
            "reveal" => {
                log(LogLevel::Info, "running reveal exploit");

                // Like smuggle/capture, this fires its own wrapper directly and
                // needs no prior detection. It smuggles a POST to a reflecting
                // endpoint with an oversized Content-Length so the next request —
                // as rewritten by the front-end — is echoed back, exposing any
                // injected headers.
                let reveal_params = smugglex::exploit::RevealParams {
                    host: params.host,
                    port: params.port,
                    path: params.path,
                    use_tls: params.use_tls,
                    timeout: params.timeout,
                    verbose: params.verbose,
                    reflect_endpoint: params.reveal_endpoint.unwrap_or(params.path).to_string(),
                    reflect_param: params.reveal_param.to_string(),
                    follow_ups: 4,
                };
                match smugglex::exploit::test_reveal(&reveal_params).await {
                    Ok(result) => smugglex::exploit::print_reveal_results(
                        &result,
                        params.target_url,
                        &reveal_params,
                    ),
                    Err(e) => log(LogLevel::Error, &format!("reveal exploit failed: {}", e)),
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
