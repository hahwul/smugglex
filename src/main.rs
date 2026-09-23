use clap::Parser;
use colored::*;
use indicatif::{ProgressBar, ProgressStyle};
use std::io::{self, BufRead, IsTerminal};
use std::time::Duration;
use url::Url;

use smugglex::cli::Cli;
use smugglex::desync::{ConnectionDesyncParams, run_cl0_check, run_zero_cl_check};
use smugglex::error::{Result, SmugglexError};
use smugglex::exploit::{
    LocalhostAccessParams, PathFuzzParams, VulnerabilityContext, extract_vulnerability_context,
    get_fuzz_paths, print_localhost_results, print_path_fuzz_results,
    test_localhost_access_with_authority, test_path_fuzz_with_authority,
};
use smugglex::fingerprint::{fingerprint_target_with_authority, suggest_checks};
use smugglex::http;
use smugglex::model::{CheckResult, FingerprintInfo, ScanResults};
use smugglex::mutator::{Mutator, MutatorConfig};
use smugglex::output::{
    build_batch_results, log_scan_results, print_batch_json, save_batch_to_file,
    save_scan_results_to_file,
};
use smugglex::parser::{ParserDiscrepancyParams, run_parser_discrepancy_check_with_authority};
use smugglex::payloads::{
    get_cl_edge_case_payloads, get_cl_te_payloads, get_h2_payloads, get_h2c_payloads,
    get_te_cl_payloads, get_te_te_payloads,
};
use smugglex::raw_request::{
    merge_headers, parse_raw_request, validate_host_header_value, validate_http_method,
};
use smugglex::scanner::{CheckParams, run_checks_for_type};
use smugglex::utils::{LogLevel, fetch_cookies_with_authority, is_machine, log, set_machine};

/// Convert a `Vec<String>` payload family into the byte-oriented representation
/// (`Vec<Vec<u8>>`) the scanner consumes.
fn strings_to_bytes(payloads: Vec<String>) -> Vec<Vec<u8>> {
    payloads.into_iter().map(String::into_bytes).collect()
}

// Byte-oriented adapters for the pure-ASCII payload families (h2c/h2/cl-edge),
// which still build `Vec<String>`. They let the whole `all_checks` dispatch table
// share one `fn(...) -> Vec<Vec<u8>>` signature alongside the raw-byte TE families.
fn h2c_payloads_bytes(
    path: &str,
    host: &str,
    method: &str,
    custom_headers: &[String],
    cookies: &[String],
) -> Vec<Vec<u8>> {
    strings_to_bytes(get_h2c_payloads(
        path,
        host,
        method,
        custom_headers,
        cookies,
    ))
}

fn h2_payloads_bytes(
    path: &str,
    host: &str,
    method: &str,
    custom_headers: &[String],
    cookies: &[String],
) -> Vec<Vec<u8>> {
    strings_to_bytes(get_h2_payloads(path, host, method, custom_headers, cookies))
}

fn cl_edge_payloads_bytes(
    path: &str,
    host: &str,
    method: &str,
    custom_headers: &[String],
    cookies: &[String],
) -> Vec<Vec<u8>> {
    strings_to_bytes(get_cl_edge_case_payloads(
        path,
        host,
        method,
        custom_headers,
        cookies,
    ))
}

#[derive(Debug)]
struct ExploitParams<'a> {
    exploit_str: &'a str,
    results: &'a [CheckResult],
    host: &'a str,
    authority: &'a str,
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
enum ScanOutcome {
    Success {
        scan_results: ScanResults,
        found_vulnerability: bool,
    },
    Failure {
        target: String,
        error: String,
    },
}

impl ScanOutcome {
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

/// Whether an outcome should drive a non-zero (failure) exit code: a hard
/// `Failure` (URL/host error, worker panic) or a `Success` whose `ScanResults`
/// carries an `error` (e.g. an unreachable target where every check failed to
/// connect). Both let a scripted batch tell "down/errored" from "clean".
fn outcome_is_failure(o: &ScanOutcome) -> bool {
    match o {
        ScanOutcome::Failure { .. } => true,
        ScanOutcome::Success { scan_results, .. } => scan_results.error.is_some(),
    }
}

/// Parse a comma-separated `--exploit-ports` list into `(valid ports, invalid
/// tokens)`. Empty/whitespace-only segments are ignored; any token that is not a
/// valid `u16` is returned as invalid so the caller can warn rather than silently
/// drop it.
fn parse_exploit_ports(ports_str: &str) -> (Vec<u16>, Vec<String>) {
    let mut valid = Vec::new();
    let mut invalid = Vec::new();
    for tok in ports_str
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        match tok.parse::<u16>() {
            Ok(p) => valid.push(p),
            Err(_) => invalid.push(tok.to_string()),
        }
    }
    (valid, invalid)
}

/// Interpret literal `\r\n` / `\n` escape sequences in a CLI-supplied request so
/// a multi-line raw request can be passed on a single command line. Order matters:
/// `\r\n` is expanded before the bare `\n` so a CRLF is not split into `\r` + LF.
fn interpret_line_escapes(s: &str) -> String {
    s.replace("\\r\\n", "\r\n").replace("\\n", "\n")
}

/// What to do with a requested `--exploit` list, given the scan state.
#[derive(Debug, PartialEq, Eq)]
enum ExploitAction {
    /// Run the exploit phase (plain mode, and either a detection or a
    /// direct-firing exploit like smuggle/capture/reveal).
    Run,
    /// Skip because output is JSON/machine mode (exploit output is human-oriented).
    SkipMachineMode,
    /// Skip because nothing was detected and no direct-firing exploit was asked for.
    SkipNoDetection,
}

/// Decide the exploit action. Extracted so every case is covered and testable —
/// in particular a direct exploit (`reveal`/`smuggle`/`capture`) requested in
/// JSON mode used to fall through *all* branches and be dropped with no message.
fn decide_exploit_action(
    exploit_str: &str,
    found_vulnerability: bool,
    machine: bool,
) -> ExploitAction {
    if machine {
        // Exploit output never goes to the JSON stream; always tell the user.
        return ExploitAction::SkipMachineMode;
    }
    let direct = exploit_str
        .split(',')
        .any(|x| matches!(x.trim(), "smuggle" | "capture" | "reveal"));
    if found_vulnerability || direct {
        ExploitAction::Run
    } else {
        ExploitAction::SkipNoDetection
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let mut cli = Cli::parse();
    cli.apply_global_settings();

    // Initialize TLS config (must happen before any network requests).
    http::init_tls_config(
        cli.insecure,
        cli.cacert.as_deref().map(std::path::Path::new),
    )
    .unwrap_or_else(|e| {
        eprintln!("{} TLS init error: {}", "[!]".yellow().bold(), e);
        std::process::exit(2);
    });

    // Activate machine mode for clean structured output (used by AI agents, scripts, CI).
    // When active, stdout will contain *only* JSON; all chatter goes to stderr or is suppressed.
    if cli.effective_format().is_json() {
        set_machine(true);
        // In pure machine mode we also want to suppress most progress noise.
        // (progress bar creation below already respects verbose, we additionally hide it for json)
    }

    if cli.version {
        // Keep stdout a single JSON document in machine mode; a bare text line
        // would break a JSON consumer that also passes -v/--version.
        if is_machine() {
            println!(
                "{}",
                serde_json::json!({ "smugglex_version": env!("CARGO_PKG_VERSION") })
            );
        } else {
            println!("smugglex {}", env!("CARGO_PKG_VERSION"));
        }
        return Ok(());
    }

    // Validate --proxy up front so an unsupported scheme (e.g. socks5) or a
    // malformed URL fails immediately with a clear message, rather than failing
    // per target once scanning starts.
    if let Some(ref proxy) = cli.proxy
        && let Err(e) = http::validate_proxy_url(proxy)
    {
        emit_input_error(&cli, &e.to_string());
        std::process::exit(2);
    }

    let urls = match resolve_urls(&mut cli) {
        Ok(urls) => urls,
        Err(e) => {
            emit_input_error(&cli, &e.to_string());
            // Usage/input error → exit 2 (common convention for CLI tools)
            std::process::exit(2);
        }
    };
    if let Err(e) = validate_http_method(&cli.method) {
        emit_input_error(&cli, &e.to_string());
        std::process::exit(2);
    }
    if let Some(vhost) = cli.vhost.as_deref()
        && let Err(e) = validate_host_header_value(vhost)
    {
        emit_input_error(&cli, &e.to_string());
        std::process::exit(2);
    }
    if urls.is_empty() {
        emit_input_error(&cli, "No valid URLs provided");
        // Usage/input error → exit 2 (common convention for CLI tools)
        std::process::exit(2);
    }

    // Validate `--checks` up front (target-independent): a typo must not
    // silently scan nothing and report a clean target with exit 0.
    if let Some(ref checks_str) = cli.checks {
        let unknown =
            smugglex::cli::unknown_check_names(checks_str, &smugglex::cli::KNOWN_CHECK_NAMES);
        if !unknown.is_empty() && !is_machine() {
            log(
                LogLevel::Warning,
                &format!(
                    "ignoring unrecognized check name(s): {} (known: {})",
                    unknown.join(", "),
                    smugglex::cli::KNOWN_CHECK_NAMES.join(", "),
                ),
            );
        }
        if !smugglex::cli::has_any_known_check(checks_str, &smugglex::cli::KNOWN_CHECK_NAMES) {
            emit_input_error(
                &cli,
                &format!(
                    "no valid checks selected from --checks '{}'; nothing would be scanned (known checks: {})",
                    checks_str,
                    smugglex::cli::KNOWN_CHECK_NAMES.join(", "),
                ),
            );
            // Usage/input error → exit 2
            std::process::exit(2);
        }
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
    let any_failures = outcomes.iter().any(outcome_is_failure);

    // Convert outcomes to ScanResults (synthesize a minimal entry for failures
    // so every requested target appears in the output).
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

    // Emit results. Track whether writing the -o file failed so a silent write
    // error (disk full, unwritable path) is surfaced in the exit code rather
    // than leaving a scripted caller believing the report was saved.
    let json_mode = cli.effective_format().is_json();
    let mut output_write_failed = false;
    if json_mode {
        let batch = build_batch_results(scan_results, Some(env!("CARGO_PKG_VERSION")));
        print_batch_json(&batch);

        if let Some(ref output_file) = cli.output
            && let Err(e) = save_batch_to_file(&batch, output_file)
        {
            output_write_failed = true;
            log(
                LogLevel::Error,
                &format!("failed to write batch output file: {}", e),
            );
        }
    } else {
        // Plain text mode: the per-target human output was already printed
        // inside scan_one_target. Any `-o` file, though, is written here — once,
        // after all targets — so a multi-target run no longer overwrites the
        // file with only the last target's results. A single target keeps the
        // flat ScanResults shape for backward compatibility; multiple targets
        // get the same batch envelope as JSON mode.
        if let Some(ref output_file) = cli.output {
            let write_result = match scan_results.as_slice() {
                [single] => save_scan_results_to_file(single, output_file),
                _ => {
                    let batch = build_batch_results(scan_results, Some(env!("CARGO_PKG_VERSION")));
                    save_batch_to_file(&batch, output_file)
                }
            };
            if let Err(e) = write_result {
                output_write_failed = true;
                log(
                    LogLevel::Error,
                    &format!("failed to write output file: {}", e),
                );
            }
        }
    }

    // Final timing is intentionally omitted in machine mode to keep stdout pure.
    // In plain mode the per-target "scan completed in" messages were already emitted by the old path.

    // A confirmed vulnerability is the primary signal, so it keeps priority for
    // the exit code. Otherwise a target-level failure or a failed -o write is an
    // operational problem → exit 2.
    if any_vulnerable {
        std::process::exit(1);
    }

    if any_failures || output_write_failed {
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
        eprintln!("ERR {message}");
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
        collect_url_lines(io::stdin().lock().lines())
    } else if is_machine() {
        // No URLs and stdin is an interactive terminal. In machine/JSON mode we
        // must NOT dump clap's help banner to stdout and let it exit 0 — that
        // violates JSON-stdout purity and the exit-code contract. Return an empty
        // list so the caller emits the structured input error and exits 2 (the
        // same path the piped/empty-stdin branch takes).
        Ok(Vec::new())
    } else {
        Cli::parse_from(["smugglex", "--help"]);
        Ok(Vec::new())
    }
}

/// Collect target URLs from a stream of input lines: each is trimmed of
/// surrounding whitespace and dropped if empty, so a `urls.txt` entry like
/// ` http://x ` (stray spaces, common when piping) still parses downstream
/// instead of failing `Url::parse` on the leading space. A read error aborts
/// collection so a partial stdin batch cannot be reported as a complete scan.
fn collect_url_lines(lines: impl Iterator<Item = io::Result<String>>) -> Result<Vec<String>> {
    let mut urls = Vec::new();
    for line in lines {
        let line = line.map_err(|e| SmugglexError::Io(format!("error reading from stdin: {e}")))?;
        let trimmed = line.trim();
        if !trimmed.is_empty() {
            urls.push(trimmed.to_string());
        }
    }
    Ok(urls)
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

    // Only http/https are meaningful for an HTTP request-smuggling scanner. Any
    // other scheme that happens to carry a known default port (ftp://, ws://,
    // gopher://, …) would otherwise be silently treated as plaintext HTTP on that
    // port (use_tls keys solely off "https"), scanning the wrong service. Reject
    // it as an input error instead of connecting somewhere the user didn't mean.
    match url.scheme() {
        "http" | "https" => {}
        other => {
            return scan_failure(format!(
                "unsupported URL scheme '{other}'; only http:// and https:// are supported"
            ));
        }
    }

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
        match fetch_cookies_with_authority(
            host,
            host_header,
            port,
            path,
            use_tls,
            cli.timeout,
            network_verbose,
        )
        .await
        {
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
        match fingerprint_target_with_authority(
            host,
            host_header,
            port,
            path,
            cli.timeout,
            network_verbose,
            use_tls,
        )
        .await
        {
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

    // The CL.TE/TE.CL/TE.TE families return raw request bytes (`Vec<Vec<u8>>`) so
    // their extended-ASCII TE obfuscations reach the wire verbatim. The h2c/h2/
    // cl-edge families are pure ASCII and return `Vec<String>`; wrap them so the
    // whole dispatch table shares one byte-oriented signature.
    let all_checks = [
        (
            "cl-te",
            get_cl_te_payloads as fn(&str, &str, &str, &[String], &[String]) -> Vec<Vec<u8>>,
        ),
        ("te-cl", get_te_cl_payloads),
        ("te-te", get_te_te_payloads),
        ("h2c", h2c_payloads_bytes),
        ("h2", h2_payloads_bytes),
        ("cl-edge", cl_edge_payloads_bytes),
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
    // Whether at least one check actually reached the target (established a
    // baseline / got an HTTP/2 response). If every check failed to connect, the
    // target is unreachable — a distinct outcome from a genuinely clean scan,
    // which we must not silently report as "0 vulnerabilities" with exit 0.
    let mut any_check_reachable = false;

    // The real-HTTP/2 downgrade check (H2.CL / H2.TE) speaks ALPN h2, so it only
    // applies to https targets. It is not a payload-string check, so it lives
    // outside `all_checks`; honour it when checks are unspecified or it is named.
    let h2_explicitly_requested = matches!(
        cli.checks,
        Some(ref s) if s.split(',').any(|x| x.trim() == "h2-downgrade")
    );
    let h2_downgrade_selected = use_tls && (cli.checks.is_none() || h2_explicitly_requested);
    // Parser discrepancy is intentionally opt-in: it repeats a small control
    // corpus and is most useful as a focused audit after the faster payload
    // families have been triaged.
    let parser_discrepancy_selected = matches!(
        cli.checks,
        Some(ref s) if s.split(',').any(|x| x.trim() == "parser-discrepancy")
    );
    // CL.0 is intentionally opt-in because it deliberately reuses one
    // connection for setup and follow-up requests and can affect connection
    // state on intermediaries that do not isolate backend pools.
    let cl0_selected = matches!(
        cli.checks,
        Some(ref s) if s.split(',').any(|x| x.trim() == "cl-0")
    );
    // 0.CL needs a two-phase HTTP/1.1 exchange (headers, early-response wait,
    // then body) and is therefore also opt-in.
    let zero_cl_selected = matches!(
        cli.checks,
        Some(ref s) if s.split(',').any(|x| x.trim() == "0-cl")
    );
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
    let total_checks = checks_to_run.len()
        + parser_discrepancy_selected as usize
        + cl0_selected as usize
        + zero_cl_selected as usize
        + h2_downgrade_selected as usize;

    for (i, (check_name, payload_fn)) in checks_to_run.iter().enumerate() {
        if cli.exit_first && found_vulnerability {
            break;
        }

        let mut payloads: Vec<Vec<u8>> =
            payload_fn(path, host_header, &cli.method, &cli.headers, &cookies);

        if cli.fuzz {
            let config = MutatorConfig {
                seed: cli.fuzz_seed,
                mutations_per_payload: 5,
            };
            let mut mutator = Mutator::new(config);
            // The mutation engine is UTF-8/string based, so it can only mutate
            // seeds that are valid UTF-8. Split them: UTF-8-clean seeds go through
            // the mutator; seeds carrying non-UTF-8 obfuscation bytes (NEL/NBSP/
            // soft-hyphen/…) are passed through VERBATIM rather than lossily
            // round-tripped — otherwise --fuzz would replace those exact bytes
            // with U+FFFD and silently un-test the very vectors the byte pipeline
            // exists to send.
            let mut mutable: Vec<String> = Vec::new();
            let mut passthrough: Vec<Vec<u8>> = Vec::new();
            for p in std::mem::take(&mut payloads) {
                match String::from_utf8(p) {
                    Ok(s) => mutable.push(s),
                    Err(e) => passthrough.push(e.into_bytes()),
                }
            }
            payloads = mutator
                .mutate_payloads(&mutable)
                .into_iter()
                .map(String::into_bytes)
                .collect();
            payloads.extend(passthrough);
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
                // A returned result means the baseline was measured, so the
                // target answered at least one request.
                any_check_reachable = true;
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
                results.push(CheckResult::failed(check_name, e));
                pb.inc(1);
            }
        }
    }

    if parser_discrepancy_selected && !(cli.exit_first && found_vulnerability) {
        let current_check = checks_to_run.len() + 1;
        if !cli.verbose && !is_machine() {
            pb.set_message(format!(
                "[{}/{}] checking parser-discrepancy",
                current_check, total_checks
            ));
        }
        let result = run_parser_discrepancy_check_with_authority(
            ParserDiscrepancyParams {
                pb: &pb,
                host,
                port,
                path,
                method: &cli.method,
                use_tls,
                custom_headers: &cli.headers,
                cookies: &cookies,
                timeout: cli.timeout,
                verbose: network_verbose,
                max_payloads: cli.max_payloads,
                baseline_count: cli.baseline_count,
                delay: cli.delay,
                current_check,
                total_checks,
            },
            host_header,
        )
        .await;
        match result {
            Ok(result) => {
                any_check_reachable |= !result
                    .diagnostics
                    .iter()
                    .any(|d| d == "parser_baseline_no_response");
                found_vulnerability |= result.vulnerable;
                results.push(result);
            }
            Err(error) => {
                if !is_machine() {
                    log(
                        LogLevel::Warning,
                        &format!("parser-discrepancy check failed: {error}"),
                    );
                }
                results.push(CheckResult::failed("parser-discrepancy", error));
            }
        }
        pb.inc(1);
    }

    if cl0_selected && !(cli.exit_first && found_vulnerability) {
        let current_check = checks_to_run.len() + parser_discrepancy_selected as usize + 1;
        if !cli.verbose && !is_machine() {
            pb.set_message(format!(
                "[{}/{}] checking cl-0",
                current_check, total_checks
            ));
        }
        let result = run_cl0_check(ConnectionDesyncParams {
            pb: &pb,
            host,
            port,
            authority: host_header,
            path,
            method: &cli.method,
            custom_headers: &cli.headers,
            cookies: &cookies,
            timeout: cli.timeout,
            verbose: network_verbose,
            use_tls,
            max_payloads: cli.max_payloads,
            delay: cli.delay,
            current_check,
            total_checks,
        })
        .await;
        match result {
            Ok(result) => {
                any_check_reachable |= !result
                    .diagnostics
                    .iter()
                    .any(|d| d == "cl0_baseline_no_response");
                found_vulnerability |= result.vulnerable;
                results.push(result);
            }
            Err(error) => {
                if !is_machine() {
                    log(LogLevel::Warning, &format!("cl-0 check failed: {error}"));
                }
                results.push(CheckResult::failed("cl-0", error));
            }
        }
        pb.inc(1);
    }

    if zero_cl_selected && !(cli.exit_first && found_vulnerability) {
        let current_check =
            checks_to_run.len() + parser_discrepancy_selected as usize + cl0_selected as usize + 1;
        if !cli.verbose && !is_machine() {
            pb.set_message(format!(
                "[{}/{}] checking 0-cl",
                current_check, total_checks
            ));
        }
        let result = run_zero_cl_check(ConnectionDesyncParams {
            pb: &pb,
            host,
            port,
            authority: host_header,
            path,
            method: &cli.method,
            custom_headers: &cli.headers,
            cookies: &cookies,
            timeout: cli.timeout,
            verbose: network_verbose,
            use_tls,
            max_payloads: cli.max_payloads,
            delay: cli.delay,
            current_check,
            total_checks,
        })
        .await;
        match result {
            Ok(result) => {
                any_check_reachable |= !result
                    .diagnostics
                    .iter()
                    .any(|d| d == "zero_cl_baseline_no_response");
                found_vulnerability |= result.vulnerable;
                results.push(result);
            }
            Err(error) => {
                if !is_machine() {
                    log(LogLevel::Warning, &format!("0-cl check failed: {error}"));
                }
                results.push(CheckResult::failed("0-cl", error));
            }
        }
        pb.inc(1);
    }

    // Real HTTP/2 downgrade smuggling (H2.CL / H2.TE) over ALPN h2. Runs after
    // the HTTP/1.1 checks because it uses a genuine HTTP/2 client rather than a
    // payload string.
    if h2_downgrade_selected && !(cli.exit_first && found_vulnerability) {
        if !cli.verbose && !is_machine() {
            pb.set_message(format!(
                "[{}/{}] checking h2-downgrade",
                checks_to_run.len()
                    + parser_discrepancy_selected as usize
                    + cl0_selected as usize
                    + zero_cl_selected as usize
                    + 1,
                total_checks
            ));
        }
        let result = smugglex::http2::run_h2_downgrade_check(smugglex::http2::H2DowngradeParams {
            host,
            port,
            authority: host_header,
            path,
            method: &cli.method,
            custom_headers: &cli.headers,
            cookies: &cookies,
            timeout: cli.timeout,
            verbose: network_verbose,
        })
        .await;
        found_vulnerability |= result.vulnerable;
        // The h2 check flags a failed handshake with this diagnostic; anything
        // else means we spoke HTTP/2 to the target, i.e. it was reachable.
        if !result
            .diagnostics
            .iter()
            .any(|d| d == "h2_baseline_no_response")
        {
            any_check_reachable = true;
        }
        results.push(result);
        pb.inc(1);
    }

    // If the requested checks resolved to nothing runnable for this target, the
    // scan tested nothing — it must NOT be reported as a clean exit-0 result. The
    // canonical trigger is `--checks h2-downgrade` against an http:// target: the
    // name is valid (so the up-front validation passes) but h2-downgrade needs
    // ALPN h2 over TLS, leaving zero runnable checks. Surfacing it as an error
    // makes the JSON output and exit code distinguish "0 checks run" from "clean".
    let no_runnable_checks = total_checks == 0;
    if no_runnable_checks && !is_machine() {
        log(
            LogLevel::Warning,
            &format!(
                "{display_target}: no runnable checks for this target (e.g. h2-downgrade requires an https target); nothing was scanned"
            ),
        );
    }

    // If checks were attempted but none reached the target, it is unreachable
    // (host down, connection refused, TLS failure) rather than clean. Record it
    // so the scan is not misreported as a clean exit-0 result.
    let target_unreachable = total_checks > 0 && !any_check_reachable;
    if target_unreachable && !is_machine() {
        log(
            LogLevel::Warning,
            &format!("{display_target} appears unreachable: every check failed to connect"),
        );
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
        // and do not depend on a prior detection, so they may run even when the
        // scan was quiet. Every case is classified so none is silently dropped.
        match decide_exploit_action(exploit_str, found_vulnerability, is_machine()) {
            ExploitAction::Run => {
                let exploit_params = ExploitParams {
                    exploit_str,
                    results: &results,
                    host,
                    authority: host_header,
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
            }
            ExploitAction::SkipMachineMode => log(
                LogLevel::Warning,
                "exploit requested in JSON mode; skipping (re-run without --json/-f json for exploit output)",
            ),
            ExploitAction::SkipNoDetection => log(
                LogLevel::Warning,
                "exploit requested but no vulnerabilities found to exploit",
            ),
        }
    }

    // File output (-o) is written once by the caller after every target has
    // been scanned, so multi-target plain-mode runs no longer overwrite each
    // other (each `scan_one_target` used to clobber the shared file with only
    // its own results). The caller has the full ScanResults via the outcome.

    let duration = start_time.elapsed();
    if !is_machine() {
        log(
            LogLevel::Info,
            &format!("scan completed in {:.3} seconds", duration.as_secs_f64()),
        );
    }

    // Build the structured result for the outcome (always produced, used for JSON batch or exit code).
    // An unreachable target carries an `error` so it is distinguishable from a
    // clean scan in both the JSON output and the process exit code, while still
    // preserving the per-check CHECK_FAILED diagnostics in `checks`.
    let scan_results = ScanResults {
        target: display_target.to_string(),
        method: cli.method.clone(),
        timestamp: chrono::Utc::now().to_rfc3339(),
        fingerprint: fingerprint_info,
        checks: results,
        error: if no_runnable_checks {
            Some(
                "no runnable checks for this target (e.g. h2-downgrade requires an https target); nothing was scanned"
                    .to_string(),
            )
        } else if target_unreachable {
            Some("target unreachable: every check failed to connect".to_string())
        } else {
            None
        },
    };

    ScanOutcome::Success {
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

                // Parse target ports, surfacing any invalid tokens instead of
                // silently dropping them (e.g. a typo'd `--exploit-ports 22,htt,80`).
                let (localhost_ports, invalid_ports) = parse_exploit_ports(params.ports_str);
                if !invalid_ports.is_empty() {
                    log(
                        LogLevel::Warning,
                        &format!(
                            "ignoring invalid --exploit-ports token(s): {} (must be 0-65535)",
                            invalid_ports.join(", ")
                        ),
                    );
                }

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
                match test_localhost_access_with_authority(&localhost_params, params.authority)
                    .await
                {
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
                match test_path_fuzz_with_authority(&path_fuzz_params, params.authority).await {
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
                    .map(interpret_line_escapes)
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
                match smugglex::exploit::test_smuggle_with_authority(
                    &smuggle_params,
                    params.authority,
                )
                .await
                {
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
                    .map(interpret_line_escapes)
                    .unwrap_or_else(|| {
                        format!("GET /admin HTTP/1.1\r\nHost: {}\r\n\r\n", params.authority)
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
                match smugglex::exploit::test_capture_with_authority(
                    &capture_params,
                    params.authority,
                )
                .await
                {
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
                match smugglex::exploit::test_reveal_with_authority(
                    &reveal_params,
                    params.authority,
                )
                .await
                {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn interpret_line_escapes_expands_crlf_before_lf() {
        // A literal \r\n becomes a real CRLF (not split into \r + LF), and a
        // bare \n becomes a lone LF.
        assert_eq!(
            interpret_line_escapes("GET / HTTP/1.1\\r\\nHost: x\\r\\n\\r\\n"),
            "GET / HTTP/1.1\r\nHost: x\r\n\r\n"
        );
        assert_eq!(interpret_line_escapes("a\\nb"), "a\nb");
        assert_eq!(interpret_line_escapes("no escapes"), "no escapes");
    }

    #[test]
    fn collect_url_lines_trims_and_drops_blanks() {
        let lines = vec![
            Ok("  http://a.example  ".to_string()),
            Ok("\thttp://b.example\t".to_string()),
            Ok("   ".to_string()), // whitespace-only → dropped
            Ok("".to_string()),    // empty → dropped
            Ok("http://c.example".to_string()),
        ];
        assert_eq!(
            collect_url_lines(lines.into_iter()).unwrap(),
            vec![
                "http://a.example".to_string(),
                "http://b.example".to_string(),
                "http://c.example".to_string(),
            ]
        );
    }

    fn scan_results_with_error(error: Option<&str>) -> ScanResults {
        ScanResults {
            target: "http://x".to_string(),
            method: "POST".to_string(),
            timestamp: "t".to_string(),
            fingerprint: None,
            checks: Vec::new(),
            error: error.map(|s| s.to_string()),
        }
    }

    #[test]
    fn parse_exploit_ports_separates_valid_and_invalid() {
        let (valid, invalid) = parse_exploit_ports("22, 80 ,http,443,99999,,8080");
        assert_eq!(valid, vec![22, 80, 443, 8080]);
        // "http" is non-numeric; "99999" overflows u16 — both reported, not dropped.
        assert_eq!(invalid, vec!["http".to_string(), "99999".to_string()]);
        // All-valid input yields no invalid tokens.
        assert_eq!(parse_exploit_ports("22,443").1, Vec::<String>::new());
        // Empty/whitespace input yields nothing at all.
        assert_eq!(parse_exploit_ports("  , ,").0, Vec::<u16>::new());
    }

    #[test]
    fn decide_exploit_action_covers_every_case() {
        use ExploitAction::*;
        // Plain mode: a detection runs the phase; a direct exploit runs even
        // without one; otherwise it's a no-detection skip.
        assert_eq!(decide_exploit_action("localhost-access", true, false), Run);
        assert_eq!(decide_exploit_action("reveal", false, false), Run);
        assert_eq!(decide_exploit_action("smuggle,capture", false, false), Run);
        assert_eq!(
            decide_exploit_action("localhost-access", false, false),
            SkipNoDetection
        );
        // JSON/machine mode always skips with a message — including the case that
        // previously fell through every branch: a direct exploit, no detection.
        assert_eq!(
            decide_exploit_action("reveal", false, true),
            SkipMachineMode
        );
        assert_eq!(
            decide_exploit_action("localhost-access", true, true),
            SkipMachineMode
        );
    }

    #[test]
    fn outcome_is_failure_classifies_unreachable_success_and_hard_failure() {
        // Hard failure → failure.
        assert!(outcome_is_failure(&ScanOutcome::Failure {
            target: "http://x".to_string(),
            error: "URL parse error".to_string(),
        }));
        // Success carrying an error (unreachable target) → failure (exit 2).
        assert!(outcome_is_failure(&ScanOutcome::Success {
            scan_results: scan_results_with_error(Some("target unreachable")),
            found_vulnerability: false,
        }));
        // Clean success → not a failure (exit 0).
        assert!(!outcome_is_failure(&ScanOutcome::Success {
            scan_results: scan_results_with_error(None),
            found_vulnerability: false,
        }));
        // Vulnerable success → not counted as a failure (exit 1 takes priority).
        assert!(!outcome_is_failure(&ScanOutcome::Success {
            scan_results: scan_results_with_error(None),
            found_vulnerability: true,
        }));
    }

    #[test]
    fn collect_url_lines_rejects_partial_batch_after_read_error() {
        let lines = vec![
            Ok("http://ok.example".to_string()),
            Err(io::Error::other("boom")),
            Ok("http://ok2.example".to_string()),
        ];
        assert!(collect_url_lines(lines.into_iter()).is_err());
    }
}
