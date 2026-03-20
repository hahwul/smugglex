use crate::error::{Result, SmugglexError};
use crate::http::send_request;
use crate::model::{CheckResult, Confidence};
use crate::utils::{export_payload, parse_status_code};
use chrono::Utc;
use colored::*;
use indicatif::ProgressBar;
use std::time::Duration;

/// Multiplier applied to baseline timing to determine anomaly threshold
pub const TIMING_MULTIPLIER: u128 = 3;
/// Minimum response delay in milliseconds to consider as suspicious
pub const MIN_DELAY_MS: u128 = 1000;
/// Default number of baseline requests for timing measurement
pub const DEFAULT_BASELINE_COUNT: usize = 3;
/// Number of retries used to confirm a detected vulnerability
pub const CONFIRMATION_RETRIES: usize = 2;

/// Parameters for running vulnerability checks
pub struct CheckParams<'a> {
    /// Progress bar for displaying scan status
    pub pb: &'a ProgressBar,
    /// Name of the check type (e.g., "CL.TE", "TE.CL")
    pub check_name: &'a str,
    /// Target hostname
    pub host: &'a str,
    /// Target port number
    pub port: u16,
    /// Request path on the target
    pub path: &'a str,
    /// List of raw HTTP attack payloads to test
    pub attack_requests: Vec<String>,
    /// Socket timeout in seconds
    pub timeout: u64,
    /// Whether to print verbose debug output
    pub verbose: bool,
    /// Whether to use TLS for connections
    pub use_tls: bool,
    /// Directory to export successful payloads to
    pub export_dir: Option<&'a str>,
    /// Index of the current check (for progress display)
    pub current_check: usize,
    /// Total number of checks to run (for progress display)
    pub total_checks: usize,
    /// Delay in milliseconds between requests
    pub delay: u64,
    /// Number of baseline requests for timing measurement
    pub baseline_count: usize,
}

struct VulnerabilityInfo {
    status: String,
    duration: Duration,
    is_connection_timeout: bool,
}

struct BaselineMeasurement {
    status: String,
    duration: Duration,
    observed_status_codes: Vec<Option<u16>>,
}

/// Measure baseline by sending normal requests and computing median timing.
/// Requests are sent concurrently for faster baseline establishment.
async fn measure_baseline(
    host: &str,
    port: u16,
    path: &str,
    timeout: u64,
    verbose: bool,
    use_tls: bool,
    baseline_count: usize,
) -> Result<BaselineMeasurement> {
    let normal_request = format!(
        "GET {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
        path, host
    );

    // Send baseline requests concurrently
    let mut futures = Vec::with_capacity(baseline_count);
    for _ in 0..baseline_count {
        futures.push(send_request(
            host,
            port,
            &normal_request,
            timeout,
            verbose,
            use_tls,
        ));
    }

    let results = futures::future::join_all(futures).await;

    let mut durations = Vec::with_capacity(baseline_count);
    let mut observed_status_codes = Vec::with_capacity(baseline_count);
    let mut last_status = String::new();

    for result in results {
        let (response, duration) = result?;
        let status_line = response.lines().next().unwrap_or("");
        let code = parse_status_code(status_line);
        observed_status_codes.push(code);
        durations.push(duration);
        last_status = status_line.to_string();
    }

    // Use median duration as the baseline
    durations.sort();
    let median_duration = durations[durations.len() / 2];

    Ok(BaselineMeasurement {
        status: last_status,
        duration: median_duration,
        observed_status_codes,
    })
}

struct PayloadCheckParams<'a> {
    host: &'a str,
    port: u16,
    attack_request: &'a str,
    timeout: u64,
    verbose: bool,
    use_tls: bool,
    timing_threshold: u128,
    baseline_status_codes: &'a [Option<u16>],
}

async fn check_single_payload(
    params: &PayloadCheckParams<'_>,
) -> Result<Option<VulnerabilityInfo>> {
    match send_request(
        params.host,
        params.port,
        params.attack_request,
        params.timeout,
        params.verbose,
        params.use_tls,
    )
    .await
    {
        Ok((attack_response, attack_duration)) => {
            let attack_status_line = attack_response.lines().next().unwrap_or("");
            let attack_millis = attack_duration.as_millis();

            let status_code = parse_status_code(attack_status_line);

            // Only treat 408/504 as smuggling signal if baseline didn't also produce them
            let baseline_has_timeout = params
                .baseline_status_codes
                .iter()
                .any(|c| matches!(c, Some(408) | Some(504)));
            let is_timeout_error =
                matches!(status_code, Some(408) | Some(504)) && !baseline_has_timeout;
            let is_delayed =
                attack_millis > params.timing_threshold && attack_millis > MIN_DELAY_MS;

            if is_timeout_error || is_delayed {
                Ok(Some(VulnerabilityInfo {
                    status: attack_status_line.to_string(),
                    duration: attack_duration,
                    is_connection_timeout: false,
                }))
            } else {
                Ok(None)
            }
        }
        Err(e) => {
            if matches!(e, SmugglexError::Timeout(_)) {
                Ok(Some(VulnerabilityInfo {
                    status: "Connection Timeout".to_string(),
                    duration: Duration::from_secs(params.timeout),
                    is_connection_timeout: true,
                }))
            } else {
                Err(e)
            }
        }
    }
}

/// Confirm a detected vulnerability by retrying CONFIRMATION_RETRIES times
async fn confirm_vulnerability(
    params: &PayloadCheckParams<'_>,
    is_connection_timeout: bool,
) -> bool {
    let mut confirmed_count = 0;

    for _ in 0..CONFIRMATION_RETRIES {
        if let Ok(Some(_)) = check_single_payload(params).await {
            confirmed_count += 1;
        }
    }

    if is_connection_timeout {
        // Connection timeout signals require ALL retries to reproduce
        confirmed_count == CONFIRMATION_RETRIES
    } else {
        // Normal signals require at least half to reproduce
        confirmed_count >= CONFIRMATION_RETRIES.div_ceil(2)
    }
}

/// Compute confidence level based on the nature of the detection signals
fn compute_confidence(info: &VulnerabilityInfo, timing_threshold: u128) -> Confidence {
    if info.is_connection_timeout {
        return Confidence::Low;
    }

    let status_code = parse_status_code(&info.status);
    let is_timeout_status = matches!(status_code, Some(408) | Some(504));
    let attack_millis = info.duration.as_millis();
    let is_timing_anomaly = attack_millis > timing_threshold && attack_millis > MIN_DELAY_MS;
    let is_extreme_timing = timing_threshold > 0 && attack_millis > timing_threshold * 2;

    if (is_timeout_status && is_timing_anomaly) || is_extreme_timing {
        Confidence::High
    } else {
        Confidence::Medium
    }
}

/// Runs a set of attack requests for a given check type.
pub async fn run_checks_for_type(params: CheckParams<'_>) -> Result<CheckResult> {
    let total_requests = params.attack_requests.len();

    if !params.verbose {
        params.pb.set_message(format!(
            "[{}/{}] checking {} (0/{})",
            params.current_check, params.total_checks, params.check_name, total_requests
        ));
    }

    // Measure baseline with multiple requests
    let baseline = measure_baseline(
        params.host,
        params.port,
        params.path,
        params.timeout,
        params.verbose,
        params.use_tls,
        params.baseline_count,
    )
    .await?;
    let normal_status = baseline.status;
    let normal_duration = baseline.duration;

    let mut vulnerability_info = None;
    let timing_threshold = normal_duration.as_millis() * TIMING_MULTIPLIER;

    for (i, attack_request) in params.attack_requests.iter().enumerate() {
        if params.delay > 0 && i > 0 {
            tokio::time::sleep(Duration::from_millis(params.delay)).await;
        }

        if !params.verbose {
            let current = i + 1;
            let percentage = (current as u32 * 100) / total_requests as u32;
            params.pb.set_message(format!(
                "[{}/{}] checking {} ({}/{} - {}%)",
                params.current_check,
                params.total_checks,
                params.check_name,
                current,
                total_requests,
                percentage
            ));
        }

        let payload_params = PayloadCheckParams {
            host: params.host,
            port: params.port,
            attack_request,
            timeout: params.timeout,
            verbose: params.verbose,
            use_tls: params.use_tls,
            timing_threshold,
            baseline_status_codes: &baseline.observed_status_codes,
        };

        match check_single_payload(&payload_params).await {
            Ok(Some(info)) => {
                // Confirm the vulnerability with retries
                let confirmed =
                    confirm_vulnerability(&payload_params, info.is_connection_timeout).await;

                if confirmed {
                    vulnerability_info = Some((i, attack_request.clone(), info));
                    break;
                }
            }
            Ok(None) => { /* Not vulnerable with this payload, continue */ }
            Err(e) => {
                if params.verbose {
                    println!(
                        "\n{} Error during {} attack request (payload {}): {}",
                        "[!]".yellow(),
                        params.check_name,
                        i,
                        e
                    );
                }
            }
        }
    }

    let (
        vulnerable,
        result_payload_index,
        result_payload,
        result_attack_status,
        last_attack_duration,
        confidence,
    ) = if let Some((i, payload, info)) = vulnerability_info {
        let conf = compute_confidence(&info, timing_threshold);
        (
            true,
            Some(i),
            Some(payload),
            Some(info.status),
            Some(info.duration),
            Some(conf),
        )
    } else {
        (false, None, None, None, None, None)
    };

    if vulnerable
        && let (Some(export_dir), Some(payload_index), Some(payload)) =
            (params.export_dir, result_payload_index, &result_payload)
        && let Err(e) = export_payload(
            export_dir,
            params.host,
            params.check_name,
            payload_index,
            payload,
            params.use_tls,
        )
        && params.verbose
    {
        println!("  {} Failed to export payload: {}", "[!]".yellow(), e);
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
        payload: result_payload,
        confidence,
    })
}
