use crate::error::{Result, SmugglexError};
use crate::http::send_request;
use crate::model::CheckResult;
use crate::utils::export_payload;
use chrono::Utc;
use colored::*;
use indicatif::ProgressBar;
use std::time::Duration;

// Detection thresholds
pub const TIMING_MULTIPLIER: u128 = 3; // Flag if response is 3x slower than baseline
pub const MIN_DELAY_MS: u128 = 1000; // Minimum delay to consider (1 second)

/// Parameters for running vulnerability checks
pub struct CheckParams<'a> {
    pub pb: &'a ProgressBar,
    pub check_name: &'a str,
    pub host: &'a str,
    pub port: u16,
    pub path: &'a str,
    pub attack_requests: Vec<String>,
    pub timeout: u64,
    pub verbose: bool,
    pub use_tls: bool,
    pub export_dir: Option<&'a str>,
    pub current_check: usize,
    pub total_checks: usize,
}

struct VulnerabilityInfo {
    status: String,
    duration: Duration,
}

async fn check_single_payload(
    host: &str,
    port: u16,
    attack_request: &str,
    timeout: u64,
    verbose: bool,
    use_tls: bool,
    timing_threshold: u128,
) -> Result<Option<VulnerabilityInfo>> {
    match send_request(host, port, attack_request, timeout, verbose, use_tls).await {
        Ok((attack_response, attack_duration)) => {
            let attack_status_line = attack_response.lines().next().unwrap_or("").to_string();
            let attack_millis = attack_duration.as_millis();

            let status_code = {
                let parts: Vec<&str> = attack_status_line.split_whitespace().collect();
                if parts.len() >= 2 && (parts[0].starts_with("HTTP/1.") || parts[0].starts_with("HTTP/2")) {
                    parts[1].parse::<u16>().ok()
                } else {
                    None
                }
            };

            let is_timeout_error = matches!(status_code, Some(408) | Some(504));
            let is_delayed = attack_millis > timing_threshold && attack_millis > MIN_DELAY_MS;

            if is_timeout_error || is_delayed {
                Ok(Some(VulnerabilityInfo {
                    status: attack_status_line,
                    duration: attack_duration,
                }))
            } else {
                Ok(None)
            }
        }
        Err(e) => {
            if matches!(e, SmugglexError::Timeout(_)) {
                Ok(Some(VulnerabilityInfo {
                    status: "Connection Timeout".to_string(),
                    duration: Duration::from_secs(timeout),
                }))
            } else {
                Err(e)
            }
        }
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

    let (normal_response, normal_duration) = send_request(
        params.host,
        params.port,
        &format!(
            "GET {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
            params.path, params.host
        ),
        params.timeout,
        params.verbose,
        params.use_tls,
    )
    .await?;
    let normal_status = normal_response.lines().next().unwrap_or("").to_string();

    let mut vulnerability_info = None;
    let timing_threshold = normal_duration.as_millis() * TIMING_MULTIPLIER;

    for (i, attack_request) in params.attack_requests.iter().enumerate() {
        if !params.verbose {
            let current = i + 1;
            let percentage = (current as f64 / total_requests as f64 * 100.0) as u32;
            params.pb.set_message(format!(
                "[{}/{}] checking {} ({}/{} - {}%)",
                params.current_check, params.total_checks, params.check_name, current, total_requests, percentage
            ));
        }

        match check_single_payload(
            params.host,
            params.port,
            attack_request,
            params.timeout,
            params.verbose,
            params.use_tls,
            timing_threshold,
        )
        .await
        {
            Ok(Some(info)) => {
                vulnerability_info = Some((i, attack_request.clone(), info));
                break;
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

    let (vulnerable, result_payload_index, result_payload, result_attack_status, last_attack_duration) =
        if let Some((i, payload, info)) = vulnerability_info {
            (true, Some(i), Some(payload), Some(info.status), Some(info.duration))
        } else {
            (false, None, None, None, None)
        };

    if vulnerable {
        if let (Some(export_dir), Some(payload_index), Some(payload)) =
            (params.export_dir, result_payload_index, &result_payload)
        {
            if let Err(e) =
                export_payload(export_dir, params.host, params.check_name, payload_index, payload, params.use_tls)
            {
                if params.verbose {
                    println!("  {} Failed to export payload: {}", "[!]".yellow(), e);
                }
            }
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
        payload: result_payload,
    })
}

