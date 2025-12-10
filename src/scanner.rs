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

    let mut vulnerable = false;
    let mut result_payload_index = None;
    let mut result_attack_status = None;
    let mut last_attack_duration = None;
    let mut result_payload = None;

    // Threshold for detecting timing-based smuggling
    let timing_threshold = normal_duration.as_millis() * TIMING_MULTIPLIER;

    for (i, attack_request) in params.attack_requests.iter().enumerate() {
        // Update progress message with current/total and percentage
        if !params.verbose {
            let current = i + 1;
            let percentage = (current as f64 / total_requests as f64 * 100.0) as u32;
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
        match send_request(
            params.host,
            params.port,
            attack_request,
            params.timeout,
            params.verbose,
            params.use_tls,
        )
        .await
        {
            Ok((attack_response, attack_duration)) => {
                last_attack_duration = Some(attack_duration);
                let attack_status_line = attack_response.lines().next().unwrap_or("");
                let attack_millis = attack_duration.as_millis();

                // Extract HTTP status code from status line (e.g., "HTTP/1.1 504 Gateway Timeout")
                // Validate proper HTTP response format before parsing
                let status_code = {
                    let parts: Vec<&str> = attack_status_line.split_whitespace().collect();
                    if parts.len() >= 2
                        && (parts[0].starts_with("HTTP/1.") || parts[0].starts_with("HTTP/2"))
                    {
                        parts[1].parse::<u16>().ok()
                    } else {
                        None
                    }
                };

                // Check for smuggling indicators:
                // 1. Timeout status codes (408 Request Timeout, 504 Gateway Timeout)
                // 2. Significantly delayed response (3x+ slower than baseline AND exceeds minimum threshold)
                let is_timeout_error = matches!(status_code, Some(408) | Some(504));
                let is_delayed = attack_millis > timing_threshold && attack_millis > MIN_DELAY_MS;

                if is_timeout_error || is_delayed {
                    vulnerable = true;
                    result_payload_index = Some(i);
                    result_attack_status = Some(attack_status_line.to_string());
                    result_payload = Some(attack_request.clone());

                    // Export payload if export_dir is specified
                    if let Some(export_dir) = params.export_dir {
                        match export_payload(
                            export_dir,
                            params.host,
                            params.check_name,
                            i,
                            attack_request,
                            params.use_tls,
                        ) {
                            Ok(_) => {
                                // Silently exported, will be shown in final results
                            }
                            Err(e) => {
                                if params.verbose {
                                    println!(
                                        "  {} Failed to export payload: {}",
                                        "[!] ".yellow(),
                                        e
                                    );
                                }
                            }
                        }
                    }
                    break;
                }
            }
            Err(e) => {
                // Check if error is a timeout error
                let is_timeout = matches!(e, SmugglexError::Timeout(_)) || {
                    // Check for timeout in error message
                    let error_str = e.to_string().to_lowercase();
                    error_str.contains("timed out") || error_str.contains("timeout")
                };

                if is_timeout {
                    vulnerable = true;
                    result_payload_index = Some(i);
                    result_attack_status = Some("Connection Timeout".to_string());
                    last_attack_duration = Some(Duration::from_secs(params.timeout));
                    result_payload = Some(attack_request.clone());

                    // Export payload if export_dir is specified
                    if let Some(export_dir) = params.export_dir {
                        match export_payload(
                            export_dir,
                            params.host,
                            params.check_name,
                            i,
                            attack_request,
                            params.use_tls,
                        ) {
                            Ok(_) => {
                                // Silently exported, will be shown in final results
                            }
                            Err(e) => {
                                if params.verbose {
                                    println!(
                                        "  {} Failed to export payload: {}",
                                        "[!] ".yellow(),
                                        e
                                    );
                                }
                            }
                        }
                    }
                    break;
                } else if params.verbose {
                    println!(
                        "\n{} Error during {} attack request (payload {}): {}",
                        "[!] ".yellow(),
                        params.check_name,
                        i,
                        e
                    );
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

