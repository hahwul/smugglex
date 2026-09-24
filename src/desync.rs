//! Same-connection desynchronization probes.
//!
//! The payload-string checks in `scanner` are intentionally optimized for
//! timing anomalies on independent connections.  CL.0 is different: the
//! useful signal is a response arriving at the wrong position in a
//! *persistent* request/response queue.  This module keeps that probe
//! separate so it can compare a normal pipeline with a framing-stripped
//! control and require the response shift to reproduce.

use crate::error::Result;
use crate::http::{
    ExpectContinueParams, ExpectContinueResult, expect_continue_sequence, pipeline_requests,
    send_request,
};
use crate::model::{CheckResult, Confidence};
use crate::payloads::{format_cookies, format_custom_headers};
use crate::scanner::response_body_length;
use crate::utils::parse_status_code;
use chrono::Utc;
use indicatif::ProgressBar;
use std::time::{Duration, Instant};

/// Number of repeated control/attack sequences required after the first
/// candidate.  A one-off shifted response is too easy to produce with a
/// flaky keep-alive connection or an ordinary pipelining implementation.
const CONFIRMATION_RUNS: usize = 2;

/// Body-size ratio below which two otherwise same-status responses are treated
/// as structurally different.  This mirrors the conservative threshold used
/// by the timing scanner without importing its private response helpers.
const BODY_DIVERGENCE_PCT: usize = 75;

/// Minimum body size before a size ratio is considered meaningful.
const BODY_DIVERGENCE_MIN_BYTES: usize = 32;

/// Wait for an early response after sending an Expect header, while leaving
/// enough of the caller's timeout for the body and follow-up exchange.
const ZERO_CL_EARLY_WAIT_MS: u64 = 500;

/// Parameters for the opt-in same-connection CL.0 check.
pub struct ConnectionDesyncParams<'a> {
    /// Progress bar for scan status.
    pub pb: &'a ProgressBar,
    /// Target hostname used for the TCP/TLS connection.
    pub host: &'a str,
    /// Target port.
    pub port: u16,
    /// Host/authority value placed in generated requests.
    pub authority: &'a str,
    /// Request path used by the normal follow-up request.
    pub path: &'a str,
    /// Method used by the setup request.
    pub method: &'a str,
    /// User-supplied headers copied into all requests.
    pub custom_headers: &'a [String],
    /// Cookies copied into all requests.
    pub cookies: &'a [String],
    /// Socket timeout in seconds.
    pub timeout: u64,
    /// Whether raw requests/responses should be printed.
    pub verbose: bool,
    /// Whether to use TLS.
    pub use_tls: bool,
    /// Limit the number of CL.0 cases.  The default corpus is intentionally
    /// small; this option is still honoured for consistent CLI behavior.
    pub max_payloads: Option<usize>,
    /// Delay between repeated connection sequences, in milliseconds.
    pub delay: u64,
    /// Current check number for progress output.
    pub current_check: usize,
    /// Total check count for progress output.
    pub total_checks: usize,
}

#[derive(Debug, Clone)]
struct Cl0Case {
    name: &'static str,
    setup_request: String,
    control_request: String,
    followup_request: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ResponseObservation {
    status_line: String,
    status_code: Option<u16>,
    body_length: usize,
}

#[derive(Debug, Default)]
struct SequenceObservation {
    responses: Vec<ResponseObservation>,
    duration: Duration,
}

#[derive(Debug, Clone)]
struct ZeroClCase {
    name: &'static str,
    attack_headers: String,
    control_headers: String,
    attack_body: String,
    control_body: String,
    followup_request: String,
}

/// Run a conservative, opt-in CL.0 response-queue probe.
pub async fn run_cl0_check(params: ConnectionDesyncParams<'_>) -> Result<CheckResult> {
    params.pb.set_message(format!(
        "[{}/{}] checking cl-0",
        params.current_check, params.total_checks
    ));

    let cases = build_cases(&params);
    if cases.is_empty() {
        return Ok(clean_result(
            "cl0_no_probe_cases",
            "cl-0",
            "",
            None,
            0,
            0,
            Vec::new(),
        ));
    }

    // Establish the expected response for the follow-up on a fresh
    // connection.  A missing baseline makes a queue-shift finding impossible
    // to interpret, so it is surfaced distinctly to the caller.
    let (baseline_raw, baseline_duration) = send_request(
        params.host,
        params.port,
        &cases[0].followup_request,
        params.timeout,
        params.verbose,
        params.use_tls,
    )
    .await?;
    let baseline = observe_response(&baseline_raw);
    if baseline.status_line.is_empty() || baseline.status_code.is_none() {
        return Ok(clean_result(
            "cl0_baseline_no_response",
            "cl-0",
            &cases[0].setup_request,
            None,
            baseline_duration.as_millis() as u64,
            0,
            Vec::new(),
        ));
    }

    let mut last_diagnostics = Vec::new();
    for (case_index, case) in cases.iter().enumerate() {
        if !last_diagnostics.is_empty() && params.delay > 0 {
            tokio::time::sleep(Duration::from_millis(params.delay)).await;
        }

        let mut reproduced = true;
        let mut last_attack: Option<SequenceObservation> = None;
        let mut last_signals = Vec::new();

        // One initial attempt plus two confirmations.  Each attempt opens a
        // fresh TCP/TLS connection, while setup and follow-up share that one
        // connection.  Control runs are deliberately performed immediately
        // before their corresponding attack runs.
        for run_index in 0..=CONFIRMATION_RUNS {
            if run_index > 0 && params.delay > 0 {
                tokio::time::sleep(Duration::from_millis(params.delay)).await;
            }

            let control =
                match run_sequence(&params, &case.control_request, &case.followup_request).await {
                    Ok(observation) => observation,
                    Err(error) => {
                        reproduced = false;
                        last_diagnostics.push(format!(
                            "cl0_control_sequence_error:{}:{}",
                            case.name, error
                        ));
                        break;
                    }
                };
            let attack =
                match run_sequence(&params, &case.setup_request, &case.followup_request).await {
                    Ok(observation) => observation,
                    Err(error) => {
                        reproduced = false;
                        last_diagnostics
                            .push(format!("cl0_attack_sequence_error:{}:{}", case.name, error));
                        break;
                    }
                };

            let signals = queue_shift_signals(&baseline, &control, &attack);
            if signals.is_empty() {
                reproduced = false;
                last_diagnostics.push(format!(
                    "cl0_no_response_queue_shift:{}:run={}",
                    case.name, run_index
                ));
                break;
            }
            last_signals = signals;
            last_attack = Some(attack);
        }

        if reproduced {
            let attack = last_attack.expect("a reproduced case has an attack observation");
            let attack_response = attack
                .responses
                .get(1)
                .expect("a queue shift requires a second attack response");
            let mut detection_signals = vec![
                "same_connection_followup".to_string(),
                "cl0_response_queue_shift".to_string(),
                "cl0_control_matches_baseline".to_string(),
                format!("cl0_confirmation_runs={}", CONFIRMATION_RUNS),
            ];
            detection_signals.extend(last_signals);
            return Ok(CheckResult {
                check_type: "cl-0".to_string(),
                vulnerable: true,
                payload_index: Some(case_index),
                normal_status: baseline.status_line.clone(),
                attack_status: Some(attack_response.status_line.clone()),
                normal_duration_ms: baseline_duration.as_millis() as u64,
                attack_duration_ms: Some(attack.duration.as_millis() as u64),
                timestamp: Utc::now().to_rfc3339(),
                payload: Some(format!(
                    "{}\n\n-- follow-up request --\n{}",
                    case.setup_request, case.followup_request
                )),
                confidence: Some(Confidence::High),
                detection_signals,
                diagnostics: vec![format!(
                    "cl0_case={}; baseline_status={}; attack_response_count={}",
                    case.name,
                    baseline.status_line,
                    attack.responses.len()
                )],
            });
        }
    }

    if last_diagnostics.is_empty() {
        last_diagnostics.push("cl0_no_confirmed_response_queue_shift".to_string());
    }
    let mut result = clean_result(
        "cl0_no_confirmed_response_queue_shift",
        "cl-0",
        &cases[0].setup_request,
        None,
        baseline_duration.as_millis() as u64,
        0,
        last_diagnostics,
    );
    result.normal_status = baseline.status_line;
    Ok(result)
}

/// Run a conservative, opt-in 0.CL probe.
///
/// A plain timeout is deliberately not considered a finding: 0.CL commonly
/// produces only a deadlock.  This check requires a non-100 response before
/// the body, a control sequence that behaves normally, and a reproducible
/// response change after the body and follow-up are sent.
pub async fn run_zero_cl_check(params: ConnectionDesyncParams<'_>) -> Result<CheckResult> {
    params.pb.set_message(format!(
        "[{}/{}] checking 0-cl",
        params.current_check, params.total_checks
    ));

    let cases = build_zero_cl_cases(&params);
    if cases.is_empty() {
        return Ok(clean_result(
            "zero_cl_no_probe_cases",
            "0-cl",
            "",
            None,
            0,
            0,
            Vec::new(),
        ));
    }

    let (baseline_raw, baseline_duration) = send_request(
        params.host,
        params.port,
        &cases[0].followup_request,
        params.timeout,
        params.verbose,
        params.use_tls,
    )
    .await?;
    let baseline = observe_response(&baseline_raw);
    if baseline.status_line.is_empty() || baseline.status_code.is_none() {
        return Ok(clean_result(
            "zero_cl_baseline_no_response",
            "0-cl",
            &cases[0].attack_headers,
            None,
            baseline_duration.as_millis() as u64,
            0,
            Vec::new(),
        ));
    }

    let mut diagnostics = Vec::new();
    for (case_index, case) in cases.iter().enumerate() {
        let mut reproduced = true;
        let mut last_attack: Option<ExpectContinueResult> = None;
        let mut last_signals = Vec::new();

        for run_index in 0..=CONFIRMATION_RUNS {
            if run_index > 0 && params.delay > 0 {
                tokio::time::sleep(Duration::from_millis(params.delay)).await;
            }

            let control = match expect_continue_sequence(ExpectContinueParams {
                host: params.host,
                port: params.port,
                headers: &case.control_headers,
                body: &case.control_body,
                followup: &case.followup_request,
                early_wait: Duration::from_millis(ZERO_CL_EARLY_WAIT_MS),
                timeout: params.timeout,
                verbose: params.verbose,
                use_tls: params.use_tls,
            })
            .await
            {
                Ok(observation) => observation,
                Err(error) => {
                    reproduced = false;
                    diagnostics.push(format!(
                        "zero_cl_control_sequence_error:{}:{}",
                        case.name, error
                    ));
                    break;
                }
            };
            let attack = match expect_continue_sequence(ExpectContinueParams {
                host: params.host,
                port: params.port,
                headers: &case.attack_headers,
                body: &case.attack_body,
                followup: &case.followup_request,
                early_wait: Duration::from_millis(ZERO_CL_EARLY_WAIT_MS),
                timeout: params.timeout,
                verbose: params.verbose,
                use_tls: params.use_tls,
            })
            .await
            {
                Ok(observation) => observation,
                Err(error) => {
                    reproduced = false;
                    diagnostics.push(format!(
                        "zero_cl_attack_sequence_error:{}:{}",
                        case.name, error
                    ));
                    break;
                }
            };

            let signals = zero_cl_signals(&baseline, &control, &attack);
            if signals.is_empty() {
                reproduced = false;
                diagnostics.push(format!(
                    "zero_cl_no_confirmed_queue_shift:{}:run={}",
                    case.name, run_index
                ));
                break;
            }
            last_signals = signals;
            last_attack = Some(attack);
        }

        if reproduced {
            let attack = last_attack.expect("a reproduced case has an attack observation");
            let early_response = attack
                .early_response
                .as_deref()
                .map(observe_response)
                .expect("a 0.CL finding has an early response");
            let early_status_line = early_response.status_line.clone();
            let mut detection_signals = vec![
                "expect_early_response_before_body".to_string(),
                "zero_cl_response_queue_shift".to_string(),
                "zero_cl_control_matches_baseline".to_string(),
                format!("zero_cl_confirmation_runs={}", CONFIRMATION_RUNS),
            ];
            detection_signals.extend(last_signals);
            return Ok(CheckResult {
                check_type: "0-cl".to_string(),
                vulnerable: true,
                payload_index: Some(case_index),
                normal_status: baseline.status_line.clone(),
                attack_status: Some(early_status_line.clone()),
                normal_duration_ms: baseline_duration.as_millis() as u64,
                attack_duration_ms: Some(attack.duration.as_millis() as u64),
                timestamp: Utc::now().to_rfc3339(),
                payload: Some(format!(
                    "{}{}\n\n-- follow-up request --\n{}",
                    case.attack_headers, case.attack_body, case.followup_request
                )),
                confidence: Some(Confidence::High),
                detection_signals,
                diagnostics: vec![format!(
                    "zero_cl_case={}; early_response_status={}; post_body_response_count={}",
                    case.name,
                    early_status_line,
                    attack.post_body_responses.len()
                )],
            });
        }
    }

    if diagnostics.is_empty() {
        diagnostics.push("zero_cl_no_confirmed_response_queue_shift".to_string());
    }
    let mut result = clean_result(
        "zero_cl_no_confirmed_response_queue_shift",
        "0-cl",
        &cases[0].attack_headers,
        None,
        baseline_duration.as_millis() as u64,
        0,
        diagnostics,
    );
    result.normal_status = baseline.status_line;
    Ok(result)
}

fn clean_result(
    diagnostic: &str,
    check_type: &str,
    payload: &str,
    attack_status: Option<String>,
    normal_duration_ms: u64,
    attack_duration_ms: u64,
    mut diagnostics: Vec<String>,
) -> CheckResult {
    if diagnostics.is_empty() {
        diagnostics.push(diagnostic.to_string());
    } else if !diagnostics.iter().any(|entry| entry == diagnostic) {
        diagnostics.insert(0, diagnostic.to_string());
    }
    CheckResult {
        check_type: check_type.to_string(),
        vulnerable: false,
        payload_index: None,
        normal_status: "NO_CONFIRMED_DESYNC".to_string(),
        attack_status,
        normal_duration_ms,
        attack_duration_ms: (attack_duration_ms > 0).then_some(attack_duration_ms),
        timestamp: Utc::now().to_rfc3339(),
        payload: (!payload.is_empty()).then(|| payload.to_string()),
        confidence: None,
        detection_signals: Vec::new(),
        diagnostics,
    }
}

fn build_cases(params: &ConnectionDesyncParams<'_>) -> Vec<Cl0Case> {
    // Two distinct inner targets help avoid relying on one route's cache or
    // error page.  Both are intentionally harmless, non-existent paths.
    let inner_requests = [
        (
            "get-1",
            format!(
                "GET /__smugglex_cl0_probe?case=1 HTTP/1.1\r\nHost: {}\r\nX-Smugglex-CL0: 1\r\n\r\n",
                params.authority
            ),
        ),
        (
            "get-2",
            format!(
                "GET /__smugglex_cl0_probe?case=2 HTTP/1.1\r\nHost: {}\r\nX-Smugglex-CL0: 1\r\n\r\n",
                params.authority
            ),
        ),
    ];
    let max_cases = params.max_payloads.unwrap_or(inner_requests.len());
    inner_requests
        .into_iter()
        .take(max_cases)
        .map(|(name, inner_request)| {
            let setup_request = build_setup_request(
                params.method,
                params.path,
                params.authority,
                params.custom_headers,
                params.cookies,
                &inner_request,
            );
            let control_body = "A".repeat(inner_request.len());
            let control_request = build_setup_request(
                params.method,
                params.path,
                params.authority,
                params.custom_headers,
                params.cookies,
                &control_body,
            );
            let followup_request = build_followup_request(
                params.path,
                params.authority,
                params.custom_headers,
                params.cookies,
            );
            Cl0Case {
                name,
                setup_request,
                control_request,
                followup_request,
            }
        })
        .collect()
}

fn build_zero_cl_cases(params: &ConnectionDesyncParams<'_>) -> Vec<ZeroClCase> {
    let inner_requests = [
        (
            "standard-expect",
            "Content-Length: {length}\r\nExpect: 100-continue",
        ),
        (
            "space-before-cl-colon",
            "Content-Length : {length}\r\nExpect: 100-continue",
        ),
        (
            "obfuscated-expect",
            "Content-Length: {length}\r\nExpect: y 100-continue",
        ),
        (
            "tab-after-cl-colon",
            "Content-Length:\t{length}\r\nExpect: 100-continue",
        ),
    ];
    let max_cases = params.max_payloads.unwrap_or(inner_requests.len());
    inner_requests
        .into_iter()
        .take(max_cases)
        .map(|(name, framing_headers)| {
            let inner = format!(
                "GET /__smugglex_0cl_probe?case={} HTTP/1.1\r\nHost: {}\r\nX-Smugglex-0CL: 1\r\n\r\n",
                name, params.authority
            );
            let control_body = "A".repeat(inner.len());
            let attack_headers = build_expect_headers(
                params,
                framing_headers.replace("{length}", &inner.len().to_string()),
            );
            let control_headers = build_expect_headers(
                params,
                framing_headers.replace("{length}", &control_body.len().to_string()),
            );
            ZeroClCase {
                name,
                attack_headers,
                control_headers,
                attack_body: inner,
                control_body,
                followup_request: build_followup_request(
                    params.path,
                    params.authority,
                    params.custom_headers,
                    params.cookies,
                ),
            }
        })
        .collect()
}

fn build_expect_headers(params: &ConnectionDesyncParams<'_>, framing_headers: String) -> String {
    let custom = format_custom_headers(params.custom_headers);
    let cookie = format_cookies(params.cookies);
    format!(
        "{} {} HTTP/1.1\r\nHost: {}\r\n{}{}Connection: keep-alive\r\nContent-Type: application/x-www-form-urlencoded\r\n{}\r\n\r\n",
        params.method, params.path, params.authority, custom, cookie, framing_headers
    )
}

fn build_setup_request(
    method: &str,
    path: &str,
    authority: &str,
    custom_headers: &[String],
    cookies: &[String],
    body: &str,
) -> String {
    let custom = format_custom_headers(custom_headers);
    let cookie = format_cookies(cookies);
    format!(
        "{method} {path} HTTP/1.1\r\nHost: {authority}\r\n{custom}{cookie}Connection: keep-alive\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    )
}

fn build_followup_request(
    path: &str,
    authority: &str,
    custom_headers: &[String],
    cookies: &[String],
) -> String {
    let custom = format_custom_headers(custom_headers);
    let cookie = format_cookies(cookies);
    format!(
        "GET {path} HTTP/1.1\r\nHost: {authority}\r\n{custom}{cookie}Connection: close\r\nX-Smugglex-Followup: 1\r\n\r\n"
    )
}

async fn run_sequence(
    params: &ConnectionDesyncParams<'_>,
    setup_request: &str,
    followup_request: &str,
) -> Result<SequenceObservation> {
    let start = Instant::now();
    let requests = vec![setup_request.to_string(), followup_request.to_string()];
    let raw_responses = pipeline_requests(
        params.host,
        params.port,
        &requests,
        params.timeout,
        params.verbose,
        params.use_tls,
    )
    .await?;
    Ok(SequenceObservation {
        responses: raw_responses
            .iter()
            .map(|response| observe_response(response))
            .collect(),
        duration: start.elapsed(),
    })
}

fn observe_response(response: &str) -> ResponseObservation {
    let status_line = response.lines().next().unwrap_or_default().to_string();
    ResponseObservation {
        status_code: parse_status_code(&status_line),
        status_line,
        body_length: response_body_length(response),
    }
}

/// Return only concrete response-queue evidence.  The control's second
/// response must match a direct baseline first; otherwise a server-specific
/// pipeline behavior is not attributable to CL.0.
fn queue_shift_signals(
    baseline: &ResponseObservation,
    control: &SequenceObservation,
    attack: &SequenceObservation,
) -> Vec<String> {
    let Some(control_followup) = control.responses.get(1) else {
        return Vec::new();
    };
    let Some(attack_followup) = attack.responses.get(1) else {
        return Vec::new();
    };
    if !responses_equivalent(baseline, control_followup) {
        return Vec::new();
    }

    let mut signals = response_difference_signals(control_followup, attack_followup);
    if attack.responses.len() > control.responses.len() {
        signals.push("response_count_shift".to_string());
    }
    signals
}

fn responses_equivalent(left: &ResponseObservation, right: &ResponseObservation) -> bool {
    matches!((left.status_code, right.status_code), (Some(left), Some(right)) if left == right)
        && !body_structurally_diverges(left.body_length, right.body_length)
}

fn response_difference_signals(
    control: &ResponseObservation,
    attack: &ResponseObservation,
) -> Vec<String> {
    let mut signals = Vec::new();
    if let (Some(control_status), Some(attack_status)) = (control.status_code, attack.status_code)
        && control_status != attack_status
    {
        signals.push(format!(
            "followup_status_shift:{}->{attack_status:?}",
            control.status_line
        ));
    }
    if control.status_code.is_some()
        && attack.status_code.is_some()
        && body_structurally_diverges(control.body_length, attack.body_length)
    {
        signals.push(format!(
            "followup_body_shift:{}->{}",
            control.body_length, attack.body_length
        ));
    }
    signals
}

fn body_structurally_diverges(left: usize, right: usize) -> bool {
    if left < BODY_DIVERGENCE_MIN_BYTES || right < BODY_DIVERGENCE_MIN_BYTES || left == right {
        return false;
    }
    let smaller = left.min(right);
    let larger = left.max(right);
    smaller.saturating_mul(100) < larger.saturating_mul(BODY_DIVERGENCE_PCT)
}

fn zero_cl_signals(
    baseline: &ResponseObservation,
    control: &ExpectContinueResult,
    attack: &ExpectContinueResult,
) -> Vec<String> {
    let Some(early_raw) = attack.early_response.as_deref() else {
        return Vec::new();
    };
    if !attack.body_sent || attack.transport_error.is_some() {
        return Vec::new();
    }
    let early = observe_response(early_raw);
    if early.status_code.is_none() || early.status_code.is_some_and(|code| code < 200) {
        return Vec::new();
    }

    // A normal endpoint that rejects both the control and attack before the
    // body is sent is not evidence of 0.CL. Compare the early responses when
    // both paths produced one.
    if let Some(control_early_raw) = control.early_response.as_deref()
        && responses_equivalent(&early, &observe_response(control_early_raw))
    {
        return Vec::new();
    }

    let Some(control_followup) = control
        .post_body_responses
        .get(1)
        .map(|s| observe_response(s))
    else {
        return Vec::new();
    };
    if !responses_equivalent(baseline, &control_followup) {
        return Vec::new();
    }

    // Once the body is released, the hidden request should occupy a response
    // slot that a normal control sequence does not have. A deadlock with no
    // post-body response is intentionally rejected as insufficient evidence.
    let shifted = attack
        .post_body_responses
        .iter()
        .map(|response| observe_response(response))
        .find(|response| {
            response.status_code.is_some() && !responses_equivalent(baseline, response)
        });
    let Some(shifted) = shifted else {
        return Vec::new();
    };

    let mut signals = vec![
        "early_response_before_body".to_string(),
        "control_followup_matches_baseline".to_string(),
    ];
    let difference_signals = response_difference_signals(baseline, &shifted);
    if difference_signals.is_empty() {
        return Vec::new();
    }
    signals.extend(difference_signals);
    signals
}

#[cfg(test)]
mod tests {
    use super::*;

    fn params<'a>(
        pb: &'a ProgressBar,
        headers: &'a [String],
        cookies: &'a [String],
    ) -> ConnectionDesyncParams<'a> {
        ConnectionDesyncParams {
            pb,
            host: "127.0.0.1",
            port: 80,
            authority: "example.test",
            path: "/submit",
            method: "POST",
            custom_headers: headers,
            cookies,
            timeout: 1,
            verbose: false,
            use_tls: false,
            max_payloads: Some(1),
            delay: 0,
            current_check: 1,
            total_checks: 1,
        }
    }

    #[test]
    fn cl0_setup_uses_exact_body_length_and_preserves_context() {
        let headers = vec!["Authorization: Bearer test".to_string()];
        let cookies = vec!["sid=abc".to_string()];
        let pb = ProgressBar::hidden();
        let p = params(&pb, &headers, &cookies);
        let cases = build_cases(&p);
        let setup = &cases[0].setup_request;
        let body = setup.split_once("\r\n\r\n").unwrap().1;
        let advertised = setup
            .lines()
            .find_map(|line| line.strip_prefix("Content-Length: "))
            .unwrap()
            .parse::<usize>()
            .unwrap();
        assert_eq!(advertised, body.len());
        assert!(setup.contains("Authorization: Bearer test\r\n"));
        assert!(setup.contains("Cookie: sid=abc\r\n"));
        assert!(body.starts_with("GET /__smugglex_cl0_probe?case=1"));
        assert!(cases[0].control_request.ends_with(&"A".repeat(body.len())));
        assert!(cases[0].followup_request.contains("Connection: close\r\n"));
    }

    #[test]
    fn queue_shift_requires_control_to_match_direct_baseline() {
        let baseline = observe_response("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK");
        let control = SequenceObservation {
            responses: vec![
                observe_response("HTTP/1.1 200 OK\r\n\r\nsetup"),
                observe_response("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK"),
            ],
            duration: Duration::from_millis(1),
        };
        let attack = SequenceObservation {
            responses: vec![
                observe_response("HTTP/1.1 200 OK\r\n\r\nsetup"),
                observe_response("HTTP/1.1 404 Not Found\r\nContent-Length: 9\r\n\r\nnot found"),
            ],
            duration: Duration::from_millis(1),
        };
        let signals = queue_shift_signals(&baseline, &control, &attack);
        assert!(
            signals
                .iter()
                .any(|s| s.starts_with("followup_status_shift:"))
        );

        let bad_control = SequenceObservation {
            responses: vec![
                observe_response("HTTP/1.1 200 OK\r\n\r\nsetup"),
                observe_response("HTTP/1.1 503 Service Unavailable\r\n\r\n"),
            ],
            duration: Duration::from_millis(1),
        };
        assert!(queue_shift_signals(&baseline, &bad_control, &attack).is_empty());
    }

    #[test]
    fn body_shift_is_only_used_for_meaningful_sizes() {
        assert!(!body_structurally_diverges(4, 100));
        assert!(body_structurally_diverges(32, 100));
        assert!(!body_structurally_diverges(75, 100));
    }

    #[test]
    fn response_equivalence_requires_parseable_status_codes() {
        let valid = observe_response("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK");
        let malformed = observe_response("not an HTTP response\r\n\r\nlarge body");
        assert!(!responses_equivalent(&malformed, &malformed));
        assert!(!responses_equivalent(&valid, &malformed));
    }

    #[test]
    fn malformed_followup_does_not_create_a_queue_shift_signal() {
        let baseline = observe_response("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK");
        let control = SequenceObservation {
            responses: vec![
                observe_response("HTTP/1.1 200 OK\r\n\r\nsetup"),
                observe_response("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK"),
            ],
            duration: Duration::from_millis(1),
        };
        let attack = SequenceObservation {
            responses: vec![
                observe_response("HTTP/1.1 200 OK\r\n\r\nsetup"),
                observe_response("not an HTTP response\r\n\r\nlarge body"),
            ],
            duration: Duration::from_millis(1),
        };
        assert!(queue_shift_signals(&baseline, &control, &attack).is_empty());
    }

    #[test]
    fn zero_cl_cases_keep_control_and_attack_lengths_equal() {
        let headers = vec!["Authorization: Bearer test".to_string()];
        let cookies = Vec::new();
        let pb = ProgressBar::hidden();
        let mut p = params(&pb, &headers, &cookies);
        p.max_payloads = Some(4);
        let cases = build_zero_cl_cases(&p);
        assert_eq!(cases.len(), 4);
        for case in cases {
            let attack_len = case.attack_headers.lines().find_map(|line| {
                line.strip_prefix("Content-Length: ")
                    .or_else(|| line.strip_prefix("Content-Length : "))
                    .or_else(|| line.strip_prefix("Content-Length:\t"))
            });
            let control_len = case.control_headers.lines().find_map(|line| {
                line.strip_prefix("Content-Length: ")
                    .or_else(|| line.strip_prefix("Content-Length : "))
                    .or_else(|| line.strip_prefix("Content-Length:\t"))
            });
            assert_eq!(attack_len, control_len);
            assert_eq!(
                attack_len.unwrap().parse::<usize>().unwrap(),
                case.attack_body.len()
            );
            assert_eq!(case.control_body.len(), case.attack_body.len());
            assert!(case.attack_headers.contains("Expect:"));
        }
    }

    #[test]
    fn zero_cl_requires_early_response_and_post_body_shift() {
        let baseline = observe_response("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK");
        let control = ExpectContinueResult {
            interim_responses: vec!["HTTP/1.1 100 Continue\r\n\r\n".to_string()],
            post_body_responses: vec![
                "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n".to_string(),
                "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK".to_string(),
            ],
            body_sent: true,
            ..Default::default()
        };
        let attack = ExpectContinueResult {
            early_response: Some("HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n".to_string()),
            post_body_responses: vec![
                "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n".to_string(),
            ],
            body_sent: true,
            ..Default::default()
        };
        let signals = zero_cl_signals(&baseline, &control, &attack);
        assert!(signals.iter().any(|s| s == "early_response_before_body"));
        assert!(
            signals
                .iter()
                .any(|s| s.starts_with("followup_status_shift:"))
        );

        let ordinary_rejection = ExpectContinueResult {
            early_response: Some("HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n".to_string()),
            post_body_responses: attack.post_body_responses.clone(),
            body_sent: true,
            ..Default::default()
        };
        let same_control = ExpectContinueResult {
            early_response: ordinary_rejection.early_response.clone(),
            ..control
        };
        assert!(zero_cl_signals(&baseline, &same_control, &ordinary_rejection).is_empty());
    }

    #[test]
    fn zero_cl_ignores_malformed_post_body_response() {
        let baseline = observe_response("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK");
        let control = ExpectContinueResult {
            post_body_responses: vec![
                "HTTP/1.1 200 OK\r\n\r\nsetup".to_string(),
                "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK".to_string(),
            ],
            body_sent: true,
            ..Default::default()
        };
        let attack = ExpectContinueResult {
            early_response: Some("HTTP/1.1 404 Not Found\r\n\r\n".to_string()),
            post_body_responses: vec!["not an HTTP response\r\n\r\nlarge body".to_string()],
            body_sent: true,
            ..Default::default()
        };
        assert!(zero_cl_signals(&baseline, &control, &attack).is_empty());
    }
}
