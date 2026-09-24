//! Differential HTTP/1.x parser-discrepancy checks.
//!
//! The regular CL.TE/TE.CL checks are timing-oriented payload families. This
//! module adds a smaller, explicitly selected audit that compares a malformed
//! request with a framing-stripped control request and records structural
//! response differences (status/body/timeout). A timeout-backed, repeatable
//! difference is the only condition promoted to vulnerable=true; weaker
//! response differences remain in diagnostics for manual review.

use std::time::Duration;

use chrono::Utc;
use indicatif::ProgressBar;

use crate::error::{Result, SmugglexError};
use crate::http::send_request_bytes;
use crate::model::{CheckResult, Confidence};
use crate::payloads::{
    get_cl_edge_case_payloads, get_cl_te_payloads, get_te_cl_payloads, get_te_te_payloads,
};
use crate::scanner::{build_control_request, response_body_length};
use crate::utils::parse_status_code;

/// Keep the opt-in parser audit bounded even when the caller does not pass
/// --max-payloads. The full payload families are still available through the
/// dedicated checks.
const DEFAULT_CASE_LIMIT: usize = 8;
const SEEDS_PER_FAMILY: usize = 2;
const CONFIRMATION_RETRIES: usize = 2;
const MIN_BODY_DIFF: usize = 32;

/// Parameters for the parser discrepancy audit.
pub struct ParserDiscrepancyParams<'a> {
    pub pb: &'a ProgressBar,
    pub host: &'a str,
    pub port: u16,
    pub path: &'a str,
    pub method: &'a str,
    pub use_tls: bool,
    pub custom_headers: &'a [String],
    pub cookies: &'a [String],
    pub timeout: u64,
    pub verbose: bool,
    pub max_payloads: Option<usize>,
    pub baseline_count: usize,
    pub delay: u64,
    pub current_check: usize,
    pub total_checks: usize,
}

#[derive(Clone, Debug)]
struct ParserCase {
    name: String,
    /// Raw probe request bytes (may carry non-UTF-8 TE-obfuscation bytes).
    probe: Vec<u8>,
    /// Framing-stripped control request — always pure ASCII.
    control: String,
}

#[derive(Clone, Debug)]
struct Observation {
    status_line: String,
    status_code: Option<u16>,
    body_length: usize,
    duration: Duration,
    timed_out: bool,
    failed: bool,
}

impl Observation {
    fn responded(&self) -> bool {
        !self.timed_out && !self.failed && self.status_code.is_some()
    }

    fn gateway_timeout(&self) -> bool {
        matches!(self.status_code, Some(408 | 504))
    }
}

fn build_cases(
    path: &str,
    host: &str,
    method: &str,
    custom_headers: &[String],
    cookies: &[String],
    max_payloads: Option<usize>,
) -> Vec<ParserCase> {
    let limit = max_payloads.unwrap_or(DEFAULT_CASE_LIMIT);
    // The TE families already return raw bytes; cl-edge is pure ASCII, so convert
    // it to bytes for a uniform corpus.
    let families: [(&str, Vec<Vec<u8>>); 4] = [
        (
            "cl-te",
            get_cl_te_payloads(path, host, method, custom_headers, cookies),
        ),
        (
            "te-cl",
            get_te_cl_payloads(path, host, method, custom_headers, cookies),
        ),
        (
            "te-te",
            get_te_te_payloads(path, host, method, custom_headers, cookies),
        ),
        (
            "cl-edge",
            get_cl_edge_case_payloads(path, host, method, custom_headers, cookies)
                .into_iter()
                .map(String::into_bytes)
                .collect(),
        ),
    ];
    let mut cases = Vec::new();
    let add_case = |cases: &mut Vec<ParserCase>, family: &str, index: usize, probe: Vec<u8>| {
        cases.push(ParserCase {
            name: format!("{family}[{index}]"),
            control: build_control_request(&probe),
            probe,
        });
    };

    // Keep the default audit representative: it should cover each framing
    // family instead of consuming the whole budget on CL.TE's first variants.
    for seed_index in 0..SEEDS_PER_FAMILY {
        for (family, payloads) in &families {
            if cases.len() >= limit {
                break;
            }
            if let Some(probe) = payloads.get(seed_index) {
                add_case(&mut cases, family, seed_index, probe.clone());
            }
        }
    }

    // A caller-provided larger --max-payloads budget continues through the
    // remaining corpus in family order.
    if cases.len() < limit {
        for (family, payloads) in &families {
            for (index, probe) in payloads.iter().enumerate().skip(SEEDS_PER_FAMILY) {
                if cases.len() >= limit {
                    break;
                }
                add_case(&mut cases, family, index, probe.clone());
            }
        }
    }

    cases
}

async fn observe(
    host: &str,
    port: u16,
    request: &[u8],
    timeout: u64,
    verbose: bool,
    use_tls: bool,
) -> Observation {
    match send_request_bytes(host, port, request, timeout, verbose, use_tls).await {
        Ok((response, duration)) => Observation {
            status_code: parse_status_code(response.lines().next().unwrap_or_default()),
            status_line: response
                .lines()
                .next()
                .unwrap_or("HTTP/1.x (malformed response)")
                .to_string(),
            body_length: response_body_length(&response),
            duration,
            timed_out: false,
            failed: false,
        },
        Err(SmugglexError::Timeout(_)) => Observation {
            status_line: "TIMEOUT".to_string(),
            status_code: None,
            body_length: 0,
            duration: Duration::from_secs(timeout),
            timed_out: true,
            failed: false,
        },
        Err(error) => Observation {
            status_line: format!("ERROR: {error}"),
            status_code: None,
            body_length: 0,
            duration: Duration::ZERO,
            timed_out: false,
            failed: true,
        },
    }
}

fn representative(samples: &[Observation]) -> Observation {
    let mut responders: Vec<Observation> = samples
        .iter()
        .filter(|sample| sample.responded())
        .cloned()
        .collect();

    if responders.is_empty() {
        return samples.first().cloned().unwrap_or_else(|| Observation {
            status_line: "NO_OBSERVATION".to_string(),
            status_code: None,
            body_length: 0,
            duration: Duration::ZERO,
            timed_out: false,
            failed: true,
        });
    }

    responders.sort_by_key(|sample| sample.duration);
    responders[responders.len() / 2].clone()
}

fn discrepancy_signals(probe: &Observation, control: &Observation) -> Vec<String> {
    let mut signals = Vec::new();

    if probe.timed_out != control.timed_out {
        signals.push("timeout_mismatch".to_string());
    }
    if probe.status_code != control.status_code
        && probe.status_code.is_some()
        && control.status_code.is_some()
    {
        signals.push(format!(
            "status_mismatch:{}:{}",
            control.status_code.unwrap_or_default(),
            probe.status_code.unwrap_or_default()
        ));
    }

    let body_delta = probe.body_length.abs_diff(control.body_length);
    if body_delta >= MIN_BODY_DIFF
        && (probe.body_length.max(control.body_length)
            >= probe.body_length.min(control.body_length).saturating_mul(2))
    {
        signals.push(format!(
            "body_length_mismatch:{}:{}",
            control.body_length, probe.body_length
        ));
    }

    signals
}

fn is_timeout_backed_candidate(probe: &Observation, control: &Observation) -> bool {
    // A 5xx control response is not a stable parser baseline: upstream
    // overload or a route-specific server error can make a probe's 408/504
    // look different without any framing discrepancy. Require a non-5xx
    // non-timeout control response before promoting the timeout difference.
    (probe.timed_out || probe.gateway_timeout())
        && control.responded()
        && control
            .status_code
            .is_some_and(|code| code < 500 && !matches!(code, 408 | 504))
}

async fn confirm_timeout_difference(
    case: &ParserCase,
    params: &ParserDiscrepancyParams<'_>,
) -> bool {
    for _ in 0..CONFIRMATION_RETRIES {
        let control = observe(
            params.host,
            params.port,
            case.control.as_bytes(),
            params.timeout,
            params.verbose,
            params.use_tls,
        )
        .await;
        let probe = observe(
            params.host,
            params.port,
            &case.probe,
            params.timeout,
            params.verbose,
            params.use_tls,
        )
        .await;
        if !is_timeout_backed_candidate(&probe, &control) {
            return false;
        }
    }
    true
}

/// Run the opt-in parser discrepancy audit.
pub async fn run_parser_discrepancy_check(
    params: ParserDiscrepancyParams<'_>,
) -> Result<CheckResult> {
    let authority = params.host.to_string();
    run_parser_discrepancy_check_with_authority(params, &authority).await
}

/// Run the parser discrepancy audit with a separate HTTP `Host` value. The
/// connection hostname can differ when scanning a virtual host by IP address.
pub async fn run_parser_discrepancy_check_with_authority(
    params: ParserDiscrepancyParams<'_>,
    authority: &str,
) -> Result<CheckResult> {
    let cases = build_cases(
        params.path,
        authority,
        params.method,
        params.custom_headers,
        params.cookies,
        params.max_payloads,
    );
    if cases.is_empty() {
        return Err(SmugglexError::InvalidInput(
            "parser-discrepancy produced no payload cases".to_string(),
        ));
    }

    let mut observed_differences = Vec::new();
    let mut saw_response = false;
    let mut normal_status = "no parser control response".to_string();
    let mut normal_duration_ms = 0;
    let repetitions = params.baseline_count.clamp(1, 3);

    for (index, case) in cases.iter().enumerate() {
        if params.delay > 0 && index > 0 {
            tokio::time::sleep(Duration::from_millis(params.delay)).await;
        }
        if !params.verbose {
            params.pb.set_message(format!(
                "[{}/{}] checking parser-discrepancy ({}/{})",
                params.current_check,
                params.total_checks,
                index + 1,
                cases.len()
            ));
        }

        let mut controls = Vec::with_capacity(repetitions);
        for _ in 0..repetitions {
            controls.push(
                observe(
                    params.host,
                    params.port,
                    case.control.as_bytes(),
                    params.timeout,
                    params.verbose,
                    params.use_tls,
                )
                .await,
            );
        }
        let control = representative(&controls);
        saw_response |= control.responded();
        if control.responded() && normal_duration_ms == 0 {
            normal_status = control.status_line.clone();
            normal_duration_ms = control.duration.as_millis() as u64;
        }
        let probe = observe(
            params.host,
            params.port,
            &case.probe,
            params.timeout,
            params.verbose,
            params.use_tls,
        )
        .await;

        let signals = discrepancy_signals(&probe, &control);
        if !signals.is_empty() {
            observed_differences.push(format!("{}:{}", case.name, signals.join("|")));
        }

        if is_timeout_backed_candidate(&probe, &control)
            && confirm_timeout_difference(case, &params).await
        {
            let mut detection_signals = vec![
                "parser_discrepancy_timeout".to_string(),
                format!("case:{}", case.name),
                "control_responds".to_string(),
                "confirmation_reproduced".to_string(),
            ];
            detection_signals.extend(signals);
            return Ok(CheckResult {
                check_type: "parser-discrepancy".to_string(),
                vulnerable: true,
                payload_index: Some(index),
                normal_status: control.status_line,
                attack_status: Some(probe.status_line),
                normal_duration_ms: control.duration.as_millis() as u64,
                attack_duration_ms: Some(probe.duration.as_millis() as u64),
                timestamp: Utc::now().to_rfc3339(),
                // Textual echo of the probe (a JSON string must be valid UTF-8);
                // a non-UTF-8 obfuscation byte renders lossily here.
                payload: Some(String::from_utf8_lossy(&case.probe).into_owned()),
                confidence: Some(Confidence::High),
                detection_signals,
                diagnostics: vec![format!("confirmation_retries:{}", CONFIRMATION_RETRIES)],
            });
        }
    }

    let mut diagnostics = Vec::new();
    if !saw_response {
        diagnostics.push("parser_baseline_no_response".to_string());
    }
    diagnostics.extend(
        observed_differences
            .into_iter()
            .take(16)
            .map(|difference| format!("observed_differential:{difference}")),
    );

    Ok(CheckResult {
        check_type: "parser-discrepancy".to_string(),
        vulnerable: false,
        payload_index: None,
        normal_status,
        attack_status: None,
        normal_duration_ms,
        attack_duration_ms: None,
        timestamp: Utc::now().to_rfc3339(),
        payload: None,
        confidence: None,
        detection_signals: Vec::new(),
        diagnostics,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn observation(status: Option<u16>, body_length: usize) -> Observation {
        Observation {
            status_line: status
                .map(|code| format!("HTTP/1.1 {code} Test"))
                .unwrap_or_else(|| "TIMEOUT".to_string()),
            status_code: status,
            body_length,
            duration: Duration::from_millis(10),
            timed_out: status.is_none(),
            failed: false,
        }
    }

    #[test]
    fn timeout_difference_is_a_candidate_only_when_control_responds() {
        assert!(is_timeout_backed_candidate(
            &observation(None, 0),
            &observation(Some(200), 12)
        ));
        assert!(!is_timeout_backed_candidate(
            &observation(None, 0),
            &observation(None, 0)
        ));
        assert!(!is_timeout_backed_candidate(
            &observation(None, 0),
            &observation(Some(500), 12)
        ));
        assert!(!is_timeout_backed_candidate(
            &observation(None, 0),
            &observation(Some(408), 12)
        ));
        assert!(!is_timeout_backed_candidate(
            &observation(None, 0),
            &observation(Some(504), 12)
        ));
    }

    #[test]
    fn structural_differences_are_recorded() {
        let signals =
            discrepancy_signals(&observation(Some(500), 100), &observation(Some(200), 10));
        assert!(signals.iter().any(|s| s.starts_with("status_mismatch:")));
        assert!(
            signals
                .iter()
                .any(|s| s.starts_with("body_length_mismatch:"))
        );
    }

    #[test]
    fn parser_case_has_a_framing_stripped_control() {
        let cases = build_cases("/", "example.test", "POST", &[], &[], Some(1));
        assert_eq!(cases.len(), 1);
        assert!(!cases[0].probe.is_empty());
        assert!(cases[0].control.contains("Content-Length:"));
        assert!(
            !cases[0]
                .control
                .to_ascii_lowercase()
                .contains("transfer-encoding:")
        );
    }

    #[test]
    fn default_corpus_covers_each_framing_family() {
        let cases = build_cases("/", "example.test", "POST", &[], &[], None);
        assert_eq!(cases.len(), DEFAULT_CASE_LIMIT);
        assert_eq!(cases[0].name, "cl-te[0]");
        assert_eq!(cases[1].name, "te-cl[0]");
        assert_eq!(cases[2].name, "te-te[0]");
        assert_eq!(cases[3].name, "cl-edge[0]");
    }
}
