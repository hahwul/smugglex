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
/// Number of retries used to confirm a detected vulnerability.
/// A larger value enables strict-majority confirmation (>N/2) which reduces
/// false positives caused by single transient spikes.
pub const CONFIRMATION_RETRIES: usize = 3;
/// Absolute buffer in milliseconds added to the *maximum* baseline duration
/// when computing the timing threshold. Protects against noisy baselines where
/// natural per-request variance approaches the smuggling-induced delay.
pub const BASELINE_NOISE_BUFFER_MS: u128 = 500;
/// Ratio (control_ms * 100 / attack_ms) at or above which a control request is
/// considered "suspiciously similar" to the attack. When the smuggling-stripped
/// control takes nearly as long as the attack, the slowness was not caused by
/// the smuggling artifacts and the finding is rejected as a false positive.
pub const CONTROL_SIMILARITY_PCT: u128 = 60;
/// Number of differential control samples to send. The maximum observed control
/// duration is compared against the attack — using max (rather than median) is
/// conservative against control flukes that would otherwise let an FP slip
/// through.
pub const CONTROL_SAMPLES: usize = 2;
/// Body-size ratio (smaller_len * 100 / larger_len) at or below which the attack
/// and control responses are considered structurally different. A large body
/// divergence is a strong smuggling signal that overrides the timing/status
/// similarity FP rule.
pub const CONTROL_BODY_DIVERGENCE_PCT: u128 = 75;
/// Minimum body size (bytes) required on both sides before the body-divergence
/// rule kicks in. Avoids tripping the heuristic on near-empty responses where
/// a few bytes of difference are noise.
pub const CONTROL_BODY_MIN_BYTES: usize = 32;
/// Number of fresh follow-up GET probes sent after confirmation+control to
/// detect proxy↔backend desync that persists past the attack — the classic
/// "second-request" smuggling signature.
pub const FOLLOWUP_PROBE_COUNT: usize = 3;
/// When this many consecutive payloads in the same check all detect AND get
/// rejected by the control-FP rule, abandon the rest of the check. The
/// backend is producing the same shape-dependent anomaly for every payload
/// variant, so further iteration is wasted scan time and a strong signal
/// that the responses are not smuggling-induced. Recorded as a `diagnostics`
/// note on the CheckResult.
pub const CONSECUTIVE_FP_REJECTIONS_LIMIT: usize = 3;

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
    /// Number of baseline requests for timing measurement (values < 1 are clamped to 1)
    pub baseline_count: usize,
}

struct VulnerabilityInfo {
    status: String,
    status_code: Option<u16>,
    duration: Duration,
    /// Size of the response body in bytes (post-headers).
    /// Used to detect structural divergence between attack and control responses.
    body_length: usize,
    /// Fingerprint of response headers that frequently shift on desync
    /// (Content-Type, Server, Content-Length value). Compared between attack
    /// and control as an orthogonal divergence signal alongside body length.
    header_fingerprint: ResponseHeaderFingerprint,
    is_connection_timeout: bool,
}

/// Compact fingerprint of response headers used for divergence comparison.
/// Stores lowercased values for case-insensitive comparison.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct ResponseHeaderFingerprint {
    content_type: Option<String>,
    server: Option<String>,
    content_length: Option<String>,
}

impl ResponseHeaderFingerprint {
    /// Parse the header section of an HTTP response into a comparison fingerprint.
    fn from_response(response: &str) -> Self {
        let head = match response.split_once("\r\n\r\n") {
            Some((h, _)) => h,
            None => response,
        };
        let mut fp = ResponseHeaderFingerprint::default();
        for line in head.lines() {
            if let Some((name, value)) = line.split_once(':') {
                let name = name.trim();
                // Only allocate the lowercased value for the three headers we
                // track, instead of lowercasing every header's name and value.
                if name.eq_ignore_ascii_case("content-type") {
                    fp.content_type = Some(value.trim().to_ascii_lowercase());
                } else if name.eq_ignore_ascii_case("server") {
                    fp.server = Some(value.trim().to_ascii_lowercase());
                } else if name.eq_ignore_ascii_case("content-length") {
                    fp.content_length = Some(value.trim().to_ascii_lowercase());
                }
            }
        }
        fp
    }

    /// Count of fields where attack and control disagree. A bare presence vs
    /// absence counts as a disagreement.
    fn divergence_count(&self, other: &Self) -> u32 {
        let mut diff = 0u32;
        if self.content_type != other.content_type {
            diff += 1;
        }
        if self.server != other.server {
            diff += 1;
        }
        if self.content_length != other.content_length {
            diff += 1;
        }
        diff
    }
}

/// Extract the response body length (everything after the headers terminator).
/// Returns 0 if the response is malformed or has no body section.
fn response_body_length(response: &str) -> usize {
    response
        .split_once("\r\n\r\n")
        .map(|(_, body)| body.len())
        .unwrap_or(0)
}

struct BaselineMeasurement {
    status: String,
    /// HTTP status code from the last baseline probe (parsed once for reuse).
    status_code: Option<u16>,
    /// Median baseline duration.
    duration: Duration,
    /// Maximum baseline duration. Used to derive a noise-aware timing threshold
    /// so that natural per-request variance does not trigger false positives.
    max_duration: Duration,
    /// Response body length from the last baseline probe. Used by follow-up
    /// probes to detect post-attack body divergence.
    body_length: usize,
    observed_status_codes: Vec<Option<u16>>,
}

/// True when the majority of baseline responses are gateway-timeout codes (408/504).
/// Used to suppress status-only smuggling signals on backends that naturally return those codes.
/// A single transient timeout in baseline does NOT suppress the signal, which reduces false negatives.
fn baseline_majority_timeout(baseline_status_codes: &[Option<u16>]) -> bool {
    if baseline_status_codes.is_empty() {
        return false;
    }
    let timeouts = baseline_status_codes
        .iter()
        .filter(|c| matches!(c, Some(408) | Some(504)))
        .count();
    timeouts * 2 > baseline_status_codes.len()
}

/// Median of a non-empty slice of durations. Mutates input by sorting.
fn median_duration(durations: &mut [Duration]) -> Duration {
    debug_assert!(!durations.is_empty(), "median of empty slice");
    durations.sort();
    durations[durations.len() / 2]
}

/// Extract the HTTP method (first whitespace-delimited token of the first line)
/// from a raw request payload. Returns uppercased method.
fn payload_method(payload: &str) -> String {
    payload
        .lines()
        .next()
        .and_then(|l| l.split_whitespace().next())
        .map(|m| m.to_ascii_uppercase())
        .unwrap_or_else(|| "GET".to_string())
}

/// Send `count` shape-matched baseline probes that mirror the attack method but
/// carry no smuggling artifacts (Content-Length: 0, empty body). Used to
/// augment the GET baseline so timing thresholds account for backend's natural
/// per-method latency overhead. Returns the durations observed; failures are
/// silently dropped (the augmentation is best-effort).
#[allow(clippy::too_many_arguments)]
async fn method_matched_baseline_durations(
    host: &str,
    port: u16,
    path: &str,
    method: &str,
    count: usize,
    timeout: u64,
    verbose: bool,
    use_tls: bool,
) -> Vec<Duration> {
    let probe = format!(
        "{} {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\nContent-Length: 0\r\n\r\n",
        method, path, host
    );
    let mut futures = Vec::with_capacity(count);
    for _ in 0..count {
        futures.push(send_request(host, port, &probe, timeout, verbose, use_tls));
    }
    futures::future::join_all(futures)
        .await
        .into_iter()
        .filter_map(|r| r.ok().map(|(_, d)| d))
        .collect()
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
    // Clamp to a minimum of 1 to avoid empty-slice panic and meaningless thresholds.
    let count = baseline_count.max(1);

    let normal_request = format!(
        "GET {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
        path, host
    );

    let mut futures = Vec::with_capacity(count);
    for _ in 0..count {
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
    aggregate_baseline(results)
}

/// Aggregate the concurrent baseline probe results into a [`BaselineMeasurement`].
///
/// Failed probes (connection reset, timeout, EOF on a flaky network) are
/// dropped rather than aborting the whole measurement — discarding the
/// surviving samples over a single transient failure would turn an otherwise
/// viable check into a false negative. Only when *every* probe failed is an
/// error returned, since there is then nothing to measure against. This mirrors
/// the best-effort behavior of `method_matched_baseline_durations`.
fn aggregate_baseline(results: Vec<Result<(String, Duration)>>) -> Result<BaselineMeasurement> {
    let mut durations = Vec::with_capacity(results.len());
    let mut observed_status_codes = Vec::with_capacity(results.len());
    let mut last_status = String::new();
    let mut last_body_length = 0usize;
    let mut last_error: Option<SmugglexError> = None;

    for result in results {
        match result {
            Ok((response, duration)) => {
                let status_line = response.lines().next().unwrap_or("");
                observed_status_codes.push(parse_status_code(status_line));
                durations.push(duration);
                last_status = status_line.to_string();
                last_body_length = response_body_length(&response);
            }
            Err(e) => last_error = Some(e),
        }
    }

    if durations.is_empty() {
        return Err(last_error.unwrap_or_else(|| {
            SmugglexError::Io("baseline measurement produced no samples".into())
        }));
    }

    let max_duration = durations.iter().copied().max().unwrap_or_default();
    let median = median_duration(&mut durations);
    let status_code = parse_status_code(&last_status);

    Ok(BaselineMeasurement {
        status: last_status,
        status_code,
        duration: median,
        max_duration,
        body_length: last_body_length,
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

            // Only treat 408/504 as a smuggling signal if the baseline did NOT
            // produce such codes for the majority of probes.
            let baseline_timeout_majority = baseline_majority_timeout(params.baseline_status_codes);
            let is_timeout_error =
                matches!(status_code, Some(408) | Some(504)) && !baseline_timeout_majority;
            let is_delayed =
                attack_millis > params.timing_threshold && attack_millis > MIN_DELAY_MS;

            if is_timeout_error || is_delayed {
                Ok(Some(VulnerabilityInfo {
                    status: attack_status_line.to_string(),
                    status_code,
                    duration: attack_duration,
                    body_length: response_body_length(&attack_response),
                    header_fingerprint: ResponseHeaderFingerprint::from_response(&attack_response),
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
                    status_code: None,
                    duration: Duration::from_secs(params.timeout),
                    body_length: 0,
                    header_fingerprint: ResponseHeaderFingerprint::default(),
                    is_connection_timeout: true,
                }))
            } else {
                Err(e)
            }
        }
    }
}

/// Outcome of vulnerability confirmation across retries.
struct ConfirmationResult {
    confirmed: bool,
    /// Attack durations from each successful confirmation retry.
    durations: Vec<Duration>,
}

/// Observation from a "control" request — a smuggling-stripped sibling of the
/// attack payload used to validate that the detected anomaly is caused by the
/// smuggling artifacts themselves, not by the backend's general behavior for
/// requests of this shape.
struct ControlObservation {
    duration: Duration,
    status_code: Option<u16>,
    body_length: usize,
    header_fingerprint: ResponseHeaderFingerprint,
    is_connection_timeout: bool,
}

/// True when a payload carries smuggling-specific markers that the control
/// comparison knows how to strip. Plain HTTP requests (no TE artifact) and
/// Upgrade/HTTP-2-shaped payloads are excluded because stripping wouldn't
/// produce a meaningful control.
fn payload_eligible_for_control(payload: &str) -> bool {
    let head_end = payload.find("\r\n\r\n").unwrap_or(payload.len());
    let head_lower = payload[..head_end].to_ascii_lowercase();

    // Skip Upgrade-based / HTTP/2-shaped payloads — stripping TE does not
    // disable the H2C/H2 smuggling vector, so a control would not be a
    // meaningful reference.
    if head_lower.contains("upgrade:") || head_lower.contains("http/2") {
        return false;
    }

    // Apply control only to payloads that actually carry TE-related artifacts.
    head_lower.contains("transfer-encoding")
        || head_lower.contains("transfer_encoding")
        || head_lower.contains("transfer encoding")
        || head_lower.contains("nsfer-encoding")
}

/// Maximum bytes of synthetic body padding emitted by the control request.
/// Caps the request size to avoid sending large payloads even if the attack
/// declared a huge Content-Length.
const CONTROL_BODY_MAX_BYTES: usize = 4096;

/// Build a "control" version of `payload` with smuggling artifacts removed.
///
/// Drops any Transfer-Encoding header (including common obfuscated variants)
/// and the original Content-Length / body, then re-emits a well-formed request
/// with a benign body whose size matches the original attack body length
/// (capped at `CONTROL_BODY_MAX_BYTES`). Matching the body size is important
/// for shape parity — some backends route requests through different code
/// paths based on body length, and a zero-length control would not reflect
/// that timing.
///
/// All other headers (Host, Cookie, custom headers, Connection, etc.) are
/// preserved so the backend processes a request shaped as closely as possible
/// to the attack minus the smuggling-specific bits.
fn build_control_request(payload: &str) -> String {
    let (head, original_body) = match payload.find("\r\n\r\n") {
        Some(idx) => (&payload[..idx], &payload[idx + 4..]),
        None => (payload, ""),
    };

    let mut kept: Vec<&str> = Vec::new();
    for (i, line) in head.lines().enumerate() {
        if i == 0 {
            kept.push(line);
            continue;
        }
        let header_name = line.split(':').next().unwrap_or("");
        let name_lower = header_name.to_ascii_lowercase();
        if name_lower.contains("encoding")
            || name_lower.contains("content-length")
            || name_lower.contains("content_length")
        {
            continue;
        }
        kept.push(line);
    }

    // Match the original body size (capped) with benign ASCII padding so the
    // backend takes the same shape-conditional code paths it would for the
    // attack, minus the smuggling tricks.
    let body_len = original_body.len().min(CONTROL_BODY_MAX_BYTES);
    let mut result = String::with_capacity(payload.len());
    for line in kept {
        result.push_str(line);
        result.push_str("\r\n");
    }
    result.push_str(&format!("Content-Length: {}\r\n\r\n", body_len));
    if body_len > 0 {
        result.extend(std::iter::repeat_n('x', body_len));
    }
    result
}

/// Send a single control request and observe its timing/status/body. Returns
/// `None` if the network layer errored in a way the caller cannot reason about.
async fn observe_control_once(
    params: &PayloadCheckParams<'_>,
    control_request: &str,
) -> Option<ControlObservation> {
    match send_request(
        params.host,
        params.port,
        control_request,
        params.timeout,
        params.verbose,
        params.use_tls,
    )
    .await
    {
        Ok((response, duration)) => {
            let status_line = response.lines().next().unwrap_or("");
            Some(ControlObservation {
                duration,
                status_code: parse_status_code(status_line),
                body_length: response_body_length(&response),
                header_fingerprint: ResponseHeaderFingerprint::from_response(&response),
                is_connection_timeout: false,
            })
        }
        Err(SmugglexError::Timeout(_)) => Some(ControlObservation {
            duration: Duration::from_secs(params.timeout),
            status_code: None,
            body_length: 0,
            header_fingerprint: ResponseHeaderFingerprint::default(),
            is_connection_timeout: true,
        }),
        Err(_) => None,
    }
}

/// Send `CONTROL_SAMPLES` control requests and aggregate them conservatively:
/// duration is the MAX (worst case favors FP rejection of borderline detections),
/// status_code/body_length is taken from the slowest sample, and connection
/// timeout is set if ANY sample timed out.
///
/// Multiple samples protect against single-control flukes (a transient fast
/// response that would otherwise let a real FP slip through) at the cost of one
/// extra request per confirmed vulnerability.
async fn observe_control(
    params: &PayloadCheckParams<'_>,
    control_request: &str,
) -> Option<ControlObservation> {
    let mut samples: Vec<ControlObservation> = Vec::with_capacity(CONTROL_SAMPLES);
    for _ in 0..CONTROL_SAMPLES {
        if let Some(obs) = observe_control_once(params, control_request).await {
            samples.push(obs);
        }
    }
    if samples.is_empty() {
        return None;
    }
    let worst_idx = samples
        .iter()
        .enumerate()
        .max_by_key(|(_, s)| s.duration)
        .map(|(i, _)| i)
        .unwrap_or(0);
    let any_timeout = samples.iter().any(|s| s.is_connection_timeout);
    let worst = &samples[worst_idx];
    Some(ControlObservation {
        duration: worst.duration,
        status_code: worst.status_code,
        body_length: worst.body_length,
        header_fingerprint: worst.header_fingerprint.clone(),
        is_connection_timeout: any_timeout,
    })
}

/// Aggregated observation from `FOLLOWUP_PROBE_COUNT` post-attack follow-up
/// GETs, used to detect persistent proxy↔backend desync that outlives the
/// attack request itself.
struct FollowupObservation {
    /// Number of follow-up probes whose response diverged from baseline (by
    /// status code or substantial body-length difference).
    diverging: usize,
    /// Total number of follow-up probes actually sent (failures excluded).
    total: usize,
    /// True when this observation came from the unconditional second-request
    /// desync probe (i.e., the attack itself carried no direct anomaly and the
    /// finding rests entirely on follow-up corruption). Used to emit the
    /// `second_request_desync` signal.
    second_request: bool,
}

impl FollowupObservation {
    fn has_divergence(&self) -> bool {
        self.diverging > 0
    }

    /// Whether the follow-up divergence is corroborated strongly enough to
    /// override a control-based false-positive verdict. A single flaky probe —
    /// one transient timeout or a lone status change — must NOT be enough, or a
    /// uniformly slow backend (exactly the population the control check exists
    /// to reject) gets promoted to a confirmed finding on one fluke. So the
    /// main path requires a *majority* of the probes to diverge. The
    /// unconditional second-request path already proves reproduction across two
    /// independent plant+probe sequences, so a single divergence counts there
    /// (it does not currently flow through the control FP check, but the guard
    /// keeps the contract correct if it ever does).
    fn has_corroborated_divergence(&self) -> bool {
        if self.second_request {
            self.diverging > 0
        } else {
            self.diverging * 2 > self.total
        }
    }
}

/// Send `FOLLOWUP_PROBE_COUNT` fresh-connection GET probes against the target
/// path and count how many returned a response that diverges from the baseline
/// (status code differs, or body length differs structurally per
/// `bodies_diverge`). Each probe uses `Connection: close` so the scanner does
/// not reuse the attack socket — divergence here therefore reflects state
/// shared between the proxy and the backend pool, the canonical desync
/// signature for HTTP request smuggling.
async fn observe_followup_divergence(
    params: &PayloadCheckParams<'_>,
    path: &str,
    baseline: &BaselineMeasurement,
) -> FollowupObservation {
    let probe = format!(
        "GET {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
        path, params.host
    );
    let mut diverging = 0usize;
    let mut total = 0usize;
    for _ in 0..FOLLOWUP_PROBE_COUNT {
        let res = send_request(
            params.host,
            params.port,
            &probe,
            params.timeout,
            params.verbose,
            params.use_tls,
        )
        .await;
        match res {
            Ok((response, _)) => {
                total += 1;
                let status_line = response.lines().next().unwrap_or("");
                let status_code = parse_status_code(status_line);
                let body_len = response_body_length(&response);
                // Use the structural status check (excludes flake-prone 5xx) so a
                // transient gateway error does not count as desync divergence,
                // matching `count_structural_followup_divergence`.
                let status_diverged = followup_status_diverged(status_code, baseline.status_code);
                let body_diverged = bodies_diverge(body_len, baseline.body_length);
                if status_diverged || body_diverged {
                    diverging += 1;
                }
            }
            // Network-level errors on a fresh follow-up connection can themselves
            // be a desync signal (backend tearing down poisoned connections),
            // but they're also noisy. Count them but do not over-weight.
            Err(SmugglexError::Timeout(_)) => {
                total += 1;
                diverging += 1;
            }
            Err(_) => {
                // Other connection errors aren't reliable signals — skip.
            }
        }
    }
    FollowupObservation {
        diverging,
        total,
        second_request: false,
    }
}

/// True when a follow-up probe status structurally diverges from the baseline:
/// it differs from the baseline status AND is not a 5xx gateway/server error.
/// 5xx responses (502/503/504) are flake-prone and already covered by the
/// timing/status confirmation path, so excluding them keeps the unconditional
/// second-request probe from firing on transient upstream errors.
fn followup_status_diverged(status_code: Option<u16>, baseline_status: Option<u16>) -> bool {
    match status_code {
        Some(c) if c < 500 => status_code != baseline_status,
        _ => false,
    }
}

/// Send `FOLLOWUP_PROBE_COUNT` fresh-connection GET probes and count how many
/// returned a response that *structurally* diverges from the baseline — a
/// non-5xx status change (per `followup_status_diverged`) or a body-length
/// divergence (per `bodies_diverge`). Stricter than `observe_followup_divergence`
/// because it backs the unconditional second-request probe, where there is no
/// prior anomaly to corroborate the finding.
async fn count_structural_followup_divergence(
    params: &PayloadCheckParams<'_>,
    path: &str,
    baseline: &BaselineMeasurement,
) -> usize {
    let probe = format!(
        "GET {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
        path, params.host
    );
    let mut diverging = 0usize;
    for _ in 0..FOLLOWUP_PROBE_COUNT {
        if let Ok((response, _)) = send_request(
            params.host,
            params.port,
            &probe,
            params.timeout,
            params.verbose,
            params.use_tls,
        )
        .await
        {
            let status_line = response.lines().next().unwrap_or("");
            let status_code = parse_status_code(status_line);
            // Skip 5xx responses entirely — gateway/server errors are
            // flake-prone (overload, transient upstream failures) and are
            // handled by the timing/status confirmation path, not the
            // second-request probe. This also prevents a small 5xx error-page
            // body from tripping the body-divergence check below.
            if matches!(status_code, Some(c) if c >= 500) {
                continue;
            }
            let body_len = response_body_length(&response);
            if followup_status_diverged(status_code, baseline.status_code)
                || bodies_diverge(body_len, baseline.body_length)
            {
                diverging += 1;
            }
        }
    }
    diverging
}

/// Unconditional second-request desync probe, run only when the main payload
/// loop found no direct anomaly. Some CL.TE desyncs return a perfectly normal
/// response to the smuggling request itself and only corrupt the *following*
/// request on the shared proxy↔backend connection (the classic "second-request"
/// smuggling signature). We plant the first TE-carrying payload, then send
/// fresh follow-up GETs and look for structural divergence from the baseline.
///
/// To suppress transient backend flakiness the divergence must reproduce across
/// two independent plant+probe sequences — a single corrupted follow-up is not
/// enough. Returns a `FollowupObservation` (with `second_request = true`) only
/// when both sequences observed divergence.
async fn probe_second_request_desync(
    params: &PayloadCheckParams<'_>,
    path: &str,
    baseline: &BaselineMeasurement,
) -> Option<FollowupObservation> {
    const PLANT_PROBE_SEQUENCES: usize = 2;
    let mut diverging_min = usize::MAX;
    for _ in 0..PLANT_PROBE_SEQUENCES {
        // Plant: send the smuggling payload to corrupt the shared upstream
        // connection. Its own response is irrelevant here — the main loop has
        // already established it carries no direct anomaly.
        let _ = send_request(
            params.host,
            params.port,
            params.attack_request,
            params.timeout,
            params.verbose,
            params.use_tls,
        )
        .await;
        let d = count_structural_followup_divergence(params, path, baseline).await;
        if d == 0 {
            // Not reproduced → transient backend behavior, not a desync.
            return None;
        }
        diverging_min = diverging_min.min(d);
    }
    Some(FollowupObservation {
        diverging: diverging_min,
        total: FOLLOWUP_PROBE_COUNT,
        second_request: true,
    })
}

/// True if attack and control responses have structurally different bodies
/// (the smaller body is less than `CONTROL_BODY_DIVERGENCE_PCT`% of the larger).
///
/// Requires the LARGER body to exceed `CONTROL_BODY_MIN_BYTES` so divergence
/// is only claimed when there is enough material on at least one side to be
/// confident the difference is structural — both sides being tiny (e.g., empty
/// or minimal error pages) carries too little signal.
fn bodies_diverge(attack_body: usize, control_body: usize) -> bool {
    let larger = attack_body.max(control_body);
    if larger < CONTROL_BODY_MIN_BYTES {
        return false;
    }
    let smaller = attack_body.min(control_body) as u128;
    let larger = larger as u128;
    smaller.saturating_mul(100) < larger.saturating_mul(CONTROL_BODY_DIVERGENCE_PCT)
}

/// Decide whether the control response is "suspiciously similar" to the attack
/// response, indicating the detected signal stems from the backend's natural
/// behavior for this request shape rather than from smuggling artifacts.
fn control_indicates_false_positive(
    attack: &VulnerabilityInfo,
    control: &ControlObservation,
    followup: Option<&FollowupObservation>,
) -> bool {
    // ESCAPE: post-attack follow-up GETs diverged from baseline → backend state
    // was perturbed by the attack and persisted into a subsequent request.
    // This is the canonical "second-request" smuggling signature and overrides
    // any timing/status FP rule — but only when *corroborated* (a majority of
    // probes diverged). A single flaky follow-up (one transient timeout or a
    // lone 5xx) must not override the control rejection, otherwise a uniformly
    // slow backend is promoted to a finding on one fluke.
    if followup.is_some_and(|f| f.has_corroborated_divergence()) {
        return false;
    }

    // ESCAPE: attack and control returned structurally different response
    // bodies → the smuggling artifacts changed how the backend interpreted the
    // request (the canonical desync signature). Keep the finding regardless of
    // timing/status similarity.
    if bodies_diverge(attack.body_length, control.body_length) {
        return false;
    }

    // ESCAPE: response header set diverges between attack and control. A change
    // in Content-Type, Server, or the Content-Length header value is a strong
    // signal that the backend interpreted the request differently — i.e. a
    // desync — even when body lengths happen to be similar.
    if attack
        .header_fingerprint
        .divergence_count(&control.header_fingerprint)
        >= 2
    {
        return false;
    }

    // Connection-level timeout on the control too → backend cannot handle the
    // request shape at all, irrespective of smuggling tricks.
    if attack.is_connection_timeout && control.is_connection_timeout {
        return true;
    }

    // Both attack and control returned a gateway-timeout status → the backend
    // returns 408/504 for this shape independent of smuggling artifacts.
    let attack_is_timeout_status = matches!(attack.status_code, Some(408) | Some(504));
    let control_is_timeout_status = matches!(control.status_code, Some(408) | Some(504));
    if attack_is_timeout_status && control_is_timeout_status {
        return true;
    }

    // Control duration is within CONTROL_SIMILARITY_PCT% of the attack duration
    // → the slowness is intrinsic to the request shape, not the smuggling.
    let attack_ms = attack.duration.as_millis();
    let control_ms = control.duration.as_millis();
    if attack_ms > 0
        && control_ms.saturating_mul(100) >= attack_ms.saturating_mul(CONTROL_SIMILARITY_PCT)
    {
        return true;
    }

    false
}

/// Confirm a detected vulnerability by retrying CONFIRMATION_RETRIES times.
/// - Connection-level timeouts: ALL retries must reproduce (strict; networks are noisy).
/// - Status-only (408/504 without timing anomaly): ALL retries must reproduce —
///   intermittent gateway-timeout responses are a common non-smuggling cause
///   and would otherwise pass strict-majority on a single fluke.
/// - Status+timing or timing-only signals: strict majority (>N/2) must reproduce.
async fn confirm_vulnerability(
    params: &PayloadCheckParams<'_>,
    initial: &VulnerabilityInfo,
) -> ConfirmationResult {
    let mut durations = Vec::with_capacity(CONFIRMATION_RETRIES);
    for _ in 0..CONFIRMATION_RETRIES {
        if let Ok(Some(info)) = check_single_payload(params).await {
            durations.push(info.duration);
        }
    }

    // "Status-only" means detection fired on the 408/504 status WITHOUT a timing
    // anomaly. A timing anomaly requires BOTH duration > timing_threshold AND
    // duration > MIN_DELAY_MS (see `is_delayed` in check_single_payload), so "no
    // timing anomaly" is the negation of that conjunction — not merely
    // `duration <= timing_threshold`. The old check missed the gray zone where
    // timing_threshold < duration <= MIN_DELAY_MS, wrongly applying lenient
    // strict-majority confirmation to what is really a status-only signal.
    let attack_millis = initial.duration.as_millis();
    let initial_has_timing_anomaly =
        attack_millis > params.timing_threshold && attack_millis > MIN_DELAY_MS;
    let initial_is_status_only = !initial.is_connection_timeout
        && matches!(initial.status_code, Some(408) | Some(504))
        && !initial_has_timing_anomaly;

    let confirmed = if initial.is_connection_timeout || initial_is_status_only {
        durations.len() == CONFIRMATION_RETRIES
    } else {
        durations.len() * 2 > CONFIRMATION_RETRIES
    };

    ConfirmationResult {
        confirmed,
        durations,
    }
}

/// True when the baseline shows enough natural variance (spread between max
/// and median exceeding `BASELINE_NOISE_BUFFER_MS`) that pure timing
/// detections become unreliable. Used to demote confidence — the finding
/// still stands but is reported as Low so users know to verify manually.
fn baseline_is_noisy(median: Duration, max: Duration) -> bool {
    max.as_millis() > median.as_millis() + BASELINE_NOISE_BUFFER_MS
}

/// Compute confidence level based on the nature of the detection signals.
///
/// `timing_threshold` is the per-target dynamic threshold; the absolute floor
/// (`MIN_DELAY_MS * 2`) prevents fast targets where any timing-detected attack
/// would trivially exceed `threshold * 2` from always reaching High confidence.
///
/// `baseline_noisy` reflects whether the baseline carries enough variance that
/// a pure-timing signal cannot be trusted at face value — such detections are
/// demoted to Low so the user knows to corroborate manually.
fn compute_confidence(
    info: &VulnerabilityInfo,
    timing_threshold: u128,
    baseline_noisy: bool,
) -> Confidence {
    if info.is_connection_timeout {
        return Confidence::Low;
    }

    let is_timeout_status = matches!(info.status_code, Some(408) | Some(504));
    let attack_millis = info.duration.as_millis();
    let is_timing_anomaly = attack_millis > timing_threshold && attack_millis > MIN_DELAY_MS;
    let is_extreme_timing = timing_threshold > 0
        && attack_millis > timing_threshold * 2
        && attack_millis > MIN_DELAY_MS * 2;

    // Demote timing-only detections from a noisy baseline to Low — the timing
    // delta isn't reliable evidence on its own.
    if baseline_noisy && !is_timeout_status && !is_extreme_timing {
        return Confidence::Low;
    }

    if (is_timeout_status && is_timing_anomaly) || is_extreme_timing {
        Confidence::High
    } else {
        Confidence::Medium
    }
}

/// Collect the discrete signals that contributed to detection, for transparency.
/// Returned as human-readable tags; ordering is stable across runs.
fn collect_detection_signals(
    info: &VulnerabilityInfo,
    normal_duration: Duration,
    timing_threshold: u128,
    baseline_noisy: bool,
    control: Option<&ControlObservation>,
    followup: Option<&FollowupObservation>,
) -> Vec<String> {
    let mut signals = Vec::new();
    if info.is_connection_timeout {
        signals.push("connection_timeout".to_string());
    }
    match info.status_code {
        Some(408) => signals.push("status_408".to_string()),
        Some(504) => signals.push("status_504".to_string()),
        _ => {}
    }
    let attack_ms = info.duration.as_millis();
    let normal_ms = normal_duration.as_millis();
    if attack_ms > timing_threshold && attack_ms > MIN_DELAY_MS {
        let ratio = if normal_ms > 0 {
            attack_ms as f64 / normal_ms as f64
        } else {
            attack_ms as f64 / 1.0
        };
        signals.push(format!("timing_anomaly:{:.1}x", ratio));
    }
    if timing_threshold > 0 && attack_ms > timing_threshold * 2 && attack_ms > MIN_DELAY_MS * 2 {
        signals.push("extreme_timing".to_string());
    }
    if baseline_noisy {
        signals.push("baseline_noisy".to_string());
    }
    if let Some(c) = control {
        if bodies_diverge(info.body_length, c.body_length) {
            signals.push("body_divergence_vs_control".to_string());
        }
        let header_diff = info
            .header_fingerprint
            .divergence_count(&c.header_fingerprint);
        if header_diff >= 2 {
            signals.push(format!("header_divergence_vs_control:{}", header_diff));
        }
    }
    if let Some(f) = followup {
        if f.has_divergence() {
            signals.push(format!("followup_divergence:{}/{}", f.diverging, f.total));
        }
        if f.second_request {
            signals.push("second_request_desync".to_string());
        }
    }
    signals
}

/// Build the final `CheckResult` from collected scan state.
#[allow(clippy::type_complexity)]
fn build_check_result(
    check_name: &str,
    normal_status: String,
    normal_duration: Duration,
    vulnerability: Option<(
        usize,
        String,
        VulnerabilityInfo,
        Option<ControlObservation>,
        Option<FollowupObservation>,
    )>,
    timing_threshold: u128,
    baseline_noisy: bool,
    diagnostics: Vec<String>,
) -> (CheckResult, Option<(usize, String)>) {
    if let Some((idx, payload, info, control, followup)) = vulnerability {
        let confidence = compute_confidence(&info, timing_threshold, baseline_noisy);
        let detection_signals = collect_detection_signals(
            &info,
            normal_duration,
            timing_threshold,
            baseline_noisy,
            control.as_ref(),
            followup.as_ref(),
        );
        let attack_status = info.status;
        let attack_duration_ms = info.duration.as_millis() as u64;
        let result = CheckResult {
            check_type: check_name.to_string(),
            vulnerable: true,
            payload_index: Some(idx),
            normal_status,
            attack_status: Some(attack_status),
            normal_duration_ms: normal_duration.as_millis() as u64,
            attack_duration_ms: Some(attack_duration_ms),
            timestamp: Utc::now().to_rfc3339(),
            payload: Some(payload.clone()),
            confidence: Some(confidence),
            detection_signals,
            diagnostics,
        };
        (result, Some((idx, payload)))
    } else {
        let result = CheckResult {
            check_type: check_name.to_string(),
            vulnerable: false,
            payload_index: None,
            normal_status,
            attack_status: None,
            normal_duration_ms: normal_duration.as_millis() as u64,
            attack_duration_ms: None,
            timestamp: Utc::now().to_rfc3339(),
            payload: None,
            confidence: None,
            detection_signals: Vec::new(),
            diagnostics,
        };
        (result, None)
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
    let normal_status = baseline.status.clone();
    let normal_duration = baseline.duration;
    // Noise-aware threshold: a slow attack must beat BOTH the relative
    // multiplier over the median AND the worst observed baseline plus a buffer.
    // This prevents a single slow baseline sample from inflating noise that
    // looks like an anomaly.
    // Augment the GET baseline with a small set of method-matched probes when
    // attacks use a different method. This corrects timing thresholds on
    // backends where POST handling is naturally slower than GET — a common
    // false-positive source where the GET baseline understates the per-request
    // floor for the actual attack shape.
    let attack_method = params
        .attack_requests
        .first()
        .map(|p| payload_method(p))
        .unwrap_or_else(|| "GET".to_string());
    let mut max_baseline = baseline.max_duration;
    let mut median_baseline = normal_duration;
    if attack_method != "GET" && !attack_method.is_empty() {
        let extra = method_matched_baseline_durations(
            params.host,
            params.port,
            params.path,
            &attack_method,
            params.baseline_count.max(1),
            params.timeout,
            params.verbose,
            params.use_tls,
        )
        .await;
        if !extra.is_empty() {
            if let Some(extra_max) = extra.iter().copied().max()
                && extra_max > max_baseline
            {
                max_baseline = extra_max;
            }
            let mut combined: Vec<Duration> = extra;
            combined.push(normal_duration);
            median_baseline = median_duration(&mut combined);
        }
    }

    let timing_threshold = std::cmp::max(
        median_baseline.as_millis() * TIMING_MULTIPLIER,
        max_baseline.as_millis() + BASELINE_NOISE_BUFFER_MS,
    );
    let baseline_noisy = baseline_is_noisy(median_baseline, max_baseline);

    #[allow(clippy::type_complexity)]
    let mut vulnerability_info: Option<(
        usize,
        String,
        VulnerabilityInfo,
        Option<ControlObservation>,
        Option<FollowupObservation>,
    )> = None;

    // Track consecutive control-FP rejections so we can abandon the check if
    // the backend produces the same shape-dependent anomaly for every
    // variant — that's a strong signal the responses are not smuggling.
    let mut consecutive_fp_rejections: usize = 0;
    let mut early_termination: Option<String> = None;

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
            Ok(Some(mut info)) => {
                let confirmation = confirm_vulnerability(&payload_params, &info).await;
                if confirmation.confirmed {
                    // Use the median of (initial + retry) durations to dampen
                    // the influence of a single transient spike on confidence.
                    let mut all_durations = Vec::with_capacity(confirmation.durations.len() + 1);
                    all_durations.push(info.duration);
                    all_durations.extend(confirmation.durations);
                    info.duration = median_duration(&mut all_durations);

                    // Differential control check: send a smuggling-stripped
                    // sibling of the payload. Skipped for payloads where
                    // stripping isn't meaningful (H2C/H2 or non-TE payloads).
                    let mut control_observation: Option<ControlObservation> = None;
                    if payload_eligible_for_control(attack_request) {
                        let control_request = build_control_request(attack_request);
                        if let Some(control) =
                            observe_control(&payload_params, &control_request).await
                        {
                            control_observation = Some(control);
                        }
                    }

                    // Post-attack follow-up probes: detect proxy↔backend
                    // desync that persists past the attack. Strong escape
                    // signal — overrides the control FP rule.
                    let followup_observation = Some(
                        observe_followup_divergence(&payload_params, params.path, &baseline).await,
                    );

                    // FP rejection considers both control similarity AND the
                    // absence of follow-up divergence. If the follow-up
                    // diverged, the finding survives FP rejection.
                    if let Some(control) = control_observation.as_ref()
                        && control_indicates_false_positive(
                            &info,
                            control,
                            followup_observation.as_ref(),
                        )
                    {
                        if params.verbose {
                            println!(
                                "  {} {} payload #{} rejected as false positive (control matched attack: status={:?}, attack={}ms, control={}ms)",
                                "[*]".cyan(),
                                params.check_name,
                                i,
                                control.status_code,
                                info.duration.as_millis(),
                                control.duration.as_millis(),
                            );
                        }
                        consecutive_fp_rejections += 1;
                        if consecutive_fp_rejections >= CONSECUTIVE_FP_REJECTIONS_LIMIT {
                            early_termination = Some(format!(
                                "early_termination:consecutive_fp_rejections={}",
                                consecutive_fp_rejections
                            ));
                            if params.verbose {
                                println!(
                                    "  {} {} abandoning check after {} consecutive control-FP rejections",
                                    "[*]".cyan(),
                                    params.check_name,
                                    consecutive_fp_rejections,
                                );
                            }
                            break;
                        }
                        continue;
                    }

                    vulnerability_info = Some((
                        i,
                        attack_request.clone(),
                        info,
                        control_observation,
                        followup_observation,
                    ));
                    break;
                } else {
                    // Initial detection didn't confirm — payload was not a
                    // shape-dependent FP, so this run does not contribute to
                    // the consecutive-rejection streak.
                    consecutive_fp_rejections = 0;
                }
            }
            Ok(None) => {
                // No detection signal at all → reset the streak.
                consecutive_fp_rejections = 0;
            }
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

    // Second-request desync probe: only when the main loop found no direct
    // anomaly and did not early-terminate. Catches CL.TE desyncs whose attack
    // response is itself benign and only the FOLLOWING request on the shared
    // upstream connection is corrupted.
    if vulnerability_info.is_none()
        && early_termination.is_none()
        && let Some((idx, plant_payload)) = params
            .attack_requests
            .iter()
            .enumerate()
            .find(|(_, p)| payload_eligible_for_control(p))
    {
        let payload_params = PayloadCheckParams {
            host: params.host,
            port: params.port,
            attack_request: plant_payload,
            timeout: params.timeout,
            verbose: params.verbose,
            use_tls: params.use_tls,
            timing_threshold,
            baseline_status_codes: &baseline.observed_status_codes,
        };
        if let Some(followup) =
            probe_second_request_desync(&payload_params, params.path, &baseline).await
        {
            if params.verbose {
                println!(
                    "  {} {} second-request desync detected: {}/{} follow-up probes diverged from baseline",
                    "[+]".green(),
                    params.check_name,
                    followup.diverging,
                    followup.total,
                );
            }
            // The attack request itself carried no anomaly — synthesize a
            // benign VulnerabilityInfo so the finding is reported as a
            // medium-confidence second-request desync.
            let info = VulnerabilityInfo {
                status: normal_status.clone(),
                status_code: baseline.status_code,
                duration: normal_duration,
                body_length: baseline.body_length,
                header_fingerprint: ResponseHeaderFingerprint::default(),
                is_connection_timeout: false,
            };
            vulnerability_info = Some((idx, plant_payload.clone(), info, None, Some(followup)));
        }
    }

    let diagnostics: Vec<String> = early_termination.into_iter().collect();
    let (result, exported) = build_check_result(
        params.check_name,
        normal_status,
        normal_duration,
        vulnerability_info,
        timing_threshold,
        baseline_noisy,
        diagnostics,
    );

    if let (Some((payload_index, payload)), Some(export_dir)) = (exported, params.export_dir)
        && let Err(e) = export_payload(
            export_dir,
            params.host,
            params.check_name,
            payload_index,
            &payload,
            params.use_tls,
        )
        && params.verbose
    {
        println!("  {} Failed to export payload: {}", "[!]".yellow(), e);
    }

    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn baseline_majority_timeout_empty_is_false() {
        assert!(!baseline_majority_timeout(&[]));
    }

    #[test]
    fn baseline_majority_timeout_single_504_is_majority() {
        assert!(baseline_majority_timeout(&[Some(504)]));
    }

    #[test]
    fn baseline_majority_timeout_minority_not_flagged() {
        // 1 of 3 is NOT majority (used to be "any" → now requires majority)
        assert!(!baseline_majority_timeout(&[
            Some(504),
            Some(200),
            Some(200)
        ]));
    }

    #[test]
    fn baseline_majority_timeout_majority_flagged() {
        assert!(baseline_majority_timeout(&[
            Some(504),
            Some(504),
            Some(200)
        ]));
    }

    #[test]
    fn payload_eligible_skips_plain_request() {
        let p = "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
        assert!(!payload_eligible_for_control(p));
    }

    #[test]
    fn payload_eligible_for_te_payload() {
        let p = "POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\nContent-Length: 6\r\n\r\n0\r\n\r\nG";
        assert!(payload_eligible_for_control(p));
    }

    #[test]
    fn payload_eligible_skips_h2c_upgrade() {
        // H2C payload has TE-related body but the Upgrade header makes control
        // comparison meaningless (TE stripping doesn't disable H2C smuggling).
        let p = "POST / HTTP/1.1\r\nHost: x\r\nConnection: Upgrade\r\nUpgrade: h2c\r\nTransfer-Encoding: chunked\r\n\r\n";
        assert!(!payload_eligible_for_control(p));
    }

    #[test]
    fn build_control_strips_transfer_encoding() {
        // Original attack body "0\r\n\r\nG" is 6 bytes — control should match
        // that size with benign ASCII padding.
        let p = "POST /a HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\nContent-Length: 6\r\n\r\n0\r\n\r\nG";
        let control = build_control_request(p);
        let lower = control.to_ascii_lowercase();
        assert!(!lower.contains("transfer-encoding"));
        assert!(lower.contains("content-length: 6\r\n"));
        // Headers preserved
        assert!(control.starts_with("POST /a HTTP/1.1\r\n"));
        assert!(control.contains("Host: x"));
        // Body present, of declared length, benign padding only.
        let (_, body) = control.rsplit_once("\r\n\r\n").unwrap();
        assert_eq!(body.len(), 6);
        assert!(body.chars().all(|c| c == 'x'));
    }

    #[test]
    fn build_control_zero_body_when_attack_has_none() {
        let p = "POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n";
        let control = build_control_request(p);
        assert!(control.contains("Content-Length: 0\r\n"));
        let (_, body) = control.rsplit_once("\r\n\r\n").unwrap();
        assert!(body.is_empty());
    }

    #[test]
    fn build_control_caps_body_at_max_bytes() {
        // Construct an attack payload with a body bigger than the cap.
        let huge_body = "z".repeat(CONTROL_BODY_MAX_BYTES + 1000);
        let p = format!(
            "POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\nContent-Length: 99999\r\n\r\n{}",
            huge_body
        );
        let control = build_control_request(&p);
        assert!(control.contains(&format!("Content-Length: {}\r\n", CONTROL_BODY_MAX_BYTES)));
        let (_, body) = control.rsplit_once("\r\n\r\n").unwrap();
        assert_eq!(body.len(), CONTROL_BODY_MAX_BYTES);
    }

    #[test]
    fn build_control_preserves_custom_headers() {
        let p = "POST / HTTP/1.1\r\nHost: x\r\nCookie: s=1\r\nX-Custom: v\r\nTransfer-Encoding: chunked\r\nContent-Length: 6\r\n\r\n0\r\n\r\nG";
        let control = build_control_request(p);
        assert!(control.contains("Cookie: s=1"));
        assert!(control.contains("X-Custom: v"));
    }

    #[test]
    fn control_fp_when_both_504() {
        let attack = VulnerabilityInfo {
            status: "HTTP/1.1 504".into(),
            status_code: Some(504),
            duration: Duration::from_millis(500),
            body_length: 20,
            header_fingerprint: ResponseHeaderFingerprint::default(),
            is_connection_timeout: false,
        };
        let control = ControlObservation {
            duration: Duration::from_millis(50),
            status_code: Some(504),
            body_length: 20,
            header_fingerprint: ResponseHeaderFingerprint::default(),
            is_connection_timeout: false,
        };
        assert!(control_indicates_false_positive(&attack, &control, None));
    }

    #[test]
    fn control_fp_when_similar_timing() {
        let attack = VulnerabilityInfo {
            status: "HTTP/1.1 200".into(),
            status_code: Some(200),
            duration: Duration::from_millis(2000),
            body_length: 13,
            header_fingerprint: ResponseHeaderFingerprint::default(),
            is_connection_timeout: false,
        };
        let control = ControlObservation {
            duration: Duration::from_millis(1500), // 75% of attack
            status_code: Some(200),
            body_length: 13,
            header_fingerprint: ResponseHeaderFingerprint::default(),
            is_connection_timeout: false,
        };
        assert!(control_indicates_false_positive(&attack, &control, None));
    }

    #[test]
    fn control_kept_when_fast_and_different_status() {
        let attack = VulnerabilityInfo {
            status: "HTTP/1.1 504".into(),
            status_code: Some(504),
            duration: Duration::from_millis(2000),
            body_length: 0,
            header_fingerprint: ResponseHeaderFingerprint::default(),
            is_connection_timeout: false,
        };
        let control = ControlObservation {
            duration: Duration::from_millis(50), // 2.5% of attack — different shape
            status_code: Some(200),
            body_length: 13,
            header_fingerprint: ResponseHeaderFingerprint::default(),
            is_connection_timeout: false,
        };
        assert!(!control_indicates_false_positive(&attack, &control, None));
    }

    #[test]
    fn body_divergence_ignores_when_both_tiny() {
        // Both sides below CONTROL_BODY_MIN_BYTES → not enough signal.
        assert!(!bodies_diverge(5, 5));
        assert!(!bodies_diverge(20, 30));
    }

    #[test]
    fn body_divergence_detects_tiny_vs_large() {
        // One side tiny, the other substantial — that IS structural divergence.
        // (Real smuggling case: attack returns small error page, control returns
        // full normal response.)
        assert!(bodies_diverge(10, 1000));
        assert!(bodies_diverge(1000, 10));
    }

    #[test]
    fn body_divergence_detects_large_size_difference() {
        // 200 bytes vs 50 bytes: 50/200 = 25% < 75% threshold → diverge.
        assert!(bodies_diverge(200, 50));
        assert!(bodies_diverge(50, 200));
    }

    #[test]
    fn body_divergence_skips_close_sizes() {
        // 200 bytes vs 180 bytes: 180/200 = 90% > 75% → not divergent.
        assert!(!bodies_diverge(200, 180));
    }

    #[test]
    fn control_kept_when_bodies_diverge_despite_similar_timing() {
        // Attack and control have similar timing (would normally trigger FP)
        // but bodies differ substantially → escape clause keeps the finding.
        let attack = VulnerabilityInfo {
            status: "HTTP/1.1 200".into(),
            status_code: Some(200),
            duration: Duration::from_millis(2000),
            body_length: 50, // small response (e.g., error page)
            header_fingerprint: ResponseHeaderFingerprint::default(),
            is_connection_timeout: false,
        };
        let control = ControlObservation {
            duration: Duration::from_millis(1900), // 95% of attack — very similar timing
            status_code: Some(200),
            body_length: 5000, // large response (normal content)
            header_fingerprint: ResponseHeaderFingerprint::default(),
            is_connection_timeout: false,
        };
        assert!(!control_indicates_false_positive(&attack, &control, None));
    }

    #[test]
    fn consecutive_fp_rejections_limit_constant() {
        // Document the limit so future tuning is intentional. Value chosen
        // small enough to abandon noisy backends quickly but large enough
        // that a few real noisy retries don't trigger early termination.
        const _: () = assert!(
            CONSECUTIVE_FP_REJECTIONS_LIMIT >= 2,
            "limit should require at least 2 consecutive rejections"
        );
    }

    #[test]
    fn payload_method_extracts_post() {
        let p = "POST /a HTTP/1.1\r\nHost: x\r\n\r\n";
        assert_eq!(payload_method(p), "POST");
    }

    #[test]
    fn payload_method_uppercases() {
        let p = "patch /a HTTP/1.1\r\nHost: x\r\n\r\n";
        assert_eq!(payload_method(p), "PATCH");
    }

    #[test]
    fn payload_method_defaults_to_get_on_empty() {
        assert_eq!(payload_method(""), "GET");
    }

    #[test]
    fn baseline_noisy_when_spread_exceeds_buffer() {
        assert!(baseline_is_noisy(
            Duration::from_millis(100),
            Duration::from_millis(700)
        ));
    }

    #[test]
    fn baseline_not_noisy_when_spread_within_buffer() {
        assert!(!baseline_is_noisy(
            Duration::from_millis(400),
            Duration::from_millis(400)
        ));
        assert!(!baseline_is_noisy(
            Duration::from_millis(100),
            Duration::from_millis(599)
        ));
    }

    #[test]
    fn timing_only_demoted_to_low_on_noisy_baseline() {
        let info = VulnerabilityInfo {
            status: "HTTP/1.1 200".into(),
            status_code: Some(200),
            duration: Duration::from_millis(2000),
            body_length: 13,
            header_fingerprint: ResponseHeaderFingerprint::default(),
            is_connection_timeout: false,
        };
        // Noisy baseline, timing-only signal → Low.
        assert_eq!(compute_confidence(&info, 1200, true), Confidence::Low);
    }

    #[test]
    fn status_signal_keeps_confidence_on_noisy_baseline() {
        let info = VulnerabilityInfo {
            status: "HTTP/1.1 504".into(),
            status_code: Some(504),
            duration: Duration::from_millis(2000),
            body_length: 0,
            header_fingerprint: ResponseHeaderFingerprint::default(),
            is_connection_timeout: false,
        };
        // 504 + timing anomaly is High regardless of baseline noise.
        assert_eq!(compute_confidence(&info, 1200, true), Confidence::High);
    }

    #[test]
    fn extreme_timing_keeps_confidence_on_noisy_baseline() {
        let info = VulnerabilityInfo {
            status: "HTTP/1.1 200".into(),
            status_code: Some(200),
            duration: Duration::from_millis(5000),
            body_length: 13,
            header_fingerprint: ResponseHeaderFingerprint::default(),
            is_connection_timeout: false,
        };
        // 5000ms > 1200*2=2400 AND > MIN_DELAY_MS*2=2000 → extreme → High even
        // on noisy baseline.
        assert_eq!(compute_confidence(&info, 1200, true), Confidence::High);
    }

    #[test]
    fn header_fingerprint_extracts_known_fields() {
        let r = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nServer: nginx\r\nContent-Length: 123\r\nX-Other: ignore\r\n\r\nbody";
        let fp = ResponseHeaderFingerprint::from_response(r);
        assert_eq!(fp.content_type.as_deref(), Some("text/html"));
        assert_eq!(fp.server.as_deref(), Some("nginx"));
        assert_eq!(fp.content_length.as_deref(), Some("123"));
    }

    #[test]
    fn header_fingerprint_divergence_count() {
        let a = ResponseHeaderFingerprint::from_response(
            "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nServer: nginx\r\nContent-Length: 100\r\n\r\nb",
        );
        let b = ResponseHeaderFingerprint::from_response(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nServer: nginx\r\nContent-Length: 99\r\n\r\nb",
        );
        // content-type differs, content-length differs, server same → 2.
        assert_eq!(a.divergence_count(&b), 2);
    }

    #[test]
    fn control_kept_when_headers_diverge_despite_similar_timing() {
        // Attack and control have similar timing AND similar body length, but
        // response headers differ in two fields → escape via header divergence.
        let attack = VulnerabilityInfo {
            status: "HTTP/1.1 200".into(),
            status_code: Some(200),
            duration: Duration::from_millis(2000),
            body_length: 200,
            header_fingerprint: ResponseHeaderFingerprint::from_response(
                "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nServer: backend-v2\r\nContent-Length: 200\r\n\r\n",
            ),
            is_connection_timeout: false,
        };
        let control = ControlObservation {
            duration: Duration::from_millis(1900),
            status_code: Some(200),
            body_length: 210,
            header_fingerprint: ResponseHeaderFingerprint::from_response(
                "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nServer: proxy-edge\r\nContent-Length: 210\r\n\r\n",
            ),
            is_connection_timeout: false,
        };
        // bodies are 200 vs 210 (95% similar — not divergent). Headers differ
        // in content-type, server, content-length (3 fields) → ≥2 → escape.
        assert!(!control_indicates_false_positive(&attack, &control, None));
    }

    #[test]
    fn control_fp_when_only_one_header_diverges() {
        // A single header divergence is not enough — could be reverse proxy
        // metadata noise. Need ≥2 to escape.
        let attack = VulnerabilityInfo {
            status: "HTTP/1.1 200".into(),
            status_code: Some(200),
            duration: Duration::from_millis(2000),
            body_length: 13,
            header_fingerprint: ResponseHeaderFingerprint::from_response(
                "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nServer: nginx\r\nContent-Length: 13\r\n\r\n",
            ),
            is_connection_timeout: false,
        };
        let control = ControlObservation {
            duration: Duration::from_millis(1800),
            status_code: Some(200),
            body_length: 13,
            header_fingerprint: ResponseHeaderFingerprint::from_response(
                "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nServer: nginx-alt\r\nContent-Length: 13\r\n\r\n",
            ),
            is_connection_timeout: false,
        };
        assert!(control_indicates_false_positive(&attack, &control, None));
    }

    #[test]
    fn followup_divergence_signals_keep_finding() {
        let attack = VulnerabilityInfo {
            status: "HTTP/1.1 200".into(),
            status_code: Some(200),
            duration: Duration::from_millis(2000),
            body_length: 13,
            header_fingerprint: ResponseHeaderFingerprint::default(),
            is_connection_timeout: false,
        };
        let control = ControlObservation {
            duration: Duration::from_millis(1900), // very similar timing
            status_code: Some(200),
            body_length: 13,
            header_fingerprint: ResponseHeaderFingerprint::default(),
            is_connection_timeout: false,
        };
        let followup = FollowupObservation {
            diverging: 2,
            total: 3,
            second_request: false,
        };
        // Without follow-up: timing similarity would reject as FP. With
        // follow-up divergence: escape clause keeps the finding.
        assert!(!control_indicates_false_positive(
            &attack,
            &control,
            Some(&followup)
        ));
    }

    #[test]
    fn followup_no_divergence_lets_fp_rule_fire() {
        let attack = VulnerabilityInfo {
            status: "HTTP/1.1 200".into(),
            status_code: Some(200),
            duration: Duration::from_millis(2000),
            body_length: 13,
            header_fingerprint: ResponseHeaderFingerprint::default(),
            is_connection_timeout: false,
        };
        let control = ControlObservation {
            duration: Duration::from_millis(1900),
            status_code: Some(200),
            body_length: 13,
            header_fingerprint: ResponseHeaderFingerprint::default(),
            is_connection_timeout: false,
        };
        let followup = FollowupObservation {
            diverging: 0,
            total: 3,
            second_request: false,
        };
        // No follow-up divergence + similar timing → standard FP rule fires.
        assert!(control_indicates_false_positive(
            &attack,
            &control,
            Some(&followup)
        ));
    }

    #[test]
    fn followup_status_diverged_flags_non_5xx_change() {
        // A 4xx/3xx follow-up where the baseline was 200 is a structural divergence.
        assert!(followup_status_diverged(Some(405), Some(200)));
        assert!(followup_status_diverged(Some(400), Some(200)));
        assert!(followup_status_diverged(Some(301), Some(200)));
    }

    #[test]
    fn followup_status_diverged_ignores_5xx() {
        // 5xx responses are flake-prone and must NOT drive the second-request
        // probe, even when they differ from the baseline.
        assert!(!followup_status_diverged(Some(504), Some(200)));
        assert!(!followup_status_diverged(Some(502), Some(200)));
        assert!(!followup_status_diverged(Some(503), Some(200)));
        assert!(!followup_status_diverged(None, Some(200)));
    }

    #[test]
    fn followup_status_diverged_false_when_matching() {
        assert!(!followup_status_diverged(Some(200), Some(200)));
        assert!(!followup_status_diverged(Some(404), Some(404)));
    }

    #[test]
    fn second_request_signal_emitted() {
        let info = VulnerabilityInfo {
            status: "HTTP/1.1 200 OK".into(),
            status_code: Some(200),
            duration: Duration::from_millis(5),
            body_length: 500,
            header_fingerprint: ResponseHeaderFingerprint::default(),
            is_connection_timeout: false,
        };
        let followup = FollowupObservation {
            diverging: 1,
            total: 3,
            second_request: true,
        };
        let signals = collect_detection_signals(
            &info,
            Duration::from_millis(5),
            100,
            false,
            None,
            Some(&followup),
        );
        assert!(signals.iter().any(|s| s == "second_request_desync"));
        assert!(
            signals
                .iter()
                .any(|s| s.starts_with("followup_divergence:"))
        );
    }

    #[test]
    fn followup_observation_reports_divergence() {
        let f = FollowupObservation {
            diverging: 1,
            total: 3,
            second_request: false,
        };
        assert!(f.has_divergence());
        let none = FollowupObservation {
            diverging: 0,
            total: 3,
            second_request: false,
        };
        assert!(!none.has_divergence());
    }

    #[test]
    fn control_kept_when_bodies_diverge_despite_both_504() {
        let attack = VulnerabilityInfo {
            status: "HTTP/1.1 504".into(),
            status_code: Some(504),
            duration: Duration::from_millis(2000),
            body_length: 100,
            header_fingerprint: ResponseHeaderFingerprint::default(),
            is_connection_timeout: false,
        };
        let control = ControlObservation {
            duration: Duration::from_millis(50),
            status_code: Some(504),
            body_length: 1000,
            header_fingerprint: ResponseHeaderFingerprint::default(),
            is_connection_timeout: false,
        };
        // Both 504 would normally be FP, but body divergence overrides.
        assert!(!control_indicates_false_positive(&attack, &control, None));
    }

    #[test]
    fn followup_single_flake_does_not_override_control_fp() {
        // A uniformly-slow backend (control timing ~= attack) where exactly ONE
        // of the 3 follow-up probes flaked. The control-FP rule must still fire:
        // a single flaky follow-up is not corroboration.
        let attack = VulnerabilityInfo {
            status: "HTTP/1.1 200".into(),
            status_code: Some(200),
            duration: Duration::from_millis(2000),
            body_length: 13,
            header_fingerprint: ResponseHeaderFingerprint::default(),
            is_connection_timeout: false,
        };
        let control = ControlObservation {
            duration: Duration::from_millis(1900), // very similar timing
            status_code: Some(200),
            body_length: 13,
            header_fingerprint: ResponseHeaderFingerprint::default(),
            is_connection_timeout: false,
        };
        let single_flake = FollowupObservation {
            diverging: 1,
            total: 3,
            second_request: false,
        };
        assert!(
            control_indicates_false_positive(&attack, &control, Some(&single_flake)),
            "one flaky follow-up must not override the control rejection"
        );
    }

    #[test]
    fn has_corroborated_divergence_requires_majority_on_main_path() {
        let one = FollowupObservation {
            diverging: 1,
            total: 3,
            second_request: false,
        };
        let two = FollowupObservation {
            diverging: 2,
            total: 3,
            second_request: false,
        };
        assert!(!one.has_corroborated_divergence(), "1/3 is not a majority");
        assert!(two.has_corroborated_divergence(), "2/3 is a majority");
        // The second-request path already reproduced across sequences, so a
        // single divergence there is corroboration enough.
        let second_req = FollowupObservation {
            diverging: 1,
            total: 3,
            second_request: true,
        };
        assert!(second_req.has_corroborated_divergence());
    }

    #[test]
    fn aggregate_baseline_tolerates_partial_probe_failure() {
        // A single failed probe among successes must not discard the baseline.
        let results: Vec<Result<(String, Duration)>> = vec![
            Ok((
                "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n".to_string(),
                Duration::from_millis(100),
            )),
            Err(SmugglexError::Io("connection reset".into())),
            Ok((
                "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n".to_string(),
                Duration::from_millis(120),
            )),
        ];
        let baseline = aggregate_baseline(results).expect("survivors should yield a baseline");
        assert_eq!(
            baseline.observed_status_codes.len(),
            2,
            "only the successful probes contribute status codes"
        );
        assert_eq!(baseline.status_code, Some(200));
    }

    #[test]
    fn aggregate_baseline_errors_only_when_all_probes_fail() {
        let results: Vec<Result<(String, Duration)>> = vec![
            Err(SmugglexError::Io("reset".into())),
            Err(SmugglexError::Timeout("timed out".into())),
        ];
        assert!(
            aggregate_baseline(results).is_err(),
            "no surviving samples → error"
        );
    }
}
