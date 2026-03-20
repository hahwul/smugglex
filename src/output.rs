use chrono::Utc;
use colored::*;
use std::fs;
use std::io::Write;

use crate::error::Result;
use crate::model::{CheckResult, FingerprintInfo, ScanResults};
use crate::utils::{LogLevel, log};

/// Log scan results in the specified output format (plain text or JSON).
pub fn log_scan_results(
    results: &[CheckResult],
    format: &crate::cli::OutputFormat,
    target_url: &str,
    method: &str,
    fingerprint_info: &Option<FingerprintInfo>,
) {
    let vulnerable_count = results.iter().filter(|r| r.vulnerable).count();

    if format.is_json() {
        let scan_results = ScanResults {
            target: target_url.to_string(),
            method: method.to_string(),
            timestamp: Utc::now().to_rfc3339(),
            fingerprint: fingerprint_info.clone(),
            checks: results.to_vec(),
        };
        match serde_json::to_string_pretty(&scan_results) {
            Ok(json_output) => println!("{}", json_output),
            Err(e) => {
                log(
                    LogLevel::Error,
                    &format!("failed to serialize results to JSON: {}", e),
                );
                log(LogLevel::Info, "falling back to plain text output");
                log_plain_results(results, vulnerable_count);
            }
        }
    } else {
        log_plain_results(results, vulnerable_count);
    }
}

/// Display scan results as human-readable plain text.
pub fn log_plain_results(results: &[CheckResult], vulnerable_count: usize) {
    if vulnerable_count > 0 {
        log(
            LogLevel::Warning,
            &format!("smuggling found {} vulnerability(ies)", vulnerable_count),
        );
        if crate::utils::is_quiet() {
            return;
        }
        println!();
        for result in results.iter().filter(|r| r.vulnerable) {
            println!(
                "{}",
                format!("=== {} Vulnerability Details ===", result.check_type).bold()
            );
            if let Some(ref confidence) = result.confidence {
                println!(
                    "{} {} (Confidence: {:?})",
                    "Status:".bold(),
                    "VULNERABLE".red().bold(),
                    confidence
                );
            } else {
                println!("{} {}", "Status:".bold(), "VULNERABLE".red().bold());
            }
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

/// Serialize scan results to JSON and write them to a file.
pub fn save_results_to_file(
    output_file: &str,
    target_url: &str,
    method: &str,
    results: Vec<CheckResult>,
    fingerprint_info: &Option<FingerprintInfo>,
) -> Result<()> {
    let scan_results = ScanResults {
        target: target_url.to_string(),
        method: method.to_string(),
        timestamp: Utc::now().to_rfc3339(),
        fingerprint: fingerprint_info.clone(),
        checks: results,
    };
    let json_output = serde_json::to_string_pretty(&scan_results)?;
    if fs::metadata(output_file).is_ok() {
        log(
            LogLevel::Warning,
            &format!("overwriting existing file: {}", output_file),
        );
    }
    let mut file = fs::File::create(output_file)?;
    file.write_all(json_output.as_bytes())?;
    log(LogLevel::Info, &format!("results saved to {}", output_file));
    Ok(())
}
