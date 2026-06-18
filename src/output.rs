use chrono::Utc;
use colored::*;
use std::fs;
use std::io::Write;

use crate::error::Result;
use crate::model::{BatchScanResults, BatchSummary, CheckResult, FingerprintInfo, ScanResults};
use crate::utils::{LogLevel, log};

/// Atomically write `contents` to `path`: write to a sibling temp file, flush,
/// then rename it over the destination. A failure during the write leaves any
/// existing file at `path` untouched (the partial temp file is removed) instead
/// of truncating a previously-valid report, which is what `File::create`
/// followed by a failed `write_all` would do.
fn atomic_write(path: &str, contents: &str) -> std::io::Result<()> {
    let dest = std::path::Path::new(path);
    let name = dest
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("smugglex-output");
    // Temp file alongside the destination so the final rename stays on the same
    // filesystem (a cross-device rename would fail). Tag with the PID to avoid
    // clashing with any concurrent writer.
    let tmp_name = format!(".{}.{}.tmp", name, std::process::id());
    let tmp = match dest.parent().filter(|p| !p.as_os_str().is_empty()) {
        Some(dir) => dir.join(tmp_name),
        None => std::path::PathBuf::from(tmp_name),
    };

    let write = (|| {
        let mut f = fs::File::create(&tmp)?;
        f.write_all(contents.as_bytes())?;
        f.flush()
    })();
    if let Err(e) = write.and_then(|()| fs::rename(&tmp, dest)) {
        let _ = fs::remove_file(&tmp);
        return Err(e);
    }
    Ok(())
}

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
            error: None,
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
            if !result.detection_signals.is_empty() {
                println!(
                    "{} {}",
                    "Signals:".bold(),
                    result.detection_signals.join(", ")
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
        error: None,
    };
    let json_output = serde_json::to_string_pretty(&scan_results)?;
    if fs::metadata(output_file).is_ok() {
        log(
            LogLevel::Warning,
            &format!("overwriting existing file: {}", output_file),
        );
    }
    atomic_write(output_file, &json_output)?;
    log(LogLevel::Info, &format!("results saved to {}", output_file));
    Ok(())
}

/// Build a BatchScanResults envelope + summary from collected per-target results.
/// `version` is optional (e.g. env!("CARGO_PKG_VERSION")).
pub fn build_batch_results(results: Vec<ScanResults>, version: Option<&str>) -> BatchScanResults {
    let total_targets = results.len();
    let vulnerable_targets = results
        .iter()
        .filter(|r| r.checks.iter().any(|c| c.vulnerable))
        .count();

    let total_checks = results.iter().map(|r| r.checks.len()).sum();
    let vulnerable_checks = results
        .iter()
        .flat_map(|r| r.checks.iter())
        .filter(|c| c.vulnerable)
        .count();

    let summary = BatchSummary {
        total_targets,
        vulnerable_targets,
        total_checks,
        vulnerable_checks,
    };

    BatchScanResults {
        smugglex_version: version.map(|s| s.to_string()),
        timestamp: chrono::Utc::now().to_rfc3339(),
        results,
        summary,
    }
}

/// Serialize and print a BatchScanResults as pretty JSON to stdout.
/// This should be the *only* thing written to stdout in machine/JSON mode for batch runs.
pub fn print_batch_json(batch: &BatchScanResults) {
    match serde_json::to_string_pretty(batch) {
        Ok(json) => println!("{}", json),
        Err(e) => {
            log(
                LogLevel::Error,
                &format!("failed to serialize batch results: {}", e),
            );
        }
    }
}

/// Write batch results to a file (used by -o when emitting JSON for multiple targets).
pub fn save_batch_to_file(batch: &BatchScanResults, output_file: &str) -> crate::error::Result<()> {
    let json_output = serde_json::to_string_pretty(batch)?;
    if fs::metadata(output_file).is_ok() {
        log(
            LogLevel::Warning,
            &format!("overwriting existing file: {}", output_file),
        );
    }
    atomic_write(output_file, &json_output)?;
    log(
        LogLevel::Info,
        &format!("batch results saved to {}", output_file),
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn atomic_write_overwrites_and_leaves_no_temp_file() {
        let dir = std::env::temp_dir().join(format!("smugglex-atomic-{}", std::process::id()));
        let _ = fs::create_dir_all(&dir);
        let dest = dir.join("report.json");
        let dest_str = dest.to_str().unwrap();

        atomic_write(dest_str, "OLD").unwrap();
        // Overwriting must leave a complete, valid final file (not a truncated one).
        atomic_write(dest_str, "NEW-CONTENT").unwrap();
        assert_eq!(fs::read_to_string(&dest).unwrap(), "NEW-CONTENT");

        // The sibling temp file must be renamed away, not left behind.
        let leftover_tmp = fs::read_dir(&dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .any(|e| e.file_name().to_string_lossy().ends_with(".tmp"));
        assert!(!leftover_tmp, "temp file should be renamed/removed");

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn atomic_write_errors_on_unwritable_path() {
        // Parent directory does not exist → error surfaced, nothing created.
        let res = atomic_write("/nonexistent-smugglex-dir/sub/report.json", "DATA");
        assert!(res.is_err());
    }
}
