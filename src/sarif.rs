use crate::model::{CheckResult, ScanResults};
use serde_sarif::sarif::{
    Artifact, ArtifactLocation, Location, Message, MultiformatMessageString, PhysicalLocation,
    PropertyBag, Region, ReportingDescriptor, Result as SarifResult, ResultLevel, Run, Sarif,
    Tool, ToolComponent,
};
use std::collections::BTreeMap;

/// Convert ScanResults to SARIF format
pub fn convert_to_sarif(scan_results: &ScanResults) -> Sarif {
    let tool = create_tool_component();
    let results = convert_check_results(&scan_results.checks, &scan_results.target);
    let artifacts = vec![create_artifact(&scan_results.target)];

    let run = Run::builder()
        .tool(tool)
        .results(results)
        .artifacts(artifacts)
        .build();

    Sarif::builder().version("2.1.0").runs(vec![run]).build()
}

/// Create the tool component for SmuggleX
fn create_tool_component() -> Tool {
    let driver = ToolComponent::builder()
        .name("SmuggleX")
        .semantic_version(option_env!("CARGO_PKG_VERSION").unwrap_or("unknown"))
        .information_uri("https://github.com/hahwul/smugglex")
        .rules(create_rules())
        .build();

    Tool::builder().driver(driver).build()
}

/// Create rules for each vulnerability type
fn create_rules() -> Vec<ReportingDescriptor> {
    vec![
        create_rule("cl-te", "Content-Length vs Transfer-Encoding Smuggling"),
        create_rule("te-cl", "Transfer-Encoding vs Content-Length Smuggling"),
        create_rule("te-te", "Transfer-Encoding Obfuscation Smuggling"),
        create_rule("h2c", "HTTP/2 Cleartext Smuggling"),
        create_rule("h2", "HTTP/2 Protocol Smuggling"),
    ]
}

/// Create a single rule descriptor
fn create_rule(id: &str, name: &str) -> ReportingDescriptor {
    let help_text = match id.to_lowercase().as_str() {
        "cl.te" | "cl-te" => {
            "The front-end server uses Content-Length header while the back-end uses Transfer-Encoding. \
             This mismatch can cause HTTP request smuggling vulnerabilities."
        }
        "te.cl" | "te-cl" => {
            "The front-end server uses Transfer-Encoding header while the back-end uses Content-Length. \
             This mismatch can cause HTTP request smuggling vulnerabilities."
        }
        "te.te" | "te-te" => {
            "Both servers support Transfer-Encoding but one can be tricked with obfuscation. \
             This can lead to HTTP request smuggling vulnerabilities."
        }
        "h2c" => {
            "Exploits HTTP/1.1 to HTTP/2 upgrade mechanisms. \
             This can lead to HTTP request smuggling through protocol confusion."
        }
        "h2" => {
            "Exploits HTTP/2 protocol-level features during protocol translation. \
             This can lead to HTTP request smuggling in HTTP/2 environments."
        }
        _ => "HTTP Request Smuggling vulnerability detected.",
    };

    let short_desc = MultiformatMessageString::builder().text(name).build();
    let full_desc = MultiformatMessageString::builder().text(help_text).build();
    let help = MultiformatMessageString::builder().text(help_text).build();

    ReportingDescriptor::builder()
        .id(id)
        .name(name)
        .short_description(short_desc)
        .full_description(full_desc)
        .help(help)
        .build()
}

/// Convert CheckResults to SARIF results
fn convert_check_results(checks: &[CheckResult], target: &str) -> Vec<SarifResult> {
    checks
        .iter()
        .filter(|check| check.vulnerable)
        .map(|check| create_sarif_result(check, target))
        .collect()
}

/// Create a SARIF result from a CheckResult
fn create_sarif_result(check: &CheckResult, target: &str) -> SarifResult {
    let message = create_result_message(check);
    let rule_id = &check.check_type;

    let location = Location::builder()
        .physical_location(
            PhysicalLocation::builder()
                .artifact_location(ArtifactLocation::builder().uri(target).build())
                .region(Region::builder().build())
                .build(),
        )
        .build();

    // Create properties map for additional metadata
    let mut property_map = BTreeMap::new();

    // Add payload to properties if available
    if let Some(ref payload) = check.payload {
        property_map.insert("payload".to_string(), serde_json::json!(payload));
    }

    // Add timing information to properties
    if let Some(attack_duration) = check.attack_duration_ms {
        property_map.insert(
            "normalDurationMs".to_string(),
            serde_json::json!(check.normal_duration_ms),
        );
        property_map.insert(
            "attackDurationMs".to_string(),
            serde_json::json!(attack_duration),
        );
    }

    // Add attack status to properties if available
    if let Some(ref attack_status) = check.attack_status {
        property_map.insert("attackStatus".to_string(), serde_json::json!(attack_status));
    }

    // Add payload index to properties if available
    if let Some(payload_index) = check.payload_index {
        property_map.insert("payloadIndex".to_string(), serde_json::json!(payload_index));
    }

    let properties = PropertyBag::builder()
        .additional_properties(property_map)
        .build();

    SarifResult::builder()
        .rule_id(rule_id)
        .message(message)
        .level(ResultLevel::Error)
        .locations(vec![location])
        .properties(properties)
        .build()
}

/// Create a message for a SARIF result
fn create_result_message(check: &CheckResult) -> Message {
    let text = format!(
        "HTTP Request Smuggling vulnerability detected using {} attack. {}",
        check.check_type,
        check.attack_status.as_deref().unwrap_or("Connection issue detected.")
    );

    Message::builder().text(text).build()
}

/// Create an artifact for the target URL
fn create_artifact(target: &str) -> Artifact {
    Artifact::builder()
        .location(ArtifactLocation::builder().uri(target).build())
        .build()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_check_result(
        check_type: &str,
        vulnerable: bool,
        payload_index: Option<usize>,
        attack_status: Option<&str>,
        attack_duration_ms: Option<u64>,
    ) -> CheckResult {
        CheckResult {
            check_type: check_type.to_string(),
            vulnerable,
            payload_index,
            normal_status: "HTTP/1.1 200 OK".to_string(),
            attack_status: attack_status.map(|s| s.to_string()),
            normal_duration_ms: 150,
            attack_duration_ms,
            timestamp: "2024-01-01T12:00:00Z".to_string(),
            payload: None,
        }
    }

    #[test]
    fn test_convert_to_sarif_basic() {
        let checks = vec![create_test_check_result(
            "cl-te",
            true,
            Some(0),
            Some("HTTP/1.1 504 Gateway Timeout"),
            Some(5000),
        )];

        let scan_results = ScanResults {
            target: "https://example.com".to_string(),
            method: "POST".to_string(),
            timestamp: "2024-01-01T12:00:00Z".to_string(),
            checks,
        };

        let sarif = convert_to_sarif(&scan_results);

        assert_eq!(sarif.version, "2.1.0");
        assert_eq!(sarif.runs.len(), 1);

        let run = &sarif.runs[0];
        assert_eq!(run.tool.driver.name, "SmuggleX");
        let results = run.results.as_ref().expect("Results should be present");
        assert_eq!(results.len(), 1);

        let result = &results[0];
        assert_eq!(result.rule_id.as_deref(), Some("cl-te"));
        assert_eq!(result.level, Some(ResultLevel::Error));
    }

    #[test]
    fn test_convert_to_sarif_no_vulnerabilities() {
        let checks = vec![create_test_check_result("te-cl", false, None, None, None)];

        let scan_results = ScanResults {
            target: "https://example.com".to_string(),
            method: "POST".to_string(),
            timestamp: "2024-01-01T12:00:00Z".to_string(),
            checks,
        };

        let sarif = convert_to_sarif(&scan_results);

        // Should have no results for non-vulnerable checks
        let results = sarif.runs[0]
            .results
            .as_ref()
            .expect("Results should be present");
        assert_eq!(results.len(), 0);
    }

    #[test]
    fn test_convert_to_sarif_multiple_vulnerabilities() {
        let checks = vec![
            create_test_check_result(
                "cl-te",
                true,
                Some(0),
                Some("HTTP/1.1 504 Gateway Timeout"),
                Some(5000),
            ),
            create_test_check_result("te-cl", false, None, None, None),
            create_test_check_result(
                "te-te",
                true,
                Some(2),
                Some("Connection Timeout"),
                Some(10000),
            ),
        ];

        let scan_results = ScanResults {
            target: "https://example.com".to_string(),
            method: "POST".to_string(),
            timestamp: "2024-01-01T12:00:00Z".to_string(),
            checks,
        };

        let sarif = convert_to_sarif(&scan_results);

        // Should have 2 results (only vulnerable checks)
        let results = sarif.runs[0]
            .results
            .as_ref()
            .expect("Results should be present");
        assert_eq!(results.len(), 2);
        assert_eq!(results[0].rule_id.as_deref(), Some("cl-te"));
        assert_eq!(results[1].rule_id.as_deref(), Some("te-te"));
    }

    #[test]
    fn test_create_rules() {
        let rules = create_rules();

        // Should have rules for all vulnerability types
        assert_eq!(rules.len(), 5);

        // Check that cl-te rule exists
        let cl_te_rule = rules.iter().find(|r| r.id == "cl-te");
        assert!(cl_te_rule.is_some());

        let rule = cl_te_rule.unwrap();
        let rule_name = rule.name.as_deref().expect("Rule name should be present");
        assert!(rule_name.contains("Content-Length"));
    }

    #[test]
    fn test_create_rule() {
        let rule = create_rule("cl-te", "Test Rule");

        assert_eq!(rule.id, "cl-te");
        assert_eq!(rule.name.as_deref(), Some("Test Rule"));
        assert!(rule.short_description.is_some());
        assert!(rule.full_description.is_some());
        assert!(rule.help.is_some());
    }

    #[test]
    fn test_sarif_serialization() {
        let checks = vec![create_test_check_result(
            "cl-te",
            true,
            Some(0),
            Some("HTTP/1.1 504 Gateway Timeout"),
            Some(5000),
        )];

        let scan_results = ScanResults {
            target: "https://example.com".to_string(),
            method: "POST".to_string(),
            timestamp: "2024-01-01T12:00:00Z".to_string(),
            checks,
        };

        let sarif = convert_to_sarif(&scan_results);
        let json = serde_json::to_string_pretty(&sarif);

        assert!(json.is_ok());
        let json_str = json.unwrap();
        // Version might appear without quotes depending on serialization
        assert!(json_str.contains("2.1.0"));
        assert!(json_str.contains("SmuggleX"));
    }
}
