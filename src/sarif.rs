/// SARIF 2.1.0 output generator.
///
/// Produces output compatible with GitHub Advanced Security, GitLab SAST,
/// SonarQube, and any OASIS SARIF-compliant consumer.
///
/// Each Occurrence becomes an independent SARIF result so that CI tools
/// can annotate individual lines in pull requests.
use serde_json::{json, Value};

use crate::report::ScanReport;
use crate::rules::{get_default_rules, RiskLevel};

fn sarif_level(level: &RiskLevel) -> &'static str {
    match level {
        RiskLevel::Critical => "error",
        RiskLevel::High => "warning",
        RiskLevel::Medium => "warning",
        RiskLevel::Low => "note",
    }
}

pub fn generate(report: &ScanReport) -> Value {
    // Rule definitions for the tool driver section.
    let driver_rules: Vec<Value> = get_default_rules()
        .iter()
        .map(|r| {
            json!({
                "id": r.id,
                "shortDescription": { "text": r.name },
                "fullDescription":  { "text": r.description },
                "defaultConfiguration": { "level": sarif_level(&r.level) }
            })
        })
        .collect();

    // One SARIF result per occurrence so CI tools annotate every affected line.
    let base = report.target_directory.trim_end_matches('/');
    let mut results: Vec<Value> = Vec::new();

    for finding in &report.findings {
        for occ in &finding.occurrences {
            // Strip target directory prefix → path relative to the scanned root.
            let uri = finding
                .file_path
                .strip_prefix(base)
                .unwrap_or(&finding.file_path)
                .trim_start_matches('/');

            results.push(json!({
                "ruleId": finding.rule_id,
                "level": sarif_level(&finding.risk_level),
                "message": { "text": finding.rule_name },
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": uri,
                            // PLUGINROOT is resolved via originalUriBaseIds below.
                            "uriBaseId": "PLUGINROOT"
                        },
                        "region": {
                            "startLine": occ.line_number,
                            "snippet": { "text": occ.matched_line }
                        }
                    }
                }]
            }));
        }
    }

    // Absolute base URI lets SARIF consumers resolve full paths from relative URIs.
    let base_uri = format!("file://{}/", base);

    json!({
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "wp-risk-analyzer",
                    "version": env!("CARGO_PKG_VERSION"),
                    "informationUri": "https://github.com/f3nr1r/wp-risk-analyzer",
                    "rules": driver_rules
                }
            },
            "originalUriBaseIds": {
                "PLUGINROOT": { "uri": base_uri }
            },
            "results": results
        }]
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::RiskLevel;

    fn make_report() -> ScanReport {
        let mut report = ScanReport::new("/plugins/my-plugin".to_string());
        report.total_files_scanned = 2;
        // Two occurrences for WP-004 in the same file → 1 finding, 2 results in SARIF.
        report.add_occurrence(
            "WP-004".to_string(),
            "Eval Usage".to_string(),
            "/plugins/my-plugin/includes/bad.php".to_string(),
            RiskLevel::Critical,
            5,
            "eval($code);".to_string(),
        );
        report.add_occurrence(
            "WP-004".to_string(),
            "Eval Usage".to_string(),
            "/plugins/my-plugin/includes/bad.php".to_string(),
            RiskLevel::Critical,
            10,
            "eval($other);".to_string(),
        );
        // One separate finding in a different file.
        report.add_occurrence(
            "WP-002".to_string(),
            "System Command Execution".to_string(),
            "/plugins/my-plugin/main.php".to_string(),
            RiskLevel::Critical,
            3,
            "shell_exec('ls');".to_string(),
        );
        report
    }

    #[test]
    fn sarif_has_correct_schema_and_version() {
        let sarif = generate(&make_report());
        assert_eq!(sarif["version"], "2.1.0");
        assert!(
            sarif["$schema"].as_str().unwrap().contains("sarif"),
            "schema URI should reference sarif"
        );
    }

    #[test]
    fn sarif_results_count_equals_total_occurrences() {
        let report = make_report();
        let total_occ: usize = report.findings.iter().map(|f| f.occurrences.len()).sum();
        let sarif = generate(&report);
        let results = sarif["runs"][0]["results"].as_array().unwrap();
        assert_eq!(results.len(), total_occ, "one SARIF result per occurrence");
    }

    #[test]
    fn sarif_critical_finding_maps_to_error_level() {
        let sarif = generate(&make_report());
        let results = sarif["runs"][0]["results"].as_array().unwrap();
        let eval_result = results.iter().find(|r| r["ruleId"] == "WP-004").unwrap();
        assert_eq!(eval_result["level"], "error");
    }

    #[test]
    fn sarif_uri_is_relative_to_target_directory() {
        let sarif = generate(&make_report());
        let results = sarif["runs"][0]["results"].as_array().unwrap();
        let eval_result = results.iter().find(|r| r["ruleId"] == "WP-004").unwrap();
        let uri = eval_result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
            .as_str()
            .unwrap();
        assert!(!uri.starts_with('/'), "URI must be relative, got: {uri}");
        assert_eq!(uri, "includes/bad.php");
    }

    #[test]
    fn sarif_driver_lists_all_registered_rules() {
        let report = ScanReport::new("/tmp".to_string());
        let sarif = generate(&report);
        let driver_rules = sarif["runs"][0]["tool"]["driver"]["rules"]
            .as_array()
            .unwrap();
        assert_eq!(driver_rules.len(), get_default_rules().len());
    }

    #[test]
    fn sarif_original_uri_base_id_is_set() {
        let sarif = generate(&make_report());
        let base = &sarif["runs"][0]["originalUriBaseIds"]["PLUGINROOT"]["uri"];
        let uri = base.as_str().unwrap();
        assert!(uri.starts_with("file://"), "base URI must use file:// scheme");
        assert!(uri.ends_with('/'), "base URI must end with /");
    }

    #[test]
    fn sarif_line_numbers_are_correct() {
        let sarif = generate(&make_report());
        let results = sarif["runs"][0]["results"].as_array().unwrap();
        // eval on line 5 and 10 → both should appear
        let eval_lines: Vec<u64> = results
            .iter()
            .filter(|r| r["ruleId"] == "WP-004")
            .map(|r| {
                r["locations"][0]["physicalLocation"]["region"]["startLine"]
                    .as_u64()
                    .unwrap()
            })
            .collect();
        assert!(eval_lines.contains(&5));
        assert!(eval_lines.contains(&10));
    }
}
