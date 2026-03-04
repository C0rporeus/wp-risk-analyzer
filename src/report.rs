use serde::Serialize;
use crate::rules::RiskLevel;

#[derive(Debug, Serialize)]
pub struct Occurrence {
    pub line_number: usize,
    pub matched_line: String,
}

#[derive(Debug, Serialize)]
pub struct Finding {
    pub rule_id: String,
    pub rule_name: String,
    pub file_path: String,
    pub risk_level: RiskLevel,
    pub occurrences: Vec<Occurrence>,
}

#[derive(Debug, Serialize)]
pub struct ScanReport {
    pub target_directory: String,
    pub total_files_scanned: usize,
    /// Unique (rule_id, file_path) pairs — not raw line hits.
    pub total_findings: usize,
    /// Accumulated once per unique (rule_id, file_path), not per occurrence.
    pub risk_score: u32,
    pub findings: Vec<Finding>,
}

impl ScanReport {
    pub fn new(target_directory: String) -> Self {
        Self {
            target_directory,
            total_files_scanned: 0,
            total_findings: 0,
            risk_score: 0,
            findings: Vec::new(),
        }
    }

    /// Records one line hit. Groups occurrences by (rule_id, file_path):
    /// score is added only when a new unique pair is created.
    pub fn add_occurrence(
        &mut self,
        rule_id: String,
        rule_name: String,
        file_path: String,
        risk_level: RiskLevel,
        line_number: usize,
        matched_line: String,
    ) {
        let occurrence = Occurrence { line_number, matched_line };

        if let Some(finding) = self
            .findings
            .iter_mut()
            .find(|f| f.rule_id == rule_id && f.file_path == file_path)
        {
            finding.occurrences.push(occurrence);
        } else {
            self.risk_score += risk_level.score();
            self.total_findings += 1;
            self.findings.push(Finding {
                rule_id,
                rule_name,
                file_path,
                risk_level,
                occurrences: vec![occurrence],
            });
        }
    }

    /// Returns true if any finding has Critical risk level.
    /// Used by `--fail-on-critical` to gate pipelines regardless of cumulative score.
    pub fn has_critical(&self) -> bool {
        self.findings
            .iter()
            .any(|f| matches!(f.risk_level, RiskLevel::Critical))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::RiskLevel;

    fn add(report: &mut ScanReport, rule_id: &str, file: &str, level: RiskLevel, line: usize) {
        report.add_occurrence(
            rule_id.to_string(),
            "Test Rule".to_string(),
            file.to_string(),
            level,
            line,
            "test line".to_string(),
        );
    }

    #[test]
    fn new_report_is_empty() {
        let report = ScanReport::new("target".to_string());
        assert_eq!(report.total_files_scanned, 0);
        assert_eq!(report.total_findings, 0);
        assert_eq!(report.risk_score, 0);
        assert!(report.findings.is_empty());
    }

    #[test]
    fn two_different_rules_same_file_count_as_two_findings() {
        let mut report = ScanReport::new("target".to_string());
        add(&mut report, "WP-001", "a.php", RiskLevel::High, 1);     // +7
        add(&mut report, "WP-004", "a.php", RiskLevel::Critical, 2); // +10
        assert_eq!(report.total_findings, 2);
        assert_eq!(report.risk_score, 17);
    }

    #[test]
    fn same_rule_same_file_deduplicates() {
        let mut report = ScanReport::new("target".to_string());
        add(&mut report, "WP-004", "a.php", RiskLevel::Critical, 1);
        add(&mut report, "WP-004", "a.php", RiskLevel::Critical, 5);
        add(&mut report, "WP-004", "a.php", RiskLevel::Critical, 9);
        assert_eq!(report.total_findings, 1);
        assert_eq!(report.risk_score, 10); // counted once
        assert_eq!(report.findings[0].occurrences.len(), 3);
    }

    #[test]
    fn same_rule_different_files_are_separate_findings() {
        let mut report = ScanReport::new("target".to_string());
        add(&mut report, "WP-004", "a.php", RiskLevel::Critical, 1);
        add(&mut report, "WP-004", "b.php", RiskLevel::Critical, 1);
        assert_eq!(report.total_findings, 2);
        assert_eq!(report.risk_score, 20);
    }

    #[test]
    fn occurrence_count_is_correct() {
        let mut report = ScanReport::new("target".to_string());
        for line in [1, 2, 3, 4, 5] {
            add(&mut report, "WP-001", "x.php", RiskLevel::High, line);
        }
        assert_eq!(report.total_findings, 1);
        assert_eq!(report.findings[0].occurrences.len(), 5);
    }

    #[test]
    fn has_critical_returns_true_when_critical_present() {
        let mut report = ScanReport::new("target".to_string());
        add(&mut report, "WP-004", "a.php", RiskLevel::Critical, 1);
        assert!(report.has_critical());
    }

    #[test]
    fn has_critical_returns_false_without_critical() {
        let mut report = ScanReport::new("target".to_string());
        add(&mut report, "WP-001", "a.php", RiskLevel::High, 1);
        add(&mut report, "WP-008", "a.php", RiskLevel::Medium, 2);
        assert!(!report.has_critical());
    }

    #[test]
    fn has_critical_false_on_empty_report() {
        let report = ScanReport::new("target".to_string());
        assert!(!report.has_critical());
    }
}
