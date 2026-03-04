use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;
use regex::Regex;
use walkdir::WalkDir;

use crate::rules::{get_default_rules, Rule};
use crate::report::ScanReport;

pub struct Scanner {
    rules: Vec<(Rule, Regex, Option<Regex>)>,
}

impl Scanner {
    pub fn new() -> Self {
        let rules_def = get_default_rules();
        let mut compiled_rules = Vec::new();

        for rule in rules_def {
            if let Ok(re) = Regex::new(rule.pattern) {
                let suppression = rule.suppression.and_then(|p| Regex::new(p).ok());
                compiled_rules.push((rule, re, suppression));
            }
        }

        Self { rules: compiled_rules }
    }

    pub fn scan_directory(&self, dir_path: &Path) -> ScanReport {
        let mut report = ScanReport::new(dir_path.to_string_lossy().to_string());

        for entry in WalkDir::new(dir_path).into_iter().filter_map(|e| e.ok()) {
            if entry.path().is_file() {
                if let Some(ext) = entry.path().extension() {
                    if ext == "php" {
                        report.total_files_scanned += 1;
                        self.scan_file(entry.path(), &mut report);
                    }
                }
            }
        }

        report
    }

    fn scan_file(&self, file_path: &Path, report: &mut ScanReport) {
        let file = match File::open(file_path) {
            Ok(f) => f,
            Err(_) => return,
        };

        let reader = BufReader::new(file);

        for (line_num, line_res) in reader.lines().enumerate() {
            let line = match line_res {
                Ok(l) => l,
                Err(_) => continue,
            };

            for (rule, re, suppression) in &self.rules {
                if !re.is_match(&line) {
                    continue;
                }

                if let Some(supp) = suppression {
                    if supp.is_match(&line) {
                        continue;
                    }
                }

                report.add_occurrence(
                    rule.id.to_string(),
                    rule.name.to_string(),
                    file_path.to_string_lossy().to_string(),
                    rule.level.clone(),
                    line_num + 1,
                    line.trim().to_string(),
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::sync::atomic::{AtomicUsize, Ordering};

    static COUNTER: AtomicUsize = AtomicUsize::new(0);

    fn make_temp_dir(prefix: &str) -> std::path::PathBuf {
        let id = COUNTER.fetch_add(1, Ordering::SeqCst);
        let dir = std::env::temp_dir().join(format!("wp_test_{prefix}_{id}"));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    // ── Detection tests (true positives) ──────────────────────────────────────

    #[test]
    fn detects_eval() {
        let dir = make_temp_dir("eval");
        fs::write(dir.join("test.php"), "<?php\neval($code);\n").unwrap();
        let report = Scanner::new().scan_directory(&dir);
        fs::remove_dir_all(&dir).unwrap();
        assert!(report.findings.iter().any(|f| f.rule_id == "WP-004"));
    }

    #[test]
    fn detects_shell_exec() {
        let dir = make_temp_dir("shell");
        fs::write(dir.join("test.php"), "<?php\nshell_exec('ls');\n").unwrap();
        let report = Scanner::new().scan_directory(&dir);
        fs::remove_dir_all(&dir).unwrap();
        assert!(report.findings.iter().any(|f| f.rule_id == "WP-002"));
    }

    #[test]
    fn detects_unprepared_sql() {
        let dir = make_temp_dir("sql");
        fs::write(dir.join("test.php"), "<?php\n$wpdb->query(\"SELECT * FROM users\");\n").unwrap();
        let report = Scanner::new().scan_directory(&dir);
        fs::remove_dir_all(&dir).unwrap();
        assert!(report.findings.iter().any(|f| f.rule_id == "WP-003"));
    }

    #[test]
    fn detects_file_inclusion() {
        let dir = make_temp_dir("incl");
        fs::write(dir.join("test.php"), "<?php\ninclude($path);\n").unwrap();
        let report = Scanner::new().scan_directory(&dir);
        fs::remove_dir_all(&dir).unwrap();
        assert!(report.findings.iter().any(|f| f.rule_id == "WP-005"));
    }

    #[test]
    fn detects_unescaped_echo() {
        let dir = make_temp_dir("echo");
        fs::write(dir.join("test.php"), "<?php\necho $_GET['id'];\n").unwrap();
        let report = Scanner::new().scan_directory(&dir);
        fs::remove_dir_all(&dir).unwrap();
        assert!(report.findings.iter().any(|f| f.rule_id == "WP-006"));
    }

    #[test]
    fn detects_unserialize() {
        let dir = make_temp_dir("unser");
        fs::write(dir.join("test.php"), "<?php\n$data = unserialize($input);\n").unwrap();
        let report = Scanner::new().scan_directory(&dir);
        fs::remove_dir_all(&dir).unwrap();
        assert!(report.findings.iter().any(|f| f.rule_id == "WP-007"));
    }

    #[test]
    fn detects_open_redirect() {
        let dir = make_temp_dir("redir");
        fs::write(dir.join("test.php"), "<?php\nwp_redirect($url);\n").unwrap();
        let report = Scanner::new().scan_directory(&dir);
        fs::remove_dir_all(&dir).unwrap();
        assert!(report.findings.iter().any(|f| f.rule_id == "WP-008"));
    }

    #[test]
    fn detects_file_write() {
        let dir = make_temp_dir("fwrite");
        fs::write(dir.join("test.php"), "<?php\nfile_put_contents($path, $data);\n").unwrap();
        let report = Scanner::new().scan_directory(&dir);
        fs::remove_dir_all(&dir).unwrap();
        assert!(report.findings.iter().any(|f| f.rule_id == "WP-009"));
    }

    // ── Suppression tests (WP-001 false positive mitigation) ─────────────────

    #[test]
    fn suppresses_wp001_when_sanitize_text_field_present() {
        let dir = make_temp_dir("supp_stf");
        fs::write(dir.join("test.php"), "<?php\n$v = sanitize_text_field($_GET['id']);\n").unwrap();
        let report = Scanner::new().scan_directory(&dir);
        fs::remove_dir_all(&dir).unwrap();
        assert!(!report.findings.iter().any(|f| f.rule_id == "WP-001"));
    }

    #[test]
    fn suppresses_wp001_when_absint_present() {
        let dir = make_temp_dir("supp_abs");
        fs::write(dir.join("test.php"), "<?php\n$id = absint($_GET['id']);\n").unwrap();
        let report = Scanner::new().scan_directory(&dir);
        fs::remove_dir_all(&dir).unwrap();
        assert!(!report.findings.iter().any(|f| f.rule_id == "WP-001"));
    }

    #[test]
    fn does_not_suppress_wp001_without_sanitization() {
        let dir = make_temp_dir("nosupp");
        fs::write(dir.join("test.php"), "<?php\n$v = $_GET['id'];\n").unwrap();
        let report = Scanner::new().scan_directory(&dir);
        fs::remove_dir_all(&dir).unwrap();
        assert!(report.findings.iter().any(|f| f.rule_id == "WP-001"));
    }

    // ── Deduplication tests ───────────────────────────────────────────────────

    #[test]
    fn deduplicates_multiple_occurrences_same_file() {
        let dir = make_temp_dir("dedup");
        fs::write(dir.join("test.php"), "<?php\neval($a);\neval($b);\neval($c);\n").unwrap();
        let report = Scanner::new().scan_directory(&dir);
        fs::remove_dir_all(&dir).unwrap();

        let wp4: Vec<_> = report.findings.iter().filter(|f| f.rule_id == "WP-004").collect();
        assert_eq!(wp4.len(), 1, "should be 1 finding, not 3");
        assert_eq!(wp4[0].occurrences.len(), 3);
        assert_eq!(report.risk_score, 10); // counted once
    }

    #[test]
    fn different_rules_same_file_are_separate_findings() {
        let dir = make_temp_dir("multirule");
        fs::write(dir.join("test.php"), "<?php\neval($x);\nshell_exec('ls');\n").unwrap();
        let report = Scanner::new().scan_directory(&dir);
        fs::remove_dir_all(&dir).unwrap();
        assert_eq!(report.total_findings, 2);
    }

    // ── Other behaviour tests ─────────────────────────────────────────────────

    #[test]
    fn ignores_non_php_files() {
        let dir = make_temp_dir("ext");
        fs::write(dir.join("test.txt"), "eval($code);").unwrap();
        fs::write(dir.join("test.js"), "eval(code);").unwrap();
        let report = Scanner::new().scan_directory(&dir);
        fs::remove_dir_all(&dir).unwrap();
        assert_eq!(report.total_files_scanned, 0);
        assert_eq!(report.total_findings, 0);
    }

    #[test]
    fn matched_line_is_captured() {
        let dir = make_temp_dir("mline");
        fs::write(dir.join("test.php"), "<?php\neval($code);\n").unwrap();
        let report = Scanner::new().scan_directory(&dir);
        fs::remove_dir_all(&dir).unwrap();
        let f = report.findings.iter().find(|f| f.rule_id == "WP-004").unwrap();
        assert!(f.occurrences[0].matched_line.contains("eval"));
    }

    #[test]
    fn line_number_is_correct() {
        let dir = make_temp_dir("lnum");
        fs::write(dir.join("test.php"), "<?php\n// comment\neval($code);\n").unwrap();
        let report = Scanner::new().scan_directory(&dir);
        fs::remove_dir_all(&dir).unwrap();
        let f = report.findings.iter().find(|f| f.rule_id == "WP-004").unwrap();
        assert_eq!(f.occurrences[0].line_number, 3);
    }

    #[test]
    fn no_false_positive_on_safe_code() {
        let dir = make_temp_dir("safe");
        fs::write(dir.join("test.php"), "<?php\n// safe file\n$x = 1 + 2;\necho 'hello';\n").unwrap();
        let report = Scanner::new().scan_directory(&dir);
        fs::remove_dir_all(&dir).unwrap();
        assert_eq!(report.total_findings, 0);
    }

    // ── WP-010: SQLi via variable argument ────────────────────────────────────

    #[test]
    fn detects_sqli_variable_argument() {
        let dir = make_temp_dir("sqlivar");
        fs::write(dir.join("test.php"), "<?php\n$wpdb->query($sql);\n").unwrap();
        let report = Scanner::new().scan_directory(&dir);
        fs::remove_dir_all(&dir).unwrap();
        assert!(report.findings.iter().any(|f| f.rule_id == "WP-010"));
    }

    #[test]
    fn suppresses_sqli_variable_arg_when_prepare_present() {
        let dir = make_temp_dir("sqliprep");
        fs::write(
            dir.join("test.php"),
            "<?php\n$wpdb->query($wpdb->prepare('SELECT * FROM t WHERE id=%d', $id));\n",
        )
        .unwrap();
        let report = Scanner::new().scan_directory(&dir);
        fs::remove_dir_all(&dir).unwrap();
        assert!(!report.findings.iter().any(|f| f.rule_id == "WP-010"));
    }

    // ── WP-011: SQLi via string concatenation ─────────────────────────────────

    #[test]
    fn detects_sqli_string_concatenation() {
        let dir = make_temp_dir("sqlicat");
        fs::write(
            dir.join("test.php"),
            "<?php\n$wpdb->query(\"SELECT * FROM \" . $table . \" WHERE id=\" . $_GET['id']);\n",
        )
        .unwrap();
        let report = Scanner::new().scan_directory(&dir);
        fs::remove_dir_all(&dir).unwrap();
        assert!(report.findings.iter().any(|f| f.rule_id == "WP-011"));
    }

    #[test]
    fn suppresses_sqli_concatenation_when_prepare_present() {
        let dir = make_temp_dir("sqlicatprep");
        fs::write(
            dir.join("test.php"),
            "<?php\n$wpdb->get_results($wpdb->prepare(\"SELECT * FROM \" . $table . \" WHERE id=%d\", $id));\n",
        )
        .unwrap();
        let report = Scanner::new().scan_directory(&dir);
        fs::remove_dir_all(&dir).unwrap();
        assert!(!report.findings.iter().any(|f| f.rule_id == "WP-011"));
    }

    // ── WP-012: SSRF via wp_remote functions ──────────────────────────────────

    #[test]
    fn detects_ssrf_via_wp_remote_get() {
        let dir = make_temp_dir("ssrf");
        fs::write(dir.join("test.php"), "<?php\n$response = wp_remote_get($url);\n").unwrap();
        let report = Scanner::new().scan_directory(&dir);
        fs::remove_dir_all(&dir).unwrap();
        assert!(report.findings.iter().any(|f| f.rule_id == "WP-012"));
    }

    #[test]
    fn detects_ssrf_via_wp_remote_post() {
        let dir = make_temp_dir("ssrfpost");
        fs::write(dir.join("test.php"), "<?php\nwp_remote_post($endpoint, $args);\n").unwrap();
        let report = Scanner::new().scan_directory(&dir);
        fs::remove_dir_all(&dir).unwrap();
        assert!(report.findings.iter().any(|f| f.rule_id == "WP-012"));
    }

    #[test]
    fn suppresses_ssrf_when_url_validated_same_line() {
        let dir = make_temp_dir("ssrfsafe");
        // esc_url validates the URL on the same line before the remote call.
        fs::write(
            dir.join("test.php"),
            "<?php\n$safe = esc_url($url); wp_remote_get($safe);\n",
        )
        .unwrap();
        let report = Scanner::new().scan_directory(&dir);
        fs::remove_dir_all(&dir).unwrap();
        assert!(!report.findings.iter().any(|f| f.rule_id == "WP-012"));
    }
}
