use serde::Serialize;

#[derive(Debug, Serialize, Clone)]
pub enum RiskLevel {
    Critical,
    High,
    Medium,
    #[allow(dead_code)]
    Low,
}

impl RiskLevel {
    pub fn score(&self) -> u32 {
        match self {
            RiskLevel::Critical => 10,
            RiskLevel::High => 7,
            RiskLevel::Medium => 4,
            RiskLevel::Low => 1,
        }
    }
}

#[derive(Debug, Clone)]
pub struct Rule {
    pub id: &'static str,
    pub name: &'static str,
    /// Used in SARIF fullDescription and as human-readable context.
    pub description: &'static str,
    pub level: RiskLevel,
    pub pattern: &'static str,
    /// If a matched line also matches this pattern the finding is suppressed
    /// (same-line safe usage detected). Uses RE2 syntax — no lookaheads.
    pub suppression: Option<&'static str>,
}

pub fn get_default_rules() -> Vec<Rule> {
    vec![
        // ── Input handling ────────────────────────────────────────────────────
        Rule {
            id: "WP-001",
            name: "Direct $_GET/$_POST Usage",
            description: "Direct usage of superglobal input without sanitization. Suppressed when a known WP sanitization function wraps it on the same line.",
            level: RiskLevel::High,
            pattern: r#"(?i)(\$_GET|\$_POST|\$_REQUEST)\["#,
            suppression: Some(
                r#"(?i)(sanitize_text_field|absint|intval|floatval|esc_attr|esc_html|esc_url|wp_kses|wp_kses_post|sanitize_email|sanitize_key|sanitize_url)\s*\("#,
            ),
        },
        // ── Code execution ────────────────────────────────────────────────────
        Rule {
            id: "WP-002",
            name: "System Command Execution",
            description: "Functions capable of executing OS commands (shell_exec, exec, system, passthru, popen, proc_open). Near-zero legitimate use in plugins.",
            level: RiskLevel::Critical,
            pattern: r#"(?i)\b(shell_exec|exec|system|passthru|popen|proc_open)\s*\("#,
            suppression: None,
        },
        Rule {
            id: "WP-004",
            name: "Eval Usage",
            description: "eval() executes arbitrary PHP code. Commonly used in backdoors and obfuscated malware droppers.",
            level: RiskLevel::Critical,
            pattern: r#"(?i)\beval\s*\("#,
            suppression: None,
        },
        // ── SQL Injection ─────────────────────────────────────────────────────
        Rule {
            id: "WP-003",
            name: "Unprepared SQL Query (literal string)",
            description: "A $wpdb query method is called with a SQL keyword string literal directly as argument, bypassing $wpdb->prepare().",
            level: RiskLevel::Critical,
            pattern: r#"(?i)\$wpdb->(query|get_results|get_var|get_row|get_col)\s*\(\s*["'](SELECT|INSERT|UPDATE|DELETE|REPLACE)"#,
            suppression: None,
        },
        Rule {
            id: "WP-010",
            name: "Unprepared SQL Query (variable argument)",
            description: "A $wpdb query method receives a variable as its first argument without visible $wpdb->prepare() on the same line. The variable may have been built insecurely.",
            level: RiskLevel::Critical,
            pattern: r#"(?i)\$wpdb->(query|get_results|get_var|get_row|get_col)\s*\(\s*\$"#,
            suppression: Some(r#"(?i)->prepare\s*\("#),
        },
        Rule {
            id: "WP-011",
            name: "Unprepared SQL Query (string concatenation)",
            description: "A $wpdb query method call contains string concatenation with a variable (. $var), indicating the SQL may be built unsafely without prepare().",
            level: RiskLevel::Critical,
            pattern: r#"(?i)\$wpdb->(query|get_results|get_var|get_row|get_col)\s*\([^;]*\s*\.\s*\$"#,
            suppression: Some(r#"(?i)->prepare\s*\("#),
        },
        // ── File operations ───────────────────────────────────────────────────
        Rule {
            id: "WP-005",
            name: "File Inclusion from Variable",
            description: "Dynamic file inclusion (include/require) with a variable path enables Local/Remote File Inclusion (LFI/RFI).",
            level: RiskLevel::High,
            pattern: r#"(?i)\b(include|include_once|require|require_once)\s*\(?\s*\$"#,
            suppression: None,
        },
        Rule {
            id: "WP-009",
            name: "Arbitrary File Write",
            description: "file_put_contents() or fwrite() with a variable as the first argument can allow writing to arbitrary paths on the filesystem.",
            level: RiskLevel::High,
            pattern: r#"(?i)\b(file_put_contents|fwrite)\s*\(\s*\$"#,
            suppression: None,
        },
        // ── Output / XSS ─────────────────────────────────────────────────────
        Rule {
            id: "WP-006",
            name: "Unescaped Output (XSS)",
            description: "Direct echo of a superglobal without escaping (esc_html, esc_attr, wp_kses). Trivially exploitable reflected XSS.",
            level: RiskLevel::Critical,
            pattern: r#"(?i)\becho\s+\$_(GET|POST|REQUEST|COOKIE)"#,
            suppression: None,
        },
        // ── Deserialization ───────────────────────────────────────────────────
        Rule {
            id: "WP-007",
            name: "Unsafe unserialize()",
            description: "Calling unserialize() on untrusted data enables PHP Object Injection, which can escalate to Remote Code Execution.",
            level: RiskLevel::Critical,
            pattern: r#"(?i)\bunserialize\s*\("#,
            suppression: None,
        },
        // ── Redirects ─────────────────────────────────────────────────────────
        Rule {
            id: "WP-008",
            name: "Open Redirect via wp_redirect",
            description: "wp_redirect() with a variable argument allows open redirects. Use wp_safe_redirect() or validate the URL with wp_http_validate_url() first.",
            level: RiskLevel::Medium,
            pattern: r#"(?i)\bwp_redirect\s*\(\s*\$"#,
            suppression: None,
        },
        // ── SSRF ──────────────────────────────────────────────────────────────
        Rule {
            id: "WP-012",
            name: "SSRF via wp_remote Functions",
            description: "wp_remote_get/post/request/head with a variable URL argument. If the URL derives from user input, an attacker can probe internal services (SSRF).",
            level: RiskLevel::High,
            pattern: r#"(?i)\bwp_remote_(get|post|request|head)\s*\(\s*\$"#,
            suppression: Some(r#"(?i)(esc_url|wp_http_validate_url|filter_var)\s*\("#),
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use regex::Regex;
    use std::collections::HashSet;

    #[test]
    fn all_rules_have_valid_regex() {
        for rule in get_default_rules() {
            assert!(
                Regex::new(rule.pattern).is_ok(),
                "Rule {} has an invalid regex pattern: {}",
                rule.id,
                rule.pattern
            );
        }
    }

    #[test]
    fn all_suppression_patterns_are_valid_regex() {
        for rule in get_default_rules() {
            if let Some(supp) = rule.suppression {
                assert!(
                    Regex::new(supp).is_ok(),
                    "Rule {} has an invalid suppression pattern: {}",
                    rule.id,
                    supp
                );
            }
        }
    }

    #[test]
    fn risk_scores_are_correct() {
        assert_eq!(RiskLevel::Critical.score(), 10);
        assert_eq!(RiskLevel::High.score(), 7);
        assert_eq!(RiskLevel::Medium.score(), 4);
        assert_eq!(RiskLevel::Low.score(), 1);
    }

    #[test]
    fn rules_have_unique_ids() {
        let rules = get_default_rules();
        let unique: HashSet<&str> = rules.iter().map(|r| r.id).collect();
        assert_eq!(unique.len(), rules.len(), "Rule IDs must be unique");
    }

    #[test]
    fn all_rules_have_non_empty_fields() {
        for rule in get_default_rules() {
            assert!(!rule.id.is_empty(), "Rule has empty id");
            assert!(!rule.name.is_empty(), "Rule {} has empty name", rule.id);
            assert!(!rule.description.is_empty(), "Rule {} has empty description", rule.id);
            assert!(!rule.pattern.is_empty(), "Rule {} has empty pattern", rule.id);
        }
    }
}
