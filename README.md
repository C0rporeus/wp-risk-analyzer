# wp-risk-analyzer

Static Application Security Testing (SAST) CLI for WordPress plugins and themes, written in Rust.

Designed as a **fast, zero-dependency gate** in CI pipelines — runs before PHPCS Security Audit or Semgrep, requires no PHP runtime, and exits with a machine-readable code your pipeline can act on.

---

## Why

Third-party WordPress plugins are a common vector for supply chain attacks. This tool scans plugin source code for high-signal vulnerability patterns before they are packaged into production images, giving security teams a first line of defense without adding CI overhead.

---

## Installation

### From source

```bash
git clone https://github.com/C0rporeus/wp-risk-analyzer.git
cd wp-risk-analyzer
cargo build --release
# Binary: target/release/wp-risk-analyzer
```

### Requirements

- Rust 1.85+ (edition 2024)

---

## Usage

```bash
# Human-readable output (default)
wp-risk-analyzer --target ./plugins/my-plugin

# JSON output (for downstream tooling)
wp-risk-analyzer --target ./plugins/my-plugin --format json

# SARIF 2.1.0 (GitHub Advanced Security, GitLab SAST, SonarQube)
wp-risk-analyzer --target ./plugins/my-plugin --format sarif > results.sarif
```

### CI gates

```bash
# Fail if cumulative risk score >= 20
wp-risk-analyzer --target ./plugins/my-plugin --fail-on-score 20

# Fail if any Critical severity finding is detected
wp-risk-analyzer --target ./plugins/my-plugin --fail-on-critical

# Combine both gates
wp-risk-analyzer --target ./plugins/my-plugin --fail-on-critical --fail-on-score 14
```

### Exit codes

| Code | Meaning |
|------|---------|
| `0`  | Scan completed, no gate triggered |
| `1`  | Tool error (invalid directory, etc.) |
| `2`  | Gate triggered: score ≥ threshold **or** Critical finding detected |

---

## Security Rules

| ID     | Vulnerability                              | Severity | Suppression (same-line) |
|--------|--------------------------------------------|----------|-------------------------|
| WP-001 | Direct `$_GET`/`$_POST` without sanitization | High   | `sanitize_text_field`, `absint`, `intval`, `esc_*`, `wp_kses*` |
| WP-002 | `shell_exec`, `exec`, `system`, `passthru` | Critical | — |
| WP-003 | `$wpdb->query("SELECT…")` literal string   | Critical | — |
| WP-004 | `eval()`                                   | Critical | — |
| WP-005 | `include`/`require` with variable path     | High     | — |
| WP-006 | `echo $_GET/$_POST/$_REQUEST/$_COOKIE`     | Critical | — |
| WP-007 | `unserialize()` — PHP Object Injection     | Critical | — |
| WP-008 | `wp_redirect($var)` — Open Redirect        | Medium   | — |
| WP-009 | `file_put_contents`/`fwrite($var, …)`      | High     | — |
| WP-010 | `$wpdb->query($var)` — variable argument   | Critical | `->prepare(` |
| WP-011 | `$wpdb->query(… . $var)` — concatenation  | Critical | `->prepare(` |
| WP-012 | `wp_remote_get/post($var)` — SSRF          | High     | `esc_url`, `wp_http_validate_url`, `filter_var` |

### Risk scoring

| Severity | Score per unique finding |
|----------|--------------------------|
| Critical | 10 |
| High     | 7  |
| Medium   | 4  |
| Low      | 1  |

Score accumulates once per unique `(rule_id, file_path)` pair — multiple occurrences of the same rule in the same file count as one finding.

---

## Output Formats

### Text

```
==================================================
  WordPress Risk Analyzer - Security Report
==================================================
Target Directory: ./plugins/my-plugin
Files Scanned:    12
Findings:         3 unique (5 total occurrences)
Overall Risk Score: 27
==================================================

Findings:
- [WP-004] Eval Usage (Risk: 10 | 1 occurrence)
  File: ./plugins/my-plugin/includes/loader.php
  Line    8: eval($encoded_payload);

- [WP-010] Unprepared SQL Query (variable argument) (Risk: 10 | 2 occurrences)
  File: ./plugins/my-plugin/admin/queries.php
  Line   14: $wpdb->query($sql);
  Line   31: $wpdb->get_results($user_query);
```

### JSON

Full structured output with all findings, occurrences, line numbers, and matched lines. Pipe to `jq` for filtering.

### SARIF 2.1.0

Compatible with GitHub Advanced Security (inline PR annotations), GitLab SAST, and SonarQube. Each occurrence produces an independent SARIF result with a relative URI and line number.

---

## GitHub Actions Integration

```yaml
- name: WP Risk Analyzer
  run: |
    ./wp-risk-analyzer \
      --target ./plugins/my-plugin \
      --format sarif \
      --fail-on-critical \
      > results.sarif

- name: Upload SARIF to GitHub Security tab
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: results.sarif
  if: always()
```

The `--fail-on-critical` flag causes the step to exit 2 on any Critical finding, blocking the merge. The `if: always()` on the upload step ensures SARIF results are visible in the Security tab even when the scan step fails.

---

## Adding Rules

Rules live in `src/rules.rs`. Add a new entry to `get_default_rules()`:

```rust
Rule {
    id: "WP-013",
    name: "Your Rule Name",
    description: "Human-readable explanation used in SARIF output.",
    level: RiskLevel::High,
    pattern: r#"(?i)\byour_pattern\s*\("#,
    suppression: Some(r#"(?i)safe_wrapper\s*\("#), // or None
},
```

Conventions:
- IDs: `WP-NNN` sequential
- Patterns: RE2 syntax — no lookaheads or lookbehinds
- Suppression: only suppress when the same line clearly demonstrates safe usage
- Every new rule requires a true-positive test and a true-negative (or suppression) test in `scanner::tests`

---

## Development

```bash
cargo fmt           # Format
cargo clippy        # Lint
cargo test          # 44 tests across rules, report, scanner, sarif modules
cargo build --release
```

---

## Architecture

```
main() → Scanner::new()          # compile regex + suppression once
       → scan_directory(path)    # walkdir → .php files only
           → scan_file()         # BufReader line-by-line
               → is_match()      # N rules × M lines
               → suppression?    # skip if safe usage on same line
               → add_occurrence() # dedup by (rule_id, file_path)
       → output: text | json | sarif
       → CI gates: --fail-on-critical, --fail-on-score
```

---

## Limitations

- **Single-line analysis only**: multi-line patterns (e.g., nonce check absent from a surrounding function) require AST-level analysis (`tree-sitter`).
- **No CSRF/capability-check detection**: `wp_verify_nonce` and `current_user_can` absence cannot be detected reliably with line-level regex.
- **Suppression is same-line**: if a sanitization function is called on a previous line, the finding is still reported.

These are known trade-offs. The tool is designed as a high-confidence first filter, not a replacement for PHPCS Security Audit or manual review.

---

## License

MIT
