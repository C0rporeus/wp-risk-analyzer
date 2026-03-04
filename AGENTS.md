# AGENTS.md — WordPress Risk Analyzer

Guía de contexto, arquitectura y trabajo pendiente para agentes de IA y colaboradores.

---

## Qué es este proyecto

`wp-risk-analyzer` es una herramienta CLI en **Rust** para SAST (Static Application Security Testing) de plugins y temas de WordPress. Su propósito es actuar como **puerta de entrada en el pipeline CI** antes de que un plugin de terceros sea empaquetado en una imagen Docker corporativa.

Posición correcta en el pipeline: **Capa 1 — filtro rápido de alta confianza**. No es un sustituto de PHPCS Security Audit ni Semgrep, sino el paso previo que no requiere runtime de PHP ni configuración adicional.

Origen: ADR `docs/adrs/0001-static-analysis.md`.

---

## Estructura del proyecto

```
Cargo.toml
src/
  main.rs      — Entrypoint CLI (clap): --target, --format, --fail-on-score, --fail-on-critical
  rules.rs     — RiskLevel, Rule (con suppression), get_default_rules() — 12 reglas
  scanner.rs   — Scanner: compila regex + suppression en init, recorre .php con walkdir
  report.rs    — ScanReport, Finding, Occurrence + has_critical()
  sarif.rs     — Generador SARIF 2.1.0 (GitHub/GitLab/SonarQube compatible)
docs/
  adrs/
    0001-static-analysis.md  — Decisión de arquitectura fundacional
.github/
  workflows/ci.yml           — fmt check → cargo test → release build → artifact upload
```

---

## Comandos

```bash
# Desarrollo
cargo build --release                 # Binario en target/release/
cargo fmt                             # Formatear código
cargo clippy                          # Linter
cargo test --verbose                  # 44 tests

# Uso
cargo run -- --target ./mi-plugin --format text
cargo run -- --target ./mi-plugin --format json
cargo run -- --target ./mi-plugin --format sarif   # SARIF 2.1.0 para GitHub/GitLab

# Gates de CI
cargo run -- --target ./mi-plugin --fail-on-score 20    # exit 2 si score >= 20
cargo run -- --target ./mi-plugin --fail-on-critical     # exit 2 si hay cualquier Critical
cargo run -- --target ./mi-plugin --fail-on-critical --fail-on-score 14  # ambos
```

### Exit codes

| Código | Significado |
|--------|-------------|
| 0 | Escaneo completado, ningún gate disparado |
| 1 | Error de herramienta (directorio inválido, etc.) |
| 2 | Gate disparado: score >= threshold **o** Critical detectado |

### Integración GitHub Actions (ejemplo)

```yaml
- name: WP Risk Analyzer
  run: |
    ./wp-risk-analyzer --target ./plugins/my-plugin \
      --format sarif \
      --fail-on-critical \
      > results.sarif
- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: results.sarif
```

---

## Arquitectura

### Flujo de ejecución

```
main() → Scanner::new()
           └─ get_default_rules()
           └─ Regex::new(rule.pattern) × N       [compilación única]
           └─ Regex::new(rule.suppression) × M   [opcional por regla]
         → scanner.scan_directory(path)
           └─ WalkDir → filtro .php
           └─ scan_file() por cada archivo
               └─ BufReader línea a línea
               └─ re.is_match(line) × N reglas
                   └─ if suppression.is_match(line) → skip
                   └─ report.add_occurrence()
                       └─ busca (rule_id, file_path) → append Occurrence
                       └─ si no existe → nuevo Finding, +score una vez
         → output: text | json | sarif
         → --fail-on-critical: exit(2) si has_critical()
         → --fail-on-score:    exit(2) si risk_score >= threshold
```

### Modelo de datos

```
ScanReport
  ├─ total_files_scanned: usize
  ├─ total_findings: usize        — pares (rule_id, file_path) únicos
  ├─ risk_score: u32              — score acumulado por finding único (no por ocurrencia)
  └─ findings: Vec<Finding>
       ├─ rule_id, rule_name, file_path, risk_level
       └─ occurrences: Vec<Occurrence>
            ├─ line_number: usize
            └─ matched_line: String
```

### Scoring de riesgo

| RiskLevel | Score | SARIF level |
|-----------|-------|-------------|
| Critical  | 10    | error       |
| High      | 7     | warning     |
| Medium    | 4     | warning     |
| Low       | 1     | note        |

- `risk_score` se acumula una vez por `(rule_id, file_path)` único.
- Umbrales de color text: `> 20` → rojo · `> 0` → amarillo · `= 0` → verde

### Reglas actuales (12)

| ID     | Vulnerabilidad                              | Nivel    | Suppression                         |
|--------|---------------------------------------------|----------|-------------------------------------|
| WP-001 | `$_GET`/`$_POST` directo                    | High     | sanitize_text_field, absint, esc_*… |
| WP-002 | `shell_exec`, `exec`, `system`…             | Critical | No                                  |
| WP-003 | `$wpdb->query("SELECT…")` literal          | Critical | No                                  |
| WP-004 | `eval()`                                    | Critical | No                                  |
| WP-005 | `include`/`require` con variable            | High     | No                                  |
| WP-006 | `echo $_GET/POST/REQUEST/COOKIE`            | Critical | No                                  |
| WP-007 | `unserialize()`                             | Critical | No                                  |
| WP-008 | `wp_redirect($var)`                         | Medium   | No                                  |
| WP-009 | `file_put_contents/fwrite($var)`            | High     | No                                  |
| WP-010 | `$wpdb->query($var)` — variable directa    | Critical | `->prepare(`                        |
| WP-011 | `$wpdb->query(…. $var)` — concatenación   | Critical | `->prepare(`                        |
| WP-012 | `wp_remote_get/post($var)` — SSRF          | High     | esc_url, wp_http_validate_url       |

#### Para agregar una regla

Añadir `Rule { id, name, description, level, pattern, suppression }` en `rules::get_default_rules()`.

- IDs: formato `WP-NNN` secuencial
- `pattern`: regex RE2 — sin lookaheads/lookbehinds
- `suppression`: `Some("regex")` si hay indicador de uso seguro en la misma línea; `None` si no aplica
- Toda nueva regla requiere test de true positive + true negative en `scanner::tests`

---

## Tests — 44 en total

| Módulo  | Tests | Qué cubren |
|---------|-------|------------|
| `rules`  | 5  | Regex válidos, suppression válidos, scores, IDs únicos, campos no vacíos |
| `report` | 8  | Estado inicial, dedup, distintos archivos, score acumulado, ocurrencias, has_critical (true/false/empty) |
| `sarif`  | 6  | Schema/versión, count por ocurrencia, nivel Critical→error, URI relativa, originalUriBaseIds, line numbers |
| `scanner`| 25 | True positive por regla (WP-001..012), supresiones (sanitize, absint, prepare×2, esc_url), dedup, multi-regla, filtro extensión, matched_line, line_number, código seguro |

---

## CI Pipeline (`.github/workflows/ci.yml`)

1. `cargo fmt -- --check`
2. `cargo test --verbose`
3. `cargo build --release --verbose`
4. Upload artifact `wp-risk-analyzer-linux`

Trigger: push y PR a `main`.

---

## Pendientes y deuda técnica

### Completados

- [x] Exit code `--fail-on-score <N>` (exit 2 si `score >= N`)
- [x] `--fail-on-critical` (exit 2 si cualquier Critical, independiente del score)
- [x] Bug semántico `>` → `>=` en comparación de threshold
- [x] SARIF 2.1.0 output (`--format sarif`) con URIs relativas, originalUriBaseIds, líneas por ocurrencia
- [x] matched_line en cada ocurrencia (texto y JSON y SARIF snippet)
- [x] Deduplicación por `(rule_id, file_path)` con `Vec<Occurrence>`
- [x] Supresión de falsos positivos WP-001 vía campo `suppression`
- [x] WP-010: SQLi via variable como argumento directo (suppression: `->prepare`)
- [x] WP-011: SQLi via concatenación de strings (suppression: `->prepare`)
- [x] WP-012: SSRF via wp_remote functions (suppression: esc_url/wp_http_validate_url)
- [x] 44 tests, 0 fallos, 0 warnings

### Pendientes — cobertura de reglas

- [ ] **Nonce verification (CSRF)**: `$_POST` sin `wp_verify_nonce` en el mismo contexto. Requiere análisis multi-línea — no resolvible con regex de una sola línea.
- [ ] **Capability check**: `current_user_can()` ausente antes de operaciones privilegiadas. Misma limitación.

### Pendientes — integración y operaciones

- [ ] **Ignore file (`.wp-risk-ignore`)**: suprimir FP conocidos persistentemente por `rule_id:file_path`. Sin esto, teams con patrones intencionados (e.g., `eval` en licenciamiento) reciben ruido constante.
- [ ] **Scan de múltiples targets en una sola invocación**: actualmente requiere scripting externo en CI para escanear un directorio de 20 plugins.

### Largo plazo — del ADR

- [ ] **Parseo AST con `tree-sitter`**: resolver falsos negativos de SQLi por concatenación multi-línea, CSRF/capability checks, XSS indirecta. Dependencias: `tree-sitter` + `tree-sitter-php`.
- [ ] **Concurrencia con `rayon`**: paralelizar `scan_file()` por archivo para plugins grandes.
- [ ] **Configuración externa de reglas**: cargar desde YAML/TOML sin recompilar.

---

## Convenciones

- `rules.rs` centraliza todas las reglas. No hardcodear patrones en `scanner.rs`.
- IDs de regla: `WP-NNN` tres dígitos, secuencial.
- Regex RE2 — sin lookaheads. Validar con `Regex::new()` en tests.
- Suppression patterns: conservadores, solo suprimir cuando la línea evidencia claramente uso seguro.
- Toda nueva regla requiere test de true positive + true negative en `scanner::tests`.
- SARIF: una entrada por `Occurrence`, no por `Finding` — para anotación por línea en PRs.
