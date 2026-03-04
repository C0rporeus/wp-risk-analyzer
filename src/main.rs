mod rules;
mod report;
mod scanner;
mod sarif;

use clap::Parser;
use std::path::PathBuf;
use colored::*;

#[derive(Parser, Debug)]
#[command(author, version, about = "WordPress Static Application Security Testing (SAST) Tool")]
struct Args {
    /// Path to the WordPress plugin/theme directory to scan
    #[arg(short, long)]
    target: PathBuf,

    /// Output format: text (default), json, or sarif (SARIF 2.1.0 for CI/GitHub/GitLab)
    #[arg(short, long, default_value = "text")]
    format: String,

    /// Exit with code 2 if risk_score >= this threshold (cumulative score gate)
    #[arg(long)]
    fail_on_score: Option<u32>,

    /// Exit with code 2 if any Critical finding is detected, regardless of total score
    #[arg(long)]
    fail_on_critical: bool,
}

fn main() {
    let args = Args::parse();

    if !args.target.exists() || !args.target.is_dir() {
        eprintln!("{}", "Error: Target must be a valid directory.".red());
        std::process::exit(1);
    }

    let scanner = scanner::Scanner::new();
    let report = scanner.scan_directory(&args.target);

    match args.format.to_lowercase().as_str() {
        "json" => {
            match serde_json::to_string_pretty(&report) {
                Ok(json) => println!("{}", json),
                Err(e) => eprintln!("Error generating JSON: {}", e),
            }
        }
        "sarif" => {
            let output = sarif::generate(&report);
            match serde_json::to_string_pretty(&output) {
                Ok(json) => println!("{}", json),
                Err(e) => eprintln!("Error generating SARIF: {}", e),
            }
        }
        _ => {
            let total_occurrences: usize =
                report.findings.iter().map(|f| f.occurrences.len()).sum();

            println!("{}", "==================================================".bold());
            println!("  {}", "WordPress Risk Analyzer - Security Report".cyan().bold());
            println!("{}", "==================================================".bold());
            println!("Target Directory: {}", report.target_directory);
            println!("Files Scanned:    {}", report.total_files_scanned);
            println!(
                "Findings:         {} unique ({} total occurrences)",
                report.total_findings, total_occurrences
            );
            println!(
                "Overall Risk Score: {}",
                if report.risk_score > 20 {
                    report.risk_score.to_string().red().bold()
                } else if report.risk_score > 0 {
                    report.risk_score.to_string().yellow().bold()
                } else {
                    report.risk_score.to_string().green().bold()
                }
            );
            println!("{}", "==================================================".bold());

            if report.findings.is_empty() {
                println!("\n{}", "No obvious vulnerabilities found. Good job!".green());
            } else {
                println!("\n{}", "Findings:".bold());
                for finding in &report.findings {
                    let risk_color = match finding.risk_level {
                        rules::RiskLevel::Critical => {
                            finding.risk_level.score().to_string().red().on_black().bold()
                        }
                        rules::RiskLevel::High => finding.risk_level.score().to_string().red(),
                        rules::RiskLevel::Medium => {
                            finding.risk_level.score().to_string().yellow()
                        }
                        rules::RiskLevel::Low => finding.risk_level.score().to_string().cyan(),
                    };
                    let occ = finding.occurrences.len();
                    println!(
                        "- [{}] {} (Risk: {} | {} occurrence{})",
                        finding.rule_id.bold(),
                        finding.rule_name,
                        risk_color,
                        occ,
                        if occ == 1 { "" } else { "s" }
                    );
                    println!("  File: {}", finding.file_path);
                    for occurrence in &finding.occurrences {
                        println!(
                            "  Line {:>4}: {}",
                            occurrence.line_number,
                            occurrence.matched_line.dimmed()
                        );
                    }
                    println!();
                }
            }
        }
    }

    // ── CI gate checks ────────────────────────────────────────────────────────

    if args.fail_on_critical && report.has_critical() {
        let critical_count = report
            .findings
            .iter()
            .filter(|f| matches!(f.risk_level, rules::RiskLevel::Critical))
            .count();
        eprintln!(
            "{}",
            format!(
                "FAIL: {critical_count} Critical finding(s) detected. Review before deployment."
            )
            .red()
            .bold()
        );
        std::process::exit(2);
    }

    if let Some(threshold) = args.fail_on_score {
        if report.risk_score >= threshold {
            eprintln!(
                "{}",
                format!(
                    "FAIL: Risk score {} meets or exceeds threshold {}. Review findings before deployment.",
                    report.risk_score, threshold
                )
                .red()
                .bold()
            );
            std::process::exit(2);
        }
    }
}
