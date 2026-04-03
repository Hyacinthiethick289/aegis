use colored::Colorize;

use crate::types::{AnalysisReport, Finding, RiskLabel, Severity};

/// Print a human-readable, tree-style security report to the terminal.
pub fn print_report(report: &AnalysisReport) {
    println!();
    println!(
        "  \u{1f4e6} {}@{}",
        report.package_name.bold(),
        report.version
    );
    println!();

    if report.findings.is_empty() {
        println!("  \u{2705} {}", "Clean — no issues found".green());
        println!();
        print_risk_line(report.risk_score, &report.risk_label);
        println!();
        return;
    }

    for finding in &report.findings {
        print_finding(finding);
    }

    print_risk_line(report.risk_score, &report.risk_label);
    println!();
}

fn print_finding(f: &Finding) {
    let (icon, styled_header) = match f.severity {
        Severity::Critical => (
            "\u{26d4}",
            format!("CRITICAL — {}", f.category)
                .red()
                .bold()
                .to_string(),
        ),
        Severity::High => (
            "\u{26a0}\u{fe0f} ",
            format!("HIGH — {}", f.category).red().to_string(),
        ),
        Severity::Medium => (
            "\u{26a0}\u{fe0f} ",
            format!("MEDIUM — {}", f.category).yellow().to_string(),
        ),
        Severity::Low => (
            "\u{2139}\u{fe0f} ",
            format!("LOW — {}", f.category).blue().to_string(),
        ),
        Severity::Info => (
            "\u{2139}\u{fe0f} ",
            format!("INFO — {}", f.category).green().to_string(),
        ),
    };

    println!("  {} {}", icon, styled_header);
    println!("  {}  {}", "\u{2502}".dimmed(), f.description);

    if let Some(ref file) = f.file {
        let location = match f.line {
            Some(line) => format!("{}:{}", file, line),
            None => file.clone(),
        };
        println!("  {}  \u{1f4c4} {}", "\u{2502}".dimmed(), location.dimmed());
    }

    if let Some(ref snippet) = f.snippet {
        println!(
            "  {}  {} {}",
            "\u{2502}".dimmed(),
            "\u{2514}\u{2500}".dimmed(),
            snippet.dimmed()
        );
    }

    println!();
}

fn print_risk_line(score: f64, label: &RiskLabel) {
    let score_str = format!("{:.1}/10", score);
    let colored_score = if score < 3.0 {
        score_str.green()
    } else if score <= 7.0 {
        score_str.yellow()
    } else {
        score_str.red()
    };

    let label_str = format!("{}", label);
    let colored_label = match label {
        RiskLabel::Clean => label_str.green().bold(),
        RiskLabel::Low => label_str.green().bold(),
        RiskLabel::Medium => label_str.yellow().bold(),
        RiskLabel::High => label_str.red().bold(),
        RiskLabel::Critical => label_str.red().bold(),
    };

    println!("  Risk: {} — {}", colored_score, colored_label);
}
