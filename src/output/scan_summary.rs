use colored::Colorize;

use crate::types::{AnalysisReport, RiskLabel};

/// Bucket counts by risk label.
pub struct RiskBuckets {
    pub critical: Vec<AnalysisReport>,
    pub high: Vec<AnalysisReport>,
    pub medium: Vec<AnalysisReport>,
    pub clean: Vec<AnalysisReport>, // Clean + Low
}

pub fn bucket_reports(reports: &[AnalysisReport]) -> RiskBuckets {
    let mut b = RiskBuckets {
        critical: Vec::new(),
        high: Vec::new(),
        medium: Vec::new(),
        clean: Vec::new(),
    };
    for r in reports {
        match r.risk_label {
            RiskLabel::Critical => b.critical.push(r.clone()),
            RiskLabel::High => b.high.push(r.clone()),
            RiskLabel::Medium => b.medium.push(r.clone()),
            RiskLabel::Low | RiskLabel::Clean => b.clean.push(r.clone()),
        }
    }
    b
}

pub fn print_scan_summary(reports: &[AnalysisReport], errors: &[(String, String)]) {
    let b = bucket_reports(reports);

    println!();
    if !b.critical.is_empty() {
        println!(
            "  \u{26d4} {} critical",
            b.critical.len().to_string().red().bold()
        );
    }
    if !b.high.is_empty() {
        println!(
            "  \u{26a0}\u{fe0f}  {} high risk",
            b.high.len().to_string().red()
        );
    }
    if !b.medium.is_empty() {
        println!(
            "  \u{26a1} {} medium risk",
            b.medium.len().to_string().yellow()
        );
    }
    println!("  \u{2705} {} clean", b.clean.len().to_string().green());
    if !errors.is_empty() {
        println!("  \u{274c} {} failed", errors.len().to_string().red());
    }
    println!();

    // Detailed lists for critical and high.
    if !b.critical.is_empty() {
        println!("  {}:", "CRITICAL".red().bold());
        print_report_list(&b.critical);
        println!();
    }

    if !b.high.is_empty() {
        println!("  {}:", "HIGH".red());
        print_report_list(&b.high);
        println!();
    }

    if !b.medium.is_empty() {
        println!("  {}:", "MEDIUM".yellow());
        print_report_list(&b.medium);
        println!();
    }

    if !errors.is_empty() {
        println!("  {}:", "ERRORS".red());
        for (i, (name, err)) in errors.iter().enumerate() {
            let connector = if i == errors.len() - 1 {
                "\u{2514}\u{2500}"
            } else {
                "\u{251c}\u{2500}"
            };
            println!("  {} {} \u{2014} {}", connector, name.bold(), err.dimmed());
        }
        println!();
    }

    println!(
        "  Full results: {} for details",
        "aegis check <package>".bold()
    );
    println!();
}

pub fn print_report_list(reports: &[AnalysisReport]) {
    for (i, r) in reports.iter().enumerate() {
        let connector = if i == reports.len() - 1 {
            "\u{2514}\u{2500}"
        } else {
            "\u{251c}\u{2500}"
        };

        // Build a short description from the top finding(s).
        let desc = if r.findings.is_empty() {
            "no details".to_string()
        } else {
            // Summarize the top 1-2 finding titles.
            let summaries: Vec<&str> = r
                .findings
                .iter()
                .take(2)
                .map(|f| f.title.as_str())
                .collect();
            summaries.join(", ")
        };

        println!(
            "  {} {}@{} \u{2014} {} ({:.1}/10)",
            connector,
            r.package_name.bold(),
            r.version,
            desc,
            r.risk_score
        );
    }
}
