use std::io::Write;
use std::path::PathBuf;

use anyhow::{Context, Result};
use colored::Colorize;

use crate::cli::{clean_version_spec, collect_dependencies, parse_package_specifier};
use crate::output;
use crate::pipeline::analyze_package;
use crate::types::{AnalysisReport, RiskLabel};

use super::super::output::scan_summary::print_scan_summary;

/// Prompt the user for y/N confirmation. Returns true if the user types "y" or
/// "yes" (case-insensitive). Defaults to No on empty input.
pub fn confirm(prompt: &str) -> bool {
    eprint!("{}", prompt);
    std::io::stderr().flush().ok();
    let mut input = String::new();
    if std::io::stdin().read_line(&mut input).is_err() {
        return false;
    }
    matches!(input.trim().to_lowercase().as_str(), "y" | "yes")
}

/// Run `npm install` with optional package arguments. Returns the exit status.
pub fn run_npm_install(packages: &[String]) -> Result<()> {
    let mut cmd = std::process::Command::new("npm");
    cmd.arg("install");
    for pkg in packages {
        cmd.arg(pkg);
    }

    eprintln!("\n\u{1f4e6} Running: npm install {}\n", packages.join(" "));

    let status = cmd
        .status()
        .context("failed to run `npm install` — is npm installed and on PATH?")?;

    if !status.success() {
        anyhow::bail!("`npm install` exited with status {}", status);
    }

    Ok(())
}

pub async fn run_install(
    packages: &[String],
    force: bool,
    skip_dev: bool,
    no_cache: bool,
) -> Result<()> {
    let use_cache = !no_cache;

    if packages.is_empty() {
        // ---- No explicit packages: scan the whole project, then npm install ----
        let project_path = PathBuf::from(".");
        let deps = collect_dependencies(&project_path, skip_dev)?;
        let total = deps.len();

        if total == 0 {
            eprintln!("No dependencies found in package.json — running npm install directly.");
            return run_npm_install(&[]);
        }

        eprintln!(
            "\n\u{1f50d} Scanning {} dependencies before install...\n",
            total
        );

        let mut reports: Vec<AnalysisReport> = Vec::new();
        let mut errors: Vec<(String, String)> = Vec::new();

        for (i, (name, version_spec)) in deps.iter().enumerate() {
            let idx = i + 1;
            let version_hint = clean_version_spec(version_spec);
            let display_ver = version_hint.as_deref().unwrap_or("latest");
            let prefix = format!("  [{}/{}] ", idx, total);

            eprintln!(
                "  [{}/{}] Checking {}@{}...",
                idx,
                total,
                name.bold(),
                display_ver
            );

            match analyze_package(name, version_hint.as_deref(), use_cache, &prefix, None).await {
                Ok(report) => reports.push(report),
                Err(e) => {
                    eprintln!(
                        "  [{}/{}] \u{274c} Failed to analyze {}: {:#}",
                        idx, total, name, e
                    );
                    errors.push((name.clone(), format!("{:#}", e)));
                }
            }
        }

        // Show summary.
        print_scan_summary(&reports, &errors);

        let risky: Vec<&AnalysisReport> = reports
            .iter()
            .filter(|r| matches!(r.risk_label, RiskLabel::High | RiskLabel::Critical))
            .collect();

        if !risky.is_empty() && !force {
            eprintln!(
                "\u{26a0}\u{fe0f} {} package(s) rated HIGH or CRITICAL risk:",
                risky.len()
            );
            for r in &risky {
                eprintln!(
                    "  - {}@{} ({}, {:.1}/10)",
                    r.package_name.bold(),
                    r.version,
                    r.risk_label,
                    r.risk_score
                );
            }
            eprintln!();

            if !confirm("Proceed with npm install anyway? [y/N] ") {
                eprintln!("Aborted.");
                std::process::exit(1);
            }
        }

        run_npm_install(&[])
    } else {
        // ---- Explicit packages: check each, then npm install the approved set ----
        let mut approved: Vec<String> = Vec::new();
        let prefix = "  \u{1f50d} ";

        for spec in packages {
            let (name, version) = parse_package_specifier(spec);

            eprintln!("\n\u{1f50d} Checking {} before install...\n", spec.bold());

            let report =
                match analyze_package(&name, version.as_deref(), use_cache, prefix, None).await {
                    Ok(r) => r,
                    Err(e) => {
                        eprintln!("\u{274c} Failed to analyze {}: {:#}", spec, e);
                        // If analysis fails, still ask whether to install.
                        if force
                            || confirm(&format!(
                                "Could not analyze {}. Install anyway? [y/N] ",
                                spec
                            ))
                        {
                            approved.push(spec.clone());
                        }
                        continue;
                    }
                };

            output::terminal::print_report(&report);

            let is_risky = matches!(report.risk_label, RiskLabel::High | RiskLabel::Critical);

            if is_risky && !force {
                let prompt = format!(
                    "\n\u{26a0}\u{fe0f}  {} has {} ({:.1}/10). Install anyway? [y/N] ",
                    spec.bold(),
                    report.risk_label.to_string().red(),
                    report.risk_score
                );
                if !confirm(&prompt) {
                    eprintln!("Skipping {}.", spec);
                    continue;
                }
            }

            approved.push(spec.clone());
        }

        if approved.is_empty() {
            eprintln!("No packages approved for installation.");
            return Ok(());
        }

        run_npm_install(&approved)
    }
}
