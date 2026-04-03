use std::path::PathBuf;
use std::sync::OnceLock;

use regex::Regex;

use crate::types::{Finding, FindingCategory, Severity};

use super::{truncate, Analyzer};

/// Scripts in package.json that run during install lifecycle.
const LIFECYCLE_SCRIPTS: &[&str] = &["preinstall", "postinstall", "preuninstall", "prepare"];

fn re_dangerous_cmd() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r#"(?:curl|wget|bash|sh\s+-c|node\s+-e|eval\s|https?://)"#).unwrap()
    })
}

fn re_node_file() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r#"node\s+([^\s;&|]+\.(?:js|cjs|mjs))"#).unwrap())
}

/// Analyzes package.json install scripts for suspicious patterns.
pub struct InstallScriptAnalyzer;

impl Analyzer for InstallScriptAnalyzer {
    fn analyze(
        &self,
        files: &[(PathBuf, String)],
        package_json: &serde_json::Value,
    ) -> Vec<Finding> {
        let mut findings = Vec::new();

        let scripts = match package_json.get("scripts").and_then(|v| v.as_object()) {
            Some(s) => s,
            None => return findings,
        };

        let dangerous = re_dangerous_cmd();

        for &script_name in LIFECYCLE_SCRIPTS {
            let script_value = match scripts.get(script_name).and_then(|v| v.as_str()) {
                Some(s) => s,
                None => continue,
            };

            // CRITICAL: script contains dangerous commands / URLs
            if dangerous.is_match(script_value) {
                findings.push(Finding {
                    severity: Severity::Critical,
                    category: FindingCategory::InstallScript,
                    title: format!("Dangerous command in \"{}\" script", script_name),
                    description: format!(
                        "The \"{}\" script contains a potentially dangerous command (curl, wget, bash, node -e, eval, or a URL)",
                        script_name
                    ),
                    file: Some("package.json".to_string()),
                    line: None,
                    snippet: Some(truncate(script_value, 100)),
                });
            } else {
                // HIGH: any install script at all is unusual
                findings.push(Finding {
                    severity: Severity::High,
                    category: FindingCategory::InstallScript,
                    title: format!("Install lifecycle script \"{}\" present", script_name),
                    description: format!(
                        "The package defines a \"{}\" script. Legitimate packages rarely need install scripts.",
                        script_name
                    ),
                    file: Some("package.json".to_string()),
                    line: None,
                    snippet: Some(truncate(script_value, 100)),
                });
            }

            // MEDIUM: script references a JS file that doesn't exist in the package
            check_missing_script_file(script_value, files, script_name, &mut findings);
        }

        findings
    }
}

/// If the install script runs a JS file (e.g. `node install.js`), check that
/// the file actually exists in the package.
fn check_missing_script_file(
    script_value: &str,
    files: &[(PathBuf, String)],
    script_name: &str,
    findings: &mut Vec<Finding>,
) {
    let re = re_node_file();

    if let Some(caps) = re.captures(script_value) {
        let target = &caps[1];
        let target_path = PathBuf::from(target);

        let exists = files
            .iter()
            .any(|(p, _)| p == &target_path || p.ends_with(&target_path));

        if !exists {
            findings.push(Finding {
                severity: Severity::Medium,
                category: FindingCategory::InstallScript,
                title: format!(
                    "\"{}\" script references missing file: {}",
                    script_name, target
                ),
                description: format!(
                    "The script runs \"{}\" but this file was not found in the package",
                    target
                ),
                file: Some("package.json".to_string()),
                line: None,
                snippet: Some(truncate(script_value, 100)),
            });
        }
    }
}
