//! Detects packages that look like AI-hallucinated or typosquatted names.
//!
//! AI code assistants sometimes suggest package names that don't actually exist.
//! Attackers register these fake names with malicious payloads. This analyzer
//! flags packages exhibiting signals consistent with that attack pattern.

use chrono::Utc;

use crate::registry::package::PackageMetadata;
use crate::types::{Finding, FindingCategory, Severity};

/// Top popular npm packages used for Levenshtein distance comparison.
const TOP_PACKAGES: &[&str] = &[
    "react",
    "express",
    "lodash",
    "axios",
    "chalk",
    "commander",
    "debug",
    "dotenv",
    "fs-extra",
    "glob",
    "inquirer",
    "jest",
    "moment",
    "mongoose",
    "next",
    "nodemon",
    "prettier",
    "socket.io",
    "typescript",
    "uuid",
    "webpack",
    "yargs",
    "bluebird",
    "body-parser",
    "cheerio",
    "cors",
    "dayjs",
    "eslint",
    "fastify",
    "helmet",
    "jsonwebtoken",
    "knex",
    "luxon",
    "marked",
    "mysql2",
    "nanoid",
    "passport",
    "pg",
    "pino",
    "ramda",
    "redis",
    "rimraf",
    "rxjs",
    "semver",
    "sequelize",
    "sharp",
    "underscore",
    "validator",
    "vue",
    "zod",
];

/// Generic name fragments that AI models tend to hallucinate.
const HALLUCINATION_PATTERNS: &[&str] = &[
    "utils-helper",
    "data-processor",
    "string-formatter",
    "json-utils",
    "file-helper",
    "array-utils",
    "object-helper",
    "math-helper",
    "date-utils",
    "config-helper",
    "log-helper",
    "http-helper",
    "api-helper",
    "parse-helper",
    "format-helper",
    "convert-helper",
    "validate-helper",
    "transform-utils",
    "common-utils",
    "simple-utils",
];

/// Compute the Levenshtein edit distance between two strings.
fn levenshtein(a: &str, b: &str) -> usize {
    let a_len = a.len();
    let b_len = b.len();
    if a_len == 0 {
        return b_len;
    }
    if b_len == 0 {
        return a_len;
    }

    let mut prev: Vec<usize> = (0..=b_len).collect();
    let mut curr = vec![0usize; b_len + 1];

    for (i, ca) in a.chars().enumerate() {
        curr[0] = i + 1;
        for (j, cb) in b.chars().enumerate() {
            let cost = if ca == cb { 0 } else { 1 };
            curr[j + 1] = (prev[j] + cost).min(prev[j + 1] + 1).min(curr[j] + 1);
        }
        std::mem::swap(&mut prev, &mut curr);
    }

    prev[b_len]
}

/// Try to parse an ISO-8601 timestamp from the npm `time` map and return the
/// number of days between that timestamp and now. Returns `None` if unparsable.
fn days_since(iso: &str) -> Option<i64> {
    let parsed = chrono::DateTime::parse_from_rfc3339(iso).ok()?;
    let duration = Utc::now().signed_duration_since(parsed);
    Some(duration.num_days())
}

/// Analyzer for AI-hallucinated / typosquatted package names.
pub struct HallucinationAnalyzer;

impl HallucinationAnalyzer {
    pub fn new() -> Self {
        Self
    }

    /// Analyse a `PackageMetadata` and return findings.
    ///
    /// This does **not** implement the `Analyzer` trait because it operates on
    /// registry metadata rather than extracted file contents.
    pub fn analyze(&self, metadata: &PackageMetadata) -> Vec<Finding> {
        let mut findings: Vec<Finding> = Vec::new();

        let pkg_name = metadata.name.as_deref().unwrap_or("");

        // ── Derive helper values ──────────────────────────────────────
        let version_count = metadata.versions.len();

        // Weekly downloads: npm includes this in the packument `extra` as a
        // nested value; fall back to 0 when absent.
        let weekly_downloads: u64 = metadata
            .extra
            .get("weeklyDownloads")
            .or_else(|| metadata.extra.get("weekly_downloads"))
            .and_then(|v| v.as_u64())
            .unwrap_or(0);

        // Days since the package was first created (from `time.created`).
        let days_since_creation: Option<i64> =
            metadata.time.get("created").and_then(|ts| days_since(ts));

        let latest_info = metadata.latest_version_info();

        let has_install_scripts = latest_info
            .map(|v| !v.install_scripts().is_empty())
            .unwrap_or(false);

        let description = metadata
            .description
            .as_deref()
            .or_else(|| latest_info.and_then(|v| v.description.as_deref()))
            .unwrap_or("");

        let has_repo = metadata
            .extra
            .get("repository")
            .map(|v| !v.is_null())
            .unwrap_or(false);

        let maintainer_has_email = metadata
            .maintainers
            .as_ref()
            .and_then(|ms| ms.first())
            .and_then(|m| m.email.as_ref())
            .map(|e| !e.is_empty())
            .unwrap_or(false);

        let latest_version_str = metadata.latest_version().unwrap_or("");

        // ── CRITICAL: new + low downloads + install scripts ───────────
        if let Some(age) = days_since_creation {
            if age <= 30 && weekly_downloads == 0 && has_install_scripts {
                findings.push(Finding {
                    severity: Severity::Critical,
                    category: FindingCategory::HallucinatedPackage,
                    title: "Likely malicious hallucinated package".into(),
                    description: format!(
                        "Package '{}' was created {} days ago, has 0 weekly downloads, \
                         and contains install scripts. This is a strong signal of a \
                         malicious package registered to exploit AI hallucinations.",
                        pkg_name, age
                    ),
                    file: None,
                    line: None,
                    snippet: None,
                });
            }
        }

        // ── HIGH: very new + very low downloads ───────────────────────
        if let Some(age) = days_since_creation {
            if age < 7 && weekly_downloads < 100 {
                findings.push(Finding {
                    severity: Severity::High,
                    category: FindingCategory::HallucinatedPackage,
                    title: "Very new package with almost no downloads".into(),
                    description: format!(
                        "Package '{}' was created only {} days ago and has {} weekly \
                         downloads. Newly created packages with negligible adoption \
                         are a hallucination/typosquat risk.",
                        pkg_name, age, weekly_downloads
                    ),
                    file: None,
                    line: None,
                    snippet: None,
                });
            }
        }

        // ── HIGH: name suspiciously close to a top package ────────────
        for &top in TOP_PACKAGES {
            if pkg_name == top {
                continue; // exact match means it IS the real package
            }
            let dist = levenshtein(pkg_name, top);
            if dist > 0 && dist <= 2 {
                findings.push(Finding {
                    severity: Severity::High,
                    category: FindingCategory::HallucinatedPackage,
                    title: format!("Name suspiciously similar to '{}'", top),
                    description: format!(
                        "Package '{}' is only {} edit(s) away from the popular \
                         package '{}'. This may be a typosquat or hallucinated variant.",
                        pkg_name, dist, top
                    ),
                    file: None,
                    line: None,
                    snippet: None,
                });
                break; // one match is enough
            }
        }

        // ── MEDIUM: no/short description ──────────────────────────────
        if description.is_empty() || description.len() < 10 {
            findings.push(Finding {
                severity: Severity::Medium,
                category: FindingCategory::HallucinatedPackage,
                title: "Missing or very short description".into(),
                description: format!(
                    "Package '{}' has no README or a description shorter than 10 \
                     characters, which is unusual for legitimate packages.",
                    pkg_name
                ),
                file: None,
                line: None,
                snippet: None,
            });
        }

        // ── MEDIUM: no repository URL ─────────────────────────────────
        if !has_repo {
            findings.push(Finding {
                severity: Severity::Medium,
                category: FindingCategory::HallucinatedPackage,
                title: "No repository URL".into(),
                description: format!(
                    "Package '{}' does not declare a source repository, making it \
                     harder to verify its legitimacy.",
                    pkg_name
                ),
                file: None,
                line: None,
                snippet: None,
            });
        }

        // ── MEDIUM: suspicious first version ──────────────────────────
        if version_count == 1 && (latest_version_str == "0.0.1" || latest_version_str == "1.0.0") {
            findings.push(Finding {
                severity: Severity::Medium,
                category: FindingCategory::HallucinatedPackage,
                title: "Single version published at 0.0.1 or 1.0.0".into(),
                description: format!(
                    "Package '{}' has exactly one published version ({}). \
                     Combined with other signals this can indicate a placeholder \
                     or malicious registration.",
                    pkg_name, latest_version_str
                ),
                file: None,
                line: None,
                snippet: None,
            });
        }

        // ── MEDIUM: maintainer without email ──────────────────────────
        if !maintainer_has_email {
            findings.push(Finding {
                severity: Severity::Medium,
                category: FindingCategory::HallucinatedPackage,
                title: "Maintainer has no published email".into(),
                description: format!(
                    "The primary maintainer of '{}' has no public email address, \
                     which can be a signal of a throwaway account.",
                    pkg_name
                ),
                file: None,
                line: None,
                snippet: None,
            });
        }

        // ── LOW: generic AI hallucination name patterns ───────────────
        let lower = pkg_name.to_lowercase();
        for &pattern in HALLUCINATION_PATTERNS {
            if lower.contains(pattern) {
                findings.push(Finding {
                    severity: Severity::Low,
                    category: FindingCategory::HallucinatedPackage,
                    title: "Name matches common AI hallucination pattern".into(),
                    description: format!(
                        "Package name '{}' contains the generic fragment '{}', \
                         which AI assistants frequently hallucinate as a package \
                         name.",
                        pkg_name, pattern
                    ),
                    file: None,
                    line: None,
                    snippet: None,
                });
                break; // one match is enough
            }
        }

        findings
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_levenshtein_identical() {
        assert_eq!(levenshtein("react", "react"), 0);
    }

    #[test]
    fn test_levenshtein_one_edit() {
        assert_eq!(levenshtein("react", "reakt"), 1);
    }

    #[test]
    fn test_levenshtein_two_edits() {
        assert_eq!(levenshtein("lodash", "lodasg"), 1);
        assert_eq!(levenshtein("axos", "axios"), 1);
    }

    #[test]
    fn test_levenshtein_different() {
        assert!(levenshtein("react", "totally-different") > 2);
    }
}
