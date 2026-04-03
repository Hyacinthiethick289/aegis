use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::Path;
use std::sync::OnceLock;

use regex::Regex;

use crate::types::{Finding, FindingCategory, Severity};

use super::truncate;

// ---------------------------------------------------------------------------
// Regex helpers (lazily compiled)
// ---------------------------------------------------------------------------

macro_rules! lazy_re {
    ($name:ident, $pat:expr) => {
        static $name: OnceLock<Regex> = OnceLock::new();
    };
}

lazy_re!(RE_EVAL, r"eval\s*\(");
lazy_re!(RE_FUNCTION_CTOR, r"(?i)new\s+Function\s*\(");
lazy_re!(RE_BUFFER_EVAL, r"Buffer\.from\s*\(.*(?:eval|Function)");
lazy_re!(RE_CHILD_PROC, r"child_process");
lazy_re!(RE_HTTP_REQUEST, r"https?\.request\s*\(");
lazy_re!(RE_FETCH, r"\bfetch\s*\(");
lazy_re!(RE_DNS, r"dns\.(?:lookup|resolve)\s*\(");
lazy_re!(RE_OBFUSCATED, r"\\x[0-9a-fA-F]{2}(?:\\x[0-9a-fA-F]{2}){7,}");

fn re_eval() -> &'static Regex {
    RE_EVAL.get_or_init(|| Regex::new(r"eval\s*\(").unwrap())
}
fn re_function_ctor() -> &'static Regex {
    RE_FUNCTION_CTOR.get_or_init(|| Regex::new(r"(?i)new\s+Function\s*\(").unwrap())
}
fn re_buffer_eval() -> &'static Regex {
    RE_BUFFER_EVAL.get_or_init(|| Regex::new(r"Buffer\.from\s*\(.*(?:eval|Function)").unwrap())
}
fn re_child_proc() -> &'static Regex {
    RE_CHILD_PROC.get_or_init(|| Regex::new(r"child_process").unwrap())
}
fn re_http_request() -> &'static Regex {
    RE_HTTP_REQUEST.get_or_init(|| Regex::new(r"https?\.request\s*\(").unwrap())
}
fn re_fetch() -> &'static Regex {
    RE_FETCH.get_or_init(|| Regex::new(r"\bfetch\s*\(").unwrap())
}
fn re_dns() -> &'static Regex {
    RE_DNS.get_or_init(|| Regex::new(r"dns\.(?:lookup|resolve)\s*\(").unwrap())
}
fn re_obfuscated() -> &'static Regex {
    RE_OBFUSCATED.get_or_init(|| Regex::new(r"\\x[0-9a-fA-F]{2}(?:\\x[0-9a-fA-F]{2}){7,}").unwrap())
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Collect relative file paths and their content from a directory.
fn collect_files(dir: &Path) -> HashMap<String, String> {
    let mut map = HashMap::new();
    if let Ok(entries) = walk_dir(dir) {
        for entry in entries {
            if entry.is_file() {
                let rel = entry
                    .strip_prefix(dir)
                    .unwrap_or(&entry)
                    .to_string_lossy()
                    .to_string();
                if let Ok(content) = fs::read_to_string(&entry) {
                    map.insert(rel, content);
                } else {
                    // Binary file — store empty sentinel so we know it exists.
                    map.insert(rel, String::new());
                }
            }
        }
    }
    map
}

/// Simple recursive directory walker (no external crate needed).
fn walk_dir(dir: &Path) -> std::io::Result<Vec<std::path::PathBuf>> {
    let mut result = Vec::new();
    if !dir.is_dir() {
        return Ok(result);
    }
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.is_dir() {
            result.extend(walk_dir(&path)?);
        } else {
            result.push(path);
        }
    }
    Ok(result)
}

/// Returns true if the regex matches anywhere in `content`.
fn has_match(re: &Regex, content: &str) -> bool {
    re.is_match(content)
}

/// Parse a semver string into (major, minor, patch). Returns None on failure.
fn parse_semver(v: &str) -> Option<(u64, u64, u64)> {
    let cleaned = v.trim().trim_start_matches('v');
    let parts: Vec<&str> = cleaned.split('.').collect();
    if parts.len() >= 3 {
        let major = parts[0].parse().ok()?;
        let minor = parts[1].parse().ok()?;
        // patch may have pre-release suffix like "1-beta.0"
        let patch_str = parts[2].split('-').next().unwrap_or(parts[2]);
        let patch = patch_str.parse().ok()?;
        Some((major, minor, patch))
    } else {
        None
    }
}

/// Determine bump type between two semver strings.
fn version_bump_type(old: &str, new: &str) -> &'static str {
    match (parse_semver(old), parse_semver(new)) {
        (Some((om, _, _)), Some((nm, _, _))) if nm != om => "major",
        (Some((_, omi, _)), Some((_, nmi, _))) if nmi != omi => "minor",
        _ => "patch",
    }
}

/// Check if a filename looks suspicious.
fn is_suspicious_name(name: &str) -> bool {
    let lower = name.to_lowercase();
    let suspicious = [
        "payload", "exploit", "backdoor", "keylog", "stealer", "malware", "trojan",
    ];
    suspicious.iter().any(|s| lower.contains(s))
}

/// Check if a file is likely a JS/TS source file.
fn is_js_file(path: &str) -> bool {
    let lower = path.to_lowercase();
    lower.ends_with(".js")
        || lower.ends_with(".cjs")
        || lower.ends_with(".mjs")
        || lower.ends_with(".ts")
        || lower.ends_with(".tsx")
        || lower.ends_with(".jsx")
}

/// Check if a file is likely binary (failed to read as UTF-8 means it was stored as empty).
fn looks_binary(path: &str) -> bool {
    let lower = path.to_lowercase();
    lower.ends_with(".node")
        || lower.ends_with(".exe")
        || lower.ends_with(".dll")
        || lower.ends_with(".so")
        || lower.ends_with(".dylib")
        || lower.ends_with(".wasm")
        || lower.ends_with(".bin")
}

/// Count lines that look heavily obfuscated/minified (very long lines).
fn obfuscation_score(content: &str) -> usize {
    let mut score = 0;
    for line in content.lines() {
        if line.len() > 500 {
            score += 1;
        }
    }
    // Also count hex-encoded strings
    if re_obfuscated().is_match(content) {
        score += re_obfuscated().find_iter(content).count();
    }
    score
}

// ---------------------------------------------------------------------------
// DiffAnalyzer
// ---------------------------------------------------------------------------

/// Compares two extracted package versions and flags security-relevant changes.
pub struct DiffAnalyzer;

impl DiffAnalyzer {
    /// Analyze the diff between two package versions.
    ///
    /// `old_dir` and `new_dir` are paths to the extracted package contents.
    /// Returns a list of `Finding`s describing security-relevant changes.
    pub fn analyze_diff(
        old_dir: &Path,
        new_dir: &Path,
        old_version: &str,
        new_version: &str,
    ) -> Vec<Finding> {
        let old_files = collect_files(old_dir);
        let new_files = collect_files(new_dir);

        let old_keys: HashSet<&str> = old_files.keys().map(|s| s.as_str()).collect();
        let new_keys: HashSet<&str> = new_files.keys().map(|s| s.as_str()).collect();

        let mut findings = Vec::new();

        // -----------------------------------------------------------------
        // 1. Detect new files
        // -----------------------------------------------------------------
        let added_files: Vec<&str> = new_keys.difference(&old_keys).copied().collect();
        let removed_files: Vec<&str> = old_keys.difference(&new_keys).copied().collect();

        for &file in &added_files {
            // LOW: any new file
            findings.push(Finding {
                severity: Severity::Low,
                category: FindingCategory::Suspicious,
                title: "New file added between versions".into(),
                description: format!(
                    "File '{}' was added in {} (not present in {})",
                    file, new_version, old_version
                ),
                file: Some(file.to_string()),
                line: None,
                snippet: None,
            });

            // HIGH: suspicious file name
            let file_name = Path::new(file)
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or(file);
            if is_suspicious_name(file_name) {
                findings.push(Finding {
                    severity: Severity::High,
                    category: FindingCategory::Suspicious,
                    title: "New file with suspicious name".into(),
                    description: format!("File '{}' has a name suggesting malicious intent", file),
                    file: Some(file.to_string()),
                    line: None,
                    snippet: None,
                });
            }

            // MEDIUM: new binary file
            if looks_binary(file) {
                findings.push(Finding {
                    severity: Severity::Medium,
                    category: FindingCategory::Suspicious,
                    title: "New binary file added".into(),
                    description: format!("Binary file '{}' was added in {}", file, new_version),
                    file: Some(file.to_string()),
                    line: None,
                    snippet: None,
                });
            }
        }

        // -----------------------------------------------------------------
        // 2. CRITICAL: new dangerous patterns introduced
        // -----------------------------------------------------------------
        struct DiffPattern {
            regex_fn: fn() -> &'static Regex,
            severity: Severity,
            category: FindingCategory,
            title: &'static str,
            description: &'static str,
        }

        let critical_patterns = [
            DiffPattern {
                regex_fn: re_eval,
                severity: Severity::Critical,
                category: FindingCategory::CodeExecution,
                title: "New eval() usage added between versions",
                description: "eval() was not present in the old version but appears in the new one",
            },
            DiffPattern {
                regex_fn: re_function_ctor,
                severity: Severity::Critical,
                category: FindingCategory::CodeExecution,
                title: "New Function() constructor added between versions",
                description:
                    "new Function() was not present in the old version but appears in the new one",
            },
            DiffPattern {
                regex_fn: re_buffer_eval,
                severity: Severity::Critical,
                category: FindingCategory::Obfuscation,
                title: "New Buffer.from+eval pattern added between versions",
                description: "Buffer decode-and-eval pattern was not present in the old version",
            },
            DiffPattern {
                regex_fn: re_child_proc,
                severity: Severity::Critical,
                category: FindingCategory::ProcessSpawn,
                title: "New child_process usage added between versions",
                description:
                    "child_process was not used in the old version but appears in the new one",
            },
        ];

        let network_patterns = [
            DiffPattern {
                regex_fn: re_http_request,
                severity: Severity::High,
                category: FindingCategory::NetworkAccess,
                title: "New http.request() added between versions",
                description: "HTTP request calls were not present in the old version",
            },
            DiffPattern {
                regex_fn: re_fetch,
                severity: Severity::High,
                category: FindingCategory::NetworkAccess,
                title: "New fetch() call added between versions",
                description:
                    "fetch() was not present in the old version but appears in the new one",
            },
            DiffPattern {
                regex_fn: re_dns,
                severity: Severity::High,
                category: FindingCategory::NetworkAccess,
                title: "New DNS lookup added between versions",
                description: "dns.lookup/resolve was not present in the old version",
            },
        ];

        // For each JS file in new version, check if patterns are newly introduced
        for (file, new_content) in &new_files {
            if !is_js_file(file) {
                continue;
            }

            let old_content = old_files.get(file).map(|s| s.as_str()).unwrap_or("");

            for pat in critical_patterns.iter().chain(network_patterns.iter()) {
                let re = (pat.regex_fn)();
                let new_has = has_match(re, new_content);
                let old_has = has_match(re, old_content);

                if new_has && !old_has {
                    // Find the first matching line for a useful snippet
                    let (line_num, snippet) = new_content
                        .lines()
                        .enumerate()
                        .find(|(_, line)| re.is_match(line))
                        .map(|(n, l)| (Some(n + 1), Some(truncate(l, 120))))
                        .unwrap_or((None, None));

                    findings.push(Finding {
                        severity: pat.severity,
                        category: pat.category.clone(),
                        title: pat.title.to_string(),
                        description: pat.description.to_string(),
                        file: Some(file.clone()),
                        line: line_num,
                        snippet,
                    });
                }
            }
        }

        // -----------------------------------------------------------------
        // 3. CRITICAL: new install scripts added
        // -----------------------------------------------------------------
        let old_pkg_json = old_files
            .get("package.json")
            .and_then(|c| serde_json::from_str::<serde_json::Value>(c).ok());
        let new_pkg_json = new_files
            .get("package.json")
            .and_then(|c| serde_json::from_str::<serde_json::Value>(c).ok());

        if let Some(ref new_pj) = new_pkg_json {
            let install_hooks = ["preinstall", "postinstall", "preuninstall", "postuninstall"];
            for hook in install_hooks {
                let new_has = new_pj
                    .get("scripts")
                    .and_then(|s| s.get(hook))
                    .and_then(|v| v.as_str());
                let old_has = old_pkg_json
                    .as_ref()
                    .and_then(|p| p.get("scripts"))
                    .and_then(|s| s.get(hook))
                    .and_then(|v| v.as_str());

                if let Some(script) = new_has {
                    if old_has.is_none() {
                        findings.push(Finding {
                            severity: Severity::Critical,
                            category: FindingCategory::InstallScript,
                            title: format!("New '{}' script added between versions", hook),
                            description: format!(
                                "'{}' script was added in {} (not present in {}): {}",
                                hook, new_version, old_version, script
                            ),
                            file: Some("package.json".into()),
                            line: None,
                            snippet: Some(truncate(script, 120)),
                        });
                    }
                }
            }

            // HIGH: new dependencies added
            if let Some(new_deps) = new_pj.get("dependencies").and_then(|d| d.as_object()) {
                let old_dep_keys: HashSet<&str> = old_pkg_json
                    .as_ref()
                    .and_then(|p| p.get("dependencies"))
                    .and_then(|d| d.as_object())
                    .map(|m| m.keys().map(|k| k.as_str()).collect())
                    .unwrap_or_default();

                for (dep, ver) in new_deps {
                    if !old_dep_keys.contains(dep.as_str()) {
                        findings.push(Finding {
                            severity: Severity::High,
                            category: FindingCategory::Suspicious,
                            title: "New dependency added between versions".into(),
                            description: format!(
                                "Dependency '{}@{}' was added in {} (not present in {})",
                                dep,
                                ver.as_str().unwrap_or("?"),
                                new_version,
                                old_version
                            ),
                            file: Some("package.json".into()),
                            line: None,
                            snippet: None,
                        });
                    }
                }
            }
        }

        // -----------------------------------------------------------------
        // 4. MEDIUM: increase in obfuscated/minified code
        // -----------------------------------------------------------------
        let mut old_obf_total: usize = 0;
        let mut new_obf_total: usize = 0;

        for (file, content) in &old_files {
            if is_js_file(file) {
                old_obf_total += obfuscation_score(content);
            }
        }
        for (file, content) in &new_files {
            if is_js_file(file) {
                new_obf_total += obfuscation_score(content);
            }
        }

        if new_obf_total > old_obf_total + 5 {
            findings.push(Finding {
                severity: Severity::Medium,
                category: FindingCategory::Obfuscation,
                title: "Significant increase in obfuscated/minified code".into(),
                description: format!(
                    "Obfuscation score increased from {} to {} between {} and {}",
                    old_obf_total, new_obf_total, old_version, new_version
                ),
                file: None,
                line: None,
                snippet: None,
            });
        }

        // -----------------------------------------------------------------
        // 5. MEDIUM: decrease in total code size (replaced files)
        // -----------------------------------------------------------------
        let old_total_size: usize = old_files.values().map(|c| c.len()).sum();
        let new_total_size: usize = new_files.values().map(|c| c.len()).sum();

        if old_total_size > 0 && !removed_files.is_empty() {
            let decrease_pct =
                ((old_total_size as f64 - new_total_size as f64) / old_total_size as f64) * 100.0;
            if decrease_pct > 30.0 {
                findings.push(Finding {
                    severity: Severity::Medium,
                    category: FindingCategory::Suspicious,
                    title: "Significant decrease in package size".into(),
                    description: format!(
                        "Package shrank by {:.0}% ({} -> {} bytes) with {} files removed — may indicate replaced files",
                        decrease_pct, old_total_size, new_total_size, removed_files.len()
                    ),
                    file: None,
                    line: None,
                    snippet: None,
                });
            }
        }

        // -----------------------------------------------------------------
        // 6. LOW: version bump analysis
        // -----------------------------------------------------------------
        let bump = version_bump_type(old_version, new_version);
        // Count modified files
        let modified_count = new_keys
            .intersection(&old_keys)
            .filter(|k| new_files.get(**k) != old_files.get(**k))
            .count();
        let total_changes = added_files.len() + removed_files.len() + modified_count;

        if bump == "patch" && total_changes > 10 {
            findings.push(Finding {
                severity: Severity::Low,
                category: FindingCategory::Suspicious,
                title: "Patch version with many changes".into(),
                description: format!(
                    "Version bump {} -> {} is a patch release but has {} file changes — \
                     unusually large for a patch",
                    old_version, new_version, total_changes
                ),
                file: None,
                line: None,
                snippet: None,
            });
        }

        findings
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    fn setup_dirs(old_files: &[(&str, &str)], new_files: &[(&str, &str)]) -> (TempDir, TempDir) {
        let old_dir = TempDir::new().unwrap();
        let new_dir = TempDir::new().unwrap();

        for (name, content) in old_files {
            let path = old_dir.path().join(name);
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent).unwrap();
            }
            fs::write(path, content).unwrap();
        }
        for (name, content) in new_files {
            let path = new_dir.path().join(name);
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent).unwrap();
            }
            fs::write(path, content).unwrap();
        }

        (old_dir, new_dir)
    }

    #[test]
    fn detects_new_eval() {
        let (old, new) = setup_dirs(
            &[("index.js", "console.log('hello');")],
            &[("index.js", "eval(atob(x));")],
        );
        let findings = DiffAnalyzer::analyze_diff(old.path(), new.path(), "1.0.0", "1.0.1");
        assert!(findings.iter().any(|f| f.title.contains("eval()")));
    }

    #[test]
    fn detects_new_postinstall() {
        let old_pkg = r#"{"name":"foo","version":"1.0.0","scripts":{"test":"jest"}}"#;
        let new_pkg = r#"{"name":"foo","version":"1.0.1","scripts":{"test":"jest","postinstall":"node setup.js"}}"#;
        let (old, new) = setup_dirs(&[("package.json", old_pkg)], &[("package.json", new_pkg)]);
        let findings = DiffAnalyzer::analyze_diff(old.path(), new.path(), "1.0.0", "1.0.1");
        assert!(findings.iter().any(|f| f.title.contains("postinstall")));
    }

    #[test]
    fn detects_new_dependency() {
        let old_pkg = r#"{"name":"foo","dependencies":{"lodash":"^4.0.0"}}"#;
        let new_pkg = r#"{"name":"foo","dependencies":{"lodash":"^4.0.0","evil-pkg":"^1.0.0"}}"#;
        let (old, new) = setup_dirs(&[("package.json", old_pkg)], &[("package.json", new_pkg)]);
        let findings = DiffAnalyzer::analyze_diff(old.path(), new.path(), "1.0.0", "1.0.1");
        assert!(findings.iter().any(|f| f.description.contains("evil-pkg")));
    }

    #[test]
    fn detects_suspicious_filename() {
        let (old, new) = setup_dirs(
            &[("index.js", "module.exports = {};")],
            &[
                ("index.js", "module.exports = {};"),
                ("payload.js", "console.log('hi');"),
            ],
        );
        let findings = DiffAnalyzer::analyze_diff(old.path(), new.path(), "1.0.0", "1.0.1");
        assert!(findings.iter().any(|f| f.title.contains("suspicious name")));
    }

    #[test]
    fn patch_with_many_changes() {
        // Test the version logic directly.
        assert_eq!(version_bump_type("1.0.0", "1.0.1"), "patch");
        assert_eq!(version_bump_type("1.0.0", "1.1.0"), "minor");
        assert_eq!(version_bump_type("1.0.0", "2.0.0"), "major");
    }
}
