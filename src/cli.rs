use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};

// ---------------------------------------------------------------------------
// CLI definition
// ---------------------------------------------------------------------------

#[derive(Parser)]
#[command(
    name = "aegis-scan",
    about = "Supply-chain security scanner for npm packages",
    version,
    after_help = "Examples:\n  aegis check axios\n  aegis check axios@1.7.0\n  aegis check @scope/pkg@1.0.0\n  aegis check lodash --json\n  aegis scan .\n  aegis scan ./my-project --skip-dev\n  aegis install axios express\n  aegis install --force\n  aegis install"
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,

    /// Output results as JSON instead of the default terminal format
    #[arg(long, global = true, conflicts_with = "sarif")]
    pub json: bool,

    /// Output results as SARIF v2.1.0 JSON (for GitHub Security tab)
    #[arg(long, global = true, conflicts_with = "json")]
    pub sarif: bool,

    /// Enable verbose / debug logging
    #[arg(long, short, global = true)]
    pub verbose: bool,

    /// Bypass the local analysis cache
    #[arg(long, global = true)]
    pub no_cache: bool,

    /// Directory containing custom YAML rule files
    #[arg(long, global = true)]
    pub rules: Option<PathBuf>,

    /// Disable colored output (also respects NO_COLOR env var and non-TTY stdout)
    #[arg(long, global = true)]
    pub no_color: bool,

    /// Ignore findings matching a rule (case-insensitive substring match on
    /// category, title, or severity). Can be specified multiple times.
    #[arg(long = "ignore-rule", global = true)]
    pub ignore_rules: Vec<String>,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Check a specific npm package for security issues
    Check {
        /// Package specifier, e.g. "axios", "axios@1.7.0", "@scope/pkg@1.0.0"
        package: String,

        /// Compare against a previous version to detect security-relevant changes
        #[arg(long)]
        compare: Option<String>,

        /// Run deep transitive dependency tree analysis
        #[arg(long)]
        deep: bool,
    },

    /// Scan a local project's dependencies for security issues
    Scan {
        /// Path to the project directory (must contain a package.json)
        path: PathBuf,

        /// Skip devDependencies
        #[arg(long)]
        skip_dev: bool,
    },

    /// Install npm packages after checking them for security issues
    Install {
        /// Packages to install (e.g. "axios", "lodash@4.17.21"). If omitted,
        /// runs `npm install` for the whole project after scanning all deps.
        packages: Vec<String>,

        /// Skip confirmation prompts and install even if high-risk packages are found
        #[arg(long)]
        force: bool,

        /// Skip devDependencies when scanning the whole project
        #[arg(long)]
        skip_dev: bool,
    },

    /// Manage the local analysis cache
    Cache {
        #[command(subcommand)]
        action: CacheCommands,
    },
}

#[derive(Subcommand)]
pub enum CacheCommands {
    /// Remove all cached analysis results
    Clear,
}

// ---------------------------------------------------------------------------
// Package specifier parsing
// ---------------------------------------------------------------------------

/// Parse a package specifier into (name, optional version).
///
/// Handles:
///   - `axios`           -> ("axios", None)
///   - `axios@1.7.0`     -> ("axios", Some("1.7.0"))
///   - `@scope/pkg`      -> ("@scope/pkg", None)
///   - `@scope/pkg@1.0`  -> ("@scope/pkg", Some("1.0"))
pub fn parse_package_specifier(spec: &str) -> (String, Option<String>) {
    if let Some(scoped) = spec.strip_prefix('@') {
        // Scoped package: find the *second* '@' (version separator).
        if let Some(at_pos) = scoped.find('@') {
            // Make sure the '@' comes after the '/', otherwise it's part of
            // the scope itself (malformed, but be defensive).
            if scoped[..at_pos].contains('/') {
                let name = format!("@{}", &scoped[..at_pos]);
                let version = scoped[at_pos + 1..].to_string();
                return (name, Some(version));
            }
        }
        // No version portion found — the whole string is the package name.
        (spec.to_string(), None)
    } else {
        // Unscoped package: split on the first '@'.
        match spec.split_once('@') {
            Some((name, version)) => (name.to_string(), Some(version.to_string())),
            None => (spec.to_string(), None),
        }
    }
}

/// Read a project's package.json and collect `(name, version_spec)` pairs for
/// all its dependencies.
pub fn collect_dependencies(
    project_path: &std::path::Path,
    skip_dev: bool,
) -> Result<Vec<(String, String)>> {
    let pkg_path = project_path.join("package.json");
    let raw = std::fs::read_to_string(&pkg_path)
        .with_context(|| format!("could not read {}", pkg_path.display()))?;
    let pkg: serde_json::Value =
        serde_json::from_str(&raw).context("failed to parse package.json")?;

    let mut deps: Vec<(String, String)> = Vec::new();

    if let Some(obj) = pkg.get("dependencies").and_then(|v| v.as_object()) {
        for (name, ver) in obj {
            deps.push((name.clone(), ver.as_str().unwrap_or("latest").to_string()));
        }
    }

    if !skip_dev {
        if let Some(obj) = pkg.get("devDependencies").and_then(|v| v.as_object()) {
            for (name, ver) in obj {
                deps.push((name.clone(), ver.as_str().unwrap_or("latest").to_string()));
            }
        }
    }

    // Sort for deterministic output.
    deps.sort_by(|a, b| a.0.cmp(&b.0));

    Ok(deps)
}

/// Clean a semver range into an exact version hint, or None if we should
/// resolve "latest".
///
/// This is intentionally simplistic: strip leading `^`, `~`, `>=`, `=` and
/// keep whatever remains.  If the result doesn't look like a version string
/// we return None and let the registry resolve it.
pub fn clean_version_spec(spec: &str) -> Option<String> {
    let trimmed = spec
        .trim_start_matches('^')
        .trim_start_matches('~')
        .trim_start_matches(">=")
        .trim_start_matches('=')
        .trim();

    if trimmed.is_empty() || trimmed == "*" || trimmed.contains("||") || trimmed.contains(' ') {
        return None;
    }

    Some(trimmed.to_string())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_unscoped_no_version() {
        let (name, ver) = parse_package_specifier("axios");
        assert_eq!(name, "axios");
        assert_eq!(ver, None);
    }

    #[test]
    fn parse_unscoped_with_version() {
        let (name, ver) = parse_package_specifier("axios@1.7.0");
        assert_eq!(name, "axios");
        assert_eq!(ver, Some("1.7.0".to_string()));
    }

    #[test]
    fn parse_scoped_no_version() {
        let (name, ver) = parse_package_specifier("@scope/pkg");
        assert_eq!(name, "@scope/pkg");
        assert_eq!(ver, None);
    }

    #[test]
    fn parse_scoped_with_version() {
        let (name, ver) = parse_package_specifier("@scope/pkg@1.0.0");
        assert_eq!(name, "@scope/pkg");
        assert_eq!(ver, Some("1.0.0".to_string()));
    }

    #[test]
    fn clean_version_spec_caret() {
        assert_eq!(clean_version_spec("^4.18.0"), Some("4.18.0".to_string()));
    }

    #[test]
    fn clean_version_spec_tilde() {
        assert_eq!(clean_version_spec("~1.2.3"), Some("1.2.3".to_string()));
    }

    #[test]
    fn clean_version_spec_star() {
        assert_eq!(clean_version_spec("*"), None);
    }

    #[test]
    fn clean_version_spec_range() {
        assert_eq!(clean_version_spec(">=1.0.0 <2.0.0"), None);
    }

    #[test]
    fn clean_version_spec_exact() {
        assert_eq!(clean_version_spec("1.0.0"), Some("1.0.0".to_string()));
    }
}
