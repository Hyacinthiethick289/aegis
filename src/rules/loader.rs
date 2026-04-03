use std::path::Path;

use anyhow::{Context, Result};
use serde::Deserialize;

use crate::types::{FindingCategory, Severity};

/// A YAML-defined detection rule.
#[derive(Debug, Clone, Deserialize)]
pub struct Rule {
    pub id: String,
    pub name: String,
    pub description: String,
    pub severity: String,
    pub category: String,
    pub pattern: String,
    /// Only match files whose name matches this glob (e.g. "*.js").
    #[serde(default)]
    pub file_pattern: Option<String>,
    /// Skip files whose path contains any of these substrings.
    #[serde(default)]
    pub exclude_paths: Vec<String>,
}

impl Rule {
    /// Map the YAML severity string to our `Severity` enum.
    pub fn parsed_severity(&self) -> Severity {
        match self.severity.to_lowercase().as_str() {
            "critical" => Severity::Critical,
            "high" => Severity::High,
            "medium" => Severity::Medium,
            "low" => Severity::Low,
            _ => Severity::Info,
        }
    }

    /// Map the YAML category string to our `FindingCategory` enum.
    pub fn parsed_category(&self) -> FindingCategory {
        match self
            .category
            .to_lowercase()
            .replace(['-', ' '], "_")
            .as_str()
        {
            "code_execution" => FindingCategory::CodeExecution,
            "network_access" => FindingCategory::NetworkAccess,
            "process_spawn" => FindingCategory::ProcessSpawn,
            "file_system_access" | "filesystem_access" => FindingCategory::FileSystemAccess,
            "obfuscation" => FindingCategory::Obfuscation,
            "install_script" => FindingCategory::InstallScript,
            "env_access" => FindingCategory::EnvAccess,
            "maintainer_change" => FindingCategory::MaintainerChange,
            "dependency_risk" => FindingCategory::DependencyRisk,
            _ => FindingCategory::Suspicious,
        }
    }
}

/// Load all `.yml` / `.yaml` rule files from the given directory.
pub fn load_rules(dir: &Path) -> Result<Vec<Rule>> {
    let mut rules = Vec::new();

    for ext in &["yml", "yaml"] {
        let pattern = format!("{}/**/*.{}", dir.display(), ext);
        let paths =
            glob::glob(&pattern).with_context(|| format!("invalid glob pattern: {}", pattern))?;

        for entry in paths {
            let path = entry.with_context(|| "failed to read glob entry")?;
            let content = std::fs::read_to_string(&path)
                .with_context(|| format!("failed to read rule file: {}", path.display()))?;
            let rule: Rule = serde_yaml::from_str(&content)
                .with_context(|| format!("failed to parse rule file: {}", path.display()))?;
            rules.push(rule);
        }
    }

    Ok(rules)
}

/// Return the set of built-in default rules (hardcoded).
pub fn load_default_rules() -> Vec<Rule> {
    let yaml_sources: &[&str] = &[
        // 1. eval with encoded payload
        r#"
id: "AEGIS-001"
name: "Eval with encoded payload"
description: "Detects eval() calls with base64 or hex encoded arguments"
severity: critical
category: code_execution
pattern: "eval\\s*\\(\\s*(?:atob|Buffer\\.from)\\s*\\("
file_pattern: "*.js"
exclude_paths:
  - "node_modules/"
  - "*.min.js"
"#,
        // 2. Function constructor with string concatenation
        r#"
id: "AEGIS-002"
name: "Function constructor abuse"
description: "Detects Function() constructor used to execute dynamically built code"
severity: critical
category: code_execution
pattern: "new\\s+Function\\s*\\(.*\\+.*\\)"
file_pattern: "*.js"
exclude_paths:
  - "node_modules/"
  - "*.min.js"
"#,
        // 3. child_process with variable command
        r#"
id: "AEGIS-003"
name: "child_process with dynamic command"
description: "Detects child_process exec/spawn with variable or concatenated commands"
severity: critical
category: process_spawn
pattern: "(?:exec|execSync|spawn|spawnSync)\\s*\\(\\s*(?:[a-zA-Z_$][a-zA-Z0-9_$]*|`|['\"]\\s*\\+)"
file_pattern: "*.js"
exclude_paths:
  - "node_modules/"
  - "test/"
"#,
        // 4. curl/wget piped to shell
        r#"
id: "AEGIS-004"
name: "Remote script execution via curl/wget"
description: "Detects curl or wget output piped to shell for remote code execution"
severity: critical
category: process_spawn
pattern: "(?:curl|wget)\\s+[^|]*\\|\\s*(?:sh|bash|node|python)"
exclude_paths:
  - "node_modules/"
"#,
        // 5. process.env bulk access
        r#"
id: "AEGIS-005"
name: "Bulk environment variable access"
description: "Detects code that accesses the entire process.env object, possibly for exfiltration"
severity: high
category: env_access
pattern: "(?:JSON\\.stringify|Object\\.(?:keys|values|entries))\\s*\\(\\s*process\\.env\\s*\\)"
file_pattern: "*.js"
exclude_paths:
  - "node_modules/"
  - "test/"
"#,
        // 6. fs.readFile on sensitive paths
        r#"
id: "AEGIS-006"
name: "Reading sensitive home directory files"
description: "Detects fs operations targeting home directory dotfiles (credentials, SSH keys, etc.)"
severity: high
category: file_system_access
pattern: "(?:readFile|readFileSync|createReadStream)\\s*\\([^)]*(?:\\.ssh|_netrc|\\.npmrc|\\.bash_history|\\.aws|\\.gnupg)"
file_pattern: "*.js"
exclude_paths:
  - "node_modules/"
  - "test/"
"#,
        // 7. Crypto mining indicators
        r#"
id: "AEGIS-007"
name: "Crypto mining indicators"
description: "Detects references to mining pools or crypto mining algorithms"
severity: critical
category: suspicious
pattern: "(?:stratum\\+tcp://|cryptonight|coinhive|minergate|xmrig|monero\\.crypto-pool)"
exclude_paths:
  - "node_modules/"
"#,
        // 8. Reverse shell patterns
        r#"
id: "AEGIS-008"
name: "Reverse shell pattern"
description: "Detects patterns consistent with establishing a reverse shell connection"
severity: critical
category: network_access
pattern: "(?:net\\.Socket|new\\s+Socket).*(?:pipe|write).*(?:child_process|spawn|exec)|(?:child_process|spawn|exec).*(?:net\\.Socket|new\\s+Socket).*pipe"
file_pattern: "*.js"
exclude_paths:
  - "node_modules/"
  - "test/"
"#,
        // 9. Data exfiltration — encode + send
        r#"
id: "AEGIS-009"
name: "Data exfiltration pattern"
description: "Detects patterns of encoding data and sending it to external servers"
severity: high
category: network_access
pattern: "(?:Buffer\\.from|btoa|encodeURIComponent)\\s*\\([^)]*\\).*(?:https?\\.request|fetch|axios|got)\\s*\\("
file_pattern: "*.js"
exclude_paths:
  - "node_modules/"
  - "test/"
"#,
        // 10. Prototype pollution
        r#"
id: "AEGIS-010"
name: "Prototype pollution"
description: "Detects direct __proto__ assignment which can lead to prototype pollution attacks"
severity: medium
category: suspicious
pattern: "__proto__\\s*(?:\\[|=)"
file_pattern: "*.js"
exclude_paths:
  - "node_modules/"
  - "test/"
  - "*.min.js"
"#,
    ];

    yaml_sources
        .iter()
        .filter_map(|src| serde_yaml::from_str::<Rule>(src).ok())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_rules_load() {
        let rules = load_default_rules();
        assert_eq!(rules.len(), 10);
    }

    #[test]
    fn severity_mapping() {
        let rules = load_default_rules();
        assert_eq!(rules[0].parsed_severity(), Severity::Critical);
        assert_eq!(rules[9].parsed_severity(), Severity::Medium);
    }

    #[test]
    fn category_mapping() {
        let rules = load_default_rules();
        assert_eq!(rules[0].parsed_category(), FindingCategory::CodeExecution);
        assert_eq!(rules[4].parsed_category(), FindingCategory::EnvAccess);
    }
}
