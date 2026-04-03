use std::collections::HashMap;

use serde::{Deserialize, Serialize};

/// Maintainer information from the npm registry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Maintainer {
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub email: Option<String>,
}

/// Distribution metadata for a specific version (tarball URL, checksums).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Dist {
    #[serde(default)]
    pub tarball: Option<String>,
    #[serde(default)]
    pub shasum: Option<String>,
    #[serde(default)]
    pub integrity: Option<String>,
}

/// All the information we care about for a specific published version.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VersionInfo {
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub version: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub dist: Option<Dist>,
    #[serde(default)]
    pub scripts: Option<HashMap<String, String>>,
    #[serde(default)]
    pub dependencies: Option<HashMap<String, String>>,
    #[serde(default, rename = "devDependencies")]
    pub dev_dependencies: Option<HashMap<String, String>>,
    #[serde(default)]
    pub maintainers: Option<Vec<Maintainer>>,
    /// Catch-all for fields we don't explicitly model.
    #[serde(flatten)]
    pub extra: HashMap<String, serde_json::Value>,
}

/// Top-level package metadata returned by `https://registry.npmjs.org/{pkg}`.
///
/// We intentionally keep this flat and optional — the npm registry response
/// varies between full-doc and abbreviated-doc endpoints.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PackageMetadata {
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
    /// Map of semver string -> VersionInfo for every published version.
    #[serde(default)]
    pub versions: HashMap<String, VersionInfo>,
    /// Map of semver string -> ISO-8601 publish timestamp.
    #[serde(default)]
    pub time: HashMap<String, String>,
    #[serde(default)]
    pub maintainers: Option<Vec<Maintainer>>,
    #[serde(default, rename = "dist-tags")]
    pub dist_tags: Option<HashMap<String, String>>,
    /// Catch-all for fields we don't explicitly model.
    #[serde(flatten)]
    pub extra: HashMap<String, serde_json::Value>,
}

// ---------------------------------------------------------------------------
// Convenience helpers
// ---------------------------------------------------------------------------

/// Names of npm lifecycle scripts that run automatically on install and are
/// commonly abused by malicious packages.
const INSTALL_SCRIPT_KEYS: &[&str] = &[
    "preinstall",
    "install",
    "postinstall",
    "preuninstall",
    "postuninstall",
    "prepare",
];

impl VersionInfo {
    /// Return only the lifecycle/install-related scripts (the ones that fire
    /// automatically when a user runs `npm install`).
    pub fn install_scripts(&self) -> HashMap<String, String> {
        let Some(scripts) = &self.scripts else {
            return HashMap::new();
        };
        scripts
            .iter()
            .filter(|(key, _)| INSTALL_SCRIPT_KEYS.contains(&key.as_str()))
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect()
    }
}

impl PackageMetadata {
    /// Resolve the `latest` dist-tag to a concrete version string.
    pub fn latest_version(&self) -> Option<&str> {
        self.dist_tags
            .as_ref()
            .and_then(|tags| tags.get("latest"))
            .map(|s| s.as_str())
    }

    /// Convenience: get the `VersionInfo` for the `latest` tag.
    pub fn latest_version_info(&self) -> Option<&VersionInfo> {
        let v = self.latest_version()?;
        self.versions.get(v)
    }
}
