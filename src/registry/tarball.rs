use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use flate2::read::GzDecoder;
use tar::Archive;
use tempfile::TempDir;

/// Download a `.tgz` tarball from `tarball_url`, extract it into `dest`, and
/// return the path to the top-level package directory inside the extraction.
///
/// npm tarballs conventionally contain a single top-level directory called
/// `package/`.  We return that inner directory so callers can work with it
/// directly.
pub async fn download_and_extract(tarball_url: &str, dest: &Path) -> Result<PathBuf> {
    tracing::info!(url = %tarball_url, "downloading tarball");

    let client = reqwest::Client::builder()
        .user_agent("aegis-cli/0.1.0")
        .build()
        .context("failed to build HTTP client")?;

    let response = client
        .get(tarball_url)
        .send()
        .await
        .with_context(|| format!("failed to download tarball from {tarball_url}"))?;

    if !response.status().is_success() {
        anyhow::bail!("tarball download returned HTTP {}", response.status());
    }

    let bytes = response
        .bytes()
        .await
        .context("failed to read tarball bytes")?;

    tracing::debug!(bytes = bytes.len(), "tarball downloaded, extracting");

    // Decompress gzip, then untar.
    let gz = GzDecoder::new(bytes.as_ref());
    let mut archive = Archive::new(gz);
    archive.unpack(dest).context("failed to extract tarball")?;

    // npm tarballs almost always contain a single `package/` directory at the
    // root.  Walk the destination to find it; fall back to `dest` itself.
    let package_dir = find_package_dir(dest)?;

    tracing::info!(path = %package_dir.display(), "extraction complete");
    Ok(package_dir)
}

/// Convenience wrapper that creates its own temp directory, extracts there,
/// and returns `(TempDir, PathBuf)`.  The caller must hold on to the `TempDir`
/// handle to keep the directory alive.
pub async fn download_and_extract_temp(tarball_url: &str) -> Result<(TempDir, PathBuf)> {
    let tmp = TempDir::new().context("failed to create temp directory")?;
    let package_dir = download_and_extract(tarball_url, tmp.path()).await?;
    Ok((tmp, package_dir))
}

/// Locate the top-level directory inside an extracted npm tarball.
fn find_package_dir(dest: &Path) -> Result<PathBuf> {
    let entries: Vec<_> = std::fs::read_dir(dest)
        .context("failed to read extraction directory")?
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().map(|ft| ft.is_dir()).unwrap_or(false))
        .collect();

    // Prefer a directory literally named "package" (the npm convention).
    if let Some(pkg) = entries.iter().find(|e| e.file_name() == "package") {
        return Ok(pkg.path());
    }

    // Otherwise fall back to the first (and presumably only) directory.
    if let Some(first) = entries.into_iter().next() {
        return Ok(first.path());
    }

    // If there are no subdirectories at all, just use dest.
    Ok(dest.to_path_buf())
}

// ---------------------------------------------------------------------------
// File collection
// ---------------------------------------------------------------------------

/// File extensions we consider "JavaScript-family" source files.
const JS_EXTENSIONS: &[&str] = &["js", "mjs", "cjs", "ts"];

/// Recursively walk `dir` and collect all files whose extension is in
/// [`JS_EXTENSIONS`].
pub fn collect_js_files(dir: &Path) -> Vec<PathBuf> {
    let mut result = Vec::new();
    collect_js_files_inner(dir, &mut result);
    result
}

fn collect_js_files_inner(dir: &Path, out: &mut Vec<PathBuf>) {
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(err) => {
            tracing::debug!(path = %dir.display(), %err, "skipping unreadable directory");
            return;
        }
    };

    for entry in entries.filter_map(|e| e.ok()) {
        let path = entry.path();
        if path.is_dir() {
            // Skip node_modules — we only care about the package's own code.
            if path
                .file_name()
                .map(|n| n == "node_modules")
                .unwrap_or(false)
            {
                continue;
            }
            collect_js_files_inner(&path, out);
        } else if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
            if JS_EXTENSIONS.contains(&ext) {
                out.push(path);
            }
        }
    }
}
