# Contributing to Aegis

Thank you for your interest in contributing to Aegis! This guide will help you get set up and productive quickly.

## Development Environment

### Prerequisites

- **Rust toolchain** (stable) -- install via [rustup](https://rustup.rs/)
- **Git**

### Setup

```bash
git clone https://github.com/z8run/aegis.git
cd aegis
cargo build
cargo test
```

### Running Locally

```bash
# Check a package
cargo run -- check axios

# Scan a project
cargo run -- scan /path/to/project

# With debug logging
cargo run -- -v check lodash
```

## Project Structure

```
src/
  main.rs           # CLI definition, entry point, check/scan commands
  types.rs          # Core types: Finding, Severity, AnalysisReport, RiskLabel
  cache.rs          # Local result caching
  registry/
    client.rs       # npm registry API client
    tarball.rs      # Tarball download and extraction
  analyzers/
    mod.rs          # Analyzer trait definition
    static_code.rs  # Regex-based pattern matching
    ast.rs          # Tree-sitter AST analysis
    install_scripts.rs  # Suspicious install script detection
    obfuscation.rs  # Obfuscated code detection
    maintainer.rs   # Maintainer change tracking
    diff.rs         # Version diff analysis
    hallucination.rs # AI hallucination package detection
    cve.rs          # CVE lookup via OSV.dev
    deptree.rs      # Dependency tree scanning
  rules/
    loader.rs       # YAML rule loading and built-in rules
    engine.rs       # Rules engine (compiles YAML rules to regex matchers)
  scoring/
    calculator.rs   # Risk score calculation and labeling
  output/
    terminal.rs     # Tree-style terminal output
    json.rs         # JSON output for CI
rules/
  examples/         # Example community YAML rules
```

## How to Add a New Analyzer

1. Create a new file in `src/analyzers/`, e.g. `src/analyzers/my_analyzer.rs`.

2. Implement the `Analyzer` trait:

```rust
use std::path::PathBuf;
use crate::analyzers::Analyzer;
use crate::types::{Finding, FindingCategory, Severity};

pub struct MyAnalyzer;

impl Analyzer for MyAnalyzer {
    fn analyze(
        &self,
        files: &[(PathBuf, String)],
        package_json: &serde_json::Value,
    ) -> Vec<Finding> {
        let mut findings = Vec::new();
        // Your detection logic here
        findings
    }
}
```

3. Register the module in `src/analyzers/mod.rs`:

```rust
pub mod my_analyzer;
```

4. Add it to the analyzer list in `src/main.rs` inside `analyze_package()`:

```rust
let all_analyzers: Vec<Box<dyn Analyzer>> = vec![
    // ...existing analyzers...
    Box::new(analyzers::my_analyzer::MyAnalyzer),
];
```

5. Write tests in the same file or in a separate test module.

## How to Add YAML Rules

YAML rules do not require any Rust code changes. Simply create a `.yml` file with the following format:

```yaml
id: "CUSTOM-001"
name: "Rule name"
description: "What this rule detects"
severity: high          # critical, high, medium, low, info
category: suspicious    # code_execution, network_access, process_spawn, etc.
pattern: "regex_here"   # Regex pattern matched against each line
file_pattern: "*.js"    # Optional: glob to filter files
exclude_paths:          # Optional: paths to skip
  - "node_modules/"
  - "test/"
```

Place the file in the `rules/` directory and it will be loaded automatically at runtime.

See `rules/examples/` for working examples. Run the test suite after adding rules to make sure your regex patterns compile:

```bash
cargo test
```

## Code Style

- **Format** all code with `rustfmt` before committing:

  ```bash
  cargo fmt
  ```

- **Lint** with Clippy and fix any warnings:

  ```bash
  cargo clippy -- -W clippy::all
  ```

- Keep functions focused and well-documented. Public items should have doc comments (`///`).
- Prefer returning `Vec<Finding>` over mutating shared state.
- Use `anyhow::Result` for fallible operations and `thiserror` for custom error types.

## Pull Request Process

1. **Fork** the repository and create a feature branch from `main`.
2. Make your changes, including tests for new functionality.
3. Ensure all checks pass:

   ```bash
   cargo fmt --check
   cargo clippy -- -W clippy::all
   cargo test
   ```

4. Write a clear PR description explaining what the change does and why.
5. One approval from a maintainer is required to merge.

## Reporting Issues

- Use [GitHub Issues](https://github.com/z8run/aegis/issues) for bugs and feature requests.
- For security vulnerabilities, please email security@z8run.dev instead of opening a public issue.

Thank you for helping make the npm ecosystem safer!
