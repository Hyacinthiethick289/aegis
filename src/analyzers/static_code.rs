use std::path::PathBuf;
use std::sync::OnceLock;

use regex::Regex;

use crate::types::{Finding, FindingCategory, Severity};

use super::{truncate, Analyzer};

// ---------------------------------------------------------------------------
// Pattern definitions
// ---------------------------------------------------------------------------

struct Pattern {
    regex: &'static OnceLock<Regex>,
    severity: Severity,
    category: FindingCategory,
    title: &'static str,
    description: &'static str,
}

macro_rules! def_pattern {
    ($name:ident) => {
        static $name: OnceLock<Regex> = OnceLock::new();
    };
}

// CRITICAL
def_pattern!(RE_EVAL_DYNAMIC);
def_pattern!(RE_FUNCTION_CTOR);
def_pattern!(RE_BUFFER_EVAL);
def_pattern!(RE_CHILD_PROC_EXEC);
def_pattern!(RE_PIPE_TO_SHELL);

// HIGH
def_pattern!(RE_REQUIRE_CHILD_PROC);
def_pattern!(RE_IMPORT_CHILD_PROC);
def_pattern!(RE_ENV_HARVEST);
def_pattern!(RE_SENSITIVE_READ);
def_pattern!(RE_RAW_SOCKET);

// MEDIUM
def_pattern!(RE_HTTP_HARDCODED_IP);
def_pattern!(RE_DNS_EXFIL);
def_pattern!(RE_FS_WRITE_SYNC);
def_pattern!(RE_WEBSOCKET);
def_pattern!(RE_CRYPTO_DECIPHER);

// LOW
def_pattern!(RE_FETCH_DYNAMIC);
def_pattern!(RE_XHR);
def_pattern!(RE_FS_READ);

fn patterns() -> &'static [Pattern] {
    static PATTERNS: OnceLock<Vec<Pattern>> = OnceLock::new();
    PATTERNS.get_or_init(|| {
        // Initialise every regex on first access
        RE_EVAL_DYNAMIC.get_or_init(|| {
            // eval( with dynamic content -- exclude eval("literal")
            Regex::new(r#"eval\s*\([^"'][^)]*\)"#).unwrap()
        });
        RE_FUNCTION_CTOR.get_or_init(|| Regex::new(r#"(?i)new\s+Function\s*\("#).unwrap());
        RE_BUFFER_EVAL.get_or_init(|| {
            // Buffer.from(...) on same line or nearby with eval/Function
            Regex::new(r#"Buffer\.from\s*\(.*(?:eval|Function)"#).unwrap()
        });
        RE_CHILD_PROC_EXEC.get_or_init(|| {
            Regex::new(r#"child_process.*\.\s*(?:exec|execSync|spawn)\s*\("#).unwrap()
        });
        RE_PIPE_TO_SHELL
            .get_or_init(|| Regex::new(r#"(?:curl|wget)\s+[^\|]*\|\s*(?:bash|sh)\b"#).unwrap());

        RE_REQUIRE_CHILD_PROC
            .get_or_init(|| Regex::new(r#"require\s*\(\s*['"]child_process['"]\s*\)"#).unwrap());
        RE_IMPORT_CHILD_PROC
            .get_or_init(|| Regex::new(r#"import\s+.*from\s+['"]child_process['"]\s*"#).unwrap());
        RE_ENV_HARVEST.get_or_init(|| {
            // Two or more process.env accesses on the same line (harvesting)
            Regex::new(r#"process\.env\b.*process\.env\b"#).unwrap()
        });
        RE_SENSITIVE_READ.get_or_init(|| {
            Regex::new(
                r#"fs\.readFileSync\s*\(\s*['"](?:/etc/passwd|/etc/shadow|~/.ssh|~/.aws|~/.npmrc)"#,
            )
            .unwrap()
        });
        RE_RAW_SOCKET
            .get_or_init(|| Regex::new(r#"(?:net\.connect|dgram\.createSocket)\s*\("#).unwrap());

        RE_HTTP_HARDCODED_IP.get_or_init(|| {
            Regex::new(r#"https?\.request\s*\(\s*['"]https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}"#)
                .unwrap()
        });
        RE_DNS_EXFIL.get_or_init(|| Regex::new(r#"dns\.(?:lookup|resolve)\s*\("#).unwrap());
        RE_FS_WRITE_SYNC.get_or_init(|| Regex::new(r#"fs\.writeFileSync\s*\("#).unwrap());
        RE_WEBSOCKET.get_or_init(|| Regex::new(r#"new\s+WebSocket\s*\("#).unwrap());
        RE_CRYPTO_DECIPHER.get_or_init(|| Regex::new(r#"crypto\.createDecipher\s*\("#).unwrap());

        RE_FETCH_DYNAMIC.get_or_init(|| {
            // fetch( with a variable, not a plain string literal
            Regex::new(r#"fetch\s*\([^"'][^)]*\)"#).unwrap()
        });
        RE_XHR.get_or_init(|| Regex::new(r#"XMLHttpRequest"#).unwrap());
        RE_FS_READ.get_or_init(|| Regex::new(r#"fs\.(?:readFileSync|readFile)\s*\("#).unwrap());

        vec![
            // CRITICAL
            Pattern {
                regex: &RE_EVAL_DYNAMIC,
                severity: Severity::Critical,
                category: FindingCategory::CodeExecution,
                title: "Dynamic eval() detected",
                description: "eval() with dynamic content can execute arbitrary code",
            },
            Pattern {
                regex: &RE_FUNCTION_CTOR,
                severity: Severity::Critical,
                category: FindingCategory::CodeExecution,
                title: "Function constructor with dynamic string",
                description:
                    "new Function() can execute arbitrary code, often used for obfuscation",
            },
            Pattern {
                regex: &RE_BUFFER_EVAL,
                severity: Severity::Critical,
                category: FindingCategory::Obfuscation,
                title: "Buffer.from + eval/Function obfuscation",
                description: "Decoding a buffer and evaluating it is a common malware pattern",
            },
            Pattern {
                regex: &RE_CHILD_PROC_EXEC,
                severity: Severity::Critical,
                category: FindingCategory::ProcessSpawn,
                title: "child_process exec/spawn call",
                description: "Direct command execution via child_process",
            },
            Pattern {
                regex: &RE_PIPE_TO_SHELL,
                severity: Severity::Critical,
                category: FindingCategory::ProcessSpawn,
                title: "Pipe-to-shell pattern (curl|bash)",
                description: "Downloading and executing remote scripts is extremely dangerous",
            },
            // HIGH
            Pattern {
                regex: &RE_REQUIRE_CHILD_PROC,
                severity: Severity::High,
                category: FindingCategory::ProcessSpawn,
                title: "require('child_process')",
                description: "Package imports child_process module",
            },
            Pattern {
                regex: &RE_IMPORT_CHILD_PROC,
                severity: Severity::High,
                category: FindingCategory::ProcessSpawn,
                title: "import from 'child_process'",
                description: "Package imports child_process module via ESM",
            },
            Pattern {
                regex: &RE_ENV_HARVEST,
                severity: Severity::High,
                category: FindingCategory::EnvAccess,
                title: "Environment variable harvesting",
                description: "Multiple process.env accesses suggest credential harvesting",
            },
            Pattern {
                regex: &RE_SENSITIVE_READ,
                severity: Severity::High,
                category: FindingCategory::FileSystemAccess,
                title: "Sensitive file read",
                description: "Reading sensitive system files (passwd, ssh keys, credentials)",
            },
            Pattern {
                regex: &RE_RAW_SOCKET,
                severity: Severity::High,
                category: FindingCategory::NetworkAccess,
                title: "Raw network socket",
                description: "Raw TCP/UDP socket usage outside normal HTTP patterns",
            },
            // MEDIUM
            Pattern {
                regex: &RE_HTTP_HARDCODED_IP,
                severity: Severity::Medium,
                category: FindingCategory::NetworkAccess,
                title: "HTTP request to hardcoded IP",
                description: "HTTP requests to raw IP addresses are suspicious",
            },
            Pattern {
                regex: &RE_DNS_EXFIL,
                severity: Severity::Medium,
                category: FindingCategory::NetworkAccess,
                title: "DNS lookup/resolve",
                description: "DNS operations can be used for data exfiltration",
            },
            Pattern {
                regex: &RE_FS_WRITE_SYNC,
                severity: Severity::Medium,
                category: FindingCategory::FileSystemAccess,
                title: "Synchronous file write",
                description: "fs.writeFileSync detected -- verify target path is safe",
            },
            Pattern {
                regex: &RE_WEBSOCKET,
                severity: Severity::Medium,
                category: FindingCategory::NetworkAccess,
                title: "WebSocket connection",
                description: "WebSocket connections can be used for C2 communication",
            },
            Pattern {
                regex: &RE_CRYPTO_DECIPHER,
                severity: Severity::Medium,
                category: FindingCategory::Obfuscation,
                title: "Crypto decipher usage",
                description: "Decrypting payloads at runtime may indicate hidden malicious code",
            },
            // LOW
            Pattern {
                regex: &RE_FETCH_DYNAMIC,
                severity: Severity::Low,
                category: FindingCategory::NetworkAccess,
                title: "fetch() with dynamic URL",
                description: "Network request with a dynamic URL",
            },
            Pattern {
                regex: &RE_XHR,
                severity: Severity::Low,
                category: FindingCategory::NetworkAccess,
                title: "XMLHttpRequest usage",
                description: "Legacy XHR detected -- uncommon in modern Node packages",
            },
            Pattern {
                regex: &RE_FS_READ,
                severity: Severity::Low,
                category: FindingCategory::FileSystemAccess,
                title: "File read operation",
                description: "File system read detected -- verify it reads expected paths",
            },
        ]
    })
}

// ---------------------------------------------------------------------------
// Analyzer
// ---------------------------------------------------------------------------

/// Check if a finding is in a known HTTP library where network patterns are expected.
fn is_http_library_pattern(path: &str, line: &str) -> bool {
    let http_lib_paths = [
        "adapters/xhr",
        "adapters/http",
        "adapters/fetch",
        "platform/common",
        "lib/request",
        "lib/response",
    ];
    let is_http_lib = http_lib_paths.iter().any(|p| path.contains(p));

    // Also skip lines that are just comments about XHR/fetch
    let is_comment = line.trim_start().starts_with("//")
        || line.trim_start().starts_with("*")
        || line.trim_start().starts_with("/*");

    is_http_lib || is_comment
}

/// Static code analysis for dangerous patterns (eval, child_process, etc.).
pub struct StaticCodeAnalyzer;

impl Analyzer for StaticCodeAnalyzer {
    fn analyze(
        &self,
        files: &[(PathBuf, String)],
        _package_json: &serde_json::Value,
    ) -> Vec<Finding> {
        let pats = patterns();
        let mut findings = Vec::new();

        for (path, content) in files {
            // Only scan JS/TS files
            let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
            if !matches!(ext, "js" | "cjs" | "mjs" | "ts" | "tsx" | "jsx") {
                continue;
            }

            // Skip minified files — they trigger too many false positives
            let file_name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
            if file_name.contains(".min.") {
                continue;
            }

            // Skip dist/bundle directories for LOW severity patterns
            let path_str = path.display().to_string();
            let is_dist = path_str.contains("/dist/") || path_str.contains("/bundle/");

            for (line_num, line) in content.lines().enumerate() {
                for pat in pats {
                    // Skip LOW patterns in dist/ directories (too noisy)
                    if is_dist && pat.severity == Severity::Low {
                        continue;
                    }

                    let re = pat.regex.get().expect("pattern not initialised");
                    if re.is_match(line) {
                        // Skip XHR/fetch in known HTTP libraries (axios, got, node-fetch, etc.)
                        if matches!(pat.severity, Severity::Low)
                            && is_http_library_pattern(&path_str, line)
                        {
                            continue;
                        }

                        findings.push(Finding {
                            severity: pat.severity,
                            category: pat.category.clone(),
                            title: pat.title.to_string(),
                            description: pat.description.to_string(),
                            file: Some(path.display().to_string()),
                            line: Some(line_num + 1),
                            snippet: Some(truncate(line, 100)),
                        });
                    }
                }
            }
        }

        findings
    }
}
