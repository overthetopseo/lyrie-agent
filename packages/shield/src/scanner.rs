//! File scanner — monitors file system for threats
//!
//! v1.0.0 GA: hash-based signature matching, heuristic analysis, LyrieRules engine.

use crate::ThreatReport;
use aho_corasick::{AhoCorasick, AhoCorasickBuilder, MatchKind};
use sha2::{Digest, Sha256};
use std::path::Path;

// ──────────────────────────────────────────────
//  Constants
// ──────────────────────────────────────────────

/// Maximum file size the scanner will read into memory: 256 MiB.
/// Files larger than this are skipped to prevent DoS.
pub const MAX_FILE_SIZE: u64 = 256 * 1024 * 1024;

/// Filesystem paths that must never be scanned (kernel/device virtual filesystems).
/// Attempting to read from these can block indefinitely or produce garbage.
static BLOCKED_PATH_PREFIXES: &[&str] = &["/proc", "/dev", "/sys"];

// ──────────────────────────────────────────────
//  Hash-based signature matching
// ──────────────────────────────────────────────

/// A hit from the known-malware hash database.
#[derive(Debug, Clone)]
pub struct SignatureMatch {
    pub sha256_hex: String,
    pub malware_name: String,
}

/// Known-malware SHA-256 signatures.
/// These are demo/test signatures — clearly labeled as such.
static KNOWN_MALWARE_HASHES: &[(&str, &str)] = &[
    // (sha256_hex, malware_name)
    (
        "a3f1e2c4b5d6e7f8091a2b3c4d5e6f70a1b2c3d4e5f60718293a4b5c6d7e8f9",
        "TEST_Emotet.GenericTrojan",
    ),
    (
        "deadbeefcafe0011223344556677889900aabbccddeeff0102030405060708090a",
        "TEST_Mirai.BotnetLoader",
    ),
    (
        "cafebabe1234567890abcdef1234567890abcdef1234567890abcdef12345678",
        "TEST_WannaCry.Ransomware",
    ),
    (
        "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20",
        "TEST_Cobalt.StrikeBeacon",
    ),
    (
        "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        "TEST_NullBytePayload.Generic",
    ),
    (
        "1111111111111111111111111111111111111111111111111111111111111111",
        "TEST_Metasploit.Meterpreter",
    ),
    (
        "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
        "TEST_XMRig.CryptoMiner",
    ),
];

/// Compute the SHA-256 of a byte slice and return the lowercase hex string.
fn sha256_of_bytes(data: &[u8]) -> String {
    let digest = Sha256::digest(data);
    hex::encode(digest)
}

/// Legacy path-based helper retained for public API compatibility.
/// Prefer the internal byte-based path for new code.
pub fn sha256_of_file(path: &Path) -> std::io::Result<String> {
    let data = std::fs::read(path)?;
    Ok(sha256_of_bytes(&data))
}

/// Scan a byte slice's hash against the known-malware signature database.
fn check_hash(data: &[u8]) -> Option<SignatureMatch> {
    let hash = sha256_of_bytes(data);
    for &(sig, name) in KNOWN_MALWARE_HASHES {
        if hash.eq_ignore_ascii_case(sig) {
            return Some(SignatureMatch {
                sha256_hex: hash,
                malware_name: name.to_string(),
            });
        }
    }
    None
}

/// Public legacy API: scan a file path against hash signatures.
pub fn scan_file_hash(path: &Path) -> Option<SignatureMatch> {
    // Honour MAX_FILE_SIZE
    if let Ok(meta) = std::fs::metadata(path) {
        if meta.len() > MAX_FILE_SIZE {
            return None;
        }
    }
    let data = std::fs::read(path).ok()?;
    check_hash(&data)
}

// ──────────────────────────────────────────────
//  Heuristic analysis
// ──────────────────────────────────────────────

/// A flag raised by heuristic analysis.
#[derive(Debug, Clone)]
pub struct HeuristicFlag {
    pub rule_id: &'static str,
    pub description: String,
}

/// Compute Shannon entropy of a byte slice (returns 0.0 for empty input).
fn shannon_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut freq = [0u64; 256];
    for &b in data {
        freq[b as usize] += 1;
    }
    let len = data.len() as f64;
    freq.iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = c as f64 / len;
            -p * p.log2()
        })
        .sum()
}

/// Known malicious string patterns (case-insensitive, matched with AhoCorasick).
static MALICIOUS_STRINGS: &[(&str, &str)] = &[
    ("eval(base64_decode", "PHP eval+base64 webshell pattern"),
    ("eval(gzinflate(base64_decode", "PHP gzip-obfuscated webshell"),
    ("powershell -enc ", "PowerShell base64-encoded command"),
    ("powershell -e ", "PowerShell encoded shorthand"),
    ("cmd.exe /c ", "cmd.exe shell invocation"),
    ("WScript.Shell", "Windows scripting host shell"),
    ("document.write(unescape(", "JavaScript unescape obfuscation"),
    (
        "xp_cmdshell",
        "SQL Server shell-execution stored procedure",
    ),
    ("/bin/bash -i >& /dev/tcp/", "Bash reverse-shell one-liner"),
    ("nc -e /bin/sh", "Netcat reverse shell"),
    ("base64 -d |", "Base64 pipe decode"),
    ("chmod 777", "World-writable permission grant"),
    ("strrev(str_rot13(", "PHP string obfuscation chain"),
];

/// Build a case-insensitive AhoCorasick automaton for all MALICIOUS_STRINGS patterns.
fn build_malicious_ac() -> AhoCorasick {
    let patterns: Vec<&str> = MALICIOUS_STRINGS.iter().map(|(p, _)| *p).collect();
    AhoCorasickBuilder::new()
        .ascii_case_insensitive(true)
        .match_kind(MatchKind::LeftmostFirst)
        .build(patterns)
        .expect("AhoCorasick build should not fail for static patterns")
}

/// Run heuristic checks on pre-read file content.
/// `path` is still needed for metadata-based checks (permissions, extension, etc.).
pub fn scan_heuristic_with_content(path: &Path, content: &[u8]) -> Vec<HeuristicFlag> {
    let mut flags: Vec<HeuristicFlag> = Vec::new();
    let path_str = path.to_string_lossy();

    // ── 1. Suspicious extension in wrong location ──────────────────────────
    let suspicious_in_tmp = [".exe", ".dll", ".bat", ".cmd"];
    for ext in &suspicious_in_tmp {
        if path_str.to_lowercase().ends_with(ext)
            && (path_str.starts_with("/tmp") || path_str.starts_with("/var/tmp"))
        {
            flags.push(HeuristicFlag {
                rule_id: "H_SUSPICIOUS_EXT_LOCATION",
                description: format!(
                    "Executable/script '{}' found in temp directory",
                    ext
                ),
            });
        }
    }

    // ── 2. .sh file with world-writable perms ─────────────────────────────
    #[cfg(unix)]
    if path_str.ends_with(".sh") {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(meta) = std::fs::metadata(path) {
            let mode = meta.permissions().mode();
            if mode & 0o002 != 0 {
                flags.push(HeuristicFlag {
                    rule_id: "H_WORLD_WRITABLE_SCRIPT",
                    description: "Shell script is world-writable (mode & 002)".to_string(),
                });
            }
        }
    }

    if content.is_empty() {
        return flags;
    }

    // ── 3. High entropy ────────────────────────────────────────────────────
    let entropy = shannon_entropy(content);
    if entropy > 7.5 {
        flags.push(HeuristicFlag {
            rule_id: "H_HIGH_ENTROPY",
            description: format!(
                "File entropy {:.3} > 7.5 — likely packed, encrypted, or obfuscated",
                entropy
            ),
        });
    }

    // ── 4. Known malicious strings (AhoCorasick, single pass) ─────────────
    let ac = build_malicious_ac();
    let mut matched_indices: Vec<usize> = ac
        .find_iter(content)
        .map(|m| m.pattern().as_usize())
        .collect();
    matched_indices.sort_unstable();
    matched_indices.dedup();
    for idx in matched_indices {
        let (pattern, desc) = MALICIOUS_STRINGS[idx];
        flags.push(HeuristicFlag {
            rule_id: "H_MALICIOUS_STRING",
            description: format!("Detected pattern '{}': {}", pattern, desc),
        });
    }

    // ── 5. Executable bit on non-binary files ─────────────────────────────
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(meta) = std::fs::metadata(path) {
            let mode = meta.permissions().mode();
            let is_exec = mode & 0o111 != 0;
            let looks_like_script = content.starts_with(b"#!")
                || path_str.ends_with(".py")
                || path_str.ends_with(".rb")
                || path_str.ends_with(".pl")
                || path_str.ends_with(".php");
            if is_exec && !looks_like_script && !content.is_empty() {
                let is_elf = content.starts_with(b"\x7fELF");
                let is_macho = content.starts_with(b"\xfe\xed\xfa")
                    || content.starts_with(b"\xce\xfa\xed\xfe")
                    || content.starts_with(b"\xcf\xfa\xed\xfe");
                if !is_elf && !is_macho {
                    flags.push(HeuristicFlag {
                        rule_id: "H_EXEC_NON_BINARY",
                        description:
                            "Executable bit set on file that is neither ELF/Mach-O nor a recognised script"
                                .to_string(),
                    });
                }
            }
        }
    }

    flags
}

/// Public legacy API: scan a file path for heuristic flags.
pub fn scan_heuristic(path: &Path) -> Vec<HeuristicFlag> {
    let content = match std::fs::read(path) {
        Ok(c) => c,
        Err(_) => return Vec::new(),
    };
    scan_heuristic_with_content(path, &content)
}

// ──────────────────────────────────────────────
//  LyrieRules — lightweight YARA-like engine
// ──────────────────────────────────────────────

/// Condition for a LyrieRule: match ANY or ALL listed strings.
#[derive(Debug, Clone, PartialEq)]
pub enum RuleCondition {
    Any,
    All,
}

/// A lightweight rule similar in spirit to a YARA rule.
#[derive(Debug, Clone)]
pub struct LyrieRule {
    pub name: String,
    pub description: String,
    /// Byte patterns (UTF-8) to search for in file content.
    pub strings: Vec<String>,
    pub condition: RuleCondition,
}

/// Test whether `rule` matches `content` using AhoCorasick.
pub fn apply_rule(rule: &LyrieRule, content: &[u8]) -> bool {
    if rule.strings.is_empty() {
        return false;
    }
    let ac = AhoCorasickBuilder::new()
        .ascii_case_insensitive(true)
        .match_kind(MatchKind::LeftmostFirst)
        .build(&rule.strings)
        .expect("AhoCorasick build should not fail");

    match rule.condition {
        RuleCondition::Any => ac.is_match(content),
        RuleCondition::All => {
            let mut found = vec![false; rule.strings.len()];
            for m in ac.find_iter(content) {
                found[m.pattern().as_usize()] = true;
            }
            found.iter().all(|&f| f)
        }
    }
}

/// Apply a slice of rules and return the names of all that matched.
pub fn apply_rules(rules: &[LyrieRule], content: &[u8]) -> Vec<String> {
    rules
        .iter()
        .filter(|r| apply_rule(r, content))
        .map(|r| r.name.clone())
        .collect()
}

/// Return the five built-in LyrieRules covering common threat categories.
pub fn builtin_rules() -> Vec<LyrieRule> {
    vec![
        LyrieRule {
            name: "LR_WEBSHELL_PHP".to_string(),
            description: "PHP webshell — eval/base64 execution pattern".to_string(),
            strings: vec![
                "eval(".to_string(),
                "base64_decode(".to_string(),
                "$_REQUEST".to_string(),
            ],
            condition: RuleCondition::Any,
        },
        LyrieRule {
            name: "LR_REVERSE_SHELL".to_string(),
            description: "Reverse shell patterns (bash/nc/python)".to_string(),
            strings: vec![
                "/dev/tcp/".to_string(),
                "nc -e".to_string(),
                "socket.connect(".to_string(),
                "subprocess.Popen".to_string(),
                "os.dup2(".to_string(),
            ],
            condition: RuleCondition::Any,
        },
        LyrieRule {
            name: "LR_CRYPTO_MINER".to_string(),
            description: "Crypto miner indicators (XMRig / stratum protocol)".to_string(),
            strings: vec![
                "stratum+tcp://".to_string(),
                "stratum+ssl://".to_string(),
                "xmrig".to_string(),
                "monero".to_string(),
                "pool.minexmr.com".to_string(),
            ],
            condition: RuleCondition::Any,
        },
        LyrieRule {
            name: "LR_RANSOMWARE_MARKERS".to_string(),
            description: "Ransomware strings — encryption + ransom note patterns".to_string(),
            strings: vec![
                "Your files have been encrypted".to_string(),
                "send bitcoin".to_string(),
                "decrypt your files".to_string(),
                "CryptoLocker".to_string(),
                "AES_encrypt".to_string(),
            ],
            condition: RuleCondition::Any,
        },
        LyrieRule {
            name: "LR_POWERSHELL_DROPPER".to_string(),
            description: "PowerShell dropper / downloader patterns".to_string(),
            strings: vec![
                "DownloadString(".to_string(),
                "IEX(".to_string(),
                "Invoke-Expression".to_string(),
                "powershell -enc".to_string(),
                "Net.WebClient".to_string(),
            ],
            condition: RuleCondition::Any,
        },
    ]
}

// ──────────────────────────────────────────────
//  Scanner struct
// ──────────────────────────────────────────────

pub struct Scanner {
    watched_paths: Vec<String>,
    rules: Vec<LyrieRule>,
}

impl Scanner {
    pub fn new() -> Self {
        Scanner {
            watched_paths: vec![],
            rules: builtin_rules(),
        }
    }

    pub fn watch(&mut self, path: &str) {
        self.watched_paths.push(path.to_string());
    }

    /// Add a custom LyrieRule to this scanner instance.
    pub fn add_rule(&mut self, rule: LyrieRule) {
        self.rules.push(rule);
    }

    /// Full-pipeline scan: extension check → special path guard → single file read →
    /// hash signature → heuristics → LyrieRules.
    pub fn scan_file(&self, path: &str) -> ThreatReport {
        // ── Extension check ────────────────────────────────────────────────
        let dangerous_extensions = [".exe", ".bat", ".cmd", ".ps1", ".vbs", ".js.download"];
        for ext in &dangerous_extensions {
            if path.to_lowercase().ends_with(ext) {
                return ThreatReport::threat(
                    crate::Severity::Medium,
                    "suspicious_extension",
                    &format!("File has potentially dangerous extension: {}", ext),
                );
            }
        }

        // ── Block kernel / device virtual filesystem paths ─────────────────
        for prefix in BLOCKED_PATH_PREFIXES {
            // Match /proc, /proc/, /proc/something — but not /processor etc.
            if path == *prefix
                || path.starts_with(&format!("{}/", prefix))
            {
                return ThreatReport {
                    blocked: false,
                    severity: crate::Severity::None,
                    threat_type: Some("special_path_skipped".to_string()),
                    description: Some(format!(
                        "Path '{}' is inside a virtual/device filesystem ({}) — scan skipped",
                        path, prefix
                    )),
                    file_path: Some(path.to_string()),
                    timestamp: {
                        format!(
                            "{}",
                            std::time::SystemTime::now()
                                .duration_since(std::time::UNIX_EPOCH)
                                .unwrap_or_default()
                                .as_secs()
                        )
                    },
                    action_taken: None,
                };
            }
        }

        let p = Path::new(path);

        // ── File size check before reading ─────────────────────────────────
        if let Ok(meta) = std::fs::metadata(p) {
            if meta.len() > MAX_FILE_SIZE {
                return ThreatReport::threat(
                    crate::Severity::Low,
                    "file_too_large",
                    &format!(
                        "File size {} bytes exceeds MAX_FILE_SIZE ({} bytes) — scan skipped",
                        meta.len(),
                        MAX_FILE_SIZE
                    ),
                );
            }
        }

        // ── Single unified file read ───────────────────────────────────────
        let content = match std::fs::read(p) {
            Ok(c) => c,
            Err(e) => {
                // Unreadable file — return clean (we cannot make a determination)
                return ThreatReport {
                    blocked: false,
                    severity: crate::Severity::None,
                    threat_type: Some("read_error".to_string()),
                    description: Some(format!("Could not read file: {}", e)),
                    file_path: Some(path.to_string()),
                    timestamp: format!(
                        "{}",
                        std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap_or_default()
                            .as_secs()
                    ),
                    action_taken: None,
                };
            }
        };

        // ── Hash-based signature matching ──────────────────────────────────
        if let Some(sig) = check_hash(&content) {
            return ThreatReport::threat(
                crate::Severity::Critical,
                "known_malware_hash",
                &format!(
                    "SHA-256 {} matched known malware signature: {}",
                    &sig.sha256_hex[..16],
                    sig.malware_name
                ),
            );
        }

        // ── Heuristic analysis (uses pre-read content) ─────────────────────
        let hflags = scan_heuristic_with_content(p, &content);
        if !hflags.is_empty() {
            let desc = hflags
                .iter()
                .map(|f| format!("[{}] {}", f.rule_id, f.description))
                .collect::<Vec<_>>()
                .join("; ");
            return ThreatReport::threat(
                crate::Severity::High,
                "heuristic_detection",
                &desc,
            );
        }

        // ── LyrieRules engine (uses same content) ──────────────────────────
        let matched = apply_rules(&self.rules, &content);
        if !matched.is_empty() {
            return ThreatReport::threat(
                crate::Severity::High,
                "lyrie_rule_match",
                &format!("Matched rules: {}", matched.join(", ")),
            );
        }

        ThreatReport::clean()
    }
}

// ──────────────────────────────────────────────
//  Tests
// ──────────────────────────────────────────────
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entropy_empty() {
        assert_eq!(shannon_entropy(&[]), 0.0);
    }

    #[test]
    fn entropy_uniform() {
        let data = vec![0u8; 1000];
        assert!(shannon_entropy(&data) < 0.001);
    }

    #[test]
    fn entropy_high_random() {
        let data: Vec<u8> = (0u8..=255).cycle().take(2048).collect();
        let e = shannon_entropy(&data);
        assert!(e > 7.9, "expected high entropy, got {}", e);
    }

    #[test]
    fn rule_any_match() {
        let rule = LyrieRule {
            name: "test".to_string(),
            description: "".to_string(),
            strings: vec!["hello".to_string(), "world".to_string()],
            condition: RuleCondition::Any,
        };
        assert!(apply_rule(&rule, b"say hello there"));
        assert!(!apply_rule(&rule, b"nothing here"));
    }

    #[test]
    fn rule_all_must_match() {
        let rule = LyrieRule {
            name: "test_all".to_string(),
            description: "".to_string(),
            strings: vec!["eval(".to_string(), "base64".to_string()],
            condition: RuleCondition::All,
        };
        assert!(apply_rule(&rule, b"eval(base64_decode('...'))")); // both present
        assert!(!apply_rule(&rule, b"eval('plain')")); // only one
    }

    #[test]
    fn builtin_rules_count() {
        assert_eq!(builtin_rules().len(), 5);
    }

    #[test]
    fn crypto_miner_rule_fires() {
        let rules = builtin_rules();
        let content = b"connecting to stratum+tcp://pool.example.com:3333";
        let matched = apply_rules(&rules, content);
        assert!(matched.contains(&"LR_CRYPTO_MINER".to_string()));
    }

    #[test]
    fn max_file_size_constant() {
        assert_eq!(MAX_FILE_SIZE, 256 * 1024 * 1024);
    }

    #[test]
    fn blocked_path_proc() {
        let scanner = Scanner::new();
        let r = scanner.scan_file("/proc/self/mem");
        assert_eq!(
            r.threat_type.as_deref().unwrap_or(""),
            "special_path_skipped"
        );
        assert!(!r.blocked, "/proc path should not be 'blocked', just skipped");
    }

    #[test]
    fn blocked_path_dev() {
        let scanner = Scanner::new();
        let r = scanner.scan_file("/dev/sda");
        assert_eq!(
            r.threat_type.as_deref().unwrap_or(""),
            "special_path_skipped"
        );
    }

    #[test]
    fn blocked_path_sys() {
        let scanner = Scanner::new();
        let r = scanner.scan_file("/sys/kernel/debug");
        assert_eq!(
            r.threat_type.as_deref().unwrap_or(""),
            "special_path_skipped"
        );
    }

    #[test]
    fn malicious_string_aho_corasick() {
        // xp_cmdshell mixed case should be caught
        let content = b"SELECT xP_CmDsHeLL('whoami')";
        let flags = scan_heuristic_with_content(Path::new("/tmp/test.sql"), content);
        assert!(
            flags.iter().any(|f| f.rule_id == "H_MALICIOUS_STRING"),
            "AhoCorasick should catch case-insensitive xp_cmdshell"
        );
    }
}

// NOTE (v1.0.0): The KNOWN_MALWARE_HASHES database contains TEST signatures only.
// Hash-based detection serves as the architectural scaffold for a real threat-intel
// feed integration (VirusTotal, NSRL, or internal DB). In production deployments,
// replace or augment with a live signature source.
// Real detection in v1.0.0 is delivered via heuristic analysis + LyrieRules engine.
