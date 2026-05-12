//! File scanner — monitors file system for threats
//!
//! v1.0.0 GA: hash-based signature matching, heuristic analysis, LyrieRules engine.

use crate::ThreatReport;
use sha2::{Digest, Sha256};
use std::path::Path;

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

/// Read a file and compute its SHA-256 digest, returning the lowercase hex string.
fn sha256_of_file(path: &Path) -> std::io::Result<String> {
    let data = std::fs::read(path)?;
    let digest = Sha256::digest(&data);
    Ok(hex::encode(digest))
}

/// Scan a file's hash against the known-malware signature database.
pub fn scan_file_hash(path: &Path) -> Option<SignatureMatch> {
    let hash = sha256_of_file(path).ok()?;
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

/// Check for known malicious string patterns inside a file's content.
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

/// Run heuristic checks on a file and return any flags raised.
pub fn scan_heuristic(path: &Path) -> Vec<HeuristicFlag> {
    let mut flags: Vec<HeuristicFlag> = Vec::new();

    // ── 1. Suspicious extension in wrong location ──────────────────────────
    let path_str = path.to_string_lossy();
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

    // ── 2. .sh file with world-writable/executable perms ──────────────────
    #[cfg(unix)]
    if path_str.ends_with(".sh") {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(meta) = std::fs::metadata(path) {
            let mode = meta.permissions().mode();
            if mode & 0o002 != 0 {
                // world-writable
                flags.push(HeuristicFlag {
                    rule_id: "H_WORLD_WRITABLE_SCRIPT",
                    description: "Shell script is world-writable (mode & 002)".to_string(),
                });
            }
        }
    }

    // Read file content for remaining checks (skip if unreadable)
    let content = match std::fs::read(path) {
        Ok(c) => c,
        Err(_) => return flags,
    };

    // ── 3. High entropy — packed or encrypted content ─────────────────────
    let entropy = shannon_entropy(&content);
    if entropy > 7.5 {
        flags.push(HeuristicFlag {
            rule_id: "H_HIGH_ENTROPY",
            description: format!(
                "File entropy {:.3} > 7.5 — likely packed, encrypted, or obfuscated",
                entropy
            ),
        });
    }

    // ── 4. Known malicious strings ─────────────────────────────────────────
    let content_lossy = String::from_utf8_lossy(&content);
    let content_lower = content_lossy.to_lowercase();
    for &(pattern, desc) in MALICIOUS_STRINGS {
        if content_lower.contains(&pattern.to_lowercase()) {
            flags.push(HeuristicFlag {
                rule_id: "H_MALICIOUS_STRING",
                description: format!("Detected pattern '{}': {}", pattern, desc),
            });
        }
    }

    // ── 5. Executable bit set on non-binary files ─────────────────────────
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(meta) = std::fs::metadata(path) {
            let mode = meta.permissions().mode();
            let is_exec = mode & 0o111 != 0;
            // "Non-binary" heuristic: starts with a text shebang or is a common script ext
            let looks_like_script = content.starts_with(b"#!")
                || path_str.ends_with(".py")
                || path_str.ends_with(".rb")
                || path_str.ends_with(".pl")
                || path_str.ends_with(".php");
            // Raise only when executable but doesn't look intentionally scripted
            if is_exec && !looks_like_script && !content.is_empty() {
                // Check for ELF/Mach-O magic — actual binaries are OK
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

/// Test whether `rule` matches `content`.
pub fn apply_rule(rule: &LyrieRule, content: &[u8]) -> bool {
    if rule.strings.is_empty() {
        return false;
    }
    match rule.condition {
        RuleCondition::Any => rule
            .strings
            .iter()
            .any(|s| contains_bytes(content, s.as_bytes())),
        RuleCondition::All => rule
            .strings
            .iter()
            .all(|s| contains_bytes(content, s.as_bytes())),
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

/// Case-insensitive substring search over raw bytes.
fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() {
        return true;
    }
    let needle_lower: Vec<u8> = needle.iter().map(|b| b.to_ascii_lowercase()).collect();
    haystack
        .windows(needle.len())
        .any(|w| w.iter().map(|b| b.to_ascii_lowercase()).collect::<Vec<_>>() == needle_lower)
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
//  Scanner struct (updated)
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

    /// Full-pipeline scan: extension check → hash signature → heuristics → LyrieRules.
    pub fn scan_file(&self, path: &str) -> ThreatReport {
        // ── Extension check (preserved from v0.1) ──────────────────────────
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

        let p = Path::new(path);

        // ── Hash-based signature matching ──────────────────────────────────
        if let Some(sig) = scan_file_hash(p) {
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

        // ── Heuristic analysis ─────────────────────────────────────────────
        let hflags = scan_heuristic(p);
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

        // ── LyrieRules engine ──────────────────────────────────────────────
        if let Ok(content) = std::fs::read(p) {
            let matched = apply_rules(&self.rules, &content);
            if !matched.is_empty() {
                return ThreatReport::threat(
                    crate::Severity::High,
                    "lyrie_rule_match",
                    &format!("Matched rules: {}", matched.join(", ")),
                );
            }
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
        // All-zero bytes → entropy = 0
        let data = vec![0u8; 1000];
        assert!(shannon_entropy(&data) < 0.001);
    }

    #[test]
    fn entropy_high_random() {
        // Pseudo-random bytes should have high entropy
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
}
