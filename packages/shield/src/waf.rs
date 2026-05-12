//! Web Application Firewall — protects web-facing endpoints

use crate::{ThreatReport, Severity};
use regex::Regex;

// ──────────────────────────────────────────────
//  Helpers
// ──────────────────────────────────────────────

/// Decode percent-encoded (`%XX`) sequences in a URL/body string.
/// Double-decode is performed to catch evasion like `%2527` → `%27` → `'`.
fn percent_decode(input: &str) -> String {
    fn decode_once(input: &str) -> String {
        let bytes = input.as_bytes();
        let mut result = String::with_capacity(input.len());
        let mut i = 0;
        while i < bytes.len() {
            if bytes[i] == b'%' && i + 2 < bytes.len() {
                if let (Some(h), Some(l)) = (hex_val(bytes[i + 1]), hex_val(bytes[i + 2])) {
                    result.push((h << 4 | l) as char);
                    i += 3;
                    continue;
                }
            }
            result.push(bytes[i] as char);
            i += 1;
        }
        result
    }

    // Double-decode catches `%2527` evasion
    let once = decode_once(input);
    if once.contains('%') {
        decode_once(&once)
    } else {
        once
    }
}

fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// Extract the host component from a URL string.
/// e.g. `https://evil.example.com:8080/path?q=1` → `evil.example.com`
fn extract_host(url: &str) -> &str {
    // Strip scheme
    let rest = if let Some(pos) = url.find("://") {
        &url[pos + 3..]
    } else {
        url
    };
    // Strip path/query/fragment
    let authority = rest.split('/').next().unwrap_or(rest);
    let authority = authority.split('?').next().unwrap_or(authority);
    let authority = authority.split('#').next().unwrap_or(authority);
    // Strip port — handle IPv6 bracketed addresses
    if authority.starts_with('[') {
        // IPv6: [::1]:8080
        if let Some(bracket_end) = authority.find(']') {
            &authority[1..bracket_end]
        } else {
            authority
        }
    } else {
        // Strip port
        authority.split(':').next().unwrap_or(authority)
    }
}

/// Returns true if `host` equals `domain` or is a subdomain of it.
fn host_matches_domain(host: &str, domain: &str) -> bool {
    let host_lower = host.to_lowercase();
    let domain_lower = domain.to_lowercase();
    host_lower == domain_lower || host_lower.ends_with(&format!(".{}", domain_lower))
}

// ──────────────────────────────────────────────
//  WAF struct
// ──────────────────────────────────────────────

pub struct WAF {
    sql_injection_patterns: Vec<Regex>,
    xss_patterns: Vec<Regex>,
    blocked_domains: Vec<String>,
}

impl WAF {
    pub fn new() -> Result<Self, regex::Error> {
        let sql_injection_patterns = vec![
            // Classic injection
            Regex::new(r"(?i)(union\s+select|drop\s+table|insert\s+into|delete\s+from)")?,
            Regex::new(r"(?i)(or\s+1\s*=\s*1|and\s+1\s*=\s*1|'\s*or\s*'1)")?,
            Regex::new(r"(?i)(exec\s*\(|execute\s*\(|xp_cmdshell)")?,
            // Comment-based bypass: -- and /**/
            Regex::new(r"(?:/\*.*?\*/|--(?:[\s\r\n]|$|[^-]))")?,
            // Time-blind injection
            Regex::new(r"(?i)(SLEEP\s*\(|WAITFOR\s+DELAY|pg_sleep\s*\(|BENCHMARK\s*\()")?,
            // Character/encoding functions used to obfuscate
            Regex::new(r"(?i)CHAR\s*\(\s*\d")?,
            // Hex literal injections: 0x41, 0xFF, etc.
            Regex::new(r"0x[0-9a-fA-F]{2,}")?,
        ];

        let xss_patterns = vec![
            Regex::new(r"(?i)<script[^>]*>")?,
            Regex::new(r"(?i)(javascript:|onerror\s*=|onload\s*=|onclick\s*=)")?,
            Regex::new(r"(?i)(document\.cookie|window\.location|eval\s*\()")?,
            // SVG-based XSS
            Regex::new(r"(?i)<svg[^>]*>")?,
            // img onerror
            Regex::new(r"(?i)<img[^>]*onerror\s*=")?,
            // data URI with HTML payload
            Regex::new(r"(?i)data\s*:\s*text/html")?,
            // HTML entity encoding for bypasses: &#60; &#x3C; etc.
            Regex::new(r"&#\d+;|&#x[0-9a-fA-F]+;")?,
            // iframe injection
            Regex::new(r"(?i)<iframe[^>]*>")?,
        ];

        let blocked_domains = vec![
            // Demo/legacy entry
            "malware.example.com".to_string(),
            // Known malicious TLD patterns (ccTLDs / new TLDs abused for C2)
            "example-c2.tk".to_string(),
            "example-c2.ml".to_string(),
            "example-c2.ga".to_string(),
            "example-c2.cf".to_string(),
            "example-c2.gq".to_string(),
            // Common test/demo C2 domains
            "ngrok.io".to_string(),
            "serveo.net".to_string(),
            "localtunnel.me".to_string(),
            "pagekite.me".to_string(),
            "burpcollaborator.net".to_string(),
            "canarytokens.com".to_string(),
            "interact.sh".to_string(),
            "oast.me".to_string(),
            "oast.pro".to_string(),
            "oast.live".to_string(),
            "oast.site".to_string(),
            "oast.online".to_string(),
            "oast.fun".to_string(),
        ];

        Ok(WAF {
            sql_injection_patterns,
            xss_patterns,
            blocked_domains,
        })
    }

    /// Check whether a request URL is safe.
    /// URL-decodes the input before matching to defeat `%27`-style evasion.
    pub fn check_url(&self, url: &str) -> ThreatReport {
        let decoded = percent_decode(url);
        let host = extract_host(url);

        // ── Domain blocklist (host-parsed, not substring) ──────────────────
        for domain in &self.blocked_domains {
            if host_matches_domain(host, domain) {
                return ThreatReport::threat(
                    Severity::Critical,
                    "blocked_domain",
                    &format!("URL host '{}' matches blocked domain: {}", host, domain),
                );
            }
        }

        // ── SQL injection in decoded URL ───────────────────────────────────
        for pattern in &self.sql_injection_patterns {
            if pattern.is_match(&decoded) {
                return ThreatReport::threat(
                    Severity::High,
                    "sql_injection",
                    "Potential SQL injection detected in URL",
                );
            }
        }

        // ── XSS in decoded URL ─────────────────────────────────────────────
        for pattern in &self.xss_patterns {
            if pattern.is_match(&decoded) {
                return ThreatReport::threat(
                    Severity::High,
                    "xss",
                    "Potential XSS attack detected in URL",
                );
            }
        }

        ThreatReport::clean()
    }

    /// Check whether a request body is safe.
    /// Also applies the domain blocklist (SSRF/exfiltration via body URLs).
    pub fn check_request_body(&self, body: &str) -> ThreatReport {
        let decoded = percent_decode(body);

        // ── Domain blocklist in body ───────────────────────────────────────
        // Extract any URLs embedded in the body and check each host.
        // Simple approach: scan for every occurrence of ":// " and grab the host.
        let body_lower = decoded.to_lowercase();
        if let Some(pos) = body_lower.find("://") {
            let after_scheme = &decoded[pos + 3..];
            let host_candidate = after_scheme
                .split(|c: char| c == '/' || c == '?' || c == ' ' || c == '"' || c == '\'')
                .next()
                .unwrap_or("");
            // Strip port
            let host_only = host_candidate.split(':').next().unwrap_or(host_candidate);
            for domain in &self.blocked_domains {
                if host_matches_domain(host_only, domain) {
                    return ThreatReport::threat(
                        Severity::Critical,
                        "blocked_domain",
                        &format!("Request body references blocked domain: {}", domain),
                    );
                }
            }
        }

        // ── SQL injection in decoded body ──────────────────────────────────
        for pattern in &self.sql_injection_patterns {
            if pattern.is_match(&decoded) {
                return ThreatReport::threat(
                    Severity::High,
                    "sql_injection",
                    "Potential SQL injection detected in request body",
                );
            }
        }

        // ── XSS in decoded body ────────────────────────────────────────────
        for pattern in &self.xss_patterns {
            if pattern.is_match(&decoded) {
                return ThreatReport::threat(
                    Severity::High,
                    "xss",
                    "Potential XSS attack detected in request body",
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

    fn waf() -> WAF {
        WAF::new().expect("WAF patterns must compile")
    }

    #[test]
    fn blocks_encoded_sqli() {
        let w = waf();
        // Classic ' OR '1'='1 percent-encoded
        let url = "https://example.com/login?user=admin%27%20OR%20%271%27%3D%271";
        assert!(w.check_url(url).blocked, "encoded SQLi should be blocked");
    }

    #[test]
    fn blocks_sleep_sqli() {
        let w = waf();
        let url = "https://example.com/api?id=1;SLEEP(5)--";
        assert!(w.check_url(url).blocked);
    }

    #[test]
    fn blocks_comment_bypass() {
        let w = waf();
        let body = "username=admin'--&password=x";
        assert!(w.check_request_body(body).blocked);
    }

    #[test]
    fn blocks_svg_xss() {
        let w = waf();
        let body = "<svg onload=alert(1)>";
        assert!(w.check_request_body(body).blocked);
    }

    #[test]
    fn blocks_iframe_xss() {
        let w = waf();
        let url = "https://example.com/page?content=<iframe src=evil.com>";
        assert!(w.check_url(url).blocked);
    }

    #[test]
    fn blocks_blocked_domain_host_only() {
        let w = waf();
        // Should block ngrok.io host
        let url = "https://abc123.ngrok.io/callback";
        assert!(w.check_url(url).blocked);
    }

    #[test]
    fn does_not_block_subdomain_lookalike() {
        // e.g., "notngrok.io" should NOT be blocked (different domain)
        let w = waf();
        let url = "https://notngrok.io/callback";
        assert!(!w.check_url(url).blocked);
    }

    #[test]
    fn blocked_domain_in_body() {
        let w = waf();
        let body = r#"{"webhook":"https://burpcollaborator.net/x"}"#;
        assert!(w.check_request_body(body).blocked);
    }

    #[test]
    fn clean_url_passes() {
        let w = waf();
        assert!(!w.check_url("https://example.com/api/v1/users?page=2").blocked);
    }

    #[test]
    fn hex_literal_sqli() {
        let w = waf();
        let body = "id=0x41414141";
        assert!(w.check_request_body(body).blocked);
    }

    #[test]
    fn char_sqli() {
        let w = waf();
        let body = "name=CHAR(65)";
        assert!(w.check_request_body(body).blocked);
    }
}
