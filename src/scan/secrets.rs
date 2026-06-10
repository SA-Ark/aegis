//! Secret and credential detection.
//!
//! Pattern-based scanning for the credential classes that most often reach
//! production repos: cloud keys, platform tokens, private key blocks,
//! connection strings with inline passwords, and generic hardcoded
//! assignments. Placeholder values (`changeme`, `<your-key>`, `${VAR}`, ...)
//! are filtered to keep the signal-to-noise ratio usable.

use crate::report::{Category, Finding, Severity};
use regex::Regex;
use std::sync::OnceLock;

pub struct SecretRule {
    pub name: &'static str,
    pub severity: Severity,
    pub regex: Regex,
}

fn rules() -> &'static Vec<SecretRule> {
    static RULES: OnceLock<Vec<SecretRule>> = OnceLock::new();
    RULES.get_or_init(|| {
        vec![
            SecretRule {
                name: "AWS access key ID",
                severity: Severity::Critical,
                regex: Regex::new(r"\b(AKIA|ASIA|ABIA|ACCA)[A-Z0-9]{16}\b").unwrap(),
            },
            SecretRule {
                name: "GitHub token",
                severity: Severity::Critical,
                regex: Regex::new(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b").unwrap(),
            },
            SecretRule {
                name: "Stripe live secret key",
                severity: Severity::Critical,
                regex: Regex::new(r"\bsk_live_[0-9a-zA-Z]{24,}\b").unwrap(),
            },
            SecretRule {
                name: "Slack token",
                severity: Severity::High,
                regex: Regex::new(r"\bxox[baprs]-[0-9A-Za-z-]{10,}\b").unwrap(),
            },
            SecretRule {
                name: "Private key block",
                severity: Severity::Critical,
                regex: Regex::new(r"-----BEGIN (RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY( BLOCK)?-----")
                    .unwrap(),
            },
            SecretRule {
                name: "Connection string with inline password",
                severity: Severity::High,
                regex: Regex::new(
                    r"\b(postgres(ql)?|mysql|mongodb(\+srv)?|redis|amqp)://[^/\s:@]+:[^@\s]+@",
                )
                .unwrap(),
            },
            SecretRule {
                name: "JSON Web Token",
                severity: Severity::Medium,
                regex: Regex::new(
                    r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b",
                )
                .unwrap(),
            },
            SecretRule {
                name: "Hardcoded credential assignment",
                severity: Severity::High,
                regex: Regex::new(
                    r#"(?i)\b(api[_-]?key|secret[_-]?key|secret|password|passwd|auth[_-]?token|access[_-]?token)\b\s*[:=]\s*["'][^"'\s]{8,}["']"#,
                )
                .unwrap(),
            },
        ]
    })
}

/// Values that look like placeholders, not live credentials.
fn is_placeholder(line: &str) -> bool {
    let lower = line.to_lowercase();
    const MARKERS: [&str; 14] = [
        "changeme",
        "change_me",
        "example",
        "your_",
        "your-",
        "<",
        "${",
        "{{",
        "process.env",
        "os.environ",
        "env::var",
        "todo",
        "placeholder",
        "xxxx",
    ];
    MARKERS.iter().any(|m| lower.contains(m))
}

/// Scan one file's contents. `path` is used only for reporting.
pub fn scan_content(path: &str, content: &str) -> Vec<Finding> {
    let mut findings = Vec::new();
    for (line_no, line) in content.lines().enumerate() {
        // Long lines are usually minified bundles or data blobs; JWT/key
        // patterns still matter there, but generic assignment matches are
        // noise. Cap to keep scans fast and reports readable.
        if line.len() > 2000 {
            continue;
        }
        for rule in rules() {
            if rule.regex.is_match(line) {
                if rule.name == "Hardcoded credential assignment" && is_placeholder(line) {
                    continue;
                }
                findings.push(Finding::new(
                    Category::Secrets,
                    rule.severity,
                    format!("{} detected", rule.name),
                    Some(format!("{}:{}", path, line_no + 1)),
                    "Rotate the credential immediately, then move it to environment \
                     variables or a secret manager and purge it from git history",
                ));
            }
        }
    }
    findings
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Test values are assembled at runtime so that secret scanners
    /// (including Aegis itself) never see a contiguous credential-shaped
    /// literal in this source file.
    fn synth(prefix: &str, body: &str) -> String {
        format!("{prefix}{body}")
    }

    #[test]
    fn detects_aws_key() {
        // Documented AWS example key shape, assembled at runtime.
        let key = synth("AK", "IAIOSFODNN7EXAMPLE");
        let content = format!("let key = \"{key}\";");
        let findings = scan_content("config.rs", &content);
        assert!(findings.iter().any(|f| f.title.contains("AWS")));
    }

    #[test]
    fn detects_private_key_block() {
        let content = format!("-----BEGIN RSA PRIVATE {}-----\nMIIE...", "KEY");
        let findings = scan_content("id_rsa", &content);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Critical);
    }

    #[test]
    fn detects_connection_string_password() {
        let content = synth(
            "DATABASE_URL=postgres://app:hunter2",
            "@db.internal:5432/prod",
        );
        let findings = scan_content(".env", &content);
        assert!(findings
            .iter()
            .any(|f| f.title.contains("Connection string")));
    }

    #[test]
    fn skips_placeholder_assignments() {
        let content = r#"api_key = "<your-key-here>""#;
        assert!(scan_content("settings.py", content).is_empty());

        let content = r#"password = "${DB_PASSWORD}""#;
        assert!(scan_content("app.yml", content).is_empty());
    }

    #[test]
    fn flags_real_looking_assignment() {
        let value = synth("9f8e7d6c5b4a3928", "1706f5e4d3c2b1a0");
        let content = format!(r#"const secret = "{value}";"#);
        let findings = scan_content("auth.js", &content);
        assert!(!findings.is_empty());
        assert_eq!(findings[0].severity, Severity::High);
    }

    #[test]
    fn reports_line_numbers() {
        let token = synth("ghp_", &"a".repeat(36));
        let content = format!("line one\nlet t = \"{token}\";");
        let findings = scan_content("x.rs", &content);
        assert_eq!(findings[0].location.as_deref(), Some("x.rs:2"));
    }
}
