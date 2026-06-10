//! Live HTTP probe: fetch a URL and grade its transport security posture
//! from response headers alone. Read-only — a single GET, no fuzzing,
//! no authenticated requests.

use crate::report::{Category, Finding, Report, ReportKind, Severity};
use anyhow::{Context, Result};
use std::time::Instant;

pub struct ProbeResponse {
    pub final_url: String,
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub elapsed_ms: u128,
}

pub fn fetch(url: &str) -> Result<ProbeResponse> {
    let start = Instant::now();
    let agent = ureq::AgentBuilder::new()
        .timeout(std::time::Duration::from_secs(15))
        .redirects(5)
        .build();

    let response = match agent.get(url).call() {
        Ok(r) => r,
        // 4xx/5xx still carry the headers we grade on.
        Err(ureq::Error::Status(_, r)) => r,
        Err(e) => return Err(e).context(format!("request to {url} failed")),
    };
    let elapsed_ms = start.elapsed().as_millis();

    let mut headers = Vec::new();
    for name in response.headers_names() {
        for value in response.all(&name) {
            headers.push((name.to_lowercase(), value.to_string()));
        }
    }

    Ok(ProbeResponse {
        final_url: response.get_url().to_string(),
        status: response.status(),
        headers,
        elapsed_ms,
    })
}

pub fn analyze(target: &str, resp: &ProbeResponse) -> Report {
    let mut findings = Vec::new();
    let header = |name: &str| -> Option<&str> {
        resp.headers
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, v)| v.as_str())
    };
    let is_https = resp.final_url.starts_with("https://");

    if !is_https {
        findings.push(Finding::new(
            Category::Transport,
            Severity::Critical,
            "Served over plaintext HTTP",
            Some(resp.final_url.clone()),
            "Terminate TLS and redirect all HTTP traffic to HTTPS",
        ));
    }

    if is_https && header("strict-transport-security").is_none() {
        findings.push(Finding::new(
            Category::Transport,
            Severity::High,
            "Missing Strict-Transport-Security header",
            None,
            "Add HSTS (max-age >= 6 months) so browsers refuse downgraded connections",
        ));
    }

    if header("content-security-policy").is_none() {
        findings.push(Finding::new(
            Category::Transport,
            Severity::High,
            "Missing Content-Security-Policy header",
            None,
            "Define a CSP — it is the single strongest XSS mitigation available",
        ));
    }

    if header("x-content-type-options").map(|v| v.trim()) != Some("nosniff") {
        findings.push(Finding::new(
            Category::Transport,
            Severity::Medium,
            "Missing X-Content-Type-Options: nosniff",
            None,
            "Add it to stop MIME-sniffing attacks on uploaded or proxied content",
        ));
    }

    let frame_protected = header("x-frame-options").is_some()
        || header("content-security-policy")
            .map(|v| v.contains("frame-ancestors"))
            .unwrap_or(false);
    if !frame_protected {
        findings.push(Finding::new(
            Category::Transport,
            Severity::Medium,
            "No clickjacking protection (X-Frame-Options / frame-ancestors)",
            None,
            "Add `frame-ancestors 'none'` to the CSP or X-Frame-Options: DENY",
        ));
    }

    if header("referrer-policy").is_none() {
        findings.push(Finding::new(
            Category::Transport,
            Severity::Low,
            "Missing Referrer-Policy header",
            None,
            "Set `strict-origin-when-cross-origin` to stop URL data leaking to third parties",
        ));
    }

    for leaky in ["server", "x-powered-by"] {
        if let Some(v) = header(leaky) {
            // Bare product names are common; version strings are the leak.
            if v.chars().any(|c| c.is_ascii_digit()) {
                findings.push(Finding::new(
                    Category::Transport,
                    Severity::Low,
                    format!("Version disclosure in `{leaky}` header ({v})"),
                    None,
                    "Strip version strings; they hand attackers a CVE shopping list",
                ));
            }
        }
    }

    for (name, value) in resp.headers.iter().filter(|(n, _)| n == "set-cookie") {
        let lower = value.to_lowercase();
        if !lower.contains("httponly") || (is_https && !lower.contains("secure")) {
            let cookie_name = value.split('=').next().unwrap_or("cookie");
            findings.push(Finding::new(
                Category::Transport,
                Severity::Medium,
                format!("Cookie `{cookie_name}` missing Secure/HttpOnly flags"),
                Some(format!("{name} header")),
                "Set both flags on session cookies; without them XSS or downgrade = session theft",
            ));
        }
    }

    if resp.status >= 500 {
        findings.push(Finding::new(
            Category::Transport,
            Severity::High,
            format!("Endpoint returned HTTP {}", resp.status),
            Some(resp.final_url.clone()),
            "The audited page is erroring in production; check server logs first",
        ));
    }

    if resp.elapsed_ms > 3000 {
        findings.push(Finding::new(
            Category::Transport,
            Severity::Medium,
            format!("Slow response: {} ms to first byte", resp.elapsed_ms),
            None,
            "Profile the request path; >3s responses bleed users and search ranking",
        ));
    } else {
        findings.push(Finding::new(
            Category::Transport,
            Severity::Info,
            format!(
                "Response time: {} ms (HTTP {})",
                resp.elapsed_ms, resp.status
            ),
            None,
            "No action needed",
        ));
    }

    Report::build(target, ReportKind::Probe, findings, &[Category::Transport])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn resp(headers: Vec<(&str, &str)>, https: bool) -> ProbeResponse {
        ProbeResponse {
            final_url: if https {
                "https://example.com/".into()
            } else {
                "http://example.com/".into()
            },
            status: 200,
            headers: headers
                .into_iter()
                .map(|(a, b)| (a.to_string(), b.to_string()))
                .collect(),
            elapsed_ms: 120,
        }
    }

    #[test]
    fn plaintext_http_is_critical() {
        let report = analyze("http://example.com", &resp(vec![], false));
        assert!(report
            .findings
            .iter()
            .any(|f| f.severity == Severity::Critical));
    }

    #[test]
    fn hardened_response_scores_high() {
        let report = analyze(
            "https://example.com",
            &resp(
                vec![
                    ("strict-transport-security", "max-age=63072000"),
                    (
                        "content-security-policy",
                        "default-src 'self'; frame-ancestors 'none'",
                    ),
                    ("x-content-type-options", "nosniff"),
                    ("referrer-policy", "strict-origin-when-cross-origin"),
                ],
                true,
            ),
        );
        assert_eq!(report.score, 100.0);
    }

    #[test]
    fn missing_csp_and_hsts_flagged() {
        let report = analyze("https://example.com", &resp(vec![], true));
        assert!(report
            .findings
            .iter()
            .any(|f| f.title.contains("Content-Security-Policy")));
        assert!(report
            .findings
            .iter()
            .any(|f| f.title.contains("Strict-Transport-Security")));
    }

    #[test]
    fn insecure_cookie_flagged() {
        let report = analyze(
            "https://example.com",
            &resp(vec![("set-cookie", "session=abc123; Path=/")], true),
        );
        assert!(report.findings.iter().any(|f| f.title.contains("Cookie")));
    }

    #[test]
    fn version_leak_flagged_bare_product_not() {
        let report = analyze(
            "https://example.com",
            &resp(vec![("server", "nginx/1.18.0")], true),
        );
        assert!(report
            .findings
            .iter()
            .any(|f| f.title.contains("Version disclosure")));

        let report = analyze(
            "https://example.com",
            &resp(vec![("server", "nginx")], true),
        );
        assert!(!report
            .findings
            .iter()
            .any(|f| f.title.contains("Version disclosure")));
    }
}
