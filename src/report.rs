//! Report model: findings, severities, category grades, and the overall
//! readiness score. All scanners and probes emit [`Finding`]s into a
//! [`Report`]; rendering (text / JSON / Markdown) lives here too.

use serde::Serialize;
use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    /// Points deducted from the owning category (each category starts at 100).
    pub fn penalty(self) -> f64 {
        match self {
            Severity::Critical => 40.0,
            Severity::High => 15.0,
            Severity::Medium => 6.0,
            Severity::Low => 2.0,
            Severity::Info => 0.0,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Severity::Critical => "CRITICAL",
            Severity::High => "HIGH",
            Severity::Medium => "MEDIUM",
            Severity::Low => "LOW",
            Severity::Info => "INFO",
        }
    }

    fn color(self) -> &'static str {
        match self {
            Severity::Critical => "\x1b[1;31m", // bold red
            Severity::High => "\x1b[31m",       // red
            Severity::Medium => "\x1b[33m",     // yellow
            Severity::Low => "\x1b[36m",        // cyan
            Severity::Info => "\x1b[2m",        // dim
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Category {
    Secrets,
    Dependencies,
    TestDebt,
    Configuration,
    Ci,
    Transport,
}

impl Category {
    pub fn label(self) -> &'static str {
        match self {
            Category::Secrets => "Secrets & Credentials",
            Category::Dependencies => "Dependency Hygiene",
            Category::TestDebt => "Test Debt",
            Category::Configuration => "Configuration",
            Category::Ci => "CI / Automation",
            Category::Transport => "Transport & Headers",
        }
    }

    /// Weight of this category in the overall readiness score.
    pub fn weight(self) -> f64 {
        match self {
            Category::Secrets => 0.30,
            Category::Dependencies => 0.20,
            Category::TestDebt => 0.20,
            Category::Configuration => 0.20,
            Category::Ci => 0.10,
            Category::Transport => 1.0, // probe-only reports: sole category
        }
    }

    pub const SCAN_SET: [Category; 5] = [
        Category::Secrets,
        Category::Dependencies,
        Category::TestDebt,
        Category::Configuration,
        Category::Ci,
    ];
}

#[derive(Debug, Clone, Serialize)]
pub struct Finding {
    pub category: Category,
    pub severity: Severity,
    pub title: String,
    /// File path + line, header name, or other locator. Optional.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub location: Option<String>,
    /// What to do about it.
    pub remediation: String,
}

impl Finding {
    pub fn new(
        category: Category,
        severity: Severity,
        title: impl Into<String>,
        location: Option<String>,
        remediation: impl Into<String>,
    ) -> Self {
        Self {
            category,
            severity,
            title: title.into(),
            location,
            remediation: remediation.into(),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct CategoryScore {
    pub category: Category,
    pub score: f64,
    pub grade: char,
    pub findings: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct Report {
    pub target: String,
    pub kind: ReportKind,
    pub findings: Vec<Finding>,
    pub categories: Vec<CategoryScore>,
    pub score: f64,
    pub grade: char,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ReportKind {
    Scan,
    Probe,
}

pub fn grade_for(score: f64) -> char {
    match score {
        s if s >= 90.0 => 'A',
        s if s >= 80.0 => 'B',
        s if s >= 70.0 => 'C',
        s if s >= 55.0 => 'D',
        _ => 'F',
    }
}

impl Report {
    pub fn build(
        target: impl Into<String>,
        kind: ReportKind,
        findings: Vec<Finding>,
        categories: &[Category],
    ) -> Self {
        let mut category_scores = Vec::new();
        let mut weighted_total = 0.0;
        let mut weight_sum = 0.0;

        for &cat in categories {
            let cat_findings: Vec<&Finding> =
                findings.iter().filter(|f| f.category == cat).collect();
            let penalty: f64 = cat_findings.iter().map(|f| f.severity.penalty()).sum();
            let score = (100.0 - penalty).max(0.0);
            category_scores.push(CategoryScore {
                category: cat,
                score,
                grade: grade_for(score),
                findings: cat_findings.len(),
            });
            weighted_total += score * cat.weight();
            weight_sum += cat.weight();
        }

        let score = if weight_sum > 0.0 {
            (weighted_total / weight_sum).clamp(0.0, 100.0)
        } else {
            100.0
        };

        Self {
            target: target.into(),
            kind,
            findings,
            categories: category_scores,
            score,
            grade: grade_for(score),
        }
    }

    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(self).expect("report serialization is infallible")
    }

    pub fn to_markdown(&self) -> String {
        let mut out = String::new();
        out.push_str(&format!(
            "# Aegis Report — `{}`\n\n**Readiness score: {:.0}/100 (grade {})**\n\n",
            self.target, self.score, self.grade
        ));
        out.push_str("| Category | Score | Grade | Findings |\n|---|---|---|---|\n");
        for c in &self.categories {
            out.push_str(&format!(
                "| {} | {:.0} | {} | {} |\n",
                c.category.label(),
                c.score,
                c.grade,
                c.findings
            ));
        }
        out.push('\n');
        if self.findings.is_empty() {
            out.push_str("No findings. Ship it.\n");
            return out;
        }
        out.push_str("## Findings\n\n");
        let mut sorted = self.findings.clone();
        sorted.sort_by_key(|f| std::cmp::Reverse(f.severity));
        for f in &sorted {
            out.push_str(&format!(
                "- **[{}]** {} — {}{}\n",
                f.severity.label(),
                f.title,
                f.remediation,
                f.location
                    .as_ref()
                    .map(|l| format!(" (`{l}`)"))
                    .unwrap_or_default()
            ));
        }
        out
    }

    pub fn render_text(&self, color: bool) -> String {
        let mut out = String::new();
        let (bold, reset, dim) = if color {
            ("\x1b[1m", "\x1b[0m", "\x1b[2m")
        } else {
            ("", "", "")
        };

        out.push_str(&format!(
            "\n{bold}AEGIS — production readiness report{reset}\n"
        ));
        out.push_str(&format!("{dim}target:{reset} {}\n\n", self.target));

        for c in &self.categories {
            let bar = score_bar(c.score);
            out.push_str(&format!(
                "  {:<24} {bar} {:>3.0}  {}\n",
                c.category.label(),
                c.score,
                c.grade
            ));
        }
        out.push_str(&format!(
            "\n  {bold}OVERALL: {:.0}/100 (grade {}){reset}\n\n",
            self.score, self.grade
        ));

        if self.findings.is_empty() {
            out.push_str("  No findings. Ship it.\n");
            return out;
        }

        let mut sorted = self.findings.clone();
        sorted.sort_by_key(|f| std::cmp::Reverse(f.severity));
        for f in &sorted {
            let (sev_color, sev_reset) = if color {
                (f.severity.color(), "\x1b[0m")
            } else {
                ("", "")
            };
            out.push_str(&format!(
                "  {sev_color}[{:>8}]{sev_reset} {}\n",
                f.severity.label(),
                f.title
            ));
            if let Some(loc) = &f.location {
                out.push_str(&format!("             {dim}at{reset} {loc}\n"));
            }
            out.push_str(&format!(
                "             {dim}fix:{reset} {}\n",
                f.remediation
            ));
        }
        out
    }
}

fn score_bar(score: f64) -> String {
    let filled = (score / 10.0).round() as usize;
    let mut bar = String::from("[");
    for i in 0..10 {
        bar.push(if i < filled { '#' } else { '-' });
    }
    bar.push(']');
    bar
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn grades_map_to_expected_bands() {
        assert_eq!(grade_for(95.0), 'A');
        assert_eq!(grade_for(85.0), 'B');
        assert_eq!(grade_for(75.0), 'C');
        assert_eq!(grade_for(60.0), 'D');
        assert_eq!(grade_for(20.0), 'F');
    }

    #[test]
    fn clean_report_scores_100() {
        let report = Report::build("x", ReportKind::Scan, vec![], &Category::SCAN_SET);
        assert_eq!(report.score, 100.0);
        assert_eq!(report.grade, 'A');
    }

    #[test]
    fn critical_finding_tanks_its_category() {
        let findings = vec![Finding::new(
            Category::Secrets,
            Severity::Critical,
            "AWS key in source",
            Some("src/main.rs:3".into()),
            "Rotate the key and move it to a secret manager",
        )];
        let report = Report::build("x", ReportKind::Scan, findings, &Category::SCAN_SET);
        let secrets = report
            .categories
            .iter()
            .find(|c| c.category == Category::Secrets)
            .unwrap();
        assert_eq!(secrets.score, 60.0);
        assert!(report.score < 100.0);
    }

    #[test]
    fn category_floor_is_zero() {
        let findings: Vec<Finding> = (0..5)
            .map(|i| {
                Finding::new(
                    Category::Secrets,
                    Severity::Critical,
                    format!("leak {i}"),
                    None,
                    "rotate",
                )
            })
            .collect();
        let report = Report::build("x", ReportKind::Scan, findings, &Category::SCAN_SET);
        let secrets = report
            .categories
            .iter()
            .find(|c| c.category == Category::Secrets)
            .unwrap();
        assert_eq!(secrets.score, 0.0);
    }

    #[test]
    fn json_and_markdown_render() {
        let findings = vec![Finding::new(
            Category::Ci,
            Severity::High,
            "No CI pipeline detected",
            None,
            "Add a CI workflow that runs tests on every push",
        )];
        let report = Report::build("demo", ReportKind::Scan, findings, &Category::SCAN_SET);
        assert!(report.to_json().contains("\"score\""));
        assert!(report.to_markdown().contains("No CI pipeline"));
        assert!(report.render_text(false).contains("OVERALL"));
    }
}
