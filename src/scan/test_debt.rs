//! Test-debt analysis.
//!
//! Estimates how much of the codebase is protected by tests and how much
//! deferred-work residue (TODO/FIXME, panic-prone unwraps, stray debug
//! logging) has accumulated. Heuristic by design: the goal is a defensible
//! risk signal, not a coverage report.

use crate::report::{Category, Finding, Severity};
use crate::scan::walk::SourceFile;

#[derive(Debug, Default)]
pub struct TestDebtStats {
    pub source_files: usize,
    pub test_files: usize,
    pub rust_test_fns: usize,
    pub todo_count: usize,
    pub unwrap_count: usize,
    pub non_test_lines: usize,
    pub console_log_count: usize,
}

pub fn analyze(files: &[SourceFile]) -> (TestDebtStats, Vec<Finding>) {
    let mut stats = TestDebtStats::default();

    for file in files {
        let is_test = is_test_file(&file.rel_path);
        let lang = language_of(&file.rel_path);
        if lang.is_none() {
            continue;
        }

        if is_test {
            stats.test_files += 1;
        } else {
            stats.source_files += 1;
            stats.non_test_lines += file.content.lines().count();
        }

        for line in file.content.lines() {
            let trimmed = line.trim();
            if trimmed.contains("TODO") || trimmed.contains("FIXME") || trimmed.contains("HACK") {
                stats.todo_count += 1;
            }
            match lang {
                Some(Lang::Rust) => {
                    if trimmed == "#[test]" || trimmed.starts_with("#[tokio::test") {
                        stats.rust_test_fns += 1;
                        // inline #[test] counts as test presence even in src files
                    }
                    if !is_test && (trimmed.contains(".unwrap()") || trimmed.contains(".expect(")) {
                        stats.unwrap_count += 1;
                    }
                }
                Some(Lang::Js) => {
                    if !is_test && trimmed.contains("console.log(") {
                        stats.console_log_count += 1;
                    }
                }
                _ => {}
            }
        }
    }

    let mut findings = Vec::new();
    let has_tests = stats.test_files > 0 || stats.rust_test_fns > 0;

    if stats.source_files >= 3 && !has_tests {
        findings.push(Finding::new(
            Category::TestDebt,
            Severity::High,
            "No tests detected anywhere in the project",
            None,
            "Add tests for the critical paths first (auth, payments, data writes); \
             untested production code is a rescue waiting to happen",
        ));
    } else if stats.source_files > 0 && has_tests {
        let ratio = (stats.test_files + stats.rust_test_fns) as f64 / stats.source_files as f64;
        if ratio < 0.2 {
            findings.push(Finding::new(
                Category::TestDebt,
                Severity::Medium,
                format!(
                    "Thin test coverage signal: {} test file(s)/fn(s) across {} source files",
                    stats.test_files + stats.rust_test_fns,
                    stats.source_files
                ),
                None,
                "Grow tests alongside fixes; prioritize the modules that change most often",
            ));
        }
    }

    if stats.todo_count > 20 {
        findings.push(Finding::new(
            Category::TestDebt,
            Severity::Medium,
            format!("{} TODO/FIXME/HACK markers", stats.todo_count),
            None,
            "Triage them into tickets or delete them — silent deferred work is invisible risk",
        ));
    } else if stats.todo_count > 5 {
        findings.push(Finding::new(
            Category::TestDebt,
            Severity::Low,
            format!("{} TODO/FIXME/HACK markers", stats.todo_count),
            None,
            "Triage into tracked issues so deferred work stays visible",
        ));
    }

    if stats.non_test_lines > 0 {
        let unwraps_per_kloc = stats.unwrap_count as f64 / (stats.non_test_lines as f64 / 1000.0);
        if stats.unwrap_count >= 10 && unwraps_per_kloc > 15.0 {
            findings.push(Finding::new(
                Category::TestDebt,
                Severity::Medium,
                format!(
                    "High panic density: {} unwrap()/expect() calls outside tests ({:.0}/KLoC)",
                    stats.unwrap_count, unwraps_per_kloc
                ),
                None,
                "Convert hot-path unwraps to proper error handling; each one is a latent 500",
            ));
        }
    }

    if stats.console_log_count > 10 {
        findings.push(Finding::new(
            Category::TestDebt,
            Severity::Low,
            format!(
                "{} console.log calls outside tests",
                stats.console_log_count
            ),
            None,
            "Replace with a leveled logger; stray console output leaks data and noise",
        ));
    }

    (stats, findings)
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum Lang {
    Rust,
    Js,
    Python,
    Other,
}

fn language_of(path: &str) -> Option<Lang> {
    let ext = path.rsplit('.').next()?;
    Some(match ext {
        "rs" => Lang::Rust,
        "js" | "jsx" | "ts" | "tsx" | "mjs" | "cjs" => Lang::Js,
        "py" => Lang::Python,
        "go" | "java" | "rb" | "php" | "cs" => Lang::Other,
        _ => return None,
    })
}

fn is_test_file(path: &str) -> bool {
    let lower = path.to_lowercase();
    lower.contains("/tests/")
        || lower.starts_with("tests/")
        || lower.contains(".test.")
        || lower.contains(".spec.")
        || lower.contains("__tests__")
        || lower
            .rsplit('/')
            .next()
            .map(|f| f.starts_with("test_") && f.ends_with(".py"))
            .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn file(path: &str, content: &str) -> SourceFile {
        SourceFile {
            rel_path: path.to_string(),
            content: content.to_string(),
        }
    }

    #[test]
    fn flags_project_with_no_tests() {
        let files = vec![
            file("src/a.rs", "fn main() {}"),
            file("src/b.rs", "pub fn x() {}"),
            file("src/c.rs", "pub fn y() {}"),
        ];
        let (_, findings) = analyze(&files);
        assert!(findings.iter().any(|f| f.title.contains("No tests")));
    }

    #[test]
    fn inline_rust_tests_count_as_coverage() {
        let files = vec![
            file("src/a.rs", "fn main() {}\n#[test]\nfn t() {}"),
            file("src/b.rs", "pub fn x() {}"),
            file("src/c.rs", "pub fn y() {}"),
        ];
        let (stats, findings) = analyze(&files);
        assert_eq!(stats.rust_test_fns, 1);
        assert!(!findings.iter().any(|f| f.title.contains("No tests")));
    }

    #[test]
    fn counts_todos_and_unwraps() {
        let body = "// TODO: fix\nlet x = y.unwrap();\n".repeat(12);
        let files = vec![
            file("src/a.rs", &body),
            file("tests/t.rs", "#[test]\nfn t(){}"),
        ];
        let (stats, findings) = analyze(&files);
        assert_eq!(stats.todo_count, 12);
        assert_eq!(stats.unwrap_count, 12);
        assert!(findings.iter().any(|f| f.title.contains("panic density")));
    }

    #[test]
    fn test_file_detection() {
        assert!(is_test_file("tests/integration.rs"));
        assert!(is_test_file("src/app.test.ts"));
        assert!(is_test_file("pkg/__tests__/x.js"));
        assert!(is_test_file("api/test_routes.py"));
        assert!(!is_test_file("src/main.rs"));
    }
}
