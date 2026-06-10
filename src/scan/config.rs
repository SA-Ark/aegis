//! Configuration & CI hygiene checks.
//!
//! Covers the boring-but-fatal launch mistakes: env files in the repo,
//! missing `.gitignore` coverage, Dockerfiles running as root, permissive
//! CORS, and the total absence of CI.

use crate::report::{Category, Finding, Severity};
use crate::scan::walk::SourceFile;
use std::path::Path;

pub fn scan(root: &Path, files: &[SourceFile]) -> Vec<Finding> {
    let mut findings = Vec::new();

    findings.extend(check_env_files(root, files));
    findings.extend(check_dockerfiles(files));
    findings.extend(check_cors(files));
    findings.extend(check_ci(root));

    findings
}

fn check_env_files(root: &Path, files: &[SourceFile]) -> Vec<Finding> {
    let mut findings = Vec::new();

    let gitignore = std::fs::read_to_string(root.join(".gitignore")).unwrap_or_default();
    let env_ignored = gitignore
        .lines()
        .map(str::trim)
        .any(|l| l == ".env" || l == ".env*" || l == "*.env" || l.starts_with(".env"));

    if !root.join(".gitignore").exists() {
        findings.push(Finding::new(
            Category::Configuration,
            Severity::Medium,
            "No .gitignore present",
            None,
            "Add one — without it, env files, build output and editor junk end up committed",
        ));
    }

    let env_files: Vec<&SourceFile> = files
        .iter()
        .filter(|f| {
            let name = f.rel_path.rsplit('/').next().unwrap_or(&f.rel_path);
            name == ".env" || (name.starts_with(".env.") && name != ".env.example")
        })
        .collect();

    for env in &env_files {
        // Distinguish "file exists on disk" from "file is exposed": when
        // .gitignore covers it the risk is lower but still worth surfacing.
        let severity = if env_ignored {
            Severity::Low
        } else {
            Severity::Critical
        };
        let title = if env_ignored {
            format!("Env file `{}` on disk (gitignored)", env.rel_path)
        } else {
            format!("Env file `{}` not covered by .gitignore", env.rel_path)
        };
        findings.push(Finding::new(
            Category::Configuration,
            severity,
            title,
            Some(env.rel_path.clone()),
            "Keep secrets out of the worktree where possible; verify the file was never \
             committed (git log --all -- <file>) and rotate anything that was",
        ));
    }

    findings
}

fn check_dockerfiles(files: &[SourceFile]) -> Vec<Finding> {
    let mut findings = Vec::new();
    for f in files {
        let name = f.rel_path.rsplit('/').next().unwrap_or(&f.rel_path);
        if !(name == "Dockerfile" || name.starts_with("Dockerfile.")) {
            continue;
        }

        let has_user = f
            .content
            .lines()
            .any(|l| l.trim_start().to_uppercase().starts_with("USER "));
        if !has_user {
            findings.push(Finding::new(
                Category::Configuration,
                Severity::Medium,
                format!("`{}` runs as root (no USER directive)", f.rel_path),
                Some(f.rel_path.clone()),
                "Add a non-root USER; a container escape from root is a host compromise",
            ));
        }

        for (i, line) in f.content.lines().enumerate() {
            let t = line.trim();
            if t.to_uppercase().starts_with("FROM ") && t.contains(":latest") {
                findings.push(Finding::new(
                    Category::Configuration,
                    Severity::Low,
                    format!("`{}` pins base image to :latest", f.rel_path),
                    Some(format!("{}:{}", f.rel_path, i + 1)),
                    "Pin a digest or version tag so rebuilds are reproducible",
                ));
            }
        }
    }
    findings
}

fn check_cors(files: &[SourceFile]) -> Vec<Finding> {
    let mut findings = Vec::new();
    for f in files {
        for (i, line) in f.content.lines().enumerate() {
            let lower = line.to_lowercase();
            let wildcard_header = lower.contains("access-control-allow-origin")
                && line.contains('*')
                && !lower.trim_start().starts_with("//")
                && !lower.trim_start().starts_with('#');
            let permissive_axum =
                line.contains("allow_origin(Any)") || line.contains("CorsLayer::permissive()");
            if wildcard_header || permissive_axum {
                findings.push(Finding::new(
                    Category::Configuration,
                    Severity::Medium,
                    "Wildcard CORS policy",
                    Some(format!("{}:{}", f.rel_path, i + 1)),
                    "Allow specific origins; `*` plus credentials or sensitive APIs is a \
                     cross-site data leak",
                ));
            }
        }
    }
    findings
}

fn check_ci(root: &Path) -> Vec<Finding> {
    let has_ci = root.join(".github/workflows").is_dir()
        || root.join(".gitlab-ci.yml").exists()
        || root.join("Jenkinsfile").exists()
        || root.join(".circleci").is_dir();

    if has_ci {
        Vec::new()
    } else {
        vec![Finding::new(
            Category::Ci,
            Severity::High,
            "No CI pipeline detected",
            None,
            "Add a workflow that builds and tests every push; unreviewed manual deploys \
             are how regressions reach users",
        )]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    fn file(path: &str, content: &str) -> SourceFile {
        SourceFile {
            rel_path: path.to_string(),
            content: content.to_string(),
        }
    }

    #[test]
    fn env_file_without_gitignore_is_critical() {
        let dir = TempDir::new().unwrap();
        let files = vec![file(".env", "KEY=value")];
        let findings = scan(dir.path(), &files);
        assert!(findings
            .iter()
            .any(|f| f.severity == Severity::Critical && f.title.contains(".env")));
    }

    #[test]
    fn gitignored_env_file_is_low() {
        let dir = TempDir::new().unwrap();
        fs::write(dir.path().join(".gitignore"), ".env\n").unwrap();
        let files = vec![file(".env", "KEY=value")];
        let findings = scan(dir.path(), &files);
        let env_finding = findings.iter().find(|f| f.title.contains(".env")).unwrap();
        assert_eq!(env_finding.severity, Severity::Low);
    }

    #[test]
    fn env_example_is_fine() {
        let dir = TempDir::new().unwrap();
        fs::write(dir.path().join(".gitignore"), ".env\n").unwrap();
        let files = vec![file(".env.example", "KEY=changeme")];
        let findings = scan(dir.path(), &files);
        assert!(!findings.iter().any(|f| f.title.contains(".env.example")));
    }

    #[test]
    fn rootful_dockerfile_flagged() {
        let dir = TempDir::new().unwrap();
        let files = vec![file("Dockerfile", "FROM node:latest\nCMD [\"node\"]")];
        let findings = scan(dir.path(), &files);
        assert!(findings.iter().any(|f| f.title.contains("root")));
        assert!(findings.iter().any(|f| f.title.contains(":latest")));
    }

    #[test]
    fn wildcard_cors_flagged() {
        let dir = TempDir::new().unwrap();
        let files = vec![file(
            "server.js",
            "res.setHeader('Access-Control-Allow-Origin', '*');",
        )];
        let findings = scan(dir.path(), &files);
        assert!(findings.iter().any(|f| f.title.contains("CORS")));
    }

    #[test]
    fn missing_ci_flagged_present_ci_not() {
        let dir = TempDir::new().unwrap();
        let findings = scan(dir.path(), &[]);
        assert!(findings.iter().any(|f| f.title.contains("CI")));

        fs::create_dir_all(dir.path().join(".github/workflows")).unwrap();
        let findings = scan(dir.path(), &[]);
        assert!(!findings.iter().any(|f| f.title.contains("CI")));
    }
}
