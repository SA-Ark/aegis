//! Dependency hygiene checks.
//!
//! Static analysis of manifest + lockfile state across the three ecosystems
//! Aegis most often audits: npm (`package.json`), Cargo (`Cargo.toml`),
//! and pip (`requirements.txt`). No network calls — everything is judged
//! from what is committed to the repo.

use crate::report::{Category, Finding, Severity};
use serde_json::Value;
use std::path::Path;

pub fn scan(root: &Path) -> Vec<Finding> {
    let mut findings = Vec::new();

    if root.join("package.json").exists() {
        findings.extend(check_npm(root));
    }
    if root.join("Cargo.toml").exists() {
        findings.extend(check_cargo(root));
    }
    if root.join("requirements.txt").exists() {
        findings.extend(check_pip(root));
    }

    findings
}

fn check_npm(root: &Path) -> Vec<Finding> {
    let mut findings = Vec::new();
    let manifest = root.join("package.json");
    let Ok(raw) = std::fs::read_to_string(&manifest) else {
        return findings;
    };
    let Ok(json) = serde_json::from_str::<Value>(&raw) else {
        findings.push(Finding::new(
            Category::Dependencies,
            Severity::Medium,
            "package.json is not valid JSON",
            Some("package.json".into()),
            "Fix the manifest — tooling and installs will fail on it",
        ));
        return findings;
    };

    let has_lockfile = [
        "package-lock.json",
        "yarn.lock",
        "pnpm-lock.yaml",
        "bun.lockb",
    ]
    .iter()
    .any(|f| root.join(f).exists());
    if !has_lockfile {
        findings.push(Finding::new(
            Category::Dependencies,
            Severity::High,
            "No npm lockfile committed",
            Some("package.json".into()),
            "Commit package-lock.json (or yarn/pnpm equivalent) so builds are reproducible",
        ));
    }

    for section in ["dependencies", "devDependencies"] {
        if let Some(deps) = json.get(section).and_then(|d| d.as_object()) {
            for (name, version) in deps {
                let v = version.as_str().unwrap_or_default();
                if v == "*" || v == "latest" {
                    findings.push(Finding::new(
                        Category::Dependencies,
                        Severity::Medium,
                        format!("Unpinned npm dependency `{name}` ({v})"),
                        Some("package.json".into()),
                        "Pin to a semver range; `*`/`latest` makes every install a gamble",
                    ));
                } else if v.starts_with("git+http://") || v.starts_with("http://") {
                    findings.push(Finding::new(
                        Category::Dependencies,
                        Severity::High,
                        format!("npm dependency `{name}` fetched over plaintext HTTP"),
                        Some("package.json".into()),
                        "Use https/git+https — plaintext fetch is a supply-chain MITM vector",
                    ));
                }
            }
        }
    }

    findings
}

fn check_cargo(root: &Path) -> Vec<Finding> {
    let mut findings = Vec::new();
    let manifest = root.join("Cargo.toml");
    let Ok(raw) = std::fs::read_to_string(&manifest) else {
        return findings;
    };

    // Lightweight line scan; avoids a full TOML dependency for two checks.
    let mut in_deps = false;
    for line in raw.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('[') {
            in_deps = trimmed.contains("dependencies");
            continue;
        }
        if !in_deps || trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        if let Some((name, spec)) = trimmed.split_once('=') {
            let name = name.trim();
            let spec = spec.trim();
            if spec == "\"*\"" || spec.contains("version = \"*\"") {
                findings.push(Finding::new(
                    Category::Dependencies,
                    Severity::Medium,
                    format!("Wildcard Cargo dependency `{name}`"),
                    Some("Cargo.toml".into()),
                    "Pin a version — wildcard deps break reproducibility and invite breakage",
                ));
            }
            if spec.contains("git =") && !spec.contains("rev =") && !spec.contains("tag =") {
                findings.push(Finding::new(
                    Category::Dependencies,
                    Severity::Medium,
                    format!("Git Cargo dependency `{name}` without a pinned rev/tag"),
                    Some("Cargo.toml".into()),
                    "Pin `rev` or `tag` — a moving branch is an unreviewed code injection path",
                ));
            }
        }
    }

    if !root.join("Cargo.lock").exists() {
        findings.push(Finding::new(
            Category::Dependencies,
            Severity::Low,
            "No Cargo.lock committed",
            Some("Cargo.toml".into()),
            "Commit Cargo.lock for binaries/services so production builds are reproducible",
        ));
    }

    findings
}

fn check_pip(root: &Path) -> Vec<Finding> {
    let mut findings = Vec::new();
    let Ok(raw) = std::fs::read_to_string(root.join("requirements.txt")) else {
        return findings;
    };

    let mut unpinned = 0usize;
    for line in raw.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with('-') {
            continue;
        }
        if !trimmed.contains("==") && !trimmed.contains("@") {
            unpinned += 1;
        }
    }
    if unpinned > 0 {
        findings.push(Finding::new(
            Category::Dependencies,
            Severity::Medium,
            format!("{unpinned} unpinned Python requirement(s)"),
            Some("requirements.txt".into()),
            "Pin exact versions (pip-compile / uv lock) so deploys are reproducible",
        ));
    }
    findings
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    #[test]
    fn flags_missing_npm_lockfile_and_wildcards() {
        let dir = TempDir::new().unwrap();
        fs::write(
            dir.path().join("package.json"),
            r#"{"dependencies": {"left-pad": "*", "express": "^4.18.0"}}"#,
        )
        .unwrap();

        let findings = scan(dir.path());
        assert!(findings.iter().any(|f| f.title.contains("lockfile")));
        assert!(findings.iter().any(|f| f.title.contains("left-pad")));
        assert!(!findings.iter().any(|f| f.title.contains("express")));
    }

    #[test]
    fn flags_unpinned_cargo_git_dep() {
        let dir = TempDir::new().unwrap();
        fs::write(
            dir.path().join("Cargo.toml"),
            "[package]\nname = \"x\"\n[dependencies]\nfoo = { git = \"https://github.com/a/b\" }\nbar = \"1.0\"\n",
        )
        .unwrap();

        let findings = scan(dir.path());
        assert!(findings.iter().any(|f| f.title.contains("foo")));
        assert!(!findings.iter().any(|f| f.title.contains("`bar`")));
    }

    #[test]
    fn flags_unpinned_python_requirements() {
        let dir = TempDir::new().unwrap();
        fs::write(
            dir.path().join("requirements.txt"),
            "flask\nrequests==2.31.0\n# comment\n",
        )
        .unwrap();

        let findings = scan(dir.path());
        assert!(findings.iter().any(|f| f.title.contains("1 unpinned")));
    }

    #[test]
    fn clean_project_yields_no_findings() {
        let dir = TempDir::new().unwrap();
        fs::write(
            dir.path().join("package.json"),
            r#"{"dependencies": {"express": "^4.18.0"}}"#,
        )
        .unwrap();
        fs::write(dir.path().join("package-lock.json"), "{}").unwrap();

        assert!(scan(dir.path()).is_empty());
    }
}
