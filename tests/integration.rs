//! End-to-end scan test against a synthetic "leaky" project assembled in a
//! temp directory at runtime. Fixture credentials are constructed from
//! fragments so no scanner (including Aegis itself, run on this repo) ever
//! sees a contiguous secret-shaped literal in committed source.

use std::fs;
use std::path::Path;
use std::process::Command;

fn write(root: &Path, rel: &str, content: &str) {
    let path = root.join(rel);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).unwrap();
    }
    fs::write(path, content).unwrap();
}

fn build_leaky_fixture(root: &Path) {
    // Secret assembled from fragments (documented AWS example key shape).
    let aws_key = format!("AK{}", "IAIOSFODNN7EXAMPLE");
    write(
        root,
        "src/config.js",
        &format!("const awsKey = \"{aws_key}\";\nconsole.log('booting');\n"),
    );
    write(
        root,
        ".env",
        &format!("DATABASE_URL=postgres://app:s3cr3tpw{}\n", "@db:5432/prod"),
    );
    write(
        root,
        "package.json",
        r#"{"name": "leaky", "dependencies": {"left-pad": "*"}}"#,
    );
    write(
        root,
        "Dockerfile",
        "FROM node:latest\nCMD [\"node\", \"src/config.js\"]\n",
    );
    write(
        root,
        "src/app.js",
        "// TODO: add auth\nmodule.exports = {};\n",
    );
    write(root, "src/api.js", "// FIXME\nmodule.exports = {};\n");
    // No .gitignore, no tests, no CI — all intentional.
}

fn build_clean_fixture(root: &Path) {
    write(root, ".gitignore", ".env\nnode_modules/\n");
    write(
        root,
        "package.json",
        r#"{"name": "clean", "dependencies": {"express": "^4.18.0"}}"#,
    );
    write(root, "package-lock.json", "{}");
    write(root, "src/app.js", "module.exports = () => 'ok';\n");
    write(
        root,
        "src/app.test.js",
        "const app = require('./app');\ntest('ok', () => expect(app()).toBe('ok'));\n",
    );
    write(
        root,
        ".github/workflows/ci.yml",
        "on: push\njobs:\n  test:\n    runs-on: ubuntu-latest\n    steps:\n      - run: npm test\n",
    );
}

fn aegis() -> Command {
    Command::new(env!("CARGO_BIN_EXE_aegis"))
}

#[test]
fn leaky_project_fails_threshold_with_expected_findings() {
    let dir = tempfile::TempDir::new().unwrap();
    build_leaky_fixture(dir.path());

    let output = aegis()
        .args(["scan"])
        .arg(dir.path())
        .args(["--format", "json", "--fail-under", "80"])
        .output()
        .unwrap();

    // Score must be below threshold => exit code 1.
    assert_eq!(output.status.code(), Some(1));

    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let findings = report["findings"].as_array().unwrap();
    let titles: Vec<&str> = findings
        .iter()
        .map(|f| f["title"].as_str().unwrap())
        .collect();

    assert!(
        titles.iter().any(|t| t.contains("AWS")),
        "AWS key: {titles:?}"
    );
    assert!(titles.iter().any(|t| t.contains("Connection string")));
    assert!(titles
        .iter()
        .any(|t| t.contains("not covered by .gitignore")));
    assert!(titles.iter().any(|t| t.contains("lockfile")));
    assert!(titles.iter().any(|t| t.contains("left-pad")));
    assert!(titles.iter().any(|t| t.contains("root")));
    assert!(titles.iter().any(|t| t.contains("No tests")));
    assert!(titles.iter().any(|t| t.contains("No CI")));

    assert!(report["score"].as_f64().unwrap() < 80.0);
}

#[test]
fn clean_project_passes_threshold() {
    let dir = tempfile::TempDir::new().unwrap();
    build_clean_fixture(dir.path());

    let output = aegis()
        .args(["scan"])
        .arg(dir.path())
        .args(["--format", "json", "--fail-under", "90"])
        .output()
        .unwrap();

    assert_eq!(
        output.status.code(),
        Some(0),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["score"].as_f64().unwrap(), 100.0);
    assert_eq!(report["grade"].as_str().unwrap(), "A");
}

#[test]
fn markdown_output_renders() {
    let dir = tempfile::TempDir::new().unwrap();
    build_leaky_fixture(dir.path());

    let output = aegis()
        .args(["scan"])
        .arg(dir.path())
        .args(["--format", "markdown"])
        .output()
        .unwrap();

    let md = String::from_utf8(output.stdout).unwrap();
    assert!(md.contains("# Aegis Report"));
    assert!(md.contains("| Category |"));
}

#[test]
fn scan_of_missing_dir_errors_cleanly() {
    let output = aegis()
        .args(["scan", "/definitely/not/a/real/path"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&output.stderr).contains("error"));
}
