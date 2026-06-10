//! Static project scan: walks the tree once, then runs every analyzer
//! over the collected files.

pub mod config;
pub mod deps;
pub mod secrets;
pub mod test_debt;
pub mod walk;

use crate::report::{Category, Report, ReportKind};
use anyhow::{bail, Result};
use std::path::Path;

pub fn run(root: &Path) -> Result<Report> {
    if !root.is_dir() {
        bail!("scan target is not a directory: {}", root.display());
    }

    let files = walk::collect(root);
    let mut findings = Vec::new();

    for file in &files {
        findings.extend(secrets::scan_content(&file.rel_path, &file.content));
    }
    findings.extend(deps::scan(root));
    let (_stats, test_findings) = test_debt::analyze(&files);
    findings.extend(test_findings);
    findings.extend(config::scan(root, &files));

    Ok(Report::build(
        root.display().to_string(),
        ReportKind::Scan,
        findings,
        &Category::SCAN_SET,
    ))
}
