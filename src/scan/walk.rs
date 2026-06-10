//! Filesystem walker: collects readable text files under a project root,
//! skipping VCS internals, build output, and vendored trees.

use std::path::Path;
use walkdir::WalkDir;

const SKIP_DIRS: [&str; 12] = [
    ".git",
    "node_modules",
    "target",
    "dist",
    "build",
    "vendor",
    ".venv",
    "venv",
    "__pycache__",
    ".next",
    ".cache",
    "coverage",
];

const MAX_FILE_BYTES: u64 = 1_000_000;

#[derive(Debug, Clone)]
pub struct SourceFile {
    /// Path relative to the scan root, `/`-separated.
    pub rel_path: String,
    pub content: String,
}

pub fn collect(root: &Path) -> Vec<SourceFile> {
    let mut files = Vec::new();

    let walker = WalkDir::new(root).into_iter().filter_entry(|e| {
        let name = e.file_name().to_string_lossy();
        !(e.file_type().is_dir() && SKIP_DIRS.contains(&name.as_ref()))
    });

    for entry in walker.flatten() {
        if !entry.file_type().is_file() {
            continue;
        }
        if entry.metadata().map(|m| m.len()).unwrap_or(u64::MAX) > MAX_FILE_BYTES {
            continue;
        }
        let Ok(bytes) = std::fs::read(entry.path()) else {
            continue;
        };
        // Binary heuristic: NUL byte in the first 8 KiB.
        if bytes.iter().take(8192).any(|&b| b == 0) {
            continue;
        }
        let Ok(content) = String::from_utf8(bytes) else {
            continue;
        };
        let rel = entry
            .path()
            .strip_prefix(root)
            .unwrap_or(entry.path())
            .to_string_lossy()
            .replace('\\', "/");
        files.push(SourceFile {
            rel_path: rel,
            content,
        });
    }

    files.sort_by(|a, b| a.rel_path.cmp(&b.rel_path));
    files
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    #[test]
    fn skips_node_modules_and_binaries() {
        let dir = TempDir::new().unwrap();
        fs::create_dir_all(dir.path().join("node_modules/dep")).unwrap();
        fs::write(dir.path().join("node_modules/dep/index.js"), "x").unwrap();
        fs::write(dir.path().join("app.js"), "console.log(1)").unwrap();
        fs::write(dir.path().join("blob.bin"), [0u8, 1, 2, 3]).unwrap();

        let files = collect(dir.path());
        let paths: Vec<&str> = files.iter().map(|f| f.rel_path.as_str()).collect();
        assert_eq!(paths, vec!["app.js"]);
    }

    #[test]
    fn collects_nested_text_files() {
        let dir = TempDir::new().unwrap();
        fs::create_dir_all(dir.path().join("src/api")).unwrap();
        fs::write(dir.path().join("src/api/routes.rs"), "fn x() {}").unwrap();

        let files = collect(dir.path());
        assert_eq!(files.len(), 1);
        assert_eq!(files[0].rel_path, "src/api/routes.rs");
    }
}
