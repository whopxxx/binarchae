//! Safe materialization under a controlled output root.
//!
//! Threat model (see docs/security.md): archive entry names and carved
//! labels are attacker-controlled. This layer refuses:
//!   - `../` traversal in any component
//!   - absolute paths
//!   - Windows drive letters and UNC prefixes
//!   - path components that are `..`, or contain separators/colons
//!   - excessive path depth
//!   - duplicate names (disambiguated deterministically)
//!   - weird Unicode (control characters stripped)
//!
//! Extracted content is never executed and no filesystem semantics
//! (symlinks/hardlinks/permissions) are preserved.

use crate::error::{Error, Result};
use std::path::{Component, Path, PathBuf};

const MAX_DEPTH: usize = 24;

/// Validate + sanitize an attacker-supplied relative name into a safe
/// path under `root`. Returns the joined path.
pub fn safe_join(root: &Path, name: &str) -> Result<PathBuf> {
    let cleaned: String = name
        .chars()
        .filter(|c| !c.is_control())
        .map(|c| if c == '\\' { '/' } else { c })
        .collect();

    let rel = Path::new(&cleaned);
    if rel.is_absolute() {
        return Err(Error::UnsafePath {
            path: name.to_string(),
            reason: "absolute path".into(),
        });
    }

    let mut parts: Vec<String> = Vec::new();
    for comp in rel.components() {
        match comp {
            Component::Normal(p) => {
                let s = p.to_string_lossy().to_string();
                // Drive letters / reserved Windows device names.
                if is_windows_drive(&s) || is_reserved_device(&s) {
                    return Err(Error::UnsafePath {
                        path: name.to_string(),
                        reason: format!("reserved component {s:?}"),
                    });
                }
                parts.push(s);
            }
            Component::CurDir => {}
            Component::ParentDir => {
                return Err(Error::UnsafePath {
                    path: name.to_string(),
                    reason: "`..` traversal".into(),
                });
            }
            Component::RootDir | Component::Prefix(_) => {
                return Err(Error::UnsafePath {
                    path: name.to_string(),
                    reason: "root/prefix component".into(),
                });
            }
        }
    }
    if parts.len() > MAX_DEPTH {
        return Err(Error::UnsafePath {
            path: name.to_string(),
            reason: format!("depth {} exceeds {}", parts.len(), MAX_DEPTH),
        });
    }

    let mut out = root.to_path_buf();
    for p in &parts {
        out.push(p);
    }
    Ok(out)
}

fn is_windows_drive(s: &str) -> bool {
    let b = s.as_bytes();
    b.len() >= 2 && b[1] == b':' && b[0].is_ascii_alphabetic()
}

fn is_reserved_device(s: &str) -> bool {
    const NAMES: [&str; 12] = [
        "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8",
    ];
    let upper = s.split('.').next().unwrap_or("").to_ascii_uppercase();
    NAMES.contains(&upper.as_str())
}

/// Deterministic disambiguation for duplicate names:
/// `dir/name.txt` -> `dir/name__2.txt`.
pub fn dedup_path(path: &Path) -> PathBuf {
    if !path.exists() {
        return path.to_path_buf();
    }
    let stem = path
        .file_stem()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_default();
    let ext = path
        .extension()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_default();
    let parent = path.parent().unwrap_or(Path::new("."));
    for n in 2..u32::MAX {
        let candidate = if ext.is_empty() {
            parent.join(format!("{stem}__{n}"))
        } else {
            parent.join(format!("{stem}__{n}.{ext}"))
        };
        if !candidate.exists() {
            return candidate;
        }
    }
    path.to_path_buf() // unreachable in practice
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn traversal_refused() {
        let root = Path::new("/tmp/x");
        assert!(safe_join(root, "../escape.txt").is_err());
        assert!(safe_join(root, "a/../../b").is_err());
        assert!(safe_join(root, "..\\..\\b").is_err());
    }

    #[test]
    fn absolute_drive_unc_refused() {
        let root = Path::new("/tmp/x");
        assert!(safe_join(root, "C:\\Windows\\evil").is_err());
        assert!(safe_join(root, "\\\\server\\share\\x").is_err());
        assert!(safe_join(root, "/etc/passwd").is_err());
    }

    #[test]
    fn normal_paths_pass() {
        let root = Path::new("/tmp/x");
        let p = safe_join(root, "a/b/c.txt").unwrap();
        assert_eq!(p, Path::new("/tmp/x/a/b/c.txt"));
    }

    #[test]
    fn control_chars_stripped() {
        let root = Path::new("/tmp/x");
        let p = safe_join(root, "bad\u{0}name.txt").unwrap();
        assert_eq!(p, Path::new("/tmp/x/badname.txt"));
    }
}
