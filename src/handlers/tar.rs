//! TAR handler: structural validation + native entry extraction via the
//! `tar` crate. Safe-path rules enforced at the extraction layer.

use crate::artifact::{Confidence, Evidence, RelationKind};
use crate::bytesource::ByteSource;
use crate::engine::{ArtifactDraft, Budget, Candidate, ChildDraft, Handler, HandlerOutput};
use crate::error::{Error, Result};
use std::collections::BTreeMap;
use std::io::Cursor;

pub struct TarHandler;

impl Handler for TarHandler {
    fn format(&self) -> &'static str {
        "tar"
    }

    fn find_candidates(&self, src: &ByteSource) -> Vec<Candidate> {
        // TAR has no magic at offset 0; the ustar magic lives at 257.
        // Candidate = source start only (offset 0), validated structurally.
        if src.len() >= 512 {
            vec![Candidate { offset: 0 }]
        } else {
            Vec::new()
        }
    }

    fn validate(
        &self,
        src: &ByteSource,
        candidate: Candidate,
        limits: &crate::engine::EngineLimits,
        budget: &mut Budget,
    ) -> Result<HandlerOutput> {
        let base = candidate.offset;
        if base != 0 || src.len() < 512 {
            return Err(Error::Validation {
                format: "tar",
                reason: "tar must start at source offset 0 with >=512 bytes".into(),
            });
        }
        // ustar magic at 257: "ustar" (old GNU: "ustar  \0").
        let mut magic = [0u8; 6];
        src.read_at(257, &mut magic)?;
        if &magic[..5] != b"ustar" {
            return Err(Error::Validation {
                format: "tar",
                reason: "no ustar magic at offset 257".into(),
            });
        }

        let data = src.read_all()?;
        let mut archive = tar::Archive::new(Cursor::new(&data[..]));
        archive.set_preserve_permissions(false);
        archive.set_unpack_xattrs(false);
        archive.set_preserve_mtime(false);

        let entries = archive
            .entries()
            .map_err(|e| Error::Validation {
                format: "tar",
                reason: format!("header chain invalid: {e}"),
            })?
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|e| Error::Validation {
                format: "tar",
                reason: format!("corrupt entry: {e}"),
            })?;

        if entries.len() > limits.max_archive_entries {
            return Err(Error::LimitExceeded {
                limit: "max-archive-entries",
                detail: format!("{} entries", entries.len()),
            });
        }

        let mut children: Vec<ChildDraft> = Vec::new();
        let mut names: Vec<String> = Vec::new();
        let mut warnings: Vec<String> = Vec::new();
        for mut entry in entries {
            let name = entry
                .path()
                .map(|p| p.display().to_string())
                .unwrap_or_else(|_| "<unnamed>".to_string());
            names.push(name.clone());
            let header_size = entry.size();
            if header_size > limits.max_child_size {
                warnings.push(format!("entry {name:?} exceeds max child size; skipped"));
                continue;
            }
            let mut buf = Vec::new();
            if std::io::Read::read_to_end(&mut entry, &mut buf).is_err() {
                warnings.push(format!("entry {name:?} failed to read"));
                continue;
            }
            if !budget.charge(limits, buf.len() as u64) {
                return Err(Error::LimitExceeded {
                    limit: "max-total-expanded-bytes",
                    detail: format!("tar entry {name:?} +{} bytes", buf.len()),
                });
            }
            children.push(ChildDraft {
                relation: RelationKind::Contains,
                label: format!("tar entry {name}"),
                format_hint: "raw",
                bytes: buf,
                metadata: BTreeMap::new(),
                warnings: Vec::new(),
                entry_name: Some(name),
            });
        }

        let mut metadata = BTreeMap::new();
        metadata.insert("entries".to_string(), names.len().to_string());
        metadata.insert("entry_names".to_string(), names.join("\n"));

        // Boundary: entries consume whole 512-byte blocks; source length
        // is a safe upper bound for a validated start-of-source archive.
        let size = src.len();

        Ok(HandlerOutput {
            artifacts: vec![ArtifactDraft {
                format: "tar".to_string(),
                label: format!("TAR archive ({} entries)", names.len()),
                offset: base,
                size,
                confidence: Confidence::Validated,
                evidence: Evidence::facts([
                    "ustar magic at offset 257".to_string(),
                    format!("{} entry headers parsed", names.len()),
                ]),
                metadata,
                warnings,
                errors: Vec::new(),
                inline_bytes: None,
                children,
            }],
        })
    }
}
