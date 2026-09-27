//! ZIP handler: native inspection and extraction via the `zip` crate,
//! behind this project-owned abstraction. Encrypted archives are
//! recognized distinctly. Safe-path rules are enforced at extraction.

use crate::artifact::{Confidence, Evidence};
use crate::bytesource::ByteSource;
use crate::engine::{ArtifactDraft, Budget, Candidate, ChildDraft, Handler, HandlerOutput};
use crate::error::{Error, Result};
use crate::handlers::find_all;
use std::collections::BTreeMap;

pub struct ZipHandler;

impl Handler for ZipHandler {
    fn format(&self) -> &'static str {
        "zip"
    }

    fn find_candidates(&self, src: &ByteSource) -> Vec<Candidate> {
        // Local file header PK\x03\x04 or central directory PK\x01\x02.
        let mut hits: Vec<u64> = find_all(src, b"PK\x03\x04");
        hits.extend(find_all(src, b"PK\x01\x02"));
        hits.sort_unstable();
        hits.dedup();
        hits.into_iter()
            .map(|offset| Candidate { offset })
            .collect()
    }

    fn validate(
        &self,
        src: &ByteSource,
        candidate: Candidate,
        limits: &crate::engine::EngineLimits,
        _budget: &mut Budget,
    ) -> Result<HandlerOutput> {
        // Read the whole candidate region (from signature to source end);
        // the zip crate needs seeking, so materialize bounded bytes.
        if src.len() > limits.max_child_size {
            return Err(Error::Validation {
                format: "zip",
                reason: format!("region {} exceeds max child size", src.len()),
            });
        }
        let data = src.read_all()?;
        let rel = candidate.offset as usize;
        if rel >= data.len() {
            return Err(Error::Validation {
                format: "zip",
                reason: "candidate out of range".into(),
            });
        }
        let cursor = std::io::Cursor::new(&data[rel..]);
        let mut archive = zip::ZipArchive::new(cursor).map_err(|e| Error::Validation {
            format: "zip",
            reason: format!("central directory invalid: {e}"),
        })?;

        let entry_count = archive.len();
        if entry_count > limits.max_archive_entries {
            return Err(Error::Validation {
                format: "zip",
                reason: format!("{entry_count} entries exceeds limit"),
            });
        }

        let mut children: Vec<ChildDraft> = Vec::new();
        let mut names: Vec<String> = Vec::new();
        let mut encrypted = false;
        let mut warnings: Vec<String> = Vec::new();

        for i in 0..entry_count {
            let mut entry = archive.by_index(i).map_err(|e| Error::Validation {
                format: "zip",
                reason: format!("entry {i} unreadable: {e}"),
            })?;
            let raw_name = entry.name().to_string();
            names.push(raw_name.clone());

            if entry.encrypted() {
                encrypted = true;
                // Do not attempt to decrypt; record the entry distinctly.
                warnings.push(format!("entry {raw_name:?} is encrypted"));
                continue;
            }

            let mut buf = Vec::new();
            if std::io::copy(&mut entry, &mut buf).is_err() {
                warnings.push(format!("entry {raw_name:?} failed to decompress"));
                continue;
            }
            if buf.len() as u64 > limits.max_child_size {
                warnings.push(format!(
                    "entry {raw_name:?} exceeds max child size; skipped"
                ));
                continue;
            }
            children.push(ChildDraft {
                relation: crate::artifact::RelationKind::Contains,
                label: format!("zip entry {raw_name}"),
                format_hint: "raw",
                bytes: buf,
                metadata: BTreeMap::new(),
                warnings: Vec::new(),
                entry_name: Some(raw_name),
            });
        }

        let mut metadata = BTreeMap::new();
        metadata.insert("entries".to_string(), entry_count.to_string());
        metadata.insert("encrypted".to_string(), encrypted.to_string());
        if !names.is_empty() {
            metadata.insert("entry_names".to_string(), names.join("\n"));
        }

        // Boundary: archive ends at the end of the central directory +
        // comment. The zip crate consumed everything we gave it from the
        // first signature; use the region end as the structural boundary.
        let size = src.len() - candidate.offset;

        Ok(HandlerOutput {
            artifacts: vec![ArtifactDraft {
                format: "zip".to_string(),
                label: format!("ZIP archive ({entry_count} entries)"),
                offset: candidate.offset,
                size,
                confidence: Confidence::Validated,
                evidence: Evidence::facts([
                    "central directory parsed".to_string(),
                    format!("{entry_count} entries read"),
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
