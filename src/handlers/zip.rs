//! ZIP handler: native inspection and extraction via the `zip` crate,
//! behind this project-owned abstraction. Encrypted archives are
//! recognized distinctly. Safe-path rules are enforced at extraction.
//!
//! Boundary logic (B7): the archive end is anchored on the End of
//! Central Directory record (EOCD) — the last valid `PK\x05\x06` whose
//! comment length is consistent with the bytes that follow. The
//! artifact spans from the first signature to the EOCD end, so appended
//! data after the ZIP stays discoverable as trailing data.

use crate::artifact::{Confidence, Evidence, RelationKind};
use crate::bytesource::ByteSource;
use crate::engine::{
    ArtifactDraft, Budget, Candidate, ChildContent, ChildDraft, Handler, HandlerOutput,
};
use crate::error::{Error, Result};
use crate::handlers::find_all;
use std::collections::BTreeMap;
use std::io::Read;

pub struct ZipHandler;

const EOCD_MIN: usize = 22; // EOCD record minimum size
const EOCD_SIG: [u8; 4] = [0x50, 0x4b, 0x05, 0x06];

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
        budget: &mut Budget,
    ) -> Result<HandlerOutput> {
        if src.len() > limits.max_child_size {
            return Err(Error::Validation {
                format: "zip",
                reason: format!("region {} exceeds max child size", src.len()),
            });
        }
        let data = src.read_all()?;
        let rel = candidate.offset as usize;
        if rel + 4 > data.len() {
            return Err(Error::Validation {
                format: "zip",
                reason: "candidate out of range".into(),
            });
        }

        // B7: find the EOCD that terminates this archive.
        let archive_end = find_eocd_end(&data, rel)?;
        if archive_end <= rel {
            return Err(Error::Validation {
                format: "zip",
                reason: "EOCD precedes candidate".into(),
            });
        }

        // Parse via the zip crate on exactly the archive bytes.
        let cursor = std::io::Cursor::new(&data[rel..archive_end]);
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

        // B1: entries are decoded incrementally; each output chunk is
        // charged against the run-wide budget and bounded by the ratio
        // cap BEFORE the buffer grows further, so bombs are cut off
        // mid-stream instead of after a full unbounded allocation.
        let mut children: Vec<ChildDraft> = Vec::new();
        let mut names: Vec<String> = Vec::new();
        let mut encrypted = false;
        let mut warnings: Vec<String> = Vec::new();
        let mut total_expanded: u64 = 0;
        let compressed_hint = (archive_end - rel) as u64;

        for i in 0..entry_count {
            let mut entry = archive.by_index(i).map_err(|e| Error::Validation {
                format: "zip",
                reason: format!("entry {i} unreadable: {e}"),
            })?;
            let raw_name = entry.name().to_string();
            names.push(raw_name.clone());

            if entry.encrypted() {
                encrypted = true;
                warnings.push(format!("entry {raw_name:?} is encrypted"));
                continue;
            }

            // Ratio cap per entry based on archive size so far.
            let entry_cap = limits.max_child_size.min(
                limits
                    .max_expansion_ratio
                    .saturating_mul(compressed_hint.max(1)),
            );
            let mut buf = Vec::new();
            let mut chunk = [0u8; 64 * 1024];
            loop {
                match entry.read(&mut chunk) {
                    Ok(0) => break,
                    Ok(n) => {
                        total_expanded += n as u64;
                        if total_expanded > entry_cap {
                            return Err(Error::LimitExceeded {
                                limit: "compression-expansion-ratio/child-size",
                                detail: format!(
                                    "zip entries exceeded {entry_cap} bytes (archive {compressed_hint})"
                                ),
                            });
                        }
                        if !budget.charge(limits, n as u64) {
                            return Err(Error::LimitExceeded {
                                limit: "max-total-expanded-bytes",
                                detail: format!("zip entry {raw_name:?} +{n}"),
                            });
                        }
                        buf.extend_from_slice(&chunk[..n]);
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                    Err(e) => {
                        warnings.push(format!("entry {raw_name:?} failed to decompress: {e}"));
                        break;
                    }
                }
            }
            if buf.is_empty() {
                continue;
            }
            let buf_size = buf.len() as u64;
            children.push(ChildDraft {
                relation: RelationKind::Contains,
                label: format!("zip entry {raw_name}"),
                format_hint: "raw",
                content: ChildContent::Owned(buf),
                size: buf_size,
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

        // B7: exact boundary — from the first signature to the EOCD end.
        let size = (archive_end - rel) as u64;

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
                    "EOCD-anchored boundary".to_string(),
                ]),
                metadata,
                warnings,
                errors: Vec::new(),
                children,
            }],
        })
    }
}

/// Find the archive end: scan backwards for the last EOCD signature whose
/// comment length is consistent with the bytes that follow it. The EOCD
/// ends at `sig + 22 + comment_len`; anything after that is not part of
/// this archive.
fn find_eocd_end(data: &[u8], from: usize) -> Result<usize> {
    if data.len() < EOCD_MIN {
        return Err(Error::Validation {
            format: "zip",
            reason: "region too short for EOCD".into(),
        });
    }
    // Walk backwards over EOCD candidates; the LAST well-formed one wins
    // (an EOCD buried inside a comment is shadowed by the real one).
    let mut i = data.len() - EOCD_MIN;
    loop {
        if i >= from && data[i..i + 4] == EOCD_SIG {
            let comment_len = u16::from_le_bytes([data[i + 20], data[i + 21]]) as usize;
            let eocd_end = i + EOCD_MIN + comment_len;
            if eocd_end <= data.len() {
                return Ok(eocd_end);
            }
            // comment_len overruns the region: stale signature inside
            // appended data; keep scanning backwards.
        }
        if i == 0 {
            break;
        }
        i -= 1;
    }
    Err(Error::Validation {
        format: "zip",
        reason: "no well-formed EOCD found".into(),
    })
}
