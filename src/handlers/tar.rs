//! TAR handler: manual 512-byte header walk with salvage (#7 §8) —
//! complete entries before a corruption point or truncation are still
//! exposed; truncated final entries yield the bytes that exist
//! (flagged truncated). Safe-path rules enforced at the extraction layer.

use crate::artifact::{Confidence, Evidence, RelationKind};
use crate::bytesource::ByteSource;
use crate::engine::{
    ArtifactDraft, Budget, Candidate, ChildContent, ChildDraft, Handler, HandlerOutput,
};
use crate::error::{Error, Result};
use std::collections::BTreeMap;

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

        // #7 §8: manual header walk so complete entries BEFORE a
        // corruption point / truncation are still salvaged. The `tar`
        // crate aborts on the first bad header; a CTF image often has
        // one mangled entry followed by readable ones.
        let mut children: Vec<ChildDraft> = Vec::new();
        let mut names: Vec<String> = Vec::new();
        let mut warnings: Vec<String> = Vec::new();
        let mut off: u64 = 0;
        let mut complete_entries = 0usize;
        let mut corrupt = false;
        while off + 512 <= src.len() && complete_entries < limits.max_archive_entries {
            let mut hdr = [0u8; 512];
            if src.read_at(off, &mut hdr).is_err() {
                break;
            }
            // Name: first 100 bytes, NUL-terminated.
            let name_end = hdr[..100].iter().position(|&b| b == 0).unwrap_or(100);
            if name_end == 0 {
                // Zero block region (end-of-archive padding) — stop.
                break;
            }
            let name = String::from_utf8_lossy(&hdr[..name_end]).into_owned();
            // Numeric fields: octal, space/NUL-terminated.
            let oct = |f: &[u8]| -> Option<u64> {
                let t: Vec<u8> = f
                    .iter()
                    .copied()
                    .take_while(|&b| b.is_ascii_digit())
                    .collect();
                if t.is_empty() {
                    return None;
                }
                u64::from_str_radix(&String::from_utf8_lossy(&t), 8).ok()
            };
            let size_field = oct(&hdr[124..136]);
            let typeflag = hdr[156];
            let ustar = &hdr[257..262] == b"ustar";
            let Some(size) = size_field else {
                corrupt = true;
                warnings.push(format!(
                    "entry {}: unreadable size field; salvage stops here",
                    name
                ));
                break;
            };
            if !ustar && typeflag != b'0' && typeflag != 0 {
                // Not a plausible header at all.
                corrupt = true;
                warnings.push(format!(
                    "entry {}: no ustar magic; salvage stops here",
                    name
                ));
                break;
            }
            let data_start = off + 512;
            let data_blocks = size.div_ceil(512);
            let data_end = data_start
                .checked_add(data_blocks * 512)
                .ok_or(Error::Validation {
                    format: "tar",
                    reason: "size overflow".into(),
                })?;
            if data_end > src.len() {
                // Truncated final entry: salvage the bytes that exist.
                // FINAL-B1/R1: `have` is bounded by BOTH the source
                // length and max_child_size (an attacker-declared huge
                // size at the end of a large source must not materialize
                // a per-entry buffer past the child cap), and the budget
                // is charged before the allocation.
                let have = (src.len() - data_start).min(limits.max_child_size);
                if !budget.charge(limits, have) {
                    return Err(Error::LimitExceeded {
                        limit: "max-total-expanded-bytes",
                        detail: format!("tar salvage {name:?} +{have} bytes"),
                    });
                }
                let mut buf = vec![0u8; have as usize];
                src.read_at(data_start, &mut buf)?;
                let _ = typeflag;
                names.push(name.clone());
                children.push(ChildDraft {
                    relation: RelationKind::Contains,
                    label: format!("tar entry {name} (truncated: {} of {} bytes)", have, size),
                    format_hint: "raw",
                    content: ChildContent::Owned(buf),
                    size: have,
                    metadata: {
                        let mut m = BTreeMap::new();
                        m.insert("truncated".to_string(), "true".to_string());
                        m.insert("declared_size".to_string(), size.to_string());
                        m
                    },
                    warnings: vec![format!(
                        "entry truncated at source end ({} of {} bytes present)",
                        have, size
                    )],
                    entry_name: Some(name),
                    // FINAL-R6: a truncated entry is PARTIAL bytes, not
                    // a structurally complete decode — never Validated.
                    confidence: Confidence::Partial,
                    evidence: vec![
                        "entry header valid but payload truncated at source end".to_string(),
                        format!("{} of {} declared bytes present", have, size),
                    ],
                });
                complete_entries += 1;
                corrupt = true;
                break;
            }
            // Complete entry: expose its full content.
            let is_file = typeflag == b'0' || typeflag == 0;
            if is_file && size > 0 {
                if size > limits.max_child_size {
                    warnings.push(format!("entry {name:?} exceeds max child size; skipped"));
                } else {
                    let region = src.slice(data_start, size)?;
                    if !budget.charge(limits, size) {
                        return Err(Error::LimitExceeded {
                            limit: "max-total-expanded-bytes",
                            detail: format!("tar entry {name:?} +{size} bytes"),
                        });
                    }
                    names.push(name.clone());
                    complete_entries += 1;
                    children.push(ChildDraft {
                        relation: RelationKind::Contains,
                        label: format!("tar entry {name}"),
                        format_hint: "raw",
                        content: ChildContent::Source(region),
                        size,
                        metadata: BTreeMap::new(),
                        warnings: Vec::new(),
                        entry_name: Some(name),
                        confidence: Confidence::Validated,
                        evidence: vec!["structurally decoded by parent handler".to_string()],
                    });
                }
            } else if !is_file {
                // Directories / links: metadata only.
                names.push(name.clone());
                complete_entries += 1;
                children.push(ChildDraft {
                    relation: RelationKind::Contains,
                    label: format!("tar entry {name} (type {typeflag})"),
                    format_hint: "metadata",
                    content: ChildContent::Owned(Vec::new()),
                    size: 0,
                    metadata: BTreeMap::new(),
                    warnings: Vec::new(),
                    entry_name: None,
                    confidence: Confidence::Validated,
                    evidence: vec!["structurally decoded by parent handler".to_string()],
                });
            } else {
                names.push(name.clone());
                complete_entries += 1;
            }
            off = data_end;
        }

        if complete_entries == 0 {
            return Err(Error::Validation {
                format: "tar",
                reason: "no parseable entry headers".into(),
            });
        }
        let _ = corrupt;

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
                children,
                entry_names: Vec::new(),
            }],
        })
    }
}
