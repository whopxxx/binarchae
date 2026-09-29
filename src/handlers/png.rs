//! PNG handler: full chunk walk, IEND-proven boundary, trailing-data
//! detection is performed by the engine on the parent region.

use crate::artifact::{Confidence, Evidence};
use crate::bytesource::ByteSource;
use crate::engine::{ArtifactDraft, Budget, Candidate, Handler, HandlerOutput};
use crate::error::{Error, Result};
use crate::handlers::read_u32_be;
use std::collections::BTreeMap;

pub struct PngHandler;

const SIGNATURE: [u8; 8] = [0x89, b'P', b'N', b'G', 0x0d, 0x0a, 0x1a, 0x0a];
const MAX_CHUNK: u64 = 512 * 1024 * 1024;

impl Handler for PngHandler {
    fn format(&self) -> &'static str {
        "png"
    }

    fn find_candidates(&self, src: &ByteSource) -> Vec<Candidate> {
        let mut hits = Vec::new();
        let data = match src.read_prefix(64 * 1024 * 1024) {
            Ok(d) => d,
            Err(_) => return hits,
        };
        if data.len() < 8 {
            return hits;
        }
        for i in 0..=(data.len() - 8) {
            if data[i..i + 8] == SIGNATURE {
                hits.push(Candidate { offset: i as u64 });
            }
        }
        hits
    }

    fn validate(
        &self,
        src: &ByteSource,
        candidate: Candidate,
        limits: &crate::engine::EngineLimits,
        _budget: &mut Budget,
    ) -> Result<HandlerOutput> {
        let base = candidate.offset;
        if base + 8 > src.len() {
            return Err(Error::Validation {
                format: "png",
                reason: "truncated signature".into(),
            });
        }

        // Walk chunks: len(4) type(4) data(len) crc(4).
        let mut off = base + 8;
        let mut chunks: Vec<String> = Vec::new();
        let mut width = None;
        let mut height = None;
        let end_boundary;
        loop {
            if off + 8 > src.len() {
                return Err(Error::Validation {
                    format: "png",
                    reason: "chunk header truncated before IEND".into(),
                });
            }
            let len = read_u32_be(src, off).ok_or(Error::Validation {
                format: "png",
                reason: "unreadable chunk length".into(),
            })? as u64;
            if len > MAX_CHUNK || len > limits.max_child_size {
                return Err(Error::Validation {
                    format: "png",
                    reason: format!("chunk length {len} exceeds limits"),
                });
            }
            let mut ctype = [0u8; 4];
            src.read_at(off + 4, &mut ctype)?;
            let ctype_str: String = ctype.iter().map(|&c| c as char).collect();
            let data_start = off + 8;
            let next = data_start
                .checked_add(len)
                .and_then(|v| v.checked_add(4))
                .ok_or(Error::Validation {
                    format: "png",
                    reason: "chunk length overflow".into(),
                })?;
            if next > src.len() {
                return Err(Error::Validation {
                    format: "png",
                    reason: format!("chunk {ctype_str} extends past end of source"),
                });
            }
            if ctype == *b"IHDR" && len >= 8 {
                width = read_u32_be(src, data_start);
                height = read_u32_be(src, data_start + 4);
            }
            chunks.push(ctype_str.clone());
            off = next;
            if ctype == *b"IEND" {
                end_boundary = Some(off);
                break;
            }
            if chunks.len() > 100_000 {
                return Err(Error::Validation {
                    format: "png",
                    reason: "implausible chunk count".into(),
                });
            }
        }

        let end = end_boundary.ok_or(Error::Validation {
            format: "png",
            reason: "no IEND".into(),
        })?;
        let size = end - base;

        let mut metadata = BTreeMap::new();
        metadata.insert("chunks".to_string(), chunks.len().to_string());
        if let (Some(w), Some(h)) = (width, height) {
            metadata.insert("width".to_string(), w.to_string());
            metadata.insert("height".to_string(), h.to_string());
        }
        metadata.insert("chunk_types".to_string(), chunks.join(","));

        Ok(HandlerOutput {
            artifacts: vec![ArtifactDraft {
                format: "png".to_string(),
                label: match (width, height) {
                    (Some(w), Some(h)) => format!("PNG image {w}x{h}"),
                    _ => "PNG image".to_string(),
                },
                offset: base,
                size,
                confidence: Confidence::Validated,
                evidence: Evidence::facts([
                    "8-byte PNG signature".to_string(),
                    "chunk walk completed to IEND".to_string(),
                ]),
                metadata,
                warnings: Vec::new(),
                errors: Vec::new(),
                children: Vec::new(),
                entry_names: Vec::new(),
            }],
        })
    }
}
