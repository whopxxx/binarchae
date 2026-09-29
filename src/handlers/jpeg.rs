//! JPEG handler: marker-aware validation with EOI-proven boundary.
//! Unrelated false SOI signatures are tolerated (rejected) without
//! affecting anything else.

use crate::artifact::{Confidence, Evidence};
use crate::bytesource::ByteSource;
use crate::engine::{ArtifactDraft, Budget, Candidate, Handler, HandlerOutput};
use crate::error::{Error, Result};
use std::collections::BTreeMap;

pub struct JpegHandler;

impl Handler for JpegHandler {
    fn format(&self) -> &'static str {
        "jpeg"
    }

    fn find_candidates(&self, src: &ByteSource) -> Vec<Candidate> {
        let mut hits = Vec::new();
        let data = match src.read_prefix(64 * 1024 * 1024) {
            Ok(d) => d,
            Err(_) => return hits,
        };
        if data.len() < 4 {
            return hits;
        }
        for i in 0..=(data.len() - 2) {
            if data[i] == 0xff && data[i + 1] == 0xd8 {
                hits.push(Candidate { offset: i as u64 });
            }
        }
        hits
    }

    fn validate(
        &self,
        src: &ByteSource,
        candidate: Candidate,
        _limits: &crate::engine::EngineLimits,
        _budget: &mut Budget,
    ) -> Result<HandlerOutput> {
        let base = candidate.offset;
        let mut off = base + 2;
        if off >= src.len() {
            return Err(Error::Validation {
                format: "jpeg",
                reason: "nothing after SOI".into(),
            });
        }

        let mut segments: u32 = 0;
        let mut saw_sof = false;
        let mut width = None;
        let mut height = None;
        let end_boundary;

        loop {
            if off + 4 > src.len() {
                return Err(Error::Validation {
                    format: "jpeg",
                    reason: "truncated before EOI".into(),
                });
            }
            let mut m = [0u8; 2];
            src.read_at(off, &mut m)?;
            if m[0] != 0xff {
                return Err(Error::Validation {
                    format: "jpeg",
                    reason: format!("expected marker at {off:#x}, found {:#04x}", m[0]),
                });
            }
            let marker = m[1];
            if marker == 0xd9 {
                // EOI
                end_boundary = Some(off + 2);
                break;
            }
            if marker == 0x01 || (0xd0..=0xd7).contains(&marker) {
                // Standalone marker, no length field.
                off += 2;
                segments += 1;
                continue;
            }
            // Segment with length.
            let mut lb = [0u8; 2];
            src.read_at(off + 2, &mut lb)?;
            let seg_len = u16::from_be_bytes(lb) as u64;
            if seg_len < 2 {
                return Err(Error::Validation {
                    format: "jpeg",
                    reason: "segment length < 2".into(),
                });
            }
            if off + 2 + seg_len > src.len() {
                return Err(Error::Validation {
                    format: "jpeg",
                    reason: "segment extends past end".into(),
                });
            }
            let is_sof = (0xc0..=0xcf).contains(&marker)
                && marker != 0xc4
                && marker != 0xc8
                && marker != 0xcc;
            if is_sof && seg_len >= 8 {
                let mut hb = [0u8; 4];
                src.read_at(off + 5, &mut hb)?;
                height = Some(u16::from_be_bytes([hb[0], hb[1]]));
                width = Some(u16::from_be_bytes([hb[2], hb[3]]));
                saw_sof = true;
            }
            if marker == 0xda {
                // Start of scan: skip entropy-coded data to next EOI.
                off += 2 + seg_len;
                end_boundary = self.find_scan_end(src, off)?;
                break;
            }
            off += 2 + seg_len;
            segments += 1;
            if segments > 100_000 {
                return Err(Error::Validation {
                    format: "jpeg",
                    reason: "implausible segment count".into(),
                });
            }
        }

        let end = end_boundary.ok_or(Error::Validation {
            format: "jpeg",
            reason: "no EOI".into(),
        })?;
        let size = end - base;

        let mut metadata = BTreeMap::new();
        metadata.insert("segments".to_string(), segments.to_string());
        if let (Some(w), Some(h)) = (width, height) {
            metadata.insert("width".to_string(), w.to_string());
            metadata.insert("height".to_string(), h.to_string());
        }

        Ok(HandlerOutput {
            artifacts: vec![ArtifactDraft {
                format: "jpeg".to_string(),
                label: match (width, height) {
                    (Some(w), Some(h)) => format!("JPEG image {w}x{h}"),
                    _ => "JPEG image".to_string(),
                },
                offset: base,
                size,
                confidence: if saw_sof {
                    Confidence::Validated
                } else {
                    Confidence::Partial
                },
                evidence: Evidence::facts([
                    "SOI/EOI marker walk completed".to_string(),
                    if saw_sof {
                        "frame header present".to_string()
                    } else {
                        "no frame header (partial)".to_string()
                    },
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

impl JpegHandler {
    /// Walk entropy-coded data after SOS to the next marker (EOI or new
    /// marker sequence), tolerating restart markers.
    fn find_scan_end(&self, src: &ByteSource, mut off: u64) -> Result<Option<u64>> {
        loop {
            if off + 1 >= src.len() {
                return Err(Error::Validation {
                    format: "jpeg",
                    reason: "scan data truncated before EOI".into(),
                });
            }
            let mut b = [0u8; 2];
            src.read_at(off, &mut b)?;
            if b[0] == 0xff {
                if b[1] == 0x00 || (0xd0..=0xd7).contains(&b[1]) {
                    // Stuffed byte or restart marker: part of scan data.
                    off += 2;
                    continue;
                }
                if b[1] == 0xd9 {
                    return Ok(Some(off + 2));
                }
                // Any other marker after scan: treat scan as ending here
                // without consuming it (EOI still proven if we saw 0xff).
                return Err(Error::Validation {
                    format: "jpeg",
                    reason: "unexpected marker inside scan; EOI not found".into(),
                });
            }
            off += 1;
        }
    }
}
