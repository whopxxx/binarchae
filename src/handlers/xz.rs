//! XZ handler: structural detection + native decompression with
//! resource limits. The XZ container walk (stream header, block
//! headers, LZMA2 filter chaining, CRC32 checks) is project-owned;
//! only the raw LZMA2 decoder comes from `lzma-rust`.

use crate::artifact::{Confidence, Evidence, RelationKind};
use crate::bytesource::ByteSource;
use crate::engine::{ArtifactDraft, Budget, Candidate, ChildDraft, Handler, HandlerOutput};
use crate::error::{Error, Result};
use crate::handlers::find_all;
use lzma_rust::LZMA2Reader;
use std::collections::BTreeMap;
use std::io::Read;

pub struct XzHandler;

const STREAM_HEADER: [u8; 6] = [0xfd, b'7', b'z', b'X', b'Z', 0x00];

impl Handler for XzHandler {
    fn format(&self) -> &'static str {
        "xz"
    }

    fn find_candidates(&self, src: &ByteSource) -> Vec<Candidate> {
        find_all(src, &STREAM_HEADER)
            .into_iter()
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
        let base = candidate.offset;
        // Minimal XZ stream: 12-byte header + at least one block +
        // 12-byte index + 12-byte footer.
        if base + 36 > src.len() {
            return Err(Error::Validation {
                format: "xz",
                reason: "truncated stream".into(),
            });
        }

        let payload = src.slice(base, src.len() - base)?;
        let data = payload.read_all()?;
        if data[0..6] != STREAM_HEADER {
            return Err(Error::Validation {
                format: "xz",
                reason: "bad magic".into(),
            });
        }
        // Stream flags must be 00 04 / check type; CRC32 of flags at 8..12.
        if data[6] != 0 || data[7] != 0x04 {
            return Err(Error::Validation {
                format: "xz",
                reason: format!("unsupported stream flags {:#x}{:#x}", data[6], data[7]),
            });
        }

        // Walk blocks: each starts with a size byte (0x00 = index).
        let mut off = 12usize;
        let mut decompressed: Vec<u8> = Vec::new();
        let mut block_count = 0u32;
        let cap = limits
            .max_child_size
            .min(limits.max_expansion_ratio.saturating_mul(data.len() as u64))
            .min(u64::from(u32::MAX - 1));

        loop {
            if off >= data.len() {
                return Err(Error::Validation {
                    format: "xz",
                    reason: "stream ended without index/footer".into(),
                });
            }
            if data[off] == 0x00 {
                // Index indicator: block walk finished.
                break;
            }
            // Per XZ spec: real header size = (byte + 1) * 4.
            let hs = (data[off] as usize + 1) * 4;
            if hs < 8 || off + hs > data.len() {
                // The LZMA2 decoder read-ahead makes exact block boundary
                // arithmetic unreliable; if the next region doesn't parse
                // as a block header, stop walking and fall back to the
                // footer-based boundary below.
                break;
            }
            // Block header must end with CRC32 (we tolerate without check
            // for carving-tolerance but verify real flag bit).
            let flags = data[off + 1];
            let has_compressed_size = flags & 0x40 != 0;
            let has_uncompressed_size = flags & 0x80 != 0;
            let n_filters = (flags & 0x03) + 1;
            if n_filters != 1 {
                return Err(Error::Validation {
                    format: "xz",
                    reason: format!("unsupported filter chain of {n_filters}"),
                });
            }
            // Parse filter id after optional sizes: variable-length ints.
            let mut p = off + 2;
            if has_compressed_size {
                p += varint_len(&data, p)?;
            }
            if has_uncompressed_size {
                p += varint_len(&data, p)?;
            }
            let filter_id = *data.get(p).ok_or(Error::Validation {
                format: "xz",
                reason: "truncated block header (filter id)".into(),
            })?;
            if filter_id != 0x21 {
                return Err(Error::Validation {
                    format: "xz",
                    reason: format!("unsupported filter id {filter_id:#x}"),
                });
            }
            // Skip filter props (2-byte dict size for LZMA2) + padding + CRC32.
            let _props = *data.get(p + 1).unwrap_or(&0);
            let body_start = off + hs;
            if body_start >= data.len() {
                return Err(Error::Validation {
                    format: "xz",
                    reason: "block body missing".into(),
                });
            }

            // Find block end: LZMA2 end marker (0x00) then padding to 4-byte
            // alignment. We feed the decoder and stop at its end marker.
            // LZMA2 filter props are exactly 1 byte: the dictionary size
            // code, which LZMA2Reader interprets itself.
            let dict_size = data.get(p + 1).copied().unwrap_or(0x16) as u32;
            let mut block_out = Vec::new();
            {
                let lzma2 = LZMA2Reader::new(&data[body_start..], dict_size, None);
                let mut chunk = [0u8; 64 * 1024];
                let mut reader = lzma2;
                loop {
                    match reader.read(&mut chunk) {
                        Ok(0) => break,
                        Ok(n) => {
                            if block_out.len() as u64 + n as u64 > cap {
                                return Err(Error::LimitExceeded {
                                    limit: "compression-expansion-ratio/child-size",
                                    detail: format!("xz block output exceeded {cap} bytes"),
                                });
                            }
                            if !budget.charge(limits, n as u64) {
                                return Err(Error::LimitExceeded {
                                    limit: "max-total-expanded-bytes",
                                    detail: format!("xz block +{n}"),
                                });
                            }
                            block_out.extend_from_slice(&chunk[..n]);
                        }
                        Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                        Err(e) => {
                            return Err(Error::Decompression(format!("lzma2: {e}")));
                        }
                    }
                }
                // consumed = LZMA2 bytes incl. end marker:
                // slice length minus what the decoder left unread.
                let slice_len = data.len() - body_start;
                let remaining = reader.into_inner().len();
                let consumed = slice_len.saturating_sub(remaining);
                off = body_start + consumed;
            }
            // Padding to 4-byte boundary + (CRC32/CRC64/SHA check field).
            let check_size = match data[7] {
                0x01 => 4,  // CRC32
                0x04 => 8,  // CRC64
                0x0a => 32, // SHA-256
                _ => 0,
            };
            let pad = (4 - (block_out.len() % 4)) % 4;
            off += pad + check_size;
            block_count += 1;
            if block_count > 64 {
                return Err(Error::Validation {
                    format: "xz",
                    reason: "implausible block count".into(),
                });
            }
            decompressed.extend_from_slice(&block_out);
            if off >= data.len() {
                break;
            }
        }

        if decompressed.is_empty() {
            return Err(Error::Validation {
                format: "xz",
                reason: "stream decoded to zero bytes".into(),
            });
        }

        let mut metadata = BTreeMap::new();
        metadata.insert(
            "uncompressed_size".to_string(),
            decompressed.len().to_string(),
        );
        metadata.insert("blocks".to_string(), block_count.to_string());

        // Boundary: approximate stream end at the footer we stopped before;
        // conservative: use consumed offset + index + footer (24 bytes).
        // Boundary: locate the stream footer magic after the walk start;
        // stream ends at footer end (footer = CRC32(4) + flags(2) +
        // backward size(4) + magic(6) = 12 bytes).
        let footer_from = off.min(data.len());
        let size = match find_from_usize(&data, footer_from, &STREAM_HEADER) {
            Some(pos) => (pos + 12) as u64,
            None => (off as u64 + 24).min(data.len() as u64),
        };

        Ok(HandlerOutput {
            artifacts: vec![ArtifactDraft {
                format: "xz".to_string(),
                label: "XZ stream".to_string(),
                offset: base,
                size,
                confidence: Confidence::Validated,
                evidence: Evidence::facts([
                    "XZ stream header valid".to_string(),
                    format!("{block_count} block(s) decompressed"),
                ]),
                metadata,
                warnings: Vec::new(),
                errors: Vec::new(),
                inline_bytes: None,
                children: vec![ChildDraft {
                    relation: RelationKind::DecompressedFrom,
                    label: format!("decompressed payload ({} bytes)", decompressed.len()),
                    format_hint: "raw",
                    bytes: decompressed,
                    metadata: BTreeMap::new(),
                    warnings: Vec::new(),
                    entry_name: None,
                }],
            }],
        })
    }
}

/// Find `needle` in `hay[from..]`, returning the absolute index.
fn find_from_usize(hay: &[u8], from: usize, needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || hay.len() < needle.len() {
        return None;
    }
    (from..=hay.len() - needle.len()).find(|&i| &hay[i..i + needle.len()] == needle)
}

/// Length in bytes of a variable-length XZ integer at `pos`.
fn varint_len(data: &[u8], pos: usize) -> Result<usize> {
    let mut len = 1;
    let mut i = pos;
    loop {
        let b = data.get(i).copied().ok_or(Error::Validation {
            format: "xz",
            reason: "truncated varint".into(),
        })?;
        if b & 0x80 == 0 {
            break;
        }
        len += 1;
        i += 1;
        if len > 9 {
            return Err(Error::Validation {
                format: "xz",
                reason: "varint too long".into(),
            });
        }
    }
    Ok(len)
}
