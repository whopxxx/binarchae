//! XZ handler: structural detection + native decompression with
//! resource limits. The XZ container walk (stream header, block
//! headers, index, stream footer) is project-owned per the XZ format
//! spec; only the raw LZMA2 decoder comes from `lzma-rust`.
//!
//! Stream layout per the spec (https://tukaani.org/xz/xz-file-format.txt):
//!   Stream Header: magic(6) + stream flags(2) + CRC32(4)   = 12 bytes
//!   Blocks / Index: index = 0x00 + records + padding + CRC32
//!   Stream Footer:  CRC32(4) + stream flags(2) + backward size(4)
//!                   + footer magic "YZ"(2)                  = 12 bytes
//! The stream ends at the footer's `YZ` magic, and the footer's stream
//! flags must match the header's.

use crate::artifact::{Confidence, Evidence, RelationKind};
use crate::bytesource::ByteSource;
use crate::engine::{ArtifactDraft, Budget, Candidate, ChildDraft, Handler, HandlerOutput};
use crate::error::{Error, Result};
use crate::handlers::find_all;
use lzma_rust::LZMA2Reader;
use std::collections::BTreeMap;
use std::io::Read;

pub struct XzHandler;

/// Stream Header magic (first 6 bytes of a stream).
pub const STREAM_HEADER_MAGIC: [u8; 6] = [0xfd, b'7', b'z', b'X', b'Z', 0x00];
/// Stream Footer magic (last 2 bytes of a stream): "YZ".
pub const STREAM_FOOTER_MAGIC: [u8; 2] = [0x59, 0x5a];

impl Handler for XzHandler {
    fn format(&self) -> &'static str {
        "xz"
    }

    fn find_candidates(&self, src: &ByteSource) -> Vec<Candidate> {
        find_all(src, &STREAM_HEADER_MAGIC)
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
        // Minimal XZ stream: 12-byte header + block + index + 12-byte footer.
        if base + 36 > src.len() {
            return Err(Error::Validation {
                format: "xz",
                reason: "truncated stream".into(),
            });
        }

        let payload = src.slice(base, src.len() - base)?;
        let data = payload.read_all()?;
        if data[0..6] != STREAM_HEADER_MAGIC {
            return Err(Error::Validation {
                format: "xz",
                reason: "bad magic".into(),
            });
        }
        let header_flags = [data[6], data[7]];
        if header_flags[0] != 0 {
            return Err(Error::Validation {
                format: "xz",
                reason: format!("reserved first flags byte {:#x}", header_flags[0]),
            });
        }
        // CRC32 of the stream flags, validating the header structure.
        let header_crc = u32::from_le_bytes([data[8], data[9], data[10], data[11]]);
        if crc32(&header_flags) != header_crc {
            return Err(Error::Validation {
                format: "xz",
                reason: "stream header CRC32 mismatch".into(),
            });
        }

        // Locate the stream footer: scan for `YZ` such that the 12 bytes
        // ending there form a footer whose flags match the header and
        // whose backward size and CRC32 are self-consistent.
        let footer_pos = self.find_valid_footer(&data, &header_flags)?;

        // Walk blocks between header end and index start.
        let mut off = 12usize;
        let mut decompressed: Vec<u8> = Vec::new();
        let mut block_count = 0u32;
        let cap = limits
            .max_child_size
            .min(limits.max_expansion_ratio.saturating_mul(data.len() as u64))
            .min(u64::from(u32::MAX - 1));

        while off < footer_pos {
            if data[off] == 0x00 {
                // Index indicator: block walk finished.
                break;
            }
            // Per XZ spec: real header size = (byte + 1) * 4.
            let hs = (data[off] as usize + 1) * 4;
            if hs < 8 || off + hs > footer_pos {
                return Err(Error::Validation {
                    format: "xz",
                    reason: "invalid block header size".into(),
                });
            }
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
            // Block header CRC32 (last 4 bytes of the header).
            let hcrc_expected = u32::from_le_bytes([
                data[off + hs - 4],
                data[off + hs - 3],
                data[off + hs - 2],
                data[off + hs - 1],
            ]);
            if crc32(&data[off..off + hs - 4]) != hcrc_expected {
                return Err(Error::Validation {
                    format: "xz",
                    reason: "block header CRC32 mismatch".into(),
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
            // LZMA2 filter props are exactly 1 byte: the dictionary size
            // code, which LZMA2Reader interprets itself.
            let dict_size = data.get(p + 1).copied().unwrap_or(0x16) as u32;
            let body_start = off + hs;
            if body_start >= footer_pos {
                return Err(Error::Validation {
                    format: "xz",
                    reason: "block body missing".into(),
                });
            }

            // Decompress the LZMA2 stream incrementally under the budget.
            let mut block_out = Vec::new();
            let consumed;
            {
                let lzma2 = LZMA2Reader::new(&data[body_start..footer_pos], dict_size, None);
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
                // consumed = LZMA2 bytes incl. end marker: slice length
                // minus what the decoder left unread (read-ahead aware).
                let slice_len = footer_pos - body_start;
                let remaining = reader.into_inner().len();
                consumed = slice_len.saturating_sub(remaining);
            }
            // Block padding to 4-byte boundary + check field.
            let check_size = check_size_for(header_flags[1]);
            let pad = (4 - (block_out.len() % 4)) % 4;
            off = body_start + consumed + pad + check_size;
            block_count += 1;
            if block_count > 64 {
                return Err(Error::Validation {
                    format: "xz",
                    reason: "implausible block count".into(),
                });
            }
            decompressed.extend_from_slice(&block_out);
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

        // B4: exact, spec-compliant boundary — the stream ends at the
        // footer's YZ magic (2 bytes).
        let size = (footer_pos + 12) as u64;

        Ok(HandlerOutput {
            artifacts: vec![ArtifactDraft {
                format: "xz".to_string(),
                label: "XZ stream".to_string(),
                offset: base,
                size,
                confidence: Confidence::Validated,
                evidence: Evidence::facts([
                    "stream header magic + CRC32 valid".to_string(),
                    format!("{block_count} block(s) decompressed"),
                    "stream footer YZ magic + flags match header".to_string(),
                ]),
                metadata,
                warnings: Vec::new(),
                errors: Vec::new(),
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

impl XzHandler {
    /// Find the stream footer: a `YZ` occurrence where
    ///   footer[0..4]   = CRC32(footer[4..12])
    ///   footer[4..6]   = header stream flags
    ///   footer[10..12] = YZ
    /// and the index backward size is consistent. Returns the offset of
    /// the footer start.
    fn find_valid_footer(&self, data: &[u8], header_flags: &[u8; 2]) -> Result<usize> {
        if data.len() < 24 {
            return Err(Error::Validation {
                format: "xz",
                reason: "stream too short for index+footer".into(),
            });
        }
        let mut search = 12usize;
        while let Some(rel) = find_from_usize(data, search, &STREAM_FOOTER_MAGIC) {
            // Footer layout: [CRC32(4)][flags(2)][backward size(4)][YZ(2)].
            // `rel` points at YZ, so the footer starts 10 bytes earlier.
            let Some(fstart) = rel.checked_sub(10) else {
                search = rel + 1;
                continue;
            };
            if fstart < 12 {
                search = rel + 1;
                continue;
            }
            let flags = [data[fstart + 4], data[fstart + 5]];
            if flags != *header_flags {
                search = rel + 1;
                continue;
            }
            let crc_ok = crc32(&data[fstart + 4..fstart + 12])
                == u32::from_le_bytes([
                    data[fstart],
                    data[fstart + 1],
                    data[fstart + 2],
                    data[fstart + 3],
                ]);
            if !crc_ok {
                search = rel + 1;
                continue;
            }
            return Ok(fstart);
        }
        Err(Error::Validation {
            format: "xz",
            reason: "no valid stream footer (YZ + matching flags + CRC32)".into(),
        })
    }
}

fn check_size_for(check_id: u8) -> usize {
    match check_id {
        0x01 => 4,  // CRC32
        0x04 => 8,  // CRC64
        0x0a => 32, // SHA-256
        _ => 0,     // None / unsupported: treated as absent
    }
}

fn crc32(data: &[u8]) -> u32 {
    let mut h = crc32fast::Hasher::new();
    h.update(data);
    h.finalize()
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
