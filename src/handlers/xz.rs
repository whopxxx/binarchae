//! XZ handler: structural detection + native decompression with
//! resource limits. The XZ container walk (stream header, block
//! headers, index, stream footer) is project-owned per the XZ file
//! format specification (XZ Utils / xz-file-format.txt); only the raw
//! LZMA2 decoder comes from `lzma-rust`.
//!
//! Stream layout per the spec:
//!   Stream Header: magic(6) + stream flags(2) + CRC32(flags)(4) = 12 B
//!   Block Header:  RLE byte (size/4 - 1), block flags, optional
//!                  compressed/uncompressed sizes (varints), filter
//!                  flags [filter ID varint, props size varint, props],
//!                  padding to 4-byte multiple, CRC32(header)(4)
//!   Block:         compressed data, padding to 4-byte boundary (of the
//!                  COMPRESSED size), check field per stream flags
//!   Index:         0x00 indicator, record count varint, per-block
//!                  [unpadded size, uncompressed size] varints, padding
//!                  to 4, CRC32(index)
//!   Stream Footer: CRC32(4) over [backward size(4) + stream flags(2)],
//!                  backward size (index size/4 - 1), stream flags
//!                  (must match header), footer magic "YZ"(2) = 12 B
//!
//! The stream boundary ends at the footer's final `YZ` byte pair.
//! Tests use a fixture generated once by XZ Utils (standard-compliant)
//! and fixed as bytes, so a parser regression cannot drift the fixture.

use crate::artifact::{Confidence, Evidence, RelationKind};
use crate::bytesource::ByteSource;
use crate::engine::{
    ArtifactDraft, Budget, Candidate, ChildContent, ChildDraft, Handler, HandlerOutput,
};
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
        // whose CRC32 (covering backward size + flags) is consistent.
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
            // Filter flags per spec: filter ID varint, then a Properties
            // Size varint, then that many property bytes.
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
            p += 1; // past filter id
                    // Properties Size varint (spec §5.3.1.2), then the properties.
            let props_size_pos = p;
            let props_size = read_varint(&data, props_size_pos)? as usize;
            let props_start = p + varint_len(&data, props_size_pos)?;
            if props_size != 1 || props_start + props_size > off + hs - 4 {
                return Err(Error::Validation {
                    format: "xz",
                    reason: format!("unsupported LZMA2 property size {props_size}"),
                });
            }
            // The single LZMA2 property byte is the dictionary size CODE
            // (spec §5.3.1.2): real byte size = (2 | (code & 1)) <<
            // (code/2 + 11). lzma-rust's LZMA2Reader expects the actual
            // byte count, not the encoded code.
            let dict_code = data.get(props_start).copied().unwrap_or(0x16) as u32;
            let dict_size = (2u32 | (dict_code & 1)) << (dict_code / 2 + 11);
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
                // Walk the LZMA2 chunk headers to find where the stream
                // ends: each chunk starts with a control byte; 0x00 is the
                // end marker. LZMA chunks (control >= 0x80) carry an
                // uncompressed size (2B) and compressed size (2B), which
                // gives exact spans; uncompressed chunks (0x01/0x02) carry
                // a 2B size. This avoids relying on decoder read-ahead
                // behavior entirely.
                let mut q = body_start;
                loop {
                    let control = *data.get(q).ok_or(Error::Validation {
                        format: "xz",
                        reason: "LZMA2 stream truncated (no end marker)".into(),
                    })?;
                    if control == 0x00 {
                        q += 1; // end marker
                        break;
                    }
                    if control >= 0x80 {
                        // LZMA chunk (F2): control(1) + uncompressed size
                        // (2B, output-side only — it does NOT occupy
                        // input) + compressed size (2B), then exactly
                        // `csz` bytes of range-coded input. Header is 5
                        // bytes, plus 1 more props byte only when the
                        // chunk carries new properties (control >= 0xC0;
                        // this includes 0xE0 dict-reset chunks).
                        let csz = u16::from_be_bytes([
                            *data.get(q + 3).ok_or(Error::Validation {
                                format: "xz",
                                reason: "truncated LZMA2 chunk".into(),
                            })?,
                            *data.get(q + 4).ok_or(Error::Validation {
                                format: "xz",
                                reason: "truncated LZMA2 chunk".into(),
                            })?,
                        ]) as usize
                            + 1;
                        let hdr = if control >= 0xC0 { 6 } else { 5 };
                        q += hdr + csz;
                    } else if control == 0x01 || control == 0x02 {
                        // Uncompressed chunk: 1B control + 2B size-1 + data.
                        let sz = u16::from_be_bytes([
                            *data.get(q + 1).ok_or(Error::Validation {
                                format: "xz",
                                reason: "truncated LZMA2 chunk".into(),
                            })?,
                            *data.get(q + 2).ok_or(Error::Validation {
                                format: "xz",
                                reason: "truncated LZMA2 chunk".into(),
                            })?,
                        ]) as usize
                            + 1;
                        q += 3 + sz;
                    } else {
                        return Err(Error::Validation {
                            format: "xz",
                            reason: format!("invalid LZMA2 control byte {control:#x}"),
                        });
                    }
                }
                consumed = q - body_start;
            }
            // Block padding per spec pads the COMPRESSED data to a
            // 4-byte boundary, followed by the check field.
            let check_size = check_size_for(header_flags[1]);
            let compressed_total = body_start + consumed - (off);
            let block_compressed = compressed_total - hs;
            let pad = (4 - (block_compressed % 4)) % 4;
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

        let decompressed_size = decompressed.len() as u64;
        let mut metadata = BTreeMap::new();
        metadata.insert(
            "uncompressed_size".to_string(),
            decompressed.len().to_string(),
        );
        metadata.insert("blocks".to_string(), block_count.to_string());

        // Exact, spec-compliant boundary — the stream ends at the
        // footer's YZ magic.
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
                    "stream footer YZ magic + flags + CRC32 valid".to_string(),
                ]),
                metadata,
                warnings: Vec::new(),
                errors: Vec::new(),
                children: vec![ChildDraft {
                    relation: RelationKind::DecompressedFrom,
                    label: format!("decompressed payload ({} bytes)", decompressed.len()),
                    format_hint: "raw",
                    content: ChildContent::Owned(decompressed),
                    size: decompressed_size,
                    metadata: BTreeMap::new(),
                    warnings: Vec::new(),
                    entry_name: None,
                    confidence: Confidence::Validated,
                    evidence: vec!["structurally decoded by parent handler".to_string()],
                }],
                entry_names: Vec::new(),
            }],
        })
    }
}

impl XzHandler {
    /// Find the stream footer: a `YZ` occurrence where
    ///   footer[0..4]   = CRC32(footer[4..12])
    ///   footer[4..8]   = backward size (index size/4 - 1)
    ///   footer[8..10]  = stream flags (must match header)
    ///   footer[10..12] = YZ
    /// Returns the offset of the footer start.
    fn find_valid_footer(&self, data: &[u8], header_flags: &[u8; 2]) -> Result<usize> {
        if data.len() < 24 {
            return Err(Error::Validation {
                format: "xz",
                reason: "stream too short for index+footer".into(),
            });
        }
        let mut search = 12usize;
        while let Some(rel) = find_from_usize(data, search, &STREAM_FOOTER_MAGIC) {
            // Footer layout: [CRC32(4)][backward(4)][flags(2)][YZ(2)];
            // `rel` points at YZ, so the footer starts 10 bytes earlier.
            let Some(fstart) = rel.checked_sub(10) else {
                search = rel + 1;
                continue;
            };
            if fstart < 12 {
                search = rel + 1;
                continue;
            }
            let flags = [data[fstart + 8], data[fstart + 9]];
            if flags != *header_flags {
                search = rel + 1;
                continue;
            }
            // CRC32 covers backward size + stream flags only (bytes 4..10).
            let crc_ok = crc32(&data[fstart + 4..fstart + 10])
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

/// Read a variable-length XZ integer at `pos` (max 9 bytes, little-endian
/// groups of 7 bits with continuation bits).
fn read_varint(data: &[u8], pos: usize) -> Result<u64> {
    let mut value: u64 = 0;
    for (byte_idx, i) in (0usize..9).zip(pos..) {
        let b = data.get(i).copied().ok_or(Error::Validation {
            format: "xz",
            reason: "truncated varint".into(),
        })?;
        value |= u64::from(b & 0x7f) << (7 * byte_idx as u32);
        if b & 0x80 == 0 {
            return Ok(value);
        }
    }
    Err(Error::Validation {
        format: "xz",
        reason: "varint too long".into(),
    })
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

#[cfg(test)]
mod tests {
    use super::*;

    /// Fixture generated ONCE by XZ Utils 5.8.3 (`xz -z --check=crc32`
    /// over the 20-byte payload `flag{xz-std-fixture}`) and fixed as
    /// bytes. It is external ground truth: if this handler drifts from
    /// the real XZ format, this fixture stops parsing — the fixture is
    /// never regenerated to match a broken parser.
    const STD_XZ_HEX: &str = "fd377a585a0000016922de3604c01814210116000000000000000000fadb09f5010013666c61677b787a2d7374642d666978747572657d00e141859c00013014a5571ae59042990d010000000001595a";

    fn std_xz() -> Vec<u8> {
        (0..STD_XZ_HEX.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&STD_XZ_HEX[i..i + 2], 16).unwrap())
            .collect()
    }

    /// The fixture is spec-shaped: footer fields in the documented order,
    /// footer CRC covering bytes 4..12, block padding computed from the
    /// compressed size, and the payload matching the original message.
    #[test]
    fn parses_standard_xz_utils_fixture() {
        let data = std_xz();
        // Footer sanity per spec: CRC32 | backward(4) | flags(2) | YZ.
        let f = data.len() - 12;
        assert_eq!(&data[f + 10..f + 12], &STREAM_FOOTER_MAGIC);
        assert_eq!([data[f + 8], data[f + 9]], [0x00, 0x01]);
        // Footer CRC32 covers backward size + stream flags (6 bytes).
        assert_eq!(
            crc32(&data[f + 4..f + 10]),
            u32::from_le_bytes([data[f], data[f + 1], data[f + 2], data[f + 3]])
        );

        let src = ByteSource::from_vec(data);
        let h = XzHandler;
        let cands = h.find_candidates(&src);
        assert_eq!(cands.len(), 1);
        let mut budget = Budget::default();
        let out = h
            .validate(
                &src,
                cands[0],
                &crate::engine::EngineLimits::default(),
                &mut budget,
            )
            .expect("standard fixture must parse");
        let art = &out.artifacts[0];
        assert_eq!(art.size, 80);
        assert_eq!(art.confidence, Confidence::Validated);
        let payload = art.children[0].content.to_bytes().unwrap_or_default();
        assert_eq!(payload, b"flag{xz-std-fixture}");
    }

    /// Corrupting the footer CRC must reject the stream (the footer is
    /// actually verified, not merely located).
    #[test]
    fn rejects_corrupted_footer_crc() {
        let mut data = std_xz();
        let f = data.len() - 12;
        data[f] ^= 0xff;
        let src = ByteSource::from_vec(data);
        let h = XzHandler;
        let mut budget = Budget::default();
        let res = h.validate(
            &src,
            Candidate { offset: 0 },
            &crate::engine::EngineLimits::default(),
            &mut budget,
        );
        assert!(res.is_err(), "corrupt footer CRC must not validate");
    }

    /// Corrupting the block header CRC must reject the stream.
    #[test]
    fn rejects_corrupted_block_header_crc() {
        let mut data = std_xz();
        data[28] ^= 0xff; // last byte of the block header CRC
        let src = ByteSource::from_vec(data);
        let h = XzHandler;
        let mut budget = Budget::default();
        let res = h.validate(
            &src,
            Candidate { offset: 0 },
            &crate::engine::EngineLimits::default(),
            &mut budget,
        );
        assert!(res.is_err(), "corrupt block header CRC must not validate");
    }

    /// Trailing bytes after the footer end are NOT part of the stream:
    /// the artifact size stays footer-anchored.
    #[test]
    fn footer_anchored_boundary_with_appended_data() {
        let mut data = std_xz();
        data.extend_from_slice(b"appended junk");
        let src = ByteSource::from_vec(data);
        let h = XzHandler;
        let mut budget = Budget::default();
        let out = h
            .validate(
                &src,
                Candidate { offset: 0 },
                &crate::engine::EngineLimits::default(),
                &mut budget,
            )
            .expect("parses with trailing bytes");
        assert_eq!(out.artifacts[0].size, 80);
    }

    /// F2 regression: a REAL compressed LZMA2 chunk (control >= 0x80),
    /// frozen from XZ Utils 5.8.3 (`xz -z --check=crc32` over
    /// `msg*8 + 300 random bytes`). Verifies: (a) the body chunk really
    /// is range-coded, (b) the full 788-byte payload round-trips,
    /// (c) the stream boundary is exact, (d) the LZMA chunk walk consumed
    /// exactly header+csz (5-byte header when no new props, 6 with).
    const STD_XZ_LZMA_HEX: &str = "fd377a585a0000016922de3604c08203940621011600000000000000b4fc7de9e00313017a5d00331b084758477a2aeb4c936f658d77db64f5867c4d26669bb5df78a682e97b1c156e604ac38dc14d19c4b6b00823e216a0cb92ca12f57bca04ccfab8b20c3b76d162f663cd21deacc76b6fc4d42bc177b53a656870fb38d6eae341a762a180ee7a7254e7514463090799cd2541cd952927b4fc796156403fb618d78ceab98a75377bc5f6852b5c58d82e55a5d92ddc5b6d388fc3f68667bcdd76fbc57684ddefe8d23ac65dbc5d8a53a7b99d853542e0bcd4d9e94c91029e6718ec5cd8f43df0d45b0eb2ef4685a9098a50bfc2e53ff8dce95fd3843e89d1632aa71738abecd1cfc0d9482a2d9299a9c52bb1bf1c798c9571373e43f8a8c5a7f206eaac2a20ff6e36c7e024db7f09a0da857000d08c08211310a0ad210201b6ebff64df4f4c15243d88ca4cee8be213a778caefa375cdfb31d6457e12bc2841bc717445901fec8799708eb76ed747c7d769d6d927ee24364e43d9b0176d7fbf262ee87ab44d52af70cd8d8763694679c4f0243c1e2296f04a4ed236318d4d34a500000037de4ea400019a03940600006991a70e3e300d8b020000000001595a";

    #[test]
    fn parses_real_compressed_lzma2_chunk() {
        let data: Vec<u8> = (0..STD_XZ_LZMA_HEX.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&STD_XZ_LZMA_HEX[i..i + 2], 16).unwrap())
            .collect();
        assert_eq!(data.len(), 448);

        // (a) The body chunk is genuinely range-coded: control >= 0x80.
        // Block header is 20 bytes (first byte 0x04 => (4+1)*4), so the
        // LZMA2 body starts at 32.
        let control = data[32];
        assert!(
            control >= 0x80,
            "fixture must use a compressed LZMA chunk, got {control:#x}"
        );
        // This chunk carries new properties (0xE0 = 0x80|0x60): 6B header.
        assert_eq!(control, 0xE0);
        let csz = u16::from_be_bytes([data[35], data[36]]) as usize + 1;
        let usz = (((control & 0x1F) as usize) << 16)
            + u16::from_be_bytes([data[33], data[34]]) as usize
            + 1;
        assert_eq!(usz, 788);
        // LZMA2 body = 6B header + csz compressed bytes + end marker(1).
        assert_eq!(32 + 6 + csz + 1, 418);

        let src = ByteSource::from_vec(data);
        let h = XzHandler;
        let mut budget = Budget::default();
        let out = h
            .validate(
                &src,
                Candidate { offset: 0 },
                &crate::engine::EngineLimits::default(),
                &mut budget,
            )
            .expect("compressed-chunk fixture must parse");

        // (c) Exact footer-anchored boundary.
        assert_eq!(out.artifacts[0].size, 448);

        // (b) Full payload round-trips: 8x the marker message + noise.
        let payload = out.artifacts[0].children[0]
            .content
            .to_bytes()
            .unwrap_or_default();
        assert_eq!(payload.len(), 788);
        let marker = b"flag{xz-compressed-chunk-larger-payload-for-real-lzma-coding}";
        for (i, chunk) in payload.chunks(marker.len()).enumerate() {
            if i < 8 {
                assert_eq!(chunk, marker, "repeated marker segment {i}");
            }
        }
        // The trailing 300 bytes are random; assert they are not all zero.
        assert!(payload[488..].iter().any(|&b| b != 0));
    }
}
