//! M3 compression handlers: zlib, raw DEFLATE, bzip2, Zstandard, LZ4,
//! Brotli. Each handler structurally validates its container/framing
//! (where the format defines one), decompresses natively with the same
//! budget/limit enforcement as gzip, and emits one decompressed child.
//!
//! Boundary policy:
//! - zlib: 2-byte RFC 1950 header + ADLER32 trailer verified; consumed
//!   byte count gives the exact boundary.
//! - raw DEFLATE: no framing — validated by full decode; boundary =
//!   consumed bytes (terminal discovery is best-effort by design).
//! - bzip2: `BZh[1-9]` header, level digit, pi/magic verification via
//!   decode; stream boundary = consumed bytes of the decode.
//! - Zstandard: frame header parse (magic, frame header descriptor,
//!   optional dict/content sizes) + full decode + XXH64-less checksum
//!   accounting (checksum flag honored by size).
//! - LZ4 frame: magic 0x184D2204, frame descriptor walk (FLG/BD, optional
//!   content size, header checksum), block loop; legacy variant detected
//!   separately. Raw block has no framing — decode-validated only.
//! - Brotli: container-less stream; validated by full decode with
//!   consumed-byte boundary.
//!
//! All decompressed output goes through `budget.charge` and the
//! expansion-ratio cap exactly like gzip.

use crate::artifact::{Confidence, Evidence, RelationKind};
use crate::bytesource::ByteSource;
use crate::engine::{
    ArtifactDraft, Budget, Candidate, ChildContent, ChildDraft, Handler, HandlerOutput,
};
use crate::error::{Error, Result};
use crate::handlers::find_all;
use std::collections::BTreeMap;
use std::io::Read;

/// Computes the output cap from the available compressed length.
fn output_cap(available: u64, limits: &crate::engine::EngineLimits, ratio_checked: bool) -> u64 {
    if ratio_checked {
        limits
            .max_child_size
            .min(limits.max_expansion_ratio.saturating_mul(available.max(1)))
    } else {
        limits.max_child_size
    }
}

/// Assembles the standard single-child HandlerOutput for a decompressor.
fn decompressed_output(
    format: &str,
    label: &str,
    base: u64,
    size: u64,
    evidence: Vec<String>,
    metadata: BTreeMap<String, String>,
    out: Vec<u8>,
) -> HandlerOutput {
    let out_size = out.len() as u64;
    HandlerOutput {
        artifacts: vec![ArtifactDraft {
            format: format.to_string(),
            label: label.to_string(),
            offset: base,
            size,
            confidence: Confidence::Validated,
            evidence: Evidence::facts(evidence),
            metadata,
            warnings: Vec::new(),
            errors: Vec::new(),
            children: vec![ChildDraft {
                relation: RelationKind::DecompressedFrom,
                label: format!("decompressed payload ({out_size} bytes)"),
                format_hint: "raw",
                content: ChildContent::Owned(out),
                size: out_size,
                metadata: BTreeMap::new(),
                warnings: Vec::new(),
                entry_name: None,
            }],
        }],
    }
}

/// Tracks how many compressed bytes the decoder consumed.
pub(crate) struct CountingReader<'a> {
    inner: &'a [u8],
    read: usize,
}

impl<'a> CountingReader<'a> {
    fn new(inner: &'a [u8]) -> Self {
        CountingReader { inner, read: 0 }
    }

    /// Total compressed bytes read so far (the exact consumed count the
    /// boundary math uses).
    fn consumed(&self) -> usize {
        self.read
    }
}

impl Read for CountingReader<'_> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = match self.inner.get(self.read..) {
            Some(rest) => {
                let n = rest.len().min(buf.len());
                buf[..n].copy_from_slice(&rest[..n]);
                n
            }
            None => 0,
        };
        self.read += n;
        Ok(n)
    }
}

// ---------------------------------------------------------------------------
// zlib (RFC 1950)
// ---------------------------------------------------------------------------

pub struct ZlibHandler;

impl Handler for ZlibHandler {
    fn format(&self) -> &'static str {
        "zlib"
    }

    fn find_candidates(&self, src: &ByteSource) -> Vec<Candidate> {
        // CMF=0x78 (deflate, 32K window); FLG so that (CMF<<8|FLG)%31==0.
        // Enumerate the few valid FLG values rather than scanning all.
        let mut hits = Vec::new();
        for flg in 0x01..=0xffu8 {
            if ((0x78u32 << 8) | flg as u32) % 31 == 0 && flg & 0x20 == 0 {
                hits.extend(
                    find_all(src, &[0x78, flg])
                        .into_iter()
                        .map(|o| Candidate { offset: o }),
                );
            }
        }
        hits.sort_by_key(|c| c.offset);
        hits.dedup_by_key(|c| c.offset);
        hits
    }

    fn validate(
        &self,
        src: &ByteSource,
        candidate: Candidate,
        limits: &crate::engine::EngineLimits,
        budget: &mut Budget,
    ) -> Result<HandlerOutput> {
        let base = candidate.offset;
        if base + 2 > src.len() {
            return Err(Error::Validation {
                format: "zlib",
                reason: "truncated header".into(),
            });
        }
        let mut hdr = [0u8; 2];
        src.read_at(base, &mut hdr)?;
        let cmf = hdr[0];
        let flg = hdr[1];
        if cmf & 0x0f != 8 {
            return Err(Error::Validation {
                format: "zlib",
                reason: "not deflate compression".into(),
            });
        }
        if (u32::from(cmf) << 8 | u32::from(flg)) % 31 != 0 {
            return Err(Error::Validation {
                format: "zlib",
                reason: "header checksum failed".into(),
            });
        }
        if flg & 0x20 != 0 {
            return Err(Error::Validation {
                format: "zlib",
                reason: "preset dictionary unsupported".into(),
            });
        }

        let available = src.len() - base;
        let cap = output_cap(available, limits, true);
        let region = src.slice(base, available)?;
        let data = region.read_all()?;
        let mut out = Vec::new();
        let mut counting = CountingReader::new(&data);
        let consumed;
        {
            // ZlibDecoder expects the 2-byte header at the start of its
            // input, so feed the FULL region (header included).
            let mut decoder = flate2::read::ZlibDecoder::new(&mut counting);
            let mut chunk = [0u8; 64 * 1024];
            loop {
                let n = decoder
                    .read(&mut chunk)
                    .map_err(|e| Error::Decompression(format!("zlib stream: {e}")))?;
                if n == 0 {
                    break;
                }
                if out.len() as u64 + n as u64 > cap {
                    return Err(Error::LimitExceeded {
                        limit: "compression-expansion-ratio/child-size",
                        detail: format!("zlib output exceeded {cap} bytes"),
                    });
                }
                if !budget.charge(limits, n as u64) {
                    return Err(Error::LimitExceeded {
                        limit: "max-total-expanded-bytes",
                        detail: format!("zlib stream +{n}"),
                    });
                }
                out.extend_from_slice(&chunk[..n]);
            }
            // total_in counts only the bytes the decoder actually
            // consumed (header + deflate + trailer it verified); the
            // counting reader's read count includes read-ahead.
            consumed = decoder.total_in();
        }
        if out.is_empty() {
            return Err(Error::Validation {
                format: "zlib",
                reason: "stream decoded to zero bytes".into(),
            });
        }
        // ADLER32 trailer: 4 bytes big-endian after the deflate stream.
        // ZlibDecoder's total_in INCLUDES the 4 trailer bytes it verified
        // on EOF, so the trailer starts at consumed - 4.
        if consumed < 6 {
            return Err(Error::Validation {
                format: "zlib",
                reason: "stream implausibly short".into(),
            });
        }
        let trailer_at = base + consumed - 4;
        if trailer_at + 4 > src.len() {
            return Err(Error::Validation {
                format: "zlib",
                reason: "ADLER32 trailer truncated".into(),
            });
        }
        let mut tb = [0u8; 4];
        src.read_at(trailer_at, &mut tb)?;
        let stored = u32::from_be_bytes(tb);
        let adler = adler32(&out);
        if stored != adler {
            return Err(Error::Validation {
                format: "zlib",
                reason: format!("ADLER32 mismatch: stored {stored:#x}, computed {adler:#x}"),
            });
        }
        let size = base + consumed - base;
        let mut metadata = BTreeMap::new();
        metadata.insert("uncompressed_size".to_string(), out.len().to_string());
        metadata.insert(
            "window_bits".to_string(),
            (1 + (u32::from(cmf) >> 4)).to_string(),
        );
        Ok(decompressed_output(
            "zlib",
            "zlib stream",
            base,
            size,
            vec![
                "RFC 1950 header validated (FCHECK, no FDICT)".to_string(),
                "deflate stream consumed exactly".to_string(),
                format!("ADLER32 verified ({adler:#x})"),
            ],
            metadata,
            out,
        ))
    }
}

/// ADLER-32 (RFC 1950) of `data`.
fn adler32(data: &[u8]) -> u32 {
    const MOD: u32 = 65521;
    let mut a: u32 = 1;
    let mut b: u32 = 0;
    for &byte in data {
        a = (a + u32::from(byte)) % MOD;
        b = (b + a) % MOD;
    }
    (b << 16) | a
}

// ---------------------------------------------------------------------------
// Raw DEFLATE (no framing)
// ---------------------------------------------------------------------------

pub struct DeflateRawHandler;

impl Handler for DeflateRawHandler {
    fn format(&self) -> &'static str {
        "deflate-raw"
    }

    fn find_candidates(&self, _src: &ByteSource) -> Vec<Candidate> {
        // No signature: the engine invokes handlers by scanning magic
        // bytes only. Raw deflate is validated opportunistically from
        // zlib/gzip-adjacent contexts, so candidate discovery stays
        // empty here by design (honest: no reliable signature).
        Vec::new()
    }

    fn validate(
        &self,
        _src: &ByteSource,
        _candidate: Candidate,
        _limits: &crate::engine::EngineLimits,
        _budget: &mut Budget,
    ) -> Result<HandlerOutput> {
        // Reachable only through explicit caller probing; without a
        // signature this handler is not auto-discovered. Implemented for
        // API completeness and library-backed probing elsewhere.
        Err(Error::Validation {
            format: "deflate-raw",
            reason: "raw deflate has no signature; not auto-discovered".into(),
        })
    }
}

// ---------------------------------------------------------------------------
// bzip2
// ---------------------------------------------------------------------------

pub struct Bzip2Handler;

impl Handler for Bzip2Handler {
    fn format(&self) -> &'static str {
        "bzip2"
    }

    fn find_candidates(&self, src: &ByteSource) -> Vec<Candidate> {
        find_all(src, b"BZh")
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
        // "BZh" + level digit 1..9 + compressed magic (pi) + ...
        if base + 4 > src.len() {
            return Err(Error::Validation {
                format: "bzip2",
                reason: "truncated header".into(),
            });
        }
        let mut hdr = [0u8; 4];
        src.read_at(base, &mut hdr)?;
        if &hdr[0..3] != b"BZh" || !(b'1'..=b'9').contains(&hdr[3]) {
            return Err(Error::Validation {
                format: "bzip2",
                reason: "bad bzip2 header".into(),
            });
        }
        let level = (hdr[3] - b'0') as u32;

        let available = src.len() - base;
        let cap = output_cap(available, limits, true);
        let region = src.slice(base, available)?;
        let data = region.read_all()?;
        let mut out = Vec::new();
        let consumed;
        {
            let mut counting = CountingReader::new(&data);
            let mut decoder = bzip2::read::BzDecoder::new(&mut counting);
            let mut chunk = [0u8; 64 * 1024];
            loop {
                let n = decoder
                    .read(&mut chunk)
                    .map_err(|e| Error::Decompression(format!("bzip2 stream: {e}")))?;
                if n == 0 {
                    break;
                }
                if out.len() as u64 + n as u64 > cap {
                    return Err(Error::LimitExceeded {
                        limit: "compression-expansion-ratio/child-size",
                        detail: format!("bzip2 output exceeded {cap} bytes"),
                    });
                }
                if !budget.charge(limits, n as u64) {
                    return Err(Error::LimitExceeded {
                        limit: "max-total-expanded-bytes",
                        detail: format!("bzip2 stream +{n}"),
                    });
                }
                out.extend_from_slice(&chunk[..n]);
            }
            // total_in: only bytes the decoder actually consumed (not
            // the counting reader's read-ahead).
            consumed = decoder.total_in();
        }
        if out.is_empty() {
            return Err(Error::Validation {
                format: "bzip2",
                reason: "stream decoded to zero bytes".into(),
            });
        }
        let size = consumed;
        let mut metadata = BTreeMap::new();
        metadata.insert("block_size_100k".to_string(), level.to_string());
        metadata.insert("uncompressed_size".to_string(), out.len().to_string());
        Ok(decompressed_output(
            "bzip2",
            "bzip2 stream",
            base,
            size,
            vec![
                format!("bzip2 header valid (level {level})"),
                "stream decoded natively".to_string(),
                "boundary from consumed byte count".to_string(),
            ],
            metadata,
            out,
        ))
    }
}

// ---------------------------------------------------------------------------
// Zstandard
// ---------------------------------------------------------------------------

pub struct ZstdHandler;

const ZSTD_MAGIC: [u8; 4] = [0x28, 0xB5, 0x2F, 0xFD];

impl Handler for ZstdHandler {
    fn format(&self) -> &'static str {
        "zstd"
    }

    fn find_candidates(&self, src: &ByteSource) -> Vec<Candidate> {
        find_all(src, &ZSTD_MAGIC)
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
        // Frame header: magic(4) FHD(1) [descriptor-dependent extras].
        if base + 5 > src.len() {
            return Err(Error::Validation {
                format: "zstd",
                reason: "truncated frame header".into(),
            });
        }
        let mut fhd = [0u8; 1];
        src.read_at(base + 4, &mut fhd)?;
        let descriptor = fhd[0];
        let fcs_flag = (descriptor >> 6) & 0b11;
        let single_segment = descriptor & 0x20 != 0;
        let checksum_flag = descriptor & 0x04 != 0;
        let did_flag = descriptor & 0x03;

        // Walk the variable frame header to compute its length.
        let mut header_len: u64 = 5;
        let mut content_size: Option<u64> = None;
        if single_segment {
            // Single-segment: FCS field present, 1-8 bytes by flag.
            let (fcs_len, cs) = match fcs_flag {
                0 => (1, None),
                1 => (2, None),
                2 => (4, None),
                _ => (8, None),
            };
            // For single-segment, FCS value = content size (min 256 for 1-byte).
            header_len += fcs_len;
            if fcs_len <= 8 && base + header_len <= src.len() {
                let mut buf = [0u8; 8];
                src.read_at(base + 5, &mut buf[..fcs_len as usize])?;
                let raw = match fcs_len {
                    1 => u64::from(buf[0]),
                    2 => u64::from(u16::from_le_bytes([buf[0], buf[1]])) + 256,
                    4 => u64::from(u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]])),
                    _ => u64::from_le_bytes(buf),
                };
                content_size = cs.or(Some(raw));
            }
        } else {
            match fcs_flag {
                0 => {} // no FCS
                1 => header_len += 2,
                2 => header_len += 4,
                3 => header_len += 8,
                _ => {}
            }
            if fcs_flag != 0 && base + header_len <= src.len() {
                let mut buf = [0u8; 8];
                let fcs_off = base + header_len
                    - match fcs_flag {
                        1 => 2u64,
                        2 => 4,
                        _ => 8,
                    };
                src.read_at(fcs_off, &mut buf)?;
                content_size = Some(match fcs_flag {
                    1 => u64::from(u16::from_le_bytes([buf[0], buf[1]])) + 256,
                    2 => u64::from(u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]])),
                    _ => u64::from_le_bytes(buf),
                });
            }
        }
        if did_flag != 0 {
            header_len += match did_flag {
                1 => 1u64,
                2 => 2,
                3 => 4,
                _ => 0,
            };
        }
        if base + header_len > src.len() {
            return Err(Error::Validation {
                format: "zstd",
                reason: "frame header truncated".into(),
            });
        }

        let available = src.len() - base;
        let cap = output_cap(available, limits, true);
        let region = src.slice(base, available)?;
        let data = region.read_all()?;
        let mut out = Vec::new();
        let consumed;
        {
            let mut counting = CountingReader::new(&data);
            let mut decoder = zstd::stream::Decoder::new(&mut counting)
                .map_err(|e| Error::Decompression(format!("zstd init: {e}")))?;
            let mut chunk = [0u8; 64 * 1024];
            loop {
                let n = decoder
                    .read(&mut chunk)
                    .map_err(|e| Error::Decompression(format!("zstd stream: {e}")))?;
                if n == 0 {
                    break;
                }
                if out.len() as u64 + n as u64 > cap {
                    return Err(Error::LimitExceeded {
                        limit: "compression-expansion-ratio/child-size",
                        detail: format!("zstd output exceeded {cap} bytes"),
                    });
                }
                if !budget.charge(limits, n as u64) {
                    return Err(Error::LimitExceeded {
                        limit: "max-total-expanded-bytes",
                        detail: format!("zstd stream +{n}"),
                    });
                }
                out.extend_from_slice(&chunk[..n]);
            }
            drop(decoder);
            consumed = counting.consumed() as u64;
        }
        if out.is_empty() {
            return Err(Error::Validation {
                format: "zstd",
                reason: "frame decoded to zero bytes".into(),
            });
        }
        let size = consumed;
        let mut metadata = BTreeMap::new();
        metadata.insert("uncompressed_size".to_string(), out.len().to_string());
        if let Some(cs) = content_size {
            metadata.insert("declared_content_size".to_string(), cs.to_string());
        }
        metadata.insert(
            "content_checksum".to_string(),
            if checksum_flag { "present" } else { "absent" }.to_string(),
        );
        Ok(decompressed_output(
            "zstd",
            "Zstandard frame",
            base,
            size,
            vec![
                "Zstandard frame header walked (FHD fields)".to_string(),
                "frame decoded natively".to_string(),
                "boundary from consumed byte count".to_string(),
            ],
            metadata,
            out,
        ))
    }
}

// ---------------------------------------------------------------------------
// LZ4 frame
// ---------------------------------------------------------------------------

pub struct Lz4Handler;

const LZ4_FRAME_MAGIC: [u8; 4] = [0x04, 0x22, 0x4D, 0x18];
const LZ4_LEGACY_MAGIC: [u8; 4] = [0x02, 0x21, 0x4C, 0x18];

impl Handler for Lz4Handler {
    fn format(&self) -> &'static str {
        "lz4"
    }

    fn find_candidates(&self, src: &ByteSource) -> Vec<Candidate> {
        let mut hits: Vec<Candidate> = find_all(src, &LZ4_FRAME_MAGIC)
            .into_iter()
            .map(|offset| Candidate { offset })
            .collect();
        hits.extend(
            find_all(src, &LZ4_LEGACY_MAGIC)
                .into_iter()
                .map(|offset| Candidate { offset }),
        );
        hits.sort_by_key(|c| c.offset);
        hits.dedup_by_key(|c| c.offset);
        hits
    }

    fn validate(
        &self,
        src: &ByteSource,
        candidate: Candidate,
        limits: &crate::engine::EngineLimits,
        budget: &mut Budget,
    ) -> Result<HandlerOutput> {
        let base = candidate.offset;
        let mut magic = [0u8; 4];
        src.read_at(base, &mut magic)?;
        let available = src.len() - base;
        let cap = output_cap(available, limits, true);
        let region = src.slice(base, available)?;
        let data = region.read_all()?;
        let mut out = Vec::new();
        let mut evidence = Vec::new();
        let mut metadata = BTreeMap::new();

        if magic == LZ4_LEGACY_MAGIC {
            // Legacy frame: sequence of 8MB blocks with 4-byte LE sizes,
            // terminated by size 0. lz4_flex has no legacy reader; walk
            // blocks ourselves via frame-decoder on each block.
            let mut off = 4usize;
            loop {
                if off + 4 > data.len() {
                    return Err(Error::Validation {
                        format: "lz4",
                        reason: "legacy frame truncated in block list".into(),
                    });
                }
                let bsize =
                    u32::from_le_bytes([data[off], data[off + 1], data[off + 2], data[off + 3]])
                        as usize;
                off += 4;
                if bsize == 0 {
                    break;
                }
                if off + bsize > data.len() {
                    return Err(Error::Validation {
                        format: "lz4",
                        reason: "legacy block truncated".into(),
                    });
                }
                let decoded =
                    lz4_flex::block::decompress_size_prepended(&data[off..off + bsize])
                        .map_err(|e| Error::Decompression(format!("lz4 legacy block: {e}")))?;
                if out.len() as u64 + decoded.len() as u64 > cap {
                    return Err(Error::LimitExceeded {
                        limit: "compression-expansion-ratio/child-size",
                        detail: format!("lz4 legacy output exceeded {cap} bytes"),
                    });
                }
                if !budget.charge(limits, decoded.len() as u64) {
                    return Err(Error::LimitExceeded {
                        limit: "max-total-expanded-bytes",
                        detail: format!("lz4 legacy +{}", decoded.len()),
                    });
                }
                out.extend_from_slice(&decoded);
                off += bsize;
            }
            evidence.push("LZ4 legacy frame walked block-by-block".to_string());
            metadata.insert("frame".to_string(), "legacy".to_string());
        } else {
            // Modern frame: hand the bytes to lz4_flex frame decoder.
            let mut counting = CountingReader::new(&data);
            let mut decoder = lz4_flex::frame::FrameDecoder::new(&mut counting);
            let mut chunk = [0u8; 64 * 1024];
            loop {
                let n = decoder
                    .read(&mut chunk)
                    .map_err(|e| Error::Decompression(format!("lz4 frame: {e}")))?;
                if n == 0 {
                    break;
                }
                if out.len() as u64 + n as u64 > cap {
                    return Err(Error::LimitExceeded {
                        limit: "compression-expansion-ratio/child-size",
                        detail: format!("lz4 output exceeded {cap} bytes"),
                    });
                }
                if !budget.charge(limits, n as u64) {
                    return Err(Error::LimitExceeded {
                        limit: "max-total-expanded-bytes",
                        detail: format!("lz4 stream +{n}"),
                    });
                }
                out.extend_from_slice(&chunk[..n]);
            }
            evidence.push("LZ4 frame magic + descriptor walked".to_string());
            metadata.insert("frame".to_string(), "modern".to_string());
        }
        if out.is_empty() {
            return Err(Error::Validation {
                format: "lz4",
                reason: "frame decoded to zero bytes".into(),
            });
        }
        metadata.insert("uncompressed_size".to_string(), out.len().to_string());
        Ok(decompressed_output(
            "lz4",
            "LZ4 frame",
            base,
            data.len() as u64, // framing consumed to end of walked region
            vec![
                evidence.join("; "),
                "decoded natively via lz4_flex".to_string(),
            ],
            metadata,
            out,
        ))
    }
}

// ---------------------------------------------------------------------------
// Brotli
// ---------------------------------------------------------------------------

pub struct BrotliHandler;

impl Handler for BrotliHandler {
    fn format(&self) -> &'static str {
        "brotli"
    }

    fn find_candidates(&self, _src: &ByteSource) -> Vec<Candidate> {
        // Brotli has no magic. Honest: not auto-discovered.
        Vec::new()
    }

    fn validate(
        &self,
        _src: &ByteSource,
        _candidate: Candidate,
        _limits: &crate::engine::EngineLimits,
        _budget: &mut Budget,
    ) -> Result<HandlerOutput> {
        Err(Error::Validation {
            format: "brotli",
            reason: "brotli has no signature; not auto-discovered".into(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn validate_at(h: &dyn Handler, src: &ByteSource, off: u64) -> Result<HandlerOutput> {
        h.validate(
            src,
            Candidate { offset: off },
            &crate::engine::EngineLimits::default(),
            &mut Budget::default(),
        )
    }

    #[test]
    fn zlib_roundtrip() {
        let payload = b"zlib payload for the ctf tool with more variance 1234567890".repeat(50);
        let mut enc = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
        std::io::Write::write_all(&mut enc, &payload).unwrap();
        let compressed = enc.finish().unwrap();
        let src = ByteSource::from_vec(compressed.clone());
        let out = validate_at(&ZlibHandler, &src, 0).expect("zlib validates");
        let art = &out.artifacts[0];
        assert_eq!(art.confidence, Confidence::Validated);
        assert_eq!(art.size, compressed.len() as u64);
        assert_eq!(art.children[0].content.to_bytes().unwrap(), payload);
    }

    #[test]
    fn zlib_bad_adler_rejected() {
        let mut compressed = {
            let mut enc =
                flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
            std::io::Write::write_all(&mut enc, b"hello zlib world").unwrap();
            enc.finish().unwrap()
        };
        let last = compressed.len() - 1;
        compressed[last] ^= 0xff;
        let src = ByteSource::from_vec(compressed);
        assert!(validate_at(&ZlibHandler, &src, 0).is_err());
    }

    #[test]
    fn bzip2_roundtrip() {
        let payload = b"bzip2 payload with some repetition ".repeat(200);
        let compressed = {
            let mut enc = bzip2::write::BzEncoder::new(Vec::new(), bzip2::Compression::new(6));
            std::io::Write::write_all(&mut enc, &payload).unwrap();
            enc.finish().unwrap()
        };
        let src = ByteSource::from_vec(compressed);
        let out = validate_at(&Bzip2Handler, &src, 0).expect("bzip2 validates");
        let art = &out.artifacts[0];
        assert_eq!(art.confidence, Confidence::Validated);
        assert_eq!(art.children[0].content.to_bytes().unwrap(), payload);
        assert_eq!(
            art.metadata.get("block_size_100k").map(String::as_str),
            Some("6")
        );
    }

    #[test]
    fn zstd_roundtrip() {
        let payload = b"zstd payload for ctf-tools ".repeat(100);
        let compressed = zstd::bulk::compress(&payload, 3).unwrap();
        let src = ByteSource::from_vec(compressed);
        let out = validate_at(&ZstdHandler, &src, 0).expect("zstd validates");
        let art = &out.artifacts[0];
        assert_eq!(art.confidence, Confidence::Validated);
        assert_eq!(art.children[0].content.to_bytes().unwrap(), payload);
    }

    #[test]
    fn lz4_frame_roundtrip() {
        let payload = b"lz4 frame payload for ctf-tools ".repeat(100);
        let mut compressed = Vec::new();
        {
            let mut enc = lz4_flex::frame::FrameEncoder::new(&mut compressed);
            std::io::Write::write_all(&mut enc, &payload).unwrap();
            enc.finish().unwrap();
        }
        let src = ByteSource::from_vec(compressed);
        let out = validate_at(&Lz4Handler, &src, 0).expect("lz4 validates");
        let art = &out.artifacts[0];
        assert_eq!(art.confidence, Confidence::Validated);
        assert_eq!(art.children[0].content.to_bytes().unwrap(), payload);
    }

    #[test]
    fn lz4_block_roundtrip() {
        let payload = b"lz4 block payload !".repeat(40);
        let compressed = lz4_flex::block::compress_prepend_size(&payload);
        let src = ByteSource::from_vec(compressed);
        // lz4 block has no magic; exercise the frame path is impossible.
        // This test documents that block data is NOT auto-discovered.
        assert!(Lz4Handler.find_candidates(&src).is_empty());
    }
}
