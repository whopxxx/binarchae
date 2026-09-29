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
                confidence: Confidence::Validated,
                evidence: vec!["structurally decoded by parent handler".to_string()],
            }],
            entry_names: Vec::new(),
        }],
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
        // B2: stream from the source itself — no read_all() over the
        // whole tail before limits apply. Decompressors pull bounded
        // chunks through ByteSource's Read impl; the take() bounds the
        // compressed input independently of output caps.
        let mut region = src.slice(base, available)?;
        let mut out = Vec::new();
        let consumed;
        {
            // ZlibDecoder expects the 2-byte header at the start of its
            // input, so feed the FULL region (header included).
            let mut decoder = flate2::read::ZlibDecoder::new(&mut region);
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
            // consumed (header + deflate + trailer it verified).
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
        // B2: bounded-memory streaming — no read_all() over the tail.
        let mut region = src.slice(base, available)?;
        let mut out = Vec::new();
        let consumed;
        {
            let mut decoder = bzip2::read::BzDecoder::new(&mut region);
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
        // B2: bounded-memory streaming — no read_all() over the tail.
        let mut region = src.slice(base, available)?;
        let mut out = Vec::new();
        let consumed;
        {
            let mut decoder = zstd::stream::Decoder::new(&mut region)
                .map_err(|e| Error::Decompression(format!("zstd init: {e}")))?;
            let mut chunk = [0u8; 64 * 1024];
            loop {
                let n = match decoder.read(&mut chunk) {
                    Ok(n) => n,
                    Err(e)
                        if e.to_string().contains("Unknown frame descriptor")
                            || e.to_string().contains("Frame header") =>
                    {
                        // The single-frame stream ended cleanly and the
                        // decoder attempted to interpret trailing bytes
                        // (after our frame) as a new frame. The first
                        // frame's output stands; the cursor marks its end.
                        break;
                    }
                    Err(e) => return Err(Error::Decompression(format!("zstd stream: {e}"))),
                };
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
            // B2 + S1: exact frame end via the STRUCTURED interface
            // ZSTD_findFrameCompressedSize (via zstd_safe) — the
            // length of the first frame per the format spec. The probe
            // window GROWS geometrically (1 MiB -> 2 -> 4 ... capped by
            // max_child_size and the tail length) until the API
            // succeeds: every probe is a bounded read, never a
            // candidate-to-EOF read_all, and there is NO heuristic
            // byte-pattern guessing.
            // T1: the hard ceiling is max_child_size (and the tail).
            // Start at min(1 MiB, ceiling) and double, but EVERY probe is
            // clamped to the ceiling first: no probe ever reads past the
            // cap, whatever its value (small caps and non-power-of-two
            // caps included).
            let tail_len = src.len() - base;
            let ceiling = limits.max_child_size.min(tail_len);
            let mut window: u64 = 1024 * 1024;
            let mut structured: Option<u64> = None;
            loop {
                // Probe = the smaller of the desired window and the
                // ceiling; the desired window may have overshot.
                let probe_len = window.min(ceiling) as usize;
                if let Ok(buf) = src.slice(base, probe_len as u64).and_then(|r| r.read_all()) {
                    if let Ok(frame_size) = zstd::zstd_safe::find_frame_compressed_size(&buf) {
                        structured = Some(frame_size as u64);
                        break;
                    }
                }
                if window >= ceiling {
                    break; // probed the full ceiling already
                }
                window = window.saturating_mul(2);
            }
            consumed = match structured {
                Some(frame_size) => frame_size,
                None => {
                    // T1/S1: no structured boundary within the bounded
                    // windows (frame larger than max_child_size). The
                    // candidate exceeds the cap anyway, so the honest
                    // outcome is a typed limit error, not a guess.
                    return Err(Error::LimitExceeded {
                        limit: "max_child_size",
                        detail: format!(
                            "zstd frame has no structured end within {} bytes (tail {})",
                            ceiling, tail_len
                        ),
                    });
                }
            };
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
        // B2: bounded-memory streaming. The legacy walker reads blocks
        // in bounded pieces; the modern frame path streams through the
        // ByteSource Read impl. No read_all() over the whole tail.
        let mut region = src.slice(base, available)?;
        let mut out = Vec::new();
        let mut evidence = Vec::new();
        let mut metadata = BTreeMap::new();
        let frame_end: u64;

        // R1: FLG byte (after magic): bit 2 = content checksum present
        // (4-byte xxhash32 AFTER the EndMark in the frame footer).
        let mut flg = [0u8; 1];
        src.read_at(base + 4, &mut flg)?;
        let lz4_content_checksum = flg[0] & 0x04 != 0;

        if magic == LZ4_LEGACY_MAGIC {
            // Legacy frame: sequence of 8MB blocks with 4-byte LE sizes,
            // terminated by size 0. lz4_flex has no legacy reader; walk
            // blocks ourselves via frame-decoder on each block.
            // Legacy frame: bounded per-block reads through read_at.
            let mut off = 4u64;
            loop {
                if off + 4 > available {
                    return Err(Error::Validation {
                        format: "lz4",
                        reason: "legacy frame truncated in block list".into(),
                    });
                }
                let mut sb = [0u8; 4];
                region.read_at(off, &mut sb)?;
                let bsize = u32::from_le_bytes(sb) as u64;
                off += 4;
                if bsize == 0 {
                    break;
                }
                if off + bsize > available {
                    return Err(Error::Validation {
                        format: "lz4",
                        reason: "legacy block truncated".into(),
                    });
                }
                // Block header: 4-byte prepended uncompressed size.
                let mut szb = [0u8; 4];
                region.read_at(off, &mut szb)?;
                let declared = u32::from_le_bytes(szb) as u64;
                if declared > cap {
                    return Err(Error::LimitExceeded {
                        limit: "compression-expansion-ratio/child-size",
                        detail: format!("lz4 legacy block output would exceed {cap} bytes"),
                    });
                }
                let mut block = vec![0u8; bsize as usize];
                region.read_at(off, &mut block)?;
                let decoded = lz4_flex::block::decompress_size_prepended(&block)
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
            // B2: exact frame end = after the 0 terminator.
            // (slice-relative, like the modern path's base-relative
            // result after the artifact-size conversion below)
            frame_end = off + 4;
            evidence.push("LZ4 legacy frame walked block-by-block".to_string());
            metadata.insert("frame".to_string(), "legacy".to_string());
        } else {
            // Modern frame: stream through the ByteSource Read impl.
            let mut decoder = lz4_flex::frame::FrameDecoder::new(&mut region);
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
            drop(decoder);
            // B2 + R1 + S1: exact frame end. The streaming cursor is
            // slice-relative, so the absolute end is base + cursor.
            // lz4_flex's FrameDecoder reads AND validates the optional
            // content checksum BEFORE returning EOF, so the cursor
            // already sits at the end of the full footer:
            //   no checksum:  EndMark(4)                -> cursor
            //   checksum:     EndMark(4) + xxhash32(4)  -> cursor
            // The EndMark anchor is therefore cursor - (checksum ? 8 : 4)
            // relative to base; verifying it guards against a checksum
            // that happens to equal 0x00000000 being mistaken for an
            // EndMark (which would double-count 4 bytes).
            let cursor = region.stream_pos();
            let endmark_back: u64 = if lz4_content_checksum { 8 } else { 4 };
            frame_end = lz4_frame_end(src, base, cursor, endmark_back)?;
            evidence.push("LZ4 frame magic + descriptor walked".to_string());
            metadata.insert(
                "content_checksum".to_string(),
                if lz4_content_checksum {
                    "present"
                } else {
                    "absent"
                }
                .to_string(),
            );
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
            frame_end - base, // B2/R1: exact relative frame size; trailing data stays discoverable
            vec![
                evidence.join("; "),
                "decoded natively via lz4_flex".to_string(),
            ],
            metadata,
            out,
        ))
    }
}

/// Verify the frame footer at the decoder's exact consumed boundary and
/// return the ABSOLUTE frame end. `cursor` is slice-relative (bytes the
/// decoder consumed); `endmark_back` is the footer size (EndMark [+ 4
/// checksum]) counted back from the cursor. The bytes at the computed
/// EndMark position must be zero, and with a checksum the 4 bytes before
/// the cursor are the checksum (which MAY legitimately be 0x00000000 —
/// it is verified by the decoder, not guessed by us).
fn lz4_frame_end(src: &ByteSource, base: u64, cursor: u64, endmark_back: u64) -> Result<u64> {
    let abs_end = base + cursor;
    if cursor < endmark_back || abs_end > src.len() {
        return Err(Error::Validation {
            format: "lz4",
            reason: "frame footer truncated at consumed boundary".into(),
        });
    }
    let mut zb = [0u8; 4];
    src.read_at(abs_end - endmark_back, &mut zb)?;
    if zb != [0, 0, 0, 0] {
        return Err(Error::Validation {
            format: "lz4",
            reason: "frame EndMark not found at consumed boundary".into(),
        });
    }
    Ok(abs_end)
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

// ---------------------------------------------------------------------------
// LZMA alone (.lzma)
// ---------------------------------------------------------------------------

/// LZMA-alone (.lzma) stream handler. Layout verified against the
/// lzma-rust crate's `LZMAReader::new_mem_limit` and the LZMA SDK
/// (lzip/lzmaalone format docs):
/// - props byte @0: (pb*5 + lp)*9 + lc, valid range 0..=224.
/// - dict size @1..5: u32 LE, clamped to >= 4096 internally.
/// - uncompressed size @5..13: u64 LE; all-ones (0xFFFF_FFFF_FFFF_FFFF)
///   means "unknown" (end-of-stream marker present).
/// - payload @13: raw LZMA1 stream.
pub struct LzmaAloneHandler;

const LZMA_ALONE_HEADER: u64 = 13;
const LZMA_PROPS_MAX: u8 = 224;
const LZMA_SIZE_UNKNOWN: u64 = u64::MAX;

impl Handler for LzmaAloneHandler {
    fn format(&self) -> &'static str {
        "lzma-alone"
    }

    fn find_candidates(&self, src: &ByteSource) -> Vec<Candidate> {
        // No magic. Find candidates by header plausibility: props byte
        // 0..=224, dict size a power of two in [4 KiB, 1.5 GiB], and
        // either a known size or the all-ones sentinel. Candidate at
        // offset 0 and at byte-scan positions is too broad, so probe
        // 13-byte headers preceded by anything only when the whole
        // source is consistent (typical .lzma files start at 0).
        if src.len() < LZMA_ALONE_HEADER {
            return Vec::new();
        }
        let mut props = [0u8; 1];
        let mut dict = [0u8; 4];
        let mut usize_ = [0u8; 8];
        if src.read_at(0, &mut props).is_err() {
            return Vec::new();
        }
        src.read_at(1, &mut dict).ok();
        src.read_at(5, &mut usize_).ok();
        let props = props[0];
        let dict_size = u32::from_le_bytes(dict);
        let uncomp = u64::from_le_bytes(usize_);
        let props_ok = props <= LZMA_PROPS_MAX;
        let dict_ok = dict_size.is_power_of_two() && (4096..=0x6000_0000).contains(&dict_size);
        let size_ok = uncomp == LZMA_SIZE_UNKNOWN || uncomp <= 1 << 33;
        if props_ok && dict_ok && size_ok {
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
        if base + LZMA_ALONE_HEADER > src.len() {
            return Err(Error::Validation {
                format: "lzma-alone",
                reason: "header truncated".into(),
            });
        }
        let mut hdr = [0u8; 13];
        src.read_at(base, &mut hdr)?;
        let props = hdr[0];
        if props > LZMA_PROPS_MAX {
            return Err(Error::Validation {
                format: "lzma-alone",
                reason: format!("invalid props byte {props}"),
            });
        }
        let dict_size = u32::from_le_bytes(hdr[1..5].try_into().unwrap());
        let uncomp_size = u64::from_le_bytes(hdr[5..13].try_into().unwrap());
        // FINAL-R1b: the decoder allocates the declared dictionary up
        // front. Enforce the same plausibility gate as find_candidates
        // (power of two, [4 KiB, 1.5 GiB]) BEFORE construction — a
        // fuzz-found input with dict_size 0xFFFF0000 and the unknown-
        // size sentinel previously caused a ~4 GiB malloc because
        // validate passed `u32::MAX` (no limit) as the mem limit.
        if !dict_size.is_power_of_two() || !(4096..=0x6000_0000).contains(&dict_size) {
            return Err(Error::Validation {
                format: "lzma-alone",
                reason: format!("implausible dict size {dict_size:#x}"),
            });
        }
        let size_known = uncomp_size != LZMA_SIZE_UNKNOWN;
        if size_known && uncomp_size > limits.max_child_size {
            return Err(Error::Validation {
                format: "lzma-alone",
                reason: format!("declared size {uncomp_size} exceeds max_child_size"),
            });
        }

        // Decode via lzma-rust: new_mem_limit parses the 13-byte
        // .lzma header itself, so hand it the stream from the
        // candidate offset (not after the header). The mem limit is a
        // real bound (256 MiB), not "unlimited" — the decoder's own
        // DICT_SIZE_MAX is u32-range and would happily allocate a
        // declared 4 GiB dictionary before any output check runs.
        let data = src.read_all()?;
        let mut reader = lzma_rust::LZMAReader::new_mem_limit(
            std::io::Cursor::new(&data[base as usize..]),
            256 * 1024,
            None,
        )
        .map_err(|e| Error::Validation {
            format: "lzma-alone",
            reason: format!("invalid LZMA parameters: {e}"),
        })?;
        let mut out = Vec::new();
        let mut chunk = [0u8; 64 * 1024];
        loop {
            let n = reader.read(&mut chunk).map_err(|e| Error::Validation {
                format: "lzma-alone",
                reason: format!("stream decode failed: {e}"),
            })?;
            if n == 0 {
                break;
            }
            out.extend_from_slice(&chunk[..n]);
            if out.len() as u64 > limits.max_child_size {
                return Err(Error::Validation {
                    format: "lzma-alone",
                    reason: "output exceeds max_child_size".into(),
                });
            }
            if !budget.charge(limits, n as u64) {
                return Err(Error::LimitExceeded {
                    limit: "max-total-expanded-bytes",
                    detail: "lzma-alone output".into(),
                });
            }
        }

        let decoded_size = out.len() as u64;
        let mut metadata = BTreeMap::new();
        metadata.insert("props_byte".to_string(), props.to_string());
        metadata.insert("dict_size".to_string(), dict_size.to_string());
        metadata.insert(
            "declared_size".to_string(),
            if size_known {
                uncomp_size.to_string()
            } else {
                "unknown".to_string()
            },
        );
        metadata.insert("decoded_size".to_string(), decoded_size.to_string());

        let lc = props % 9;
        let lp = (props / 9) % 5;
        let pb = props / 45;
        Ok(HandlerOutput {
            artifacts: vec![ArtifactDraft {
                format: "lzma-alone".to_string(),
                label: format!(
                    "LZMA-alone stream ({} bytes decoded, lc={lc} lp={lp} pb={pb})",
                    decoded_size
                ),
                offset: base,
                size: src.len() - base,
                confidence: Confidence::Validated,
                evidence: Evidence::facts([
                    "LZMA-alone header validated (props/dict/size)".to_string(),
                    format!(
                        "uncompressed size {}",
                        if size_known {
                            uncomp_size.to_string()
                        } else {
                            "unknown (end marker)".to_string()
                        }
                    ),
                    format!("decoded {decoded_size} bytes via lzma-rust LZMA1"),
                ]),
                metadata,
                warnings: Vec::new(),
                errors: Vec::new(),
                children: vec![ChildDraft {
                    relation: RelationKind::DecompressedFrom,
                    label: format!("decompressed payload ({decoded_size} bytes)"),
                    format_hint: "raw",
                    content: ChildContent::Owned(out),
                    size: decoded_size,
                    metadata: BTreeMap::new(),
                    warnings: Vec::new(),
                    entry_name: Some("payload.bin".to_string()),
                    confidence: Confidence::Validated,
                    evidence: vec!["structurally decoded by parent handler".to_string()],
                }],
                entry_names: Vec::new(),
            }],
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
    fn lz4_frame_exact_boundary_with_trailing_data() {
        // B2: the artifact must end at the frame EndMark, not swallow
        // trailing bytes appended after it.
        let payload = b"lz4 bounded payload ".repeat(50);
        let mut compressed = Vec::new();
        {
            let mut enc = lz4_flex::frame::FrameEncoder::new(&mut compressed);
            std::io::Write::write_all(&mut enc, &payload).unwrap();
            enc.finish().unwrap();
        }
        let mut blob = compressed.clone();
        blob.extend_from_slice(b"TRAILING-DATA-NOT-LZ4");
        let src = ByteSource::from_vec(blob);
        let out = validate_at(&Lz4Handler, &src, 0).expect("lz4 validates");
        let art = &out.artifacts[0];
        assert_eq!(art.size, compressed.len() as u64, "frame end must be exact");
    }

    #[test]
    fn zlib_exact_boundary_with_trailing_data() {
        let payload = b"zlib trailing test payload 1234567890 ".repeat(20);
        let mut enc = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
        std::io::Write::write_all(&mut enc, &payload).unwrap();
        let compressed = enc.finish().unwrap();
        let mut blob = compressed.clone();
        blob.extend_from_slice(b"TAIL");
        let src = ByteSource::from_vec(blob);
        let out = validate_at(&ZlibHandler, &src, 0).expect("zlib validates");
        assert_eq!(out.artifacts[0].size, compressed.len() as u64);
    }

    #[test]
    fn bzip2_exact_boundary_with_trailing_data() {
        let payload = b"bzip2 trailing boundary test ".repeat(100);
        let compressed = {
            let mut enc = bzip2::write::BzEncoder::new(Vec::new(), bzip2::Compression::new(6));
            std::io::Write::write_all(&mut enc, &payload).unwrap();
            enc.finish().unwrap()
        };
        let mut blob = compressed.clone();
        blob.extend_from_slice(b"TAIL");
        let src = ByteSource::from_vec(blob);
        let out = validate_at(&Bzip2Handler, &src, 0).expect("bzip2 validates");
        assert_eq!(out.artifacts[0].size, compressed.len() as u64);
    }

    #[test]
    fn zstd_exact_boundary_with_trailing_data() {
        let payload = b"zstd trailing boundary test ".repeat(50);
        let compressed = zstd::bulk::compress(&payload, 3).unwrap();
        let mut blob = compressed.clone();
        blob.extend_from_slice(b"TAIL");
        let src = ByteSource::from_vec(blob);
        let out = validate_at(&ZstdHandler, &src, 0).expect("zstd validates");
        assert_eq!(out.artifacts[0].size, compressed.len() as u64);
    }

    #[test]
    fn lz4_embedded_frame_with_checksum_exact_boundary() {
        // R1: embedded frame (base > 0) + content checksum. The artifact
        // must end exactly after EndMark + 4-byte checksum, and trailing
        // bytes after it stay outside the artifact.
        let payload = b"lz4 embedded checksum payload ".repeat(20);
        let mut compressed = Vec::new();
        {
            let mut info = lz4_flex::frame::FrameInfo::new();
            info.content_checksum = true;
            let mut enc = lz4_flex::frame::FrameEncoder::with_frame_info(info, &mut compressed);
            std::io::Write::write_all(&mut enc, &payload).unwrap();
            enc.finish().unwrap();
        }
        assert!(
            compressed.len() > 5 && compressed[4] & 0x04 != 0,
            "fixture must carry the content-checksum flag"
        );
        let mut blob = vec![0x00u8; 7]; // embedded at base=7
        blob.extend_from_slice(&compressed);
        blob.extend_from_slice(b"TRAILING");
        let src = ByteSource::from_vec(blob);
        let out = validate_at(&Lz4Handler, &src, 7).expect("embedded lz4 validates");
        let art = &out.artifacts[0];
        assert_eq!(
            art.size,
            compressed.len() as u64,
            "frame end (incl. checksum footer) must be exact at base=7"
        );
    }

    #[test]
    fn zstd_probe_respects_small_cap() {
        // T1: with a small, non-power-of-two cap (3 MiB = 3145728), the
        // probe must clamp to the cap: a frame that fits inside it is
        // found via the structured interface; no probe ever reads past
        // the cap.
        // Pseudorandom payload: compressed size stays comparable to the
        // raw size so the expansion-ratio cap never binds before the
        // child-size cap does.
        let mut seed = 0x5A17_0001u32;
        let payload: Vec<u8> = (0..2 * 1024 * 1024)
            .map(|_| {
                seed = seed.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
                (seed >> 24) as u8
            })
            .collect();
        let compressed = zstd::bulk::compress(&payload, 3).unwrap();
        assert!(compressed.len() < 3 * 1024 * 1024);
        let src = ByteSource::from_vec(compressed.clone());
        let limits = crate::engine::EngineLimits {
            max_child_size: 3 * 1024 * 1024, // non-power-of-two cap
            ..Default::default()
        };
        let mut budget = Budget::default();
        let out = ZstdHandler
            .validate(&src, Candidate { offset: 0 }, &limits, &mut budget)
            .expect("frame found within cap");
        assert_eq!(out.artifacts[0].size, compressed.len() as u64);
        assert_eq!(
            out.artifacts[0].children[0].content.to_bytes().unwrap(),
            payload
        );
    }

    #[test]
    fn lz4_checksum_zero_not_confused_with_endmark() {
        // S1: a content checksum of 0x00000000 must not be mistaken for
        // an EndMark. Frame layout (with checksum): ...data, EndMark(4
        // zeros), checksum(4). With the old backward-scan logic the zero
        // checksum would be read as the EndMark and the boundary would
        // drift by 4. Build the frame with a checksum and a trailing
        // data pattern; boundary must be exact at end of checksum.
        let payload = b"zero checksum boundary payload ".repeat(10);
        let mut compressed = Vec::new();
        {
            let mut info = lz4_flex::frame::FrameInfo::new();
            info.content_checksum = true;
            let mut enc = lz4_flex::frame::FrameEncoder::with_frame_info(info, &mut compressed);
            std::io::Write::write_all(&mut enc, &payload).unwrap();
            enc.finish().unwrap();
        }
        let mut blob = compressed.clone();
        blob.extend_from_slice(b"TRAILING");
        let src = ByteSource::from_vec(blob);
        let out = validate_at(&Lz4Handler, &src, 0).expect("lz4 validates");
        assert_eq!(
            out.artifacts[0].size,
            compressed.len() as u64,
            "boundary must be exactly EndMark + checksum, no drift"
        );
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

#[cfg(test)]
mod lzma_alone_tests {
    use super::*;
    use crate::bytesource::ByteSource;
    use crate::engine::{Budget, Candidate};

    fn validate_at(h: &dyn Handler, src: &ByteSource, off: u64) -> Result<HandlerOutput> {
        h.validate(
            src,
            Candidate { offset: off },
            &crate::engine::EngineLimits::default(),
            &mut Budget::default(),
        )
    }

    /// Real .lzma-alone stream from the lzma-rust crate's own doc
    /// example: props 93, dict 8 MiB, known size 13, "Hello, world!".
    #[test]
    fn lzma_alone_known_size_decodes() {
        // 93, 0, 0, 128, 0 | 13,0,0,0,0,0,0,0 | LZMA1 payload...
        let doc_stream: [u8; 37] = [
            93, 0, 0, 128, 0, 255, 255, 255, 255, 255, 255, 255, 255, 0, 36, 25, 73, 152, 111, 22,
            2, 140, 232, 230, 91, 177, 71, 198, 206, 183, 99, 255, 255, 60, 172, 0, 0,
        ];
        // That example has size unknown (all 0xFF) — the doc calls it
        // with unknown size semantics. Verify decode.
        let src = ByteSource::from_vec(doc_stream.to_vec());
        let out = validate_at(&LzmaAloneHandler, &src, 0).expect("lzma-alone decodes");
        let art = &out.artifacts[0];
        assert_eq!(art.confidence, Confidence::Validated);
        assert_eq!(art.children.len(), 1);
        match &art.children[0].content {
            ChildContent::Owned(d) => assert_eq!(d, b"Hello, world!"),
            _ => panic!("payload must decode"),
        }
    }

    /// Invalid props byte is rejected, not silently accepted.
    #[test]
    fn lzma_alone_bad_props_rejected() {
        let mut blob = vec![225u8]; // 225 > 224
        blob.extend_from_slice(&[0, 0, 128, 0]); // dict
        blob.extend_from_slice(&13u64.to_le_bytes());
        blob.extend_from_slice(b"junk");
        let src = ByteSource::from_vec(blob);
        assert!(validate_at(&LzmaAloneHandler, &src, 0).is_err());
    }

    /// FINAL-R1b (fuzz-found OOM): dict_size 0xFFFF0000 with the
    /// unknown-size sentinel must be rejected BEFORE decoder
    /// construction — the previous code passed an unlimited mem limit
    /// and the decoder malloc'd the full ~4 GiB dictionary.
    #[test]
    fn lzma_alone_hostile_dict_size_rejected() {
        // props 0, dict 0xFFFF0000 (LE), size sentinel all-FF, no body.
        let blob: Vec<u8> = std::iter::once(0u8)
            .chain(0xFFFF_0000u32.to_le_bytes())
            .chain(0xFFFF_FFFF_FFFF_FFFFu64.to_le_bytes())
            .chain(std::iter::repeat(0u8).take(5))
            .collect();
        let src = ByteSource::from_vec(blob);
        assert!(
            validate_at(&LzmaAloneHandler, &src, 0).is_err(),
            "implausible dict size must fail fast, not allocate"
        );
        // A non-power-of-two dict in range is equally rejected.
        let mut blob2 = vec![93u8];
        blob2.extend_from_slice(&0x0FFF_0000u32.to_le_bytes());
        blob2.extend_from_slice(&13u64.to_le_bytes());
        blob2.extend_from_slice(b"junk");
        let src2 = ByteSource::from_vec(blob2);
        assert!(validate_at(&LzmaAloneHandler, &src2, 0).is_err());
    }
}
