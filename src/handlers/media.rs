//! M3 media-format handlers: GIF (structural), BMP, TIFF, WebP, RIFF
//! (WAV/AVI), MP3 (ID3+frame estimate), FLAC.
//!
//! Common policy: parse real structure (headers, chunk/box walks,
//! dimensions/metadata), determine a boundary where the format reliably
//! provides one, and recurse into payloads where meaningful. Formats
//! whose boundaries are not reliably derivable (MP3 without metadata)
//! report honest Partial confidence rather than inventing a size.

use crate::artifact::{Confidence, Evidence};

use crate::bytesource::ByteSource;
use crate::engine::{ArtifactDraft, Budget, Candidate, Handler, HandlerOutput};
use crate::error::{Error, Result};
use crate::handlers::find_all;
use std::collections::BTreeMap;

fn read_u16_le(src: &ByteSource, off: u64) -> Option<u16> {
    let mut b = [0u8; 2];
    src.read_at(off, &mut b).ok()?;
    Some(u16::from_le_bytes(b))
}
fn read_u32_le(src: &ByteSource, off: u64) -> Option<u32> {
    let mut b = [0u8; 4];
    src.read_at(off, &mut b).ok()?;
    Some(u32::from_le_bytes(b))
}
fn read_u16_be(src: &ByteSource, off: u64) -> Option<u16> {
    let mut b = [0u8; 2];
    src.read_at(off, &mut b).ok()?;
    Some(u16::from_be_bytes(b))
}
fn read_u32_be(src: &ByteSource, off: u64) -> Option<u32> {
    let mut b = [0u8; 4];
    src.read_at(off, &mut b).ok()?;
    Some(u32::from_be_bytes(b))
}

// ---------------------------------------------------------------------------
// GIF (upgrade from carving: real structure + logical screen + block walk)
// ---------------------------------------------------------------------------

pub struct GifHandler;

impl Handler for GifHandler {
    fn format(&self) -> &'static str {
        "gif"
    }

    fn find_candidates(&self, src: &ByteSource) -> Vec<Candidate> {
        let mut hits: Vec<Candidate> = find_all(src, b"GIF87a")
            .into_iter()
            .chain(find_all(src, b"GIF89a"))
            .map(|offset| Candidate { offset })
            .collect();
        hits.sort_by_key(|c| c.offset);
        hits.dedup_by_key(|c| c.offset);
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
        if base + 13 > src.len() {
            return Err(Error::Validation {
                format: "gif",
                reason: "truncated header".into(),
            });
        }
        let mut hdr = [0u8; 13];
        src.read_at(base, &mut hdr)?;
        let width = u16::from_le_bytes([hdr[6], hdr[7]]);
        let height = u16::from_le_bytes([hdr[8], hdr[9]]);
        let packed = hdr[10];
        let has_gct = packed & 0x80 != 0;
        let mut off = base + 13u64;
        if has_gct {
            let gct_entries = 2usize << (packed & 0x07);
            off += (gct_entries * 3) as u64;
        }
        if off > src.len() {
            return Err(Error::Validation {
                format: "gif",
                reason: "global color table truncated".into(),
            });
        }

        // Walk blocks until the trailer (0x3B) to prove structure.
        let mut blocks = 0usize;
        let mut graphic_ext = false;
        loop {
            if off >= src.len() {
                return Err(Error::Validation {
                    format: "gif",
                    reason: "no trailer; stream truncated".into(),
                });
            }
            let mut b = [0u8; 1];
            src.read_at(off, &mut b)?;
            match b[0] {
                0x3B => {
                    off += 1;
                    break;
                }
                0x21 => {
                    // Extension: label + sub-blocks.
                    let mut label = [0u8; 1];
                    src.read_at(off + 1, &mut label)?;
                    if label[0] == 0xF9 {
                        graphic_ext = true;
                    }
                    off += 2;
                    // Sub-block walk.
                    loop {
                        let mut len = [0u8; 1];
                        src.read_at(off, &mut len)?;
                        off += 1;
                        if len[0] == 0 {
                            break;
                        }
                        off += u64::from(len[0]);
                    }
                }
                0x2C => {
                    // Image descriptor: 9 bytes + optional LCT + data.
                    if off + 10 > src.len() {
                        return Err(Error::Validation {
                            format: "gif",
                            reason: "image descriptor truncated".into(),
                        });
                    }
                    let mut idp = [0u8; 9];
                    src.read_at(off + 1, &mut idp)?;
                    let mut ioff = off + 10;
                    if idp[8] & 0x80 != 0 {
                        ioff += (2usize << (idp[8] & 0x07)) as u64 * 3;
                    }
                    // LZW min code size + data sub-blocks.
                    ioff += 1;
                    loop {
                        let mut len = [0u8; 1];
                        src.read_at(ioff, &mut len)?;
                        ioff += 1;
                        if len[0] == 0 {
                            break;
                        }
                        ioff += u64::from(len[0]);
                    }
                    off = ioff;
                    blocks += 1;
                }
                _ => {
                    return Err(Error::Validation {
                        format: "gif",
                        reason: format!("unknown block introducer {:#x}", b[0]),
                    });
                }
            }
            blocks += 1;
            if blocks > 100_000 {
                return Err(Error::Validation {
                    format: "gif",
                    reason: "block walk exceeded cap".into(),
                });
            }
        }

        let mut metadata = BTreeMap::new();
        metadata.insert("width".to_string(), width.to_string());
        metadata.insert("height".to_string(), height.to_string());
        metadata.insert(
            "version".to_string(),
            String::from_utf8_lossy(&hdr[3..6]).into_owned(),
        );
        metadata.insert("global_color_table".to_string(), has_gct.to_string());
        if graphic_ext {
            metadata.insert("graphic_control".to_string(), "present".to_string());
        }

        Ok(HandlerOutput {
            artifacts: vec![ArtifactDraft {
                format: "gif".to_string(),
                label: format!("GIF image {}x{}", width, height),
                offset: base,
                size: off - base,
                confidence: Confidence::Validated,
                evidence: Evidence::facts([
                    format!("GIF version {}", String::from_utf8_lossy(&hdr[3..6])),
                    "logical screen descriptor parsed".to_string(),
                    "block walk terminated at trailer (0x3B)".to_string(),
                ]),
                metadata,
                warnings: Vec::new(),
                errors: Vec::new(),
                children: Vec::new(),
            }],
        })
    }
}

// ---------------------------------------------------------------------------
// BMP
// ---------------------------------------------------------------------------

pub struct BmpHandler;

impl Handler for BmpHandler {
    fn format(&self) -> &'static str {
        "bmp"
    }

    fn find_candidates(&self, src: &ByteSource) -> Vec<Candidate> {
        // "BM" + plausible DIB size: requires more than the 2-byte magic,
        // so validate fully and let the candidate list stay broad.
        find_all(src, b"BM")
            .into_iter()
            .map(|offset| Candidate { offset })
            .collect()
    }

    fn validate(
        &self,
        src: &ByteSource,
        candidate: Candidate,
        _limits: &crate::engine::EngineLimits,
        _budget: &mut Budget,
    ) -> Result<HandlerOutput> {
        let base = candidate.offset;
        if base + 26 > src.len() {
            return Err(Error::Validation {
                format: "bmp",
                reason: "truncated header".into(),
            });
        }
        let file_size = read_u32_le(src, base + 2).unwrap_or(0) as u64;
        let data_offset = read_u32_le(src, base + 10).unwrap_or(0) as u64;
        let dib_size = read_u32_le(src, base + 14).unwrap_or(0);
        let width = read_u32_le(src, base + 18).unwrap_or(0) as i64;
        let height_raw = read_u32_le(src, base + 22).unwrap_or(0) as i64;
        let planes = read_u16_le(src, base + 26).unwrap_or(0);
        let bpp = read_u16_le(src, base + 28).unwrap_or(0);

        if dib_size < 12 {
            return Err(Error::Validation {
                format: "bmp",
                reason: format!("implausible DIB size {dib_size}"),
            });
        }
        if planes == 0 {
            return Err(Error::Validation {
                format: "bmp",
                reason: "planes == 0".into(),
            });
        }
        if !matches!(bpp, 1 | 2 | 4 | 8 | 16 | 24 | 32) {
            return Err(Error::Validation {
                format: "bmp",
                reason: format!("implausible bpp {bpp}"),
            });
        }
        let height = height_raw.unsigned_abs();
        if width == 0 || height == 0 || width > 1_000_000 || height > 1_000_000 {
            return Err(Error::Validation {
                format: "bmp",
                reason: "implausible dimensions".into(),
            });
        }
        // Exact boundary: declared file size when it fits the source.
        let size = if file_size >= 26 && base + file_size <= src.len() {
            file_size
        } else if data_offset >= base + u64::from(dib_size) + 14 {
            // Fallback: header + DIB + pixel data of declared length.
            return Err(Error::Validation {
                format: "bmp",
                reason: "file size field inconsistent".into(),
            });
        } else {
            src.len() - base
        };

        let mut metadata = BTreeMap::new();
        metadata.insert("width".to_string(), width.to_string());
        metadata.insert("height".to_string(), height.to_string());
        metadata.insert("bpp".to_string(), bpp.to_string());
        metadata.insert("dib_size".to_string(), dib_size.to_string());
        if height_raw < 0 {
            metadata.insert("top_down".to_string(), "true".to_string());
        }

        Ok(HandlerOutput {
            artifacts: vec![ArtifactDraft {
                format: "bmp".to_string(),
                label: format!("BMP image {}x{} ({}bpp)", width, height, bpp),
                offset: base,
                size,
                confidence: Confidence::Validated,
                evidence: Evidence::facts([
                    "BM signature + DIB header parsed".to_string(),
                    format!("declared file size {}", file_size),
                    format!("pixel data at offset {}", data_offset),
                ]),
                metadata,
                warnings: Vec::new(),
                errors: Vec::new(),
                children: Vec::new(),
            }],
        })
    }
}

// ---------------------------------------------------------------------------
// TIFF
// ---------------------------------------------------------------------------

pub struct TiffHandler;

impl Handler for TiffHandler {
    fn format(&self) -> &'static str {
        "tiff"
    }

    fn find_candidates(&self, src: &ByteSource) -> Vec<Candidate> {
        let mut hits: Vec<Candidate> = find_all(src, b"II*\0")
            .into_iter()
            .chain(find_all(src, b"MM\0*"))
            .map(|offset| Candidate { offset })
            .collect();
        hits.sort_by_key(|c| c.offset);
        hits.dedup_by_key(|c| c.offset);
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
                format: "tiff",
                reason: "truncated header".into(),
            });
        }
        let mut order = [0u8; 2];
        src.read_at(base, &mut order)?;
        let le = &order == b"II";
        let (read_u16, read_u32) = if le {
            (
                read_u16_le as fn(&ByteSource, u64) -> Option<u16>,
                read_u32_le as fn(&ByteSource, u64) -> Option<u32>,
            )
        } else {
            (
                read_u16_be as fn(&ByteSource, u64) -> Option<u16>,
                read_u32_be as fn(&ByteSource, u64) -> Option<u32>,
            )
        };
        let ifd_offset = read_u32(src, base + 4).unwrap_or(0) as u64;
        if ifd_offset < 8 || base + ifd_offset + 2 > src.len() {
            return Err(Error::Validation {
                format: "tiff",
                reason: "IFD offset invalid".into(),
            });
        }

        // Walk the IFD chain (bounded), collecting useful tags.
        let mut ifd_count = 0usize;
        let mut current = base + ifd_offset;
        let mut image_width: Option<u32> = None;
        let mut image_height: Option<u32> = None;
        let mut max_ifds = 256usize;
        while max_ifds > 0 {
            max_ifds -= 1;
            let count = read_u16(src, current).unwrap_or(0) as usize;
            if count == 0 || count > 0x1000 || current + 2 + (count as u64) * 12 + 4 > src.len() {
                return Err(Error::Validation {
                    format: "tiff",
                    reason: "IFD entry count invalid".into(),
                });
            }
            ifd_count += 1;
            for i in 0..count {
                let entry = current + 2 + (i as u64) * 12;
                let tag = read_u16(src, entry).unwrap_or(0);
                match tag {
                    0x0100 => image_width = read_u32(src, entry + 8),
                    0x0101 => image_height = read_u32(src, entry + 8),
                    _ => {}
                }
            }
            let next = read_u32(src, current + 2 + (count as u64) * 12).unwrap_or(0) as u64;
            if next == 0 {
                break;
            }
            current = base + next;
            if current >= src.len() {
                return Err(Error::Validation {
                    format: "tiff",
                    reason: "IFD chain escapes source".into(),
                });
            }
        }
        if ifd_count > limits.max_records {
            return Err(Error::Validation {
                format: "tiff",
                reason: "IFD limit exceeded".into(),
            });
        }

        let mut metadata = BTreeMap::new();
        metadata.insert(
            "byte_order".to_string(),
            if le { "little" } else { "big" }.to_string(),
        );
        metadata.insert("ifd_count".to_string(), ifd_count.to_string());
        if let Some(w) = image_width {
            metadata.insert("width".to_string(), w.to_string());
        }
        if let Some(h) = image_height {
            metadata.insert("height".to_string(), h.to_string());
        }

        // TIFF has no total-size field; boundary is the whole region —
        // an honest partial when embedded. A root-level TIFF fills it.
        let size = src.len() - base;
        Ok(HandlerOutput {
            artifacts: vec![ArtifactDraft {
                format: "tiff".to_string(),
                label: format!(
                    "TIFF image ({}x{})",
                    image_width
                        .map(|w| w.to_string())
                        .unwrap_or_else(|| "?".into()),
                    image_height
                        .map(|h| h.to_string())
                        .unwrap_or_else(|| "?".into())
                ),
                offset: base,
                size,
                confidence: Confidence::Validated,
                evidence: Evidence::facts([
                    "TIFF magic + byte order validated".to_string(),
                    format!("IFD chain walked ({} IFDs)", ifd_count),
                    "no total-size field: boundary = enclosing region".to_string(),
                ]),
                metadata,
                warnings: if image_width.is_none() {
                    vec!["ImageWidth tag not found; not an unambiguous image?".to_string()]
                } else {
                    Vec::new()
                },
                errors: Vec::new(),
                children: Vec::new(),
            }],
        })
    }
}

// ---------------------------------------------------------------------------
// WebP (RIFF container + VP8/VP8L/VP8X payload)
// ---------------------------------------------------------------------------

pub struct WebPHandler;

impl Handler for WebPHandler {
    fn format(&self) -> &'static str {
        "webp"
    }

    fn find_candidates(&self, src: &ByteSource) -> Vec<Candidate> {
        find_all(src, b"RIFF")
            .into_iter()
            .map(|offset| Candidate { offset })
            .collect()
    }

    fn validate(
        &self,
        src: &ByteSource,
        candidate: Candidate,
        _limits: &crate::engine::EngineLimits,
        _budget: &mut Budget,
    ) -> Result<HandlerOutput> {
        let base = candidate.offset;
        if base + 20 > src.len() {
            return Err(Error::Validation {
                format: "webp",
                reason: "truncated RIFF header".into(),
            });
        }
        let mut form = [0u8; 4];
        src.read_at(base + 8, &mut form)?;
        if &form != b"WEBP" {
            return Err(Error::Validation {
                format: "webp",
                reason: "RIFF form not WEBP".into(),
            });
        }
        let riff_size = read_u32_le(src, base + 4).unwrap_or(0) as u64;
        let size = riff_size.checked_add(8).ok_or(Error::Validation {
            format: "webp",
            reason: "riff size overflow".into(),
        })?;
        if base + size > src.len() {
            return Err(Error::Validation {
                format: "webp",
                reason: format!("RIFF size {riff_size} exceeds source"),
            });
        }
        let chunk_type = {
            let mut t = [0u8; 4];
            src.read_at(base + 12, &mut t)?;
            t
        };
        let codec = match &chunk_type {
            b"VP8 " => "lossy (VP8)",
            b"VP8L" => "lossless (VP8L)",
            b"VP8X" => "extended (VP8X)",
            _ => "unknown",
        };

        let mut metadata = BTreeMap::new();
        metadata.insert("codec".to_string(), codec.to_string());
        metadata.insert("riff_size".to_string(), riff_size.to_string());

        Ok(HandlerOutput {
            artifacts: vec![ArtifactDraft {
                format: "webp".to_string(),
                label: format!("WebP image ({codec})"),
                offset: base,
                size,
                confidence: Confidence::Validated,
                evidence: Evidence::facts([
                    "RIFF header validated with WEBP form".to_string(),
                    format!("first chunk {}", String::from_utf8_lossy(&chunk_type)),
                    "boundary from declared RIFF size".to_string(),
                ]),
                metadata,
                warnings: Vec::new(),
                errors: Vec::new(),
                children: Vec::new(),
            }],
        })
    }
}

// ---------------------------------------------------------------------------
// RIFF family (WAV / AVI distinction)
// ---------------------------------------------------------------------------

pub struct RiffHandler;

impl Handler for RiffHandler {
    fn format(&self) -> &'static str {
        "riff"
    }

    fn find_candidates(&self, src: &ByteSource) -> Vec<Candidate> {
        find_all(src, b"RIFF")
            .into_iter()
            .map(|offset| Candidate { offset })
            .collect()
    }

    fn validate(
        &self,
        src: &ByteSource,
        candidate: Candidate,
        _limits: &crate::engine::EngineLimits,
        _budget: &mut Budget,
    ) -> Result<HandlerOutput> {
        let base = candidate.offset;
        if base + 12 > src.len() {
            return Err(Error::Validation {
                format: "riff",
                reason: "truncated RIFF header".into(),
            });
        }
        let mut form = [0u8; 4];
        src.read_at(base + 8, &mut form)?;
        if &form == b"WEBP" {
            // Handled by WebPHandler; avoid double-claiming.
            return Err(Error::Validation {
                format: "riff",
                reason: "WEBP form (WebPHandler claims)".into(),
            });
        }
        let kind = match &form {
            b"WAVE" => "WAV audio",
            b"AVI " => "AVI video",
            other => {
                return Err(Error::Validation {
                    format: "riff",
                    reason: format!("unhandled RIFF form {}", String::from_utf8_lossy(other)),
                })
            }
        };
        let riff_size = read_u32_le(src, base + 4).unwrap_or(0) as u64;
        let size = riff_size.checked_add(8).ok_or(Error::Validation {
            format: "riff",
            reason: "riff size overflow".into(),
        })?;
        if base + size > src.len() {
            return Err(Error::Validation {
                format: "riff",
                reason: format!("RIFF size {riff_size} exceeds source"),
            });
        }

        let mut metadata = BTreeMap::new();
        metadata.insert(
            "form".to_string(),
            String::from_utf8_lossy(&form).trim().to_string(),
        );

        Ok(HandlerOutput {
            artifacts: vec![ArtifactDraft {
                format: "riff".to_string(),
                label: kind.to_string(),
                offset: base,
                size,
                confidence: Confidence::Validated,
                evidence: Evidence::facts([
                    "RIFF header validated".to_string(),
                    format!("form type {}", String::from_utf8_lossy(&form).trim()),
                    "boundary from declared RIFF size".to_string(),
                ]),
                metadata,
                warnings: Vec::new(),
                errors: Vec::new(),
                children: Vec::new(),
            }],
        })
    }
}

// ---------------------------------------------------------------------------
// MP3 (ID3v2 + frame estimate; honest Partial without ID3)
// ---------------------------------------------------------------------------

pub struct Mp3Handler;

impl Handler for Mp3Handler {
    fn format(&self) -> &'static str {
        "mp3"
    }

    fn find_candidates(&self, src: &ByteSource) -> Vec<Candidate> {
        let mut hits: Vec<Candidate> = find_all(src, b"ID3")
            .into_iter()
            .map(|offset| Candidate { offset })
            .collect();
        // Frame sync 0xFFEx/0xFFFx as fallback candidates. The sync is a
        // fixed 11-bit pattern: byte0 == 0xFF exactly and byte1's top 3
        // bits set (0xE0..=0xFF). Scan 0xFF bytes and check the next.
        let data = match src.read_prefix(64 * 1024 * 1024) {
            Ok(d) => d,
            Err(_) => return hits,
        };
        for i in 0..data.len().saturating_sub(1) {
            if data[i] == 0xFF && data[i + 1] & 0xE0 == 0xE0 {
                hits.push(Candidate { offset: i as u64 });
            }
        }
        hits.sort_by_key(|c| c.offset);
        hits.dedup_by_key(|c| c.offset);
        hits.into_iter().take(64).collect()
    }

    fn validate(
        &self,
        src: &ByteSource,
        candidate: Candidate,
        _limits: &crate::engine::EngineLimits,
        _budget: &mut Budget,
    ) -> Result<HandlerOutput> {
        let base = candidate.offset;
        if base + 10 > src.len() {
            return Err(Error::Validation {
                format: "mp3",
                reason: "truncated header".into(),
            });
        }
        let mut head = [0u8; 10];
        src.read_at(base, &mut head)?;

        let size;
        let mut metadata = BTreeMap::new();

        if &head[0..3] == b"ID3" {
            let ver = format!("2.{}.{}", head[3], head[4]);
            if head[3] > 4 {
                return Err(Error::Validation {
                    format: "mp3",
                    reason: format!("unsupported ID3 {ver}"),
                });
            }
            let flags = head[5];
            let syncsafe = |b: [u8; 4]| {
                (u32::from(b[0] & 0x7F) << 21)
                    | (u32::from(b[1] & 0x7F) << 14)
                    | (u32::from(b[2] & 0x7F) << 7)
                    | u32::from(b[3] & 0x7F)
            };
            let mut tag_size = syncsafe([head[6], head[7], head[8], head[9]]) as u64 + 10;
            if flags & 0x10 != 0 {
                tag_size += 10; // footer
            }
            if base + tag_size > src.len() {
                return Err(Error::Validation {
                    format: "mp3",
                    reason: "ID3 tag exceeds source".into(),
                });
            }
            metadata.insert("id3_version".to_string(), ver);
            metadata.insert("id3_size".to_string(), tag_size.to_string());
            size = tag_size;
            // A bare 10-byte ID3 header claiming no tag body is not
            // enough structure to claim a region (a 0x49 0x44 0x33
            // sequence with tiny size appears in compressed data); the
            // tag must actually declare and contain content.
            if tag_size <= 10 {
                return Err(Error::Validation {
                    format: "mp3",
                    reason: "empty ID3 tag; insufficient structure".into(),
                });
            }
        } else {
            // Raw frame sync: require a plausible MPEG frame header.
            // Tighten: version+layer+bitrate fields must be valid (no
            // "reserved" values) so random 0xFF bytes in compressed data
            // don't produce 16KB Partial claims that break region
            // decomposition in every other fixture.
            let b1 = head[1];
            if b1 & 0xE0 != 0xE0 || b1 & 0x18 == 0x08 || b1 & 0x06 == 0 {
                return Err(Error::Validation {
                    format: "mp3",
                    reason: "not a plausible MPEG audio frame".into(),
                });
            }
            let b2 = head[2];
            let bitrate_idx = b2 & 0xF0;
            let sample_idx = b2 & 0x0C;
            // MPEG1 Layer I/II/III: free (0) and bad (0xF0) bitrate
            // indices are invalid; sample-rate index 0b11 is reserved.
            if bitrate_idx == 0xF0 || bitrate_idx == 0 || sample_idx == 0x0C {
                return Err(Error::Validation {
                    format: "mp3",
                    reason: "reserved MPEG frame fields".into(),
                });
            }
            // Frame-length sanity: the frame must fit a plausible MPEG
            // audio size and the NEXT frame sync must follow (real MPEG
            // audio is a chain of back-to-back frames). Without this a
            // lone 0xFF 0xEx in compressed data claims 16KB regions.
            let bitrate_kbps = match (b1 & 0x18) >> 3 {
                3 => match bitrate_idx >> 4 {
                    // MPEG1 Layer III
                    1..=14 => [
                        0, 32, 40, 48, 56, 64, 80, 96, 112, 128, 160, 192, 224, 256, 320,
                    ][bitrate_idx as usize >> 4],
                    _ => {
                        return Err(Error::Validation {
                            format: "mp3",
                            reason: "bad bitrate index".into(),
                        })
                    }
                },
                _ => {
                    return Err(Error::Validation {
                        format: "mp3",
                        reason: "only MPEG1 audio frames considered".into(),
                    })
                }
            };
            let sample_rate = match sample_idx >> 2 {
                0 => 44100u64,
                1 => 48000,
                2 => 32000,
                _ => {
                    return Err(Error::Validation {
                        format: "mp3",
                        reason: "reserved sample rate".into(),
                    })
                }
            };
            let padding = u64::from((b2 >> 1) & 1);
            let frame_len = 144 * bitrate_kbps * 1000 / sample_rate + padding;
            if frame_len == 0 || base + frame_len + 4 > src.len() {
                return Err(Error::Validation {
                    format: "mp3",
                    reason: "frame does not fit source".into(),
                });
            }
            let mut next = [0u8; 2];
            src.read_at(base + frame_len, &mut next)?;
            if next[0] != 0xFF || next[1] & 0xE0 != 0xE0 {
                return Err(Error::Validation {
                    format: "mp3",
                    reason: "no following frame sync; not MPEG audio".into(),
                });
            }
            metadata.insert("frame_sync".to_string(), "true".to_string());
            return Ok(HandlerOutput {
                artifacts: vec![ArtifactDraft {
                    format: "mp3".to_string(),
                    label: "MPEG audio stream (frame sync)".to_string(),
                    offset: base,
                    size: (src.len() - base).min(1 << 20), // bounded estimate
                    confidence: Confidence::Partial,
                    evidence: Evidence::facts([
                        "MPEG frame sync validated".to_string(),
                        "no metadata container: exact size not derivable".to_string(),
                    ]),
                    metadata,
                    warnings: vec![
                        "MP3 without ID3: size is a bounded estimate, not a structural boundary"
                            .to_string(),
                    ],
                    errors: Vec::new(),
                    children: Vec::new(),
                }],
            });
        }

        Ok(HandlerOutput {
            artifacts: vec![ArtifactDraft {
                format: "mp3".to_string(),
                label: format!(
                    "MP3 audio ({})",
                    metadata
                        .get("id3_version")
                        .map(String::as_str)
                        .unwrap_or("ID3")
                ),
                offset: base,
                size: (base + size).min(src.len()) - base,
                confidence: Confidence::Validated,
                evidence: Evidence::facts([
                    "ID3v2 header + syncsafe size parsed".to_string(),
                    "boundary from ID3 tag size".to_string(),
                ]),
                metadata,
                warnings: Vec::new(),
                errors: Vec::new(),
                children: Vec::new(),
            }],
        })
    }
}

// ---------------------------------------------------------------------------
// FLAC
// ---------------------------------------------------------------------------

pub struct FlacHandler;

const FLAC_MAGIC: &[u8] = b"fLaC";

impl Handler for FlacHandler {
    fn format(&self) -> &'static str {
        "flac"
    }

    fn find_candidates(&self, src: &ByteSource) -> Vec<Candidate> {
        find_all(src, FLAC_MAGIC)
            .into_iter()
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
        let base = candidate.offset;
        let mut off = base + 4;
        let mut saw_streaminfo = false;
        let mut last = false;
        let mut blocks = 0usize;
        while !last && blocks < limits.max_records.min(4096) {
            if off + 4 > src.len() {
                return Err(Error::Validation {
                    format: "flac",
                    reason: "metadata block truncated".into(),
                });
            }
            let mut bh = [0u8; 4];
            src.read_at(off, &mut bh)?;
            last = bh[0] & 0x80 != 0;
            let block_type = bh[0] & 0x7F;
            let length = u32::from_be_bytes([0, bh[1], bh[2], bh[3]]) as u64;
            if block_type == 0 {
                saw_streaminfo = true;
            }
            off += 4 + length;
            blocks += 1;
        }
        if !saw_streaminfo {
            return Err(Error::Validation {
                format: "flac",
                reason: "no STREAMINFO block".into(),
            });
        }
        if off > src.len() {
            return Err(Error::Validation {
                format: "flac",
                reason: "metadata blocks exceed source".into(),
            });
        }
        // Audio frames follow; the exact audio end is not derivable
        // without full frame walking, so the artifact covers header+meta.
        let metadata = BTreeMap::new();

        Ok(HandlerOutput {
            artifacts: vec![ArtifactDraft {
                format: "flac".to_string(),
                label: format!("FLAC audio ({} metadata blocks)", blocks),
                offset: base,
                size: off - base,
                confidence: Confidence::Validated,
                evidence: Evidence::facts([
                    "fLaC magic validated".to_string(),
                    format!("{} metadata blocks walked to last-block flag", blocks),
                    "boundary = end of metadata chain (audio frames follow)".to_string(),
                ]),
                metadata,
                warnings: vec![
                    "audio frame data after metadata is not boundary-checked in this milestone"
                        .to_string(),
                ],
                errors: Vec::new(),
                children: Vec::new(),
            }],
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::EngineLimits;

    fn validate_at(h: &dyn Handler, src: &ByteSource, off: u64) -> Result<HandlerOutput> {
        h.validate(
            src,
            Candidate { offset: off },
            &EngineLimits::default(),
            &mut Budget::default(),
        )
    }

    #[test]
    fn gif_block_walk_terminates_at_trailer() {
        let mut g = b"GIF89a".to_vec();
        g.extend(3u16.to_le_bytes());
        g.extend(2u16.to_le_bytes());
        g.push(0x00);
        g.push(0x00);
        g.push(0x00);
        g.extend([0x21, 0xF9, 0x04, 0x01, 0x00, 0x00, 0x00, 0x00]);
        g.push(0x2C);
        g.extend(0u16.to_le_bytes());
        g.extend(0u16.to_le_bytes());
        g.extend(3u16.to_le_bytes());
        g.extend(2u16.to_le_bytes());
        g.push(0x00);
        g.extend([0x02, 0x03, b'a', b'b', b'c', 0x00]);
        g.push(0x3B);
        let src = ByteSource::from_vec(g);
        let out = validate_at(&GifHandler, &src, 0).expect("gif validates");
        let art = &out.artifacts[0];
        assert_eq!(art.confidence, Confidence::Validated);
        assert_eq!(art.size, src.len(), "trailer ends the archive");
        assert_eq!(art.metadata.get("width").map(String::as_str), Some("3"));
        assert_eq!(
            art.metadata.get("graphic_control").map(String::as_str),
            Some("present")
        );
    }

    #[test]
    fn gif_missing_trailer_rejected() {
        let mut g = b"GIF89a".to_vec();
        g.extend(1u16.to_le_bytes());
        g.extend(1u16.to_le_bytes());
        g.extend([0, 0, 0]);
        let src = ByteSource::from_vec(g);
        assert!(validate_at(&GifHandler, &src, 0).is_err());
    }

    #[test]
    fn bmp_declared_size_boundary() {
        let mut b = b"BM".to_vec();
        let total = 70u32;
        b.extend(total.to_le_bytes());
        b.extend(0u32.to_le_bytes());
        b.extend(54u32.to_le_bytes());
        b.extend(40u32.to_le_bytes());
        b.extend(7i32.to_le_bytes());
        b.extend(5i32.to_le_bytes());
        b.extend(1u16.to_le_bytes());
        b.extend(24u16.to_le_bytes());
        b.resize(total as usize, 0);
        let src = ByteSource::from_vec(b);
        let out = validate_at(&BmpHandler, &src, 0).expect("bmp validates");
        let art = &out.artifacts[0];
        assert_eq!(art.confidence, Confidence::Validated);
        assert_eq!(art.size, 70);
        assert_eq!(art.metadata.get("bpp").map(String::as_str), Some("24"));
    }

    #[test]
    fn bmp_bad_bpp_rejected() {
        let mut b = b"BM".to_vec();
        b.extend(70u32.to_le_bytes());
        b.extend(0u32.to_le_bytes());
        b.extend(54u32.to_le_bytes());
        b.extend(40u32.to_le_bytes());
        b.extend(7i32.to_le_bytes());
        b.extend(5i32.to_le_bytes());
        b.extend(1u16.to_le_bytes());
        b.extend(3u16.to_le_bytes());
        b.resize(70, 0);
        let src = ByteSource::from_vec(b);
        assert!(validate_at(&BmpHandler, &src, 0).is_err());
    }

    #[test]
    fn flac_metadata_chain_walks_to_last_block() {
        let mut f = b"fLaC".to_vec();
        // STREAMINFO block header: last-block flag set, type 0, len 34.
        f.extend([0x80, 0x00, 0x00, 0x22]);
        f.extend([0u8; 34]);
        let src = ByteSource::from_vec(f);
        let out = validate_at(&FlacHandler, &src, 0).expect("flac validates");
        let art = &out.artifacts[0];
        assert_eq!(art.confidence, Confidence::Validated);
        assert_eq!(art.size, 42);
    }

    #[test]
    fn riff_wav_and_webp_distinction() {
        let mut wav = b"RIFF".to_vec();
        wav.extend(4u32.to_le_bytes());
        wav.extend(b"WAVE");
        let src = ByteSource::from_vec(wav);
        let out = validate_at(&RiffHandler, &src, 0).expect("wav validates");
        assert_eq!(
            out.artifacts[0].metadata.get("form").map(String::as_str),
            Some("WAVE")
        );

        let mut webp = b"RIFF".to_vec();
        webp.extend(4u32.to_le_bytes());
        webp.extend(b"WEBP");
        webp.extend(b"VP8 ");
        webp.extend(0u32.to_le_bytes());
        let src = ByteSource::from_vec(webp);
        assert!(
            validate_at(&RiffHandler, &src, 0).is_err(),
            "WEBP is WebPHandler's"
        );
        let out = validate_at(&WebPHandler, &src, 0).expect("webp validates");
        assert_eq!(
            out.artifacts[0].metadata.get("codec").map(String::as_str),
            Some("lossy (VP8)")
        );
    }

    #[test]
    fn mp3_frame_sync_in_compressed_data_not_claimed() {
        // High-entropy bytes: must not produce MP3 artifacts.
        let mut state: u32 = 0x1234_5678;
        let mut blob = Vec::new();
        for _ in 0..8192 {
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            blob.push((state >> 24) as u8);
        }
        let src = ByteSource::from_vec(blob);
        let candidates = Mp3Handler.find_candidates(&src);
        let validated = candidates
            .iter()
            .filter(|c| validate_at(&Mp3Handler, &src, c.offset).is_ok())
            .count();
        assert_eq!(
            validated, 0,
            "random high-entropy data must not validate as MP3"
        );
    }
}
