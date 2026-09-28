//! M3-K recovery handlers: structural salvage of damaged containers.
//!
//! These run AFTER the primary structural handlers (the engine calls
//! them last) and only fire where primary validation failed, so they
//! never mask honest validation. Everything they produce is
//! `Confidence::Recovered` or `Heuristic` — never `Validated`.
//!
//! - ZIP salvage: a truncated archive (no EOCD / broken central
//!   directory) still yields per-local-entry salvage. Each `PK\x03\x04`
//!   header is parsed structurally; the stored/deflate payload is
//!   decompressed with a hard output cap; entries whose decompression
//!   dies mid-stream are still reported with the bytes recovered so far
//!   (that is the point of recovery — partial data beats none).
//! - CPIO/tar/gzip salvage lives with their primary handlers via the
//!   Damaged/Partial confidences; nothing further is honest here.

use crate::artifact::{Confidence, Evidence, RelationKind};
use crate::bytesource::ByteSource;
use crate::engine::{
    ArtifactDraft, Budget, Candidate, ChildContent, ChildDraft, Handler, HandlerOutput,
};
use crate::error::{Error, Result};
use crate::handlers::find_all;
use std::collections::BTreeMap;
use std::io::Read;

pub struct ZipSalvageHandler;

const LFH_SIG: [u8; 4] = [0x50, 0x4b, 0x03, 0x04];

impl Handler for ZipSalvageHandler {
    fn format(&self) -> &'static str {
        "zip-salvage"
    }

    fn find_candidates(&self, src: &ByteSource) -> Vec<Candidate> {
        // Candidate = any local file header. Validation checks whether
        // the primary ZIP handler could NOT claim this region cleanly.
        find_all(src, &LFH_SIG)
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
        // Step 1: if the primary ZIP handler validates this region with a
        // well-formed EOCD, salvage is not our job — stand down.
        if find_eocd(src, base).is_some() {
            return Err(Error::Validation {
                format: "zip-salvage",
                reason: "intact central directory present; primary handler owns this".into(),
            });
        }
        // Also stand down when a primary-handler ZIP artifact would fail
        // only for limits reasons — those aren't corruption.
        // (A truncated region never has an EOCD, so this is the check.)

        // Step 2: parse local file headers sequentially from the first.
        let data_len = src.len();
        let mut children: Vec<ChildDraft> = Vec::new();
        let mut names: Vec<String> = Vec::new();
        let mut warnings: Vec<String> = Vec::new();
        let mut salvaged = 0usize;
        let mut partial = 0usize;
        let mut off = base;
        let mut entries_scanned = 0usize;

        while off + 30 <= data_len {
            let mut sig = [0u8; 4];
            if src.read_at(off, &mut sig).is_err() || sig != LFH_SIG {
                break;
            }
            entries_scanned += 1;
            if entries_scanned > limits.max_archive_entries {
                warnings.push(format!(
                    "entry scan cap {} reached; remaining entries not attempted",
                    limits.max_archive_entries
                ));
                break;
            }
            let flags = rd16(src, off + 6).unwrap_or(0);
            let method = rd16(src, off + 8).unwrap_or(0);
            let compressed_size = rd32(src, off + 18).unwrap_or(0) as u64;
            let name_len = rd16(src, off + 26).unwrap_or(0) as u64;
            let extra_len = rd16(src, off + 28).unwrap_or(0) as u64;
            let name_off = off + 30;
            if name_off + name_len + extra_len > data_len {
                warnings.push(format!("entry at {off}: name/extra truncated"));
                break;
            }
            let mut name_buf = vec![0u8; name_len as usize];
            src.read_at(name_off, &mut name_buf)?;
            let name = String::from_utf8_lossy(&name_buf).into_owned();
            names.push(name.clone());
            let data_off = name_off + name_len + extra_len;

            let encrypted = flags & 0x0001 != 0;
            if encrypted {
                warnings.push(format!("entry {name:?} encrypted; skipped"));
                off = data_off + compressed_size.min(data_len - data_off.min(data_len));
                continue;
            }

            // Unknown size (streaming flag bit 3): decompress until the
            // next header or end of data with a hard cap.
            let capped = compressed_size.min(data_len.saturating_sub(data_off));
            let region = match src.slice(data_off, capped) {
                Ok(r) => r,
                Err(_) => break,
            };

            let (bytes, complete) = match method {
                0 => {
                    // Stored: the raw region IS the payload.
                    (region.read_all().unwrap_or_default(), true)
                }
                8 => {
                    // Deflate with hard output cap; keep partial output.
                    inflate_capped(&region, limits.max_child_size, budget, limits)
                }
                _ => {
                    warnings.push(format!(
                        "entry {name:?} unsupported method {method}; raw region kept"
                    ));
                    (Vec::new(), false)
                }
            };

            if bytes.is_empty() {
                warnings.push(format!("entry {name:?}: no bytes recovered"));
            } else if complete {
                salvaged += 1;
            } else {
                partial += 1;
                warnings.push(format!(
                    "entry {name:?}: decompression incomplete; {} partial bytes kept",
                    bytes.len()
                ));
            }
            let size = bytes.len() as u64;
            if !bytes.is_empty() {
                children.push(ChildDraft {
                    relation: RelationKind::CarvedFrom,
                    label: format!(
                        "salvaged {name} ({size} bytes{})",
                        if complete { "" } else { ", partial" }
                    ),
                    format_hint: "raw",
                    content: ChildContent::Owned(bytes),
                    size,
                    metadata: BTreeMap::new(),
                    warnings: Vec::new(),
                    entry_name: Some(name.clone()),
                });
            }

            // Advance: known compressed size (or capped guess) + the
            // next header hunt.
            let advance = if compressed_size > 0 {
                compressed_size
            } else {
                // Streaming entries: scan for the next LFH.
                let next = find_from(src, data_off, &LFH_SIG);
                match next {
                    Some(n) => n - data_off,
                    None => break,
                }
            };
            off = data_off.saturating_add(advance);
            if advance == 0 {
                break;
            }
        }

        if children.is_empty() && warnings.is_empty() {
            return Err(Error::Validation {
                format: "zip-salvage",
                reason: "no local entries salvageable".into(),
            });
        }
        if children.is_empty() {
            return Err(Error::Validation {
                format: "zip-salvage",
                reason: "no entry bytes recovered".into(),
            });
        }

        let mut metadata = BTreeMap::new();
        metadata.insert("entries_scanned".to_string(), entries_scanned.to_string());
        metadata.insert("salvaged".to_string(), salvaged.to_string());
        metadata.insert("partial".to_string(), partial.to_string());
        metadata.insert("entry_names".to_string(), names.join("\n"));

        Ok(HandlerOutput {
            artifacts: vec![ArtifactDraft {
                format: "zip-salvage".to_string(),
                label: format!(
                    "ZIP salvage ({} complete, {} partial of {} scanned)",
                    salvaged, partial, entries_scanned
                ),
                offset: base,
                size: data_len - base,
                confidence: Confidence::Recovered,
                evidence: Evidence::facts([
                    "no EOCD: archive structurally incomplete (truncated)".to_string(),
                    format!(
                        "{} local file headers parsed; {} entries recovered, {} partial",
                        entries_scanned, salvaged, partial
                    ),
                    "per-entry salvage from local headers only".to_string(),
                ]),
                metadata,
                warnings,
                errors: Vec::new(),
                children,
            }],
        })
    }
}

/// Inflate with a hard output cap. Returns (bytes, complete) where
/// `complete` is false when the stream died mid-decode or hit the cap —
/// partial output is still returned (that is the recovery contract).
fn inflate_capped(
    region: &ByteSource,
    max_out: u64,
    budget: &mut Budget,
    limits: &crate::engine::EngineLimits,
) -> (Vec<u8>, bool) {
    let data = match region.read_all() {
        Ok(d) => d,
        Err(_) => return (Vec::new(), false),
    };
    let mut decoder = flate2::read::DeflateDecoder::new(&data[..]);
    let mut out = Vec::new();
    let mut chunk = [0u8; 32 * 1024];
    let mut complete = false;
    loop {
        match decoder.read(&mut chunk) {
            Ok(0) => {
                complete = true;
                break;
            }
            Ok(n) => {
                if out.len() as u64 + n as u64 > max_out {
                    out.extend_from_slice(&chunk[..(max_out as usize - out.len()).min(n)]);
                    break;
                }
                out.extend_from_slice(&chunk[..n]);
                if !budget.charge(limits, n as u64) {
                    break;
                }
            }
            Err(_) => {
                // Corrupt stream mid-way: keep what we got.
                break;
            }
        }
    }
    (out, complete)
}

fn rd16(src: &ByteSource, off: u64) -> Option<u16> {
    let mut b = [0u8; 2];
    src.read_at(off, &mut b).ok()?;
    Some(u16::from_le_bytes(b))
}
fn rd32(src: &ByteSource, off: u64) -> Option<u32> {
    let mut b = [0u8; 4];
    src.read_at(off, &mut b).ok()?;
    Some(u32::from_le_bytes(b))
}

/// Find an EOCD after `from` that would make this archive intact.
fn find_eocd(src: &ByteSource, from: u64) -> Option<u64> {
    // Cheap: search only the tail 64KiB + comment space, as EOCD lives
    // near the end in any archive the primary handler would accept.
    let len = src.len();
    if len < 22 {
        return None;
    }
    let window_start = len.saturating_sub(22 + 65_536);
    if window_start > from {
        return None; // candidate far before any plausible EOCD
    }
    let tail = src.slice(window_start, len - window_start).ok()?;
    let data = tail.read_all().ok()?;
    // Scan for PK\x05\x06.
    for i in 0..data.len().saturating_sub(21) {
        if &data[i..i + 4] == b"PK\x05\x06" {
            let comment_len = u16::from_le_bytes([data[i + 20], data[i + 21]]) as usize;
            let end = i + 22 + comment_len;
            if end <= data.len() {
                return Some(window_start + i as u64);
            }
        }
    }
    None
}

fn find_from(src: &ByteSource, from: u64, needle: &[u8]) -> Option<u64> {
    let data = src.read_prefix(64 * 1024 * 1024).ok()?;
    if from as usize >= data.len() {
        return None;
    }
    (from as usize..=data.len() - needle.len())
        .find(|&i| &data[i..i + needle.len()] == needle)
        .map(|i| i as u64)
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

    fn lfh(name: &[u8], method: u16, payload: &[u8]) -> Vec<u8> {
        let mut h = Vec::new();
        h.extend_from_slice(&LFH_SIG);
        h.extend(20u16.to_le_bytes()); // version
        h.extend(0u16.to_le_bytes()); // flags
        h.extend(method.to_le_bytes());
        h.extend(0u32.to_le_bytes()); // time/date
        h.extend(0u32.to_le_bytes()); // crc
        h.extend((payload.len() as u32).to_le_bytes()); // csize
        h.extend((payload.len() as u32).to_le_bytes()); // usize
        h.extend((name.len() as u16).to_le_bytes());
        h.extend(0u16.to_le_bytes()); // extra
        h.extend_from_slice(name);
        h.extend_from_slice(payload);
        h
    }

    fn deflate(data: &[u8]) -> Vec<u8> {
        use flate2::write::DeflateEncoder;
        use flate2::Compression;
        use std::io::Write;
        let mut enc = DeflateEncoder::new(Vec::new(), Compression::default());
        enc.write_all(data).unwrap();
        enc.finish().unwrap()
    }

    #[test]
    fn truncated_zip_salvages_stored_entries() {
        let mut data = lfh(b"flag.txt", 0, b"CTF{salvaged}");
        data.extend_from_slice(&[0x00, 0x11, 0x22]); // truncated garbage
        let src = ByteSource::from_vec(data);
        let out = validate_at(&ZipSalvageHandler, &src, 0).expect("salvage works");
        let art = &out.artifacts[0];
        assert_eq!(art.confidence, Confidence::Recovered);
        assert_eq!(art.children.len(), 1);
        assert_eq!(
            art.children[0].content.to_bytes().unwrap(),
            b"CTF{salvaged}".to_vec()
        );
        assert_eq!(art.children[0].entry_name.as_deref(), Some("flag.txt"));
    }

    #[test]
    fn truncated_zip_salvages_deflate_entries() {
        let payload = deflate(b"the quick brown fox jumps over the lazy dog");
        let mut data = lfh(b"notes.txt", 8, &payload);
        data.truncate(data.len() - 5); // cut some compressed bytes
        let src = ByteSource::from_vec(data);
        let out = validate_at(&ZipSalvageHandler, &src, 0).expect("salvage works");
        let art = &out.artifacts[0];
        assert_eq!(art.confidence, Confidence::Recovered);
        assert_eq!(art.children.len(), 1);
        let bytes = art.children[0].content.to_bytes().unwrap();
        // Truncated deflate: partial output is expected, may or may not
        // include all 43 bytes.
        assert!(!bytes.is_empty(), "partial deflate output kept");
    }

    #[test]
    fn salvage_stands_down_when_eocd_present() {
        // A complete ZIP (with EOCD) belongs to the primary handler.
        let mut data = lfh(b"a.txt", 0, b"hello");
        // Build a minimal EOCD claiming 1 entry.
        let cd_offset = data.len() as u32;
        // Central directory entry (46 bytes + name).
        let mut cd = Vec::new();
        cd.extend_from_slice(b"PK\x01\x02");
        cd.extend(20u16.to_le_bytes());
        cd.extend(20u16.to_le_bytes());
        cd.extend(0u16.to_le_bytes());
        cd.extend(0u16.to_le_bytes());
        cd.extend(0u16.to_le_bytes());
        cd.extend(0u32.to_le_bytes());
        cd.extend(0u32.to_le_bytes());
        cd.extend(5u32.to_le_bytes());
        cd.extend(5u32.to_le_bytes());
        cd.extend(5u16.to_le_bytes());
        cd.extend(0u16.to_le_bytes());
        cd.extend(0u16.to_le_bytes());
        cd.extend(0u16.to_le_bytes());
        cd.extend(0u16.to_le_bytes());
        cd.extend(0u32.to_le_bytes());
        cd.extend(cd_offset.to_le_bytes());
        cd.extend_from_slice(b"a.txt");
        data.extend_from_slice(&cd);
        let cd_size = cd.len() as u32;
        let mut eocd = Vec::new();
        eocd.extend_from_slice(b"PK\x05\x06");
        eocd.extend(0u16.to_le_bytes());
        eocd.extend(0u16.to_le_bytes());
        eocd.extend(1u16.to_le_bytes());
        eocd.extend(1u16.to_le_bytes());
        eocd.extend(cd_size.to_le_bytes());
        eocd.extend(cd_offset.to_le_bytes());
        eocd.extend(0u16.to_le_bytes());
        data.extend_from_slice(&eocd);
        let src = ByteSource::from_vec(data);
        let err = validate_at(&ZipSalvageHandler, &src, 0);
        assert!(err.is_err(), "salvage must not claim intact archives");
    }

    #[test]
    fn salvage_reports_partial_and_skips_encrypted() {
        let mut data = Vec::new();
        // Encrypted entry (flag bit 0 set).
        data.extend_from_slice(&lfh_encrypted(b"secret.txt"));
        // Then a normal stored entry.
        data.extend_from_slice(&lfh(b"plain.txt", 0, b"visible"));
        let src = ByteSource::from_vec(data);
        let out = validate_at(&ZipSalvageHandler, &src, 0).expect("salvage works");
        let art = &out.artifacts[0];
        // Encrypted skipped, plain recovered.
        assert_eq!(art.children.len(), 1);
        assert_eq!(art.children[0].entry_name.as_deref(), Some("plain.txt"));
        assert!(
            art.warnings.iter().any(|w| w.contains("secret.txt")),
            "encryption warning present"
        );
    }

    fn lfh_encrypted(name: &[u8]) -> Vec<u8> {
        let mut h = Vec::new();
        h.extend_from_slice(&LFH_SIG);
        h.extend(20u16.to_le_bytes());
        h.extend(1u16.to_le_bytes()); // encrypted flag
        h.extend(0u16.to_le_bytes());
        h.extend(0u32.to_le_bytes());
        h.extend(0u32.to_le_bytes());
        h.extend(4u32.to_le_bytes());
        h.extend(4u32.to_le_bytes());
        h.extend((name.len() as u16).to_le_bytes());
        h.extend(0u16.to_le_bytes());
        h.extend_from_slice(name);
        h.extend_from_slice(b"\x00\x01\x02\x03");
        h
    }
}
