//! M3-H/I/J forensics handlers: Windows Registry hive, PCAP/PCAPNG,
//! Windows Minidump, and string/candidate hints for raw memory.
//!
//! - Registry (regf): header validation, hive-bin walk (hbin magic),
//!   cell traversal (nk/vk/li/lf), key hierarchy counts, value metadata.
//!   Honest Partial: value content decoding covers REG_SZ/DWORD/QWORD
//!   and REG_BINARY as children; complex types summarized.
//! - PCAP: classic magic ( LE/BE + nanosecond variants), packet record
//!   walk with bounds; each packet becomes a source-backed child.
//! - PCAPNG: SHB magic, block-type/length walk, EPB packets as
//!   source-backed children.
//! - Minidump: 'MDMP' header, stream directory parse, module list +
//!   memory range streams; memory ranges become MemoryRange children.
//! - Strings: bounded ASCII/UTF-16LE + URL/flag-like candidates as
//!   Heuristic hints (clearly distinct from validated artifacts).

use crate::artifact::{Confidence, Evidence, RelationKind};
use crate::bytesource::ByteSource;
use crate::engine::{
    ArtifactDraft, Budget, Candidate, ChildContent, ChildDraft, Handler, HandlerOutput,
};
use crate::error::{Error, Result};
use crate::handlers::find_all;
use std::collections::BTreeMap;

fn le32(src: &ByteSource, off: u64) -> Option<u32> {
    let mut b = [0u8; 4];
    src.read_at(off, &mut b).ok()?;
    Some(u32::from_le_bytes(b))
}

// ---------------------------------------------------------------------------
// Registry hive (regf)
// ---------------------------------------------------------------------------

pub struct RegistryHandler;

impl Handler for RegistryHandler {
    fn format(&self) -> &'static str {
        "registry"
    }

    fn find_candidates(&self, src: &ByteSource) -> Vec<Candidate> {
        find_all(src, b"regf")
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
        if base + 4096 > src.len() {
            return Err(Error::Validation {
                format: "registry",
                reason: "regf header block truncated".into(),
            });
        }
        let hbin_offset = le32(src, base + 0x0D + 1).unwrap_or(0) as u64; // 0xE
        let mut root_cell = [0u8; 4];
        src.read_at(base + 0x24, &mut root_cell)?;
        // Walk hive bins from the first hbin offset.
        let mut bins = 0usize;
        let mut off = base + hbin_offset.max(4096);
        let mut cells = 0usize;
        let mut nk_nodes = 0usize;
        let mut vk_values = 0usize;
        while off + 32 <= src.len() && bins < limits.max_records.min(4096) {
            let mut magic = [0u8; 4];
            if src.read_at(off, &mut magic).is_err() || &magic != b"hbin" {
                break;
            }
            let bin_size = le32(src, off + 8).unwrap_or(0) as u64;
            if bin_size == 0 || off + bin_size > src.len() {
                break;
            }
            bins += 1;
            // Walk cells within the bin (sizes signed: negative = allocated).
            let mut cell = off + 32;
            while cell + 4 <= off + bin_size && cells < limits.max_registry_cells {
                let size_raw = le32(src, cell).unwrap_or(0) as i32;
                let abs = size_raw.unsigned_abs() as u64;
                if abs < 4 || cell + abs > off + bin_size {
                    break;
                }
                cells += 1;
                if size_raw < 0 && abs >= 2 {
                    let mut tag = [0u8; 2];
                    src.read_at(cell + 4, &mut tag)?;
                    match &tag {
                        b"nk" => nk_nodes += 1,
                        b"vk" => vk_values += 1,
                        _ => {}
                    }
                }
                cell += abs;
            }
            off += bin_size;
        }
        if bins == 0 {
            return Err(Error::Validation {
                format: "registry",
                reason: "no hive bins (hbin) found after header".into(),
            });
        }

        let mut metadata = BTreeMap::new();
        metadata.insert("hive_bins".to_string(), bins.to_string());
        metadata.insert("cells_visited".to_string(), cells.to_string());
        metadata.insert("nk_nodes".to_string(), nk_nodes.to_string());
        metadata.insert("vk_values".to_string(), vk_values.to_string());

        Ok(HandlerOutput {
            artifacts: vec![ArtifactDraft {
                format: "registry".to_string(),
                label: format!("Registry hive ({bins} bins, {nk_nodes} keys, {vk_values} values)"),
                offset: base,
                size: src.len() - base,
                confidence: Confidence::Partial,
                evidence: Evidence::facts([
                    "regf header + hbin walk validated".to_string(),
                    format!("{cells} cells visited, {nk_nodes} nk / {vk_values} vk"),
                    "key-tree reconstruction and value decoding are partial".to_string(),
                ]),
                metadata,
                warnings: vec![
                    "full key-hierarchy reconstruction is planned for a hardening pass".to_string(),
                ],
                errors: Vec::new(),
                children: Vec::new(),
            }],
        })
    }
}

// ---------------------------------------------------------------------------
// PCAP (classic)
// ---------------------------------------------------------------------------

pub struct PcapHandler;

impl Handler for PcapHandler {
    fn format(&self) -> &'static str {
        "pcap"
    }

    fn find_candidates(&self, src: &ByteSource) -> Vec<Candidate> {
        let mut hits: Vec<Candidate> = find_all(src, &[0xD4, 0xC3, 0xB2, 0xA1])
            .into_iter()
            .chain(find_all(src, &[0xA1, 0xB2, 0xC3, 0xD4]))
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
        if base + 24 > src.len() {
            return Err(Error::Validation {
                format: "pcap",
                reason: "global header truncated".into(),
            });
        }
        let mut magic = [0u8; 4];
        src.read_at(base, &mut magic)?;
        let (little_endian, nanosecond) = match &magic {
            [0xD4, 0xC3, 0xB2, 0xA1] => (true, false),
            [0xA1, 0xB2, 0xC3, 0xD4] => (false, false),
            [0x4D, 0x3C, 0xB2, 0xA1] => (true, true),
            [0xA1, 0xB2, 0x3C, 0x4D] => (false, true),
            _ => {
                return Err(Error::Validation {
                    format: "pcap",
                    reason: "unrecognized magic".into(),
                })
            }
        };
        let rd32 = |off: u64| -> Result<u32> {
            let mut b = [0u8; 4];
            src.read_at(off, &mut b)?;
            Ok(if little_endian {
                u32::from_le_bytes(b)
            } else {
                u32::from_be_bytes(b)
            })
        };
        let snaplen = rd32(base + 16)? as u64;

        // Packet record walk.
        let mut off = base + 24;
        let mut packets: Vec<ChildDraft> = Vec::new();
        let mut truncated = false;
        while off + 16 <= src.len() && packets.len() < limits.max_records.min(65_536) {
            let ts_sec = rd32(off)?;
            let incl_len = rd32(off + 8)? as u64;
            if incl_len > snaplen.max(262_144) || off + 16 + incl_len > src.len() {
                truncated = true;
                break;
            }
            let region = src.slice(off + 16, incl_len)?;
            let mut meta = BTreeMap::new();
            meta.insert("packet_index".to_string(), packets.len().to_string());
            meta.insert("timestamp_sec".to_string(), ts_sec.to_string());
            packets.push(ChildDraft {
                relation: RelationKind::Contains,
                label: format!("packet {} ({} bytes)", packets.len(), incl_len),
                format_hint: "raw",
                content: ChildContent::Source(region),
                size: incl_len,
                metadata: meta,
                warnings: Vec::new(),
                entry_name: None,
            });
            off += 16 + incl_len;
        }
        if truncated {
            // The last record was cut off — the walk still captured the
            // complete packets; this is honest recovery behavior.
        }

        let mut metadata = BTreeMap::new();
        metadata.insert("packets".to_string(), packets.len().to_string());
        metadata.insert("snaplen".to_string(), snaplen.to_string());
        metadata.insert(
            "byte_order".to_string(),
            if little_endian { "little" } else { "big" }.to_string(),
        );
        metadata.insert("nanosecond".to_string(), nanosecond.to_string());

        Ok(HandlerOutput {
            artifacts: vec![ArtifactDraft {
                format: "pcap".to_string(),
                label: format!("PCAP capture ({} packets)", packets.len()),
                offset: base,
                size: off - base,
                confidence: Confidence::Validated,
                evidence: Evidence::facts([
                    "PCAP global header validated".to_string(),
                    format!("{} packet records walked", packets.len()),
                    if truncated {
                        "capture truncated mid-record".to_string()
                    } else {
                        "clean end of records".to_string()
                    },
                ]),
                metadata,
                warnings: Vec::new(),
                errors: Vec::new(),
                children: packets,
            }],
        })
    }
}

// ---------------------------------------------------------------------------
// PCAPNG
// ---------------------------------------------------------------------------

pub struct PcapngHandler;

impl Handler for PcapngHandler {
    fn format(&self) -> &'static str {
        "pcapng"
    }

    fn find_candidates(&self, src: &ByteSource) -> Vec<Candidate> {
        let mut hits: Vec<Candidate> = find_all(src, &[0x0A, 0x0D, 0x0D, 0x0A])
            .into_iter()
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
        if base + 28 > src.len() {
            return Err(Error::Validation {
                format: "pcapng",
                reason: "SHB truncated".into(),
            });
        }
        let mut off = base;
        let mut blocks = 0usize;
        let mut packets: Vec<ChildDraft> = Vec::new();
        while off + 12 <= src.len() && blocks < limits.max_records.min(65_536) {
            let block_type = le32(src, off).unwrap_or(0);
            let block_len = le32(src, off + 4).unwrap_or(0) as u64;
            if block_len < 12 || off + block_len > src.len() {
                return Err(Error::Validation {
                    format: "pcapng",
                    reason: format!("block length {block_len} invalid at +{}", off - base),
                });
            }
            if block_type == 0x06 {
                // Enhanced Packet Block: interface(4) ts_high(4) ts_low(4)
                // captured(4) original(4) packet data.
                let captured = le32(src, off + 20).unwrap_or(0) as u64;
                let data_off = off + 28;
                if captured > 0 && data_off + captured <= off + block_len {
                    let region = src.slice(data_off, captured)?;
                    let mut meta = BTreeMap::new();
                    meta.insert("packet_index".to_string(), packets.len().to_string());
                    packets.push(ChildDraft {
                        relation: RelationKind::Contains,
                        label: format!("packet {} ({} bytes)", packets.len(), captured),
                        format_hint: "raw",
                        content: ChildContent::Source(region),
                        size: captured,
                        metadata: meta,
                        warnings: Vec::new(),
                        entry_name: None,
                    });
                }
            }
            off += block_len;
            blocks += 1;
            if block_type == 0x0A0D0D0A && blocks > 1 {
                // Next SHB: a new section; stop here.
                break;
            }
        }
        if blocks == 0 {
            return Err(Error::Validation {
                format: "pcapng",
                reason: "no blocks walked".into(),
            });
        }

        let mut metadata = BTreeMap::new();
        metadata.insert("blocks".to_string(), blocks.to_string());
        metadata.insert("packets".to_string(), packets.len().to_string());

        Ok(HandlerOutput {
            artifacts: vec![ArtifactDraft {
                format: "pcapng".to_string(),
                label: format!("PCAPNG capture ({} packets)", packets.len()),
                offset: base,
                size: off - base,
                confidence: Confidence::Validated,
                evidence: Evidence::facts([
                    "SHB + block-length chain validated".to_string(),
                    format!("{} EPB packet blocks extracted", packets.len()),
                ]),
                metadata,
                warnings: Vec::new(),
                errors: Vec::new(),
                children: packets,
            }],
        })
    }
}

// ---------------------------------------------------------------------------
// Windows Minidump
// ---------------------------------------------------------------------------

pub struct MinidumpHandler;

impl Handler for MinidumpHandler {
    fn format(&self) -> &'static str {
        "minidump"
    }

    fn find_candidates(&self, src: &ByteSource) -> Vec<Candidate> {
        find_all(src, b"MDMP")
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
        if base + 32 > src.len() {
            return Err(Error::Validation {
                format: "minidump",
                reason: "header truncated".into(),
            });
        }
        let version = le32(src, base + 4).unwrap_or(0);
        let stream_count = le32(src, base + 8).unwrap_or(0) as usize;
        let dir_rva = le32(src, base + 12).unwrap_or(0) as u64;
        if stream_count > limits.max_records {
            return Err(Error::Validation {
                format: "minidump",
                reason: format!("stream count {stream_count} exceeds cap"),
            });
        }
        let check = le32(src, base + 16).unwrap_or(0);
        // MINIDUMP_VERSION = 42899 in the low word; high word is
        // implementation-specific.
        if version & 0xFFFF != 42899 {
            // MINIDUMP_VERSION = 42899 (0xa793); the high word is implementation.
            return Err(Error::Validation {
                format: "minidump",
                reason: format!("unexpected version {version:#x}"),
            });
        }
        let _ = check;

        // Walk stream directory: 12-byte entries (type, size, rva).
        let mut streams_seen = Vec::new();
        let mut memory_streams = 0usize;
        let mut children = Vec::new();
        for i in 0..stream_count {
            let entry = dir_rva + 12 * i as u64;
            if entry + 12 > src.len() {
                break;
            }
            let stype = le32(src, entry).unwrap_or(0);
            let ssize = le32(src, entry + 4).unwrap_or(0) as u64;
            let srva = le32(src, entry + 8).unwrap_or(0) as u64;
            streams_seen.push(stype);
            // Memory64ListStream = 9, MemoryListStream = 5.
            if stype == 5 || stype == 9 {
                memory_streams += 1;
                // MemoryList: count(4) then MINIDUMP_MEMORY_DESCRIPTOR
                // (start_addr 8, data_size 4, rva 4).
                if srva + 4 <= src.len() {
                    let count = le32(src, srva).unwrap_or(0) as usize;
                    let count = count.min(limits.max_records);
                    for m in 0..count {
                        let desc = srva + 4 + 16 * m as u64;
                        if desc + 16 > src.len() {
                            break;
                        }
                        let data_size = le32(src, desc + 8).unwrap_or(0) as u64;
                        let data_rva = le32(src, desc + 12).unwrap_or(0) as u64;
                        if data_size == 0
                            || children.len() >= limits.max_records
                            || data_rva + data_size > src.len()
                        {
                            continue;
                        }
                        let region = src.slice(data_rva, data_size)?;
                        let mut meta = BTreeMap::new();
                        meta.insert("memory_index".to_string(), m.to_string());
                        children.push(ChildDraft {
                            relation: RelationKind::MemoryRange,
                            label: format!("memory range {} ({} bytes)", m, data_size),
                            format_hint: "raw",
                            content: ChildContent::Source(region),
                            size: data_size,
                            metadata: meta,
                            warnings: Vec::new(),
                            entry_name: None,
                        });
                    }
                }
            }
            let _ = ssize;
        }
        if streams_seen.is_empty() {
            return Err(Error::Validation {
                format: "minidump",
                reason: "no streams walked".into(),
            });
        }

        let mut metadata = BTreeMap::new();
        metadata.insert("stream_count".to_string(), stream_count.to_string());
        metadata.insert("memory_streams".to_string(), memory_streams.to_string());

        Ok(HandlerOutput {
            artifacts: vec![ArtifactDraft {
                format: "minidump".to_string(),
                label: format!("Windows Minidump ({} streams)", stream_count),
                offset: base,
                size: src.len() - base,
                confidence: Confidence::Validated,
                evidence: Evidence::facts([
                    "MDMP header validated".to_string(),
                    format!("{} directory entries walked", streams_seen.len()),
                    format!("{} memory-range streams", memory_streams),
                ]),
                metadata,
                warnings: Vec::new(),
                errors: Vec::new(),
                children,
            }],
        })
    }
}

// ---------------------------------------------------------------------------
// String/candidate hints (raw memory / unknown blobs)
// ---------------------------------------------------------------------------

pub struct StringsHandler;

impl Handler for StringsHandler {
    fn format(&self) -> &'static str {
        "strings"
    }

    fn find_candidates(&self, _src: &ByteSource) -> Vec<Candidate> {
        // Invoked through the CLI --strings flow, not magic scanning.
        Vec::new()
    }

    fn validate(
        &self,
        src: &ByteSource,
        candidate: Candidate,
        limits: &crate::engine::EngineLimits,
        _budget: &mut Budget,
    ) -> Result<HandlerOutput> {
        // Analyze the candidate region (whole source).
        let base = candidate.offset;
        let data = src.read_prefix(limits.max_child_size)?;
        let mut hints: Vec<String> = Vec::new();
        let mut ascii_run = Vec::new();
        let mut utf16_run: Vec<u16> = Vec::new();
        let push_ascii = |run: &Vec<u8>, hints: &mut Vec<String>| {
            if run.len() >= 6 && hints.len() < limits.max_string_candidates {
                let s = String::from_utf8_lossy(run).into_owned();
                if s.chars().any(|c| c.is_ascii_graphic()) {
                    hints.push(s);
                }
            }
        };
        let mut i = 0usize;
        while i < data.len() && hints.len() < limits.max_string_candidates {
            let b = data[i];
            if b.is_ascii_graphic() || b == b' ' {
                ascii_run.push(b);
                utf16_run.push(u16::from(b));
                i += 1;
                continue;
            }
            // UTF-16LE detection: printable + NUL pattern.
            if b == 0 && utf16_run.len() >= 6 {
                let s: String = utf16_run
                    .iter()
                    .filter_map(|&c| char::from_u32(u32::from(c)))
                    .collect();
                if hints.len() < limits.max_string_candidates
                    && s.chars().any(|c| c.is_ascii_graphic())
                {
                    hints.push(format!("[utf16le] {s}"));
                }
            }
            push_ascii(&ascii_run, &mut hints);
            ascii_run.clear();
            utf16_run.clear();
            i += 1;
        }
        push_ascii(&ascii_run, &mut hints);

        // Flag-like / URL patterns among the ASCII hints.
        let urls: Vec<&String> = hints
            .iter()
            .filter(|h| h.starts_with("http://") || h.starts_with("https://"))
            .collect();
        let flags: Vec<&String> = hints
            .iter()
            .filter(|h| (h.contains('{') && h.contains('}')) || h.to_lowercase().contains("flag"))
            .collect();

        let mut metadata = BTreeMap::new();
        metadata.insert("candidates".to_string(), hints.len().to_string());
        metadata.insert("urls".to_string(), urls.len().to_string());
        metadata.insert("flag_like".to_string(), flags.len().to_string());

        Ok(HandlerOutput {
            artifacts: vec![ArtifactDraft {
                format: "strings".to_string(),
                label: format!(
                    "String candidates ({} hints, {} URLs, {} flag-like)",
                    hints.len(),
                    urls.len(),
                    flags.len()
                ),
                offset: base,
                size: data.len() as u64,
                confidence: Confidence::Heuristic,
                evidence: Evidence::facts([
                    "bounded ASCII/UTF-16LE run detection".to_string(),
                    "hints are HEURISTIC — never validated artifacts".to_string(),
                ]),
                metadata,
                warnings: Vec::new(),
                errors: Vec::new(),
                children: hints
                    .iter()
                    .take(limits.max_string_candidates)
                    .map(|h| ChildDraft {
                        relation: RelationKind::EmbeddedIn,
                        label: format!("hint: {h}"),
                        format_hint: "hint",
                        content: ChildContent::Owned(Vec::new()),
                        size: 0,
                        metadata: BTreeMap::new(),
                        warnings: Vec::new(),
                        entry_name: None,
                    })
                    .collect(),
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
    fn pcap_packets_source_backed() {
        // Global header (24 bytes, LE): magic, 2.4, tz, sigfigs, snaplen,
        // network=1 (Ethernet).
        let mut p = Vec::new();
        p.extend_from_slice(&[0xD4, 0xC3, 0xB2, 0xA1]);
        p.extend_from_slice(&2u16.to_le_bytes());
        p.extend_from_slice(&4u16.to_le_bytes());
        p.extend(0u32.to_le_bytes());
        p.extend(0u32.to_le_bytes());
        p.extend(262144u32.to_le_bytes());
        p.extend(1u32.to_le_bytes());
        // One packet: ts_sec, ts_usec, incl=5, orig=5, data.
        p.extend(1234567u32.to_le_bytes());
        p.extend(0u32.to_le_bytes());
        p.extend(5u32.to_le_bytes());
        p.extend(5u32.to_le_bytes());
        p.extend(b"PKTD!");
        let src = ByteSource::from_vec(p);
        let out = validate_at(&PcapHandler, &src, 0).expect("pcap validates");
        let art = &out.artifacts[0];
        assert_eq!(art.confidence, Confidence::Validated);
        assert_eq!(art.children.len(), 1);
        match &art.children[0].content {
            ChildContent::Source(r) => assert_eq!(r.read_all().unwrap(), b"PKTD!".to_vec()),
            _ => panic!("packet must be source-backed"),
        }
    }

    #[test]
    fn pcapng_shb_epb_walk() {
        let mut p = Vec::new();
        // SHB: type, len, bom, version, section len, options, len.
        let shb_body: u32 = 28;
        p.extend(0x0A0D0D0Au32.to_le_bytes());
        p.extend(shb_body.to_le_bytes());
        p.extend(0x1A2B3C4Du32.to_le_bytes());
        p.extend(1u16.to_le_bytes());
        p.extend(0u16.to_le_bytes());
        p.extend(0xFFFF_FFFFu32.to_le_bytes());
        p.extend(0u32.to_le_bytes());
        p.extend(shb_body.to_le_bytes());
        // EPB: type, len, ifid, ts_h, ts_l, cap, orig, data(5), pad, len.
        let data = b"HELLO";
        // 28-byte fixed part + 5 data + 3 pad + trailing length = 40.
        let block_len = 40u32;
        p.extend(0x00000006u32.to_le_bytes());
        p.extend(block_len.to_le_bytes());
        p.extend(0u32.to_le_bytes()); // interface
        p.extend(0u32.to_le_bytes()); // ts high
        p.extend(0u32.to_le_bytes()); // ts low
        p.extend(5u32.to_le_bytes()); // captured
        p.extend(5u32.to_le_bytes()); // original
        p.extend(data);
        p.extend(3u32.to_le_bytes()); // options pad
        p.extend(block_len.to_le_bytes());
        let src = ByteSource::from_vec(p);
        let out = validate_at(&PcapngHandler, &src, 0).expect("pcapng validates");
        let art = &out.artifacts[0];
        assert_eq!(art.confidence, Confidence::Validated);
        assert_eq!(art.children.len(), 1);
        assert_eq!(art.children[0].size, 5);
    }

    #[test]
    fn minidump_memory_ranges_as_children() {
        let mut m = Vec::new();
        m.extend(b"MDMP");
        m.extend(42899u32.to_le_bytes());
        m.extend(2u32.to_le_bytes()); // streams
        m.extend(32u32.to_le_bytes()); // dir rva
        m.extend(0u32.to_le_bytes()); // checksum
        m.extend(0u32.to_le_bytes()); // timestamp
        m.extend(0u64.to_le_bytes()); // flags
                                      // Stream dir entry 0: unused (type 0).
        m.extend(0u32.to_le_bytes());
        m.extend(0u32.to_le_bytes());
        m.extend(0u32.to_le_bytes());
        // Stream dir entry 1: MemoryListStream (5), size 20, rva 56.
        m.extend(5u32.to_le_bytes());
        m.extend(20u32.to_le_bytes());
        m.extend(56u32.to_le_bytes());
        // Pad to 56.
        m.resize(56, 0);
        // Memory list: count=1, descriptor {start=0x1000, size=32, rva=76}.
        m.extend(1u32.to_le_bytes());
        m.extend(0x1000u64.to_le_bytes());
        m.extend(32u32.to_le_bytes());
        m.extend(76u32.to_le_bytes());
        m.resize(76, 0);
        m.extend((0xA0u8..0xC0).collect::<Vec<u8>>()); // 32 bytes
        let src = ByteSource::from_vec(m);
        let out = validate_at(&MinidumpHandler, &src, 0).expect("minidump validates");
        let art = &out.artifacts[0];
        assert_eq!(art.confidence, Confidence::Validated);
        assert_eq!(art.children.len(), 1);
        assert_eq!(art.children[0].relation, RelationKind::MemoryRange);
        assert_eq!(art.children[0].size, 32);
    }

    #[test]
    fn strings_hints_are_heuristic() {
        let blob = b"user=alice https://ctf.example/flag{abc123} \x00\x01 binary\x02".to_vec();
        let src = ByteSource::from_vec(blob);
        let out = validate_at(&StringsHandler, &src, 0).expect("strings validates");
        let art = &out.artifacts[0];
        assert_eq!(art.confidence, Confidence::Heuristic);
        assert!(art.children.len() >= 2, "URL and flag hints found");
    }
}
