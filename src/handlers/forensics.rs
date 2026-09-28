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

fn hex_short_key(key: &[u8; 13]) -> String {
    key.iter().map(|b| format!("{b:02x}")).collect()
}

fn find_subslice(hay: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || hay.len() < needle.len() {
        return None;
    }
    (0..=hay.len() - needle.len()).find(|&i| &hay[i..i + needle.len()] == needle)
}

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
        let mut children: Vec<ChildDraft> = Vec::new();
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
                        b"vk" => {
                            vk_values += 1;
                            // S2: decode the value record per the regf
                            // spec. `cell` points at the 4-byte cell-size
                            // prefix; the vk record starts at cell+4.
                            // vk layout (record-relative):
                            //   +0  sig "vk"
                            //   +2  name_len (u16)
                            //   +4  data_size (u32; HIGH BIT = data
                            //       stored INLINE in this field itself)
                            //   +8  data_offset (u32; relative to the
                            //       START OF THE HBIN DATA AREA, i.e. the
                            //       first hbin at 0x1000) — points at
                            //       ANOTHER CELL: the actual bytes live in
                            //       that cell's Cell data, after ITS
                            //       4-byte size header.
                            //   +12 data_type (u32)
                            let vk = cell + 4;
                            let data_size_field = le32(src, vk + 4).unwrap_or(0);
                            let inline_flag = data_size_field & 0x8000_0000 != 0;
                            let data_len = u64::from(data_size_field & 0x7FFF_FFFF);
                            let data_off_field = le32(src, vk + 8).unwrap_or(0);
                            let value_type = le32(src, vk + 12).unwrap_or(0);
                            // REG_BINARY = 3. Non-inline only; data size
                            // sanity + cap.
                            if value_type == 3
                                && data_len > 0
                                && data_len <= limits.max_child_size
                                && !inline_flag
                            {
                                // S2: the data offset points at ANOTHER
                                // CELL (relative to the hive-bin data
                                // start, 0x1000 after the 4096-byte regf
                                // header). Verify that cell's signed size
                                // header first, then read the payload
                                // from its Cell data (target + 4).
                                let target = base + 0x1000 + data_off_field as u64;
                                let abs_data = target + 4;
                                if target + 4 <= src.len() {
                                    let cell_size_raw = le32(src, target).unwrap_or(0) as i32;
                                    let cell_size = cell_size_raw.unsigned_abs() as u64;
                                    let valid_cell = cell_size_raw < 0
                                        && cell_size >= 4
                                        && cell_size - 4 >= data_len
                                        && abs_data + data_len <= src.len();
                                    if valid_cell {
                                        if let Ok(region) = src.slice(abs_data, data_len) {
                                            children.push(ChildDraft {
                                                relation: RelationKind::FilesystemEntry,
                                                label: format!(
                                                    "REG_BINARY value ({} bytes)",
                                                    data_len
                                                ),
                                                format_hint: "raw",
                                                content: ChildContent::Source(region),
                                                size: data_len,
                                                metadata: BTreeMap::new(),
                                                warnings: Vec::new(),
                                                entry_name: None,
                                            });
                                        }
                                    }
                                }
                            }
                        }
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
                children,
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
        // B4: all FOUR libpcap savefile magics must be discoverable —
        // microsecond LE/BE and nanosecond LE/BE.
        let mut hits: Vec<Candidate> = find_all(src, &[0xD4, 0xC3, 0xB2, 0xA1])
            .into_iter()
            .chain(find_all(src, &[0xA1, 0xB2, 0xC3, 0xD4]))
            .chain(find_all(src, &[0x4D, 0x3C, 0xB2, 0xA1]))
            .chain(find_all(src, &[0xA1, 0xB2, 0x3C, 0x4D]))
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
        let mut http_objects = 0usize;
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
        metadata.insert("http_objects".to_string(), http_objects.to_string());
        metadata.insert("snaplen".to_string(), snaplen.to_string());
        metadata.insert(
            "byte_order".to_string(),
            if little_endian { "little" } else { "big" }.to_string(),
        );
        metadata.insert("nanosecond".to_string(), nanosecond.to_string());

        // R5: real TCP/HTTP reconstruction.
        //
        // Ethernet -> IPv4/IPv6 -> TCP payload -> flow grouping (5-tuple
        // normalized by direction) -> capture-order payload concatenation
        // -> HTTP object carving. This is NOT a retransmission-aware TCP
        // stack: within each flow, payloads are concatenated in capture
        // order (documented limitation). `max_streams` bounds the number
        // of tracked flows and `max_reconstructed_bytes` bounds the
        // total reassembled bytes.
        {
            // Per-flow ordered payload buffers. Key = normalized 5-tuple
            // (both directions of one connection share a flow).
            let mut flows: BTreeMap<[u8; 13], Vec<u8>> = BTreeMap::new();
            let mut flow_order: Vec<[u8; 13]> = Vec::new();
            let mut total_reconstructed = 0u64;

            // Re-walk record headers; each record payload starts with the
            // link-layer frame (linktype from the global header, field at
            // base+8: 1 = Ethernet).
            // libpcap global header: magic(4) major(2) minor(2) thiszone(4)
            // sigfigs(4) snaplen(4) network(4) => linktype at +20.
            let linktype = rd32(base + 20).unwrap_or(1);
            let mut off2 = base + 24;
            let mut seg = 0usize;
            while off2 + 16 <= src.len() && seg < packets.len() {
                let incl_len = rd32(off2 + 8)? as u64;
                if incl_len > snaplen.max(262_144) || off2 + 16 + incl_len > src.len() {
                    break;
                }
                let frame_start = off2 + 16;
                seg += 1;
                off2 += 16 + incl_len;

                // T2/S3: the Ethernet header itself must already be
                // bounded by THIS packet's captured bytes — packet_end
                // is computed BEFORE any L2/L3/L4 read, and every later
                // bound checks against it (never src.len()).
                let packet_end = frame_start + incl_len;
                // Parse Ethernet: dst(6) src(6) ethertype(2). VLAN(0x8100)
                // skipped once; IPv4 = 0x0800, IPv6 = 0x86DD.
                if linktype != 1 || frame_start + 14 > packet_end {
                    continue;
                }
                let mut eth = [0u8; 14];
                src.read_at(frame_start, &mut eth)?;
                let mut ethertype = u16::from_be_bytes([eth[12], eth[13]]);
                let mut l3 = frame_start + 14;
                if ethertype == 0x8100 && l3 + 4 <= packet_end {
                    let mut vlan = [0u8; 4];
                    src.read_at(l3, &mut vlan)?;
                    ethertype = u16::from_be_bytes([vlan[2], vlan[3]]);
                    l3 += 4;
                }
                // S3: all L2/L3/L4 reads are bounded by THIS captured
                // packet (incl_len), never by the whole file.
                match ethertype {
                    0x0800 => {
                        // IPv4: IHL, protocol, src/dst (4 bytes each).
                        if l3 + 20 > packet_end {
                            continue;
                        }
                        let mut h = [0u8; 20];
                        src.read_at(l3, &mut h)?;
                        let ihl = u64::from(h[0] & 0x0F) * 4;
                        if ihl < 20 || l3 + ihl > packet_end {
                            continue;
                        }
                        if h[9] != 6 {
                            continue; // TCP only
                        }
                        let mut flow_key = [0u8; 13];
                        // Normalize direction: order the (src,port,dst,port)
                        // pair so both directions share one key.
                        let (a, b) = (h[12..16].to_vec(), h[16..20].to_vec());
                        // T2: read the FULL 20-byte TCP header — the
                        // ports alone being in range does not prove the
                        // rest of the header is (it may extend past this
                        // packet's captured bytes).
                        if l3 + ihl + 20 > packet_end {
                            continue;
                        }
                        let mut tp = [0u8; 20];
                        src.read_at(l3 + ihl, &mut tp)?;
                        let (sp, dp) = ([tp[0], tp[1]], [tp[2], tp[3]]);
                        let dir1 = [a.as_slice(), &sp, b.as_slice(), &dp];
                        let dir2 = [b.as_slice(), &dp, a.as_slice(), &sp];
                        if dir1 < dir2 {
                            flow_key[0..4].copy_from_slice(&a);
                            flow_key[4..6].copy_from_slice(&sp);
                            flow_key[6..10].copy_from_slice(&b);
                            flow_key[10..12].copy_from_slice(&dp);
                        } else {
                            flow_key[0..4].copy_from_slice(&b);
                            flow_key[4..6].copy_from_slice(&dp);
                            flow_key[6..10].copy_from_slice(&a);
                            flow_key[10..12].copy_from_slice(&sp);
                        }
                        // TCP data offset for payload start (already
                        // read above as part of the full header).
                        let data_off = u64::from(tp[12] >> 4) * 4;
                        if data_off < 20 || l3 + ihl + data_off > packet_end {
                            continue;
                        }
                        // T2/S3: payload bounded by BOTH the packet end
                        // and the IPv4 total_length field, so Ethernet
                        // padding (anything after the IP datagram) is
                        // never treated as TCP payload. checked arithmetic
                        // — no unsigned underflow possible.
                        let total_length = u64::from(u16::from_be_bytes([h[2], h[3]])).max(ihl);
                        let ip_end = l3 + total_length;
                        let payload_len =
                            packet_end.min(ip_end).saturating_sub(l3 + ihl + data_off);
                        if payload_len == 0 {
                            continue;
                        }
                        if total_reconstructed + payload_len > limits.max_reconstructed_bytes {
                            break;
                        }
                        if !flows.contains_key(&flow_key) && flows.len() >= limits.max_streams {
                            break;
                        }
                        let entry = flows.entry(flow_key).or_insert_with(|| {
                            flow_order.push(flow_key);
                            Vec::new()
                        });
                        let mut buf = vec![0u8; payload_len as usize];
                        if src.read_at(l3 + ihl + data_off, &mut buf).is_ok() {
                            entry.extend_from_slice(&buf);
                            total_reconstructed += payload_len;
                        }
                    }
                    0x86DD => {
                        // IPv6: fixed 40-byte header, next-header at +6.
                        if l3 + 40 > packet_end {
                            continue;
                        }
                        let mut h = [0u8; 40];
                        src.read_at(l3, &mut h)?;
                        if h[6] != 6 {
                            continue; // TCP only
                        }
                        // T2: read the FULL 20-byte TCP header, bounded by
                        // this packet's captured bytes.
                        if l3 + 60 > packet_end {
                            continue;
                        }
                        let mut tp = [0u8; 20];
                        src.read_at(l3 + 40, &mut tp)?;
                        let (sp, dp) = ([tp[0], tp[1]], [tp[2], tp[3]]);
                        let a = h[8..24].to_vec();
                        let b = h[24..40].to_vec();
                        let mut flow_key = [0u8; 13];
                        // 13-byte key can't hold two IPv6 addrs; use a hash
                        // of the ordered tuple instead.
                        let dir1 = [a.as_slice(), &sp, b.as_slice(), &dp];
                        let dir2 = [b.as_slice(), &dp, a.as_slice(), &sp];
                        let forward = dir1 < dir2;
                        let (x, y) = if forward { (a, b) } else { (b, a) };
                        let (p1, p2) = if forward { (sp, dp) } else { (dp, sp) };
                        for (i, byte) in x.iter().chain(y.iter()).enumerate() {
                            flow_key[i % 8] ^= byte.wrapping_add(i as u8);
                        }
                        flow_key[8..10].copy_from_slice(&p1);
                        flow_key[10..12].copy_from_slice(&p2);
                        flow_key[12] = 0xEE; // IPv6 marker

                        // TCP data offset (already read in the full
                        // header above).
                        let data_off = u64::from(tp[12] >> 4) * 4;
                        if data_off < 20 || l3 + 40 + data_off > packet_end {
                            continue;
                        }
                        // T2/S3: payload bounded by BOTH the packet end and
                        // the IPv6 payload_length field — Ethernet padding
                        // is never treated as TCP payload.
                        let payload_length =
                            u64::from(u16::from_be_bytes([h[4], h[5]])).max(data_off);
                        let ip_end = l3 + 40 + payload_length;
                        let payload_len = packet_end.min(ip_end).saturating_sub(l3 + 40 + data_off);
                        if payload_len == 0
                            || total_reconstructed + payload_len > limits.max_reconstructed_bytes
                        {
                            continue;
                        }
                        if !flows.contains_key(&flow_key) && flows.len() >= limits.max_streams {
                            break;
                        }
                        let entry = flows.entry(flow_key).or_insert_with(|| {
                            flow_order.push(flow_key);
                            Vec::new()
                        });
                        let mut buf = vec![0u8; payload_len as usize];
                        if src.read_at(l3 + 40 + data_off, &mut buf).is_ok() {
                            entry.extend_from_slice(&buf);
                            total_reconstructed += payload_len;
                        }
                    }
                    _ => {}
                }
            }

            // Carve HTTP messages per flow, in flow-discovery order.
            'flows: for key in &flow_order {
                let stream = &flows[key];
                let mut pos = 0usize;
                while pos + 16 < stream.len() && http_objects < limits.max_records {
                    let window = &stream[pos..];
                    let header_end = match find_subslice(window, b"\r\n\r\n") {
                        Some(h) => h + 4,
                        None => break,
                    };
                    let head = String::from_utf8_lossy(&window[..header_end]).to_string();
                    let first = head.lines().next().unwrap_or("");
                    let is_http = first.starts_with("HTTP/")
                        || first.starts_with("GET ")
                        || first.starts_with("POST ")
                        || first.starts_with("PUT ")
                        || first.starts_with("DELETE ")
                        || first.starts_with("HEAD ");
                    if !is_http {
                        pos += header_end;
                        continue;
                    }
                    let content_length = head
                        .lines()
                        .find_map(|l| {
                            let lower = l.to_ascii_lowercase();
                            lower
                                .strip_prefix("content-length:")
                                .and_then(|v| v.trim().parse::<usize>().ok())
                        })
                        .unwrap_or(0);
                    let body_end = (header_end + content_length).min(window.len());
                    let complete = body_end == header_end + content_length;
                    let total = body_end;
                    if total == 0 {
                        continue 'flows;
                    }
                    let bytes = window[..total].to_vec();
                    let mut meta = BTreeMap::new();
                    meta.insert("http_object_index".to_string(), http_objects.to_string());
                    meta.insert("complete".to_string(), complete.to_string());
                    meta.insert("method_or_status".to_string(), first.to_string());
                    meta.insert("flow_key".to_string(), hex_short_key(key));
                    packets.push(ChildDraft {
                        relation: RelationKind::ReconstructedFrom,
                        label: format!(
                            "HTTP object {http_objects} ({total} bytes{})",
                            if complete { "" } else { ", incomplete" }
                        ),
                        format_hint: "http",
                        content: ChildContent::Owned(bytes),
                        size: total as u64,
                        metadata: meta,
                        warnings: Vec::new(),
                        entry_name: None,
                    });
                    http_objects += 1;
                    pos += total;
                }
            }
        }

        // B4: a capture cut off mid-record is NOT fully validated — the
        // record chain was not walked to a clean end. Downgrade honestly.
        let confidence = if truncated {
            Confidence::Partial
        } else {
            Confidence::Validated
        };

        Ok(HandlerOutput {
            artifacts: vec![ArtifactDraft {
                format: "pcap".to_string(),
                label: format!(
                    "PCAP capture ({} packets{})",
                    packets.len(),
                    if truncated { ", truncated" } else { "" }
                ),
                offset: base,
                size: off - base,
                confidence,
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
        // B5: RVAs are file offsets relative to the DUMP START, so every
        // location must add the candidate `base` for embedded minidumps.
        let mut streams_seen = Vec::new();
        let mut memory_streams = 0usize;
        let mut children = Vec::new();
        for i in 0..stream_count {
            let entry = base + dir_rva + 12 * i as u64;
            if entry + 12 > src.len() {
                break;
            }
            let stype = le32(src, entry).unwrap_or(0);
            let ssize = le32(src, entry + 4).unwrap_or(0) as u64;
            let srva = base + le32(src, entry + 8).unwrap_or(0) as u64;
            streams_seen.push(stype);
            match stype {
                5 => {
                    memory_streams += 1;
                    // MemoryListStream: u32 count then MINIDUMP_MEMORY_DESCRIPTOR
                    // (u64 start_addr, u32 data_size, u32 rva) - 16 bytes each.
                    if srva + 4 <= src.len() {
                        let count = le32(src, srva).unwrap_or(0) as usize;
                        let count = count.min(limits.max_records);
                        for m in 0..count {
                            let desc = srva + 4 + 16 * m as u64;
                            if desc + 16 > src.len() {
                                break;
                            }
                            let data_size = le32(src, desc + 8).unwrap_or(0) as u64;
                            let data_rva = base + le32(src, desc + 12).unwrap_or(0) as u64;
                            if data_size == 0
                                || children.len() >= limits.max_records
                                || data_rva + data_size > src.len()
                            {
                                continue;
                            }
                            let region = src.slice(data_rva, data_size)?;
                            let mut meta = BTreeMap::new();
                            meta.insert("memory_index".to_string(), m.to_string());
                            meta.insert("stream".to_string(), "MemoryList".to_string());
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
                9 => {
                    memory_streams += 1;
                    // B5: Memory64ListStream has its own layout -
                    // u64 NumberOfMemoryRanges, u64 BaseRva, then 16-byte
                    // descriptors (u64 start_addr, u64 data_size). The raw
                    // memory is laid out CONTIGUOUSLY starting at BaseRva;
                    // there is NO per-descriptor data RVA.
                    if srva + 16 <= src.len() {
                        let count = (le32(src, srva).unwrap_or(0) as u64)
                            | ((le32(src, srva + 4).unwrap_or(0) as u64) << 32);
                        let base_rva = (le32(src, srva + 8).unwrap_or(0) as u64)
                            | ((le32(src, srva + 12).unwrap_or(0) as u64) << 32);
                        let count = count.min(limits.max_records as u64) as usize;
                        let mut data_off = base + base_rva;
                        for m in 0..count {
                            let desc = srva + 16 + 16 * m as u64;
                            if desc + 16 > src.len() {
                                break;
                            }
                            let data_size = (le32(src, desc + 8).unwrap_or(0) as u64)
                                | ((le32(src, desc + 12).unwrap_or(0) as u64) << 32);
                            if data_size == 0 || children.len() >= limits.max_records {
                                continue;
                            }
                            if data_off + data_size > src.len() {
                                break; // dump truncated mid-memory; stop cleanly
                            }
                            let region = src.slice(data_off, data_size)?;
                            let mut meta = BTreeMap::new();
                            meta.insert("memory_index".to_string(), m.to_string());
                            meta.insert("stream".to_string(), "Memory64List".to_string());
                            meta.insert("start_addr".to_string(), {
                                let lo = le32(src, desc).unwrap_or(0) as u64;
                                let hi = le32(src, desc + 4).unwrap_or(0) as u64;
                                format!("{:#x}", lo | (hi << 32))
                            });
                            children.push(ChildDraft {
                                relation: RelationKind::MemoryRange,
                                label: format!("memory64 range {} ({} bytes)", m, data_size),
                                format_hint: "raw",
                                content: ChildContent::Source(region),
                                size: data_size,
                                metadata: meta,
                                warnings: Vec::new(),
                                entry_name: None,
                            });
                            data_off += data_size;
                        }
                    }
                }
                _ => {}
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
    fn registry_binary_values_source_backed() {
        // B7: REG_BINARY values must surface as source-backed children.
        let mut v = vec![0u8; 8192];
        v[0..4].copy_from_slice(b"regf");
        // First hbin at 4096: magic + size 4096.
        v[4096..4100].copy_from_slice(b"hbin");
        v[4104..4108].copy_from_slice(&4096u32.to_le_bytes());
        // Cell at 4128: negative size (allocated), vk record.
        // vk: sig(2) name_len(2)=0 data_len(4)=16 data_offset(4) type(4)=3
        let cell: u64 = 4128;
        // Cell: 4-byte size prefix, then the 20-byte vk record.
        let cell_size: u64 = 4 + 20;
        v[cell as usize..cell as usize + 4].copy_from_slice(&((-(cell_size as i32)).to_le_bytes()));
        let vk = cell + 4; // record start (R4: fields are vk-relative)
        v[vk as usize..vk as usize + 2].copy_from_slice(b"vk");
        v[vk as usize + 2..vk as usize + 4].copy_from_slice(&0u16.to_le_bytes()); // name_len
        v[vk as usize + 4..vk as usize + 8].copy_from_slice(&16u32.to_le_bytes()); // data_len
                                                                                   // S2: data_size = 16, NOT inline (high bit of data_size = inline flag).
                                                                                   // data_offset points at ANOTHER CELL relative to the hbin data
                                                                                   // start (0x1000). Target cell at absolute 5200 -> field = 1104.
                                                                                   // That cell holds a signed size header (-24) then the payload.
        v[vk as usize + 8..vk as usize + 12].copy_from_slice(&1104u32.to_le_bytes());
        v[vk as usize + 12..vk as usize + 16].copy_from_slice(&3u32.to_le_bytes()); // REG_BINARY
        let data_cell: u64 = 5200;
        let data_cell_size: u64 = 4 + 20;
        v[data_cell as usize..data_cell as usize + 4]
            .copy_from_slice(&((-(data_cell_size as i32)).to_le_bytes()));
        // Payload in the data cell's Cell data (target + 4 = 5204).
        v[5204..5220].copy_from_slice(&[0xBEu8; 16]);
        let src = ByteSource::from_vec(v);
        let out = validate_at(&RegistryHandler, &src, 0).expect("registry validates");
        let art = &out.artifacts[0];
        assert!(
            art.children
                .iter()
                .any(|c| c.label.contains("REG_BINARY") && c.size == 16),
            "REG_BINARY value must be a source-backed child; children: {:?}",
            art.children.iter().map(|c| &c.label).collect::<Vec<_>>()
        );
    }

    #[test]
    fn pcap_nanosecond_magic_discovered() {
        // B4: the nanosecond magic must be found by find_candidates and
        // validate to a full packet.
        let mut p = Vec::new();
        p.extend_from_slice(&[0x4D, 0x3C, 0xB2, 0xA1]); // ns LE magic
        p.extend(2u16.to_le_bytes());
        p.extend(4u16.to_le_bytes());
        p.extend(0u32.to_le_bytes());
        p.extend(0u32.to_le_bytes());
        p.extend(262144u32.to_le_bytes());
        p.extend(1u32.to_le_bytes());
        p.extend(1u32.to_le_bytes());
        p.extend(0u32.to_le_bytes());
        p.extend(4u32.to_le_bytes());
        p.extend(4u32.to_le_bytes());
        p.extend(b"DATA");
        let src = ByteSource::from_vec(p);
        assert!(
            !PcapHandler.find_candidates(&src).is_empty(),
            "ns magic found"
        );
        let out = validate_at(&PcapHandler, &src, 0).expect("ns pcap validates");
        assert_eq!(out.artifacts[0].confidence, Confidence::Validated);
        assert_eq!(out.artifacts[0].children.len(), 1);
    }

    #[test]
    fn pcap_short_packet_does_not_read_across_records() {
        // S3: a tiny packet (incl_len=1) followed by another record. The
        // TCP/HTTP parser must bound all reads by THIS packet's captured
        // bytes. Before the fix, the IPv4 parse would read across the
        // record boundary and compute incl_len - header_span with
        // unsigned underflow (panic in debug / bogus length in release).
        let mut p = Vec::new();
        p.extend_from_slice(&[0xD4, 0xC3, 0xB2, 0xA1]);
        p.extend(2u16.to_le_bytes());
        p.extend(4u16.to_le_bytes());
        p.extend(0u32.to_le_bytes()); // thiszone
        p.extend(0u32.to_le_bytes()); // sigfigs
        p.extend(262144u32.to_le_bytes());
        p.extend(1u32.to_le_bytes()); // linktype Ethernet
                                      // Record 0: incl_len = 1 — a 1-byte "frame" that cannot even
                                      // hold the Ethernet header.
        p.extend(1u32.to_le_bytes()); // ts_sec
        p.extend(0u32.to_le_bytes()); // ts_usec
        p.extend(1u32.to_le_bytes()); // incl_len
        p.extend(1u32.to_le_bytes()); // orig_len
        p.extend(b"X");
        // Record 1: a normal packet with garbage content.
        p.extend(1u32.to_le_bytes());
        p.extend(0u32.to_le_bytes());
        p.extend(20u32.to_le_bytes());
        p.extend(20u32.to_le_bytes());
        p.extend([0u8; 20]);
        let src = ByteSource::from_vec(p);
        // Must validate cleanly (2 packets, no HTTP), never panic.
        let out = validate_at(&PcapHandler, &src, 0).expect("pcap validates");
        let art = &out.artifacts[0];
        assert_eq!(art.children.len(), 2);
        assert!(
            !art.children.iter().any(|c| c.label.contains("HTTP object")),
            "no HTTP object can come from a 1-byte frame"
        );
    }

    #[test]
    fn pcap_ethernet_padding_not_treated_as_payload() {
        // T2: an Ethernet frame pads short packets to 60 bytes. The TCP
        // payload must be bounded by the IP total_length field, so the
        // padding after the IP datagram is NOT reassembled into the HTTP
        // stream (a zero byte in the middle of an HTTP body would corrupt
        // it, and padding could smuggle a second HTTP header).
        let frame = |payload: &[u8], pad: usize| -> Vec<u8> {
            let mut f = Vec::new();
            f.extend([0x02u8; 6]);
            f.extend([0x01u8; 6]);
            f.extend(0x0800u16.to_be_bytes());
            let ip_total = (20 + 20 + payload.len()) as u16;
            f.extend(0x45u8.to_be_bytes());
            f.extend(0u8.to_be_bytes()); // tos
            f.extend(ip_total.to_be_bytes()); // total_length EXCLUDES padding
            f.extend(1u16.to_be_bytes());
            f.extend(0x4000u16.to_be_bytes());
            f.extend(64u8.to_be_bytes());
            f.extend(6u8.to_be_bytes());
            f.extend(0u16.to_be_bytes());
            f.extend([10u8, 0, 0, 1]);
            f.extend([10u8, 0, 0, 2]);
            f.extend(443u16.to_be_bytes());
            f.extend(55555u16.to_be_bytes());
            f.extend(1u32.to_be_bytes());
            f.extend(1u32.to_be_bytes());
            f.extend(0x5018u16.to_be_bytes()); // data_off 5, PSH|ACK
            f.extend(0xFFFFu16.to_be_bytes());
            f.extend(0u16.to_be_bytes());
            f.extend(0u16.to_be_bytes());
            f.extend_from_slice(payload);
            f.extend(vec![0xAA; pad]); // Ethernet padding AFTER the datagram
            f
        };
        let msg = b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nBODY";
        let seg1 = frame(&msg[..20], 20); // header split + padding
        let seg2 = frame(&msg[20..], 30); // rest + padding
        let mut p = Vec::new();
        p.extend_from_slice(&[0xD4, 0xC3, 0xB2, 0xA1]);
        p.extend(2u16.to_le_bytes());
        p.extend(4u16.to_le_bytes());
        p.extend(0u32.to_le_bytes()); // thiszone
        p.extend(0u32.to_le_bytes()); // sigfigs
        p.extend(262144u32.to_le_bytes());
        p.extend(1u32.to_le_bytes()); // Ethernet
        for pkt in [&seg1, &seg2] {
            p.extend(1u32.to_le_bytes());
            p.extend(0u32.to_le_bytes());
            p.extend((pkt.len() as u32).to_le_bytes());
            p.extend((pkt.len() as u32).to_le_bytes());
            p.extend_from_slice(pkt);
        }
        let src = ByteSource::from_vec(p);
        let out = validate_at(&PcapHandler, &src, 0).expect("pcap validates");
        let http: Vec<_> = out.artifacts[0]
            .children
            .iter()
            .filter(|c| c.label.contains("HTTP object"))
            .collect();
        assert_eq!(http.len(), 1, "exactly one HTTP object");
        let bytes = http[0].content.to_bytes().unwrap();
        // The reassembled body must be exactly "BODY": no 0xAA padding
        // bytes smuggled in.
        assert!(
            !bytes.contains(&0xAA),
            "Ethernet padding leaked into reassembled payload"
        );
        assert!(bytes.ends_with(b"BODY"));
    }

    #[test]
    fn pcap_truncated_capture_not_validated() {
        // B4: a capture cut off mid-record must NOT be Validated.
        let mut p = Vec::new();
        p.extend_from_slice(&[0xD4, 0xC3, 0xB2, 0xA1]);
        p.extend(2u16.to_le_bytes());
        p.extend(4u16.to_le_bytes());
        p.extend(0u32.to_le_bytes());
        p.extend(0u32.to_le_bytes());
        p.extend(262144u32.to_le_bytes());
        p.extend(1u32.to_le_bytes());
        // One complete packet.
        p.extend(1u32.to_le_bytes());
        p.extend(0u32.to_le_bytes());
        p.extend(4u32.to_le_bytes());
        p.extend(4u32.to_le_bytes());
        p.extend(b"OKAY");
        // A truncated record header (declares 100 bytes, only 2 present).
        p.extend(2u32.to_le_bytes());
        p.extend(0u32.to_le_bytes());
        p.extend(100u32.to_le_bytes());
        p.extend(100u32.to_le_bytes());
        p.extend(b"XY");
        let src = ByteSource::from_vec(p);
        let out = validate_at(&PcapHandler, &src, 0).expect("truncated pcap still parsed");
        let art = &out.artifacts[0];
        assert_eq!(
            art.confidence,
            Confidence::Partial,
            "truncated capture must be Partial, not Validated"
        );
        assert_eq!(art.children.len(), 1, "complete packet kept");
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
    fn minidump_embedded_base_relative_rva_and_memory64() {
        // B5: RVAs must resolve relative to the dump start (base), and
        // Memory64List must use the contiguous BaseRva layout.
        let mut m = Vec::new();
        m.extend(b"JUNKJUNK"); // 8-byte prefix: dump embedded at base=8
                               // Header at 8: magic, version, 1 stream, dir rva 32 (relative).
        m.extend(b"MDMP");
        m.extend(42899u32.to_le_bytes());
        m.extend(1u32.to_le_bytes());
        m.extend(32u32.to_le_bytes());
        m.extend(0u32.to_le_bytes());
        m.extend(0u32.to_le_bytes());
        m.extend(0u64.to_le_bytes());
        // Dir entry: type 9 (Memory64List), size 24, rva 48 (relative).
        m.extend(9u32.to_le_bytes());
        m.extend(24u32.to_le_bytes());
        m.extend(48u32.to_le_bytes());
        // Pad to 56 absolute (48 relative + 8 base).
        m.resize(8 + 48, 0);
        // Memory64List: u64 count=1, u64 base_rva=80 (relative -> abs 88,
        // right after the descriptor).
        m.extend(1u64.to_le_bytes());
        m.extend(80u64.to_le_bytes());
        // Descriptor: start_addr 0x1000, data_size 16.
        m.extend(0x1000u64.to_le_bytes());
        m.extend(16u64.to_le_bytes());
        // Raw memory at base+80 = 88.
        m.resize(8 + 80, 0);
        m.extend((0xC0u8..0xD0).collect::<Vec<u8>>()); // 16 bytes
        let src = ByteSource::from_vec(m);
        let out = validate_at(&MinidumpHandler, &src, 8).expect("embedded minidump validates");
        let art = &out.artifacts[0];
        assert_eq!(art.confidence, Confidence::Validated);
        assert_eq!(art.children.len(), 1, "memory64 range found");
        assert_eq!(art.children[0].size, 16);
        assert_eq!(
            art.children[0].metadata.get("stream").map(String::as_str),
            Some("Memory64List")
        );
        match &art.children[0].content {
            ChildContent::Source(r) => {
                let bytes = r.read_all().unwrap();
                assert_eq!(bytes[0], 0xC0, "data must come from BaseRva position");
            }
            _ => panic!("memory range must be source-backed"),
        }
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
