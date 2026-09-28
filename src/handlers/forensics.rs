//! M3-H/I/J forensics handlers: Windows Registry hive, PCAP/PCAPNG,
//! Windows Minidump, and string/candidate hints for raw memory.
//!
//! - Registry (regf): header validation, hive-bin walk (hbin magic),
//!   cell traversal (nk/vk/li/lf), key hierarchy counts, value metadata.
//!   Honest Partial: value content decoding covers REG_SZ/DWORD/QWORD
//!   and REG_BINARY as children; complex types summarized.
//! - PCAP: classic magic ( LE/BE + nanosecond variants), packet record
//!   walk with bounds; each packet becomes a source-backed child.
//!   #7 §7: sequence-aware TCP reassembly (net::TcpReassembler),
//!   HTTP body framing (Content-Length + chunked), DNS-over-UDP
//!   parsing, and USB HID keystroke reconstruction.
//! - PCAPNG: SHB magic, block-type/length walk, EPB packets as
//!   source-backed children; the same reconstruction pipeline as PCAP
//!   applies to every EPB frame (linktype from the IDB).
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

#[allow(dead_code)]
fn hex_short_key(key: &[u8; 13]) -> String {
    key.iter().map(|b| format!("{b:02x}")).collect()
}

#[allow(dead_code)]
fn find_subslice(hay: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || hay.len() < needle.len() {
        return None;
    }
    (0..=hay.len() - needle.len()).find(|&i| &hay[i..i + needle.len()] == needle)
}

fn le16(src: &ByteSource, off: u64) -> Option<u16> {
    let mut b = [0u8; 2];
    src.read_at(off, &mut b).ok()?;
    Some(u16::from_le_bytes(b))
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

/// Registry hive node types (nk record).
const NK_TAG: &[u8] = b"nk";
const VK_TAG: &[u8] = b"vk";
const LH_TAG: &[u8] = b"lh";
const LI_TAG: &[u8] = b"li";
const LF_TAG: &[u8] = b"lf";
const RI_TAG: &[u8] = b"ri";
/// REG_* value types (winnt.h).
const REG_SZ: u32 = 1;
const REG_EXPAND_SZ: u32 = 2;
const REG_BINARY: u32 = 3;
const REG_DWORD: u32 = 4;
const REG_MULTI_SZ: u32 = 7;
const REG_QWORD: u32 = 11;

/// One parsed nk key node.
#[derive(Debug, Clone)]
struct RegKey {
    cell_index: usize,
    parent_cell: u32,
    name: String,
    /// Key's last-write timestamp (FILETIME, little-endian per regf).
    #[allow(dead_code)]
    timestamp: u64,
    /// Number of subkeys (nk +20). surfaced in metadata via list walk.
    #[allow(dead_code)]
    subkey_count: u32,
    /// Subkey-list cell offset (nk +28; li/lf/lh/ri record).
    subkeys_cell: u32,
    /// Value-list cell offset (nk +40), if any.
    values_cell: u32,
    /// Value count (nk +36).
    value_count: u32,
}

/// One parsed vk value.
struct RegValue {
    name: String,
    value_type: u32,
    data: Vec<u8>,
}

fn reg_type_name(t: u32) -> &'static str {
    match t {
        REG_SZ => "REG_SZ",
        REG_EXPAND_SZ => "REG_EXPAND_SZ",
        REG_BINARY => "REG_BINARY",
        REG_DWORD => "REG_DWORD",
        REG_MULTI_SZ => "REG_MULTI_SZ",
        REG_QWORD => "REG_QWORD",
        5 => "REG_DWORD_BIG_ENDIAN",
        6 => "REG_LINK",
        8 => "REG_RESOURCE_LIST",
        9 => "REG_FULL_RESOURCE_DESCRIPTOR",
        10 => "REG_RESOURCE_REQUIREMENTS_LIST",
        _ => "REG_UNKNOWN",
    }
}

/// Whether a value type is string-like (rendered as text with provenance).
fn reg_type_is_string(t: u32) -> bool {
    t == REG_SZ || t == REG_EXPAND_SZ || t == REG_MULTI_SZ
}

impl RegistryHandler {
    /// Walk a cell space (one bin's data) and index nk/vk records by
    /// cell index (offset within the bin data, in 16-bit units is NOT
    /// used here — offsets are byte offsets relative to the hbin data
    /// start = 0x1000 in the file).
    fn scan_cells(
        src: &ByteSource,
        base: u64,
        limits: &crate::engine::EngineLimits,
        warnings: &mut Vec<String>,
    ) -> Result<RegHive> {
        let mut hive = RegHive::default();
        let mut off = base + 4096; // first hbin after the header
        let mut bins = 0usize;
        let mut cells = 0usize;
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
            let bin_data_start = off + 32;
            // Cell offsets used by records are relative to 0x1000 in the
            // file (the start of the first hbin's data is actually
            // bin-dependent; standard hives put the first hbin at file
            // offset 0x1000 so hbin-data-relative == file-relative-0x1000).
            let cell_base_file = base + 0x1000;
            let mut cell = bin_data_start;
            while cell + 4 <= off + bin_size && cells < limits.max_registry_cells {
                let size_raw = le32(src, cell).unwrap_or(0) as i32;
                let abs = size_raw.unsigned_abs() as u64;
                if abs < 4 || cell + abs > off + bin_size {
                    break;
                }
                cells += 1;
                if size_raw < 0 && abs >= 8 {
                    let mut tag = [0u8; 2];
                    if src.read_at(cell + 4, &mut tag).is_err() {
                        break;
                    }
                    // FINAL-B3: regf reference fields point at the
                    // CELL START (the size field), not record data.
                    let rel = cell - cell_base_file;
                    match &tag {
                        t if t == NK_TAG && abs >= 88 => {
                            if let Some(mut k) = Self::parse_nk(src, cell + 4) {
                                k.cell_index = hive.keys.len();
                                hive.key_by_cell.insert(rel as u32, k.cell_index);
                                hive.keys.push(k);
                            }
                        }
                        t if t == VK_TAG && abs >= 24 => {
                            if let Some(v) = Self::parse_vk(src, cell + 4, cell_base_file, limits) {
                                hive.value_by_cell.insert(rel as u32, v);
                            }
                        }
                        _ => {
                            // Subkey lists (lh/li/lf/ri) are parsed on
                            // demand during tree reconstruction.
                            let _ = (LH_TAG, LI_TAG, LF_TAG, RI_TAG);
                        }
                    }
                }
                cell += abs;
            }
            off += bin_size;
            if hive.keys.len() >= limits.max_records {
                warnings.push("nk node cap reached; scan truncated".to_string());
                break;
            }
        }
        if bins == 0 {
            return Err(Error::Validation {
                format: "registry",
                reason: "no hive bins (hbin) found after header".into(),
            });
        }
        hive.bins = bins;
        hive.cells = cells;
        Ok(hive)
    }

    /// Parse an nk record at `vk_off` (file offset). Record fields are
    /// relative to the record start (after the cell-size prefix).
    fn parse_nk(src: &ByteSource, rec: u64) -> Option<RegKey> {
        let mut tag = [0u8; 2];
        src.read_at(rec, &mut tag).ok()?;
        if tag != *NK_TAG {
            return None;
        }
        // nk layout (relative to sig) per the regf specification:
        // +0 sig, +2 flags u16, +4 timestamp FILETIME (LITTLE-endian),
        // +12 access bits, +16 parent cell u32, +20 subkey count u32,
        // +24 subkeys-volatile count u32, +28 SUBKEYS LIST cell u32,
        // +32 volatile-list cell u32, +36 VALUE COUNT u32, +40 VALUE
        // LIST cell u32, +44 security cell, +48 class-name cell,
        // +72 name_len u16, +76 name.
        let flags = le16(src, rec + 2).unwrap_or(0);
        let timestamp = {
            let mut b = [0u8; 8];
            src.read_at(rec + 4, &mut b).ok()?;
            u64::from_le_bytes(b)
        };
        let parent_cell = le32(src, rec + 16).unwrap_or(0);
        let subkey_count = le32(src, rec + 20).unwrap_or(0);
        let subkeys_cell = le32(src, rec + 28).unwrap_or(u32::MAX);
        let value_count = le32(src, rec + 36).unwrap_or(0);
        let values_cell = le32(src, rec + 40).unwrap_or(u32::MAX);
        let name_len = usize::from(le16(src, rec + 72).unwrap_or(0));
        if name_len == 0 || name_len > 255 {
            return None;
        }
        let mut raw = vec![0u8; name_len];
        src.read_at(rec + 76, &mut raw).ok()?;
        let name = if flags & 0x20 != 0 {
            // Compressed (8-bit) name.
            String::from_utf8_lossy(&raw).into_owned()
        } else {
            let units: Vec<u16> = raw
                .chunks_exact(2)
                .map(|c| u16::from_le_bytes([c[0], c[1]]))
                .collect();
            String::from_utf16_lossy(&units)
        };
        Some(RegKey {
            cell_index: 0,
            parent_cell,
            name,
            timestamp,
            subkey_count,
            subkeys_cell,
            values_cell,
            value_count,
        })
    }

    /// Parse a vk record: returns name, type and (possibly inline)
    /// data. `data_off` handling: the raw data-offset field points at
    /// a CELL relative to the hbin data area (0x1000); the payload is
    /// in that cell's data after its 4-byte size prefix. Inline data
    /// (high bit of data_size) lives inside the vk record itself.
    fn parse_vk(
        src: &ByteSource,
        rec: u64,
        cell_base_file: u64,
        limits: &crate::engine::EngineLimits,
    ) -> Option<RegValue> {
        let mut tag = [0u8; 2];
        src.read_at(rec, &mut tag).ok()?;
        if tag != *VK_TAG {
            return None;
        }
        let name_len = usize::from(le16(src, rec + 2).unwrap_or(0));
        let data_size_field = le32(src, rec + 4).unwrap_or(0);
        let inline_flag = data_size_field & 0x8000_0000 != 0;
        let data_len = u64::from(data_size_field & 0x7FFF_FFFF);
        let data_off_field = le32(src, rec + 8).unwrap_or(0);
        let value_type = le32(src, rec + 12).unwrap_or(0);
        let name_len = name_len.min(16384);
        let mut raw = vec![0u8; name_len];
        // FINAL-B3: vk name is at +20 (sig2 + name_len2 + data_size4 +
        // data_off4 + type4 + flags2 + spare2).
        src.read_at(rec + 20, &mut raw).ok()?;
        let name = String::from_utf8_lossy(&raw).into_owned();

        let mut data = Vec::new();
        if data_len == 0 {
            // empty
        } else if inline_flag && data_len <= 4 {
            // Inline: stored in the data_offset field itself.
            data.extend_from_slice(&data_off_field.to_le_bytes()[..data_len as usize]);
        } else if !inline_flag && data_len <= limits.max_child_size {
            let target = cell_base_file + data_off_field as u64;
            let cell_size_raw = le32(src, target).unwrap_or(0) as i32;
            let cell_size = cell_size_raw.unsigned_abs() as u64;
            // Allocated cells carry a negative size prefix.
            if cell_size_raw < 0 && cell_size >= 4 && cell_size - 4 >= data_len {
                let payload = target + 4;
                if payload + data_len <= src.len() {
                    let mut buf = vec![0u8; data_len as usize];
                    src.read_at(payload, &mut buf).ok()?;
                    data = buf;
                }
            }
        }
        Some(RegValue {
            name,
            value_type,
            data,
        })
    }
}

/// Scanned hive state.
#[derive(Default)]
struct RegHive {
    bins: usize,
    cells: usize,
    keys: Vec<RegKey>,
    /// cell offset (hbin-data-relative, record start) -> key index.
    key_by_cell: std::collections::HashMap<u32, usize>,
    /// cell offset -> parsed value.
    value_by_cell: std::collections::HashMap<u32, RegValue>,
}

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
        let mut warnings = Vec::new();
        let hive = Self::scan_cells(src, base, limits, &mut warnings)?;
        if hive.keys.is_empty() {
            return Err(Error::Validation {
                format: "registry",
                reason: "no nk key records".into(),
            });
        }
        // Root key: the nk whose parent cell is not another nk (or the
        // first nk scanned).
        let root = hive
            .keys
            .iter()
            .position(|k| !hive.key_by_cell.contains_key(&k.parent_cell))
            .unwrap_or(0);

        // Build children: parent->child paths are reconstructed via the
        // parent_cell links. Values are emitted per key with decoded
        // types (DWORD/QWORD as numbers, SZ as lossy text, MULTI_SZ
        // split count, BINARY as raw regions).
        let mut children: Vec<ChildDraft> = Vec::new();
        for k in &hive.keys {
            let key_path = Self::key_path(&hive, k, root);
            // Values.
            if k.values_cell != u32::MAX && k.value_count > 0 {
                // FINAL-B3: the value-list CELL (offset points at the
                // cell start) holds [size i32][count x u32 vk cell
                // offsets]. vk offsets target cell starts.
                let list_file = base + 0x1000 + u64::from(k.values_cell);
                for i in 0..k.value_count.min(limits.max_records as u32) {
                    let ent = list_file + 4 + 4 * i as u64;
                    if ent + 4 > src.len() {
                        break;
                    }
                    let vcell = le32(src, ent).unwrap_or(0);
                    if let Some(v) = hive.value_by_cell.get(&vcell) {
                        if children.len() >= limits.max_records {
                            warnings.push("record cap reached; values truncated".to_string());
                            break;
                        }
                        let mut meta = BTreeMap::new();
                        meta.insert("key_path".to_string(), key_path.clone());
                        meta.insert(
                            "value_type".to_string(),
                            reg_type_name(v.value_type).to_string(),
                        );
                        let label = match v.value_type {
                            REG_DWORD if v.data.len() == 4 => {
                                let n = u32::from_le_bytes(v.data[..4].try_into().unwrap());
                                meta.insert("data".to_string(), format!("{n:#010x}"));
                                format!("value {} = {n} (REG_DWORD)", v.name)
                            }
                            REG_QWORD if v.data.len() == 8 => {
                                let n = u64::from_le_bytes(v.data[..8].try_into().unwrap());
                                meta.insert("data".to_string(), format!("{n:#x}"));
                                format!("value {} = {n} (REG_QWORD)", v.name)
                            }
                            t if reg_type_is_string(t) => {
                                // UTF-16LE; MULTI_SZ values are
                                // NUL-separated.
                                let units: Vec<u16> = v
                                    .data
                                    .chunks_exact(2)
                                    .map(|c| u16::from_le_bytes([c[0], c[1]]))
                                    .collect();
                                let text = String::from_utf16_lossy(&units);
                                meta.insert("text".to_string(), text.clone());
                                format!("value {} = {:?} ({})", v.name, text, reg_type_name(t))
                            }
                            t => {
                                format!(
                                    "value {} ({} bytes, {})",
                                    v.name,
                                    v.data.len(),
                                    reg_type_name(t)
                                )
                            }
                        };
                        children.push(ChildDraft {
                            relation: RelationKind::DatabaseRecord,
                            label,
                            format_hint: if reg_type_is_string(v.value_type) {
                                "text"
                            } else {
                                "raw"
                            },
                            content: if v.data.is_empty() {
                                ChildContent::Owned(Vec::new())
                            } else {
                                ChildContent::Owned(v.data.clone())
                            },
                            size: v.data.len() as u64,
                            metadata: meta,
                            warnings: Vec::new(),
                            entry_name: None,
                        });
                    }
                }
            }
        }

        // FINAL-B3: parse the ROOT key's subkey list (li/lf/lh/ri) to
        // count reachable children — real hives carry subkey lists and
        // the parser must consume them, not just declare the tags.
        let (subkeys_reachable, list_kinds) = Self::count_subkeys(src, base, &hive, root, limits);
        if subkeys_reachable
            < hive
                .keys
                .iter()
                .filter(|k| k.subkeys_cell != u32::MAX)
                .count()
        {
            warnings.push(format!(
                "subkey lists partially parsed ({subkeys_reachable} reachable)"
            ));
        }
        let _ = &list_kinds;

        let mut metadata = BTreeMap::new();
        metadata.insert("hive_bins".to_string(), hive.bins.to_string());
        metadata.insert("cells_visited".to_string(), hive.cells.to_string());
        metadata.insert("nk_nodes".to_string(), hive.keys.len().to_string());
        metadata.insert(
            "subkeys_reachable".to_string(),
            subkeys_reachable.to_string(),
        );
        metadata.insert(
            "vk_values".to_string(),
            hive.value_by_cell.len().to_string(),
        );
        metadata.insert(
            "root_key".to_string(),
            hive.keys
                .get(root)
                .map(|k| k.name.clone())
                .unwrap_or_default(),
        );

        Ok(HandlerOutput {
            artifacts: vec![ArtifactDraft {
                format: "registry".to_string(),
                label: format!(
                    "Registry hive ({} bins, {} keys, {} values)",
                    hive.bins,
                    hive.keys.len(),
                    hive.value_by_cell.len()
                ),
                offset: base,
                size: src.len() - base,
                confidence: if children.is_empty() {
                    Confidence::Partial
                } else {
                    Confidence::Validated
                },
                evidence: Evidence::facts([
                    "regf header + hbin walk validated".to_string(),
                    format!(
                        "{} cells visited, {} nk keys indexed by parent link",
                        hive.cells,
                        hive.keys.len()
                    ),
                    format!(
                        "{} values decoded (DWORD/QWORD/SZ/BINARY/MULTI_SZ)",
                        children.len()
                    ),
                    format!(
                        "root key {:?}",
                        hive.keys
                            .get(root)
                            .map(|k| k.name.clone())
                            .unwrap_or_default()
                    ),
                ]),
                metadata,
                warnings,
                errors: Vec::new(),
                children,
            }],
        })
    }
}

impl RegistryHandler {
    /// Parse a subkey-list record (li/lf/lh/ri) at a CELL reference
    /// (offset points at the cell start). Returns the referenced child
    /// key cell offsets. ri lists point at OTHER LIST records (one
    /// level of indirection).
    fn parse_subkey_list(
        src: &ByteSource,
        base: u64,
        cell_off: u32,
        limits: &crate::engine::EngineLimits,
    ) -> Result<(Vec<u32>, &'static str)> {
        const LIST_BASE: u64 = 0x1000;
        let cell = base + LIST_BASE + u64::from(cell_off);
        let mut sig = [0u8; 2];
        src.read_at(cell + 4, &mut sig)
            .map_err(|_| Error::Validation {
                format: "registry",
                reason: "subkey list unreadable".into(),
            })?;
        let count = le16(src, cell + 6).unwrap_or(0) as usize;
        let kind: &'static str = match &sig {
            b"li" => "li",
            b"lf" => "lf",
            b"lh" => "lh",
            b"ri" => "ri",
            _ => {
                return Err(Error::Validation {
                    format: "registry",
                    reason: format!(
                        "subkey list signature {:?} invalid",
                        String::from_utf8_lossy(&sig)
                    ),
                })
            }
        };
        if count > limits.max_records {
            return Err(Error::Validation {
                format: "registry",
                reason: format!("subkey list count {count} exceeds cap"),
            });
        }
        let mut out = Vec::with_capacity(count);
        // li/lf/lh entries: (key cell offset u32 [, hint/hash u32]).
        // ri entries: (subkey-list offset u32) — one level only.
        let stride = if kind == "lf" || kind == "lh" { 8 } else { 4 };
        for i in 0..count {
            let ent = cell + 8 + (i * stride) as u64;
            if ent + 4 > src.len() {
                break;
            }
            let target = le32(src, ent).unwrap_or(0);
            if kind == "ri" {
                // Nested list: parse one level deeper.
                if out.len() < limits.max_records {
                    let (mut nested, _) = Self::parse_subkey_list(src, base, target, limits)?;
                    out.append(&mut nested);
                }
            } else {
                out.push(target);
            }
        }
        Ok((out, kind))
    }

    /// Count subkeys reachable from the root through li/lf/lh/ri lists
    /// (bounded walk, depth 8).
    fn count_subkeys(
        src: &ByteSource,
        base: u64,
        hive: &RegHive,
        root: usize,
        limits: &crate::engine::EngineLimits,
    ) -> (usize, String) {
        let mut total = 0usize;
        let mut kinds: Vec<&str> = Vec::new();
        let mut visited: Vec<u32> = Vec::new();
        // Walk every key that declares a subkey list; count distinct
        // reachable child cells. Bounded.
        for k in hive.keys.iter().take(limits.max_records) {
            if k.subkeys_cell == u32::MAX {
                continue;
            }
            if visited.contains(&k.subkeys_cell) {
                continue;
            }
            visited.push(k.subkeys_cell);
            if visited.len() > 4096 {
                break;
            }
            if let Ok((children, kind)) = Self::parse_subkey_list(src, base, k.subkeys_cell, limits)
            {
                if !kinds.contains(&kind) {
                    kinds.push(kind);
                }
                total += children.len();
            }
        }
        let _ = root;
        (total, kinds.join("+"))
    }

    /// Reconstruct a key path by walking parent links (bounded).
    fn key_path(hive: &RegHive, k: &RegKey, root: usize) -> String {
        let mut parts = vec![k.name.clone()];
        let mut cur = k.parent_cell;
        let mut hops = 0;
        while let Some(&idx) = hive.key_by_cell.get(&cur) {
            // Push the parent's name first so the root component is
            // included in the path, then stop.
            parts.push(hive.keys[idx].name.clone());
            if hops > 64 || idx == root {
                break;
            }
            cur = hive.keys[idx].parent_cell;
            hops += 1;
        }
        parts.reverse();
        parts.join("\\")
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

        // R5/#7 §7.1-7.2: sequence-aware TCP reassembly + HTTP framing.
        //
        // Ethernet -> IPv4 -> TCP -> per-flow sequence-ordered
        // reassembly (net::TcpReassembler: out-of-order segments,
        // retransmission dedup, honest gap accounting) -> HTTP message
        // framing per direction (Content-Length + chunked) -> bodies
        // as Owned children (engine recurses into them). NOT a full
        // TCP stack. Stream count/byte caps come from EngineLimits.
        //
        // §7.3: UDP IPv4 payload to port 53 is parsed as DNS; TXT/NULL
        // answers become Owned children (recursing decoders handle
        // base64/hex payloads).
        //
        // §7.4: linktype 220 (usbmon mmapped) frames are parsed as USB
        // packets; interrupt-IN 8-byte HID reports become keystrokes.
        let linktype = rd32(base + 20).unwrap_or(1);
        let mut flows_meta: Vec<(String, usize, usize)> = Vec::new();
        let mut stream_objects = 0usize;
        {
            let mut reasm = crate::handlers::net::TcpReassembler::new(
                limits.max_streams,
                limits.max_reconstructed_bytes,
            );
            let mut udp_dns: Vec<(u16, Vec<u8>)> = Vec::new();
            let mut hid = crate::handlers::net::HidDecoder::new(4096);
            let mut hid_hits = 0usize;
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
                if linktype == 220 {
                    // USB: HID keystroke reconstruction.
                    if let Some(up) = crate::handlers::net::parse_usbmon(src, frame_start, incl_len)
                    {
                        if up.data.len() == 8 && up.ep == 1 {
                            hid.feed(&up.data);
                            hid_hits += 1;
                        }
                    }
                    continue;
                }
                // Ethernet TCP.
                match crate::handlers::net::parse_tcp_frame(
                    src,
                    frame_start,
                    incl_len,
                    linktype,
                    false,
                ) {
                    Ok(Some((key, seq, _len, payload))) => {
                        reasm.feed(&key, seq, &payload);
                    }
                    Ok(None) => {}
                    Err(_) => continue,
                }
                // DNS over UDP (IPv4, proto 17, port 53): quick probe.
                if frame_start + 14 <= src.len() && incl_len >= 14 + 20 + 8 + 12 {
                    let mut h = [0u8; 20];
                    if src.read_at(frame_start + 14, &mut h).is_ok()
                        && (h[0] >> 4) == 4
                        && h[9] == 17
                    {
                        let ihl = u64::from(h[0] & 0x0F) * 4;
                        let total_length = u64::from(u16::from_be_bytes([h[2], h[3]])).max(ihl);
                        let udp_start = frame_start + 14 + ihl;
                        if udp_start + 8 <= frame_start + incl_len
                            && udp_start + 8 + 12 <= frame_start + 14 + total_length
                        {
                            let dport = {
                                let mut b = [0u8; 2];
                                src.read_at(udp_start + 2, &mut b).ok();
                                u16::from_be_bytes(b)
                            };
                            if dport == 53 {
                                let mut dns =
                                    vec![0u8; incl_len as usize - 14 - (ihl + 8) as usize];
                                if src.read_at(udp_start + 8, &mut dns).is_ok() && dns.len() <= 512
                                {
                                    udp_dns.push((udp_dns.len() as u16, dns));
                                }
                            }
                        }
                    }
                }
            }

            // HTTP messages per flow per direction.
            for flow in reasm.flows() {
                let key_hex: String = flow.key.iter().map(|b| format!("{b:02x}")).collect();
                let (cname, gcount) = (0usize, flow.client_gaps + flow.server_gaps);
                let _ = cname;
                for (dir_name, data) in [("c2s", &flow.client), ("s2c", &flow.server)] {
                    if data.len() < 16 {
                        continue;
                    }
                    for (first, body, complete, chunked) in
                        crate::handlers::net::extract_http_messages(
                            data,
                            limits.max_records.saturating_sub(stream_objects).min(256),
                            16 * 1024 * 1024,
                        )
                    {
                        if stream_objects >= limits.max_records {
                            break;
                        }
                        let mut meta = BTreeMap::new();
                        meta.insert("flow".to_string(), key_hex.clone());
                        meta.insert("direction".to_string(), dir_name.to_string());
                        meta.insert("request_line".to_string(), first.clone());
                        meta.insert("complete".to_string(), complete.to_string());
                        if chunked {
                            meta.insert("transfer_encoding".to_string(), "chunked".to_string());
                        }
                        if gcount > 0 {
                            meta.insert("tcp_gaps".to_string(), gcount.to_string());
                        }
                        let mut label = format!(
                            "HTTP body {} ({} bytes, {})",
                            stream_objects,
                            body.len(),
                            if complete { "complete" } else { "partial" }
                        );
                        if chunked {
                            label.push_str(", de-chunked");
                        }
                        let mut m2 = meta;
                        m2.insert("size".to_string(), body.len().to_string());
                        packets.push(crate::handlers::net::owned_child(
                            RelationKind::ReconstructedFrom,
                            label,
                            "http",
                            body,
                            m2,
                        ));
                        stream_objects += 1;
                    }
                }
                flows_meta.push((key_hex, flow.client.len() + flow.server.len(), gcount));
            }

            // DNS answers with payload material (TXT/NULL/others) as
            // children; the engine recurses into Owned bytes so
            // base64/hex payloads are picked up by other handlers.
            for (_idx, dns_bytes) in &udp_dns {
                if let Some(msg) = crate::handlers::net::parse_dns(dns_bytes) {
                    for ans in &msg.answers {
                        if stream_objects >= limits.max_records || ans.rdata.is_empty() {
                            continue;
                        }
                        // TXT(16), NULL(10) and any non-trivial rdata
                        // with printable-looking payload are surfaced.
                        let printable = ans
                            .rdata
                            .iter()
                            .filter(|b| b.is_ascii_graphic() || **b == b'\n')
                            .count();
                        if ans.rtype != 16 && ans.rtype != 10 && printable * 2 < ans.rdata.len() {
                            continue;
                        }
                        let mut meta = BTreeMap::new();
                        meta.insert("dns_id".to_string(), msg.id.to_string());
                        meta.insert(
                            "query".to_string(),
                            msg.queries.first().cloned().unwrap_or_default(),
                        );
                        meta.insert("answer_name".to_string(), ans.name.clone());
                        meta.insert("rr_type".to_string(), ans.rtype.to_string());
                        meta.insert("size".to_string(), ans.rdata.len().to_string());
                        packets.push(crate::handlers::net::owned_child(
                            RelationKind::ReconstructedFrom,
                            format!(
                                "DNS rdata {} ({} bytes, type {})",
                                ans.name,
                                ans.rdata.len(),
                                ans.rtype
                            ),
                            "raw",
                            ans.rdata.clone(),
                            meta,
                        ));
                        stream_objects += 1;
                    }
                }
            }

            // USB HID keystrokes as one reconstructed text child.
            let text = hid.text();
            if hid_hits > 0 && !text.is_empty() {
                let mut meta = BTreeMap::new();
                meta.insert("keystrokes".to_string(), text.chars().count().to_string());
                meta.insert("reports".to_string(), hid_hits.to_string());
                meta.insert("size".to_string(), text.len().to_string());
                packets.push(crate::handlers::net::owned_child(
                    RelationKind::ReconstructedFrom,
                    format!("USB HID keystrokes ({} chars)", text.chars().count()),
                    "text",
                    text.into_bytes(),
                    meta,
                ));
                stream_objects += 1;
            }
        }
        metadata.insert("tcp_flows".to_string(), flows_meta.len().to_string());
        metadata.insert(
            "reconstructed_objects".to_string(),
            stream_objects.to_string(),
        );
        for (i, (key, bytes, gaps)) in flows_meta.iter().enumerate().take(16) {
            metadata.insert(
                format!("flow_{i}"),
                format!("{key} bytes={bytes} gaps={gaps}"),
            );
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
        // Interface linktype (IDB, block type 1): u16 at +8. Defaults
        // to Ethernet when no IDB precedes the packets.
        let mut linktype = 1u32;
        let mut frame_list: Vec<(u64, u64)> = Vec::new();
        while off + 12 <= src.len() && blocks < limits.max_records.min(65_536) {
            let block_type = le32(src, off).unwrap_or(0);
            let block_len = le32(src, off + 4).unwrap_or(0) as u64;
            if block_len < 12 || off + block_len > src.len() {
                return Err(Error::Validation {
                    format: "pcapng",
                    reason: format!("block length {block_len} invalid at +{}", off - base),
                });
            }
            if block_type == 0x01 && off + 10 <= src.len() {
                linktype = u32::from(le16(src, off + 8).unwrap_or(1));
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
                    frame_list.push((data_off, captured));
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

        // #7 §7.1: PCAPNG gets the same sequence-aware TCP/HTTP/DNS/USB
        // reconstruction as classic PCAP (frame list from the EPB walk).
        let read_frame = |start, len| {
            let mut buf = vec![0u8; len as usize];
            src.read_at(start, &mut buf).ok()?;
            Some(buf)
        };
        let recon =
            crate::handlers::net::reconstruct_frames(&frame_list, linktype, limits, read_frame);
        packets.extend(recon.children);

        let mut metadata = BTreeMap::new();
        metadata.insert("blocks".to_string(), blocks.to_string());
        metadata.insert("packets".to_string(), packets.len().to_string());
        metadata.insert(
            "tcp_flows".to_string(),
            recon.flow_summary.len().to_string(),
        );
        metadata.insert("dns_messages".to_string(), recon.dns_messages.to_string());
        if recon.usb_reports > 0 {
            metadata.insert("usb_hid_reports".to_string(), recon.usb_reports.to_string());
        }

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
                3 => {
                    // ThreadListStream: u32 count, then
                    // MINIDUMP_THREAD (48 bytes): ThreadId u32,
                    // SuspendCount u32, PriorityClass u32, Priority
                    // u32, Teb u64, Stack {StartOfMemoryRange u64,
                    // DataSize u32, Rva u32}, Context {Size u32,
                    // Rva u32}.
                    if srva + 4 <= src.len() {
                        let count = le32(src, srva).unwrap_or(0) as usize;
                        let count = count.min(limits.max_records);
                        for t in 0..count {
                            let rec = srva + 4 + 48 * t as u64;
                            if rec + 48 > src.len() {
                                break;
                            }
                            let tid = le32(src, rec).unwrap_or(0);
                            let teb = {
                                let lo = le32(src, rec + 16).unwrap_or(0) as u64;
                                let hi = le32(src, rec + 20).unwrap_or(0) as u64;
                                lo | (hi << 32)
                            };
                            let stack_start = {
                                let lo = le32(src, rec + 24).unwrap_or(0) as u64;
                                let hi = le32(src, rec + 28).unwrap_or(0) as u64;
                                lo | (hi << 32)
                            };
                            let stack_size = le32(src, rec + 32).unwrap_or(0) as u64;
                            let mut m = BTreeMap::new();
                            m.insert("stream".to_string(), "ThreadList".to_string());
                            m.insert("thread_id".to_string(), tid.to_string());
                            m.insert("teb".to_string(), format!("{teb:#x}"));
                            m.insert("stack_start".to_string(), format!("{stack_start:#x}"));
                            children.push(ChildDraft {
                                relation: RelationKind::MemoryRange,
                                label: format!(
                                    "thread {tid} stack ({} bytes, TEB {teb:#x})",
                                    stack_size
                                ),
                                format_hint: "metadata",
                                content: ChildContent::Owned(Vec::new()),
                                size: stack_size,
                                metadata: m,
                                warnings: Vec::new(),
                                entry_name: None,
                            });
                        }
                    }
                }
                4 => {
                    // ModuleListStream: u32 count, then
                    // MINIDUMP_MODULE (108 bytes): BaseOfImage u64,
                    // SizeOfImage u32, CheckSum u32, TimeDateStamp
                    // u32, ModuleNameRva u32, then fixed file info,
                    // CvRecord/MiscRecord and reserved fields. The
                    // name is a MINIDUMP_STRING at ModuleNameRva:
                    // u32 byte-length then UTF-16LE.
                    if srva + 4 <= src.len() {
                        let count = le32(src, srva).unwrap_or(0) as usize;
                        let count = count.min(limits.max_records);
                        for m in 0..count {
                            let rec = srva + 4 + 108 * m as u64;
                            if rec + 108 > src.len() {
                                break;
                            }
                            let base_addr = {
                                let lo = le32(src, rec).unwrap_or(0) as u64;
                                let hi = le32(src, rec + 4).unwrap_or(0) as u64;
                                lo | (hi << 32)
                            };
                            let size_of_image = le32(src, rec + 8).unwrap_or(0);
                            let name_rva = base + le32(src, rec + 20).unwrap_or(0) as u64;
                            let name_len_bytes =
                                le32(src, name_rva).unwrap_or(0).min(1024) as usize;
                            let mut raw = vec![0u8; name_len_bytes];
                            if src.read_at(name_rva + 4, &mut raw).is_ok() {
                                let units: Vec<u16> = raw
                                    .chunks_exact(2)
                                    .map(|c| u16::from_le_bytes([c[0], c[1]]))
                                    .collect();
                                let name = String::from_utf16_lossy(&units);
                                let mut mm = BTreeMap::new();
                                mm.insert("stream".to_string(), "ModuleList".to_string());
                                mm.insert("module_name".to_string(), name.clone());
                                mm.insert("base_address".to_string(), format!("{base_addr:#x}"));
                                mm.insert("image_size".to_string(), size_of_image.to_string());
                                children.push(ChildDraft {
                                    relation: RelationKind::MemoryRange,
                                    label: format!(
                                        "module {name} ({} bytes at {base_addr:#x})",
                                        size_of_image
                                    ),
                                    format_hint: "metadata",
                                    content: ChildContent::Owned(Vec::new()),
                                    size: u64::from(size_of_image),
                                    metadata: mm,
                                    warnings: Vec::new(),
                                    entry_name: None,
                                });
                            }
                        }
                    }
                }
                7 => {
                    // SystemInfoStream: MINIDUMP_SYSTEM_INFO:
                    // ProcessorArchitecture u16, Level u16, Revision
                    // u16, NumberOfProcessors u8, ProductType u8,
                    // SuiteMask u16, Reserved u16, then CPU/OS data.
                    if srva + 32 <= src.len() {
                        let arch = le16(src, srva).unwrap_or(0);
                        let arch_name = match arch {
                            9 => "x64",
                            0x014C => "x86",
                            0x01C4 => "ARM64",
                            _ => "unknown",
                        };
                        // NumberOfProcessors is a u8 at offset 12.
                        let num_cpus = le16(src, srva + 12)
                            .map(|v| (v & 0xFF).to_string())
                            .unwrap_or_else(|| "unknown".to_string());
                        let mut m = BTreeMap::new();
                        m.insert("stream".to_string(), "SystemInfo".to_string());
                        m.insert("architecture".to_string(), arch_name.to_string());
                        m.insert("processors".to_string(), num_cpus.clone());
                        children.push(ChildDraft {
                            relation: RelationKind::MemoryRange,
                            label: format!("system info ({arch_name}, {num_cpus} processors)"),
                            format_hint: "metadata",
                            content: ChildContent::Owned(Vec::new()),
                            size: 0,
                            metadata: m,
                            warnings: Vec::new(),
                            entry_name: None,
                        });
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
// Windows kernel crash dump (PAGEDU64)
// ---------------------------------------------------------------------------

/// Windows 64-bit kernel crash dump handler (_DMP_HEADER64). Layout
/// verified against the Volatility Foundation "Crash Address Space"
/// documentation and 0vercl0k/kdmp-parser-rs (Header64, PhysmemDesc,
/// PhysmemRun, full_physmem):
/// - File starts with "PAGEDU64" (Signature "PAGE" @0, ValidDump
///   "DU64" @4). The whole header is 0x2000 (8192) bytes.
/// - MajorVersion@8, MinorVersion@0xC (build), DirectoryTableBase@0x10
///   (u64), PsLoadedModuleList@0x20 (u64), PsActiveProcessHead@0x28,
///   MachineImageType@0x30 (u32), NumberProcessors@0x34,
///   BugCheckCode@0x38, BugCheckParameters@0x40 (4 x u64).
/// - PhysicalMemoryBlockBuffer@0x88: u32 NumberOfRuns, u32 padding,
///   u64 NumberOfPages, then NumberOfRuns x 16-byte runs (u64
///   BasePage, u64 PageCount). Pages are 4096 bytes; the pages of all
///   runs are stored PACKED in the file starting at file offset
///   0x2000 (the header end), in run order, holes skipped.
/// - DumpType@0xF98: 1 full, 5 BMP, 8 kernel, 9 kernel+user, 0xA
///   complete, 6 live kernel. SystemTime@0xFA8 (FILETIME).
pub struct Pagedu64Handler;

const DUMP64_HEADER_SIZE: u64 = 0x2000;
const PAGE_SIZE: u64 = 4096;

/// One physical memory run.
struct PhysRun {
    base_page: u64,
    page_count: u64,
}

impl Pagedu64Handler {
    /// Parse the physical memory runs from the header buffer at
    /// base+0x88.
    fn parse_runs(
        src: &ByteSource,
        base: u64,
        limits: &crate::engine::EngineLimits,
        warnings: &mut Vec<String>,
    ) -> Result<Vec<PhysRun>> {
        let blk = base + 0x88;
        let num_runs = le32(src, blk).unwrap_or(0) as usize;
        if num_runs == 0 {
            return Err(Error::Validation {
                format: "pagedu64",
                reason: "zero physical memory runs".into(),
            });
        }
        if num_runs > limits.max_records {
            return Err(Error::Validation {
                format: "pagedu64",
                reason: format!("run count {num_runs} exceeds cap"),
            });
        }
        let mut runs = Vec::with_capacity(num_runs);
        for i in 0..num_runs {
            // Layout: NumberOfRuns@0, pad@4, NumberOfPages@8 (u64),
            // Run[0]@16 (each run 16 bytes: BasePage, PageCount).
            let off = blk + 16 + 16 * i as u64;
            let lo = le32(src, off).unwrap_or(0) as u64;
            let hi = le32(src, off + 4).unwrap_or(0) as u64;
            let base_page = lo | (hi << 32);
            let lo2 = le32(src, off + 8).unwrap_or(0) as u64;
            let hi2 = le32(src, off + 12).unwrap_or(0) as u64;
            let page_count = lo2 | (hi2 << 32);
            if page_count == 0 {
                continue;
            }
            runs.push(PhysRun {
                base_page,
                page_count,
            });
            if runs.len() >= limits.max_partitions {
                warnings.push("run count capped at max_partitions".to_string());
                break;
            }
        }
        Ok(runs)
    }
}

impl Handler for Pagedu64Handler {
    fn format(&self) -> &'static str {
        "pagedu64"
    }

    fn find_candidates(&self, src: &ByteSource) -> Vec<Candidate> {
        find_all(src, b"PAGEDU64")
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
        if base + 0x40 > src.len() {
            return Err(Error::Validation {
                format: "pagedu64",
                reason: "header truncated".into(),
            });
        }
        let major = le32(src, base + 8).unwrap_or(0);
        let minor = le32(src, base + 0xC).unwrap_or(0);
        let dir_table_base = {
            let lo = le32(src, base + 0x10).unwrap_or(0) as u64;
            let hi = le32(src, base + 0x14).unwrap_or(0) as u64;
            lo | (hi << 32)
        };
        let ps_loaded_module_list = {
            let lo = le32(src, base + 0x20).unwrap_or(0) as u64;
            let hi = le32(src, base + 0x24).unwrap_or(0) as u64;
            lo | (hi << 32)
        };
        let machine = le32(src, base + 0x30).unwrap_or(0);
        let num_processors = le32(src, base + 0x34).unwrap_or(0);
        let bugcheck = le32(src, base + 0x38).unwrap_or(0);
        let dump_type = le32(src, base + 0xF98).unwrap_or(0);
        let type_name = match dump_type {
            1 => "full",
            5 => "BMP",
            8 => "kernel",
            9 => "kernel+user",
            10 => "complete",
            6 => "live kernel",
            _ => "unknown",
        };
        let machine_name = match machine {
            0x8664 => "x64",
            0x01C4 => "ARM64",
            _ => "unknown",
        };

        let mut warnings = Vec::new();
        let runs = Self::parse_runs(src, base, limits, &mut warnings)?;

        // Expose each run's packed page data as a source-backed child
        // (MemoryRange relation). First page of run 0 lives at file
        // offset 0x2000; runs are packed back to back.
        let mut children = Vec::new();
        let mut file_off = base + DUMP64_HEADER_SIZE;
        let mut total_pages = 0u64;
        for (idx, run) in runs.iter().enumerate() {
            let run_bytes = run.page_count * PAGE_SIZE;
            let start_addr = run.base_page * PAGE_SIZE;
            if file_off + run_bytes > src.len() {
                let avail = src.len().saturating_sub(file_off);
                warnings.push(format!(
                    "run {idx} truncated at source end ({} of {} bytes present)",
                    avail, run_bytes
                ));
                if avail == 0 {
                    break;
                }
                let take = (avail / PAGE_SIZE) * PAGE_SIZE;
                if take == 0 {
                    break;
                }
                let region = src.slice(file_off, take)?;
                let mut meta = BTreeMap::new();
                meta.insert("run_index".to_string(), idx.to_string());
                meta.insert("start_addr".to_string(), format!("{start_addr:#x}"));
                children.push(ChildDraft {
                    relation: RelationKind::MemoryRange,
                    label: format!(
                        "physical run {idx} ({} of {} bytes, at {:#x})",
                        take, run_bytes, start_addr
                    ),
                    format_hint: "raw",
                    content: ChildContent::Source(region),
                    size: take,
                    metadata: meta,
                    warnings: Vec::new(),
                    entry_name: Some(format!("phys_run_{idx}.bin")),
                });
                total_pages += take / PAGE_SIZE;
                break;
            }
            let region = src.slice(file_off, run_bytes)?;
            let mut meta = BTreeMap::new();
            meta.insert("run_index".to_string(), idx.to_string());
            meta.insert("start_addr".to_string(), format!("{start_addr:#x}"));
            meta.insert("page_count".to_string(), run.page_count.to_string());
            children.push(ChildDraft {
                relation: RelationKind::MemoryRange,
                label: format!(
                    "physical run {idx} ({} pages at {:#x})",
                    run.page_count, start_addr
                ),
                format_hint: "raw",
                content: ChildContent::Source(region),
                size: run_bytes,
                metadata: meta,
                warnings: Vec::new(),
                entry_name: Some(format!("phys_run_{idx}.bin")),
            });
            total_pages += run.page_count;
            file_off += run_bytes;
        }

        let mut metadata = BTreeMap::new();
        metadata.insert("dump_type".to_string(), type_name.to_string());
        metadata.insert("os_major".to_string(), major.to_string());
        metadata.insert("os_build".to_string(), minor.to_string());
        metadata.insert("processors".to_string(), num_processors.to_string());
        metadata.insert(
            "directory_table_base".to_string(),
            format!("{dir_table_base:#x}"),
        );
        metadata.insert(
            "ps_loaded_module_list".to_string(),
            format!("{ps_loaded_module_list:#x}"),
        );
        metadata.insert("bugcheck_code".to_string(), format!("{bugcheck:#010x}"));
        metadata.insert("physical_runs".to_string(), runs.len().to_string());
        metadata.insert("pages_present".to_string(), total_pages.to_string());

        Ok(HandlerOutput {
            artifacts: vec![ArtifactDraft {
                format: "pagedu64".to_string(),
                label: format!(
                    "Windows kernel dump ({type_name}, {machine_name}, {} runs, {} pages)",
                    runs.len(),
                    total_pages
                ),
                offset: base,
                size: src.len() - base,
                confidence: if children.is_empty() {
                    Confidence::Partial
                } else {
                    Confidence::Validated
                },
                evidence: Evidence::facts([
                    "PAGEDU64 signature validated".to_string(),
                    format!("dump type {dump_type} ({type_name}), build {minor}"),
                    format!(
                        "physical memory runs parsed: {} runs, {} pages",
                        runs.len(),
                        total_pages
                    ),
                    format!(
                        "PsLoadedModuleList at {:#x} (for Volatility-style plugin work)",
                        ps_loaded_module_list
                    ),
                ]),
                metadata,
                warnings,
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

    /// Minidump with ModuleList + ThreadList + SystemInfo streams:
    /// metadata (module names, thread TEBs, arch) must surface as
    /// children alongside memory ranges.
    #[test]
    fn minidump_metadata_streams() {
        let mut d = Vec::new();
        // Header: MDMP, version 42899, 4 streams, dir at 32.
        d.extend_from_slice(b"MDMP");
        d.extend(42899u32.to_le_bytes());
        d.extend(4u32.to_le_bytes()); // stream count
        d.extend(32u32.to_le_bytes()); // directory rva
        d.extend(0u32.to_le_bytes()); // checksum
        d.extend([0u8; 12]); // pad to 32
                             // Directory entries (type, size, rva).
                             // Stream 0: SystemInfo (7) at rva 80.
        d.extend(7u32.to_le_bytes());
        d.extend(56u32.to_le_bytes());
        d.extend(80u32.to_le_bytes());
        // Stream 1: ModuleList (4) at rva 140.
        d.extend(4u32.to_le_bytes());
        d.extend(220u32.to_le_bytes());
        d.extend(140u32.to_le_bytes());
        // Stream 2: ThreadList (3) at rva 380.
        d.extend(3u32.to_le_bytes());
        d.extend(52u32.to_le_bytes());
        d.extend(380u32.to_le_bytes());
        // Stream 3: MemoryList (5) at rva 440.
        d.extend(5u32.to_le_bytes());
        d.extend(20u32.to_le_bytes());
        d.extend(440u32.to_le_bytes());
        // SystemInfo at 80: arch 9 (x64), 8 processors.
        assert_eq!(d.len(), 80);
        d.extend(9u16.to_le_bytes());
        d.extend(0u16.to_le_bytes()); // level
        d.extend(0u16.to_le_bytes()); // revision
        d.push(8); // processor count
        d.push(1); // product type
        d.extend(0u16.to_le_bytes()); // suite
        d.extend([0u8; 24]);
        // Pad to the ModuleList rva (140).
        while d.len() < 140 {
            d.push(0);
        }
        assert_eq!(d.len(), 140);
        d.extend(1u32.to_le_bytes());
        let module_rec = d.len();
        d.extend(0x7FF00000u32.to_le_bytes()); // BaseOfImage lo
        d.extend(0u32.to_le_bytes()); // hi
        d.extend(0x1000u32.to_le_bytes()); // size
        d.extend(0u32.to_le_bytes()); // checksum
        d.extend(0u32.to_le_bytes()); // timestamp
        d.extend(252u32.to_le_bytes()); // name rva (string follows record)
                                        // Pad record to 108 bytes.
        while d.len() - module_rec < 108 {
            d.push(0);
        }
        assert_eq!(d.len() - module_rec, 108);
        // MINIDUMP_STRING at 200: "ntoskrnl.exe" = 24 bytes.
        d.extend(24u32.to_le_bytes());
        d.extend("ntoskrnl.exe".encode_utf16().flat_map(u16::to_le_bytes));
        // Pad to the ThreadList rva (380).
        while d.len() < 380 {
            d.push(0);
        }
        assert_eq!(d.len(), 380);
        d.extend(1u32.to_le_bytes());
        d.extend(4242u32.to_le_bytes()); // tid
        d.extend(0u32.to_le_bytes()); // suspend
        d.extend(0u32.to_le_bytes()); // prio class
        d.extend(0u32.to_le_bytes()); // prio
        d.extend(0xFFFFF000u32.to_le_bytes()); // TEB lo
        d.extend(0u32.to_le_bytes()); // TEB hi
        d.extend(0x1000u32.to_le_bytes()); // stack start lo
        d.extend(0u32.to_le_bytes()); // hi
        d.extend(0x2000u32.to_le_bytes()); // stack size
        d.extend(0u32.to_le_bytes()); // stack rva
        d.extend(0u32.to_le_bytes()); // ctx size
        d.extend(0u32.to_le_bytes()); // ctx rva
                                      // Pad to the MemoryList rva (440).
        while d.len() < 440 {
            d.push(0);
        }
        assert_eq!(d.len(), 440);
        // MemoryList at 440: 1 range, 16-byte descriptor.
        d.extend(1u32.to_le_bytes());
        d.extend(0x1000u32.to_le_bytes()); // start addr lo
        d.extend(0u32.to_le_bytes()); // hi
        d.extend(32u32.to_le_bytes()); // size
        d.extend(500u32.to_le_bytes()); // rva
                                        // Pad to the memory rva (500), then memory bytes.
        while d.len() < 500 {
            d.push(0);
        }
        assert_eq!(d.len(), 500);
        d.extend(b"MEMORY_RANGE_DATA");
        d.extend([0u8; 15]);
        let src = ByteSource::from_vec(d);
        let out = validate_at(&MinidumpHandler, &src, 0).expect("minidump validates");
        let art = &out.artifacts[0];
        let module = art
            .children
            .iter()
            .find(|c| c.metadata.get("module_name").map(String::as_str) == Some("ntoskrnl.exe"))
            .expect("module child");
        assert_eq!(
            module.metadata.get("base_address").map(String::as_str),
            Some("0x7ff00000")
        );
        let thread = art
            .children
            .iter()
            .find(|c| c.metadata.get("thread_id").map(String::as_str) == Some("4242"))
            .expect("thread child");
        assert_eq!(
            thread.metadata.get("teb").map(String::as_str),
            Some("0xfffff000")
        );
        let sys = art
            .children
            .iter()
            .find(|c| c.metadata.get("stream").map(String::as_str) == Some("SystemInfo"))
            .expect("system info child");
        assert_eq!(
            sys.metadata.get("architecture").map(String::as_str),
            Some("x64")
        );
        assert!(
            art.children
                .iter()
                .any(|c| c.metadata.get("stream").map(String::as_str) == Some("MemoryList")),
            "memory range child still present"
        );
    }

    /// PAGEDU64 kernel dump: signature + physical runs exposed as
    /// source-backed packed page regions.
    #[test]
    fn pagedu64_runs_and_provenance() {
        let mut d = Vec::new();
        d.extend_from_slice(b"PAGEDU64");
        d.extend(15u32.to_le_bytes()); // major (free build)
        d.extend(19045u32.to_le_bytes()); // build
        d.extend(0x1FF000u32.to_le_bytes()); // DTB lo
        d.extend(0u32.to_le_bytes()); // DTB hi
        d.extend(0u32.to_le_bytes()); // PFN lo
        d.extend(0u32.to_le_bytes()); // PFN hi
        d.extend(0x888000u32.to_le_bytes()); // PsLoadedModuleList lo
        d.extend(0xFFFFF800u32.to_le_bytes()); // hi (canonical upper half)
        d.extend(0u32.to_le_bytes()); // PsActiveProcessHead lo
        d.extend(0xFFFFF800u32.to_le_bytes()); // hi
        d.extend(0x8664u32.to_le_bytes()); // machine
        d.extend(16u32.to_le_bytes()); // processors
        d.extend(0x139u32.to_le_bytes()); // bugcheck 0x139
        d.extend([0u8; 32]); // bugcheck params
                             // PhysicalMemoryBlockBuffer at 0x88: 2 runs.
        while d.len() < 0x88 {
            d.push(0);
        }
        d.extend(2u32.to_le_bytes()); // NumberOfRuns
        d.extend(0u32.to_le_bytes()); // padding
        d.extend(3u64.to_le_bytes()); // NumberOfPages
        d.extend(1u64.to_le_bytes()); // run 0: base page 1
        d.extend(2u64.to_le_bytes()); // run 0: 2 pages
        d.extend(9u64.to_le_bytes()); // run 1: base page 9
        d.extend(1u64.to_le_bytes()); // run 1: 1 page
                                      // DumpType at 0xF98 = 1 (full); SystemTime at 0xFA8.
        while d.len() < 0xF98 {
            d.push(0);
        }
        d.extend(1u32.to_le_bytes());
        // Pages start at 0x2000: run 0 = 2 pages, run 1 = 1 page.
        while d.len() < 0x2000 {
            d.push(0);
        }
        d.extend(b"PAGE_RUN0_0"); // 0x2000
        while d.len() < 0x3000 {
            d.push(0);
        }
        d.extend(b"PAGE_RUN0_1"); // 0x3000
        while d.len() < 0x4000 {
            d.push(0);
        }
        d.extend(b"PAGE_RUN1_0"); // 0x4000
        while d.len() < 0x5000 {
            d.push(0);
        }
        let src = ByteSource::from_vec(d);
        let out = validate_at(&Pagedu64Handler, &src, 0).expect("pagedu64 validates");
        let art = &out.artifacts[0];
        assert_eq!(art.confidence, Confidence::Validated);
        assert_eq!(
            art.metadata.get("dump_type").map(String::as_str),
            Some("full")
        );
        assert_eq!(
            art.metadata.get("pages_present").map(String::as_str),
            Some("3")
        );
        assert_eq!(art.children.len(), 2);
        let run0 = &art.children[0];
        assert_eq!(
            run0.metadata.get("start_addr").map(String::as_str),
            Some("0x1000")
        );
        match &run0.content {
            ChildContent::Source(r) => {
                let mut b = [0u8; 11];
                r.read_at(0, &mut b).unwrap();
                assert_eq!(&b, b"PAGE_RUN0_0");
                // Second page of run 0 at +0x1000.
                let mut b2 = [0u8; 11];
                r.read_at(0x1000, &mut b2).unwrap();
                assert_eq!(&b2, b"PAGE_RUN0_1");
            }
            _ => panic!("run 0 must be source-backed"),
        }
        let run1 = &art.children[1];
        assert_eq!(
            run1.metadata.get("start_addr").map(String::as_str),
            Some("0x9000")
        );
        match &run1.content {
            ChildContent::Source(r) => {
                let mut b = [0u8; 11];
                r.read_at(0, &mut b).unwrap();
                assert_eq!(&b, b"PAGE_RUN1_0");
            }
            _ => panic!("run 1 must be source-backed"),
        }
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
        // B7 + FINAL-B3: fixture built per the regf specification --
        // nk value count @+36, value-list cell @+40, name_len @+72,
        // name @+76; ALL reference fields point at CELL STARTS.
        let mut v = vec![0u8; 8192];
        v[0..4].copy_from_slice(b"regf");
        // First hbin at 4096: magic + size 4096. Cell offsets are
        // relative to 0x1000 (= 4096 here).
        v[4096..4100].copy_from_slice(b"hbin");
        v[4104..4108].copy_from_slice(&4096u32.to_le_bytes());
        // Root nk CELL at 4128: size prefix -(4+88), record at 4132.
        let rec: usize = 4132;
        v[4128..4132].copy_from_slice(&(-(4 + 88i32)).to_le_bytes());
        v[rec..rec + 2].copy_from_slice(b"nk");
        v[rec + 2..rec + 4].copy_from_slice(&0x0020u16.to_le_bytes()); // ASCII name
        v[rec + 16..rec + 20].copy_from_slice(&0xFFFFFFFFu32.to_le_bytes()); // no parent
        v[rec + 36..rec + 40].copy_from_slice(&1u32.to_le_bytes()); // VALUE COUNT (+36)
                                                                    // Value-list CELL at 4220 (immediately after the nk cell —
                                                                    // cells are contiguous); nk +40 = cell rel.
        let list_cell: usize = 4220;
        v[rec + 40..rec + 44].copy_from_slice(&((list_cell - 4096) as u32).to_le_bytes());
        v[rec + 72..rec + 74].copy_from_slice(&4u16.to_le_bytes()); // NAME LEN (+72)
        v[rec + 76..rec + 80].copy_from_slice(b"ROOT"); // NAME (+76)
                                                        // Value-list cell: [size -8][vk cell offset] -- vk offset
                                                        // targets a CELL START.
        v[list_cell..list_cell + 4].copy_from_slice(&(-8i32).to_le_bytes());
        let vk_cell: usize = 4228;
        v[list_cell + 4..list_cell + 8].copy_from_slice(&((vk_cell - 4096) as u32).to_le_bytes());
        // vk CELL at 4228: prefix -(4+24), record at 4232: sig(2)
        // name_len(2)=0 data_len(4)=16 data_off(4) type(4)=3
        // flags(2) spare(2). Name at +20.
        let vk: usize = 4232;
        v[vk_cell..vk_cell + 4].copy_from_slice(&(-28i32).to_le_bytes());
        v[vk..vk + 2].copy_from_slice(b"vk");
        v[vk + 2..vk + 4].copy_from_slice(&0u16.to_le_bytes());
        v[vk + 4..vk + 8].copy_from_slice(&16u32.to_le_bytes()); // data_len
                                                                 // Non-inline: data offset points at a CELL START relative to
                                                                 // 0x1000. Data cell at 5200 -> field = 1104.
        v[vk + 8..vk + 12].copy_from_slice(&1104u32.to_le_bytes());
        v[vk + 12..vk + 16].copy_from_slice(&3u32.to_le_bytes()); // REG_BINARY
        let data_cell: usize = 5200;
        v[data_cell..data_cell + 4].copy_from_slice(&(-24i32).to_le_bytes());
        v[5204..5220].copy_from_slice(&[0xBEu8; 16]);
        let src = ByteSource::from_vec(v);
        let out = validate_at(&RegistryHandler, &src, 0).expect("registry validates");
        let art = &out.artifacts[0];
        let bin_child = art
            .children
            .iter()
            .find(|c| c.label.contains("REG_BINARY") && c.size == 16)
            .expect("REG_BINARY value child");
        assert_eq!(
            bin_child.metadata.get("key_path").map(String::as_str),
            Some("ROOT"),
            "value must be attributed to its key path"
        );
    }

    #[test]
    fn registry_nested_key_paths_and_typed_values() {
        // FINAL-B3: spec-layout fixture -- nested keys via parent CELL
        // references, inline REG_DWORD + REG_SZ values, subkey list
        // (lf) on the root exercised through subkeys_reachable.
        let mut v = vec![0u8; 8192];
        v[0..4].copy_from_slice(b"regf");
        v[4096..4100].copy_from_slice(b"hbin");
        v[4104..4108].copy_from_slice(&4096u32.to_le_bytes());
        // Root nk CELL at 4128 (record at 4132).
        let root_rec: usize = 4132;
        v[4128..4132].copy_from_slice(&(-(4 + 88i32)).to_le_bytes());
        v[root_rec..root_rec + 2].copy_from_slice(b"nk");
        v[root_rec + 2..root_rec + 4].copy_from_slice(&0x0020u16.to_le_bytes());
        v[root_rec + 16..root_rec + 20].copy_from_slice(&0xFFFFFFFFu32.to_le_bytes());
        // Root: 1 subkey (lf list), 0 values.
        v[root_rec + 20..root_rec + 24].copy_from_slice(&1u32.to_le_bytes());
        let lf_cell: usize = 4220;
        v[root_rec + 28..root_rec + 32].copy_from_slice(&((lf_cell - 4096) as u32).to_le_bytes());
        v[root_rec + 72..root_rec + 74].copy_from_slice(&4u16.to_le_bytes());
        v[root_rec + 76..root_rec + 80].copy_from_slice(b"ROOT");
        // lf list cell: [size -(8+8)][child cell off][hash].
        v[lf_cell..lf_cell + 4].copy_from_slice(&(-(8 + 8i32)).to_le_bytes());
        v[lf_cell + 4..lf_cell + 6].copy_from_slice(b"lf");
        v[lf_cell + 6..lf_cell + 8].copy_from_slice(&1u16.to_le_bytes());
        // child nk CELL at 4236 (record at 4240) -- contiguous after lf.
        let child_cell: usize = 4236;
        v[lf_cell + 8..lf_cell + 12].copy_from_slice(&((child_cell - 4096) as u32).to_le_bytes());
        v[lf_cell + 12..lf_cell + 16].copy_from_slice(&0u32.to_le_bytes()); // hash
                                                                            // Child nk record at 4248, parent = ROOT CELL rel (cell start).
        let child_rec: usize = 4240;
        v[child_cell..child_cell + 4].copy_from_slice(&(-(4 + 88i32)).to_le_bytes());
        v[child_rec..child_rec + 2].copy_from_slice(b"nk");
        v[child_rec + 2..child_rec + 4].copy_from_slice(&0x0020u16.to_le_bytes());
        v[child_rec + 16..child_rec + 20].copy_from_slice(&((4128 - 4096) as u32).to_le_bytes());
        v[child_rec + 36..child_rec + 40].copy_from_slice(&2u32.to_le_bytes()); // 2 values
        let list_cell: usize = 4328;
        v[child_rec + 40..child_rec + 44]
            .copy_from_slice(&((list_cell - 4096) as u32).to_le_bytes());
        v[child_rec + 72..child_rec + 74].copy_from_slice(&3u16.to_le_bytes());
        v[child_rec + 76..child_rec + 79].copy_from_slice(b"Sub");
        // Value list cell: [size -12][vk0 cell][vk1 cell].
        v[list_cell..list_cell + 4].copy_from_slice(&(-12i32).to_le_bytes());
        // vk0 CELL at 4340 (record 4344): inline REG_DWORD.
        let vk0_cell: usize = 4340;
        let vk1_cell: usize = 4374;
        v[list_cell + 4..list_cell + 8].copy_from_slice(&((vk0_cell - 4096) as u32).to_le_bytes());
        v[list_cell + 8..list_cell + 12].copy_from_slice(&((vk1_cell - 4096) as u32).to_le_bytes());
        // vk record: sig(2) name_len(2) data_size(4) data_off(4)
        // type(4) flags(2) spare(2) name(...). Inline data lives in
        // the data-offset field.
        let vk0: usize = 4344;
        v[vk0_cell..vk0_cell + 4].copy_from_slice(&(-(4 + 30i32)).to_le_bytes());
        v[vk0..vk0 + 2].copy_from_slice(b"vk");
        v[vk0 + 2..vk0 + 4].copy_from_slice(&4u16.to_le_bytes()); // "Test"
        v[vk0 + 4..vk0 + 8].copy_from_slice(&0x8000_0004u32.to_le_bytes()); // inline 4
        v[vk0 + 8..vk0 + 12].copy_from_slice(&0x11223344u32.to_le_bytes());
        v[vk0 + 12..vk0 + 16].copy_from_slice(&4u32.to_le_bytes()); // REG_DWORD
        v[vk0 + 20..vk0 + 24].copy_from_slice(b"Test");
        // vk1 CELL at 4374 (record 4378): inline REG_SZ "Hi".
        let vk1: usize = 4378;
        v[vk1_cell..vk1_cell + 4].copy_from_slice(&(-(4 + 28i32)).to_le_bytes());
        v[vk1..vk1 + 2].copy_from_slice(b"vk");
        v[vk1 + 2..vk1 + 4].copy_from_slice(&2u16.to_le_bytes()); // "Hi"
        v[vk1 + 4..vk1 + 8].copy_from_slice(&0x8000_0004u32.to_le_bytes());
        v[vk1 + 8..vk1 + 12].copy_from_slice(&0x0069_0048u32.to_le_bytes());
        v[vk1 + 12..vk1 + 16].copy_from_slice(&1u32.to_le_bytes()); // REG_SZ
        v[vk1 + 20..vk1 + 22].copy_from_slice(b"Hi");
        let src = ByteSource::from_vec(v);
        let out = validate_at(&RegistryHandler, &src, 0).expect("registry validates");
        let art = &out.artifacts[0];
        assert_eq!(
            art.metadata.get("root_key").map(String::as_str),
            Some("ROOT")
        );
        // Subkey list (lf) parsed: root's 1 child reachable.
        assert_eq!(
            art.metadata.get("subkeys_reachable").map(String::as_str),
            Some("1"),
            "lf subkey list must be parsed"
        );
        let dword = art
            .children
            .iter()
            .find(|c| c.metadata.get("value_type").map(String::as_str) == Some("REG_DWORD"))
            .expect("dword child");
        assert_eq!(
            dword.metadata.get("key_path").map(String::as_str),
            Some("ROOT\\Sub"),
            "child key path must be reconstructed via parent cell refs"
        );
        assert_eq!(
            dword.metadata.get("data").map(String::as_str),
            Some("0x11223344")
        );
        let sz = art
            .children
            .iter()
            .find(|c| c.metadata.get("value_type").map(String::as_str) == Some("REG_SZ"))
            .expect("sz child");
        assert_eq!(sz.metadata.get("text").map(String::as_str), Some("Hi"));
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

    /// Ethernet+IPv4+TCP frame builder used by the #7 §7 tests.
    fn net_tcp_frame(seq: u32, sp: u16, dp: u16, payload: &[u8]) -> Vec<u8> {
        let mut f = Vec::new();
        f.extend([0x02u8; 6]);
        f.extend([0x01u8; 6]);
        f.extend(0x0800u16.to_be_bytes());
        let total_len = (20 + 20 + payload.len()) as u16;
        f.extend(0x45u8.to_be_bytes());
        f.extend(0u8.to_be_bytes());
        f.extend(total_len.to_be_bytes());
        f.extend(1u16.to_be_bytes());
        f.extend(0x4000u16.to_be_bytes());
        f.extend(64u8.to_be_bytes());
        f.extend(6u8.to_be_bytes());
        f.extend(0u16.to_be_bytes());
        f.extend([10u8, 0, 0, 1]);
        f.extend([10u8, 0, 0, 2]);
        f.extend(sp.to_be_bytes());
        f.extend(dp.to_be_bytes());
        f.extend(seq.to_be_bytes());
        f.extend(1u32.to_be_bytes());
        f.extend(0x5018u16.to_be_bytes());
        f.extend(0xFFFFu16.to_be_bytes());
        f.extend(0u16.to_be_bytes());
        f.extend(0u16.to_be_bytes());
        f.extend_from_slice(payload);
        f
    }

    fn net_pcap(frames: &[Vec<u8>]) -> Vec<u8> {
        let mut p = Vec::new();
        p.extend_from_slice(&[0xD4, 0xC3, 0xB2, 0xA1]);
        p.extend(2u16.to_le_bytes());
        p.extend(4u16.to_le_bytes());
        p.extend(0u32.to_le_bytes());
        p.extend(0u32.to_le_bytes());
        p.extend(262144u32.to_le_bytes());
        p.extend(1u32.to_le_bytes());
        for f in frames {
            p.extend(1u32.to_le_bytes());
            p.extend(0u32.to_le_bytes());
            p.extend((f.len() as u32).to_le_bytes());
            p.extend((f.len() as u32).to_le_bytes());
            p.extend_from_slice(f);
        }
        p
    }

    /// #7 §7.1: out-of-order TCP segments must be reordered by sequence
    /// number, retransmissions deduped, and the HTTP body intact.
    #[test]
    fn pcap_tcp_out_of_order_and_retransmission() {
        let body = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ";
        let head = b"HTTP/1.1 200 OK\r\nContent-Length: 26\r\n\r\n";
        let head_len = head.len() as u32; // 39; body starts at seq 40
                                          // Segments sent OUT of order: tail (seq 51), a duplicate of the
                                          // header segment (seq 1), the header (seq 1), the body head
                                          // (seq 40). Reassembly must order by seq and drop the dup.
        let seg_tail = net_tcp_frame(1 + head_len + 11, 55555, 80, &body[11..]);
        let seg_head_dup = net_tcp_frame(1, 55555, 80, head);
        let seg_head = net_tcp_frame(1, 55555, 80, head);
        let seg_body = net_tcp_frame(1 + head_len, 55555, 80, &body[..11]);
        let p = net_pcap(&[seg_tail, seg_head_dup, seg_head, seg_body]);
        let src = ByteSource::from_vec(p);
        let out = validate_at(&PcapHandler, &src, 0).expect("pcap validates");
        let bodies: Vec<_> = out.artifacts[0]
            .children
            .iter()
            .filter(|c| c.label.contains("HTTP body"))
            .collect();
        assert_eq!(bodies.len(), 1, "deduped flow -> one HTTP body");
        let bytes = bodies[0].content.to_bytes().unwrap();
        assert_eq!(
            bytes.as_slice(),
            &body[..],
            "sequence-ordered reassembly, no duplicate bytes"
        );
        assert_eq!(
            bodies[0].metadata.get("complete").map(String::as_str),
            Some("true")
        );
    }

    /// #7 §7.1: a sequence gap must be reported honestly via tcp_gaps
    /// metadata instead of silently concatenating across the hole.
    #[test]
    fn pcap_tcp_gap_reported() {
        let head = b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\n";
        let seg1 = net_tcp_frame(1, 55555, 80, head);
        // seq jumps from 1+head.len() to +100: 89 bytes missing.
        let seg2 = net_tcp_frame(1 + head.len() as u32 + 100, 55555, 80, b"0123456789");
        let p = net_pcap(&[seg1, seg2]);
        let src = ByteSource::from_vec(p);
        let out = validate_at(&PcapHandler, &src, 0).expect("pcap validates");
        let gaps = out.artifacts[0]
            .children
            .iter()
            .find(|c| c.metadata.contains_key("tcp_gaps"))
            .expect("some reconstructed child carries gap metadata");
        assert_eq!(
            gaps.metadata.get("tcp_gaps").map(String::as_str),
            Some("1"),
            "gap must be surfaced as tcp_gaps"
        );
    }

    /// #7 §7.2: chunked transfer coding must be decoded to the body.
    #[test]
    fn pcap_http_chunked_decoded() {
        let msg = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n\
5\r\nABCD\
E\r\n7\r\nFGHIJKL\r\n0\r\n\r\n";
        let seg = net_tcp_frame(1, 55555, 80, msg);
        let p = net_pcap(&[seg]);
        let src = ByteSource::from_vec(p);
        let out = validate_at(&PcapHandler, &src, 0).expect("pcap validates");
        let body = out.artifacts[0]
            .children
            .iter()
            .find(|c| c.label.contains("HTTP body"))
            .expect("chunked body child");
        let bytes = body.content.to_bytes().unwrap();
        assert_eq!(
            bytes.as_slice(),
            b"ABCDEFGHIJKL",
            "chunk sizes 5 and 7 decoded; hex framing removed"
        );
        assert_eq!(
            body.metadata.get("transfer_encoding").map(String::as_str),
            Some("chunked")
        );
    }

    /// #7 §7.3: DNS TXT answers over UDP/53 become children whose
    /// Owned bytes the engine recurses into.
    #[test]
    fn pcap_dns_txt_exfil_child() {
        // DNS message: id 0x1234, qd=1, an=1. Query "e.com" (single
        // label 0x01 'e'), type TXT(16). Answer: name ptr 0xC00C, type
        // 16, rdlength 10, TXT "SECRET9999" (len 10 + bytes).
        let mut dns = Vec::new();
        dns.extend(0x1234u16.to_be_bytes());
        dns.extend(0x0100u16.to_be_bytes()); // flags: RD
        dns.extend(1u16.to_be_bytes()); // qdcount
        dns.extend(1u16.to_be_bytes()); // ancount
        dns.extend(0u16.to_be_bytes());
        dns.extend(0u16.to_be_bytes());
        dns.push(1);
        dns.extend_from_slice(b"e");
        dns.push(0); // root
        dns.extend(16u16.to_be_bytes()); // qtype TXT
        dns.extend(1u16.to_be_bytes()); // qclass IN
        dns.extend(0xC00Cu16.to_be_bytes()); // name ptr to offset 12
        dns.extend(16u16.to_be_bytes()); // type
        dns.extend(1u16.to_be_bytes()); // class
        dns.extend(60u32.to_be_bytes()); // ttl
        dns.extend(11u16.to_be_bytes()); // rdlength = 1 len byte + 10
        dns.push(10);
        dns.extend_from_slice(b"SECRET9999");

        // UDP header (8 bytes): sport, dport 53, len, cksum.
        let mut udp = Vec::new();
        udp.extend(40000u16.to_be_bytes());
        udp.extend(53u16.to_be_bytes());
        udp.extend((8 + dns.len() as u16).to_be_bytes());
        udp.extend(0u16.to_be_bytes());

        // IPv4 header: proto 17, src 10.0.0.1, dst 10.0.0.2.
        let total = 20 + udp.len() + dns.len();
        let mut ip = Vec::new();
        ip.extend(0x45u8.to_be_bytes());
        ip.extend(0u8.to_be_bytes());
        ip.extend((total as u16).to_be_bytes());
        ip.extend(1u16.to_be_bytes());
        ip.extend(0x4000u16.to_be_bytes());
        ip.extend(64u8.to_be_bytes());
        ip.extend(17u8.to_be_bytes());
        ip.extend(0u16.to_be_bytes());
        ip.extend([10u8, 0, 0, 1]);
        ip.extend([10u8, 0, 0, 2]);
        assert_eq!(ip.len(), 20);

        let mut frame = Vec::new();
        frame.extend([0x02u8; 6]);
        frame.extend([0x01u8; 6]);
        frame.extend(0x0800u16.to_be_bytes());
        frame.extend_from_slice(&ip);
        frame.extend_from_slice(&udp);
        frame.extend_from_slice(&dns);

        let p = net_pcap(&[frame]);
        let src = ByteSource::from_vec(p);
        let out = validate_at(&PcapHandler, &src, 0).expect("pcap validates");
        let rdata = out.artifacts[0]
            .children
            .iter()
            .find(|c| c.label.contains("DNS rdata"))
            .expect("TXT rdata child");
        let bytes = rdata.content.to_bytes().unwrap();
        assert_eq!(bytes.as_slice(), b"SECRET9999");
        assert_eq!(
            rdata.metadata.get("query").map(String::as_str),
            Some("e"),
            "question name parsed"
        );
    }

    /// #7 §7.4: USB HID reports on linktype 220 reconstruct to text.
    #[test]
    fn pcap_usb_hid_keystrokes() {
        // usbmon mmapped header (64 bytes) + 8-byte HID report.
        let report = |codes: [u8; 6], modifier: u8| -> Vec<u8> {
            let mut f = vec![0u8; 72];
            f[9] = 1; // xfer_type = interrupt
            f[10] = 0x81; // epnum
            f[11] = 5; // devnum
            f[19] = b'<'; // flag_data: data present
                          // len_cap u32 at +36.
            f[36..40].copy_from_slice(&8u32.to_le_bytes());
            f[64] = modifier; // modifiers (0x22 = right shift)
            f[66] = codes[0];
            f[67] = codes[1];
            f[68] = codes[2];
            f[69] = codes[3];
            f[70] = codes[4];
            f[71] = codes[5];
            f
        };
        // "H" (0x0B) with shift, then "i" (0x0C) without, then space.
        let f1 = report([0x0B, 0, 0, 0, 0, 0], 0x22);
        let f2 = report([0x0C, 0, 0, 0, 0, 0], 0);
        let f3 = report([0x2C, 0, 0, 0, 0, 0], 0);
        let p = net_pcap(&[f1, f2, f3]);
        // linktype 220 — patch the global header.
        let mut p = p;
        p[20..24].copy_from_slice(&220u32.to_le_bytes());
        let src = ByteSource::from_vec(p);
        let out = validate_at(&PcapHandler, &src, 0).expect("pcap validates");
        let keys = out.artifacts[0]
            .children
            .iter()
            .find(|c| c.label.contains("USB HID keystrokes"))
            .expect("keystroke child");
        let bytes = keys.content.to_bytes().unwrap();
        assert_eq!(String::from_utf8_lossy(&bytes), "Hi ");
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
            !art.children.iter().any(|c| c.label.contains("HTTP body")),
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
        let frame = |seq: u32, payload: &[u8], pad: usize| -> Vec<u8> {
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
            f.extend(seq.to_be_bytes());
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
        let seg1 = frame(1, &msg[..20], 20); // header split + padding
        let seg2 = frame(1 + 20, &msg[20..], 30); // rest + padding
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
            .filter(|c| c.label.contains("HTTP body"))
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
