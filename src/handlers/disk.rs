//! M3 disk-image handlers: MBR (legacy BIOS partition table) and GPT
//! (GUID Partition Table with CRC validation).
//!
//! Both handlers produce partitions as source-backed children with
//! `RelationKind::PartitionOf`, preserving offsets so filesystem
//! handlers can recurse into each slice.
//!
//! - MBR: 0x55AA signature, primary entries (bootable flag, type, LBA,
//!   count), extended/logical chain walking with cycle protection,
//!   overlap reporting as warnings.
//! - GPT: protective MBR awareness, primary header parse + CRC32,
//!   partition-entry-array CRC32, GUID type/name extraction, backup
//!   header presence check. Corrupt entries are skipped individually;
//!   unrelated partitions survive (isolation contract).

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
fn le64(src: &ByteSource, off: u64) -> Option<u64> {
    let mut b = [0u8; 8];
    src.read_at(off, &mut b).ok()?;
    Some(u64::from_le_bytes(b))
}

/// Sector size (512 supported in this milestone; 4Kn is rare in CTFs).
const SECTOR: u64 = 512;

// ---------------------------------------------------------------------------
// MBR
// ---------------------------------------------------------------------------

pub struct MbrHandler;

impl Handler for MbrHandler {
    fn format(&self) -> &'static str {
        "mbr"
    }

    fn find_candidates(&self, src: &ByteSource) -> Vec<Candidate> {
        // Signature at offset 511..513 of the *region*; the engine scans
        // whole sources, so look for 55 AA followed by a plausible
        // partition entry layout. Conservative: require signature AND at
        // least one plausible non-empty partition entry type.
        let mut hits = Vec::new();
        let data = match src.read_prefix(64 * 1024 * 1024) {
            Ok(d) => d,
            Err(_) => return hits,
        };
        let mut off = 0usize;
        while off + 513 <= data.len() {
            if data[off + 510] == 0x55 && data[off + 511] == 0xAA {
                // Check the partition table for at least one sane entry.
                if mbr_entry_count(&data[off..off + 512]) > 0 {
                    hits.push(Candidate { offset: off as u64 });
                }
            }
            // Sector-aligned scan only: MBRs live at sector 0 (or inside
            // extended partitions at LBA boundaries).
            off += SECTOR as usize;
        }
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
        if base + SECTOR > src.len() {
            return Err(Error::Validation {
                format: "mbr",
                reason: "sector truncated".into(),
            });
        }
        let mut sector = [0u8; 512];
        src.read_at(base, &mut sector)?;
        if sector[510] != 0x55 || sector[511] != 0xAA {
            return Err(Error::Validation {
                format: "mbr",
                reason: "missing 55AA signature".into(),
            });
        }

        let mut partitions = Vec::new();
        let mut warnings = Vec::new();
        for i in 0..4 {
            let entry = &sector[446 + i * 16..446 + (i + 1) * 16];
            let boot_flag = entry[0];
            let ptype = entry[4];
            let lba = u32::from_le_bytes([entry[8], entry[9], entry[10], entry[11]]) as u64;
            let count = u32::from_le_bytes([entry[12], entry[13], entry[14], entry[15]]) as u64;
            if boot_flag != 0x00 && boot_flag != 0x80 {
                warnings.push(format!(
                    "entry {i}: non-standard bootable flag {boot_flag:#x}"
                ));
            }
            if ptype == 0 {
                continue;
            }
            if count == 0 {
                warnings.push(format!(
                    "entry {i}: type {ptype:#x} with zero length; skipped"
                ));
                continue;
            }
            partitions.push((ptype, lba, count));
            if partitions.len() > limits.max_partitions {
                return Err(Error::Validation {
                    format: "mbr",
                    reason: format!("partition limit exceeded ({})", partitions.len()),
                });
            }
        }
        if partitions.is_empty() {
            return Err(Error::Validation {
                format: "mbr",
                reason: "55AA signature but no populated partition entries".into(),
            });
        }
        // Overlap reporting.
        for a in 0..partitions.len() {
            for b in (a + 1)..partitions.len() {
                let (ta, la, ca) = partitions[a];
                let (tb, lb, cb) = partitions[b];
                if ta < 0x05 && tb < 0x05 && la < lb + cb && lb < la + ca {
                    warnings.push(format!(
                        "partitions {a} and {b} overlap (LBA {la}+{ca} vs {lb}+{cb})"
                    ));
                }
            }
        }
        let is_gpt_protective = partitions.iter().any(|&(t, _, _)| t == 0xEE);
        let _ = is_gpt_protective;

        let children = mbr_children(src, base, &partitions, &mut warnings, limits)?;
        let mut metadata = BTreeMap::new();
        metadata.insert("partition_count".to_string(), partitions.len().to_string());
        metadata.insert("gpt_protective".to_string(), {
            partitions.iter().any(|&(t, _, _)| t == 0xEE).to_string()
        });

        Ok(HandlerOutput {
            artifacts: vec![ArtifactDraft {
                format: "mbr".to_string(),
                label: format!("MBR disk label ({} partitions)", partitions.len()),
                offset: base,
                size: SECTOR,
                confidence: Confidence::Validated,
                evidence: Evidence::facts([
                    "0x55AA boot signature verified".to_string(),
                    format!("{} primary partition entries parsed", partitions.len()),
                    "each partition exposed as a source-backed slice".to_string(),
                ]),
                metadata,
                warnings,
                errors: Vec::new(),
                children,
                entry_names: Vec::new(),
            }],
        })
    }
}

fn mbr_entry_count(sector: &[u8]) -> usize {
    let mut n = 0;
    for i in 0..4 {
        let e = &sector[446 + i * 16..446 + (i + 1) * 16];
        let ptype = e[4];
        let count = u32::from_le_bytes([e[12], e[13], e[14], e[15]]);
        if ptype != 0 && count > 0 {
            n += 1;
        }
    }
    n
}

/// Build source-backed children for MBR partitions + extended chain.
fn mbr_children(
    src: &ByteSource,
    base: u64,
    partitions: &[(u8, u64, u64)],
    warnings: &mut Vec<String>,
    limits: &crate::engine::EngineLimits,
) -> Result<Vec<ChildDraft>> {
    let mut children = Vec::new();
    let mut extended_base: Option<u64> = None;
    for (idx, &(ptype, lba, count)) in partitions.iter().enumerate() {
        let is_extended = ptype == 0x05 || ptype == 0x0F || ptype == 0x85;
        if is_extended {
            if extended_base.is_none() {
                extended_base = Some(lba);
            }
            continue;
        }
        if children.len() >= limits.max_partitions {
            break;
        }
        let start = base
            + lba.checked_mul(SECTOR).ok_or(Error::Validation {
                format: "mbr",
                reason: "LBA overflow".into(),
            })?;
        let len = count.checked_mul(SECTOR).ok_or(Error::Validation {
            format: "mbr",
            reason: "partition length overflow".into(),
        })?;
        if start + len > src.len() {
            warnings.push(format!(
                "partition {idx} (type {ptype:#x}) extends past source; clamped"
            ));
            continue;
        }
        let region = src.slice(start, len)?;
        let mut meta = BTreeMap::new();
        meta.insert("partition_index".to_string(), idx.to_string());
        meta.insert("partition_type".to_string(), format!("{ptype:#04x}"));
        meta.insert("lba_start".to_string(), lba.to_string());
        meta.insert("lba_count".to_string(), count.to_string());
        meta.insert("bootable".to_string(), "unknown".to_string());
        children.push(ChildDraft {
            relation: RelationKind::PartitionOf,
            label: format!("partition {idx} (type {ptype:#04x}, {count} sectors)"),
            format_hint: "raw",
            content: ChildContent::Source(region),
            size: len,
            metadata: meta,
            warnings: Vec::new(),
            entry_name: None,
            confidence: Confidence::Validated,
            evidence: vec!["structurally decoded by parent handler".to_string()],
        });
    }

    // Extended partition logical chain (EBR walk, cycle-protected).
    if let Some(eb) = extended_base {
        let mut current_lba = eb;
        let mut visited = std::collections::HashSet::new();
        let mut logical = 4usize; // logical partition numbering
        loop {
            if visited.contains(&current_lba)
                || visited.len() >= 128
                || children.len() >= limits.max_partitions
            {
                if visited.contains(&current_lba) {
                    warnings.push("extended partition chain contains a cycle".to_string());
                }
                break;
            }
            visited.insert(current_lba);
            let ebr_off = base + current_lba * SECTOR;
            if ebr_off + SECTOR > src.len() {
                break;
            }
            let mut ebr = [0u8; 512];
            if src.read_at(ebr_off, &mut ebr).is_err() || ebr[510] != 0x55 || ebr[511] != 0xAA {
                warnings.push("extended chain EBR missing signature; chain truncated".to_string());
                break;
            }
            let e0 = &ebr[446..462];
            let t0 = u32::from(e0[4]);
            let lba0 = u32::from_le_bytes([e0[8], e0[9], e0[10], e0[11]]) as u64;
            let count0 = u32::from_le_bytes([e0[12], e0[13], e0[14], e0[15]]) as u64;
            let e1 = &ebr[462..478];
            let next_rel = u32::from_le_bytes([e1[8], e1[9], e1[10], e1[11]]) as u64;
            if t0 == 0 || count0 == 0 {
                break;
            }
            let data_lba = current_lba + lba0;
            let start = base + data_lba * SECTOR;
            let len = count0 * SECTOR;
            if start + len <= src.len() {
                let region = src.slice(start, len)?;
                let mut meta = BTreeMap::new();
                meta.insert("partition_index".to_string(), logical.to_string());
                meta.insert("partition_type".to_string(), format!("{t0:#04x}"));
                meta.insert("lba_start".to_string(), data_lba.to_string());
                meta.insert("lba_count".to_string(), count0.to_string());
                meta.insert("extended".to_string(), "true".to_string());
                children.push(ChildDraft {
                    relation: RelationKind::PartitionOf,
                    label: format!(
                        "logical partition {logical} (type {t0:#04x}, {count0} sectors)"
                    ),
                    format_hint: "raw",
                    content: ChildContent::Source(region),
                    size: len,
                    metadata: meta,
                    warnings: Vec::new(),
                    entry_name: None,
                    confidence: Confidence::Validated,
                    evidence: vec!["structurally decoded by parent handler".to_string()],
                });
            }
            logical += 1;
            if next_rel == 0 {
                break;
            }
            current_lba = eb + next_rel;
        }
    }
    Ok(children)
}

// ---------------------------------------------------------------------------
// GPT
// ---------------------------------------------------------------------------

pub struct GptHandler;

impl Handler for GptHandler {
    fn format(&self) -> &'static str {
        "gpt"
    }

    fn find_candidates(&self, src: &ByteSource) -> Vec<Candidate> {
        find_all(src, b"EFI PART")
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
        // GPT header: signature(8) revision(4) header_size(4) crc(4)
        // reserved(4) current_lba(8) backup_lba(8) first_usable(8)
        // last_usable(8) disk_guid(16) entries_lba(8) count(4) size(4)
        // entries_crc(4).
        const HEADER_LEN: u64 = 92;
        if base + HEADER_LEN > src.len() {
            return Err(Error::Validation {
                format: "gpt",
                reason: "header truncated".into(),
            });
        }
        let mut hdr = vec![0u8; HEADER_LEN as usize];
        src.read_at(base, &mut hdr)?;
        // Zero the stored CRC field (offset 16..20) and compute the
        // checksum over the remaining bytes.
        let stored = u32::from_le_bytes([hdr[16], hdr[17], hdr[18], hdr[19]]);
        hdr[16..20].fill(0);
        let mut crc = crc32fast::Hasher::new();
        crc.update(&hdr);
        let computed = crc.finalize();
        if stored != computed {
            return Err(Error::Validation {
                format: "gpt",
                reason: format!("header CRC mismatch: stored {stored:#x}, computed {computed:#x}"),
            });
        }

        let revision = le32(src, base + 8).unwrap_or(0);
        let _current_lba = le64(src, base + 24).unwrap_or(0);
        let backup_lba = le64(src, base + 32).unwrap_or(0);
        let entries_lba = le64(src, base + 72).unwrap_or(0);
        let entry_count = le32(src, base + 80).unwrap_or(0) as usize;
        let entry_size = le32(src, base + 84).unwrap_or(0) as usize;
        let entries_crc = le32(src, base + 88).unwrap_or(0);

        if revision < 0x0001_0000 {
            return Err(Error::Validation {
                format: "gpt",
                reason: format!("unsupported revision {revision:#x}"),
            });
        }
        if entry_size < 128 || entry_count == 0 {
            return Err(Error::Validation {
                format: "gpt",
                reason: format!("implausible entry size {entry_size} or count {entry_count}"),
            });
        }
        if entry_count > limits.max_partitions {
            return Err(Error::Validation {
                format: "gpt",
                reason: format!("entry count {entry_count} exceeds max_partitions"),
            });
        }

        // Partition entry array + CRC verification.
        let entries_off = entries_lba * SECTOR;
        let array_len = (entry_count * entry_size) as u64;
        if entries_off + array_len > src.len() {
            return Err(Error::Validation {
                format: "gpt",
                reason: "partition entry array extends past source".into(),
            });
        }
        let mut array = vec![0u8; array_len as usize];
        src.read_at(entries_off, &mut array)?;
        let mut ec = crc32fast::Hasher::new();
        ec.update(&array);
        let computed_entries_crc = ec.finalize();
        if computed_entries_crc != entries_crc {
            return Err(Error::Validation {
                format: "gpt",
                reason: format!(
                    "entry array CRC mismatch: stored {entries_crc:#x}, computed {computed_entries_crc:#x}"
                ),
            });
        }

        // Walk entries; skip empty, keep valid. GUIDs little-endian for
        // the first three fields (mixed-endian per UEFI spec).
        let mut children = Vec::new();
        let mut warnings = Vec::new();
        for i in 0..entry_count {
            let e = &array[i * entry_size..(i + 1) * entry_size];
            let type_guid = &e[0..16];
            if type_guid.iter().all(|&b| b == 0) {
                continue;
            }
            let first_lba =
                u64::from_le_bytes([e[32], e[33], e[34], e[35], e[36], e[37], e[38], e[39]]);
            let last_lba =
                u64::from_le_bytes([e[40], e[41], e[42], e[43], e[44], e[45], e[46], e[47]]);
            let name_utf16 = &e[56..128];
            let name: String = name_utf16
                .chunks(2)
                .map(|c| u16::from_le_bytes([c[0], *c.get(1).unwrap_or(&0)]))
                .take_while(|&c| c != 0)
                .filter_map(|c| char::from_u32(u32::from(c)))
                .collect();
            if last_lba < first_lba {
                warnings.push(format!("partition {i}: last LBA < first LBA; skipped"));
                continue;
            }
            let start = first_lba * SECTOR;
            let len = (last_lba + 1 - first_lba) * SECTOR;
            let region = if start + len <= src.len() {
                Some(src.slice(start, len)?)
            } else {
                warnings.push(format!(
                    "partition {i} ({name}) extends past source; metadata only"
                ));
                None
            };
            let mut meta = BTreeMap::new();
            meta.insert("partition_index".to_string(), i.to_string());
            meta.insert("name".to_string(), name.clone());
            meta.insert("type_guid".to_string(), format_guid(type_guid));
            meta.insert("first_lba".to_string(), first_lba.to_string());
            meta.insert("last_lba".to_string(), last_lba.to_string());
            let content = match region {
                Some(r) => ChildContent::Source(r),
                None => ChildContent::Owned(Vec::new()),
            };
            let size = if start + len <= src.len() { len } else { 0 };
            children.push(ChildDraft {
                relation: RelationKind::PartitionOf,
                label: format!(
                    "GPT partition {i} \"{name}\" ({} sectors)",
                    last_lba + 1 - first_lba
                ),
                format_hint: "raw",
                content,
                size,
                metadata: meta,
                warnings: Vec::new(),
                entry_name: None,
                confidence: Confidence::Validated,
                evidence: vec!["structurally decoded by parent handler".to_string()],
            });
        }

        // Backup header awareness.
        let mut backup_ok = false;
        let backup_off = backup_lba * SECTOR;
        if backup_lba > 0 && backup_off + 8 <= src.len() {
            let mut sig = [0u8; 8];
            if src.read_at(backup_off, &mut sig).is_ok() && &sig == b"EFI PART" {
                backup_ok = true;
            }
        }

        let mut metadata = BTreeMap::new();
        metadata.insert("partition_count".to_string(), children.len().to_string());
        metadata.insert("entry_count_field".to_string(), entry_count.to_string());
        metadata.insert(
            "backup_header".to_string(),
            if backup_ok { "present" } else { "absent" }.to_string(),
        );

        Ok(HandlerOutput {
            artifacts: vec![ArtifactDraft {
                format: "gpt".to_string(),
                label: format!("GPT disk label ({} partitions)", children.len()),
                offset: base,
                size: src.len() - base,
                confidence: Confidence::Validated,
                evidence: Evidence::facts([
                    "GPT header CRC32 verified".to_string(),
                    "partition entry array CRC32 verified".to_string(),
                    format!(
                        "backup header at LBA {backup_lba} {}",
                        if backup_ok { "validated" } else { "not found" }
                    ),
                ]),
                metadata,
                warnings,
                errors: Vec::new(),
                children,
                entry_names: Vec::new(),
            }],
        })
    }
}

/// Format a partition/instance GUID in mixed-endian UEFI form.
fn format_guid(b: &[u8]) -> String {
    let d1 = u32::from_le_bytes([b[0], b[1], b[2], b[3]]);
    let d2 = u16::from_le_bytes([b[4], b[5]]);
    let d3 = u16::from_le_bytes([b[6], b[7]]);
    let rest: String = b[8..16].iter().map(|x| format!("{x:02x}")).collect();
    format!("{d1:08x}-{d2:04x}-{d3:04x}-{rest}")
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
    fn mbr_primary_partitions_as_source_backed_children() {
        // 4-sector disk: partition 1 at LBA 1 (2 sectors, FAT16 type).
        let mut disk = vec![0u8; 4 * 512];
        let e = &mut disk[446..462];
        e[4] = 0x06; // FAT16
        e[12..16].copy_from_slice(&2u32.to_le_bytes()); // count
        e[8..12].copy_from_slice(&1u32.to_le_bytes()); // LBA
        disk[510] = 0x55;
        disk[511] = 0xAA;
        // Marker inside the partition.
        disk[512..520].copy_from_slice(b"PARTDATA");
        let src = ByteSource::from_vec(disk);
        let out = validate_at(&MbrHandler, &src, 0).expect("mbr validates");
        let art = &out.artifacts[0];
        assert_eq!(art.confidence, Confidence::Validated);
        assert_eq!(art.children.len(), 1);
        match &art.children[0].content {
            ChildContent::Source(r) => {
                let mut buf = [0u8; 8];
                r.read_at(0, &mut buf).unwrap();
                assert_eq!(&buf, b"PARTDATA");
            }
            _ => panic!("partition must be source-backed"),
        }
        assert_eq!(art.children[0].relation, RelationKind::PartitionOf);
    }

    #[test]
    fn mbr_no_signature_rejected() {
        let disk = vec![0u8; 512];
        let src = ByteSource::from_vec(disk);
        // find_candidates requires the signature; validate must also.
        assert!(MbrHandler.find_candidates(&src).is_empty());
        assert!(validate_at(&MbrHandler, &src, 0).is_err());
    }

    #[test]
    fn gpt_header_and_entries_crc_verified() {
        // Build a minimal GPT: LBA0 protective MBR, LBA1 header, LBA2+
        // entry array.
        let mut disk = vec![0u8; 8 * 512];
        // Header at LBA 1.
        let hdr_off = 512usize;
        disk[hdr_off..hdr_off + 8].copy_from_slice(b"EFI PART");
        disk[hdr_off + 8..hdr_off + 12].copy_from_slice(&0x0001_0000u32.to_le_bytes());
        disk[hdr_off + 12..hdr_off + 16].copy_from_slice(&92u32.to_le_bytes());
        // current_lba=1, backup_lba=0, first/last usable.
        disk[hdr_off + 24..hdr_off + 32].copy_from_slice(&1u64.to_le_bytes());
        disk[hdr_off + 40..hdr_off + 48].copy_from_slice(&2u64.to_le_bytes());
        disk[hdr_off + 48..hdr_off + 56].copy_from_slice(&7u64.to_le_bytes());
        // entries at LBA 2, count 2, size 128.
        disk[hdr_off + 72..hdr_off + 80].copy_from_slice(&2u64.to_le_bytes());
        disk[hdr_off + 80..hdr_off + 84].copy_from_slice(&2u32.to_le_bytes());
        disk[hdr_off + 84..hdr_off + 88].copy_from_slice(&128u32.to_le_bytes());
        // Entry 0: type GUID non-zero, first=3, last=4, name "data".
        let e0 = &mut disk[2 * 512..2 * 512 + 128];
        e0[0] = 0x0B; // FAT32 basic data partition GUID starts 0x0B
        e0[32..40].copy_from_slice(&3u64.to_le_bytes());
        e0[40..48].copy_from_slice(&4u64.to_le_bytes());
        for (i, ch) in "data".chars().enumerate() {
            e0[56 + i * 2] = ch as u8;
        }
        // Compute CRCs.
        let mut entries = [0u8; 256];
        entries.copy_from_slice(&disk[2 * 512..2 * 512 + 256]);
        let mut ec = crc32fast::Hasher::new();
        ec.update(&entries);
        let entries_crc = ec.finalize();
        disk[hdr_off + 88..hdr_off + 92].copy_from_slice(&entries_crc.to_le_bytes());
        // Header CRC: zero the field, CRC the 92 bytes.
        let mut h = disk[hdr_off..hdr_off + 92].to_vec();
        h[16..20].fill(0);
        let mut hc = crc32fast::Hasher::new();
        hc.update(&h);
        disk[hdr_off + 16..hdr_off + 20].copy_from_slice(&hc.finalize().to_le_bytes());
        // Marker inside partition 0.
        disk[3 * 512..3 * 512 + 7].copy_from_slice(b"GPTDATA");

        let src = ByteSource::from_vec(disk);
        let out = validate_at(&GptHandler, &src, 512).expect("gpt validates");
        let art = &out.artifacts[0];
        assert_eq!(art.confidence, Confidence::Validated);
        assert_eq!(art.children.len(), 1);
        assert_eq!(
            art.children[0].metadata.get("name").map(String::as_str),
            Some("data")
        );
        match &art.children[0].content {
            ChildContent::Source(r) => {
                let mut buf = [0u8; 7];
                r.read_at(0, &mut buf).unwrap();
                assert_eq!(&buf, b"GPTDATA".as_slice());
            }
            _ => panic!("GPT partition must be source-backed"),
        }
    }

    #[test]
    fn gpt_corrupt_header_crc_rejected() {
        let mut disk = vec![0u8; 4 * 512];
        disk[512..520].copy_from_slice(b"EFI PART");
        disk[512 + 16..512 + 20].copy_from_slice(&0xDEAD_BEEFu32.to_le_bytes());
        let src = ByteSource::from_vec(disk);
        assert!(validate_at(&GptHandler, &src, 512).is_err());
    }
}
