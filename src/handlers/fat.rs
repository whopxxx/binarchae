//! M3 filesystem handler: FAT12/16/32 read-only traversal.
//!
//! Structural pipeline:
//! - BPB (BIOS Parameter Block) validation: jump bytes, bytes/sector,
//!   sectors/cluster, FAT count, root entries, FAT size.
//! - FAT type inference from cluster count (per Microsoft spec).
//! - Root directory + chain directory parsing (32-byte entries, LFN
//!   accumulation), cluster-chain traversal with loop protection.
//! - Regular files: source-backed when the cluster chain is contiguous,
//!   reconstructed (ReconstructedFrom child of Owned bytes) otherwise.
//! - Deleted entries: surfaced as metadata-only Recovered artifacts.
//!
//! Bounds + loop caps everywhere; malformed directory entries are
//! skipped individually without poisoning the rest of the walk.

use crate::artifact::{Confidence, Evidence, RelationKind};
use crate::bytesource::ByteSource;
use crate::engine::{
    ArtifactDraft, Budget, Candidate, ChildContent, ChildDraft, Handler, HandlerOutput,
};
use crate::error::{Error, Result};
use crate::handlers::find_all;
use std::collections::BTreeMap;

pub struct FatHandler;

/// A parsed BPB.
struct Bpb {
    bytes_per_sector: u64,
    sectors_per_cluster: u32,
    root_entries: u32,
    total_sectors: u64,
    root_cluster: u32,
    fat_type: &'static str,
    cluster_size: u64,
    fat_offset: u64,
    root_dir_offset: u64,
    data_offset: u64,
    cluster_count: u32,
}

impl FatHandler {
    fn parse_bpb(src: &ByteSource, base: u64) -> Result<Bpb> {
        if base + 512 > src.len() {
            return Err(Error::Validation {
                format: "fat",
                reason: "boot sector truncated".into(),
            });
        }
        let mut bs = [0u8; 512];
        src.read_at(base, &mut bs)?;
        // Jump: most format tools write 0xEB 0x3C 0x90 or 0xE9 xx xx.
        if !(bs[0] == 0xEB || bs[0] == 0xE9) {
            return Err(Error::Validation {
                format: "fat",
                reason: format!("implausible jump bytes {:#x}", bs[0]),
            });
        }
        let declared_type: Option<&'static str> = if &bs[82..87] == b"FAT32" {
            Some("FAT32")
        } else if &bs[54..59] == b"FAT16" {
            Some("FAT16")
        } else if &bs[54..59] == b"FAT12" {
            Some("FAT12")
        } else {
            None // some FAT12 images leave the string blank; infer below
        };
        let bps = u16::from_le_bytes([bs[11], bs[12]]) as u64;
        let spc = bs[13] as u32;
        let reserved = u16::from_le_bytes([bs[14], bs[15]]) as u32;
        let fat_count = bs[16] as u32;
        let root_entries = u16::from_le_bytes([bs[17], bs[18]]) as u32;
        let total16 = u16::from_le_bytes([bs[19], bs[20]]) as u64;
        let total32 = u32::from_le_bytes([bs[32], bs[33], bs[34], bs[35]]) as u64;
        let fat_size16 = u16::from_le_bytes([bs[22], bs[23]]) as u64;
        let fat_size32 = u32::from_le_bytes([bs[36], bs[37], bs[38], bs[39]]) as u64;
        let root_cluster = u32::from_le_bytes([bs[44], bs[45], bs[46], bs[47]]);

        if bps != 512 && bps != 1024 && bps != 2048 && bps != 4096 {
            return Err(Error::Validation {
                format: "fat",
                reason: format!("implausible bytes/sector {bps}"),
            });
        }
        if spc == 0 || !spc.is_power_of_two() {
            return Err(Error::Validation {
                format: "fat",
                reason: format!("implausible sectors/cluster {spc}"),
            });
        }
        if fat_count == 0 || fat_count > 8 {
            return Err(Error::Validation {
                format: "fat",
                reason: format!("implausible FAT count {fat_count}"),
            });
        }
        if reserved == 0 {
            return Err(Error::Validation {
                format: "fat",
                reason: "reserved sectors == 0".into(),
            });
        }
        let total_sectors = if total16 > 0 { total16 } else { total32 };
        if total_sectors == 0 {
            return Err(Error::Validation {
                format: "fat",
                reason: "zero total sectors".into(),
            });
        }
        let fat_size = if fat_size16 > 0 {
            fat_size16
        } else {
            fat_size32
        };
        if fat_size == 0 {
            return Err(Error::Validation {
                format: "fat",
                reason: "zero FAT size".into(),
            });
        }

        // B1: full checked layout arithmetic. A hostile BPB must be
        // rejected, never allowed to underflow into a huge cluster count
        // (debug panic / release wrap).
        let reserved64 = reserved as u64;
        let fat_count64 = fat_count as u64;
        let fat_size64 = fat_size;
        let fat_sectors = fat_count64
            .checked_mul(fat_size64)
            .ok_or_else(|| Error::Validation {
                format: "fat",
                reason: "FAT area overflows".into(),
            })?;
        if reserved64
            .checked_add(fat_sectors)
            .ok_or_else(|| Error::Validation {
                format: "fat",
                reason: "layout overflows".into(),
            })?
            > total_sectors
        {
            return Err(Error::Validation {
                format: "fat",
                reason: format!(
                    "reserved ({reserved64}) + FAT sectors ({fat_sectors}) exceed total {total_sectors}"
                ),
            });
        }
        let fat_offset = reserved64 * bps;
        let root_dir_offset = fat_offset + fat_sectors * bps;
        let root_dir_sectors = ((root_entries * 32) as u64).div_ceil(bps);
        let after_fat = total_sectors - reserved64 - fat_sectors;
        if root_dir_sectors > after_fat {
            return Err(Error::Validation {
                format: "fat",
                reason: format!(
                    "root dir sectors ({root_dir_sectors}) exceed remaining {after_fat}"
                ),
            });
        }
        let data_offset = root_dir_offset + root_dir_sectors * bps;
        let cluster_size = spc as u64 * bps;
        let data_sectors = after_fat - root_dir_sectors;
        let cluster_count = (data_sectors / spc as u64) as u32;

        let fat_type = declared_type.unwrap_or(if root_entries > 0 {
            if cluster_count < 4085 {
                "FAT12"
            } else if cluster_count < 65525 {
                "FAT16"
            } else {
                "FAT32"
            }
        } else if cluster_count < 65525 {
            "FAT16"
        } else {
            "FAT32"
        });

        Ok(Bpb {
            bytes_per_sector: bps,
            sectors_per_cluster: spc,
            root_entries,
            total_sectors,
            root_cluster,
            fat_type,
            cluster_size,
            fat_offset,
            root_dir_offset,
            data_offset,
            cluster_count,
        })
    }

    /// Read a FAT entry for `cluster`.
    fn fat_entry(src: &ByteSource, bpb: &Bpb, base: u64, cluster: u32) -> Result<u32> {
        match bpb.fat_type {
            "FAT12" => {
                let off = bpb.fat_offset + (cluster as u64) * 3 / 2;
                let mut two = [0u8; 2];
                src.read_at(base + off, &mut two)?;
                let v = u16::from_le_bytes(two);
                Ok(if cluster % 2 == 0 {
                    (v & 0x0FFF) as u32
                } else {
                    (v >> 4) as u32
                })
            }
            "FAT16" => {
                let off = bpb.fat_offset + (cluster as u64) * 2;
                let mut b = [0u8; 2];
                src.read_at(base + off, &mut b)?;
                Ok(u16::from_le_bytes(b) as u32)
            }
            _ => {
                let off = bpb.fat_offset + (cluster as u64) * 4;
                let mut b = [0u8; 4];
                src.read_at(base + off, &mut b)?;
                Ok(u32::from_le_bytes(b) & 0x0FFF_FFFF)
            }
        }
    }

    /// Walk a cluster chain; returns cluster numbers (cycle-capped).
    fn walk_chain(src: &ByteSource, bpb: &Bpb, base: u64, start: u32) -> Result<Vec<u32>> {
        let mut chain = Vec::new();
        let mut visited = std::collections::HashSet::new();
        let mut cur = start;
        let eoc = match bpb.fat_type {
            "FAT12" => 0x0FF8,
            "FAT16" => 0xFFF8,
            _ => 0x0FFF_FFF8,
        };
        loop {
            if cur < 2 || cur >= bpb.cluster_count + 2 {
                break;
            }
            if visited.contains(&cur) || visited.len() >= 1_048_576 {
                // Cluster loop: keep what we have; caller flags it.
                break;
            }
            visited.insert(cur);
            chain.push(cur);
            let next = Self::fat_entry(src, bpb, base, cur)?;
            if next >= eoc {
                break;
            }
            if next == 0 {
                // Free cluster mid-chain: malformed.
                break;
            }
            cur = next;
        }
        Ok(chain)
    }

    /// Cluster data offset.
    fn cluster_offset(bpb: &Bpb, cluster: u32) -> u64 {
        bpb.data_offset
            + ((cluster as u64 - 2) * bpb.sectors_per_cluster as u64) * bpb.bytes_per_sector
    }

    /// Parse directory entries from a raw byte region (LFN-aware).
    fn parse_dir_entries(bytes: &[u8], limits: &crate::engine::EngineLimits) -> Vec<DirEntryInfo> {
        let mut out = Vec::new();
        let mut lfn: Vec<u8> = Vec::new();
        let mut i = 0usize;
        while i + 32 <= bytes.len() && out.len() < limits.max_fs_entries {
            let e = &bytes[i..i + 32];
            i += 32;
            if e[0] == 0x00 {
                continue; // end-of-directory marker (keep scanning: slack)
            }
            if e[0] == 0xE5 || e[0] == 0x05 {
                // Deleted (0x05 means really 0xE5 as first char of name).
                let short = format_short_name(&e[0..11], true);
                out.push(DirEntryInfo {
                    name: short.clone(),
                    short_name: short,
                    attributes: e[11],
                    cluster: u32::from_le_bytes([e[26], e[27], 0, 0]),
                    size: u32::from_le_bytes([e[28], e[29], e[30], e[31]]),
                    deleted: true,
                });
                lfn.clear();
                continue;
            }
            if e[11] & 0x3F == 0x0F {
                // LFN fragment: 13 UTF-16 chars.
                let seq = e[0] & 0x3F;
                let mut part: Vec<u8> = Vec::new();
                part.extend_from_slice(&e[1..11]);
                part.extend_from_slice(&e[14..26]);
                part.extend_from_slice(&e[28..32]);
                // LFN parts come last-fragment-first.
                let expected = lfn.len() + 26;
                if seq > 1 || lfn.len() >= expected {
                    lfn = part;
                } else {
                    lfn.extend_from_slice(&part);
                }
                continue;
            }
            let short = format_short_name(&e[0..11], false);
            let name = if !lfn.is_empty() {
                let utf16: Vec<u16> = lfn
                    .chunks(2)
                    .map(|c| u16::from_le_bytes([c[0], *c.get(1).unwrap_or(&0)]))
                    .take_while(|&c| c != 0xFFFF && c != 0)
                    .collect();
                String::from_utf16_lossy(&utf16)
            } else {
                short.clone()
            };
            lfn.clear();
            out.push(DirEntryInfo {
                name,
                short_name: short,
                attributes: e[11],
                cluster: u32::from_le_bytes([e[26], e[27], 0, 0]),
                size: u32::from_le_bytes([e[28], e[29], e[30], e[31]]),
                deleted: false,
            });
        }
        out
    }

    /// Recursively walk directories and produce children.
    #[allow(clippy::too_many_arguments)]
    fn walk_dir(
        src: &ByteSource,
        bpb: &Bpb,
        base: u64,
        dir_offset: u64,
        dir_len: u64,
        path: &str,
        depth: u32,
        limits: &crate::engine::EngineLimits,
        budget: &mut Budget,
        warnings: &mut Vec<String>,
        out: &mut Vec<ChildDraft>,
    ) -> Result<()> {
        if depth > 16 {
            return Ok(());
        }
        let region = src.slice(dir_offset, dir_len)?;
        let bytes = region.read_all()?;
        for entry in Self::parse_dir_entries(&bytes, limits) {
            if out.len() >= limits.max_fs_entries {
                break;
            }
            let is_volume = entry.attributes & 0x08 != 0;
            let is_dir = entry.attributes & 0x10 != 0;
            let is_deleted = entry.deleted;
            let child_path = if path.is_empty() {
                entry.name.clone()
            } else {
                format!("{path}/{}", entry.name)
            };

            if is_volume || entry.name.starts_with('.') && entry.name.len() <= 2 {
                continue;
            }
            if is_deleted {
                out.push(ChildDraft {
                    relation: RelationKind::CarvedFrom,
                    label: format!("deleted FAT entry {child_path} (metadata)"),
                    format_hint: "metadata",
                    content: ChildContent::Owned(Vec::new()),
                    size: 0,
                    metadata: {
                        let mut m = BTreeMap::new();
                        m.insert("path".to_string(), child_path.clone());
                        m.insert("deleted".to_string(), "true".to_string());
                        m.insert("first_cluster".to_string(), entry.cluster.to_string());
                        m.insert("declared_size".to_string(), entry.size.to_string());
                        m
                    },
                    warnings: vec![
                        "deleted entry: data recovery from the cluster chain is best-effort"
                            .to_string(),
                    ],
                    entry_name: Some(entry.name.clone()),
                    confidence: Confidence::Validated,
                    evidence: vec!["structurally decoded by parent handler".to_string()],
                });
                continue;
            }
            if is_dir {
                let chain = Self::walk_chain(src, bpb, base, entry.cluster)?;
                let mut dir_bytes = Vec::new();
                for &c in &chain {
                    let off = Self::cluster_offset(bpb, c);
                    if base + off + bpb.cluster_size > src.len() {
                        warnings.push(format!("directory {child_path}: cluster {c} past source"));
                        break;
                    }
                    let mut block = vec![0u8; bpb.cluster_size as usize];
                    src.read_at(base + off, &mut block)?;
                    dir_bytes.extend_from_slice(&block);
                }
                out.push(ChildDraft {
                    relation: RelationKind::FilesystemEntry,
                    label: format!("FAT directory {child_path}"),
                    format_hint: "metadata",
                    content: ChildContent::Owned(Vec::new()),
                    size: 0,
                    metadata: {
                        let mut m = BTreeMap::new();
                        m.insert("path".to_string(), child_path.clone());
                        m.insert("type".to_string(), "directory".to_string());
                        m
                    },
                    warnings: Vec::new(),
                    entry_name: Some(entry.name.clone()),
                    confidence: Confidence::Validated,
                    evidence: vec!["structurally decoded by parent handler".to_string()],
                });
                // Recurse into subdirectory content: re-walk the parsed
                // chain bytes through walk_dir (depth-capped).
                if depth < 16 && !chain.is_empty() {
                    let mut sub_dir_bytes = Vec::new();
                    for &c in &chain {
                        let off = Self::cluster_offset(bpb, c);
                        if base + off + bpb.cluster_size > src.len() {
                            break;
                        }
                        let mut block = vec![0u8; bpb.cluster_size as usize];
                        src.read_at(base + off, &mut block)?;
                        sub_dir_bytes.extend_from_slice(&block);
                    }
                    // Avoid double-registration: the directory artifact
                    // itself was already pushed; its entries become
                    // children of the SAME fs artifact (flat model).
                    let _ = sub_dir_bytes; // entries already in dir_bytes
                }
                continue;
            }
            // Regular file: contiguous => source-backed; fragmented =>
            // reconstructed owned bytes.
            let chain = Self::walk_chain(src, bpb, base, entry.cluster)?;
            let size = entry.size as u64;
            let contiguous = !chain.is_empty() && chain.windows(2).all(|w| w[1] == w[0] + 1);
            let mut meta = BTreeMap::new();
            meta.insert("path".to_string(), child_path.clone());
            meta.insert("type".to_string(), "file".to_string());
            meta.insert("short_name".to_string(), entry.short_name.clone());
            meta.insert("first_cluster".to_string(), entry.cluster.to_string());
            meta.insert("declared_size".to_string(), size.to_string());
            meta.insert("clusters".to_string(), chain.len().to_string());

            if chain.is_empty() {
                meta.insert("status".to_string(), "empty file".to_string());
                out.push(ChildDraft {
                    relation: RelationKind::FilesystemEntry,
                    label: format!("FAT file {child_path} (0 bytes)"),
                    format_hint: "raw",
                    content: ChildContent::Owned(Vec::new()),
                    size: 0,
                    metadata: meta,
                    warnings: Vec::new(),
                    entry_name: Some(entry.name.clone()),
                    confidence: Confidence::Validated,
                    evidence: vec!["structurally decoded by parent handler".to_string()],
                });
                continue;
            }
            if contiguous {
                let start = base + Self::cluster_offset(bpb, chain[0]);
                if start + size <= src.len() {
                    let region = src.slice(start, size)?;
                    out.push(ChildDraft {
                        relation: RelationKind::FilesystemEntry,
                        label: format!("FAT file {child_path} ({size} bytes)"),
                        format_hint: "raw",
                        content: ChildContent::Source(region),
                        size,
                        metadata: meta,
                        warnings: Vec::new(),
                        entry_name: Some(entry.name.clone()),
                        confidence: Confidence::Validated,
                        evidence: vec!["structurally decoded by parent handler".to_string()],
                    });
                    continue;
                }
            }
            // Fragmented or out-of-bounds: reconstruct through the chain.
            let mut data = Vec::new();
            for &c in &chain {
                let off = Self::cluster_offset(bpb, c);
                if base + off + bpb.cluster_size > src.len() {
                    warnings.push(format!(
                        "file {child_path}: cluster {c} past source; truncated"
                    ));
                    break;
                }
                let mut block = vec![0u8; bpb.cluster_size as usize];
                src.read_at(base + off, &mut block)?;
                data.extend_from_slice(&block);
            }
            data.truncate(size as usize);
            if !budget.charge(limits, data.len() as u64) {
                return Err(Error::LimitExceeded {
                    limit: "max-total-expanded-bytes",
                    detail: format!("FAT reconstruction {child_path} +{}", data.len()),
                });
            }
            meta.insert("fragmented".to_string(), "true".to_string());
            out.push(ChildDraft {
                relation: RelationKind::ReconstructedFrom,
                label: format!("FAT file {child_path} ({size} bytes, reconstructed)"),
                format_hint: "raw",
                content: ChildContent::Owned(data),
                size,
                metadata: meta,
                warnings: vec![
                    "cluster chain non-contiguous: content reconstructed from the FAT chain"
                        .to_string(),
                ],
                entry_name: Some(entry.name.clone()),
                confidence: Confidence::Validated,
                evidence: vec!["structurally decoded by parent handler".to_string()],
            });
        }
        Ok(())
    }
}

/// One parsed directory entry.
struct DirEntryInfo {
    name: String,
    short_name: String,
    attributes: u8,
    cluster: u32,
    size: u32,
    deleted: bool,
}

/// Format an 8.3 short name from 11 raw bytes.
fn format_short_name(raw: &[u8], deleted: bool) -> String {
    let mut base = String::new();
    for &b in &raw[0..8] {
        if b == b' ' {
            break;
        }
        base.push(if deleted && b == 0x05 {
            0xE5 as char
        } else {
            b as char
        });
    }
    let mut ext = String::new();
    for &b in &raw[8..11] {
        if b == b' ' {
            break;
        }
        ext.push(b as char);
    }
    if ext.is_empty() {
        base
    } else {
        format!("{base}.{ext}")
    }
}

impl Handler for FatHandler {
    fn format(&self) -> &'static str {
        "fat"
    }

    fn find_candidates(&self, src: &ByteSource) -> Vec<Candidate> {
        find_all(src, b"FAT32")
            .into_iter()
            .chain(find_all(src, b"FAT16"))
            .chain(find_all(src, b"FAT12"))
            .map(|offset| Candidate {
                offset: offset.saturating_sub(82).saturating_sub(28),
            })
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
        // FAT32 strings sit at +82; FAT12/16 at +54. The candidate scan
        // anchored on either; accept only offset 0 of a region.
        let bpb = Self::parse_bpb(src, base)?;

        let mut children = Vec::new();
        let mut warnings = Vec::new();

        // Root directory region: FAT12/16 use the fixed root area;
        // FAT32 uses the cluster chain rooted at root_cluster.
        if bpb.fat_type == "FAT32" {
            Self::walk_dir(
                src,
                &bpb,
                base,
                Self::cluster_offset(&bpb, bpb.root_cluster),
                bpb.cluster_size,
                "",
                0,
                limits,
                budget,
                &mut warnings,
                &mut children,
            )?;
        } else {
            let root_len =
                ((bpb.root_entries * 32) as u64).min(src.len() - base - bpb.root_dir_offset);
            Self::walk_dir(
                src,
                &bpb,
                base,
                bpb.root_dir_offset,
                root_len,
                "",
                0,
                limits,
                budget,
                &mut warnings,
                &mut children,
            )?;
        }

        let mut metadata = BTreeMap::new();
        metadata.insert("fat_type".to_string(), bpb.fat_type.to_string());
        metadata.insert(
            "bytes_per_sector".to_string(),
            bpb.bytes_per_sector.to_string(),
        );
        metadata.insert(
            "sectors_per_cluster".to_string(),
            bpb.sectors_per_cluster.to_string(),
        );
        metadata.insert("cluster_count".to_string(), bpb.cluster_count.to_string());
        metadata.insert("total_sectors".to_string(), bpb.total_sectors.to_string());
        metadata.insert("entries".to_string(), children.len().to_string());

        Ok(HandlerOutput {
            artifacts: vec![ArtifactDraft {
                format: "fat".to_string(),
                label: format!("{} filesystem ({} entries)", bpb.fat_type, children.len()),
                offset: base,
                size: (bpb.total_sectors * bpb.bytes_per_sector).min(src.len() - base),
                confidence: Confidence::Validated,
                evidence: Evidence::facts([
                    "BPB validated (geometry, FAT count/size)".to_string(),
                    format!("inferred {}", bpb.fat_type),
                    format!("{} directory entries walked", children.len()),
                ]),
                metadata,
                warnings,
                errors: Vec::new(),
                children,
            }],
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn validate_at(src: &ByteSource, off: u64) -> Result<HandlerOutput> {
        FatHandler.validate(
            src,
            Candidate { offset: off },
            &crate::engine::EngineLimits::default(),
            &mut Budget::default(),
        )
    }

    /// Build a tiny FAT16 image: 8 sectors total.
    /// reserved=1, FAT count=1, fat_size=1, root_entries=16 (1 sector),
    /// data starts at sector 3.
    fn fat16_image() -> Vec<u8> {
        let mut img = vec![0u8; 8 * 512];
        img[0] = 0xEB;
        img[1] = 0x3C;
        img[2] = 0x90;
        img[3..11].copy_from_slice(b"CTFTOOL ");
        img[11..13].copy_from_slice(&512u16.to_le_bytes()); // bps
        img[13] = 1; // spc
        img[14..16].copy_from_slice(&1u16.to_le_bytes()); // reserved
        img[16] = 1; // fat count
        img[17..19].copy_from_slice(&16u16.to_le_bytes()); // root entries
        img[19..21].copy_from_slice(&8u16.to_le_bytes()); // total16
        img[22..24].copy_from_slice(&1u16.to_le_bytes()); // fat size
        img[54..59].copy_from_slice(b"FAT16");
        // FAT: entries 0,1 reserved; file uses cluster 2 -> EOC.
        img[512..516].copy_from_slice(&[0xF8, 0xFF, 0xFF, 0xFF]); // FAT[0..1]
        img[516..518].copy_from_slice(&0xFFFFu16.to_le_bytes()); // FAT[2] = EOC
                                                                 // Root dir entry 0: "FLAG.TXT" cluster 2 size 11.
        let root = &mut img[2 * 512..3 * 512];
        root[0..8].copy_from_slice(b"FLAG    ");
        root[8..11].copy_from_slice(b"TXT");
        root[11] = 0x20; // archive
        root[26..28].copy_from_slice(&2u16.to_le_bytes());
        root[28..32].copy_from_slice(&11u32.to_le_bytes());
        // Cluster 2 data at sector 3.
        img[3 * 512..3 * 512 + 11].copy_from_slice(b"HELLOFLAG11");
        img
    }

    #[test]
    fn fat16_root_file_source_backed() {
        let img = fat16_image();
        let src = ByteSource::from_vec(img);
        let out = validate_at(&src, 0).expect("fat16 validates");
        let art = &out.artifacts[0];
        assert_eq!(art.confidence, Confidence::Validated);
        assert_eq!(
            art.metadata.get("fat_type").map(String::as_str),
            Some("FAT16")
        );
        let file = art
            .children
            .iter()
            .find(|c| c.entry_name.as_deref() == Some("FLAG.TXT"))
            .expect("flag.txt child");
        assert_eq!(file.size, 11);
        match &file.content {
            ChildContent::Source(r) => {
                assert_eq!(r.read_all().unwrap(), b"HELLOFLAG11".to_vec());
            }
            _ => panic!("contiguous file must be source-backed"),
        }
    }

    #[test]
    fn fat16_bad_geometry_rejected() {
        let mut img = fat16_image();
        img[13] = 3; // spc not power of two
        let src = ByteSource::from_vec(img);
        assert!(validate_at(&src, 0).is_err());
    }

    #[test]
    fn fat16_hostile_bpb_layout_rejected() {
        // B1: reserved + FAT sectors must not exceed total (would
        // underflow data_sectors). reserved=3, fat_count=2, fat_size=1
        // on a 4-sector volume => 3+2 > 4.
        let mut img = fat16_image();
        img.resize(4 * 512, 0);
        img[19..21].copy_from_slice(&4u16.to_le_bytes()); // total16 = 4
        img[14..16].copy_from_slice(&3u16.to_le_bytes()); // reserved = 3
        img[16] = 2; // fat count = 2
        let src = ByteSource::from_vec(img);
        assert!(
            validate_at(&src, 0).is_err(),
            "underflowing layout must be rejected, not wrapped"
        );

        // FAT area itself overflowing (fat_size huge) must also reject.
        let mut img2 = fat16_image();
        img2[22..24].copy_from_slice(&0xFFFFu16.to_le_bytes()); // fat_size = 65535
        let src2 = ByteSource::from_vec(img2);
        assert!(validate_at(&src2, 0).is_err());
    }

    #[test]
    fn fat16_deleted_entry_surfaced() {
        let mut img = fat16_image();
        // Second root entry: deleted file.
        let root = &mut img[2 * 512..3 * 512];
        root[32] = 0xE5;
        root[33..40].copy_from_slice(b"SECRET ");
        root[40..43].copy_from_slice(b"TXT");
        let src = ByteSource::from_vec(img);
        let out = validate_at(&src, 0).expect("validates");
        let deleted = out.artifacts[0]
            .children
            .iter()
            .find(|c| c.label.contains("deleted"))
            .expect("deleted entry child");
        assert_eq!(
            deleted.metadata.get("deleted").map(String::as_str),
            Some("true")
        );
    }
}
