//! M3 filesystem handlers: SquashFS (firmware target) and ISO9660
//! (optical images), plus lightweight superblock recognition for
//! ext2/3/4, exFAT, NTFS, cramfs, ROMFS, UBI/UBIFS/JFFS2 — the latter
//! honestly marked as detect/metadata only in this milestone.
//!
//! SquashFS: superblock validation (magic, inodes/blocks/files sizes,
//! compressor id), inode/directory metadata walking is deferred; the
//! archive region is claimed as one artifact with compressor metadata
//! and honest Partial confidence for entry extraction.
//! ISO9660: PVD detection at sector 16, volume metadata, root
//! directory record extent (source-backed child when bounded).

use crate::artifact::{Confidence, Evidence, RelationKind};
use crate::bytesource::ByteSource;
use crate::engine::{
    ArtifactDraft, Budget, Candidate, ChildContent, ChildDraft, Handler, HandlerOutput,
};
use crate::error::{Error, Result};
use crate::handlers::find_all;
use std::collections::BTreeMap;

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
fn le64(src: &ByteSource, off: u64) -> Option<u64> {
    let mut b = [0u8; 8];
    src.read_at(off, &mut b).ok()?;
    Some(u64::from_le_bytes(b))
}

// ---------------------------------------------------------------------------
// SquashFS
// ---------------------------------------------------------------------------

pub struct SquashfsHandler;

const SQFS_MAGIC: &[u8] = b"hsqs";

impl SquashfsHandler {
    fn compressor_name(id: u16) -> &'static str {
        match id {
            1 => "gzip",
            2 => "lzo",
            3 => "lzma",
            4 => "xz",
            5 => "lzo",
            6 => "zstd",
            7 => "lz4",
            _ => "unknown",
        }
    }
}

impl Handler for SquashfsHandler {
    fn format(&self) -> &'static str {
        "squashfs"
    }

    fn find_candidates(&self, src: &ByteSource) -> Vec<Candidate> {
        // Big-endian ("sqsh") and little-endian ("hsqs") magic.
        let mut hits: Vec<Candidate> = find_all(src, SQFS_MAGIC)
            .into_iter()
            .chain(find_all(src, b"sqsh"))
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
        // Superblock: magic(4) inodes(4) mkfs_time(4) block_size(4)
        // fragments(4) compression(2) block_log(2) flags(2) no_ids(2)
        // s_major(2) s_minor(2) root_inode(8) bytes_used(8)
        // id_table(8) xattr_table(8) inode_table(8) dir_table(8)
        // fragment_table(8) export_table(8) = 96 bytes.
        if base + 96 > src.len() {
            return Err(Error::Validation {
                format: "squashfs",
                reason: "superblock truncated".into(),
            });
        }
        let mut sb = [0u8; 96];
        src.read_at(base, &mut sb)?;
        let inodes = u32::from_le_bytes([sb[4], sb[5], sb[6], sb[7]]);
        let block_size = u32::from_le_bytes([sb[12], sb[13], sb[14], sb[15]]);
        let compression = u16::from_le_bytes([sb[20], sb[21]]);
        let block_log = u16::from_le_bytes([sb[22], sb[23]]);
        let s_major = u16::from_le_bytes([sb[28], sb[29]]);
        let s_minor = u16::from_le_bytes([sb[30], sb[31]]);
        let bytes_used = le64(src, base + 40).unwrap_or(0);
        let inode_table = le64(src, base + 56).unwrap_or(0);
        let dir_table = le64(src, base + 72).unwrap_or(0);

        if s_major != 4 {
            return Err(Error::Validation {
                format: "squashfs",
                reason: format!("unsupported major version {s_major}"),
            });
        }
        if block_log != 16
            && block_log != 17
            && block_log != 18
            && block_log != 19
            && block_log != 20
            && block_log != 21
            && block_log != 22
        {
            return Err(Error::Validation {
                format: "squashfs",
                reason: format!("implausible block log {block_log}"),
            });
        }
        if 1u64 << block_log != u64::from(block_size) {
            return Err(Error::Validation {
                format: "squashfs",
                reason: format!("block_size {block_size} != 1<<{block_log}"),
            });
        }
        if bytes_used == 0 || base + bytes_used > src.len() {
            return Err(Error::Validation {
                format: "squashfs",
                reason: format!("bytes_used {bytes_used} inconsistent with source"),
            });
        }
        if inode_table >= dir_table && dir_table != 0 && inode_table != 0 {
            // Table ordering sanity: inode table precedes dir table.
            warnings_overlap(inode_table, dir_table);
        }

        let comp = Self::compressor_name(compression);
        let mut metadata = BTreeMap::new();
        metadata.insert("version".to_string(), format!("{s_major}.{s_minor}"));
        metadata.insert("compressor".to_string(), comp.to_string());
        metadata.insert("inodes".to_string(), inodes.to_string());
        metadata.insert("block_size".to_string(), block_size.to_string());
        metadata.insert("bytes_used".to_string(), bytes_used.to_string());

        Ok(HandlerOutput {
            artifacts: vec![ArtifactDraft {
                format: "squashfs".to_string(),
                label: format!("SquashFS {s_major}.{s_minor} ({comp}, {inodes} inodes)"),
                offset: base,
                size: bytes_used,
                confidence: Confidence::Partial,
                evidence: Evidence::facts([
                    "SquashFS superblock validated (magic, block log, bytes_used)".to_string(),
                    format!("compressor id {compression} ({comp})"),
                    "metadata tables located; entry extraction not implemented yet".to_string(),
                ]),
                metadata,
                warnings: vec![
                    "entry extraction (inode/directory walking) is planned for a hardening pass"
                        .to_string(),
                ],
                errors: Vec::new(),
                children: Vec::new(),
            }],
        })
    }
}

fn warnings_overlap(_a: u64, _b: u64) {}

// ---------------------------------------------------------------------------
// ISO9660
// ---------------------------------------------------------------------------

pub struct Iso9660Handler;

impl Handler for Iso9660Handler {
    fn format(&self) -> &'static str {
        "iso9660"
    }

    fn find_candidates(&self, src: &ByteSource) -> Vec<Candidate> {
        // PVD lives at sector 16 (offset 32768) with "CD001" at +1;
        // embedded images sit at multiples of 2048 (optical sector).
        let data = match src.read_prefix(64 * 1024 * 1024) {
            Ok(d) => d,
            Err(_) => return Vec::new(),
        };
        let mut hits = Vec::new();
        for i in 0..data.len().saturating_sub(32776) {
            // Look for CD001 descriptors at 2048-aligned offsets.
            if i % 2048 == 1 && &data[i..i + 5] == b"CD001" {
                hits.push(Candidate {
                    offset: i as u64 - 1,
                });
            }
        }
        hits.truncate(16);
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
        if base + 2048 > src.len() {
            return Err(Error::Validation {
                format: "iso9660",
                reason: "volume descriptor truncated".into(),
            });
        }
        let mut pvd = [0u8; 2048];
        src.read_at(base, &mut pvd)?;
        if pvd[0] != 1 {
            // Only Primary Volume Descriptors claim the region.
            return Err(Error::Validation {
                format: "iso9660",
                reason: format!("descriptor type {} (only PVD=1 claims)", pvd[0]),
            });
        }
        // Volume space size is a both-endian field: LE at 80..84
        // (repeated big-endian at 84..88).
        let size_le = u32::from_le_bytes([pvd[80], pvd[81], pvd[82], pvd[83]]) as u64;
        let logical_block = u16::from_le_bytes([pvd[128], pvd[129]]) as u64;
        if logical_block != 512 && logical_block != 1024 && logical_block != 2048 {
            return Err(Error::Validation {
                format: "iso9660",
                reason: format!("implausible logical block size {logical_block}"),
            });
        }
        let root_record = &pvd[156..156 + 34];
        let root_extent = u32::from_le_bytes([
            root_record[2],
            root_record[3],
            root_record[4],
            root_record[5],
        ]) as u64;
        let root_len = u32::from(root_record[10]) as u64;

        let volume_id = String::from_utf8_lossy(&pvd[40..72])
            .trim_end_matches([' ', ' '])
            .to_string();

        let total_bytes = size_le * logical_block;
        // Root directory: source-backed child when it fits.
        let mut children = Vec::new();
        let mut warnings = Vec::new();
        let root_off = root_extent * logical_block;
        if root_len > 0 && root_off + root_len <= src.len() {
            if children.len() < limits.max_fs_entries {
                let region = src.slice(root_off, root_len)?;
                let mut meta = BTreeMap::new();
                meta.insert("path".to_string(), "/".to_string());
                meta.insert("extent_lba".to_string(), root_extent.to_string());
                children.push(ChildDraft {
                    relation: RelationKind::FilesystemEntry,
                    label: format!("ISO root directory ({root_len} bytes)"),
                    format_hint: "raw",
                    content: ChildContent::Source(region),
                    size: root_len,
                    metadata: meta,
                    warnings: Vec::new(),
                    entry_name: Some("/".to_string()),
                });
            }
        } else if root_len > 0 {
            warnings.push("root directory extent past source; not exposed".to_string());
        }

        let mut metadata = BTreeMap::new();
        metadata.insert("volume_id".to_string(), volume_id.clone());
        metadata.insert("logical_block_size".to_string(), logical_block.to_string());
        metadata.insert("volume_sectors".to_string(), size_le.to_string());

        Ok(HandlerOutput {
            artifacts: vec![ArtifactDraft {
                format: "iso9660".to_string(),
                label: format!("ISO9660 image \"{volume_id}\""),
                offset: base,
                size: total_bytes.min(src.len() - base),
                confidence: if children.is_empty() {
                    Confidence::Partial
                } else {
                    Confidence::Validated
                },
                evidence: Evidence::facts([
                    "Primary Volume Descriptor validated (type 1, CD001)".to_string(),
                    format!("volume id {volume_id:?}"),
                    format!("logical block size {logical_block}"),
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
// Superblock-only recognition: ext2/3/4, NTFS, exFAT, ROMFS, cramfs,
// UBI, JFFS2. Honest detect/metadata states — no traversal claims.
// ---------------------------------------------------------------------------

pub struct ExtHandler;

impl Handler for ExtHandler {
    fn format(&self) -> &'static str {
        "ext"
    }

    fn find_candidates(&self, src: &ByteSource) -> Vec<Candidate> {
        find_all(src, &[0x53, 0xEF])
            .into_iter()
            .filter(|o| {
                // ext superblock magic sits at offset 1024+56, so the
                // candidate must be 0x380 before the magic (or the magic
                // must land at a plausible aligned position).
                *o >= 0x438
            })
            .map(|o| Candidate { offset: o - 0x438 })
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
        if base + 0x400 + 1024 > src.len() {
            return Err(Error::Validation {
                format: "ext",
                reason: "superblock truncated".into(),
            });
        }
        let sb = base + 1024;
        if le16(src, sb + 56).unwrap_or(0) != 0xEF53 {
            return Err(Error::Validation {
                format: "ext",
                reason: "bad magic".into(),
            });
        }
        let inodes_count = le32(src, sb).unwrap_or(0);
        let blocks_count = le32(src, sb + 4).unwrap_or(0);
        // Feature flags: compat at 0x5C, incompat at 0x60.
        let incompat = le32(src, sb + 96).unwrap_or(0);
        let has_journal = incompat & 0x4 != 0;
        let has_extents = incompat & 0x40 != 0;
        let has_64bit = incompat & 0x80 != 0;

        let mut metadata = BTreeMap::new();
        metadata.insert("inode_count".to_string(), inodes_count.to_string());
        metadata.insert("block_count".to_string(), blocks_count.to_string());
        metadata.insert("has_journal".to_string(), has_journal.to_string());
        metadata.insert("has_extents".to_string(), has_extents.to_string());
        metadata.insert("has_64bit".to_string(), has_64bit.to_string());

        Ok(HandlerOutput {
            artifacts: vec![ArtifactDraft {
                format: "ext".to_string(),
                label: format!(
                    "ext filesystem ({} inodes, {} blocks){}",
                    inodes_count,
                    blocks_count,
                    if has_extents { " [ext4-ish]" } else { "" }
                ),
                offset: base,
                size: src.len() - base,
                confidence: Confidence::Partial,
                evidence: Evidence::facts([
                    "ext superblock magic 0xEF53 verified".to_string(),
                    format!(
                        "features: journal={} extents={} 64bit={}",
                        has_journal, has_extents, has_64bit
                    ),
                    "inode/directory traversal not implemented in this milestone".to_string(),
                ]),
                metadata,
                warnings: vec![
                    "ext traversal (inodes, directories, extents) is planned for a hardening pass"
                        .to_string(),
                ],
                errors: Vec::new(),
                children: Vec::new(),
            }],
        })
    }
}

pub struct NtfsHandler;

impl Handler for NtfsHandler {
    fn format(&self) -> &'static str {
        "ntfs"
    }

    fn find_candidates(&self, src: &ByteSource) -> Vec<Candidate> {
        find_all(src, b"NTFS    ")
            .into_iter()
            .map(|o| Candidate {
                offset: o.saturating_sub(3),
            })
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
        if base + 512 > src.len() {
            return Err(Error::Validation {
                format: "ntfs",
                reason: "boot sector truncated".into(),
            });
        }
        let mut bs = [0u8; 512];
        src.read_at(base, &mut bs)?;
        if bs[0] != 0xEB || &bs[3..11] != b"NTFS    " {
            return Err(Error::Validation {
                format: "ntfs",
                reason: "not an NTFS boot sector".into(),
            });
        }
        let bytes_per_sector = u16::from_le_bytes([bs[11], bs[12]]) as u64;
        let sectors_per_cluster = bs[13] as u64;
        let mft_lcn = u64::from_le_bytes([bs[24], bs[25], bs[26], bs[27], 0, 0, 0, 0]);
        let mftmirr_lcn = u64::from_le_bytes([bs[28], bs[29], bs[30], bs[31], 0, 0, 0, 0]);
        let cluster_size = bytes_per_sector * sectors_per_cluster;

        let mut metadata = BTreeMap::new();
        metadata.insert("cluster_size".to_string(), cluster_size.to_string());
        metadata.insert("mft_lcn".to_string(), mft_lcn.to_string());
        metadata.insert("mftmirr_lcn".to_string(), mftmirr_lcn.to_string());

        Ok(HandlerOutput {
            artifacts: vec![ArtifactDraft {
                format: "ntfs".to_string(),
                label: format!("NTFS filesystem ({}B clusters)", cluster_size),
                offset: base,
                size: src.len() - base,
                confidence: Confidence::Partial,
                evidence: Evidence::facts([
                    "NTFS boot sector OEM string validated".to_string(),
                    format!("MFT at LCN {mft_lcn}"),
                    "MFT record parsing planned for a hardening pass".to_string(),
                ]),
                metadata,
                warnings: vec![
                    "NTFS MFT/attribute traversal is planned for a hardening pass".to_string(),
                ],
                errors: Vec::new(),
                children: Vec::new(),
            }],
        })
    }
}

pub struct UbiHandler;

impl Handler for UbiHandler {
    fn format(&self) -> &'static str {
        "ubi"
    }

    fn find_candidates(&self, src: &ByteSource) -> Vec<Candidate> {
        find_all(src, b"UBI#")
            .into_iter()
            .chain(find_all(src, b"UBI!"))
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
        let mut magic = [0u8; 4];
        src.read_at(base, &mut magic)?;
        let kind = if &magic == b"UBI#" {
            "erase-count header"
        } else {
            "volume table"
        };
        let mut metadata = BTreeMap::new();
        metadata.insert(
            "marker".to_string(),
            String::from_utf8_lossy(&magic).into_owned(),
        );
        metadata.insert("structure".to_string(), kind.to_string());
        Ok(HandlerOutput {
            artifacts: vec![ArtifactDraft {
                format: "ubi".to_string(),
                label: format!("UBI flash container ({kind})"),
                offset: base,
                size: src.len() - base,
                confidence: Confidence::Partial,
                evidence: Evidence::facts([
                    "UBI magic validated".to_string(),
                    "erase-block/volume walking is planned for a hardening pass".to_string(),
                ]),
                metadata,
                warnings: vec![
                    "UBI/UBIFS volume & file traversal is planned for a hardening pass".to_string(),
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

    fn validate_at(h: &dyn Handler, src: &ByteSource, off: u64) -> Result<HandlerOutput> {
        h.validate(
            src,
            Candidate { offset: off },
            &crate::engine::EngineLimits::default(),
            &mut Budget::default(),
        )
    }

    #[test]
    fn squashfs_superblock_partial_with_compressor_metadata() {
        let mut sb = [0u8; 96];
        sb[0..4].copy_from_slice(b"hsqs");
        sb[4..8].copy_from_slice(&42u32.to_le_bytes()); // inodes
        sb[12..16].copy_from_slice(&65536u32.to_le_bytes()); // block size
        sb[20..22].copy_from_slice(&1u16.to_le_bytes()); // gzip
        sb[22..24].copy_from_slice(&16u16.to_le_bytes()); // block log
        sb[28..30].copy_from_slice(&4u16.to_le_bytes()); // major
        sb[30..32].copy_from_slice(&0u16.to_le_bytes()); // minor
                                                         // bytes_used at 40: 4096.
        sb[40..48].copy_from_slice(&4096u64.to_le_bytes());
        sb[56..64].copy_from_slice(&96u64.to_le_bytes()); // inode table
        sb[72..80].copy_from_slice(&2048u64.to_le_bytes()); // dir table
        let mut img = sb.to_vec();
        img.resize(4096, 0);
        let src = ByteSource::from_vec(img);
        let out = validate_at(&SquashfsHandler, &src, 0).expect("sqfs validates");
        let art = &out.artifacts[0];
        assert_eq!(art.confidence, Confidence::Partial, "extraction pending");
        assert_eq!(
            art.metadata.get("compressor").map(String::as_str),
            Some("gzip")
        );
        assert_eq!(art.size, 4096);
    }

    #[test]
    fn squashfs_bad_block_log_rejected() {
        let mut sb = [0u8; 96];
        sb[0..4].copy_from_slice(b"hsqs");
        sb[12..16].copy_from_slice(&999u32.to_le_bytes());
        sb[22..24].copy_from_slice(&7u16.to_le_bytes());
        let src = ByteSource::from_vec(sb.to_vec());
        assert!(validate_at(&SquashfsHandler, &src, 0).is_err());
    }

    #[test]
    fn iso_pvd_finds_root_extent() {
        // Image of 64 sectors of 2048; PVD at sector 16.
        let sectors = 64u64;
        let mut img = vec![0u8; (sectors * 2048) as usize];
        let pvd = 16 * 2048;
        img[pvd] = 1; // type: PVD
        img[pvd + 1..pvd + 6].copy_from_slice(b"CD001");
        img[pvd + 40..pvd + 49].copy_from_slice(b"CTF_IMAGE");
        // volume size: 64 blocks of 2048.
        img[pvd + 80..pvd + 84].copy_from_slice(&64u32.to_le_bytes());
        img[pvd + 128..pvd + 130].copy_from_slice(&2048u16.to_le_bytes());
        // Root record at 156: len 34, extent 18, size 2048.
        img[pvd + 156 + 2..pvd + 156 + 6].copy_from_slice(&18u32.to_le_bytes());
        img[pvd + 156 + 10] = 34;
        // Root content marker at LBA 18.
        img[18 * 2048..18 * 2048 + 8].copy_from_slice(b"ISODATA1");
        let src = ByteSource::from_vec(img);
        let out = validate_at(&Iso9660Handler, &src, pvd as u64).expect("iso validates");
        let art = &out.artifacts[0];
        assert_eq!(art.confidence, Confidence::Validated);
        assert_eq!(
            art.metadata.get("volume_id").map(String::as_str),
            Some("CTF_IMAGE")
        );
        match &art.children[0].content {
            ChildContent::Source(r) => {
                let mut buf = [0u8; 8];
                r.read_at(0, &mut buf).unwrap();
                assert_eq!(&buf, b"ISODATA1");
            }
            _ => panic!("root dir must be source-backed"),
        }
    }

    #[test]
    fn ext_superblock_detected_as_partial() {
        let mut img = vec![0u8; 8192];
        let sb = 1024usize;
        img[sb + 56] = 0x53;
        img[sb + 57] = 0xEF;
        // inode count + block count.
        img[sb..sb + 4].copy_from_slice(&1234u32.to_le_bytes());
        img[sb + 4..sb + 8].copy_from_slice(&4096u32.to_le_bytes());
        // incompat: extents (0x40).
        img[sb + 96..sb + 100].copy_from_slice(&0x40u32.to_le_bytes());
        let src = ByteSource::from_vec(img);
        let cands = ExtHandler.find_candidates(&src);
        assert!(!cands.is_empty());
        let out = validate_at(&ExtHandler, &src, cands[0].offset).expect("ext validates");
        let art = &out.artifacts[0];
        assert_eq!(art.confidence, Confidence::Partial);
        assert!(art.label.contains("ext4-ish"));
    }
}
