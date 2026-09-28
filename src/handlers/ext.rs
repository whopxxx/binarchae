//! ext2/ext3/ext4 read-only traversal (Issue #7 §1.3).
//!
//! Layout verified against Linux `fs/ext4/ext4.h` and
//! `fs/ext4/ext4_extents.h`:
//! - superblock at offset 1024, 1024 bytes: magic 0xEF53 @56; block size
//!   = 1024 << s_log_block_size; first_data_block; blocks_per_group;
//!   inodes_per_group; inode_size @s_inode_size (rev >= 1); feature
//!   flags: compat @0x5C, incompat @0x60, ro_compat @0x64; desc_size
//!   @0xFE (64bit);
//! - group descriptors follow the superblock (block 1 or 2 depending on
//!   first_data_block/block size): bg_inode_table_lo @8 (hi @40 with
//!   64bit desc_size 64);
//! - inode: i_mode @0, i_size_lo @4, i_dtime @20 (deleted), i_block[]
//!   @40 (15 u32 entries: 12 direct, IND, DIND, TIND);
//!   i_size_high @108 (rows/regular files); i_flags @36;
//!   EXT4_EXTENTS_FL 0x00080000 => i_block is an extent tree;
//! - extent tree (in i_block, 60 bytes): header {magic 0xF30A, entries,
//!   max, depth, gen} then leaf extents {ee_block, ee_len (max 32768;
//!   higher means unwritten), ee_start_hi, ee_start_lo} or index nodes
//!   {ei_block, ei_leaf_lo, ei_leaf_hi};
//! - directory blocks: ext4_dir_entry_2 {inode u32, rec_len u16,
//!   name_len u8, file_type u8, name}; rec_len rounds each entry to 4;
//!   rec_len == 0 or inode == 0 entries are skipped via rec_len stride.
//!
//! Unsupported incompat features (journal is fine; 64bit/extents/
//! filetype supported) reject the candidate honestly. Inline data and
//! encryption inodes are surfaced as metadata-only with a warning.

use crate::artifact::{Confidence, Evidence, RelationKind};
use crate::bytesource::ByteSource;
use crate::engine::{
    ArtifactDraft, Budget, Candidate, ChildContent, ChildDraft, Handler, HandlerOutput,
};
use crate::error::{Error, Result};
use crate::handlers::find_all;
use std::collections::BTreeMap;

pub struct ExtHandler;

const MAGIC: u16 = 0xEF53;
const ROOT_INO: u32 = 2;
const NDIR: usize = 12;
const IND: usize = 12;
const DIND: usize = 13;
const TIND: usize = 14;
const EXTENTS_FL: u32 = 0x0008_0000;
const INLINE_DATA_FL: u32 = 0x1000_0000;
const EXTENT_MAGIC: u16 = 0xF30A;
const MAX_EXTENT_LEN: u32 = 0x8000; // > this = unwritten extent
/// Incompat features we support traversing with.
const SUPPORTED_INCOMPAT: u32 = 0x0002 // FILETYPE
    | 0x0004  // HAS_JOURNAL
    | 0x0040  // EXTENTS
    | 0x0080  // 64BIT
    | 0x0200; // FLEX_BG

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

#[derive(Debug, Clone)]
struct ExtSb {
    inode_size: u64,
    block_size: u64,
    first_data_block: u64,
    blocks_per_group: u64,
    inodes_per_group: u64,
    inodes_count: u64,
    blocks_count: u64,
    incompat: u32,
    desc_size: u64,
    /// Absolute offset of the superblock within the source.
    base: u64,
}

impl ExtSb {
    fn group_count(&self) -> u64 {
        // Standard rounding: ceil((blocks_count - first_data_block) /
        // blocks_per_group), also bounded by inodes_per_group.
        let data_blocks = self.blocks_count.saturating_sub(self.first_data_block);
        let by_blocks = data_blocks.div_ceil(self.blocks_per_group);
        let by_inodes = self.inodes_count.div_ceil(self.inodes_per_group);
        by_blocks.max(by_inodes).max(1)
    }

    /// Byte offset of group `g`'s descriptor.
    fn desc_offset(&self, g: u64) -> u64 {
        // Group descriptors start in the block right after the
        // superblock. With 1KiB blocks the superblock occupies block 1
        // (first_data_block == 1); otherwise it lives in block 0 and the
        // descriptors start in block 1.
        let first_desc_block = if self.block_size == 1024 { 2 } else { 1 };
        self.base + first_desc_block * self.block_size + g * self.desc_size
    }

    fn inode_table_block(&self, src: &ByteSource, g: u64) -> Option<u64> {
        let d = self.desc_offset(g);
        let lo = le32(src, d + 8)? as u64;
        let hi = if self.desc_size >= 64 {
            u64::from(le32(src, d + 40)?)
        } else {
            0
        };
        Some(lo | (hi << 32))
    }

    /// Byte offset of inode `ino` (1-based).
    fn inode_offset(&self, src: &ByteSource, ino: u32) -> Result<u64> {
        if ino == 0 || ino as u64 > self.inodes_count {
            return Err(Error::Validation {
                format: "ext",
                reason: format!("inode {ino} out of range"),
            });
        }
        let idx = (ino - 1) as u64;
        let group = idx / self.inodes_per_group;
        let index = idx % self.inodes_per_group;
        if group >= self.group_count() {
            return Err(Error::Validation {
                format: "ext",
                reason: format!("inode {ino} group {group} out of range"),
            });
        }
        let table = self
            .inode_table_block(src, group)
            .ok_or_else(|| Error::Validation {
                format: "ext",
                reason: format!("group {group} descriptor unreadable"),
            })?;
        Ok(self.base + table * self.block_size + index * self.inode_size)
    }
}

/// Parsed inode core.
#[derive(Debug, Clone)]
struct ExtInode {
    mode: u16,
    size: u64,
    /// Nonzero => deleted (dtime set).
    dtime: u32,
    flags: u32,
    i_block: [u32; 15],
}

impl ExtInode {
    fn file_type(&self) -> u16 {
        self.mode & 0xF000
    }
    fn uses_extents(&self) -> bool {
        self.flags & EXTENTS_FL != 0
    }
    fn inline_data(&self) -> bool {
        self.flags & INLINE_DATA_FL != 0
    }
}

impl ExtHandler {
    fn parse_sb(src: &ByteSource, base: u64) -> Result<ExtSb> {
        let sb = base + 1024;
        if le16(src, sb + 56).unwrap_or(0) != MAGIC {
            return Err(Error::Validation {
                format: "ext",
                reason: "bad magic".into(),
            });
        }
        if base + 1024 + 264 > src.len() {
            return Err(Error::Validation {
                format: "ext",
                reason: "superblock truncated".into(),
            });
        }
        let log_block = le32(src, sb + 24).unwrap_or(u32::MAX);
        if log_block > 6 {
            return Err(Error::Validation {
                format: "ext",
                reason: format!("implausible log block size {log_block}"),
            });
        }
        let block_size = 1024u64 << log_block;
        let first_data_block = le32(src, sb + 20).unwrap_or(0) as u64;
        let incompat = le32(src, sb + 0x60).unwrap_or(0);
        if incompat & !SUPPORTED_INCOMPAT != 0 {
            return Err(Error::Validation {
                format: "ext",
                reason: format!("unsupported incompat features {incompat:#x}"),
            });
        }
        let rev = le32(src, sb + 76).unwrap_or(0);
        let inode_size = if rev >= 1 {
            u64::from(le16(src, sb + 0x58).unwrap_or(0))
        } else {
            128
        };
        if inode_size < 128 || inode_size > block_size || !inode_size.is_power_of_two() {
            return Err(Error::Validation {
                format: "ext",
                reason: format!("implausible inode size {inode_size}"),
            });
        }
        let desc_size = if incompat & 0x80 != 0 {
            u64::from(le16(src, sb + 0xFE).unwrap_or(64)).max(64)
        } else {
            32
        };
        let sbparsed = ExtSb {
            inode_size,
            block_size,
            first_data_block,
            blocks_per_group: le32(src, sb + 32).unwrap_or(0) as u64,
            inodes_per_group: le32(src, sb + 40).unwrap_or(0) as u64,
            inodes_count: le32(src, sb).unwrap_or(0) as u64,
            blocks_count: le32(src, sb + 4).unwrap_or(0) as u64,
            incompat,
            desc_size,
            base,
        };
        if sbparsed.blocks_per_group == 0
            || sbparsed.inodes_per_group == 0
            || sbparsed.blocks_count == 0
            || sbparsed.inodes_count == 0
        {
            return Err(Error::Validation {
                format: "ext",
                reason: "zero geometry counters".into(),
            });
        }
        if base + sbparsed.blocks_count * block_size > src.len() + block_size {
            return Err(Error::Validation {
                format: "ext",
                reason: format!("blocks_count {} exceeds source", sbparsed.blocks_count),
            });
        }
        Ok(sbparsed)
    }

    fn read_inode(src: &ByteSource, sb: &ExtSb, ino: u32) -> Result<ExtInode> {
        let off = Self::read_inode_off(src, sb, ino)?;
        let mode = le16(src, off).unwrap_or(0);
        let size_lo = le32(src, off + 4).unwrap_or(0) as u64;
        let dtime = le32(src, off + 20).unwrap_or(0);
        let flags = le32(src, off + 36).unwrap_or(0);
        let mut i_block = [0u32; 15];
        for (k, slot) in i_block.iter_mut().enumerate() {
            *slot = le32(src, off + 40 + (k as u64) * 4).unwrap_or(0);
        }
        // For regular files, size_high at +108 (0x6C).
        let mut size = size_lo;
        if mode & 0xF000 == 0x8000 {
            let hi = le32(src, off + 108).unwrap_or(0) as u64;
            size = size_lo | (hi << 32);
        }
        Ok(ExtInode {
            mode,
            size,
            dtime,
            flags,
            i_block,
        })
    }

    fn read_inode_off(src: &ByteSource, sb: &ExtSb, ino: u32) -> Result<u64> {
        sb.inode_offset(src, ino)
    }

    /// Collect the data block numbers of a file from direct/indirect
    /// pointers. `blocks_needed` bounds the walk.
    fn indirect_blocks(
        src: &ByteSource,
        sb: &ExtSb,
        i_block: &[u32; 15],
        blocks_needed: usize,
    ) -> Result<Vec<u32>> {
        let mut out = Vec::new();
        let bs = sb.block_size;
        let ppb = (bs / 4) as usize; // pointers per block

        let read_ptrs = |blk: u32, count: usize| -> Result<Vec<u32>> {
            let mut v = Vec::with_capacity(count);
            for k in 0..count {
                v.push(le32(src, sb.base + blk as u64 * bs + (k as u64) * 4).unwrap_or(0));
            }
            Ok(v)
        };

        // Direct.
        for &b in &i_block[..NDIR] {
            if b != 0 {
                out.push(b);
            }
            if out.len() >= blocks_needed {
                return Ok(out);
            }
        }
        // Singly indirect.
        if i_block[IND] != 0 {
            for b in read_ptrs(i_block[IND], ppb)? {
                if b != 0 {
                    out.push(b);
                }
                if out.len() >= blocks_needed {
                    return Ok(out);
                }
            }
        }
        // Doubly indirect.
        if i_block[DIND] != 0 {
            for l1 in read_ptrs(i_block[DIND], ppb)? {
                if l1 == 0 {
                    continue;
                }
                for b in read_ptrs(l1, ppb)? {
                    if b != 0 {
                        out.push(b);
                    }
                    if out.len() >= blocks_needed {
                        return Ok(out);
                    }
                }
                if out.len() >= blocks_needed {
                    return Ok(out);
                }
            }
        }
        // Triply indirect.
        if i_block[TIND] != 0 {
            for l1 in read_ptrs(i_block[TIND], ppb)? {
                if l1 == 0 {
                    continue;
                }
                for l2 in read_ptrs(l1, ppb)? {
                    if l2 == 0 {
                        continue;
                    }
                    for b in read_ptrs(l2, ppb)? {
                        if b != 0 {
                            out.push(b);
                        }
                        if out.len() >= blocks_needed {
                            return Ok(out);
                        }
                    }
                    if out.len() >= blocks_needed {
                        return Ok(out);
                    }
                }
            }
        }
        Ok(out)
    }

    /// Extent-tree walker: `root` is Some for the inode-local header.
    fn walk_extents(
        src: &ByteSource,
        sb: &ExtSb,
        root: Option<(u64, [u32; 15])>,
        blocks_needed: usize,
        runs: &mut Vec<(u64, u32)>,
        warnings: &mut Vec<String>,
    ) -> Result<()> {
        let mut queue: Vec<(u64, u32)> = Vec::new(); // (block offset or inode off encoded, depth)
                                                     // Root: inode-local header at ino_off+40, depth from header.
        if let Some((ino_off, _)) = root {
            let magic = le16(src, ino_off).unwrap_or(0);
            if magic != EXTENT_MAGIC {
                return Err(Error::Validation {
                    format: "ext",
                    reason: format!("bad extent header magic {magic:#x}"),
                });
            }
            let entries = le16(src, ino_off + 2).unwrap_or(0) as u64;
            let depth = le16(src, ino_off + 6).unwrap_or(0) as u32;
            if entries > 4 {
                return Err(Error::Validation {
                    format: "ext",
                    reason: format!("root extent entries {entries} exceed i_block"),
                });
            }
            if depth == 0 {
                for k in 0..entries {
                    let e = ino_off + 12 + k * 12;
                    Self::push_extent(src, e, runs, warnings)?;
                    if runs.len() >= blocks_needed {
                        return Ok(());
                    }
                }
            } else {
                for k in 0..entries {
                    let e = ino_off + 12 + k * 12;
                    let leaf = Self::extent_leaf(src, e)?;
                    queue.push((leaf, depth));
                }
            }
        }
        while let Some((node, depth)) = queue.pop() {
            if depth > 5 {
                warnings.push("extent tree deeper than 5; truncated".to_string());
                break;
            }
            let node_off = sb.base + node * sb.block_size;
            let magic = le16(src, node_off).unwrap_or(0);
            if magic != EXTENT_MAGIC {
                return Err(Error::Validation {
                    format: "ext",
                    reason: format!("bad extent header magic {magic:#x}"),
                });
            }
            let entries = le16(src, node_off + 2).unwrap_or(0) as u64;
            let node_depth = le16(src, node_off + 6).unwrap_or(0) as u32;
            if node_depth == 0 {
                for k in 0..entries {
                    let e = node_off + 12 + k * 12;
                    Self::push_extent(src, e, runs, warnings)?;
                    if runs.len() >= blocks_needed {
                        return Ok(());
                    }
                }
            } else {
                for k in 0..entries {
                    let e = node_off + 12 + k * 12;
                    let leaf = Self::extent_leaf(src, e)?;
                    queue.push((leaf, node_depth));
                }
            }
        }
        Ok(())
    }

    fn extent_leaf(src: &ByteSource, idx_off: u64) -> Result<u64> {
        let lo = le32(src, idx_off + 4).unwrap_or(0) as u64;
        let hi = le16(src, idx_off + 8).unwrap_or(0) as u64;
        Ok(lo | (hi << 32))
    }

    fn push_extent(
        src: &ByteSource,
        e: u64,
        runs: &mut Vec<(u64, u32)>,
        warnings: &mut Vec<String>,
    ) -> Result<()> {
        let ee_block = le32(src, e).unwrap_or(0) as u64;
        let ee_len = le16(src, e + 4).unwrap_or(0) as u32;
        let hi = le16(src, e + 6).unwrap_or(0) as u64;
        let lo = le32(src, e + 8).unwrap_or(0) as u64;
        if ee_len == 0 || ee_len > MAX_EXTENT_LEN {
            warnings.push("unwritten/invalid extent skipped".to_string());
            return Ok(());
        }
        let _ = ee_block;
        runs.push((lo | (hi << 32), ee_len));
        Ok(())
    }

    /// Read file content as Owned bytes (extents/indirect runs).
    fn read_file(
        src: &ByteSource,
        sb: &ExtSb,
        ino: &ExtInode,
        ino_off: u64,
        limits: &crate::engine::EngineLimits,
        budget: &mut Budget,
        warnings: &mut Vec<String>,
    ) -> Result<Vec<u8>> {
        let mut out = Vec::with_capacity(ino.size as usize);
        if ino.size > limits.max_child_size {
            warnings.push("file exceeds max_child_size; truncated".to_string());
            return Ok(Vec::new());
        }
        if ino.uses_extents() {
            let mut runs = Vec::new();
            Self::walk_extents(
                src,
                sb,
                Some((ino_off + 40, ino.i_block)),
                ino.size.div_ceil(sb.block_size) as usize,
                &mut runs,
                warnings,
            )?;
            // Sort by logical position encoded earlier (we pushed
            // sequential order during the walk, so keep as-is).
            for (phys, len) in runs {
                let want = (ino.size - out.len() as u64).min(u64::from(len) * sb.block_size);
                if want == 0 {
                    break;
                }
                let off = sb.base + phys * sb.block_size;
                let mut chunk = vec![0u8; want as usize];
                if off + want <= src.len() {
                    src.read_at(off, &mut chunk)?;
                } else {
                    warnings.push("extent past source; zero-filled".to_string());
                }
                out.extend_from_slice(&chunk);
                if !budget.charge(limits, want) {
                    return Err(Error::LimitExceeded {
                        limit: "max-total-expanded-bytes",
                        detail: "ext file reconstruction".into(),
                    });
                }
                if out.len() as u64 >= ino.size {
                    break;
                }
            }
        } else {
            let blocks = Self::indirect_blocks(
                src,
                sb,
                &ino.i_block,
                ino.size.div_ceil(sb.block_size) as usize,
            )?;
            for b in blocks {
                let want = (ino.size - out.len() as u64).min(sb.block_size);
                if want == 0 {
                    break;
                }
                let off = sb.base + u64::from(b) * sb.block_size;
                let mut chunk = vec![0u8; want as usize];
                if off + want <= src.len() {
                    src.read_at(off, &mut chunk)?;
                } else {
                    warnings.push("block past source; zero-filled".to_string());
                }
                out.extend_from_slice(&chunk);
                if !budget.charge(limits, want) {
                    return Err(Error::LimitExceeded {
                        limit: "max-total-expanded-bytes",
                        detail: "ext file reconstruction".into(),
                    });
                }
            }
        }
        out.truncate(ino.size as usize);
        Ok(out)
    }

    /// Walk a directory inode's data as ext4_dir_entry_2 records.
    #[allow(clippy::too_many_arguments)]
    fn walk_dir(
        src: &ByteSource,
        sb: &ExtSb,
        dir_ino: &ExtInode,
        dir_off: u64,
        path: &str,
        depth: u32,
        limits: &crate::engine::EngineLimits,
        budget: &mut Budget,
        warnings: &mut Vec<String>,
        out: &mut Vec<ChildDraft>,
    ) -> Result<()> {
        if depth > 16 {
            warnings.push("directory nesting deeper than 16 not walked".to_string());
            return Ok(());
        }
        if dir_ino.inline_data() {
            warnings.push(format!(
                "directory {path}: inline-data directory not walked (metadata only)"
            ));
            return Ok(());
        }
        // Directory data blocks.
        let mut dir_bytes: Vec<u8> = Vec::new();
        if dir_ino.uses_extents() {
            let mut runs = Vec::new();
            Self::walk_extents(
                src,
                sb,
                Some((dir_off + 40, dir_ino.i_block)),
                dir_ino.size.div_ceil(sb.block_size) as usize,
                &mut runs,
                warnings,
            )?;
            for (phys, len) in runs {
                for k in 0..len {
                    let off = sb.base + (phys + u64::from(k)) * sb.block_size;
                    let mut block = vec![0u8; sb.block_size as usize];
                    if off + sb.block_size <= src.len() {
                        src.read_at(off, &mut block)?;
                    } else {
                        warnings.push("directory block past source; truncated".to_string());
                        break;
                    }
                    dir_bytes.extend_from_slice(&block);
                }
                if dir_bytes.len() as u64 >= dir_ino.size {
                    break;
                }
            }
        } else {
            let blocks = Self::indirect_blocks(
                src,
                sb,
                &dir_ino.i_block,
                dir_ino.size.div_ceil(sb.block_size) as usize,
            )?;
            for b in blocks {
                let off = sb.base + u64::from(b) * sb.block_size;
                let mut block = vec![0u8; sb.block_size as usize];
                if off + sb.block_size <= src.len() {
                    src.read_at(off, &mut block)?;
                } else {
                    warnings.push("directory block past source; truncated".to_string());
                    break;
                }
                dir_bytes.extend_from_slice(&block);
            }
        }
        dir_bytes.truncate(dir_ino.size as usize);

        // Parse dir entries.
        let mut pos = 0usize;
        while pos + 8 <= dir_bytes.len() {
            if out.len() >= limits.max_fs_entries {
                warnings.push("max_fs_entries reached; walk truncated".to_string());
                return Ok(());
            }
            let inode = u32::from_le_bytes([
                dir_bytes[pos],
                dir_bytes[pos + 1],
                dir_bytes[pos + 2],
                dir_bytes[pos + 3],
            ]);
            let rec_len = u16::from_le_bytes([dir_bytes[pos + 4], dir_bytes[pos + 5]]) as usize;
            if rec_len == 0 || rec_len % 4 != 0 || pos + rec_len > dir_bytes.len() {
                warnings.push(format!(
                    "directory entry at {pos} has bad rec_len {rec_len}; walk ended"
                ));
                break;
            }
            let name_len = dir_bytes[pos + 6] as usize;
            let ftype = dir_bytes[pos + 7];
            let name_bytes = &dir_bytes[pos + 8..(pos + 8 + name_len).min(dir_bytes.len())];
            let name = String::from_utf8_lossy(name_bytes).into_owned();
            if inode != 0 && name_len > 0 && name != "." && name != ".." {
                let child_path = if path.is_empty() {
                    name.clone()
                } else {
                    format!("{path}/{name}")
                };
                Self::emit_entry(
                    src,
                    sb,
                    inode,
                    ftype,
                    &name,
                    &child_path,
                    depth,
                    limits,
                    budget,
                    warnings,
                    out,
                )?;
            }
            pos += rec_len;
        }
        Ok(())
    }

    /// Emit one directory entry child (recursing into directories).
    #[allow(clippy::too_many_arguments)]
    fn emit_entry(
        src: &ByteSource,
        sb: &ExtSb,
        ino: u32,
        ftype: u8,
        name: &str,
        child_path: &str,
        depth: u32,
        limits: &crate::engine::EngineLimits,
        budget: &mut Budget,
        warnings: &mut Vec<String>,
        out: &mut Vec<ChildDraft>,
    ) -> Result<()> {
        let inode = match Self::read_inode(src, sb, ino) {
            Ok(i) => i,
            Err(_) => {
                warnings.push(format!(
                    "entry {child_path}: inode {ino} unreadable; skipped"
                ));
                return Ok(());
            }
        };
        let deleted = inode.dtime != 0;
        let is_dir = ftype == 2 || (ftype == 0 && inode.file_type() == 0x4000);
        let is_reg = ftype == 1 || (ftype == 0 && inode.file_type() == 0x8000);
        let is_link = ftype == 7 || (ftype == 0 && inode.file_type() == 0xA000);
        let mut meta = BTreeMap::new();
        meta.insert("path".to_string(), child_path.to_string());
        meta.insert("mode".to_string(), format!("{:#06o}", inode.mode));
        meta.insert("inode".to_string(), ino.to_string());
        if deleted {
            meta.insert("deleted".to_string(), "true".to_string());
        }
        let entry_name = Some(name.to_string());
        if is_dir {
            meta.insert("type".to_string(), "directory".to_string());
            out.push(ChildDraft {
                relation: RelationKind::FilesystemEntry,
                label: format!("ext directory {child_path}"),
                format_hint: "metadata",
                content: ChildContent::Owned(Vec::new()),
                size: 0,
                metadata: meta,
                warnings: Vec::new(),
                entry_name,
            });
            if !deleted {
                Self::walk_dir(
                    src,
                    sb,
                    &inode,
                    Self::read_inode_off(src, sb, ino)?,
                    child_path,
                    depth + 1,
                    limits,
                    budget,
                    warnings,
                    out,
                )?;
            } else {
                warnings.push(format!("deleted directory {child_path} not walked"));
            }
            return Ok(());
        }
        if is_reg {
            meta.insert("type".to_string(), "file".to_string());
            meta.insert("declared_size".to_string(), inode.size.to_string());
            if inode.inline_data() {
                warnings.push(format!(
                    "file {child_path}: inline data not extracted (metadata only)"
                ));
                out.push(ChildDraft {
                    relation: RelationKind::FilesystemEntry,
                    label: format!("ext file {child_path} (inline, metadata only)"),
                    format_hint: "metadata",
                    content: ChildContent::Owned(Vec::new()),
                    size: 0,
                    metadata: meta,
                    warnings: Vec::new(),
                    entry_name,
                });
                return Ok(());
            }
            if inode.size == 0 {
                out.push(ChildDraft {
                    relation: RelationKind::FilesystemEntry,
                    label: format!("ext file {child_path} (0 bytes)"),
                    format_hint: "raw",
                    content: ChildContent::Owned(Vec::new()),
                    size: 0,
                    metadata: meta,
                    warnings: Vec::new(),
                    entry_name,
                });
                return Ok(());
            }
            let data = Self::read_file(
                src,
                sb,
                &inode,
                Self::read_inode_off(src, sb, ino)?,
                limits,
                budget,
                warnings,
            )?;
            if deleted {
                out.push(ChildDraft {
                    relation: RelationKind::CarvedFrom,
                    label: format!(
                        "ext deleted file {child_path} ({} bytes, recovered)",
                        data.len()
                    ),
                    format_hint: "raw",
                    content: ChildContent::Owned(data),
                    size: inode.size,
                    metadata: meta,
                    warnings: vec![
                        "deleted inode (dtime set): recovered from block pointers".to_string()
                    ],
                    entry_name,
                });
                return Ok(());
            }
            out.push(ChildDraft {
                relation: RelationKind::ReconstructedFrom,
                label: format!("ext file {child_path} ({} bytes)", data.len()),
                format_hint: "raw",
                content: ChildContent::Owned(data),
                size: inode.size,
                metadata: meta,
                warnings: vec!["content reconstructed from block pointers".to_string()],
                entry_name,
            });
            return Ok(());
        }
        if is_link {
            meta.insert("type".to_string(), "symlink".to_string());
            out.push(ChildDraft {
                relation: RelationKind::FilesystemEntry,
                label: format!("ext symlink {child_path}"),
                format_hint: "metadata",
                content: ChildContent::Owned(Vec::new()),
                size: 0,
                metadata: meta,
                warnings: vec!["symlink target kept as metadata; never materialized".to_string()],
                entry_name,
            });
            return Ok(());
        }
        // Devices/FIFO/socket: metadata only.
        meta.insert("type".to_string(), "special".to_string());
        out.push(ChildDraft {
            relation: RelationKind::FilesystemEntry,
            label: format!("ext special entry {child_path}"),
            format_hint: "metadata",
            content: ChildContent::Owned(Vec::new()),
            size: 0,
            metadata: meta,
            warnings: vec!["special entries are never materialized".to_string()],
            entry_name,
        });
        Ok(())
    }
}

impl Handler for ExtHandler {
    fn format(&self) -> &'static str {
        "ext"
    }

    fn find_candidates(&self, src: &ByteSource) -> Vec<Candidate> {
        find_all(src, &[0x53, 0xEF])
            .into_iter()
            .filter(|o| *o >= 0x438)
            .map(|o| Candidate { offset: o - 0x438 })
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
        let sb = Self::parse_sb(src, base)?;

        // Root inode (2).
        let root = Self::read_inode(src, &sb, ROOT_INO)?;
        if root.file_type() != 0x4000 {
            return Err(Error::Validation {
                format: "ext",
                reason: format!("root inode is not a directory (mode {:#06o})", root.mode),
            });
        }

        let mut children = Vec::new();
        let mut warnings = Vec::new();
        let root_off = Self::read_inode_off(src, &sb, ROOT_INO)?;
        Self::walk_dir(
            src,
            &sb,
            &root,
            root_off,
            "",
            0,
            limits,
            budget,
            &mut warnings,
            &mut children,
        )?;

        let mut metadata = BTreeMap::new();
        metadata.insert("block_size".to_string(), sb.block_size.to_string());
        metadata.insert("inode_count".to_string(), sb.inodes_count.to_string());
        metadata.insert("block_count".to_string(), sb.blocks_count.to_string());
        metadata.insert("groups".to_string(), sb.group_count().to_string());
        metadata.insert(
            "has_extents".to_string(),
            (sb.incompat & 0x40 != 0).to_string(),
        );
        metadata.insert(
            "has_journal".to_string(),
            (sb.incompat & 0x4 != 0).to_string(),
        );
        metadata.insert("entries".to_string(), children.len().to_string());

        Ok(HandlerOutput {
            artifacts: vec![ArtifactDraft {
                format: "ext".to_string(),
                label: format!(
                    "ext filesystem ({} inodes, {} blocks, {} entries)",
                    sb.inodes_count,
                    sb.blocks_count,
                    children.len()
                ),
                offset: base,
                size: sb.blocks_count * sb.block_size,
                confidence: Confidence::Validated,
                evidence: Evidence::facts([
                    "ext superblock magic 0xEF53 verified".to_string(),
                    format!(
                        "geometry: block size {}, {} groups, inode size {}",
                        sb.block_size,
                        sb.group_count(),
                        sb.inode_size
                    ),
                    format!(
                        "features: journal={} extents={} 64bit={}",
                        sb.incompat & 0x4 != 0,
                        sb.incompat & 0x40 != 0,
                        sb.incompat & 0x80 != 0
                    ),
                    format!("root directory walked: {} entries", children.len()),
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
        ExtHandler.validate(
            src,
            Candidate { offset: off },
            &crate::engine::EngineLimits::default(),
            &mut Budget::default(),
        )
    }

    const BS: u64 = 1024;
    const INODE_SIZE: u64 = 128;
    const INODES_PER_GROUP: u64 = 16;
    const BLOCKS_PER_GROUP: u64 = 128;

    /// Build a minimal ext2 (no extents) image:
    ///   sb @1024, group desc @2048, inode table @block 4 (4096),
    ///   root inode 2 = dir with one file entry (FLAG.TXT, inode 11),
    ///   file data at block 10.
    fn ext2_image() -> Vec<u8> {
        let total_blocks = 16u64;
        let mut img = vec![0u8; (total_blocks * BS) as usize];
        let sb = 1024usize;
        macro_rules! put16 {
            ($o:expr, $v:expr) => {
                img[$o..$o + 2].copy_from_slice(&($v as u16).to_le_bytes());
            };
        }
        macro_rules! put32 {
            ($o:expr, $v:expr) => {
                img[$o..$o + 4].copy_from_slice(&($v as u32).to_le_bytes());
            };
        }

        put32!(sb, 16); // inodes_count
        put32!(sb + 4, total_blocks as u32); // blocks_count
        put32!(sb + 20, 1); // first_data_block
        put32!(sb + 24, 0); // log_block_size -> 1024
        put32!(sb + 32, BLOCKS_PER_GROUP as u32);
        put32!(sb + 40, INODES_PER_GROUP as u32);
        put16!(sb + 56, MAGIC);
        put32!(sb + 76, 1); // rev_level = dynamic
        put16!(sb + 0x58, INODE_SIZE as u16); // inode_size
        put32!(sb + 0x60, 0); // incompat: none (no extents/journal)

        // Group descriptor 0 at block 1 (@1024*2): inode table @block 4.
        let gd = 2 * BS as usize;
        put32!(gd + 8, 4); // bg_inode_table_lo

        // Inode table at block 4 = 4096. inode N at 4096 + (N-1)*128.
        let ino_off = |n: u32| 4096 + (n as usize - 1) * INODE_SIZE as usize;
        // Root inode (2): dir, size 1024, direct block 10.
        let root = ino_off(2);
        put16!(root, 0o040755);
        put32!(root + 4, 1024); // size
        put32!(root + 40 + IND * 4, 0);
        put32!(root + 40, 10); // i_block[0] = block 10
                               // Inode 11: regular file "FLAG.TXT": size 11, block 12.
        let f = ino_off(11);
        put16!(f, 0o100644);
        put32!(f + 4, 11);
        put32!(f + 40, 12);

        // Root dir block 10 @ 10240: ".", "..", FLAG.TXT.
        let d = 10 * BS as usize;
        fn put_dirent(img: &mut [u8], off: usize, ino: u32, rec: u16, name: &[u8], ftype: u8) {
            img[off..off + 4].copy_from_slice(&ino.to_le_bytes());
            img[off + 4..off + 6].copy_from_slice(&rec.to_le_bytes());
            img[off + 6] = name.len() as u8;
            img[off + 7] = ftype;
            img[off + 8..off + 8 + name.len()].copy_from_slice(name);
        }
        put_dirent(&mut img, d, 2, 12, b".", 2);
        put_dirent(&mut img, d + 12, 2, 12, b"..", 2);
        put_dirent(&mut img, d + 24, 11, 16, b"FLAG.TXT", 1);
        put_dirent(&mut img, d + 40, 0, 1024 - 40, b"", 0); // tail filler

        // File data at block 12 = 12288.
        img[12 * BS as usize..12 * BS as usize + 11].copy_from_slice(b"FLAG{ext2}!");
        img
    }

    #[test]
    fn ext2_traversal_with_direct_blocks() {
        let src = ByteSource::from_vec(ext2_image());
        let out = validate_at(&src, 0).expect("ext2 validates");
        let art = &out.artifacts[0];
        assert_eq!(art.confidence, Confidence::Validated);
        let flag = art
            .children
            .iter()
            .find(|c| c.metadata.get("path").map(String::as_str) == Some("FLAG.TXT"))
            .expect("flag.txt child");
        assert_eq!(flag.size, 11);
        match &flag.content {
            ChildContent::Owned(d) => assert_eq!(*d, b"FLAG{ext2}!".to_vec()),
            _ => panic!("file must reconstruct"),
        }
    }

    #[test]
    fn ext3_journal_flag_accepted() {
        let mut img = ext2_image();
        let sb = 1024usize;
        img[sb + 0x60..sb + 0x64].copy_from_slice(&4u32.to_le_bytes()); // journal
        let src = ByteSource::from_vec(img);
        let out = validate_at(&src, 0).expect("ext3 validates");
        assert_eq!(
            out.artifacts[0]
                .metadata
                .get("has_journal")
                .map(String::as_str),
            Some("true")
        );
    }

    #[test]
    fn ext_unsupported_incompat_rejected() {
        let mut img = ext2_image();
        let sb = 1024usize;
        // Inline data (0x8000) unsupported.
        img[sb + 0x60..sb + 0x64].copy_from_slice(&0x8000u32.to_le_bytes());
        let src = ByteSource::from_vec(img);
        assert!(validate_at(&src, 0).is_err());
    }

    #[test]
    fn ext_hostile_geometry_rejected() {
        let mut img = ext2_image();
        let sb = 1024usize;
        img[sb + 4..sb + 8].copy_from_slice(&(1u32 << 24).to_le_bytes()); // blocks_count
        let src = ByteSource::from_vec(img);
        assert!(validate_at(&src, 0).is_err());
    }

    /// Build a small ext4 image using an extent tree for the file:
    /// root dir -> DATA.BIN (inode 12) with one extent -> block 12, len 1.
    fn ext4_extent_image() -> Vec<u8> {
        let mut img = ext2_image();
        let sb = 1024usize;
        // Turn on extents incompat.
        img[sb + 0x60..sb + 0x64].copy_from_slice(&0x40u32.to_le_bytes());
        // Inode 12: extent-based file, size 16, extent: block 0..13 len 1.
        let f = 4096 + (12 - 1) * INODE_SIZE as usize;
        macro_rules! put16 {
            ($o:expr, $v:expr) => {
                img[$o..$o + 2].copy_from_slice(&($v as u16).to_le_bytes());
            };
        }
        macro_rules! put32 {
            ($o:expr, $v:expr) => {
                img[$o..$o + 4].copy_from_slice(&($v as u32).to_le_bytes());
            };
        }
        put16!(f, 0o100644);
        put32!(f + 4, 16); // size
        put32!(f + 36, EXTENTS_FL); // flags
                                    // i_block: extent header magic 0xF30A, entries 1, max 4, depth 0.
        put16!(f + 40, EXTENT_MAGIC);
        put16!(f + 42, 1); // entries
        put16!(f + 44, 4); // max
        put16!(f + 46, 0); // depth
        put32!(f + 48, 0); // generation
                           // extent: ee_block 0, ee_len 1, start_hi 0, start_lo 13.
        put32!(f + 52, 0);
        put16!(f + 56, 1);
        put16!(f + 58, 0);
        put32!(f + 60, 13);
        // Root dir: replace filler with DATA.BIN entry (inode 12).
        let d = 10 * BS as usize;
        img[d + 24 + 8 + 8..d + 24 + 8 + 8].copy_from_slice(b"");
        // Rewrite FLAG.TXT entry rec_len to 16 and add DATA.BIN.
        put16!(d + 24 + 4, 16); // FLAG.TXT rec_len 16 (8 name + 8 header)
        let de = d + 40;
        put32!(de, 12);
        put16!(de + 4, 1024 - 40);
        img[de + 6] = 8;
        img[de + 7] = 1;
        img[de + 8..de + 16].copy_from_slice(b"DATA.BIN");
        // Data at block 13.
        img[13 * BS as usize..13 * BS as usize + 16].copy_from_slice(b"EXTENT_DATA_1234");
        img
    }

    #[test]
    fn ext4_extent_file_reconstruction() {
        let src = ByteSource::from_vec(ext4_extent_image());
        let out = validate_at(&src, 0).expect("ext4 validates");
        let art = &out.artifacts[0];
        assert_eq!(
            art.metadata.get("has_extents").map(String::as_str),
            Some("true")
        );
        let data = art
            .children
            .iter()
            .find(|c| c.metadata.get("path").map(String::as_str) == Some("DATA.BIN"))
            .expect("DATA.BIN child");
        assert_eq!(data.size, 16);
        match &data.content {
            ChildContent::Owned(d) => assert_eq!(*d, b"EXTENT_DATA_1234".to_vec()),
            _ => panic!("extent file must reconstruct"),
        }
    }
}
