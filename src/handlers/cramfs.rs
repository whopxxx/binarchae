//! cramfs read-only traversal (Issue #7 §1.8).
//!
//! Layout verified against Linux `include/uapi/linux/cramfs_fs.h` and
//! `fs/cramfs/inode.c`:
//! - superblock at 0 (or after a 512-byte boot block; kernel retries 512):
//!   magic 0x28cd3d45 (LE `hsqs`-style "45 3d cd 28"), size, flags, future,
//!   signature "Compressed ROMFS" (16), fsid {crc, edition, blocks, files},
//!   name[16], root cramfs_inode (12 bytes) — 76 bytes total;
//! - cramfs_inode bitfields: word0 {mode:16, uid:16}, word1 {size:24,
//!   gid:8}, word2 {namelen:6, offset:26}; offset is in 4-byte units
//!   (kernel shifts << 2); namelen is name length / 4 rounded up;
//! - directory entries are contiguous: next = pos + 12 + namelen*4;
//!   non-empty dirs point at their first child via offset<<2;
//! - regular files/symlinks: offset<<2 points at a u32 block-pointer
//!   table with maxblock = ceil(size / PAGE_SIZE) entries; each entry
//!   may carry CRAMFS_BLK_FLAG_UNCOMPRESSED (1<<31) and
//!   CRAMFS_BLK_FLAG_DIRECT_PTR (1<<30). Compressed blocks carry a u16
//!   length header whose value EXCLUDES the 2 header bytes; blocks are
//!   zlib-compressed. Uncompressed blocks are PAGE_SIZE (last block
//!   trimmed to offset_in_page(size)).
//!
//! Compressed blocks are inflated with `flate2`; output is charged to
//! the run-wide budget mid-stream. PAGE_SIZE is fixed at 4096 (the only
//! size mkfs.cramfs has ever emitted for block-pointer images).

use crate::artifact::{Confidence, Evidence, RelationKind};
use crate::bytesource::ByteSource;
use crate::engine::{
    ArtifactDraft, Budget, Candidate, ChildContent, ChildDraft, Handler, HandlerOutput,
};
use crate::error::{Error, Result};
use crate::handlers::find_all;
use std::collections::BTreeMap;
use std::io::Read;

pub struct CramfsHandler;

const MAGIC: u32 = 0x28cd_3d45;
const PAGE_SIZE: u64 = 4096;
const FLAG_HOLES: u32 = 0x0000_0100;
const FLAG_SHIFTED_ROOT_OFFSET: u32 = 0x0000_0400;
const BLK_UNCOMPRESSED: u32 = 1 << 31;
const BLK_DIRECT_PTR: u32 = 1 << 30;
/// Supported flags (kernel CRAMFS_SUPPORTED_FLAGS subset we understand).
const SUPPORTED_FLAGS: u32 = 0x0000_00ff | FLAG_HOLES | FLAG_SHIFTED_ROOT_OFFSET;

fn le32(src: &ByteSource, off: u64) -> Option<u32> {
    let mut b = [0u8; 4];
    src.read_at(off, &mut b).ok()?;
    Some(u32::from_le_bytes(b))
}
fn le16(src: &ByteSource, off: u64) -> Option<u16> {
    let mut b = [0u8; 2];
    src.read_at(off, &mut b).ok()?;
    Some(u16::from_le_bytes(b))
}

/// Parsed cramfs inode.
#[derive(Debug, Clone)]
struct CramInode {
    pos: u64,
    mode: u16,
    size: u32,
    /// Byte offset of the data / first child (offset field << 2).
    offset: u64,
    namelen_words: u32,
    name: String,
}

impl CramfsHandler {
    fn read_inode(src: &ByteSource, pos: u64, end: u64) -> Result<CramInode> {
        if pos.checked_add(12).map_or(true, |e| e > end) || pos + 12 > src.len() {
            return Err(Error::Validation {
                format: "cramfs",
                reason: format!("inode at {pos} out of bounds"),
            });
        }
        let w0 = le32(src, pos).unwrap_or(0);
        let w1 = le32(src, pos + 4).unwrap_or(0);
        let w2 = le32(src, pos + 8).unwrap_or(0);
        let mode = (w0 & 0xffff) as u16;
        let size = w1 & 0x00ff_ffff;
        let namelen = w2 & 0x3f;
        let offset = ((w2 >> 6) as u64) << 2;
        // Name follows the 12-byte header, namelen*4 bytes (padded).
        let name_bytes_len = (namelen as usize) * 4;
        if pos
            .checked_add(12 + name_bytes_len as u64)
            .map_or(true, |e| e > end)
        {
            return Err(Error::Validation {
                format: "cramfs",
                reason: format!("inode name at {pos} overruns image"),
            });
        }
        let mut raw = vec![0u8; name_bytes_len];
        if name_bytes_len > 0 {
            src.read_at(pos + 12, &mut raw)?;
        }
        let nul = raw.iter().position(|&b| b == 0).unwrap_or(raw.len());
        let name = String::from_utf8_lossy(&raw[..nul]).into_owned();
        Ok(CramInode {
            pos,
            mode,
            size,
            offset,
            namelen_words: namelen,
            name,
        })
    }

    fn next_entry(ino: &CramInode) -> u64 {
        ino.pos + 12 + u64::from(ino.namelen_words) * 4
    }

    fn file_type(mode: u16) -> u16 {
        mode & 0xf000
    }

    /// Reconstruct a regular file from its block-pointer table.
    /// Returns the bytes plus per-block provenance flags.
    fn read_file_data(
        src: &ByteSource,
        base: u64,
        end: u64,
        ino: &CramInode,
        limits: &crate::engine::EngineLimits,
        budget: &mut Budget,
        warnings: &mut Vec<String>,
    ) -> Result<Vec<u8>> {
        let table = ino.offset;
        let size = u64::from(ino.size);
        let maxblock = size.div_ceil(PAGE_SIZE) as usize;
        if maxblock == 0 {
            return Ok(Vec::new());
        }
        // The table itself must fit.
        if base
            .checked_add(table + maxblock as u64 * 4)
            .map_or(true, |e| e > end)
        {
            return Err(Error::Validation {
                format: "cramfs",
                reason: format!(
                    "block pointer table ({} entries) at {table} overruns image",
                    maxblock
                ),
            });
        }
        let mut out: Vec<u8> = Vec::with_capacity(size as usize);
        // Non-direct pointers chain: block 0 starts after the table.
        let mut prev_end: Option<u64> = None;
        for idx in 0..maxblock {
            let blkptr = le32(src, base + table + (idx as u64) * 4).unwrap_or(0);
            let uncompressed = blkptr & BLK_UNCOMPRESSED != 0;
            let direct = blkptr & BLK_DIRECT_PTR != 0;
            let ptr = blkptr & !(BLK_UNCOMPRESSED | BLK_DIRECT_PTR);

            let (mut block_start, mut block_len): (u64, u64);
            if direct {
                // Absolute start offset, shifted down 2 bits.
                block_start = (u64::from(ptr)) << 2;
                if uncompressed {
                    block_len = if idx == maxblock - 1 {
                        size % PAGE_SIZE
                    } else {
                        PAGE_SIZE
                    };
                } else {
                    let hdr = le16(src, base + block_start).ok_or_else(|| Error::Validation {
                        format: "cramfs",
                        reason: format!("block {idx}: length header unreadable"),
                    })?;
                    block_start += 2;
                    block_len = u64::from(hdr);
                }
            } else {
                // One-past-end pointer; start = previous block's end, or
                // just after the pointer table for block 0.
                block_start = match prev_end {
                    Some(p) => p,
                    None => table + maxblock as u64 * 4,
                };
                block_len = (u64::from(ptr)).saturating_sub(block_start);
                // Compressed blocks carry the u16 length header inside
                // that region; uncompressed (whole-page) regions don't.
                if !uncompressed {
                    let hdr = le16(src, base + block_start).ok_or_else(|| Error::Validation {
                        format: "cramfs",
                        reason: format!("block {idx}: length header unreadable"),
                    })?;
                    block_start += 2;
                    block_len = u64::from(hdr);
                }
            }
            prev_end = Some(block_start + block_len);

            if block_len == 0 && uncompressed {
                // Hole (FLAG_HOLES): zero-fill the page.
                let fill = if idx == maxblock - 1 {
                    size % PAGE_SIZE
                } else {
                    PAGE_SIZE
                };
                out.resize(out.len() + fill as usize, 0);
                continue;
            }
            if base + block_start + block_len > end || block_len > limits.max_child_size {
                warnings.push(format!(
                    "block {idx} at {block_start} ({} bytes) out of bounds; truncated",
                    block_len
                ));
                break;
            }
            let mut chunk = vec![0u8; block_len as usize];
            src.read_at(base + block_start, &mut chunk)?;
            if uncompressed {
                let take = if idx == maxblock - 1 {
                    (size - out.len() as u64).min(block_len)
                } else {
                    block_len
                };
                out.extend_from_slice(&chunk[..take as usize]);
            } else {
                // zlib-compressed block; cap output at the remaining size.
                let remaining = size.saturating_sub(out.len() as u64);
                let mut decoder = flate2::read::ZlibDecoder::new(&chunk[..]);
                let mut decoded = Vec::new();
                let capped = (&mut decoder)
                    .take(remaining.min(limits.max_child_size))
                    .read_to_end(&mut decoded);
                match capped {
                    Ok(_) => {
                        if !budget.charge(limits, decoded.len() as u64) {
                            return Err(Error::LimitExceeded {
                                limit: "max-total-expanded-bytes",
                                detail: format!("cramfs block {idx} expansion"),
                            });
                        }
                        out.extend_from_slice(&decoded);
                    }
                    Err(_) => {
                        warnings.push(format!("block {idx}: corrupt zlib stream; truncated"));
                        break;
                    }
                }
            }
            if out.len() as u64 >= size {
                break;
            }
        }
        out.truncate(size as usize);
        Ok(out)
    }

    #[allow(clippy::too_many_arguments)]
    /// Walk a directory's entry block. The directory's `size` field is
    /// the byte extent of its entries (kernel `cramfs_lookup` scans
    /// `while (offset < dir->i_size)` from `dir->offset`).
    #[allow(clippy::too_many_arguments)]
    fn walk_dir(
        src: &ByteSource,
        base: u64,
        end: u64,
        dir_pos: u64,
        dir_size: u64,
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
        let dir_end = dir_pos.checked_add(dir_size).map_or(end, |e| e.min(end));
        let mut pos = dir_pos;
        loop {
            if out.len() >= limits.max_fs_entries {
                warnings.push("max_fs_entries reached; walk truncated".to_string());
                return Ok(());
            }
            if pos + 12 > dir_end || pos + 12 > src.len() {
                // End of the directory's entry block.
                return Ok(());
            }
            let ino = Self::read_inode(src, pos, end)?;
            if ino.mode == 0 {
                // No file-type bits: zeroed padding. End of entries
                // (cramfs entries always carry a valid type in mode).
                return Ok(());
            }
            let ftype = Self::file_type(ino.mode);
            let child_path = if path.is_empty() {
                ino.name.clone()
            } else {
                format!("{path}/{}", ino.name)
            };
            let mut meta = BTreeMap::new();
            meta.insert("path".to_string(), child_path.clone());
            meta.insert("mode".to_string(), format!("{:#06o}", ino.mode));

            match ftype {
                0x4000 => {
                    // Directory: children live at ino.offset (0 = empty).
                    meta.insert("type".to_string(), "directory".to_string());
                    out.push(ChildDraft {
                        relation: RelationKind::FilesystemEntry,
                        label: format!("cramfs directory {child_path}"),
                        format_hint: "metadata",
                        content: ChildContent::Owned(Vec::new()),
                        size: 0,
                        metadata: meta,
                        warnings: Vec::new(),
                        entry_name: Some(ino.name.clone()),
                    });
                    if ino.offset != 0 && ino.size != 0 {
                        Self::walk_dir(
                            src,
                            base,
                            end,
                            base + ino.offset,
                            ino.size as u64,
                            &child_path,
                            depth + 1,
                            limits,
                            budget,
                            warnings,
                            out,
                        )?;
                    }
                }
                0x8000 => {
                    // Regular file: block-pointer reconstruction.
                    meta.insert("type".to_string(), "file".to_string());
                    meta.insert("declared_size".to_string(), ino.size.to_string());
                    if ino.size == 0 {
                        out.push(ChildDraft {
                            relation: RelationKind::FilesystemEntry,
                            label: format!("cramfs file {child_path} (0 bytes)"),
                            format_hint: "raw",
                            content: ChildContent::Owned(Vec::new()),
                            size: 0,
                            metadata: meta,
                            warnings: Vec::new(),
                            entry_name: Some(ino.name.clone()),
                        });
                    } else if u64::from(ino.size) > limits.max_child_size {
                        warnings.push(format!(
                            "file {child_path}: {} bytes exceed max_child_size; data not exposed",
                            ino.size
                        ));
                        out.push(ChildDraft {
                            relation: RelationKind::FilesystemEntry,
                            label: format!("cramfs file {child_path} (metadata only)"),
                            format_hint: "metadata",
                            content: ChildContent::Owned(Vec::new()),
                            size: 0,
                            metadata: meta,
                            warnings: Vec::new(),
                            entry_name: Some(ino.name.clone()),
                        });
                    } else {
                        let data =
                            Self::read_file_data(src, base, end, &ino, limits, budget, warnings)?;
                        meta.insert("reconstructed".to_string(), "true".to_string());
                        out.push(ChildDraft {
                            relation: RelationKind::ReconstructedFrom,
                            label: format!("cramfs file {child_path} ({} bytes)", data.len()),
                            format_hint: "raw",
                            content: ChildContent::Owned(data),
                            size: ino.size as u64,
                            metadata: meta,
                            warnings: vec![
                                "content reconstructed from cramfs block pointers (compressed)"
                                    .to_string(),
                            ],
                            entry_name: Some(ino.name.clone()),
                        });
                    }
                }
                0xA000 => {
                    // Symlink: target is the file data.
                    meta.insert("type".to_string(), "symlink".to_string());
                    let data =
                        Self::read_file_data(src, base, end, &ino, limits, budget, warnings)?;
                    out.push(ChildDraft {
                        relation: RelationKind::FilesystemEntry,
                        label: format!("cramfs symlink {child_path} -> {}", ino.name),
                        format_hint: "metadata",
                        content: ChildContent::Owned(data),
                        size: ino.size as u64,
                        metadata: meta,
                        warnings: vec![
                            "symlink target kept as metadata; never materialized".to_string()
                        ],
                        entry_name: Some(ino.name.clone()),
                    });
                }
                0x2000 | 0x6000 | 0x1000 | 0xC000 => {
                    // char/block device, FIFO, socket: metadata only.
                    meta.insert("type".to_string(), "special".to_string());
                    meta.insert("device_number".to_string(), ino.size.to_string());
                    out.push(ChildDraft {
                        relation: RelationKind::FilesystemEntry,
                        label: format!("cramfs special entry {child_path}"),
                        format_hint: "metadata",
                        content: ChildContent::Owned(Vec::new()),
                        size: 0,
                        metadata: meta,
                        warnings: vec!["special entries are never materialized".to_string()],
                        entry_name: Some(ino.name.clone()),
                    });
                }
                _ => {
                    // Unknown type: skip without poisoning the walk.
                    warnings.push(format!(
                        "entry {child_path}: unknown file type {ftype:#06x}; skipped"
                    ));
                }
            }
            pos = Self::next_entry(&ino);
        }
    }
}

impl Handler for CramfsHandler {
    fn format(&self) -> &'static str {
        "cramfs"
    }

    fn find_candidates(&self, src: &ByteSource) -> Vec<Candidate> {
        // Magic 0x28cd3d45 little-endian = 45 3d cd 28; big-endian images
        // store 28 3d cd 45 (kernel checks both).
        find_all(src, &[0x45, 0x3d, 0xcd, 0x28])
            .into_iter()
            .chain(find_all(src, &[0x28, 0x3d, 0xcd, 0x45]))
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
        // Kernel reads the superblock at 0, retrying at 512 for boot
        // sectors. The candidate offset IS the superblock position.
        if base + 76 > src.len() {
            return Err(Error::Validation {
                format: "cramfs",
                reason: "superblock truncated".into(),
            });
        }
        let magic = le32(src, base).unwrap_or(0);
        if magic != MAGIC {
            return Err(Error::Validation {
                format: "cramfs",
                reason: format!("bad magic {magic:#x}"),
            });
        }
        let size = le32(src, base + 4).unwrap_or(0) as u64;
        let flags = le32(src, base + 8).unwrap_or(0);
        if size == 0 || base.checked_add(size).map_or(true, |e| e > src.len()) {
            return Err(Error::Validation {
                format: "cramfs",
                reason: format!("size {size} inconsistent with source"),
            });
        }
        if flags & !SUPPORTED_FLAGS != 0 {
            return Err(Error::Validation {
                format: "cramfs",
                reason: format!("unsupported feature flags {flags:#x}"),
            });
        }
        // Signature check ("Compressed ROMFS" at +16).
        let mut sig = [0u8; 16];
        src.read_at(base + 16, &mut sig)?;
        if &sig != b"Compressed ROMFS" {
            return Err(Error::Validation {
                format: "cramfs",
                reason: "signature mismatch".into(),
            });
        }
        let end = base + size;
        // Root inode at +64; SHIFTED_ROOT_OFFSET shifts its offset by
        // PAGE_SIZE >> 2 units (kernel: root_offset << 2 + PAGE_SIZE).
        let mut root = Self::read_inode(src, base + 64, end)?;
        if flags & FLAG_SHIFTED_ROOT_OFFSET != 0 {
            root.offset += PAGE_SIZE;
        }
        if Self::file_type(root.mode) != 0x4000 {
            return Err(Error::Validation {
                format: "cramfs",
                reason: format!("root inode is not a directory (mode {:#06o})", root.mode),
            });
        }

        let mut children = Vec::new();
        let mut warnings = Vec::new();
        if root.offset != 0 {
            // Root entry-block extent = root.size; when the root records
            // no explicit size, bound by the image end.
            let root_extent = if root.size != 0 {
                u64::from(root.size)
            } else {
                size
            };
            Self::walk_dir(
                src,
                base,
                end,
                base + root.offset,
                root_extent,
                "",
                0,
                limits,
                budget,
                &mut warnings,
                &mut children,
            )?;
        }

        let edition = le32(src, base + 36).unwrap_or(0);
        let files = le32(src, base + 44).unwrap_or(0);
        let mut metadata = BTreeMap::new();
        metadata.insert("size".to_string(), size.to_string());
        metadata.insert("flags".to_string(), format!("{flags:#x}"));
        metadata.insert("edition".to_string(), edition.to_string());
        metadata.insert("files".to_string(), files.to_string());
        metadata.insert("entries".to_string(), children.len().to_string());

        let evidence = vec![
            "cramfs magic 0x28cd3d45 + signature 'Compressed ROMFS' validated".to_string(),
            format!(
                "{} files declared; {} entries walked",
                files,
                children.len()
            ),
            "block-pointer compressed file reconstruction enabled (zlib)".to_string(),
        ];

        Ok(HandlerOutput {
            artifacts: vec![ArtifactDraft {
                format: "cramfs".to_string(),
                label: format!("cramfs image ({} entries)", children.len()),
                offset: base,
                size,
                confidence: Confidence::Validated,
                evidence: Evidence::facts(evidence),
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
        CramfsHandler.validate(
            src,
            Candidate { offset: off },
            &crate::engine::EngineLimits::default(),
            &mut Budget::default(),
        )
    }

    fn put32(buf: &mut [u8], off: usize, v: u32) {
        buf[off..off + 4].copy_from_slice(&v.to_le_bytes());
    }

    /// Write a cramfs inode (12 bytes + padded name) at `off`.
    /// Returns the offset of the next entry.
    fn put_inode(
        buf: &mut [u8],
        off: usize,
        mode: u16,
        size: u32,
        offset: u32,
        name: &[u8],
    ) -> usize {
        let namelen = name.len().div_ceil(4) as u32;
        put32(buf, off, u32::from(mode)); // word0: mode:16 | uid:16
        put32(buf, off + 4, size); // word1: size:24 | gid:8
                                   // The offset field holds byte_offset / 4 (kernel shifts << 2).
        put32(buf, off + 8, (namelen & 0x3f) | ((offset / 4) << 6)); // word2
        buf[off + 12..off + 12 + name.len()].copy_from_slice(name);
        off + 12 + (namelen as usize) * 4
    }

    /// Build an uncompressed cramfs image:
    ///   /flag.txt "FLAG{cramfs}" (11 bytes, 1 page)
    ///   /dir/ with /dir/hello.txt "HI"
    fn cramfs_image() -> Vec<u8> {
        // Superblock 76 bytes. Each directory owns an entry BLOCK:
        // root.size bounds the root's entries (kernel: lookup scans
        // `while (offset < dir->i_size)`); subdir blocks sit outside it.
        // Layout (offsets relative to image start):
        //  64  root inode (in-superblock): child @80, size=36 (80..116)
        //  80  flag.txt (reg, 2 name words)
        // 100  dir (dir, 1 name word): child @140, size=24 (140..164)
        // 140  hello.txt (dir's child, 3 name words) [140..164]
        // 164  flag blktable (1 entry, DIRECT|UNCOMPRESSED) -> 168
        // 168  page data: "FLAG{cramfs}" (12 bytes)
        // 200  hello blktable -> data @204 "HI"
        let total = 4280usize;
        let mut img = vec![0u8; total];
        put32(&mut img, 0, MAGIC);
        put32(&mut img, 4, total as u32);
        put32(&mut img, 8, 0); // flags
        img[16..32].copy_from_slice(b"Compressed ROMFS");
        put32(&mut img, 36, 1); // edition
        put32(&mut img, 44, 2); // files

        // Root inode at 64 (inside the 76-byte superblock, after
        // fsid@32 + name[16]@48): dir, first child at 80, entry-block
        // extent 36 bytes (80..116).
        let _ = put_inode(&mut img, 64, 0o040755, 36, 80, b"root");

        // Root block: flag.txt@80 -> dir@100 (block ends at 116).
        let _ = put_inode(&mut img, 80, 0o100644, 12, 164, b"flag.txt");
        // dir: child block at 140, extent 24 bytes (140..164).
        let _ = put_inode(&mut img, 100, 0o040755, 24, 140, b"dir");

        // dir's block: hello.txt@140 (12 + 3*4 = 24 bytes).
        let _ = put_inode(&mut img, 140, 0o100644, 2, 200, b"hello.txt");

        // flag.txt block table at 164: page at 168.
        put32(
            &mut img,
            164,
            (168 >> 2) | BLK_UNCOMPRESSED | BLK_DIRECT_PTR,
        );
        img[168..180].copy_from_slice(b"FLAG{cramfs}");

        // hello.txt block table at 200: data at 204.
        put32(
            &mut img,
            200,
            (204 >> 2) | BLK_UNCOMPRESSED | BLK_DIRECT_PTR,
        );
        img[204..206].copy_from_slice(b"HI");
        img
    }

    #[test]
    fn cramfs_uncompressed_traversal() {
        let src = ByteSource::from_vec(cramfs_image());
        let out = validate_at(&src, 0).expect("cramfs validates");
        let art = &out.artifacts[0];
        assert_eq!(art.confidence, Confidence::Validated);
        let flag = art
            .children
            .iter()
            .find(|c| c.metadata.get("path").map(String::as_str) == Some("flag.txt"))
            .expect("flag.txt");
        assert_eq!(flag.size, 12);
        match &flag.content {
            ChildContent::Owned(d) => assert_eq!(*d, b"FLAG{cramfs}".to_vec()),
            _ => panic!("file content must be owned/reconstructed"),
        }
        let nested = art
            .children
            .iter()
            .find(|c| c.metadata.get("path").map(String::as_str) == Some("dir/hello.txt"))
            .expect("nested file");
        match &nested.content {
            ChildContent::Owned(d) => assert_eq!(*d, b"HI".to_vec()),
            _ => panic!("nested content"),
        }
        assert_eq!(
            art.metadata.get("entries").map(String::as_str),
            Some("3") // flag.txt + dir + dir/hello.txt
        );
    }

    #[test]
    fn cramfs_compressed_block_reconstruction() {
        // Compressed page: zlib block. blkptr with DIRECT_PTR unset,
        // UNCOMPRESSED unset: table has one entry = one-past-end.
        // Layout: table at 124, block data at 128.
        use std::io::Write;
        let mut block = Vec::new();
        {
            let mut enc =
                flate2::write::ZlibEncoder::new(&mut block, flate2::Compression::default());
            enc.write_all(b"FLAG{cramfs_compressed}").unwrap();
            enc.finish().unwrap();
        }
        let compressed_payload = &block[..]; // complete zlib stream

        let total = (128 + compressed_payload.len() + 16).max(4280);
        let mut img = vec![0u8; total];
        put32(&mut img, 0, MAGIC);
        put32(&mut img, 4, total as u32);
        img[16..32].copy_from_slice(b"Compressed ROMFS");
        put32(&mut img, 44, 1);

        // root at 64 (superblock-embedded), child at 80.
        let n = put_inode(&mut img, 64, 0o040755, 0, 80, b"root");
        // flag.txt at 80: size 23, table at 100.
        let n = put_inode(&mut img, n, 0o100644, 23, 100, b"flag.txt");

        // Block table: one entry, one-past-end = 104 + payload.len().
        put32(&mut img, n, (104 + compressed_payload.len()) as u32);
        // u16 length header + zlib data at 104.
        img[104..106].copy_from_slice(&(compressed_payload.len() as u16).to_le_bytes());
        img[106..106 + compressed_payload.len()].copy_from_slice(compressed_payload);

        let src = ByteSource::from_vec(img);
        let out = validate_at(&src, 0).expect("validates");
        let flag = out.artifacts[0]
            .children
            .iter()
            .find(|c| c.metadata.get("path").map(String::as_str) == Some("flag.txt"))
            .expect("flag.txt");
        match &flag.content {
            ChildContent::Owned(d) => assert_eq!(*d, b"FLAG{cramfs_compressed}".to_vec()),
            _ => panic!("compressed file must reconstruct"),
        }
        assert!(flag
            .warnings
            .iter()
            .any(|w| w.contains("reconstructed from cramfs block pointers")));
    }

    #[test]
    fn cramfs_bad_signature_rejected() {
        let mut img = cramfs_image();
        img[16..32].copy_from_slice(b"Compressed ROMFZ");
        let src = ByteSource::from_vec(img);
        assert!(validate_at(&src, 0).is_err());
    }

    #[test]
    fn cramfs_unsupported_flags_rejected() {
        let mut img = cramfs_image();
        put32(&mut img, 8, 0x0000_0800); // EXT_BLOCK_POINTERS unsupported here
        let src = ByteSource::from_vec(img);
        assert!(validate_at(&src, 0).is_err());
    }

    #[test]
    fn cramfs_hostile_size_rejected() {
        let mut img = cramfs_image();
        put32(&mut img, 4, 1 << 24);
        let src = ByteSource::from_vec(img);
        assert!(validate_at(&src, 0).is_err());
    }
}
