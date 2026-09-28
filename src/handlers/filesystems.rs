//! M3 filesystem handlers: SquashFS (firmware target) and ISO9660
//! (optical images), plus lightweight superblock recognition for
//! ext2/3/4, exFAT, NTFS, cramfs, ROMFS, UBI/UBIFS/JFFS2 — the latter
//! honestly marked as detect/metadata only in this milestone.
//!
//! SquashFS: superblock validation (magic, inodes/blocks/files sizes,
//! compressor id), inode/directory metadata walking is deferred; the
//! archive region is claimed as one artifact with compressor metadata
//! and honest Partial confidence for entry extraction.
//! ISO9660: descriptor-chain validation (PVD + Joliet SVD), recursive
//! directory traversal with source-backed file extents, multi-extent
//! reconstruction.

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
const METADATA_SIZE: u64 = 8192;
const COMPRESSED_BIT: u16 = 1 << 15;
const COMPRESSED_BIT_BLOCK: u32 = 1 << 24;
const INVALID_FRAG: u32 = 0xFFFF_FFFF;
/// Directory entry types (squashfs_fs.h).
const T_DIR: u16 = 1;
const T_FILE: u16 = 2;
const T_SYMLINK: u16 = 3;
const T_LDIR: u16 = 8;
const T_LREG: u16 = 9;

impl SquashfsHandler {
    fn compressor_name(id: u16) -> &'static str {
        match id {
            1 => "gzip",
            2 => "lzma",
            3 => "lzo",
            4 => "xz",
            5 => "lz4",
            6 => "zstd",
            7 => "zstd",
            _ => "unknown",
        }
    }

    /// Read one metadata block at `pos` (u16 length header; bit 15 set =
    /// uncompressed). Returns (decompressed bytes, next block position).
    fn read_meta_block(
        src: &ByteSource,
        _base: u64,
        pos: u64,
        end: u64,
        compressor: u16,
        dict_size: u32,
    ) -> Result<(Vec<u8>, u64)> {
        if pos + 2 > end || pos + 2 > src.len() {
            return Err(Error::Validation {
                format: "squashfs",
                reason: format!("metadata block header at {pos} out of bounds"),
            });
        }
        let hdr = le16(src, pos).unwrap_or(0);
        let uncompressed = hdr & COMPRESSED_BIT != 0;
        let size = u64::from(hdr & !COMPRESSED_BIT);
        if size == 0 || size > METADATA_SIZE || pos + 2 + size > end {
            return Err(Error::Validation {
                format: "squashfs",
                reason: format!("metadata block at {pos} has bad size {size}"),
            });
        }
        let mut raw = vec![0u8; size as usize];
        src.read_at(pos + 2, &mut raw)?;
        let mut cursor = pos + 2 + size;
        if uncompressed {
            Ok((raw, cursor))
        } else {
            let out = Self::decompress(compressor, dict_size, &raw, METADATA_SIZE as usize)?;
            cursor = cursor.min(end);
            Ok((out, cursor))
        }
    }

    /// Decompress a data/metadata block with the compressor named in the
    /// superblock. Supports gzip/zstd/xz (bundled crates); others are
    /// honest errors so unsupported images never fake content.
    fn decompress(
        compressor: u16,
        dict_size: u32,
        raw: &[u8],
        expected_out: usize,
    ) -> Result<Vec<u8>> {
        let comp = compressor;
        match comp {
            1 => {
                let mut out = Vec::with_capacity(expected_out);
                let mut dec = flate2::read::ZlibDecoder::new(raw);
                std::io::Read::read_to_end(&mut dec, &mut out).map_err(|_| Error::Validation {
                    format: "squashfs",
                    reason: "gzip metadata block failed to inflate".into(),
                })?;
                Ok(out)
            }
            6 | 7 => {
                let out = zstd::stream::decode_all(raw).map_err(|_| Error::Validation {
                    format: "squashfs",
                    reason: "zstd metadata block failed to decode".into(),
                })?;
                Ok(out)
            }
            4 => {
                // SquashFS xz = raw LZMA2 stream + dictionary size from
                // the compressor options. Uses lzma-rust's LZMA2Reader.
                if dict_size == 0 {
                    return Err(Error::Validation {
                        format: "squashfs",
                        reason: "xz compressor options missing dictionary size".into(),
                    });
                }
                let mut out = Vec::with_capacity(expected_out);
                let mut dec = lzma_rust::LZMA2Reader::new(raw, dict_size, None);
                std::io::Read::read_to_end(&mut dec, &mut out).map_err(|_| Error::Validation {
                    format: "squashfs",
                    reason: "lzma2 metadata block failed to decode".into(),
                })?;
                Ok(out)
            }
            other => Err(Error::Validation {
                format: "squashfs",
                reason: format!("unsupported compressor id {other}"),
            }),
        }
    }

    /// Read a full metadata region (possibly several chained blocks) and
    /// return the decompressed bytes plus a map from absolute metadata
    /// position -> offset within the decompressed buffer.
    #[allow(clippy::type_complexity)]
    fn read_meta_region(
        src: &ByteSource,
        base: u64,
        start: u64,
        end: u64,
        compressor: u16,
        dict_size: u32,
        limits: &crate::engine::EngineLimits,
    ) -> Result<(Vec<u8>, Vec<(u64, usize)>)> {
        let mut out = Vec::new();
        let mut index: Vec<(u64, usize)> = Vec::new();
        let mut pos = start;
        let blocks = limits.max_sqlite_pages.max(1024);
        let mut count = 0usize;
        while pos < end {
            count += 1;
            if count > blocks {
                return Err(Error::Validation {
                    format: "squashfs",
                    reason: "metadata region has too many blocks".into(),
                });
            }
            let (block, next) = Self::read_meta_block(src, base, pos, end, compressor, dict_size)?;
            index.push((pos, out.len()));
            out.extend_from_slice(&block);
            pos = next;
        }
        Ok((out, index))
    }

    /// Resolve an (absolute metadata pos, offset) pair into a buffer index.
    fn resolve_meta(index: &[(u64, usize)], pos: u64, offset: u64) -> Result<usize> {
        let compressed_pos = pos;
        for &(blk, buf_off) in index {
            if blk == compressed_pos {
                return Ok(buf_off + offset as usize);
            }
        }
        Err(Error::Validation {
            format: "squashfs",
            reason: format!("metadata position {pos} not in table index"),
        })
    }

    /// Parse an inode at (block-relative pos, offset). Returns the inode
    /// and its total on-disk byte size.
    #[allow(clippy::too_many_arguments)]
    fn parse_inode(
        &self,
        inode_buf: &[u8],
        inode_index: &[(u64, usize)],
        pos_abs: u64,
        offset: u64,
        sb: &SqfsSuper,
    ) -> Result<SqfsInode> {
        let start = Self::resolve_meta(inode_index, pos_abs, offset)?;
        if start + 16 > inode_buf.len() {
            return Err(Error::Validation {
                format: "squashfs",
                reason: "inode header truncated".into(),
            });
        }
        let rd16 = |o: usize| u16::from_le_bytes([inode_buf[o], inode_buf[o + 1]]);
        let rd32 = |o: usize| u32::from_le_bytes(inode_buf[o..o + 4].try_into().unwrap());
        let inode_type = rd16(start);
        let mode = rd16(start + 2);
        let uid = rd16(start + 4);
        let mtime = rd32(start + 8);
        let ino_number = rd32(start + 12);
        match inode_type {
            T_DIR | T_LDIR => {
                let (nlink, file_size, start_block, offset2, parent, i_count, hdr_len) =
                    if inode_type == T_DIR {
                        // dir inode: start_block u32 @16, nlink @20,
                        // file_size u16 @24, offset u16 @26, parent @28
                        (
                            u64::from(rd32(start + 20)),
                            u64::from(rd16(start + 24)),
                            rd32(start + 16),
                            u64::from(rd16(start + 26)),
                            rd32(start + 28),
                            0usize,
                            32usize,
                        )
                    } else {
                        // ldir: nlink @16, file_size @20, start_block @24,
                        // parent @28, i_count @32, offset @34
                        (
                            u64::from(rd32(start + 16)),
                            u64::from(rd32(start + 20)),
                            rd32(start + 24),
                            u64::from(rd16(start + 34)),
                            rd32(start + 28),
                            rd16(start + 32) as usize,
                            36usize,
                        )
                    };
                // Directory index entries (ldir only): index u32,
                // start_block u32, size u32, name (size+1 bytes).
                let mut indices = Vec::new();
                if inode_type == T_LDIR {
                    let mut p = start + hdr_len;
                    for _ in 0..i_count {
                        if p + 12 > inode_buf.len() {
                            break;
                        }
                        let index = rd32(p);
                        let idx_start = rd32(p + 4);
                        let size = rd32(p + 8) as usize;
                        let name = if p + 12 + size < inode_buf.len() {
                            String::from_utf8_lossy(&inode_buf[p + 12..p + 12 + size + 1])
                                .into_owned()
                        } else {
                            String::new()
                        };
                        indices.push((index, idx_start, name));
                        p += 12 + size + 1;
                    }
                }
                Ok(SqfsInode {
                    inode_type,
                    mode,
                    uid,
                    mtime,
                    ino_number,
                    start_block,
                    file_size,
                    offset: offset2,
                    fragment: INVALID_FRAG,
                    frag_offset: 0,
                    block_list: Vec::new(),
                    symlink: Vec::new(),
                    nlink,
                    parent,
                    indices,
                })
            }
            T_FILE | T_LREG => {
                let (start_block, file_size, fragment, frag_offset, _block_count, hdr_len) =
                    if inode_type == T_FILE {
                        // reg: start @16, fragment @20, offset @24, size @28
                        (
                            rd32(start + 16),
                            u64::from(rd32(start + 28)),
                            rd32(start + 20),
                            u64::from(rd32(start + 24)),
                            0usize,
                            32usize,
                        )
                    } else {
                        // lreg: start @16, file_size @24, sparse @32,
                        // nlink @40, fragment @44, offset @48
                        (
                            rd32(start + 16),
                            u64::from(u32::from_le_bytes(
                                inode_buf[start + 24..start + 28].try_into().unwrap(),
                            )),
                            rd32(start + 44),
                            u64::from(rd32(start + 48)),
                            0usize,
                            56usize,
                        )
                    };
                let blocks = if fragment == INVALID_FRAG {
                    // full blocks + possible tail block
                    file_size.div_ceil(u64::from(sb.block_size)) as usize
                } else {
                    (file_size / u64::from(sb.block_size)) as usize
                };
                let mut block_list = Vec::with_capacity(blocks);
                for k in 0..blocks {
                    let p = start + hdr_len + k * 4;
                    if p + 4 > inode_buf.len() {
                        return Err(Error::Validation {
                            format: "squashfs",
                            reason: "file block list truncated".into(),
                        });
                    }
                    block_list.push(u32::from_le_bytes(inode_buf[p..p + 4].try_into().unwrap()));
                }
                // For reg inodes the stored file_size covers fragment:
                // full blocks = size / block_size; tail lives in fragment.
                let file_size_adj = file_size;
                Ok(SqfsInode {
                    inode_type,
                    mode,
                    uid,
                    mtime,
                    ino_number,
                    start_block,
                    file_size: file_size_adj,
                    offset: frag_offset,
                    fragment,
                    frag_offset,
                    block_list,
                    symlink: Vec::new(),
                    nlink: 1,
                    parent: 0,
                    indices: Vec::new(),
                })
            }
            T_SYMLINK => {
                let symlink_size = rd32(start + 16) as usize;
                let target = if start + 20 + symlink_size <= inode_buf.len() {
                    inode_buf[start + 20..start + 20 + symlink_size].to_vec()
                } else {
                    Vec::new()
                };
                Ok(SqfsInode {
                    inode_type,
                    mode,
                    uid,
                    mtime,
                    ino_number,
                    start_block: 0,
                    file_size: symlink_size as u64,
                    offset: 0,
                    fragment: INVALID_FRAG,
                    frag_offset: 0,
                    block_list: Vec::new(),
                    symlink: target,
                    nlink: 1,
                    parent: 0,
                    indices: Vec::new(),
                })
            }
            _ => {
                // Devices/FIFO/socket: base header only.
                Ok(SqfsInode {
                    inode_type,
                    mode,
                    uid,
                    mtime,
                    ino_number,
                    start_block: 0,
                    file_size: 0,
                    offset: 0,
                    fragment: INVALID_FRAG,
                    frag_offset: 0,
                    block_list: Vec::new(),
                    symlink: Vec::new(),
                    nlink: 1,
                    parent: 0,
                    indices: Vec::new(),
                })
            }
        }
    }

    /// Read file content: full blocks from data region + optional
    /// fragment tail. Sparse blocks (size 0) zero-fill.
    #[allow(clippy::too_many_arguments)]
    fn read_file_content(
        &self,
        src: &ByteSource,
        base: u64,
        sb: &SqfsSuper,
        ino: &SqfsInode,
        limits: &crate::engine::EngineLimits,
        budget: &mut Budget,
        warnings: &mut Vec<String>,
    ) -> Result<Vec<u8>> {
        let bs = u64::from(sb.block_size);
        let total = ino.file_size.min(limits.max_child_size);
        let mut out = Vec::with_capacity(total as usize);
        for &blk in &ino.block_list {
            let stored = blk & !COMPRESSED_BIT_BLOCK;
            if stored == 0 {
                // Sparse block.
                let take = bs.min(total - out.len() as u64);
                out.resize(out.len() + take as usize, 0);
                continue;
            }
            let blk_abs = sb.data_start + u64::from(ino.start_block);
            if blk_abs + u64::from(stored) > src.len() {
                warnings.push("file block past source; truncated".to_string());
                break;
            }
            let mut raw = vec![0u8; stored as usize];
            src.read_at(blk_abs, &mut raw)?;
            let data = if blk & COMPRESSED_BIT_BLOCK != 0 {
                raw.clone() // uncompressed flag set
            } else {
                Self::decompress(sb.compression, sb.dict_size, &raw, sb.block_size as usize)?
            };
            if !budget.charge(limits, data.len() as u64) {
                return Err(Error::LimitExceeded {
                    limit: "max-total-expanded-bytes",
                    detail: "squashfs file block".into(),
                });
            }
            let take = (total - out.len() as u64).min(data.len() as u64) as usize;
            out.extend_from_slice(&data[..take]);
            if out.len() as u64 >= total {
                break;
            }
        }
        // Fragment tail.
        if ino.fragment != INVALID_FRAG && (out.len() as u64) < total {
            if let Some(frag) = Self::fragment_entry(src, base, sb, ino.fragment)? {
                let stored = frag.size & !COMPRESSED_BIT_BLOCK;
                let uncompressed = frag.size & COMPRESSED_BIT_BLOCK != 0;
                let frag_abs = sb.data_start + frag.start_block;
                if stored > 0 && frag_abs + u64::from(stored) <= src.len() && ino.offset < bs {
                    let mut raw = vec![0u8; stored as usize];
                    src.read_at(frag_abs, &mut raw)?;
                    let block = if uncompressed {
                        raw
                    } else {
                        Self::decompress(
                            sb.compression,
                            sb.dict_size,
                            &raw,
                            sb.block_size as usize,
                        )?
                    };
                    let frag_start = ino.offset as usize;
                    let want = (total - out.len() as u64) as usize;
                    let endi = (frag_start + want).min(block.len());
                    if frag_start <= endi {
                        let tail = &block[frag_start..endi];
                        if !budget.charge(limits, tail.len() as u64) {
                            return Err(Error::LimitExceeded {
                                limit: "max-total-expanded-bytes",
                                detail: "squashfs fragment".into(),
                            });
                        }
                        out.extend_from_slice(tail);
                    }
                } else {
                    warnings.push("fragment tail unreadable; truncated".to_string());
                }
            } else {
                warnings.push("fragment table unavailable; truncated".to_string());
            }
        }
        out.truncate(total as usize);
        Ok(out)
    }

    /// Read fragment entry `idx` from the fragment table (metadata
    /// blocks of 16-byte entries chained via index at fragment_table).
    fn fragment_entry(
        src: &ByteSource,
        base: u64,
        sb: &SqfsSuper,
        idx: u32,
    ) -> Result<Option<FragmentEntry>> {
        if sb.fragment_table == 0 || sb.fragments == 0 || idx >= sb.fragments {
            return Ok(None);
        }
        let bytes_per = 16u64;
        let meta_blocks = u64::from(idx) * bytes_per / METADATA_SIZE;
        let offset = u64::from(idx) * bytes_per % METADATA_SIZE;
        // Index of metadata block positions sits at fragment_table.
        let index_pos = base + sb.fragment_table + meta_blocks * 8;
        if index_pos + 8 > src.len() {
            return Ok(None);
        }
        let block_pos = le64(src, index_pos).unwrap_or(0);
        // Read that metadata block (u16 header + data).
        if base + block_pos + 2 > src.len() {
            return Ok(None);
        }
        let hdr = le16(src, base + block_pos).unwrap_or(0);
        let uncompressed = hdr & COMPRESSED_BIT != 0;
        let size = u64::from(hdr & !COMPRESSED_BIT);
        if size == 0 || base + block_pos + 2 + size > src.len() {
            return Ok(None);
        }
        let mut raw = vec![0u8; size as usize];
        src.read_at(base + block_pos + 2, &mut raw)?;
        let data = if uncompressed {
            raw
        } else {
            Self::decompress(sb.compression, sb.dict_size, &raw, METADATA_SIZE as usize)?
        };
        let at = offset as usize;
        if at + 16 > data.len() {
            return Ok(None);
        }
        let start_block = u64::from_le_bytes(data[at..at + 8].try_into().unwrap());
        let fsize = u32::from_le_bytes(data[at + 8..at + 12].try_into().unwrap());
        Ok(Some(FragmentEntry {
            start_block,
            size: fsize,
        }))
    }

    /// Walk one directory's listing region. `dir_pos` = (start_block,
    /// offset) from the dir inode; `size` = total listing bytes.
    #[allow(clippy::too_many_arguments)]
    fn walk_dir(
        &self,
        src: &ByteSource,
        base: u64,
        sb: &SqfsSuper,
        inode_buf: &[u8],
        inode_index: &[(u64, usize)],
        dir_buf: &[u8],
        dir_index: &[(u64, usize)],
        dir_start_block: u32,
        dir_offset: u64,
        dir_size: u64,
        path: &str,
        depth: u32,
        limits: &crate::engine::EngineLimits,
        budget: &mut Budget,
        warnings: &mut Vec<String>,
        out: &mut Vec<ChildDraft>,
    ) -> Result<()> {
        if depth > 16 {
            warnings.push("squashfs directory nesting deeper than 16 not walked".to_string());
            return Ok(());
        }
        // The listing begins at metadata block (dir_table_start +
        // dir_start_block), offset within the decompressed block.
        let pos_abs = sb.dir_table + u64::from(dir_start_block);
        let mut buf_off = Self::resolve_meta(dir_index, pos_abs, dir_offset)?;
        let end = dir_offset + dir_size;
        let mut consumed = 0u64;
        while consumed < end {
            if out.len() >= limits.max_fs_entries {
                warnings.push("max_fs_entries reached; walk truncated".to_string());
                return Ok(());
            }
            if buf_off + 12 > dir_buf.len() {
                break; // honest end of listing
            }
            let rd16 = |o: usize| u16::from_le_bytes([dir_buf[o], dir_buf[o + 1]]);
            let rd32 = |o: usize| u32::from_le_bytes(dir_buf[o..o + 4].try_into().unwrap());
            let count = rd32(buf_off) as usize;
            let hdr_start_block = rd32(buf_off + 4);
            let _hdr_inode_number = rd32(buf_off + 8);
            if count + 1 > 256 {
                return Err(Error::Validation {
                    format: "squashfs",
                    reason: format!("dir header count {} exceeds 256", count + 1),
                });
            }
            buf_off += 12;
            consumed += 12;
            for _ in 0..=count {
                if buf_off + 8 > dir_buf.len() {
                    break;
                }
                let entry_offset = u64::from(rd16(buf_off));
                let delta = i16::from_le_bytes([dir_buf[buf_off + 2], dir_buf[buf_off + 3]]);
                let etype = rd16(buf_off + 4);
                let name_size = rd16(buf_off + 6) as usize; // stored size-1
                if name_size + 1 > 256 {
                    return Err(Error::Validation {
                        format: "squashfs",
                        reason: format!("name size {} exceeds 255", name_size + 1),
                    });
                }
                let name_len = name_size + 1;
                if buf_off + 8 + name_len > dir_buf.len() {
                    break;
                }
                let name = String::from_utf8_lossy(&dir_buf[buf_off + 8..buf_off + 8 + name_len])
                    .into_owned();
                buf_off += 8 + name_len;
                consumed += (8 + name_len) as u64;
                if etype != T_DIR
                    && etype != T_FILE
                    && etype != T_SYMLINK
                    && etype != T_LDIR
                    && etype != T_LREG
                {
                    // Devices/FIFO/socket: metadata-only child.
                    let child_path = if path.is_empty() {
                        name.clone()
                    } else {
                        format!("{path}/{name}")
                    };
                    let mut meta = BTreeMap::new();
                    meta.insert("path".to_string(), child_path.clone());
                    meta.insert("type".to_string(), "special".to_string());
                    out.push(ChildDraft {
                        relation: RelationKind::FilesystemEntry,
                        label: format!("squashfs special entry {child_path}"),
                        format_hint: "metadata",
                        content: ChildContent::Owned(Vec::new()),
                        size: 0,
                        metadata: meta,
                        warnings: vec!["special entries are never materialized".to_string()],
                        entry_name: Some(name),
                    });
                    continue;
                }
                let ino_pos_abs = sb.inode_table + u64::from(hdr_start_block);
                let ino =
                    self.parse_inode(inode_buf, inode_index, ino_pos_abs, entry_offset, sb)?;
                let child_path = if path.is_empty() {
                    name.clone()
                } else {
                    format!("{path}/{name}")
                };
                self.emit_entry(
                    src,
                    base,
                    sb,
                    inode_buf,
                    inode_index,
                    dir_buf,
                    dir_index,
                    &ino,
                    &name,
                    &child_path,
                    depth,
                    limits,
                    budget,
                    warnings,
                    out,
                )?;
                let _ = delta;
            }
        }
        Ok(())
    }

    /// Emit one child for an inode (recursing into directories).
    #[allow(clippy::too_many_arguments)]
    fn emit_entry(
        &self,
        src: &ByteSource,
        base: u64,
        sb: &SqfsSuper,
        inode_buf: &[u8],
        inode_index: &[(u64, usize)],
        dir_buf: &[u8],
        dir_index: &[(u64, usize)],
        ino: &SqfsInode,
        name: &str,
        child_path: &str,
        depth: u32,
        limits: &crate::engine::EngineLimits,
        budget: &mut Budget,
        warnings: &mut Vec<String>,
        out: &mut Vec<ChildDraft>,
    ) -> Result<()> {
        let mut meta = BTreeMap::new();
        meta.insert("path".to_string(), child_path.to_string());
        meta.insert("mode".to_string(), format!("{:#06o}", ino.mode));
        meta.insert("inode_number".to_string(), ino.ino_number.to_string());
        meta.insert("uid".to_string(), ino.uid.to_string());
        meta.insert("mtime".to_string(), ino.mtime.to_string());
        meta.insert("nlink".to_string(), ino.nlink.to_string());
        let entry_name = Some(name.to_string());
        let is_dir = ino.inode_type == T_DIR || ino.inode_type == T_LDIR;
        let is_file = ino.inode_type == T_FILE || ino.inode_type == T_LREG;
        if is_dir {
            meta.insert("type".to_string(), "directory".to_string());
            out.push(ChildDraft {
                relation: RelationKind::FilesystemEntry,
                label: format!("squashfs directory {child_path}"),
                format_hint: "metadata",
                content: ChildContent::Owned(Vec::new()),
                size: 0,
                metadata: meta,
                warnings: Vec::new(),
                entry_name,
            });
            if ino.file_size > 0 {
                self.walk_dir(
                    src,
                    base,
                    sb,
                    inode_buf,
                    inode_index,
                    dir_buf,
                    dir_index,
                    ino.start_block,
                    ino.offset,
                    ino.file_size,
                    child_path,
                    depth + 1,
                    limits,
                    budget,
                    warnings,
                    out,
                )?;
            }
            return Ok(());
        }
        if is_file {
            meta.insert("type".to_string(), "file".to_string());
            meta.insert("declared_size".to_string(), ino.file_size.to_string());
            if ino.file_size == 0 {
                out.push(ChildDraft {
                    relation: RelationKind::FilesystemEntry,
                    label: format!("squashfs file {child_path} (0 bytes)"),
                    format_hint: "raw",
                    content: ChildContent::Owned(Vec::new()),
                    size: 0,
                    metadata: meta,
                    warnings: Vec::new(),
                    entry_name,
                });
                return Ok(());
            }
            if ino.file_size > limits.max_child_size {
                warnings.push(format!(
                    "file {child_path}: {} bytes exceed max_child_size; not exposed",
                    ino.file_size
                ));
                out.push(ChildDraft {
                    relation: RelationKind::FilesystemEntry,
                    label: format!("squashfs file {child_path} (metadata only)"),
                    format_hint: "metadata",
                    content: ChildContent::Owned(Vec::new()),
                    size: 0,
                    metadata: meta,
                    warnings: Vec::new(),
                    entry_name,
                });
                return Ok(());
            }
            let data = self.read_file_content(src, base, sb, ino, limits, budget, warnings)?;
            out.push(ChildDraft {
                relation: RelationKind::ReconstructedFrom,
                label: format!("squashfs file {child_path} ({} bytes)", data.len()),
                format_hint: "raw",
                content: ChildContent::Owned(data),
                size: ino.file_size,
                metadata: meta,
                warnings: vec!["content reconstructed from compressed squashfs blocks".to_string()],
                entry_name,
            });
            return Ok(());
        }
        if ino.inode_type == T_SYMLINK {
            meta.insert("type".to_string(), "symlink".to_string());
            out.push(ChildDraft {
                relation: RelationKind::FilesystemEntry,
                label: format!(
                    "squashfs symlink {child_path} -> {}",
                    String::from_utf8_lossy(&ino.symlink)
                ),
                format_hint: "metadata",
                content: ChildContent::Owned(ino.symlink.clone()),
                size: ino.symlink.len() as u64,
                metadata: meta,
                warnings: vec!["symlink target kept as metadata; never materialized".to_string()],
                entry_name,
            });
        }
        Ok(())
    }
}

struct SqfsSuper {
    block_size: u32,
    #[allow(dead_code)]
    block_log: u16,
    compression: u16,
    dict_size: u32,
    /// Absolute position of the data area (base + 96, or +100 with
    /// compressor options present).
    data_start: u64,
    inodes: u32,
    fragments: u32,
    bytes_used: u64,
    inode_table: u64,
    dir_table: u64,
    fragment_table: u64,
    /// Packed root inode ref (block << 16 | offset).
    root_inode: u64,
}

struct FragmentEntry {
    start_block: u64,
    size: u32,
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
struct SqfsInode {
    inode_type: u16,
    mode: u16,
    uid: u16,
    mtime: u32,
    ino_number: u32,
    /// Data/start block (block-relative offset).
    start_block: u32,
    file_size: u64,
    /// Dir: offset into metadata block. File: fragment offset.
    offset: u64,
    fragment: u32,
    frag_offset: u64,
    block_list: Vec<u32>,
    symlink: Vec<u8>,
    nlink: u64,
    parent: u32,
    indices: Vec<(u32, u32, String)>,
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
        limits: &crate::engine::EngineLimits,
        budget: &mut Budget,
    ) -> Result<HandlerOutput> {
        let base = candidate.offset;
        if base + 96 > src.len() {
            return Err(Error::Validation {
                format: "squashfs",
                reason: "superblock truncated".into(),
            });
        }
        let mut sb_raw = [0u8; 96];
        src.read_at(base, &mut sb_raw)?;
        let rd32 = |o: usize| u32::from_le_bytes(sb_raw[o..o + 4].try_into().unwrap());
        let rd16 = |o: usize| u16::from_le_bytes([sb_raw[o], sb_raw[o + 1]]);
        let inodes = rd32(4);
        let block_size = rd32(12);
        let fragments = rd32(16);
        let compression = rd16(20);
        let block_log = rd16(22);
        let _flags = rd16(24);
        let s_major = rd16(28);
        let bytes_used = u64::from_le_bytes(sb_raw[40..48].try_into().unwrap());
        let inode_table = u64::from_le_bytes(sb_raw[56..64].try_into().unwrap());
        let dir_table = u64::from_le_bytes(sb_raw[72..80].try_into().unwrap());
        let fragment_table = u64::from_le_bytes(sb_raw[80..88].try_into().unwrap());
        let root_inode = u64::from_le_bytes(sb_raw[32..40].try_into().unwrap());

        if s_major != 4 {
            return Err(Error::Validation {
                format: "squashfs",
                reason: format!("unsupported major version {s_major}"),
            });
        }
        if !(16..=22).contains(&block_log) {
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
            return Err(Error::Validation {
                format: "squashfs",
                reason: "inode table does not precede directory table".into(),
            });
        }

        // Compressor options: read the u32 dict_size for xz (raw LZMA2).
        let dict_size = if compression == 4 {
            le32(src, base + 96).unwrap_or(0)
        } else {
            0
        };

        // Compressor options live immediately after the superblock when
        // the compressor has them (xz: 8-byte little-endian dict size;
        // zstd: 4-byte; gzip: none). The data area starts after them.
        let data_start = match compression {
            4 => base + 96 + 8,
            6 | 7 => base + 96 + 4,
            _ => base + 96,
        };
        let sb = SqfsSuper {
            block_size,
            block_log,
            compression,
            dict_size,
            data_start,
            inodes,
            fragments,
            bytes_used,
            inode_table: base + inode_table,
            dir_table: base + dir_table,
            fragment_table,
            root_inode,
        };

        // Read metadata regions.
        let (inode_buf, inode_index) = Self::read_meta_region(
            src,
            base,
            sb.inode_table,
            sb.dir_table,
            compression,
            dict_size,
            limits,
        )?;
        let (dir_buf, dir_index) = Self::read_meta_region(
            src,
            base,
            sb.dir_table,
            base + bytes_used,
            compression,
            dict_size,
            limits,
        )?;

        // Parse root inode and walk.
        let root_block = (sb.root_inode >> 16) as u32;
        let root_offset = sb.root_inode & 0xFFFF;
        let root = self.parse_inode(
            &inode_buf,
            &inode_index,
            sb.inode_table + u64::from(root_block),
            root_offset,
            &sb,
        )?;
        if root.inode_type != T_DIR && root.inode_type != T_LDIR {
            return Err(Error::Validation {
                format: "squashfs",
                reason: format!("root inode type {} is not a directory", root.inode_type),
            });
        }

        let mut children = Vec::new();
        let mut warnings = Vec::new();
        self.walk_dir(
            src,
            base,
            &sb,
            &inode_buf,
            &inode_index,
            &dir_buf,
            &dir_index,
            root.start_block,
            root.offset,
            root.file_size,
            "",
            0,
            limits,
            budget,
            &mut warnings,
            &mut children,
        )?;

        let comp = Self::compressor_name(compression);
        let mut metadata = BTreeMap::new();
        metadata.insert("version".to_string(), format!("{s_major}.0"));
        metadata.insert("compressor".to_string(), comp.to_string());
        metadata.insert("inodes".to_string(), sb.inodes.to_string());
        metadata.insert("block_size".to_string(), sb.block_size.to_string());
        metadata.insert("bytes_used".to_string(), sb.bytes_used.to_string());
        metadata.insert("entries".to_string(), children.len().to_string());

        Ok(HandlerOutput {
            artifacts: vec![ArtifactDraft {
                format: "squashfs".to_string(),
                label: format!(
                    "SquashFS {s_major}.0 ({comp}, {inodes} inodes, {} entries)",
                    children.len()
                ),
                offset: base,
                size: bytes_used,
                confidence: Confidence::Validated,
                evidence: Evidence::facts([
                    "SquashFS superblock validated (magic, block log, bytes_used)".to_string(),
                    format!("compressor id {compression} ({comp})"),
                    format!(
                        "inode + directory tables decompressed ({} / {} bytes)",
                        inode_buf.len(),
                        dir_buf.len()
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

// ---------------------------------------------------------------------------
// ISO9660
// ---------------------------------------------------------------------------

pub struct Iso9660Handler;

/// `flags` bit 0x2 marks a directory (fs/isofs/isoinode.c: `de->flags & 2`).
const ISO_FLAG_DIR: u8 = 0x02;
/// `flags` bit 0x80 marks a multi-extent file: another directory record
/// holding the next section follows (isoinode.c: `more_entries =
/// de->flags & 0x80`).
const ISO_FLAG_MORE: u8 = 0x80;
/// ISO9660 optical sector size. Volume descriptors and directory
/// records never span a sector boundary: a zero record length means
/// "skip to the rest of this sector" (fs/isofs/isoinode.c
/// do_isofs_readdir).
const ISO_SECTOR: u64 = 2048;
/// The Primary Volume Descriptor occupies sector 16 of the image, so
/// the image origin sits 32 KiB before it.
const ISO_PVD_SECTOR: u64 = 16;
/// Cap on how much of one directory extent is walked before truncating.
const ISO_MAX_DIR_BYTES: u64 = 1024 * 1024;

/// Layout verified against Linux fs/isofs (isofs.h, isoinode.c):
/// - `struct iso_volume_descriptor`: type@0 (711), id@1..6 ("CD001"),
///   version@6. Descriptors live in consecutive 2048-byte sectors from
///   sector 16; the chain ends with a type-255 terminator.
/// - `struct iso_primary_descriptor`: volume_id@40..72,
///   volume_space_size@80..88 (733 both-endian), logical_block_size@
///   128..130 (723), root_directory_record@156..190 (a 34-byte record).
/// - `struct iso_supplementary_descriptor` (Joliet): escape@88..120.
///   Joliet = escape[0] 0x25, escape[1] 0x2F, escape[2] 0x40 (level 1),
///   0x43 (level 2) or 0x45 (level 3) (isoinode.c isofs_fill_super).
///   Joliet identifiers and the volume id are UCS-2 big-endian. When a
///   Joliet SVD is present the kernel switches the whole tree to the
///   SVD root (`pri = (struct iso_primary_descriptor *) sec`), which we
///   mirror.
/// - `struct iso_directory_record`: length@0, ext_attr_length@1,
///   extent@2..10 (733), size@10..18 (733), date@18..25, flags@25,
///   volume_sequence_number@28..32, name_len@32, name[]@33. First data
///   extent = 733(extent) + 711(ext_attr_length) (isoinode.c
///   isofs_iget). Names carry a ";version" suffix that is not part of
///   the identifier; single-byte names 0x00/0x01 are "." and "..".
///
/// Both-endian 733 field read little-endian (isofs isonum_733).
fn iso733(b: &[u8]) -> u64 {
    u32::from_le_bytes([b[0], b[1], b[2], b[3]]) as u64
}

/// Both-endian 723 field read little-endian (isofs isonum_723).
fn iso723(b: &[u8]) -> u64 {
    u16::from_le_bytes([b[0], b[1]]) as u64
}

/// Strip the ";1" version suffix and a trailing '.' from a level-1
/// identifier.
fn iso_name_ascii(raw: &[u8]) -> String {
    let s = String::from_utf8_lossy(raw);
    let base = s.split(';').next().unwrap_or("");
    base.strip_suffix('.').unwrap_or(base).to_string()
}

/// Joliet identifiers are UCS-2 big-endian, also with ";1" suffixes.
fn iso_name_utf16be(raw: &[u8]) -> String {
    let mut units = Vec::with_capacity(raw.len() / 2);
    for ch in raw.chunks_exact(2) {
        units.push(u16::from_be_bytes([ch[0], ch[1]]));
    }
    let s = String::from_utf16_lossy(&units);
    let base = s.split(';').next().unwrap_or("");
    base.strip_suffix('.').unwrap_or(base).to_string()
}

fn iso_volume_id_ascii(raw: &[u8]) -> String {
    String::from_utf8_lossy(raw)
        .trim_end_matches([' ', '\0'])
        .to_string()
}

fn iso_volume_id_utf16be(raw: &[u8]) -> String {
    let mut units = Vec::with_capacity(raw.len() / 2);
    for ch in raw.chunks_exact(2) {
        units.push(u16::from_be_bytes([ch[0], ch[1]]));
    }
    String::from_utf16_lossy(&units)
        .trim_end_matches([' ', '\0'])
        .to_string()
}

/// The tree-relevant fields of a PVD or Joliet SVD.
struct IsoDescriptor {
    root_extent: u64,
    root_size: u64,
    volume_id: String,
    logical_block: u64,
    volume_space: u64,
}

fn parse_volume_descriptor(d: &[u8]) -> Option<IsoDescriptor> {
    if &d[1..6] != b"CD001" {
        return None;
    }
    let (volume_id, _joliet) = match d[0] {
        1 => (iso_volume_id_ascii(&d[40..72]), false),
        2 => (iso_volume_id_utf16be(&d[40..72]), true),
        _ => return None,
    };
    let root = &d[156..156 + 34];
    Some(IsoDescriptor {
        root_extent: iso733(&root[2..6]) + u64::from(root[1]),
        root_size: iso733(&root[10..14]),
        volume_id,
        logical_block: iso723(&d[128..132]),
        volume_space: iso733(&d[80..88]),
    })
}

/// One directory record as read from disk.
struct IsoDirEntry {
    extent: u64,
    size: u64,
    flags: u8,
    name: String,
}

impl Iso9660Handler {
    /// Parse one directory record at `off` in `buf`. Returns None when
    /// the record is truncated.
    fn parse_dir_entry(buf: &[u8], off: usize, joliet: bool) -> Option<(IsoDirEntry, usize)> {
        let len = usize::from(*buf.get(off)?);
        if len < 34 || off + len > buf.len() {
            return None;
        }
        let r = &buf[off..off + len];
        let name_len = usize::from(r[32]);
        if 33 + name_len > len {
            return None;
        }
        let raw_name = &r[33..33 + name_len];
        let name = if name_len == 1 && raw_name[0] == 0 {
            ".".to_string()
        } else if name_len == 1 && raw_name[0] == 1 {
            "..".to_string()
        } else if joliet {
            iso_name_utf16be(raw_name)
        } else {
            iso_name_ascii(raw_name)
        };
        Some((
            IsoDirEntry {
                extent: iso733(&r[2..6]) + u64::from(r[1]),
                size: iso733(&r[10..14]),
                flags: r[25],
                name,
            },
            len,
        ))
    }

    /// Walk one directory extent and emit children, recursing into
    /// subdirectories. Extents are absolute LBAs from the image start
    /// (`image_base` = candidate PVD sector − 32 KiB). Multi-extent
    /// records (flag 0x80) chain extra directory records whose sizes
    /// are summed with honest provenance.
    #[allow(clippy::too_many_arguments)]
    fn walk_dir(
        &self,
        src: &ByteSource,
        image_base: u64,
        lba_size: u64,
        extent: u64,
        size: u64,
        path: &str,
        joliet: bool,
        depth: u32,
        limits: &crate::engine::EngineLimits,
        warnings: &mut Vec<String>,
        out: &mut Vec<ChildDraft>,
    ) -> Result<()> {
        if depth > 16 {
            warnings.push("directory nesting deeper than 16 not walked".to_string());
            return Ok(());
        }
        let walk_bytes = size.min(ISO_MAX_DIR_BYTES).min(limits.max_child_size);
        let dir_abs = image_base + extent * lba_size;
        if dir_abs + walk_bytes > src.len() {
            warnings.push(format!(
                "directory extent {extent} extends past source; truncated"
            ));
            return Ok(());
        }
        let mut buf = vec![0u8; walk_bytes as usize];
        src.read_at(dir_abs, &mut buf)?;

        let mut off = 0usize;
        let mut visited: Vec<(u64, u64)> = Vec::new();
        while off < buf.len() {
            if out.len() >= limits.max_fs_entries {
                warnings.push("max_fs_entries reached; walk truncated".to_string());
                return Ok(());
            }
            // Records never span a sector; length 0 skips the rest of
            // the current sector.
            if buf[off] == 0 {
                let next = ((off as u64 / ISO_SECTOR) + 1) * ISO_SECTOR;
                if next as usize >= buf.len() {
                    break;
                }
                off = next as usize;
                continue;
            }
            let Some((de, len)) = Self::parse_dir_entry(&buf, off, joliet) else {
                warnings.push(format!(
                    "truncated directory record at extent offset {off}; walk stopped"
                ));
                return Ok(());
            };
            off += len;
            if de.name == "." || de.name == ".." {
                continue;
            }
            let child_path = if path.is_empty() {
                de.name.clone()
            } else {
                format!("{path}/{}", de.name)
            };
            let is_dir = de.flags & ISO_FLAG_DIR != 0;
            let mut meta = BTreeMap::new();
            meta.insert("path".to_string(), child_path.clone());
            meta.insert("extent_lba".to_string(), de.extent.to_string());
            if de.flags & ISO_FLAG_MORE != 0 {
                meta.insert("multi_extent".to_string(), "true".to_string());
            }
            let entry_name = Some(de.name.clone());
            if is_dir {
                // Loop guard: repeated directory extents are cyclic.
                if visited.contains(&(de.extent, de.size)) {
                    warnings.push(format!(
                        "directory {child_path} repeats an already-visited extent; skipped"
                    ));
                    continue;
                }
                visited.push((de.extent, de.size));
                meta.insert("type".to_string(), "directory".to_string());
                out.push(ChildDraft {
                    relation: RelationKind::FilesystemEntry,
                    label: format!("iso9660 directory {child_path}"),
                    format_hint: "metadata",
                    content: ChildContent::Owned(Vec::new()),
                    size: 0,
                    metadata: meta,
                    warnings: Vec::new(),
                    entry_name,
                });
                self.walk_dir(
                    src,
                    image_base,
                    lba_size,
                    de.extent,
                    de.size,
                    &child_path,
                    joliet,
                    depth + 1,
                    limits,
                    warnings,
                    out,
                )?;
                continue;
            }
            meta.insert("type".to_string(), "file".to_string());
            meta.insert("declared_size".to_string(), de.size.to_string());
            // Multi-extent (flag 0x80): the following records hold the
            // further sections; sum their sizes.
            let (total_size, sections) = if de.flags & ISO_FLAG_MORE != 0 {
                let mut total = de.size;
                let mut sections = 1u32;
                let mut scan = off;
                while sections <= 32 {
                    let Some((next, next_len)) = Self::parse_dir_entry(&buf, scan, joliet) else {
                        break;
                    };
                    scan += next_len;
                    total += next.size;
                    sections += 1;
                    if next.flags & ISO_FLAG_MORE == 0 {
                        break;
                    }
                }
                off = scan;
                (total, sections)
            } else {
                (de.size, 1)
            };
            if sections > 1 {
                meta.insert("sections".to_string(), sections.to_string());
            }
            let content = self.file_content(
                src, image_base, lba_size, de.extent, total_size, limits, warnings,
            );
            out.push(ChildDraft {
                relation: if sections > 1 {
                    RelationKind::ReconstructedFrom
                } else {
                    RelationKind::FilesystemEntry
                },
                label: format!(
                    "iso9660 file {child_path} ({} bytes{})",
                    content_size(&content),
                    if sections > 1 {
                        format!(", {sections} extents")
                    } else {
                        String::new()
                    }
                ),
                format_hint: "raw",
                content,
                size: total_size,
                metadata: meta,
                warnings: if sections > 1 {
                    vec![
                        "multi-extent file reconstructed from chained directory records"
                            .to_string(),
                    ]
                } else {
                    Vec::new()
                },
                entry_name,
            });
        }
        Ok(())
    }

    /// File content as a source-backed region when contiguous and in
    /// bounds; Owned empty with a warning otherwise. File extents are
    /// contiguous by construction in ISO9660.
    #[allow(clippy::too_many_arguments)]
    fn file_content(
        &self,
        src: &ByteSource,
        image_base: u64,
        lba_size: u64,
        extent: u64,
        size: u64,
        limits: &crate::engine::EngineLimits,
        warnings: &mut Vec<String>,
    ) -> ChildContent {
        if size == 0 {
            return ChildContent::Owned(Vec::new());
        }
        let start = image_base + extent * lba_size;
        if start + size > src.len() {
            warnings.push(format!(
                "file at LBA {extent} ({size} bytes) extends past source; not exposed"
            ));
            return ChildContent::Owned(Vec::new());
        }
        if size > limits.max_child_size {
            warnings.push(format!(
                "file at LBA {extent} ({size} bytes) exceeds max_child_size; not exposed"
            ));
            return ChildContent::Owned(Vec::new());
        }
        match src.slice(start, size) {
            Ok(r) => ChildContent::Source(r),
            Err(_) => ChildContent::Owned(Vec::new()),
        }
    }
}

fn content_size(c: &ChildContent) -> u64 {
    match c {
        ChildContent::Source(r) => r.len(),
        ChildContent::Owned(v) => v.len() as u64,
    }
}

impl Handler for Iso9660Handler {
    fn format(&self) -> &'static str {
        "iso9660"
    }

    fn find_candidates(&self, src: &ByteSource) -> Vec<Candidate> {
        // Volume descriptors sit in 2048-byte sectors starting at
        // sector 16; "CD001" is at descriptor offset 1. Embedded images
        // appear at multiples of 2048 inside larger artifacts.
        let data = match src.read_prefix(64 * 1024 * 1024) {
            Ok(d) => d,
            Err(_) => return Vec::new(),
        };
        let mut hits = Vec::new();
        let mut i = 1usize;
        while i + 5 <= data.len() {
            if &data[i..i + 5] == b"CD001" {
                hits.push(Candidate {
                    offset: i as u64 - 1,
                });
                i += 2048;
            } else {
                i += 1;
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
        if base % ISO_SECTOR != 0 {
            return Err(Error::Validation {
                format: "iso9660",
                reason: "volume descriptor not sector aligned".into(),
            });
        }
        if base + ISO_SECTOR > src.len() {
            return Err(Error::Validation {
                format: "iso9660",
                reason: "volume descriptor truncated".into(),
            });
        }
        // Walk the descriptor chain: PVD (type 1) is mandatory; a
        // Joliet SVD (type 2 with %/@, %/C or %/E escape) overrides the
        // tree; type 255 ends the chain. The candidate may be any
        // descriptor in the chain, so scan backward too for the PVD.
        let max_descriptors = 64i64;
        let start_sector = (base / ISO_SECTOR) as i64;
        let mut pvd: Option<IsoDescriptor> = None;
        let mut svd: Option<IsoDescriptor> = None;
        let mut terminated = false;
        let mut first_sector: i64 = -1;
        let mut d = [0u8; 2048];
        for step in 0..max_descriptors {
            let sector = start_sector + step;
            let off = sector as u64 * ISO_SECTOR;
            if off + ISO_SECTOR > src.len() {
                break;
            }
            src.read_at(off, &mut d)?;
            if &d[1..6] != b"CD001" {
                break; // end of descriptor chain
            }
            if first_sector < 0 {
                first_sector = sector;
            }
            match d[0] {
                1 => {
                    if pvd.is_none() {
                        pvd = parse_volume_descriptor(&d);
                    }
                }
                2 => {
                    // Joliet SVD escape sequence (isoinode.c).
                    if d[88] == 0x25
                        && d[89] == 0x2F
                        && matches!(d[90], 0x40 | 0x43 | 0x45)
                        && svd.is_none()
                    {
                        svd = parse_volume_descriptor(&d);
                    }
                }
                255 => {
                    terminated = true;
                    break;
                }
                _ => {}
            }
        }
        if terminated && first_sector < 0 {
            return Err(Error::Validation {
                format: "iso9660",
                reason: "terminator without any volume descriptor".into(),
            });
        }
        let Some(pvd) = pvd else {
            return Err(Error::Validation {
                format: "iso9660",
                reason: "no Primary Volume Descriptor in chain".into(),
            });
        };
        // The PVD anchors the image origin: sector 16 of the volume.
        let image_base =
            (first_sector.max(ISO_PVD_SECTOR as i64) as u64 - ISO_PVD_SECTOR) * ISO_SECTOR;
        // Kernel semantics: Joliet tree wins when present (isoinode.c
        // switches `pri` to the supplementary descriptor).
        let (tree, joliet) = match &svd {
            Some(s) => (s, true),
            None => (&pvd, false),
        };
        let logical_block = tree.logical_block;
        if !(512..=32768).contains(&logical_block) || !logical_block.is_power_of_two() {
            return Err(Error::Validation {
                format: "iso9660",
                reason: format!("implausible logical block size {logical_block}"),
            });
        }

        let mut children = Vec::new();
        let mut warnings = Vec::new();
        if tree.root_size > 0 {
            self.walk_dir(
                src,
                image_base,
                logical_block,
                tree.root_extent,
                tree.root_size,
                "",
                joliet,
                0,
                limits,
                &mut warnings,
                &mut children,
            )?;
        } else {
            warnings.push("root directory record has zero size".to_string());
        }

        let mut metadata = BTreeMap::new();
        metadata.insert("volume_id".to_string(), pvd.volume_id.clone());
        if let Some(s) = &svd {
            metadata.insert("joliet_volume_id".to_string(), s.volume_id.clone());
        }
        metadata.insert("logical_block_size".to_string(), logical_block.to_string());
        metadata.insert("joliet".to_string(), joliet.to_string());
        metadata.insert("entries".to_string(), children.len().to_string());

        let total_bytes = tree.volume_space * logical_block;
        Ok(HandlerOutput {
            artifacts: vec![ArtifactDraft {
                format: "iso9660".to_string(),
                label: format!(
                    "ISO9660 image \"{}\"{} ({} entries)",
                    tree.volume_id,
                    if joliet { " [Joliet]" } else { "" },
                    children.len()
                ),
                offset: base,
                size: total_bytes.max(ISO_SECTOR).min(src.len() - base),
                confidence: if children.is_empty() {
                    Confidence::Partial
                } else {
                    Confidence::Validated
                },
                evidence: Evidence::facts([
                    "Primary Volume Descriptor validated (type 1, CD001)".to_string(),
                    if joliet {
                        "Joliet SVD present; using UCS-2 tree".to_string()
                    } else {
                        "no Joliet SVD; using level-1 ASCII tree".to_string()
                    },
                    format!("logical block size {logical_block}"),
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

// ---------------------------------------------------------------------------
// JFFS2
// ---------------------------------------------------------------------------

pub struct Jffs2Handler;

const JFFS2_MAGIC: u16 = 0x1985;
const JFFS2_NODETYPE_DIRENT: u16 = 0xc001; // INCOMPAT|1 (ACCURATE masked off)
const JFFS2_NODETYPE_INODE: u16 = 0xc002; // INCOMPAT|2 (ACCURATE masked off)
const JFFS2_NODE_ACCURATE: u16 = 0x2000;
const JFFS2_COMPAT_MASK: u16 = 0xc000;
const JFFS2_DIRENT_SIZE: usize = 40;
const JFFS2_INODE_SIZE: usize = 68;
const JFFS2_COMPR_NONE: u8 = 0x00;
const JFFS2_COMPR_ZERO: u8 = 0x01;
const JFFS2_COMPR_RTIME: u8 = 0x02;
const JFFS2_COMPR_ZLIB: u8 = 0x06;
const JFFS2_COMPR_LZO: u8 = 0x07;
/// DT_* dirent type values (fs/jffs2/dir.c writes these).
const DT_FIFO: u8 = 1;
const DT_CHR: u8 = 2;
const DT_DIR: u8 = 4;
const DT_BLK: u8 = 6;
const DT_REG: u8 = 8;
const DT_LNK: u8 = 10;
const DT_SOCK: u8 = 12;
/// Root directory inode number (convention: jffs2_mkdir uses ino 1 for
/// the root because it is the first allocated inode).
const JFFS2_ROOT_INO: u32 = 1;
/// Skip runs of erased flash rather than probing every 4 bytes.
const MAX_FF_RUN_SKIP: usize = 64 * 1024;

/// Layout verified against Linux fs/jffs2 (jffs2.h, scan.c, read.c,
/// compr.c, compr_rtime.c, compr_zlib.c):
/// - Every node starts with `struct jffs2_unknown_node`:
///   magic@0 (0x1985 big-endian), nodetype@2 (big-endian; INCOMPAT
///   0xc000 | ACCURATE 0x2000 | id), totlen@4 (be32), hdr_crc@8 (be32).
/// - hdr_crc = crc32 over the first 8 bytes with the ACCURATE bit
///   forced into nodetype (scan.c crcnode logic).
/// - `struct jffs2_raw_dirent` (40 bytes header): pino@12, version@16,
///   ino@20 (0 = unlink), mctime@24, nsize@28, type@29 (DT_*),
///   unused[2], node_crc@32 (crc32 over sizeof-8 = 32 header bytes),
///   name_crc@36 (crc32 over name bytes), name[]@40. Names may be
///   NUL-terminated; kernel truncates at the first NUL.
/// - `struct jffs2_raw_inode` (68 bytes header): ino@12, version@16,
///   mode@20, uid@24, gid@26, isize@28, atime@32, mtime@36, ctime@40,
///   offset@44, csize@48 (compressed bytes stored), dsize@52
///   (decompressed size), compr@56, usercompr@57, flags@58, data_crc@60
///   (crc32 over the csize compressed bytes), node_crc@64 (crc32 over
///   68-8 = 60 header bytes), data[]@68.
/// - Node data is at arbitrary 4-byte-aligned positions across erase
///   blocks; scan order + per-ino highest version wins. Unlinked names
///   (ino == 0) remove the previous dirent.
/// - Compression: NONE copies csize bytes (dsize == csize), ZERO is
///   dsize zero bytes, RTIME is the byte+run-of-backrefs scheme in
///   compr_rtime.c, ZLIB is deflate (kernel skips a standard 2-byte
///   zlib header and inflates raw when possible). LZO/RUBIN/COPY are
///   not supported here and produce honest metadata-only entries.
///
/// Parent inode -> children (ino, name, DT_* type).
type Jffs2Tree = BTreeMap<u32, Vec<(u32, Vec<u8>, u8)>>;

/// Name -> (version, target ino, DT_* type) per parent during resolve.
type Jffs2NameMap = BTreeMap<u32, BTreeMap<Vec<u8>, (u32, u32, u8)>>;

/// A scanned dirent node.
struct Jffs2Dirent {
    version: u32,
    pino: u32,
    ino: u32,
    dtype: u8,
    name: Vec<u8>,
    valid_crc: bool,
}

/// A scanned inode node holding one data fragment.
struct Jffs2Frag {
    ino: u32,
    version: u32,
    offset: u32,
    isize: u32,
    csize: u32,
    dsize: u32,
    compr: u8,
    data_abs: u64,
    data_crc: u32,
    valid: bool,
}

/// Compute the hdr_crc the way scan.c does: ACCURATE forced on.
fn jffs2_hdr_crc(bytes: &[u8]) -> u32 {
    let mut node = [
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
    ];
    let nt = u16::from_be_bytes([bytes[2], bytes[3]]) | JFFS2_NODE_ACCURATE;
    node[2..4].copy_from_slice(&nt.to_be_bytes());
    crc32fast::hash(&node)
}

impl Jffs2Handler {
    /// RTIME decompression (compr_rtime.c jffs2_rtime_decompress).
    fn rtime_decompress(input: &[u8], destlen: usize) -> Option<Vec<u8>> {
        let mut out = vec![0u8; destlen];
        let mut positions = [0u16; 256];
        let (mut outpos, mut pos) = (0usize, 0usize);
        while outpos < destlen {
            if pos + 2 > input.len() {
                return None;
            }
            let value = input[pos];
            pos += 1;
            let repeat = usize::from(input[pos]);
            pos += 1;
            let mut backoffs = positions[value as usize] as usize;
            positions[value as usize] = (outpos + 1) as u16;
            out[outpos] = value;
            outpos += 1;
            if repeat > 0 {
                if outpos + repeat > destlen {
                    return None;
                }
                if backoffs + repeat >= outpos {
                    for _ in 0..repeat {
                        if backoffs >= outpos {
                            return None;
                        }
                        out[outpos] = out[backoffs];
                        outpos += 1;
                        backoffs += 1;
                    }
                } else {
                    out.copy_within(backoffs..backoffs + repeat, outpos);
                    outpos += repeat;
                }
            }
        }
        Some(out)
    }

    /// JFFS2 zlib: standard zlib stream, or raw deflate after skipping
    /// the 2-byte header when there is no preset dict (compr_zlib.c).
    fn zlib_decompress(input: &[u8], destlen: usize) -> Result<Vec<u8>> {
        let skip_header = input.len() > 2
            && input[1] & 0x20 == 0
            && (input[0] & 0x0f) == 8
            && (u16::from(input[0]) << 8 | u16::from(input[1])) % 31 == 0;
        let out = if skip_header {
            let mut dec = flate2::read::DeflateDecoder::new(&input[2..]);
            let mut out = Vec::with_capacity(destlen);
            std::io::Read::read_to_end(&mut dec, &mut out).map_err(|_| Error::Validation {
                format: "jffs2",
                reason: "zlib raw inflate failed".into(),
            })?;
            out
        } else {
            let mut dec = flate2::read::ZlibDecoder::new(input);
            let mut out = Vec::with_capacity(destlen);
            std::io::Read::read_to_end(&mut dec, &mut out).map_err(|_| Error::Validation {
                format: "jffs2",
                reason: "zlib inflate failed".into(),
            })?;
            out
        };
        Ok(out)
    }

    /// Decompress one inode fragment by compr code. Unsupported codes
    /// return Ok(None) so callers emit metadata-only entries.
    fn decompress_fragment(compr: u8, data: &[u8], dsize: usize) -> Result<Option<Vec<u8>>> {
        match compr {
            JFFS2_COMPR_NONE => Ok(Some(data.to_vec())),
            JFFS2_COMPR_ZERO => Ok(Some(vec![0u8; dsize])),
            JFFS2_COMPR_RTIME => Ok(Self::rtime_decompress(data, dsize)),
            JFFS2_COMPR_ZLIB => Ok(Some(Self::zlib_decompress(data, dsize)?)),
            JFFS2_COMPR_LZO => Ok(None), // lzo crate not bundled
            other => Err(Error::Validation {
                format: "jffs2",
                reason: format!("unsupported compression code {other}"),
            }),
        }
    }

    /// Scan all nodes in the source: dirents and inode fragments with
    /// CRC validity. Bounded scan; skip 0xFF runs like the kernel's
    /// empty-region fast path.
    fn scan_nodes(
        src: &ByteSource,
        base: u64,
        limits: &crate::engine::EngineLimits,
        warnings: &mut Vec<String>,
    ) -> Result<(Vec<Jffs2Dirent>, Vec<Jffs2Frag>, u64)> {
        let mut dirents = Vec::new();
        let mut frags = Vec::new();
        let mut hdr = [0u8; 8];
        let mut ff_run = 0usize;
        let mut pos = base;
        let mut nodes = 0usize;
        let end = src.len();
        let mut last_node_end = base;
        while pos + 8 <= end {
            src.read_at(pos, &mut hdr)?;
            if hdr[0] == 0xFF && hdr[1] == 0xFF {
                // Erased region: run ahead.
                ff_run += 1;
                pos += 1;
                if ff_run > MAX_FF_RUN_SKIP {
                    pos = end;
                }
                continue;
            }
            ff_run = 0;
            let magic = u16::from_be_bytes([hdr[0], hdr[1]]);
            if magic != JFFS2_MAGIC {
                pos += 1;
                continue;
            }
            let nodetype_raw = u16::from_be_bytes([hdr[2], hdr[3]]);
            let totlen = u32::from_be_bytes([hdr[4], hdr[5], hdr[6], hdr[7]]) as usize;
            if totlen < 8 || pos + totlen as u64 > end {
                pos += 1;
                continue;
            }
            if nodetype_raw & JFFS2_COMPAT_MASK != 0xc000 {
                // ROCOMPAT/RWCOMPAT: skip, do not claim.
                pos += totlen as u64;
                continue;
            }
            let hdr_crc = jffs2_hdr_crc(&hdr);
            let stored_crc = {
                let mut b = [0u8; 4];
                src.read_at(pos + 8, &mut b)?;
                u32::from_be_bytes(b)
            };
            let hdr_ok = hdr_crc == stored_crc;
            nodes += 1;
            if nodes > limits.max_records {
                warnings.push("jffs2 node count exceeded max_records; scan truncated".to_string());
                break;
            }
            match nodetype_raw & !JFFS2_NODE_ACCURATE {
                JFFS2_NODETYPE_DIRENT if hdr_ok && totlen > JFFS2_DIRENT_SIZE => {
                    let mut h = [0u8; JFFS2_DIRENT_SIZE];
                    src.read_at(pos, &mut h)?;
                    let be32 = |o: usize| u32::from_be_bytes([h[o], h[o + 1], h[o + 2], h[o + 3]]);
                    let nsize = h[28] as usize;
                    let name_abs = pos + JFFS2_DIRENT_SIZE as u64;
                    let mut name = vec![0u8; nsize.min(totlen - JFFS2_DIRENT_SIZE)];
                    src.read_at(name_abs, &mut name)?;
                    // Kernel truncates names at the first NUL.
                    let name_len = name.iter().position(|&b| b == 0).unwrap_or(name.len());
                    name.truncate(name_len);
                    let node_crc = be32(32);
                    let name_crc = be32(36);
                    let calc_node = crc32fast::hash(&h[..32]);
                    let calc_name = crc32fast::hash(&name);
                    dirents.push(Jffs2Dirent {
                        version: be32(16),
                        pino: be32(12),
                        ino: be32(20),
                        dtype: h[29],
                        name,
                        valid_crc: calc_node == node_crc && calc_name == name_crc,
                    });
                }
                JFFS2_NODETYPE_INODE if hdr_ok && totlen > JFFS2_INODE_SIZE => {
                    let mut h = [0u8; JFFS2_INODE_SIZE];
                    src.read_at(pos, &mut h)?;
                    let be32 = |o: usize| u32::from_be_bytes([h[o], h[o + 1], h[o + 2], h[o + 3]]);
                    let csize = be32(48);
                    if csize as u64 + JFFS2_INODE_SIZE as u64 <= totlen as u64 {
                        frags.push(Jffs2Frag {
                            ino: be32(12),
                            version: be32(16),
                            offset: be32(44),
                            isize: be32(28),
                            csize,
                            dsize: be32(52),
                            compr: h[56],
                            data_abs: pos + JFFS2_INODE_SIZE as u64,
                            data_crc: be32(60),
                            valid: crc32fast::hash(&h[..60]) == be32(64),
                        });
                    }
                }
                _ => {}
            }
            pos += totlen as u64;
            last_node_end = pos;
        }
        Ok((dirents, frags, last_node_end - base))
    }
}

impl Jffs2Handler {
    /// Resolve directory contents: per parent inode, the dirent with
    /// the highest version per name wins; ino == 0 removes the name
    /// (unlink).
    fn resolve_tree(dirents: &[Jffs2Dirent]) -> BTreeMap<u32, Vec<(u32, Vec<u8>, u8)>> {
        let mut by_parent: Jffs2NameMap = BTreeMap::new();
        for d in dirents {
            if !d.valid_crc {
                continue;
            }
            let entry = by_parent.entry(d.pino).or_default().entry(d.name.clone());
            match entry {
                std::collections::btree_map::Entry::Vacant(v) => {
                    v.insert((d.version, d.ino, d.dtype));
                }
                std::collections::btree_map::Entry::Occupied(mut o) => {
                    if d.version > o.get().0 {
                        o.insert((d.version, d.ino, d.dtype));
                    }
                }
            }
        }
        by_parent
            .into_iter()
            .map(|(pino, names)| {
                (
                    pino,
                    names
                        .into_iter()
                        .filter_map(|(name, (ver, ino, dtype))| {
                            if ino == 0 {
                                None // unlink
                            } else {
                                let _ = ver;
                                Some((ino, name, dtype))
                            }
                        })
                        .collect(),
                )
            })
            .collect()
    }

    /// Assemble one file's content from its fragments: highest version
    /// per offset wins (log semantics), holes zero-fill up to isize.
    fn assemble_file(
        &self,
        src: &ByteSource,
        frags: &[Jffs2Frag],
        ino: u32,
        limits: &crate::engine::EngineLimits,
        budget: &mut Budget,
        warnings: &mut Vec<String>,
    ) -> Result<Option<Vec<u8>>> {
        let mine: Vec<&Jffs2Frag> = frags.iter().filter(|f| f.ino == ino && f.valid).collect();
        let isize = match mine.iter().map(|f| f.isize).max() {
            Some(s) => s as u64,
            None => return Ok(None),
        };
        let isize = isize.min(limits.max_child_size);
        let mut out = vec![0u8; isize as usize];
        // Highest version per offset.
        let mut best: BTreeMap<u32, &Jffs2Frag> = BTreeMap::new();
        for f in mine {
            match best.get(&f.offset) {
                Some(cur) if cur.version >= f.version => {}
                _ => {
                    best.insert(f.offset, f);
                }
            }
        }
        for f in best.values() {
            let start = f.offset as u64;
            if start >= isize {
                continue;
            }
            let take = (f.dsize as u64).min(isize - start) as usize;
            let mut raw = vec![0u8; f.csize as usize];
            if f.data_abs + f.csize as u64 > src.len() {
                warnings.push(format!(
                    "inode {ino}: fragment data at {} out of bounds; skipped",
                    f.data_abs
                ));
                continue;
            }
            src.read_at(f.data_abs, &mut raw)?;
            if crc32fast::hash(&raw) != f.data_crc {
                warnings.push(format!("inode {ino}: fragment data CRC mismatch; skipped"));
                continue;
            }
            let decoded = match Self::decompress_fragment(f.compr, &raw, f.dsize as usize)? {
                Some(d) => d,
                None => {
                    warnings.push(format!(
                        "inode {ino}: unsupported compression {}; fragment kept as metadata",
                        f.compr
                    ));
                    continue;
                }
            };
            if !budget.charge(limits, decoded.len() as u64) {
                return Err(Error::LimitExceeded {
                    limit: "max-total-expanded-bytes",
                    detail: "jffs2 fragment".into(),
                });
            }
            let n = decoded.len().min(take);
            out[start as usize..start as usize + n].copy_from_slice(&decoded[..n]);
        }
        Ok(Some(out))
    }
}

impl Handler for Jffs2Handler {
    fn format(&self) -> &'static str {
        "jffs2"
    }

    fn find_candidates(&self, src: &ByteSource) -> Vec<Candidate> {
        // Magic 0x1985 stored big-endian.
        find_all(src, &[0x19, 0x85])
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
        let mut warnings = Vec::new();
        let (dirents, frags, used) = Self::scan_nodes(src, base, limits, &mut warnings)?;
        if dirents.is_empty() && frags.is_empty() {
            return Err(Error::Validation {
                format: "jffs2",
                reason: "no valid JFFS2 nodes".into(),
            });
        }

        let tree = Self::resolve_tree(&dirents);
        let mut children = Vec::new();
        // Find the root: the inode never referenced as a child, or the
        // conventional ino 1. Depth-first from there.
        let mut referenced: std::collections::HashSet<u32> = std::collections::HashSet::new();
        for d in dirents.iter().filter(|d| d.valid_crc && d.ino != 0) {
            referenced.insert(d.ino);
        }
        let roots: Vec<u32> =
            if referenced.contains(&JFFS2_ROOT_INO) || tree.contains_key(&JFFS2_ROOT_INO) {
                vec![JFFS2_ROOT_INO]
            } else {
                tree.keys()
                    .filter(|p| !referenced.contains(p))
                    .copied()
                    .collect()
            };
        if roots.len() > 1 {
            warnings.push(format!(
                "multiple unreferenced parent inodes ({roots:?}); walking the first"
            ));
        }
        let mut visited_dirs = std::collections::HashSet::new();
        for root in roots.iter().take(1) {
            self.emit_dir(
                src,
                *root,
                "",
                &tree,
                &frags,
                0,
                limits,
                budget,
                &mut visited_dirs,
                &mut warnings,
                &mut children,
            )?;
        }

        let files = children
            .iter()
            .filter(|c| c.metadata.get("type").map(String::as_str) == Some("file"))
            .count();
        let mut metadata = BTreeMap::new();
        metadata.insert(
            "nodes".to_string(),
            (dirents.len() + frags.len()).to_string(),
        );
        metadata.insert("dirents".to_string(), dirents.len().to_string());
        metadata.insert("inode_fragments".to_string(), frags.len().to_string());
        metadata.insert("inodes".to_string(), tree.len().to_string());
        metadata.insert("entries".to_string(), children.len().to_string());

        Ok(HandlerOutput {
            artifacts: vec![ArtifactDraft {
                format: "jffs2".to_string(),
                label: format!(
                    "JFFS2 filesystem ({} nodes, {} entries)",
                    dirents.len() + frags.len(),
                    children.len()
                ),
                offset: base,
                size: used.max(8),
                confidence: if children.is_empty() {
                    Confidence::Partial
                } else {
                    Confidence::Validated
                },
                evidence: Evidence::facts([
                    "JFFS2 node chain validated (magic 0x1985, header CRCs)".to_string(),
                    format!(
                        "{} dirent nodes, {} inode fragments (CRC-checked)",
                        dirents.len(),
                        frags.len()
                    ),
                    format!("directory tree resolved: {} entries", children.len()),
                    format!("{} files reconstructed from fragments", files),
                ]),
                metadata,
                warnings,
                errors: Vec::new(),
                children,
            }],
        })
    }
}

impl Jffs2Handler {
    /// Depth-first emission of one directory's children.
    #[allow(clippy::too_many_arguments)]
    #[allow(clippy::too_many_arguments)]
    fn emit_dir(
        &self,
        src: &ByteSource,
        pino: u32,
        path: &str,
        tree: &Jffs2Tree,
        frags: &[Jffs2Frag],
        depth: u32,
        limits: &crate::engine::EngineLimits,
        budget: &mut Budget,
        visited: &mut std::collections::HashSet<u32>,
        warnings: &mut Vec<String>,
        out: &mut Vec<ChildDraft>,
    ) -> Result<()> {
        if depth > 16 {
            warnings.push("jffs2 directory nesting deeper than 16 not walked".to_string());
            return Ok(());
        }
        if !visited.insert(pino) {
            warnings.push("jffs2 directory cycle detected; subtree skipped".to_string());
            return Ok(());
        }
        let Some(entries) = tree.get(&pino) else {
            return Ok(());
        };
        for (ino, name, dtype) in entries {
            if out.len() >= limits.max_fs_entries {
                warnings.push("max_fs_entries reached; walk truncated".to_string());
                return Ok(());
            }
            let name = String::from_utf8_lossy(name).into_owned();
            let child_path = if path.is_empty() {
                name.clone()
            } else {
                format!("{path}/{name}")
            };
            let mut meta = BTreeMap::new();
            meta.insert("path".to_string(), child_path.clone());
            meta.insert("inode".to_string(), ino.to_string());
            let entry_name = Some(name);
            let _is_dir = *dtype == DT_DIR;
            match *dtype {
                DT_DIR => {
                    meta.insert("type".to_string(), "directory".to_string());
                    out.push(ChildDraft {
                        relation: RelationKind::FilesystemEntry,
                        label: format!("jffs2 directory {child_path}"),
                        format_hint: "metadata",
                        content: ChildContent::Owned(Vec::new()),
                        size: 0,
                        metadata: meta,
                        warnings: Vec::new(),
                        entry_name,
                    });
                    self.emit_dir(
                        src,
                        *ino,
                        &child_path,
                        tree,
                        frags,
                        depth + 1,
                        limits,
                        budget,
                        visited,
                        warnings,
                        out,
                    )?;
                }
                DT_REG | 0 => {
                    meta.insert("type".to_string(), "file".to_string());
                    match self.assemble_file(src, frags, *ino, limits, budget, warnings)? {
                        Some(data) => {
                            let size = data.len() as u64;
                            meta.insert(
                                "declared_size".to_string(),
                                frags
                                    .iter()
                                    .filter(|f| f.ino == *ino)
                                    .map(|f| f.isize)
                                    .max()
                                    .unwrap_or(0)
                                    .to_string(),
                            );
                            out.push(ChildDraft {
                                relation: RelationKind::ReconstructedFrom,
                                label: format!("jffs2 file {child_path} ({size} bytes)"),
                                format_hint: "raw",
                                content: ChildContent::Owned(data),
                                size,
                                metadata: meta,
                                warnings: vec![
                                    "content reconstructed from JFFS2 log fragments".to_string()
                                ],
                                entry_name,
                            });
                        }
                        None => {
                            out.push(ChildDraft {
                                relation: RelationKind::FilesystemEntry,
                                label: format!("jffs2 file {child_path} (no valid data)"),
                                format_hint: "metadata",
                                content: ChildContent::Owned(Vec::new()),
                                size: 0,
                                metadata: meta,
                                warnings: Vec::new(),
                                entry_name,
                            });
                        }
                    }
                }
                DT_LNK => {
                    meta.insert("type".to_string(), "symlink".to_string());
                    let target = self.assemble_file(src, frags, *ino, limits, budget, warnings)?;
                    let target_str = target
                        .as_ref()
                        .map(|t| String::from_utf8_lossy(t).into_owned())
                        .unwrap_or_default();
                    out.push(ChildDraft {
                        relation: RelationKind::FilesystemEntry,
                        label: format!("jffs2 symlink {child_path} -> {target_str}"),
                        format_hint: "metadata",
                        content: ChildContent::Owned(target.unwrap_or_default()),
                        size: 0,
                        metadata: meta,
                        warnings: vec![
                            "symlink target kept as metadata; never materialized".to_string()
                        ],
                        entry_name,
                    });
                }
                DT_FIFO | DT_CHR | DT_BLK | DT_SOCK => {
                    meta.insert("type".to_string(), "special".to_string());
                    out.push(ChildDraft {
                        relation: RelationKind::FilesystemEntry,
                        label: format!("jffs2 special entry {child_path}"),
                        format_hint: "metadata",
                        content: ChildContent::Owned(Vec::new()),
                        size: 0,
                        metadata: meta,
                        warnings: vec!["special entries are never materialized".to_string()],
                        entry_name,
                    });
                }
                other => {
                    warnings.push(format!(
                        "unknown dirent type {other} for {child_path}; metadata only"
                    ));
                }
            }
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// UBI + UBIFS
// ---------------------------------------------------------------------------

/// UBI volume handler: parses erase-block headers and the volume table,
/// exposes each user volume's concatenated LEB data as a child
/// artifact. A UBIFS image inside a volume is picked up by the engine
/// recursively.
pub struct UbiVolumeHandler;

const UBI_EC_MAGIC: &[u8] = b"UBI#"; // 0x55424923 big-endian
const UBI_VID_MAGIC: &[u8] = b"UBI!"; // 0x55424921 big-endian
const UBI_EC_HDR_SIZE: usize = 64;
const UBI_VID_HDR_SIZE: usize = 64;
const UBI_VTBL_RECORD_SIZE: usize = 128;
const UBI_MAX_VOLUMES: usize = 128;
const UBI_LAYOUT_VOLUME_ID: u32 = 0x7FFF_FFC0; // 0x7FFFFFFF - 4096
const UBI_VID_STATIC: u8 = 2;
/// The layout volume occupies LEBs 0 and 1 of its own mapping; its
/// table records are 128 bytes each with a trailing CRC-32.
const UBI_VTBL_CRC_LEN: usize = UBI_VTBL_RECORD_SIZE - 4;

/// Layout verified against Linux drivers/mtd/ubi (ubi-media.h, io.c,
/// build.c, vtbl.c):
/// - Each physical erase block starts with `struct ubi_ec_hdr` (64
///   bytes): magic "UBI#" (be32 0x55424923), version@4, ec@8 (be64),
///   vid_hdr_offset@16 (be32), data_offset@20 (be32), image_seq@24
///   (be32), hdr_crc@60 (be32). hdr_crc = crc32 over the first 60
///   bytes (crc32_le(0xFFFFFFFF, ...) ^ 0xFFFFFFFF, i.e. the standard
///   CRC-32 of those bytes).
/// - At vid_hdr_offset (64 by default) sits `struct ubi_vid_hdr` (64
///   bytes): magic "UBI!", version@4, vol_type@5 (1 = dynamic, 2 =
///   static), copy_flag@6, compat@7, vol_id@8 (be32), lnum@12 (be32),
///   data_size@16 (be32, static volumes), used_ebs@20, data_pad@24,
///   data_crc@28, sqnum@32 (be64), hdr_crc@60. hdr_crc over the first
///   60 bytes.
/// - User data starts at data_offset (typically 128). LEB size is not
///   stored on flash; it is inferred as the distance between identical
///   EC-header positions.
/// - The layout volume (vol_id 0x7FFFFFFF-4096 = 0x7FFFFFFC0>>0...
///   exactly 0x7FFF_FFC0) holds two copies of the volume table: an
///   array of `struct ubi_vtbl_record` (128 bytes): reserved_pebs@0
///   (be32), alignment@4, data_pad@8, vol_type@12, upd_marker@13,
///   name_len@14 (be16), name@16 (up to 128 bytes), flags@144,
///   padding[23], crc@124 (be32) = standard CRC-32 over the first 124
///   bytes. Empty records are all zero with the CRC of zeros.
struct UbiLeb {
    vol_id: u32,
    lnum: u32,
    data_offset: u64,
    data_size: u64,
    static_size: Option<u64>,
}

/// Standard CRC-32 of a byte slice.
fn ubi_crc32(data: &[u8]) -> u32 {
    let mut h = crc32fast::Hasher::new();
    h.update(data);
    h.finalize()
}

fn be32at(b: &[u8], o: usize) -> u32 {
    u32::from_be_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]])
}

impl UbiVolumeHandler {
    /// Infer the PEB size: the offset of the second EC header (or the
    /// source end for single-PEB images).
    fn scan_pebs(
        src: &ByteSource,
        base: u64,
        limits: &crate::engine::EngineLimits,
        warnings: &mut Vec<String>,
    ) -> Result<(u64, Vec<UbiLeb>)> {
        let mut ec_offsets: Vec<u64> = Vec::new();
        // First pass: find EC header offsets (bounded scan).
        let scan_end = src.len().min(base + 512 * 1024 * 1024);
        let mut magic = [0u8; 4];
        let mut pos = base;
        let mut ff_run = 0usize;
        // PEBs are uniform; use the first two headers to lock stride.
        let mut peb_stride: u64 = 0;
        while pos + UBI_EC_HDR_SIZE as u64 <= scan_end {
            src.read_at(pos, &mut magic)?;
            if magic == *UBI_EC_MAGIC {
                ec_offsets.push(pos);
                if ec_offsets.len() >= limits.max_partitions {
                    warnings.push("PEB scan hit max_partitions; truncated".to_string());
                    break;
                }
                // Next EC header cannot be inside this PEB.
                pos += peb_stride.max(4096);
                ff_run = 0;
                continue;
            }
            if magic[0] == 0xFF {
                ff_run += 1;
                if ff_run > 1024 * 1024 {
                    break; // erased tail
                }
            } else {
                ff_run = 0;
            }
            // Once the stride is known, jump PEB to PEB.
            match peb_stride {
                0 => pos += 1,
                stride => pos = (pos / stride + 1) * stride,
            }
            if ec_offsets.len() == 2 && peb_stride == 0 {
                peb_stride = ec_offsets[1] - ec_offsets[0];
            }
        }
        if ec_offsets.is_empty() {
            return Err(Error::Validation {
                format: "ubi",
                reason: "no erase-count headers found".into(),
            });
        }
        let peb_size = if ec_offsets.len() >= 2 {
            ec_offsets[1] - ec_offsets[0]
        } else {
            src.len() - ec_offsets[0]
        };
        if peb_size < 2048 || !peb_size.is_power_of_two() {
            return Err(Error::Validation {
                format: "ubi",
                reason: format!("implausible PEB size {peb_size}"),
            });
        }

        // Second pass: parse VID headers.
        let mut lebs: Vec<UbiLeb> = Vec::new();
        for &peb in &ec_offsets {
            let mut ec = [0u8; UBI_EC_HDR_SIZE];
            src.read_at(peb, &mut ec)?;
            if be32at(&ec, 60) != ubi_crc32(&ec[..60]) {
                continue; // corrupt EC header: skip like the kernel
            }
            let vid_off = peb + be32at(&ec, 16) as u64;
            let data_off = peb + be32at(&ec, 20) as u64;
            if vid_off + UBI_VID_HDR_SIZE as u64 > src.len() {
                continue;
            }
            let mut vid = [0u8; UBI_VID_HDR_SIZE];
            src.read_at(vid_off, &mut vid)?;
            if &vid[..4] != UBI_VID_MAGIC {
                continue; // unmapped/erased PEB
            }
            if be32at(&vid, 60) != ubi_crc32(&vid[..60]) {
                continue;
            }
            let vol_type = vid[5];
            let data_size = be32at(&vid, 16) as u64;
            lebs.push(UbiLeb {
                vol_id: be32at(&vid, 8),
                lnum: be32at(&vid, 12),
                data_offset: data_off,
                data_size: peb_size - (data_off - peb),
                static_size: if vol_type == UBI_VID_STATIC {
                    Some(data_size)
                } else {
                    None
                },
            });
        }
        Ok((peb_size, lebs))
    }

    /// Read the volume table from the layout volume LEBs (highest
    /// sqnum copy wins; the table itself is duplicated at lnum 0/1).
    fn read_volume_table(
        src: &ByteSource,
        lebs: &[UbiLeb],
        warnings: &mut Vec<String>,
    ) -> Result<Vec<u8>> {
        let mut table: Option<Vec<u8>> = None;
        for leb in lebs.iter().filter(|l| l.vol_id == UBI_LAYOUT_VOLUME_ID) {
            // Layout volume data starts at data_offset; the table
            // fills the rest of the LEB.
            let len = (leb.data_size).min((UBI_MAX_VOLUMES * UBI_VTBL_RECORD_SIZE) as u64) as usize;
            if len == 0 {
                continue;
            }
            let mut buf = vec![0u8; len];
            if src.read_at(leb.data_offset, &mut buf).is_err() {
                continue;
            }
            table = Some(buf);
            break;
        }
        let Some(table) = table else {
            warnings.push("layout volume not found; volume table unavailable".to_string());
            return Ok(Vec::new());
        };
        // Validate per-record CRCs; corrupt records become empty.
        let mut clean = vec![0u8; table.len()];
        for i in 0..table.len() / UBI_VTBL_RECORD_SIZE {
            let rec = &table[i * UBI_VTBL_RECORD_SIZE..(i + 1) * UBI_VTBL_RECORD_SIZE];
            if be32at(rec, 124) == ubi_crc32(&rec[..UBI_VTBL_CRC_LEN]) {
                clean[i * UBI_VTBL_RECORD_SIZE..(i + 1) * UBI_VTBL_RECORD_SIZE]
                    .copy_from_slice(rec);
            }
        }
        Ok(clean)
    }
}

/// One parsed volume table record.
struct UbiVolume {
    id: usize,
    reserved_pebs: u32,
    vol_type: u8,
    name: String,
}

impl Handler for UbiVolumeHandler {
    fn format(&self) -> &'static str {
        "ubi"
    }

    fn find_candidates(&self, src: &ByteSource) -> Vec<Candidate> {
        let mut hits: Vec<Candidate> = find_all(src, UBI_EC_MAGIC)
            .into_iter()
            .map(|offset| Candidate { offset })
            .collect();
        hits.sort_by_key(|c| c.offset);
        hits.dedup_by_key(|c| c.offset);
        hits.truncate(8);
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
        let mut warnings = Vec::new();
        let (peb_size, lebs) = Self::scan_pebs(src, base, limits, &mut warnings)?;

        let table = Self::read_volume_table(src, &lebs, &mut warnings)?;
        let mut volumes: Vec<UbiVolume> = Vec::new();
        for i in 0..table.len() / UBI_VTBL_RECORD_SIZE {
            if i >= UBI_MAX_VOLUMES {
                break;
            }
            let rec = &table[i * UBI_VTBL_RECORD_SIZE..(i + 1) * UBI_VTBL_RECORD_SIZE];
            let reserved_pebs = be32at(rec, 0);
            if reserved_pebs == 0 {
                continue;
            }
            let name_len = usize::from(u16::from_be_bytes([rec[14], rec[15]]));
            let name_len = name_len.min(UBI_MAX_VOLUMES).min(127);
            let name = String::from_utf8_lossy(&rec[16..16 + name_len]).into_owned();
            volumes.push(UbiVolume {
                id: i,
                reserved_pebs,
                vol_type: rec[12],
                name,
            });
        }

        // Map LEBs: vol_id -> sorted by lnum.
        let mut by_vol: std::collections::BTreeMap<u32, Vec<&UbiLeb>> =
            std::collections::BTreeMap::new();
        for l in &lebs {
            by_vol.entry(l.vol_id).or_default().push(l);
        }
        for v in by_vol.values_mut() {
            v.sort_by_key(|l| l.lnum);
        }

        let mut children = Vec::new();
        for vol in &volumes {
            if children.len() >= limits.max_streams {
                warnings.push("max_streams reached; remaining volumes not exposed".to_string());
                break;
            }
            let leb_list = match by_vol.get(&(vol.id as u32)) {
                Some(l) => l,
                None => continue,
            };
            // Dynamic volume: concatenate full LEB data areas. Static
            // volumes carry per-LEB data_size (ubi-media.h).
            let total: u64 = leb_list
                .iter()
                .map(|l| l.static_size.unwrap_or(l.data_size))
                .sum();
            let label = format!(
                "UBI volume \"{}\" ({} LEBs, {} bytes, type {})",
                vol.name,
                leb_list.len(),
                total,
                if vol.vol_type == UBI_VID_STATIC {
                    "static"
                } else {
                    "dynamic"
                }
            );
            let mut meta = BTreeMap::new();
            meta.insert("volume_id".to_string(), vol.id.to_string());
            meta.insert("volume_name".to_string(), vol.name.clone());
            meta.insert(
                "volume_type".to_string(),
                if vol.vol_type == UBI_VID_STATIC {
                    "static".to_string()
                } else {
                    "dynamic".to_string()
                },
            );
            meta.insert("leb_count".to_string(), leb_list.len().to_string());
            meta.insert("reserved_pebs".to_string(), vol.reserved_pebs.to_string());
            meta.insert("peb_size".to_string(), peb_size.to_string());
            // Volumes are exposed as contiguous reconstructions; the
            // engine re-runs handlers over the content, so UBIFS /
            // SquashFS inside a volume is discovered automatically.
            children.push(ChildDraft {
                relation: RelationKind::ReconstructedFrom,
                label,
                format_hint: "ubi-volume",
                content: ChildContent::Owned(Vec::new()), // filled lazily below
                size: total,
                metadata: meta,
                warnings: Vec::new(),
                entry_name: Some(vol.name.clone()),
            });
        }

        let mut metadata = BTreeMap::new();
        metadata.insert("peb_size".to_string(), peb_size.to_string());
        metadata.insert("peb_count".to_string(), (lebs.len()).to_string());
        metadata.insert("volumes".to_string(), volumes.len().to_string());

        // Assemble volume content now (Owned) with budget bounds. This
        // is intentionally simple: volumes in firmware images are
        // typically far below the expansion limits; oversized volumes
        // are reported as metadata-only.
        let mut owned_children = Vec::new();
        for mut child in children {
            let vol_id = child
                .metadata
                .get("volume_id")
                .and_then(|v| v.parse::<u32>().ok())
                .unwrap_or(u32::MAX);
            let leb_list = by_vol.get(&vol_id).cloned().unwrap_or_default();
            let total: u64 = leb_list
                .iter()
                .map(|l| l.static_size.unwrap_or(l.data_size))
                .sum();
            if total == 0 || total > limits.max_child_size {
                child
                    .warnings
                    .push("volume too large; exposed as metadata only".to_string());
                owned_children.push(child);
                continue;
            }
            let mut buf = vec![0u8; total as usize];
            let mut off = 0usize;
            let mut truncated = false;
            for l in &leb_list {
                let end = (off + l.data_size as usize).min(buf.len());
                if src.read_at(l.data_offset, &mut buf[off..end]).is_err() {
                    truncated = true;
                    break;
                }
                off = end;
                if off >= buf.len() {
                    break;
                }
            }
            if truncated {
                child.warnings.push("volume read truncated".to_string());
            }
            child.content = ChildContent::Owned(buf);
            owned_children.push(child);
        }

        Ok(HandlerOutput {
            artifacts: vec![ArtifactDraft {
                format: "ubi".to_string(),
                label: format!(
                    "UBI flash container ({} PEBs, {} volumes)",
                    lebs.len(),
                    volumes.len()
                ),
                offset: base,
                size: src.len() - base,
                confidence: if volumes.is_empty() {
                    Confidence::Partial
                } else {
                    Confidence::Validated
                },
                evidence: Evidence::facts([
                    "UBI erase-count headers validated (magic + header CRCs)".to_string(),
                    format!("PEB size {peb_size}, {} mapped LEBs", lebs.len()),
                    format!("volume table: {} user volumes", volumes.len()),
                ]),
                metadata,
                warnings,
                errors: Vec::new(),
                children: owned_children,
            }],
        })
    }
}

// ---------------------------------------------------------------------------
// UBIFS
// ---------------------------------------------------------------------------

/// UBIFS filesystem handler: walks the B-tree index rooted at the
/// master node and reconstructs the directory tree. Runs on raw UBIFS
/// images and on UBI volume content extracted by UbiVolumeHandler.
pub struct UbifsHandler;

const UBIFS_MAGIC: u32 = 0x0610_1831; // stored little-endian
const UBIFS_CH_SZ: usize = 24;
const UBIFS_SB_NODE: u8 = 6;
const UBIFS_MST_NODE: u8 = 7;
const UBIFS_IDX_NODE: u8 = 9;
const UBIFS_INO_KEY: u32 = 0;
const UBIFS_DATA_KEY: u32 = 1;
const UBIFS_DENT_KEY: u32 = 2;
/// Maximum index depth (kernel: UBIFS_MAX_LEVELS 512, but 64 bounds
/// runaway recursion on fuzzed images).
const UBIFS_MAX_DEPTH: u32 = 64;

/// Layout verified against Linux fs/ubifs (ubifs-media.h, sb.c,
/// master.c via ubifs.h, io.c, key.h, file.c, compress.c):
/// - Every node starts with `struct ubifs_ch` (24 bytes, all LE):
///   magic@0 (0x06101831), crc@4 (CRC-32 over node bytes 8..len),
///   sqnum@8 (u64), len@16 (u32), node_type@20, group_type@21.
/// - `struct ubifs_sb_node` (superblock, LEB 0): leb_size@+40 (ch 24 +
///   padding 2 + key_hash 1 + key_fmt 1 + flags 4 + min_io_size 4 =
///   offset 36..40), leb_cnt@44. Only simple key format (key_fmt 0,
///   key_len 8) is supported, per sb.c.
/// - `struct ubifs_mst_node` (master, LEBs 1 and 2; higher cmt_no
///   wins): root_lnum@+36, root_offs@+40, root_len@+44 (the B-tree
///   index root).
/// - `struct ubifs_idx_node`: child_cnt@+24 (u16), level@+26 (u16),
///   branches@+28, each `struct ubifs_branch` = 12 + key_len = 20
///   bytes: lnum@0, offs@4, len@8 (u32 LE), key[8]@12.
/// - Keys (simple format): u32 LE inum@0; u32@4 = type << 29 | payload
///   (block number for DATA keys, R5 hash for DENT keys, 0 for INO).
/// - `struct ubifs_dent_node`: key[16]@24, inum@40 (u64), type@49,
///   nlen@50 (u16), name@56.
/// - `struct ubifs_ino_node`: key[16]@24, size@48 (u64), times@56..80,
///   nlink@80? -- exact: creat_sqnum@40, size@48, atime_sec@56,
///   ctime_sec@64, mtime_sec@72, nsecs@80..92, nlink@92, uid@96,
///   gid@100, mode@104, flags@108, data_len@112, compr_type@132,
///   data@160. Inline data (symlinks, devices) is data_len bytes.
/// - `struct ubifs_data_node`: key[16]@24, size@40 (u32, uncompressed
///   size of this block), compr_type@44 (u16), data@48. Compressed
///   length = ch.len - 48. Compression codes: NONE 0, LZO 1,
///   ZLIB 2 (standard zlib stream via crypto 'deflate'), ZSTD 3.
///   Data past a block's decompressed size zero-fills (holes).
/// - LEB N lives at byte offset N * leb_size in the volume/image.
///
/// Parent inum -> dent entries (sort ref, target inum, name, ITYPE).
type UbifsDentMap = std::collections::BTreeMap<u32, Vec<(u64, u32, Vec<u8>, u8)>>;
///
/// Inum -> parsed inode node.
type UbifsInoMap = std::collections::BTreeMap<u32, UbifsIno>;

/// A leaf node reference collected from the index.
struct UbifsLeafRef {
    lnum: u32,
    offs: u32,
    len: u32,
    key_type: u32,
    inum: u32,
}

/// Parsed inode metadata.
struct UbifsIno {
    size: u64,
    mode: u32,
    nlink: u32,
    data: Vec<u8>,
}

fn ubi_le32(b: &[u8], o: usize) -> u32 {
    u32::from_le_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]])
}
fn ubi_le64(b: &[u8], o: usize) -> u64 {
    u64::from_le_bytes(b[o..o + 8].try_into().unwrap())
}

impl UbifsHandler {
    /// Read one LEB of a UBIFS image at `base` (leb_size from the
    /// superblock).
    fn read_leb(
        src: &ByteSource,
        base: u64,
        leb_size: u64,
        lnum: u32,
        len: u32,
    ) -> Result<Vec<u8>> {
        let off = base + u64::from(lnum) * leb_size;
        let take = u64::from(len).min(leb_size);
        let mut buf = vec![0u8; take as usize];
        src.read_at(off, &mut buf)?;
        Ok(buf)
    }

    /// Validate the common header; returns (node_type, len) or None.
    fn check_ch(node: &[u8]) -> Option<(u8, u32)> {
        if node.len() < UBIFS_CH_SZ {
            return None;
        }
        let magic = ubi_le32(node, 0);
        if magic != UBIFS_MAGIC {
            return None;
        }
        let len = ubi_le32(node, 16);
        if len < UBIFS_CH_SZ as u32 || len as usize > node.len() {
            return None;
        }
        let stored = ubi_le32(node, 4);
        if ubi_crc32(&node[8..len as usize]) != stored {
            return None;
        }
        Some((node[20], len))
    }

    /// Parse the superblock LEB for leb_size.
    fn parse_sb(src: &ByteSource, base: u64, leb_size_guess: u64) -> Result<u64> {
        // The superblock node sits at offset 0 (well, 2 KiB) of LEB 0.
        // The LEB size itself is only known after parsing, so probe
        // common sizes.
        for &guess in &[
            leb_size_guess,
            4096,
            8192,
            16384,
            32768,
            65536,
            131072,
            262144,
            524288,
            1048576,
            2097152,
            4194304,
        ] {
            if guess < 2048 || base + guess > src.len() {
                continue;
            }
            let mut probe = vec![0u8; 2048];
            if src.read_at(base + guess - 2048, &mut probe).is_err() {
                continue;
            }
            // Try the node right at LEB start.
            let mut node = vec![0u8; 64];
            if src.read_at(base, &mut node).is_err() {
                continue;
            }
            if ubi_le32(&node, 0) != UBIFS_MAGIC {
                continue;
            }
            if node[20] != UBIFS_SB_NODE {
                continue;
            }
            let len = ubi_le32(&node, 16) as usize;
            if len < 32 || len > probe.len() + 64 {
                continue;
            }
            let mut sb = vec![0u8; len.min(4096)];
            src.read_at(base, &mut sb)?;
            if ubi_crc32(&sb[8..len]) != ubi_le32(&sb, 4) {
                continue;
            }
            // sb layout: ch(24) + pad(2) + key_hash(1) + key_fmt(1)
            // + flags(4) + min_io_size(4) + leb_size@36.
            if sb[27] != 0 {
                continue; // key_fmt: only simple (0)
            }
            let parsed = ubi_le32(&sb, 36) as u64;
            if parsed == guess {
                return Ok(parsed);
            }
        }
        Err(Error::Validation {
            format: "ubifs",
            reason: "no valid superblock node at LEB 0".into(),
        })
    }

    /// Find the newest master node (higher cmt_no wins).
    fn find_master(src: &ByteSource, base: u64, leb_size: u64) -> Result<Vec<u8>> {
        let mut best: Option<(u64, Vec<u8>)> = None;
        for lnum in 1..=2u32 {
            let off = base + u64::from(lnum) * leb_size;
            let mut hdr = [0u8; UBIFS_CH_SZ];
            if src.read_at(off, &mut hdr).is_err() || ubi_le32(&hdr, 0) != UBIFS_MAGIC {
                continue;
            }
            if hdr[20] != UBIFS_MST_NODE {
                continue;
            }
            let len = ubi_le32(&hdr, 16) as usize;
            if !(UBIFS_CH_SZ + 36..=4096).contains(&len) {
                continue;
            }
            let mut node = vec![0u8; len];
            src.read_at(off, &mut node)?;
            if ubi_crc32(&node[8..len]) != ubi_le32(&node, 4) {
                continue;
            }
            let cmt = ubi_le64(&node, UBIFS_CH_SZ + 8);
            if best.as_ref().map(|(c, _)| cmt > *c).unwrap_or(true) {
                best = Some((cmt, node));
            }
        }
        best.map(|(_, n)| n).ok_or_else(|| Error::Validation {
            format: "ubifs",
            reason: "no valid master node".into(),
        })
    }

    /// Walk the B-tree index from `lnum`/`offs`/`len`, collecting leaf
    /// references. Index branches at level > 0 point at child index
    /// nodes; level 0 points at ino/dent/data nodes.
    #[allow(clippy::too_many_arguments)]
    fn walk_index(
        &self,
        src: &ByteSource,
        base: u64,
        leb_size: u64,
        lnum: u32,
        offs: u32,
        len: u32,
        depth: u32,
        limits: &crate::engine::EngineLimits,
        warnings: &mut Vec<String>,
        out: &mut Vec<UbifsLeafRef>,
    ) -> Result<()> {
        if depth > UBIFS_MAX_DEPTH {
            warnings.push("ubifs index deeper than 64; subtree skipped".to_string());
            return Ok(());
        }
        if out.len() >= limits.max_fs_entries {
            return Ok(());
        }
        let node = Self::read_leb(src, base, leb_size, lnum, len)?;
        let offs = offs as usize;
        if offs + len as usize > node.len() + UBIFS_CH_SZ {
            warnings.push("ubifs index node out of LEB bounds; skipped".to_string());
            return Ok(());
        }
        let node = &node[offs.min(node.len())..];
        let Some((node_type, _len)) = Self::check_ch(node) else {
            warnings.push("invalid index node header; skipped".to_string());
            return Ok(());
        };
        if node_type != UBIFS_IDX_NODE {
            return Ok(());
        }
        if node.len() < 28 {
            return Ok(());
        }
        let child_cnt = u16::from_le_bytes([node[24], node[25]]) as usize;
        let level = u16::from_le_bytes([node[26], node[27]]) as u32;
        let branch_sz = 12 + 8;
        for i in 0..child_cnt {
            if out.len() >= limits.max_fs_entries {
                warnings.push("max_fs_entries reached; index truncated".to_string());
                return Ok(());
            }
            let b = 28 + i * branch_sz;
            if b + branch_sz > node.len() {
                break;
            }
            let child_lnum = ubi_le32(node, b);
            let child_offs = ubi_le32(node, b + 4);
            let child_len = ubi_le32(node, b + 8);
            let key = &node[b + 12..b + 20];
            let inum = ubi_le32(key, 0);
            let second = ubi_le32(key, 4);
            let key_type = second >> 29;
            if level == 0 {
                if child_len >= UBIFS_CH_SZ as u32 && u64::from(child_len) <= leb_size {
                    out.push(UbifsLeafRef {
                        lnum: child_lnum,
                        offs: child_offs,
                        len: child_len,
                        key_type,
                        inum,
                    });
                }
            } else {
                self.walk_index(
                    src,
                    base,
                    leb_size,
                    child_lnum,
                    child_offs,
                    child_len,
                    depth + 1,
                    limits,
                    warnings,
                    out,
                )?;
            }
        }
        Ok(())
    }
}

impl UbifsHandler {
    /// Read one leaf node (ino / dent / data).
    fn read_leaf(
        src: &ByteSource,
        base: u64,
        leb_size: u64,
        leaf: &UbifsLeafRef,
    ) -> Option<Vec<u8>> {
        let off = base + u64::from(leaf.lnum) * leb_size + u64::from(leaf.offs);
        if off + u64::from(leaf.len) > src.len() {
            return None;
        }
        let mut node = vec![0u8; leaf.len as usize];
        src.read_at(off, &mut node).ok()?;
        Self::check_ch(&node)?;
        Some(node)
    }

    /// Parse an ino node: metadata + inline data.
    fn parse_ino(node: &[u8]) -> Option<UbifsIno> {
        if node.len() < 160 {
            return None;
        }
        let size = ubi_le64(node, 48);
        let nlink = ubi_le32(node, 92);
        let mode = ubi_le32(node, 104);
        let data_len = ubi_le32(node, 112) as usize;
        let data = if 160 + data_len <= node.len() {
            node[160..160 + data_len].to_vec()
        } else {
            Vec::new()
        };
        let _ = data_len;
        Some(UbifsIno {
            size,
            mode,
            nlink,
            data,
        })
    }

    /// Assemble file content from data node blocks. `block` from the
    /// key; per block the decompressed payload lands at block*4096.
    #[allow(clippy::too_many_arguments)]
    fn assemble_data(
        &self,
        src: &ByteSource,
        base: u64,
        leb_size: u64,
        inum: u32,
        leaves: &[UbifsLeafRef],
        total: u64,
        limits: &crate::engine::EngineLimits,
        budget: &mut Budget,
        warnings: &mut Vec<String>,
    ) -> Result<Option<Vec<u8>>> {
        let total = total.min(limits.max_child_size);
        let mut out = vec![0u8; total as usize];
        let mut wrote = false;
        for leaf in leaves
            .iter()
            .filter(|l| l.inum == inum && l.key_type == UBIFS_DATA_KEY)
        {
            let Some(node) = Self::read_leaf(src, base, leb_size, leaf) else {
                continue;
            };
            if node.len() < 48 {
                continue;
            }
            let block = (ubi_le32(&node, 28) & 0x1FFF_FFFF) as usize;
            let size = ubi_le32(&node, 40) as usize;
            let compr = u16::from_le_bytes([node[44], node[45]]);
            let payload = &node[48..];
            let start = block * 4096;
            if start >= out.len() {
                continue;
            }
            let take = (4096).min(out.len() - start).min(size);
            let decoded: Vec<u8> = match compr {
                0 => payload.to_vec(),
                2 => match Self::zlib_decompress(payload) {
                    Ok(d) => d,
                    Err(_) => {
                        warnings.push(format!(
                            "inode {inum}: zlib block {block} failed; zero-filled"
                        ));
                        continue;
                    }
                },
                3 => match zstd::stream::decode_all(payload) {
                    Ok(d) => d,
                    Err(_) => {
                        warnings.push(format!(
                            "inode {inum}: zstd block {block} failed; zero-filled"
                        ));
                        continue;
                    }
                },
                other => {
                    warnings.push(format!(
                        "inode {inum}: unsupported compression {other}; block zero-filled"
                    ));
                    continue;
                }
            };
            if !decoded.is_empty() && !budget.charge(limits, decoded.len() as u64) {
                return Err(Error::LimitExceeded {
                    limit: "max-total-expanded-bytes",
                    detail: "ubifs data block".into(),
                });
            }
            let n = decoded.len().min(take);
            out[start..start + n].copy_from_slice(&decoded[..n]);
            wrote = true;
        }
        Ok(if wrote { Some(out) } else { None })
    }

    /// UBIFS zlib: standard zlib stream (crypto 'deflate').
    fn zlib_decompress(input: &[u8]) -> Result<Vec<u8>> {
        let mut dec = flate2::read::ZlibDecoder::new(input);
        let mut out = Vec::new();
        std::io::Read::read_to_end(&mut dec, &mut out).map_err(|_| Error::Validation {
            format: "ubifs",
            reason: "zlib inflate failed".into(),
        })?;
        Ok(out)
    }
}

impl Handler for UbifsHandler {
    fn format(&self) -> &'static str {
        "ubifs"
    }

    fn find_candidates(&self, src: &ByteSource) -> Vec<Candidate> {
        // Magic 0x06101831 little-endian.
        find_all(src, &[0x31, 0x18, 0x10, 0x06])
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
        let mut warnings = Vec::new();
        // Superblock must be at the candidate (LEB 0).
        let leb_size = Self::parse_sb(src, base, 0)?;
        let master = Self::find_master(src, base, leb_size)?;
        // Master fields after ch(24): highest_inum@24, cmt_no@32,
        // flags@40, log_lnum@44, root_lnum@48, root_offs@52, root_len@56
        // (fs/ubifs/ubifs-media.h struct ubifs_mst_node).
        let root_lnum = ubi_le32(&master, 48);
        let root_offs = ubi_le32(&master, 52);
        let root_len = ubi_le32(&master, 56);

        let mut leaves: Vec<UbifsLeafRef> = Vec::new();
        self.walk_index(
            src,
            base,
            leb_size,
            root_lnum,
            root_offs,
            root_len,
            0,
            limits,
            &mut warnings,
            &mut leaves,
        )?;

        // Load ino nodes.
        let mut inos: std::collections::BTreeMap<u32, UbifsIno> = std::collections::BTreeMap::new();
        let ino_refs: Vec<&UbifsLeafRef> = leaves
            .iter()
            .filter(|l| l.key_type == UBIFS_INO_KEY)
            .collect();
        for leaf in &ino_refs {
            if let Some(node) = Self::read_leaf(src, base, leb_size, leaf) {
                if let Some(ino) = Self::parse_ino(&node) {
                    inos.insert(leaf.inum, ino);
                }
            }
        }

        // Dirents: parent inum -> children.
        let mut by_parent: UbifsDentMap = std::collections::BTreeMap::new();
        for leaf in leaves.iter().filter(|l| l.key_type == UBIFS_DENT_KEY) {
            let Some(node) = Self::read_leaf(src, base, leb_size, leaf) else {
                continue;
            };
            if node.len() < 56 {
                continue;
            }
            let inum = ubi_le64(&node, 40) as u32;
            let dtype = node[49];
            let nlen = usize::from(u16::from_le_bytes([node[50], node[51]]));
            if 56 + nlen > node.len() || nlen == 0 {
                continue;
            }
            let name = node[56..56 + nlen].to_vec();
            // Parent from the dent key.
            let parent = leaf.inum;
            by_parent.entry(parent).or_default().push((
                leaf.offs as u64 | (u64::from(leaf.lnum) << 32),
                inum,
                name,
                dtype,
            ));
        }

        let mut children = Vec::new();
        // Root: the ino referenced by dent keys of the root directory
        // is inum 1 (ubifs convention: root inode number 1).
        let root = 1u32;
        self.emit_dir(
            src,
            base,
            leb_size,
            root,
            "",
            &by_parent,
            &leaves,
            &inos,
            0,
            limits,
            budget,
            &mut std::collections::HashSet::new(),
            &mut warnings,
            &mut children,
        )?;

        let mut metadata = BTreeMap::new();
        metadata.insert("leb_size".to_string(), leb_size.to_string());
        metadata.insert("index_leaves".to_string(), leaves.len().to_string());
        metadata.insert("inodes".to_string(), inos.len().to_string());
        metadata.insert("entries".to_string(), children.len().to_string());

        Ok(HandlerOutput {
            artifacts: vec![ArtifactDraft {
                format: "ubifs".to_string(),
                label: format!(
                    "UBIFS filesystem ({}B LEBs, {} entries)",
                    leb_size,
                    children.len()
                ),
                offset: base,
                size: src.len() - base,
                confidence: if children.is_empty() {
                    Confidence::Partial
                } else {
                    Confidence::Validated
                },
                evidence: Evidence::facts([
                    "UBIFS superblock + master node validated (node CRCs)".to_string(),
                    format!(
                        "index root at LEB {root_lnum}+{root_offs}, {} leaves",
                        leaves.len()
                    ),
                    format!("{} inode nodes parsed", inos.len()),
                    format!("directory tree walked: {} entries", children.len()),
                ]),
                metadata,
                warnings,
                errors: Vec::new(),
                children,
            }],
        })
    }
}

impl UbifsHandler {
    /// Depth-first emission of one directory's children.
    #[allow(clippy::too_many_arguments)]
    #[allow(clippy::too_many_arguments)]
    fn emit_dir(
        &self,
        src: &ByteSource,
        base: u64,
        leb_size: u64,
        dnum: u32,
        path: &str,
        by_parent: &UbifsDentMap,
        leaves: &[UbifsLeafRef],
        inos: &UbifsInoMap,
        depth: u32,
        limits: &crate::engine::EngineLimits,
        budget: &mut Budget,
        visited: &mut std::collections::HashSet<u32>,
        warnings: &mut Vec<String>,
        out: &mut Vec<ChildDraft>,
    ) -> Result<()> {
        if depth > 16 {
            warnings.push("ubifs directory nesting deeper than 16 not walked".to_string());
            return Ok(());
        }
        if !visited.insert(dnum) {
            warnings.push("ubifs directory cycle detected; subtree skipped".to_string());
            return Ok(());
        }
        let Some(entries) = by_parent.get(&dnum) else {
            return Ok(());
        };
        for (_ref, inum, name, dtype) in entries {
            if out.len() >= limits.max_fs_entries {
                warnings.push("max_fs_entries reached; walk truncated".to_string());
                return Ok(());
            }
            let name = String::from_utf8_lossy(name).into_owned();
            let child_path = if path.is_empty() {
                name.clone()
            } else {
                format!("{path}/{name}")
            };
            let ino = inos.get(inum);
            let mut meta = BTreeMap::new();
            meta.insert("path".to_string(), child_path.clone());
            meta.insert("inode".to_string(), inum.to_string());
            if let Some(i) = ino {
                meta.insert("mode".to_string(), format!("{:#07o}", i.mode & 0o7777));
                meta.insert("nlink".to_string(), i.nlink.to_string());
            }
            let entry_name = Some(name);
            match *dtype {
                1 => {
                    // Directory.
                    meta.insert("type".to_string(), "directory".to_string());
                    out.push(ChildDraft {
                        relation: RelationKind::FilesystemEntry,
                        label: format!("ubifs directory {child_path}"),
                        format_hint: "metadata",
                        content: ChildContent::Owned(Vec::new()),
                        size: 0,
                        metadata: meta,
                        warnings: Vec::new(),
                        entry_name,
                    });
                    self.emit_dir(
                        src,
                        base,
                        leb_size,
                        *inum,
                        &child_path,
                        by_parent,
                        leaves,
                        inos,
                        depth + 1,
                        limits,
                        budget,
                        visited,
                        warnings,
                        out,
                    )?;
                }
                0 => {
                    // Regular file.
                    meta.insert("type".to_string(), "file".to_string());
                    let declared = ino.map(|i| i.size).unwrap_or(0);
                    meta.insert("declared_size".to_string(), declared.to_string());
                    let data = self.assemble_data(
                        src, base, leb_size, *inum, leaves, declared, limits, budget, warnings,
                    )?;
                    let (content, size) = match data {
                        Some(d) => {
                            let n = d.len() as u64;
                            (ChildContent::Owned(d), n)
                        }
                        None => (ChildContent::Owned(Vec::new()), 0),
                    };
                    out.push(ChildDraft {
                        relation: RelationKind::ReconstructedFrom,
                        label: format!("ubifs file {child_path} ({size} bytes)"),
                        format_hint: "raw",
                        content,
                        size,
                        metadata: meta,
                        warnings: vec!["content reconstructed from UBIFS B-tree nodes".to_string()],
                        entry_name,
                    });
                }
                2 => {
                    // Symlink: target is the inode inline data.
                    meta.insert("type".to_string(), "symlink".to_string());
                    let target = ino
                        .map(|i| String::from_utf8_lossy(&i.data).into_owned())
                        .unwrap_or_default();
                    out.push(ChildDraft {
                        relation: RelationKind::FilesystemEntry,
                        label: format!("ubifs symlink {child_path} -> {target}"),
                        format_hint: "metadata",
                        content: ChildContent::Owned(
                            ino.map(|i| i.data.clone()).unwrap_or_default(),
                        ),
                        size: 0,
                        metadata: meta,
                        warnings: vec![
                            "symlink target kept as metadata; never materialized".to_string()
                        ],
                        entry_name,
                    });
                }
                3..=6 => {
                    // Device / FIFO / socket: metadata only.
                    meta.insert("type".to_string(), "special".to_string());
                    out.push(ChildDraft {
                        relation: RelationKind::FilesystemEntry,
                        label: format!("ubifs special entry {child_path}"),
                        format_hint: "metadata",
                        content: ChildContent::Owned(Vec::new()),
                        size: 0,
                        metadata: meta,
                        warnings: vec!["special entries are never materialized".to_string()],
                        entry_name,
                    });
                }
                other => {
                    warnings.push(format!(
                        "unknown ubifs itype {other} for {child_path}; metadata only"
                    ));
                }
            }
        }
        Ok(())
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

    /// Build a minimal SquashFS 4.0 image with gzip-compressed metadata:
    /// data block first (after superblock), then inode table, then
    /// directory table. Root dir -> FLAG.TXT (uncompressed data block).
    fn squashfs_image() -> Vec<u8> {
        use std::io::Write as _;
        let bs = 65536usize;

        fn meta_block(data: &[u8]) -> Vec<u8> {
            let mut enc =
                flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
            enc.write_all(data).unwrap();
            let comp = enc.finish().unwrap();
            let mut out = Vec::new();
            // compressed: bit15 clear, size = comp.len()
            out.extend_from_slice(&(comp.len() as u16).to_le_bytes());
            out.extend_from_slice(&comp);
            out
        }

        // Inode table: root dir inode @0, FLAG.TXT reg inode @32.
        let mut inodes = Vec::new();
        // Root dir (type 1): start_block 0, nlink 2, file_size 29,
        // offset 0, parent 0. Listing = 12 (header) + 8 (entry) + 8
        // (name "FLAG.TXT") = 28? kernel: entry is 8 bytes + name
        // (size+1 = 8) => 12 + 16 = 28. We store 28 below.
        inodes.extend_from_slice(&1u16.to_le_bytes());
        inodes.extend_from_slice(&0o040755u16.to_le_bytes());
        inodes.extend_from_slice(&0u16.to_le_bytes()); // uid
        inodes.extend_from_slice(&0u16.to_le_bytes()); // guid
        inodes.extend_from_slice(&0u32.to_le_bytes()); // mtime
        inodes.extend_from_slice(&1u32.to_le_bytes()); // inode number
        inodes.extend_from_slice(&0u32.to_le_bytes()); // start_block
        inodes.extend_from_slice(&2u32.to_le_bytes()); // nlink
        inodes.extend_from_slice(&28u16.to_le_bytes()); // file_size
        inodes.extend_from_slice(&0u16.to_le_bytes()); // offset
        inodes.extend_from_slice(&0u32.to_le_bytes()); // parent
                                                       // FLAG.TXT reg inode @32: data at data-area offset 0, fragment
                                                       // INVALID, file_size 10, one uncompressed full-block entry.
        inodes.extend_from_slice(&2u16.to_le_bytes());
        inodes.extend_from_slice(&0o100644u16.to_le_bytes());
        inodes.extend_from_slice(&0u16.to_le_bytes());
        inodes.extend_from_slice(&0u16.to_le_bytes());
        inodes.extend_from_slice(&0u32.to_le_bytes()); // mtime
        inodes.extend_from_slice(&2u32.to_le_bytes()); // inode number
        inodes.extend_from_slice(&0u32.to_le_bytes()); // start_block
        inodes.extend_from_slice(&0xFFFF_FFFFu32.to_le_bytes()); // fragment
        inodes.extend_from_slice(&0u32.to_le_bytes()); // frag offset
        inodes.extend_from_slice(&10u32.to_le_bytes()); // file_size
        inodes.extend_from_slice(&(10u32 | (1 << 24)).to_le_bytes()); // block list

        let inode_meta = meta_block(&inodes);

        // Directory listing: header (count-1 = 0, start_block 0, ino 0)
        // + entry (offset 32, delta 0, type 2, size-1 = 7, name).
        let mut dirs = Vec::new();
        dirs.extend_from_slice(&0u32.to_le_bytes());
        dirs.extend_from_slice(&0u32.to_le_bytes());
        dirs.extend_from_slice(&0u32.to_le_bytes());
        dirs.extend_from_slice(&32u16.to_le_bytes()); // entry inode offset
        dirs.extend_from_slice(&0i16.to_le_bytes()); // inode delta
        dirs.extend_from_slice(&2u16.to_le_bytes()); // type: file
        dirs.extend_from_slice(&7u16.to_le_bytes()); // name size - 1
        dirs.extend_from_slice(b"FLAG.TXT");
        assert_eq!(dirs.len(), 28);
        let dir_meta = meta_block(&dirs);

        // Superblock. Data area begins right after the 96-byte
        // superblock (no compressor options for gzip).
        let data_start = 96u64;
        let inode_table_abs = data_start + 10;
        let dir_table_abs = inode_table_abs + inode_meta.len() as u64;
        let bytes_used = dir_table_abs + dir_meta.len() as u64;

        let mut sb = [0u8; 96];
        sb[0..4].copy_from_slice(b"hsqs");
        sb[4..8].copy_from_slice(&2u32.to_le_bytes()); // inodes
        sb[8..12].copy_from_slice(&0u32.to_le_bytes()); // mkfs_time
        sb[12..16].copy_from_slice(&(bs as u32).to_le_bytes());
        sb[16..20].copy_from_slice(&0u32.to_le_bytes()); // fragments
        sb[20..22].copy_from_slice(&1u16.to_le_bytes()); // gzip
        sb[22..24].copy_from_slice(&16u16.to_le_bytes()); // block_log
        sb[24..26].copy_from_slice(&0u16.to_le_bytes()); // flags
        sb[26..28].copy_from_slice(&1u16.to_le_bytes()); // no_ids
        sb[28..30].copy_from_slice(&4u16.to_le_bytes()); // major
        sb[30..32].copy_from_slice(&0u16.to_le_bytes()); // minor
        sb[32..40].copy_from_slice(&0u64.to_le_bytes()); // root inode @0:0
        sb[40..48].copy_from_slice(&bytes_used.to_le_bytes());
        sb[48..56].copy_from_slice(&u64::MAX.to_le_bytes()); // id table
        sb[56..64].copy_from_slice(&inode_table_abs.to_le_bytes());
        sb[64..72].copy_from_slice(&u64::MAX.to_le_bytes()); // xattr
        sb[72..80].copy_from_slice(&dir_table_abs.to_le_bytes());
        sb[80..88].copy_from_slice(&u64::MAX.to_le_bytes()); // fragment tbl
        sb[88..96].copy_from_slice(&u64::MAX.to_le_bytes()); // export tbl

        let mut img = sb.to_vec();
        img.extend_from_slice(b"SQFS_FLAG!"); // 10-byte uncompressed block
        img.extend_from_slice(&inode_meta);
        img.extend_from_slice(&dir_meta);
        img
    }

    #[test]
    fn squashfs_full_traversal_gzip() {
        let src = ByteSource::from_vec(squashfs_image());
        let out = validate_at(&SquashfsHandler, &src, 0).expect("sqfs validates");
        let art = &out.artifacts[0];
        assert_eq!(art.confidence, Confidence::Validated);
        assert_eq!(
            art.metadata.get("compressor").map(String::as_str),
            Some("gzip")
        );
        let flag = art
            .children
            .iter()
            .find(|c| c.metadata.get("path").map(String::as_str) == Some("FLAG.TXT"))
            .expect("FLAG.TXT child");
        assert_eq!(flag.size, 10);
        match &flag.content {
            ChildContent::Owned(d) => assert_eq!(*d, b"SQFS_FLAG!".to_vec()),
            _ => panic!("file content must reconstruct"),
        }
    }

    /// Build an ISO9660 image: PVD at sector 16, root dir at LBA 18,
    /// one nested directory and two files. `joliet` adds a supplementary
    /// descriptor (sector 17) with a UCS-2 volume id and its own tree.
    fn iso_image(joliet: bool) -> Vec<u8> {
        let mut img = vec![0u8; 40 * 2048];

        // Both-endian 733 write.
        fn put733(buf: &mut [u8], off: usize, v: u32) {
            buf[off..off + 4].copy_from_slice(&v.to_le_bytes());
            buf[off + 4..off + 8].copy_from_slice(&v.to_be_bytes());
        }
        // Write a 34-byte directory record. Returns bytes consumed.
        fn put_record(
            buf: &mut [u8],
            off: usize,
            extent: u32,
            size: u32,
            flags: u8,
            name: &[u8],
        ) -> usize {
            let name_len = name.len();
            let rec_len = 33 + name_len + (1 - name_len % 2); // pad to even
            buf[off] = rec_len as u8;
            buf[off + 1] = 0; // ext_attr_length
            put733(buf, off + 2, extent);
            put733(buf, off + 10, size);
            buf[off + 25] = flags;
            buf[off + 32] = name_len as u8;
            buf[off + 33..off + 33 + name_len].copy_from_slice(name);
            rec_len
        }

        // PVD at sector 16.
        let pvd = 16 * 2048;
        img[pvd] = 1;
        img[pvd + 1..pvd + 6].copy_from_slice(b"CD001");
        img[pvd + 40..pvd + 49].copy_from_slice(b"CTF_IMAGE");
        put733(&mut img, pvd + 80, 40); // volume space: 40 sectors
        img[pvd + 128..pvd + 130].copy_from_slice(&2048u16.to_le_bytes());
        img[pvd + 130..pvd + 132].copy_from_slice(&2048u16.to_be_bytes());
        // Root record: extent 18, size 2048, dir flag.
        let rlen = put_record(&mut img, pvd + 156, 18, 2048, 0x02, b"\x00");
        assert_eq!(rlen, 34);

        if joliet {
            // SVD at sector 17 with escape %/@ (level 1).
            let svd = 17 * 2048;
            img[svd] = 2;
            img[svd + 1..svd + 6].copy_from_slice(b"CD001");
            let vol: Vec<u8> = "CTF_ISO"
                .encode_utf16()
                .flat_map(|u| u.to_be_bytes())
                .collect();
            img[svd + 40..svd + 40 + vol.len()].copy_from_slice(&vol);
            img[svd + 88] = 0x25;
            img[svd + 89] = 0x2F;
            img[svd + 90] = 0x40;
            put733(&mut img, svd + 80, 40);
            img[svd + 128..svd + 130].copy_from_slice(&2048u16.to_le_bytes());
            img[svd + 130..svd + 132].copy_from_slice(&2048u16.to_be_bytes());
            let _ = put_record(&mut img, svd + 156, 20, 2048, 0x02, b"\x00");
        }

        // Joliet identifiers are UCS-2 big-endian without version
        // suffixes.
        let u16be = |s: &str| -> Vec<u8> { s.encode_utf16().flat_map(u16::to_be_bytes).collect() };
        let flag_name: Vec<u8> = if joliet {
            u16be("FLAG.TXT")
        } else {
            b"FLAG.TXT;1".to_vec()
        };
        let dir_name: Vec<u8> = if joliet {
            u16be("DIR")
        } else {
            b"DIR;1".to_vec()
        };
        let nested_name: Vec<u8> = if joliet {
            u16be("NESTED.TXT")
        } else {
            b"NESTED.TXT;1".to_vec()
        };
        let dir_lba = if joliet { 20 } else { 18 };
        let file_lba = if joliet { 22 } else { 20 };
        let dir = dir_lba * 2048;
        // Root listing: FLAG.TXT (file @file_lba, 10 bytes), then a
        // subdirectory DIR (dir_lba+1, 2048 bytes), then the next file
        // NESTED.TXT inside the subdirectory.
        let mut off = dir;
        // "." and ".."
        off += put_record(&mut img, off, dir_lba as u32, 2048, 0x02, b"\x00");
        off += put_record(&mut img, off, dir_lba as u32, 2048, 0x02, b"\x01");
        off += put_record(&mut img, off, file_lba as u32, 10, 0, &flag_name);
        let sub_lba = dir_lba + 1;
        let _ = put_record(&mut img, off, sub_lba as u32, 2048, 0x02, &dir_name);
        // Subdirectory listing (pad to next record position).
        let sub = sub_lba * 2048;
        let mut soff = sub;
        soff += put_record(&mut img, soff, sub_lba as u32, 2048, 0x02, b"\x00");
        soff += put_record(&mut img, soff, dir_lba as u32, 2048, 0x02, b"\x01");
        let _ = put_record(&mut img, soff, (file_lba + 1) as u32, 12, 0, &nested_name);
        img[file_lba * 2048..file_lba * 2048 + 10].copy_from_slice(b"ISO_FLAG1!");
        img[(file_lba + 1) * 2048..(file_lba + 1) * 2048 + 12].copy_from_slice(b"ISO_NESTED!!");
        img
    }

    /// Build a UBI image: 4 PEBs of 16 KiB, vid_hdr_offset 64,
    /// data_offset 128. LEB 0 = layout volume lnum 0 (volume table),
    /// PEB 1 = layout lnum 1, PEB 2 = user volume 0 lnum 0 (dynamic),
    /// PEB 3 = user volume 0 lnum 1.
    fn ubi_image() -> Vec<u8> {
        const PEB: usize = 16384;
        let mut img = vec![0xFFu8; 4 * PEB];

        fn crc32(b: &[u8]) -> u32 {
            let mut h = crc32fast::Hasher::new();
            h.update(b);
            h.finalize()
        }
        fn be32(v: u32) -> [u8; 4] {
            v.to_be_bytes()
        }

        // EC header: magic UBI#, version 1, ec, vid_hdr_offset 64,
        // data_offset 128, image_seq, hdr_crc over first 60 bytes.
        fn ec_header(ec: u64) -> Vec<u8> {
            let mut h = vec![0u8; 64];
            h[0..4].copy_from_slice(b"UBI#");
            h[4] = 1;
            h[8..16].copy_from_slice(&ec.to_be_bytes());
            h[16..20].copy_from_slice(&be32(64));
            h[20..24].copy_from_slice(&be32(128));
            h[24..28].copy_from_slice(&be32(0x1234));
            let crc = crc32(&h[..60]);
            h[60..64].copy_from_slice(&be32(crc));
            h
        }
        // VID header: magic UBI!, type, vol_id, lnum, hdr_crc.
        fn vid_header(vol_type: u8, vol_id: u32, lnum: u32, data_size: u32) -> Vec<u8> {
            let mut h = vec![0u8; 64];
            h[0..4].copy_from_slice(b"UBI!");
            h[4] = 1;
            h[5] = vol_type;
            h[8..12].copy_from_slice(&be32(vol_id));
            h[12..16].copy_from_slice(&be32(lnum));
            h[16..20].copy_from_slice(&be32(data_size));
            h[32..40].copy_from_slice(&1u64.to_be_bytes()); // sqnum
            let crc = crc32(&h[..60]);
            h[60..64].copy_from_slice(&be32(crc));
            h
        }

        // Volume table (128-byte records). One user volume: id 0,
        // reserved 2, dynamic, name "rootfs".
        let mut table = vec![0u8; 128 * 128];
        let rec = &mut table[0..128];
        rec[0..4].copy_from_slice(&be32(2)); // reserved_pebs
        rec[4..8].copy_from_slice(&be32(1)); // alignment
        rec[12] = 1; // dynamic
        rec[14..16].copy_from_slice(&6u16.to_be_bytes()); // name_len
        rec[16..22].copy_from_slice(b"rootfs");
        let crc = crc32(&rec[..124]);
        rec[124..128].copy_from_slice(&be32(crc));

        // PEB 0: layout lnum 0 (table copy 1), PEB 1: layout lnum 1.
        for peb in 0..2usize {
            let base = peb * PEB;
            img[base..base + 64].copy_from_slice(&ec_header(peb as u64));
            img[base + 64..base + 128].copy_from_slice(&vid_header(
                1,
                UBI_LAYOUT_VOLUME_ID,
                peb as u32,
                0,
            ));
            img[base + 128..base + 128 + table.len()].copy_from_slice(&table);
        }
        // PEB 2/3: user volume data.
        let d1 = b"UBI_VOL_DATA_1";
        let d2 = b"UBI_VOL_DATA_2";
        for (peb, d) in [(2, d1), (3, d2)] {
            let base = peb * PEB;
            img[base..base + 64].copy_from_slice(&ec_header(peb as u64));
            img[base + 64..base + 128].copy_from_slice(&vid_header(1, 0, (peb - 2) as u32, 0));
            img[base + 128..base + 128 + d.len()].copy_from_slice(d);
        }
        img
    }

    #[test]
    fn ubi_volume_table_and_extraction() {
        let src = ByteSource::from_vec(ubi_image());
        let out = validate_at(&UbiVolumeHandler, &src, 0).expect("ubi validates");
        let art = &out.artifacts[0];
        assert_eq!(art.confidence, Confidence::Validated);
        assert_eq!(
            art.metadata.get("peb_size").map(String::as_str),
            Some("16384")
        );
        assert_eq!(art.metadata.get("volumes").map(String::as_str), Some("1"));
        let vol = art
            .children
            .iter()
            .find(|c| c.metadata.get("volume_name").map(String::as_str) == Some("rootfs"))
            .expect("rootfs volume child");
        match &vol.content {
            ChildContent::Owned(d) => {
                // Both LEB data areas concatenated.
                // Each LEB contributes peb_size - data_offset bytes.
                let leb_data = 16384 - 128;
                assert_eq!(d.len(), 2 * leb_data);
                assert_eq!(&d[..14], b"UBI_VOL_DATA_1");
                assert_eq!(&d[leb_data..leb_data + 14], b"UBI_VOL_DATA_2");
            }
            _ => panic!("volume content must reconstruct"),
        }
    }

    /// Build a UBIFS image: LEB size 8 KiB, 6 LEBs. LEB 0 =
    /// superblock, LEB 1 = master (root index at LEB 3 offset 0),
    /// LEB 3 = index (one level-0 node with branches to two ino nodes,
    /// a dent node and a data node), LEB 4 = leaf nodes.
    fn ubifs_image() -> Vec<u8> {
        const LEB: usize = 8192;
        let mut img = vec![0xFFu8; 6 * LEB];

        fn crc32(b: &[u8]) -> u32 {
            let mut h = crc32fast::Hasher::new();
            h.update(b);
            h.finalize()
        }
        // Common header (24 bytes LE).
        fn ch(node_type: u8, len: usize) -> Vec<u8> {
            let mut c = vec![0u8; 24];
            c[0..4].copy_from_slice(&0x06101831u32.to_le_bytes());
            c[16..20].copy_from_slice(&(len as u32).to_le_bytes());
            c[20] = node_type;
            c
        }
        fn seal(mut node: Vec<u8>) -> Vec<u8> {
            let crc = crc32(&node[8..]);
            node[4..8].copy_from_slice(&crc.to_le_bytes());
            node
        }

        // Key: inum u32 LE; second u32 = type << 29 | payload.
        fn key(inum: u32, ktype: u32, payload: u32) -> [u8; 8] {
            let mut k = [0u8; 8];
            k[0..4].copy_from_slice(&inum.to_le_bytes());
            k[4..8].copy_from_slice(&((ktype << 29) | payload).to_le_bytes());
            k
        }

        // --- LEB 0: superblock node (36 bytes min; we emit 64) ---
        let mut sb = vec![0u8; 64];
        sb[0..24].copy_from_slice(&ch(6, 64));
        sb[27] = 0; // key_fmt = simple
        sb[36..40].copy_from_slice(&(LEB as u32).to_le_bytes()); // leb_size
        sb[40..44].copy_from_slice(&6u32.to_le_bytes()); // leb_cnt
        img[0..64].copy_from_slice(&seal(sb));

        // --- LEB 1: master node (36 bytes after ch) ---
        let mut mst = vec![0u8; 24 + 48];
        mst[0..24].copy_from_slice(&ch(7, 24 + 48));
        // highest_inum@24, cmt_no@32, flags@40? layout: ch(24),
        // highest_inum u64@24, cmt_no u64@32, then root_lnum@40... but
        // the handler reads root_lnum@36 which equals cmt_no low word.
        // Kernel mst: ch + highest_inum(8) + cmt_no(8) + flags(4) +
        // log_lnum(4) + root_lnum(4) + root_offs(4) + root_len(4).
        // ch=24 => highest_inum@24, cmt_no@32, flags@40, log_lnum@44,
        // root_lnum@48, root_offs@52, root_len@56.
        mst[24..32].copy_from_slice(&7u64.to_le_bytes()); // highest_inum
        mst[32..40].copy_from_slice(&1u64.to_le_bytes()); // cmt_no
        mst[40..44].copy_from_slice(&5u32.to_le_bytes()); // flags
        mst[44..48].copy_from_slice(&5u32.to_le_bytes()); // log_lnum
        mst[48..52].copy_from_slice(&3u32.to_le_bytes()); // root_lnum
        mst[52..56].copy_from_slice(&0u32.to_le_bytes()); // root_offs
        mst[56..60].copy_from_slice(&80u32.to_le_bytes()); // root_len
        mst[60..64].copy_from_slice(&4u32.to_le_bytes()); // gc_lnum
        mst[64..68].copy_from_slice(&3u32.to_le_bytes()); // ihead_lnum
        mst[68..72].copy_from_slice(&0u32.to_le_bytes()); // ihead_offs
        img[LEB..LEB + 72].copy_from_slice(&seal(mst.clone()));
        // Kernel keeps two copies (UBIFS_MST_LEBS = 2): LEB 2 = copy 2.
        img[2 * LEB..2 * LEB + 72].copy_from_slice(&seal(mst));

        // --- LEB 3: index node, 2 branches ---
        // Branches: LEB4 off 0 (ino of root dir), LEB4 off 96 (dent).
        // Leaf refs are (lnum, offs, len) — nodes at LEB 4 offset 0.
        let mut idx = vec![0u8; 28 + 2 * 20];
        idx[0..24].copy_from_slice(&ch(9, 28 + 2 * 20));
        // Branch 0: root dir ino node.
        idx[28..32].copy_from_slice(&4u32.to_le_bytes()); // lnum
        idx[32..36].copy_from_slice(&0u32.to_le_bytes()); // offs
        idx[36..40].copy_from_slice(&160u32.to_le_bytes()); // len
        idx[40..48].copy_from_slice(&key(1, 0, 0)); // INO key inum 1
                                                    // Branch 1: dent node "FLAG.TXT" (parent 1 -> ino 2).
        idx[48..52].copy_from_slice(&4u32.to_le_bytes());
        idx[52..56].copy_from_slice(&96u32.to_le_bytes());
        // Branch 1 filled after leaf layout is known (rebuilt below).
        img[3 * LEB..3 * LEB + idx.len()].copy_from_slice(&seal(idx));

        // --- LEB 4: leaf nodes ---
        // ino node of root dir (mode dir) at offset 0: 160 bytes.
        let mut ino1 = vec![0u8; 160];
        ino1[0..24].copy_from_slice(&ch(0, 160));
        ino1[24..40].copy_from_slice(&{
            let mut k = [0u8; 16];
            k[..8].copy_from_slice(&key(1, 0, 0));
            k
        });
        ino1[40..48].copy_from_slice(&2u64.to_le_bytes()); // creat_sqnum
        ino1[48..56].copy_from_slice(&0u64.to_le_bytes()); // size
        ino1[92..96].copy_from_slice(&2u32.to_le_bytes()); // nlink
        ino1[104..108].copy_from_slice(&0o040755u32.to_le_bytes()); // mode
        img[4 * LEB..4 * LEB + 160].copy_from_slice(&seal(ino1));

        // dent node at offset 160 (parent 1 -> ino 2, "FLAG.TXT",
        // type 0 = reg).
        let name = b"FLAG.TXT";
        // Layout: ch(24) + key(16) + inum(8) + pad(1) + type(1) +
        // nlen(2) + cookie(4) = 56; name follows.
        let dlen = 56 + name.len();
        let mut dent = vec![0u8; dlen];
        dent[0..24].copy_from_slice(&ch(2, dlen));
        dent[24..40].copy_from_slice(&{
            let mut k = [0u8; 16];
            k[..8].copy_from_slice(&key(1, 2, 0x11223344));
            k
        });
        dent[40..48].copy_from_slice(&2u64.to_le_bytes()); // inum
        dent[49] = 0; // ITYPE_REG
        dent[50..52].copy_from_slice(&(name.len() as u16).to_le_bytes()); // nlen
        dent[52..56].copy_from_slice(&7u32.to_le_bytes()); // cookie
        dent[56..56 + name.len()].copy_from_slice(name);
        img[4 * LEB + 160..4 * LEB + 160 + dlen].copy_from_slice(&seal(dent));

        // ino node of FLAG.TXT (size 0, no data) at offset 256: 160.
        let mut ino2 = vec![0u8; 160];
        ino2[0..24].copy_from_slice(&ch(0, 160));
        ino2[24..40].copy_from_slice(&{
            let mut k = [0u8; 16];
            k[..8].copy_from_slice(&key(2, 0, 0));
            k
        });
        ino2[48..56].copy_from_slice(&11u64.to_le_bytes()); // size
        ino2[92..96].copy_from_slice(&1u32.to_le_bytes()); // nlink
        ino2[104..108].copy_from_slice(&0o100644u32.to_le_bytes());
        img[4 * LEB + 256..4 * LEB + 256 + 160].copy_from_slice(&seal(ino2));

        // Inline data inside ino2: data_len@112, data@160. We placed
        // size 0 above; instead put a data node for the content.
        let content = b"UBIFS_FLAG!";
        let mut dat = vec![0u8; 48 + content.len()];
        dat[0..24].copy_from_slice(&ch(1, 48 + content.len()));
        dat[24..40].copy_from_slice(&{
            let mut k = [0u8; 16];
            k[..8].copy_from_slice(&key(2, 1, 0)); // DATA key block 0
            k
        });
        dat[40..44].copy_from_slice(&(content.len() as u32).to_le_bytes()); // size
        dat[44..46].copy_from_slice(&0u16.to_le_bytes()); // compr NONE
        dat[48..48 + content.len()].copy_from_slice(content);
        let dstart = 4 * LEB + 256 + 160;
        img[dstart..dstart + dat.len()].copy_from_slice(&seal(dat));
        // Fix branch 1 to point at the dent (offset 160, len dlen)
        // and add a third branch pointing at the data node.
        let mut idx = vec![0u8; 28 + 4 * 20];
        idx[0..24].copy_from_slice(&ch(9, 28 + 4 * 20));
        idx[24..26].copy_from_slice(&4u16.to_le_bytes());
        idx[26..28].copy_from_slice(&0u16.to_le_bytes());
        // b0: root ino
        idx[28..32].copy_from_slice(&4u32.to_le_bytes());
        idx[32..36].copy_from_slice(&0u32.to_le_bytes());
        idx[36..40].copy_from_slice(&160u32.to_le_bytes());
        idx[40..48].copy_from_slice(&key(1, 0, 0));
        // b1: dent of FLAG.TXT
        idx[48..52].copy_from_slice(&4u32.to_le_bytes());
        idx[52..56].copy_from_slice(&160u32.to_le_bytes());
        idx[56..60].copy_from_slice(&(dlen as u32).to_le_bytes());
        idx[60..68].copy_from_slice(&key(1, 2, 0x11223344));
        // b2: data node of ino 2
        idx[68..72].copy_from_slice(&4u32.to_le_bytes());
        idx[72..76].copy_from_slice(&((256 + 160) as u32).to_le_bytes());
        idx[76..80].copy_from_slice(&((48 + content.len()) as u32).to_le_bytes());
        idx[80..88].copy_from_slice(&key(2, 1, 0));
        // b3: ino node of inum 2
        idx[88..92].copy_from_slice(&4u32.to_le_bytes());
        idx[92..96].copy_from_slice(&256u32.to_le_bytes());
        idx[96..100].copy_from_slice(&160u32.to_le_bytes());
        idx[100..108].copy_from_slice(&key(2, 0, 0));
        let idx_len = idx.len();
        img[3 * LEB..3 * LEB + idx_len].copy_from_slice(&seal(idx));
        // Master root_len must match the final index node length.
        img[LEB + 56..LEB + 60].copy_from_slice(&(idx_len as u32).to_le_bytes());
        img[2 * LEB + 56..2 * LEB + 60].copy_from_slice(&(idx_len as u32).to_le_bytes());
        // Re-seal both master copies (root_len changed after sealing).
        for lnum in 1..=2usize {
            let b = lnum * LEB;
            let crc = crc32(&img[b + 8..b + 72]);
            img[b + 4..b + 8].copy_from_slice(&crc.to_le_bytes());
        }

        img
    }

    #[test]
    fn ubifs_tree_walk_with_data_node() {
        let src = ByteSource::from_vec(ubifs_image());
        let out = validate_at(&UbifsHandler, &src, 0).expect("ubifs validates");
        let art = &out.artifacts[0];
        assert_eq!(
            art.metadata.get("leb_size").map(String::as_str),
            Some("8192")
        );
        let flag = art
            .children
            .iter()
            .find(|c| c.metadata.get("path").map(String::as_str) == Some("FLAG.TXT"))
            .expect("FLAG.TXT child");
        match &flag.content {
            ChildContent::Owned(d) => assert_eq!(d, b"UBIFS_FLAG!"),
            _ => panic!("file content must reconstruct"),
        }
    }

    #[test]
    fn iso_recursive_traversal() {
        let src = ByteSource::from_vec(iso_image(false));
        let pvd = 16 * 2048;
        let out = validate_at(&Iso9660Handler, &src, pvd as u64).expect("iso validates");
        let art = &out.artifacts[0];
        assert_eq!(art.confidence, Confidence::Validated);
        assert_eq!(
            art.metadata.get("volume_id").map(String::as_str),
            Some("CTF_IMAGE")
        );
        assert_eq!(
            art.metadata.get("joliet").map(String::as_str),
            Some("false")
        );
        let flag = art
            .children
            .iter()
            .find(|c| c.metadata.get("path").map(String::as_str) == Some("FLAG.TXT"))
            .expect("FLAG.TXT child");
        assert_eq!(flag.size, 10);
        match &flag.content {
            ChildContent::Source(r) => {
                let mut buf = [0u8; 10];
                r.read_at(0, &mut buf).unwrap();
                assert_eq!(&buf, b"ISO_FLAG1!");
            }
            _ => panic!("file must be source-backed"),
        }
        let nested = art
            .children
            .iter()
            .find(|c| c.metadata.get("path").map(String::as_str) == Some("DIR/NESTED.TXT"))
            .expect("nested child");
        assert_eq!(nested.size, 12);
        match &nested.content {
            ChildContent::Source(r) => {
                let mut buf = [0u8; 12];
                r.read_at(0, &mut buf).unwrap();
                assert_eq!(&buf, b"ISO_NESTED!!");
            }
            _ => panic!("nested file must be source-backed"),
        }
    }

    #[test]
    fn iso_joliet_tree_preferred() {
        let src = ByteSource::from_vec(iso_image(true));
        let pvd = 16 * 2048;
        let out = validate_at(&Iso9660Handler, &src, pvd as u64).expect("iso validates");
        let art = &out.artifacts[0];
        assert_eq!(art.confidence, Confidence::Validated);
        assert_eq!(art.metadata.get("joliet").map(String::as_str), Some("true"));
        assert_eq!(
            art.metadata.get("joliet_volume_id").map(String::as_str),
            Some("CTF_ISO")
        );
        // The Joliet tree lives at LBA 20/22; FLAG.TXT must come from
        // there (content identical, but the extent metadata differs).
        let flag = art
            .children
            .iter()
            .find(|c| c.metadata.get("path").map(String::as_str) == Some("FLAG.TXT"))
            .expect("FLAG.TXT in joliet tree");
        assert_eq!(
            flag.metadata.get("extent_lba").map(String::as_str),
            Some("22")
        );
        let dir = art
            .children
            .iter()
            .find(|c| c.metadata.get("path").map(String::as_str) == Some("DIR"))
            .expect("DIR in joliet tree");
        assert_eq!(
            dir.metadata.get("type").map(String::as_str),
            Some("directory")
        );
    }

    /// Build a JFFS2 image. Nodes are written little-structured:
    /// magic/nodetype/totlen/hdr_crc big-endian, everything else
    /// big-endian too (jint* are big-endian on-disk).
    fn jffs2_image() -> Vec<u8> {
        fn crc32(b: &[u8]) -> u32 {
            let mut h = crc32fast::Hasher::new();
            h.update(b);
            h.finalize()
        }
        // Write one node. `kind`: b"d" dirent, b"i" inode.
        // hdr_crc is computed with ACCURATE forced (like scan.c).
        fn dirent(img: &mut Vec<u8>, pino: u32, ino: u32, version: u32, dtype: u8, name: &[u8]) {
            let totlen = 40 + name.len();
            let mut h = [0u8; 40];
            h[0..2].copy_from_slice(&0x1985u16.to_be_bytes());
            h[2..4].copy_from_slice(&0xe001u16.to_be_bytes());
            h[4..8].copy_from_slice(&(totlen as u32).to_be_bytes());
            // hdr_crc over first 8 bytes with ACCURATE forced (already set).
            let hdr_crc = crc32(&h[..8]);
            h[8..12].copy_from_slice(&hdr_crc.to_be_bytes());
            h[12..16].copy_from_slice(&pino.to_be_bytes());
            h[16..20].copy_from_slice(&version.to_be_bytes());
            h[20..24].copy_from_slice(&ino.to_be_bytes());
            h[24..28].copy_from_slice(&0u32.to_be_bytes()); // mctime
            h[28] = name.len() as u8;
            h[29] = dtype;
            let node_crc = crc32(&h[..32]);
            let name_crc = crc32(name);
            h[32..36].copy_from_slice(&node_crc.to_be_bytes());
            h[36..40].copy_from_slice(&name_crc.to_be_bytes());
            let start = img.len();
            img.extend_from_slice(&h);
            img.extend_from_slice(name);
            // Pad nodes to 4 bytes.
            while (img.len() - start) % 4 != 0 {
                img.push(0);
            }
        }
        fn inode(
            img: &mut Vec<u8>,
            ino: u32,
            version: u32,
            offset: u32,
            dsize: u32,
            compr: u8,
            payload: &[u8],
        ) {
            let isize = offset + dsize;
            let totlen = 68 + payload.len();
            let mut h = [0u8; 68];
            h[0..2].copy_from_slice(&0x1985u16.to_be_bytes());
            h[2..4].copy_from_slice(&0xe002u16.to_be_bytes());
            h[4..8].copy_from_slice(&(totlen as u32).to_be_bytes());
            let hdr_crc = crc32(&h[..8]);
            h[8..12].copy_from_slice(&hdr_crc.to_be_bytes());
            h[12..16].copy_from_slice(&ino.to_be_bytes());
            h[16..20].copy_from_slice(&version.to_be_bytes());
            h[20..24].copy_from_slice(&0o100644u32.to_be_bytes()); // mode
            h[28..32].copy_from_slice(&isize.to_be_bytes()); // isize
            h[44..48].copy_from_slice(&offset.to_be_bytes());
            h[48..52].copy_from_slice(&(payload.len() as u32).to_be_bytes()); // csize
            h[52..56].copy_from_slice(&dsize.to_be_bytes()); // dsize
            h[56] = compr;
            let data_crc = crc32(payload);
            h[60..64].copy_from_slice(&data_crc.to_be_bytes()); // data_crc
            let node_crc = crc32(&h[..60]);
            h[64..68].copy_from_slice(&node_crc.to_be_bytes()); // node_crc
            let start = img.len();
            img.extend_from_slice(&h);
            img.extend_from_slice(payload);
            while (img.len() - start) % 4 != 0 {
                img.push(0);
            }
        }

        let mut img = Vec::new();
        // Root dir ino 1, children: FLAG.TXT (ino 2, plain), RTIME.BIN
        // (ino 3, rtime-compressed), SUB (dir ino 4), ZLIB.BIN (ino 5,
        // zlib). DIR/NESTED.TXT (ino 6). One stale dirent for ino 2
        // with lower version, then a final dirent rename is covered by
        // version ordering; plus an unlink node for a temp name.
        dirent(&mut img, 1, 2, 1, 8, b"FLAG.TXT");
        inode(&mut img, 2, 1, 0, 11, 0, b"JFFS2_FLAG!");
        dirent(&mut img, 1, 4, 2, 4, b"SUB");
        dirent(&mut img, 4, 6, 1, 8, b"NESTED.TXT");
        inode(&mut img, 6, 1, 0, 13, 0, b"JFFS2_NESTED!");

        // RTIME-compressed "AAAAABBBBB" (10 bytes). Encoder: value,
        // run pairs with backrefs via positions table.
        let raw = b"AAAAABBBBB";
        let mut comp: Vec<u8> = Vec::new();
        let mut positions = [0u16; 256];
        let mut pos = 0usize;
        let data = raw.to_vec();
        while pos < data.len() {
            let value = data[pos];
            comp.push(value);
            pos += 1;
            let backpos = positions[value as usize] as usize;
            positions[value as usize] = pos as u16;
            let mut runlen = 0u8;
            while pos < data.len() && runlen < 255 && data[pos] == data[backpos + runlen as usize] {
                pos += 1;
                runlen += 1;
            }
            comp.push(runlen);
        }
        dirent(&mut img, 1, 3, 1, 8, b"RTIME.BIN");
        inode(&mut img, 3, 1, 0, 10, 2, &comp);

        // ZLIB-compressed payload.
        use std::io::Write as _;
        let mut enc = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
        enc.write_all(b"JFFS2_ZLIB_CONTENT").unwrap();
        let z = enc.finish().unwrap();
        dirent(&mut img, 1, 5, 1, 8, b"ZLIB.BIN");
        inode(&mut img, 5, 1, 0, 18, 6, &z);

        // Unlink: dirent with ino 0 removes "GONE.TXT".
        dirent(&mut img, 1, 7, 1, 8, b"GONE.TXT");
        inode(&mut img, 7, 1, 0, 4, 0, b"BYE!");
        dirent(&mut img, 1, 0, 2, 8, b"GONE.TXT");

        img
    }

    #[test]
    fn jffs2_full_traversal() {
        let src = ByteSource::from_vec(jffs2_image());
        let out = validate_at(&Jffs2Handler, &src, 0).expect("jffs2 validates");
        let art = &out.artifacts[0];
        assert_eq!(art.confidence, Confidence::Validated);
        let flag = art
            .children
            .iter()
            .find(|c| c.metadata.get("path").map(String::as_str) == Some("FLAG.TXT"))
            .expect("FLAG.TXT child");
        match &flag.content {
            ChildContent::Owned(d) => assert_eq!(d, b"JFFS2_FLAG!"),
            _ => panic!("file content must reconstruct"),
        }
        let nested = art
            .children
            .iter()
            .find(|c| c.metadata.get("path").map(String::as_str) == Some("SUB/NESTED.TXT"))
            .expect("nested child");
        match &nested.content {
            ChildContent::Owned(d) => assert_eq!(d, b"JFFS2_NESTED!"),
            _ => panic!("nested content must reconstruct"),
        }
        let rtime = art
            .children
            .iter()
            .find(|c| c.metadata.get("path").map(String::as_str) == Some("RTIME.BIN"))
            .expect("RTIME.BIN child");
        match &rtime.content {
            ChildContent::Owned(d) => assert_eq!(d, b"AAAAABBBBB"),
            _ => panic!("rtime content must reconstruct"),
        }
        let zlib = art
            .children
            .iter()
            .find(|c| c.metadata.get("path").map(String::as_str) == Some("ZLIB.BIN"))
            .expect("ZLIB.BIN child");
        match &zlib.content {
            ChildContent::Owned(d) => assert_eq!(d, b"JFFS2_ZLIB_CONTENT"),
            _ => panic!("zlib content must reconstruct"),
        }
        // The unlinked name must not appear.
        assert!(art
            .children
            .iter()
            .all(|c| c.metadata.get("path").map(String::as_str) != Some("GONE.TXT")));
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
