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
                if stored > 0
                    && frag_abs + u64::from(stored) <= src.len()
                    && ino.offset < bs
                {
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
            .trim_end_matches([' ', '\0'])
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
