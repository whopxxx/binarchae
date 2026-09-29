//! ROMFS read-only traversal (Issue #7 §1.8).
//!
//! Layout verified against Linux `fs/romfs/super.c` and
//! `include/uapi/linux/romfs_fs.h`:
//! - superblock at 0: `-rom1fs-` (be32 words "-rom" + "1fs-"),
//!   full_size be32 @8, checksum be32 @12, volume name NUL-terminated @16;
//! - superblock checksum = sum of big-endian words over the first
//!   min(512, size) bytes; a nonzero sum means "unchecked/damaged" (the
//!   kernel only warns, so we downgrade rather than reject);
//! - root inode position = round_up(16 + namelen + 1, 16);
//! - inode: next be32 (low 4 bits: type + exec flag; masked value = next
//!   entry offset), spec be32, size be32, checksum be32, name;
//!   metasize = round_up(16 + namelen + 1, 16);
//! - directories chain through `next & !15` (0 = end); the first child
//!   sits at `spec & !15`; hard links (type 0) resolve through `spec`;
//! - regular files store data at their own position + metasize, length
//!   `size`; symlinks store the target the same way;
//! - inode checksum = sum of the four be32 header words == 0.

use crate::artifact::{Confidence, Evidence, RelationKind};
use crate::bytesource::ByteSource;
use crate::engine::{
    ArtifactDraft, Budget, Candidate, ChildContent, ChildDraft, Handler, HandlerOutput,
};
use crate::error::{Error, Result};
use crate::handlers::find_all;
use std::collections::BTreeMap;

pub struct RomfsHandler;

const FH_SIZE: u64 = 16;
const FH_MASK: u64 = !15;
const MAX_HARDLINK_DEPTH: u32 = 64;

/// File types in the low bits of `next`.
const FH_HRD: u64 = 0;
const FH_DIR: u64 = 1;
const FH_REG: u64 = 2;
const FH_SYM: u64 = 3;

fn be32(src: &ByteSource, off: u64) -> Option<u32> {
    let mut b = [0u8; 4];
    src.read_at(off, &mut b).ok()?;
    Some(u32::from_be_bytes(b))
}

/// Kernel `romfs_checksum`: sum of big-endian words. 0 = valid.
fn romfs_checksum(src: &ByteSource, off: u64, len: u64) -> Option<u32> {
    let mut sum: u32 = 0;
    let mut pos = 0u64;
    while pos + 4 <= len {
        let v = be32(src, off + pos)?;
        sum = sum.wrapping_add(v);
        pos += 4;
    }
    Some(sum)
}

/// Parsed inode header + name.
struct RomInode {
    /// Position of the inode header (after hard-link resolution).
    pos: u64,
    ftype: u64,
    /// Raw `spec` field (relative offset, type bits masked off).
    spec_raw: u64,
    /// Raw `next` field (relative offset, type bits masked off).
    next_raw: u64,
    size: u64,
    /// Metadata size: position of the entry's data (or next inode).
    metasize: u64,
    name: String,
}

/// Convert an absolute `end` position back to a relative size for the
/// loop bound (root-relative disk offsets are absolute - base).
fn full_size_of(end: u64, base: u64) -> u64 {
    end.saturating_sub(base)
}

impl RomfsHandler {
    /// Read an inode whose header sits at absolute position `pos`.
    /// `next`/`spec` fields stay in raw (relative) form; callers add
    /// `base` when converting them to positions.
    fn read_inode(src: &ByteSource, pos: u64, end: u64) -> Result<RomInode> {
        if pos.checked_add(FH_SIZE).map_or(true, |e| e > end) || pos + FH_SIZE > src.len() {
            return Err(Error::Validation {
                format: "romfs",
                reason: format!("inode header at {pos} out of bounds"),
            });
        }
        let next = be32(src, pos).unwrap_or(0) as u64;
        let spec_raw = be32(src, pos + 4).unwrap_or(0) as u64;
        let size = be32(src, pos + 8).unwrap_or(0) as u64;
        // Name: NUL-terminated, hard-capped at 128 (ROMFS_MAXFN).
        let max_name = 128u64.min(end.saturating_sub(pos + FH_SIZE));
        let mut name_bytes = Vec::new();
        let mut i = 0u64;
        while i < max_name {
            let mut b = [0u8; 1];
            src.read_at(pos + FH_SIZE + i, &mut b)?;
            if b[0] == 0 {
                break;
            }
            name_bytes.push(b[0]);
            i += 1;
        }
        if i >= max_name && max_name > 0 {
            // No NUL terminator inside the cap: hostile/undecodable.
            return Err(Error::Validation {
                format: "romfs",
                reason: format!("inode name at {pos} lacks NUL terminator"),
            });
        }
        let name = String::from_utf8_lossy(&name_bytes).into_owned();
        let metasize = (FH_SIZE + i + 1 + 15) & FH_MASK;
        Ok(RomInode {
            pos,
            ftype: next & 7,
            // Raw spec field (relative offset, masked).
            spec_raw: spec_raw & FH_MASK,
            // Raw next field (relative offset, masked).
            next_raw: next & FH_MASK,
            size,
            metasize,
            name,
        })
    }

    /// Resolve hard links (type 0): jump to `spec` until a non-link type
    /// or the link-depth cap (kernel ROMFS_MAX_HARDLINK_DEPTH = 64).
    /// `base` is the image start; disk offsets are relative to it.
    fn resolve(src: &ByteSource, pos: u64, base: u64, end: u64) -> Result<RomInode> {
        let mut node = Self::read_inode(src, pos, end)?;
        let mut hops = 0;
        while node.ftype == FH_HRD {
            hops += 1;
            if node.spec_raw == 0 {
                return Err(Error::Validation {
                    format: "romfs",
                    reason: format!("hard-link chain at {pos} has no target"),
                });
            }
            if hops > MAX_HARDLINK_DEPTH {
                return Err(Error::Validation {
                    format: "romfs",
                    reason: format!("hard-link chain at {pos} unresolved after {hops} hops"),
                });
            }
            node = Self::read_inode(src, base + node.spec_raw, end)?;
        }
        Ok(node)
    }

    /// Walk a directory chain starting at relative offset `dir_pos_rel`.
    #[allow(clippy::too_many_arguments)]
    fn walk_dir(
        src: &ByteSource,
        base: u64,
        dir_pos_rel: u64,
        end: u64,
        path: &str,
        depth: u32,
        limits: &crate::engine::EngineLimits,
        _budget: &mut Budget,
        warnings: &mut Vec<String>,
        out: &mut Vec<ChildDraft>,
    ) -> Result<()> {
        if depth > 16 {
            warnings.push("directory nesting deeper than 16 not walked".to_string());
            return Ok(());
        }
        let mut pos_rel = dir_pos_rel;
        let mut visited = 0usize;
        loop {
            if out.len() >= limits.max_fs_entries {
                warnings.push("max_fs_entries reached; directory walk truncated".to_string());
                return Ok(());
            }
            visited += 1;
            if visited > limits.max_fs_entries + 1 {
                return Err(Error::Validation {
                    format: "romfs",
                    reason: format!("directory chain at {dir_pos_rel} does not terminate"),
                });
            }
            if pos_rel == 0 || pos_rel >= full_size_of(end, base) {
                break; // next == 0 ends the directory (kernel contract)
            }
            let raw = Self::read_inode(src, base + pos_rel, end)?;
            // Inode header checksum: sum of the four words must be 0.
            if romfs_checksum(src, raw.pos, FH_SIZE) != Some(0) {
                warnings.push(format!(
                    "inode checksum mismatch at {} ({})",
                    raw.pos, raw.name
                ));
            }
            // Resolve hard links before dispatching on type.
            let node = Self::resolve(src, raw.pos, base, end)?;
            let child_path = if path.is_empty() {
                raw.name.clone()
            } else {
                format!("{path}/{}", raw.name)
            };
            let mut meta = BTreeMap::new();
            meta.insert("path".to_string(), child_path.clone());
            match node.ftype {
                FH_DIR => {
                    meta.insert("type".to_string(), "directory".to_string());
                    out.push(ChildDraft {
                        relation: RelationKind::FilesystemEntry,
                        label: format!("romfs directory {child_path}"),
                        format_hint: "metadata",
                        content: ChildContent::Owned(Vec::new()),
                        size: 0,
                        metadata: meta,
                        warnings: Vec::new(),
                        entry_name: Some(raw.name.clone()),
                        confidence: Confidence::Validated,
                        evidence: vec!["structurally decoded by parent handler".to_string()],
                    });
                    if node.spec_raw != 0 {
                        Self::walk_dir(
                            src,
                            base,
                            node.spec_raw,
                            end,
                            &child_path,
                            depth + 1,
                            limits,
                            _budget,
                            warnings,
                            out,
                        )?;
                    }
                }
                FH_REG | FH_SYM => {
                    meta.insert(
                        "type".to_string(),
                        if node.ftype == FH_REG {
                            "file".to_string()
                        } else {
                            "symlink".to_string()
                        },
                    );
                    Self::emit_data(
                        src,
                        &node,
                        &raw.name,
                        &child_path,
                        meta,
                        warnings,
                        out,
                        limits,
                    );
                }
                _ => {
                    // Block/char devices, FIFOs, sockets: metadata only;
                    // never materialized as host special files.
                    meta.insert("type".to_string(), "special".to_string());
                    meta.insert(
                        "device_or_kind".to_string(),
                        format!("romfs type {}", node.ftype),
                    );
                    out.push(ChildDraft {
                        relation: RelationKind::FilesystemEntry,
                        label: format!("romfs special entry {child_path}"),
                        format_hint: "metadata",
                        content: ChildContent::Owned(Vec::new()),
                        size: 0,
                        metadata: meta,
                        warnings: vec!["special entries are never materialized".to_string()],
                        entry_name: Some(raw.name.clone()),
                        confidence: Confidence::Validated,
                        evidence: vec!["structurally decoded by parent handler".to_string()],
                    });
                }
            }
            // Advance along the sibling chain.
            pos_rel = node.next_raw;
        }
        Ok(())
    }

    /// Emit a regular-file or symlink child. Contiguous by definition:
    /// data sits directly after the inode's name. Source-backed when it
    /// fits both the source and max_child_size; metadata-only otherwise.
    #[allow(clippy::too_many_arguments)]
    fn emit_data(
        src: &ByteSource,
        node: &RomInode,
        name: &str,
        path: &str,
        mut meta: BTreeMap<String, String>,
        warnings: &mut Vec<String>,
        out: &mut Vec<ChildDraft>,
        limits: &crate::engine::EngineLimits,
    ) {
        let data_off = node.pos + node.metasize;
        meta.insert("declared_size".to_string(), node.size.to_string());
        let kind = if node.ftype == FH_REG {
            "file"
        } else {
            "symlink"
        };
        let over_child_cap = node.size > limits.max_child_size;
        let in_bounds = data_off
            .checked_add(node.size)
            .is_some_and(|e| e <= src.len());
        if node.size == 0 {
            out.push(ChildDraft {
                relation: RelationKind::FilesystemEntry,
                label: format!("romfs {kind} {path} (0 bytes)"),
                format_hint: "raw",
                content: ChildContent::Owned(Vec::new()),
                size: 0,
                metadata: meta,
                warnings: Vec::new(),
                entry_name: Some(name.to_string()),
                confidence: Confidence::Validated,
                evidence: vec!["structurally decoded by parent handler".to_string()],
            });
            return;
        }
        if in_bounds && !over_child_cap {
            let region = match src.slice(data_off, node.size) {
                Ok(r) => r,
                Err(_) => {
                    warnings.push(format!("romfs {kind} {path}: data extent unreadable"));
                    return;
                }
            };
            out.push(ChildDraft {
                relation: RelationKind::FilesystemEntry,
                label: format!("romfs {kind} {path} ({} bytes)", node.size),
                format_hint: "raw",
                content: ChildContent::Source(region),
                size: node.size,
                metadata: meta,
                warnings: Vec::new(),
                entry_name: Some(name.to_string()),
                confidence: Confidence::Validated,
                evidence: vec!["structurally decoded by parent handler".to_string()],
            });
        } else {
            if over_child_cap {
                warnings.push(format!(
                    "romfs {kind} {path}: {} bytes exceed max_child_size; data not exposed",
                    node.size
                ));
            } else {
                warnings.push(format!("romfs {kind} {path}: data extent past source"));
            }
            out.push(ChildDraft {
                relation: RelationKind::FilesystemEntry,
                label: format!("romfs {kind} {path} (metadata only)"),
                format_hint: "metadata",
                content: ChildContent::Owned(Vec::new()),
                size: 0,
                metadata: meta,
                warnings: Vec::new(),
                entry_name: Some(name.to_string()),
                confidence: Confidence::Validated,
                evidence: vec!["structurally decoded by parent handler".to_string()],
            });
        }
    }
}

impl Handler for RomfsHandler {
    fn format(&self) -> &'static str {
        "romfs"
    }

    fn find_candidates(&self, src: &ByteSource) -> Vec<Candidate> {
        find_all(src, b"-rom1fs-")
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
        if base + 16 > src.len() {
            return Err(Error::Validation {
                format: "romfs",
                reason: "superblock truncated".into(),
            });
        }
        let full_size = be32(src, base + 8).unwrap_or(0) as u64;
        if full_size == 0 || base.checked_add(full_size).map_or(true, |e| e > src.len()) {
            return Err(Error::Validation {
                format: "romfs",
                reason: format!("full_size {full_size} inconsistent with source"),
            });
        }
        let end = base + full_size;
        // Superblock checksum over min(512, size) bytes; 0 = valid. The
        // kernel only warns, so a mismatch downgrades confidence.
        let ck_len = full_size.min(512);
        let sb_checksum_ok = romfs_checksum(src, base, ck_len) == Some(0);

        // Volume name: NUL-terminated from +16.
        let max_name = 128u64.min(full_size.saturating_sub(16));
        let mut name_len = 0u64;
        while name_len < max_name {
            let mut b = [0u8; 1];
            src.read_at(base + 16 + name_len, &mut b)?;
            if b[0] == 0 {
                break;
            }
            name_len += 1;
        }
        let volume_name = {
            let mut buf = vec![0u8; name_len as usize];
            src.read_at(base + 16, &mut buf)?;
            String::from_utf8_lossy(&buf).into_owned()
        };

        // Root inode: round_up(16 + namelen + 1, 16) after superblock base.
        let root_pos = base + ((FH_SIZE + name_len + 1 + 15) & FH_MASK);
        let root = Self::read_inode(src, root_pos, end)?;
        if root.ftype != FH_DIR {
            return Err(Error::Validation {
                format: "romfs",
                reason: format!("root inode type {} is not a directory", root.ftype),
            });
        }

        let mut children = Vec::new();
        let mut warnings = Vec::new();
        if root.spec_raw != 0 {
            Self::walk_dir(
                src,
                base,
                root.spec_raw,
                end,
                "",
                0,
                limits,
                budget,
                &mut warnings,
                &mut children,
            )?;
        }

        let mut metadata = BTreeMap::new();
        metadata.insert("volume_name".to_string(), volume_name.clone());
        metadata.insert("full_size".to_string(), full_size.to_string());
        metadata.insert("entries".to_string(), children.len().to_string());
        if !sb_checksum_ok {
            metadata.insert("superblock_checksum".to_string(), "invalid".to_string());
        }

        let confidence = if sb_checksum_ok {
            Confidence::Validated
        } else {
            // Checksum damage: structure walked but header sums fail.
            Confidence::Partial
        };
        let mut evidence = vec![
            "romfs superblock magic '-rom1fs-' validated".to_string(),
            format!("volume name {volume_name:?}"),
            format!(
                "full_size {full_size}; superblock checksum {}",
                if sb_checksum_ok {
                    "ok"
                } else {
                    "invalid (kernel-tolerated)"
                }
            ),
            format!("root directory at {}", root.pos - base),
        ];

        // Checksum-invalid images with no traversable entries stay honest.
        if !sb_checksum_ok && children.is_empty() {
            evidence.push("no entries traversable from checksum-damaged superblock".to_string());
        }

        Ok(HandlerOutput {
            artifacts: vec![ArtifactDraft {
                format: "romfs".to_string(),
                label: format!("ROMFS image \"{volume_name}\" ({} entries)", children.len()),
                offset: base,
                size: full_size,
                confidence,
                evidence: Evidence::facts(evidence),
                metadata,
                warnings,
                errors: Vec::new(),
                children,
                entry_names: Vec::new(),
            }],
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn validate_at(src: &ByteSource, off: u64) -> Result<HandlerOutput> {
        RomfsHandler.validate(
            src,
            Candidate { offset: off },
            &crate::engine::EngineLimits::default(),
            &mut Budget::default(),
        )
    }

    /// Write a big-endian u32.
    fn put_be32(buf: &mut [u8], off: usize, v: u32) {
        buf[off..off + 4].copy_from_slice(&v.to_be_bytes());
    }

    /// Zero the four header words, sum them, store the negation — this is
    /// exactly how the kernel validates a romfs checksum.
    fn seal_checksum(buf: &mut [u8], off: usize) {
        let mut sum: u32 = 0;
        for i in 0..4 {
            let mut w = [0u8; 4];
            w.copy_from_slice(&buf[off + i * 4..off + i * 4 + 4]);
            // Temporarily zero the stored checksum field (word 3) while
            // computing, per the on-disk convention.
            if i == 3 {
                w = [0, 0, 0, 0];
            }
            sum = sum.wrapping_add(u32::from_be_bytes(w));
        }
        put_be32(buf, off + 12, sum.wrapping_neg());
    }

    /// Build a romfs image:
    ///   /dir (dir)
    ///     /dir/hello.txt  "HELLO_ROMFS"
    ///   /flag.txt         "FLAG{romfs}"
    ///   /link -> /flag.txt (symlink)
    ///   /null (char device, metadata only)
    fn romfs_image() -> Vec<u8> {
        // Sequential layout — file data directly follows its own inode's
        // name (kernel: i_dataoffset = pos + metasize):
        //   0..16   superblock header; 16..25 name "CTFROMFS\0"; pad -> 32
        //   32      root inode (dir), first child at 48
        //   48      hello.txt (reg)   data @ 80 (11 bytes) -> next free 96
        //   96      flag.txt (reg)    data @128 (11 bytes) -> next free 144
        //   144     link (sym)        data @176 ("/flag.txt\0") -> next 192
        //   192     null (char dev)   -> next free 224
        //   224     dir (dir)         first child @256
        //   256     dir/hello.txt     data @288 (11 bytes) -> end 304
        let total = 304usize;
        let mut img = vec![0u8; total];
        img[0..4].copy_from_slice(b"-rom");
        img[4..8].copy_from_slice(b"1fs-");
        put_be32(&mut img, 8, total as u32);
        img[16..24].copy_from_slice(b"CTFROMFS");
        img[24] = 0;

        let mut inode = |off: usize, next: u32, spec: u32, size: u32, name: &[u8]| {
            put_be32(&mut img, off, next);
            put_be32(&mut img, off + 4, spec);
            put_be32(&mut img, off + 8, size);
            img[off + 16..off + 16 + name.len()].copy_from_slice(name);
            img[off + 16 + name.len()] = 0;
            seal_checksum(&mut img, off);
        };

        // Root: next = FH_DIR (1) | end-of-chain 0, spec = 48 (first child).
        inode(32, 1, 48, 0, b"/");
        // Root children chain: hello.txt -> flag.txt -> link -> null -> dir.
        inode(48, 96 | FH_REG as u32, 0, 11, b"hello.txt");
        inode(96, 144 | FH_REG as u32, 0, 11, b"flag.txt");
        inode(144, 192 | FH_SYM as u32, 0, 10, b"link");
        inode(192, 224 | 4, 0, 0, b"null"); // type 4 = ROMFH_BLK (device)
        inode(224, FH_DIR as u32, 256, 0, b"dir");
        // /dir children: single reg entry, next=0.
        inode(256, FH_REG as u32, 0, 11, b"hello.txt");

        // Data (each directly after its own inode's name, 16-aligned).
        img[80..91].copy_from_slice(b"HELLO_ROMFS");
        img[128..139].copy_from_slice(b"FLAG{romfs}");
        img[176..185].copy_from_slice(b"/flag.txt");
        img[185] = 0;
        img[288..299].copy_from_slice(b"HELLO_ROMFS");

        // Superblock checksum LAST (mkromfs convention): sum of be32
        // words over min(512, full_size) with the checksum field read as
        // zero; the stored value is the negation of that sum.
        {
            let cover = total.min(512) / 4;
            let mut sum: u32 = 0;
            for w in 0..cover {
                if w != 3 {
                    sum = sum.wrapping_add(u32::from_be_bytes(
                        img[w * 4..w * 4 + 4].try_into().unwrap(),
                    ));
                }
            }
            put_be32(&mut img, 12, sum.wrapping_neg());
        }
        img
    }

    #[test]
    fn romfs_full_traversal() {
        let src = ByteSource::from_vec(romfs_image());
        let out = validate_at(&src, 0).expect("romfs validates");
        let art = &out.artifacts[0];
        assert_eq!(art.confidence, Confidence::Validated);
        assert_eq!(
            art.metadata.get("volume_name").map(String::as_str),
            Some("CTFROMFS")
        );
        // Files are source-backed with correct bytes.
        let flag = art
            .children
            .iter()
            .find(|c| c.metadata.get("path").map(String::as_str) == Some("flag.txt"))
            .expect("flag.txt child");
        match &flag.content {
            ChildContent::Source(r) => assert_eq!(r.read_all().unwrap(), b"FLAG{romfs}".to_vec()),
            _ => panic!("regular file must be source-backed"),
        }
        // Nested directory file found with full path.
        let nested = art
            .children
            .iter()
            .find(|c| c.metadata.get("path").map(String::as_str) == Some("dir/hello.txt"))
            .expect("nested file child");
        assert_eq!(nested.size, 11);
        // Symlink exposes its target as data with symlink type.
        let link = art
            .children
            .iter()
            .find(|c| c.metadata.get("type").map(String::as_str) == Some("symlink"))
            .expect("symlink child");
        match &link.content {
            // Stored target includes its NUL (mkromfs convention, size=10).
            ChildContent::Source(r) => {
                assert_eq!(r.read_all().unwrap(), b"/flag.txt\0".to_vec())
            }
            _ => panic!("symlink target must be readable"),
        }
        // Special entry present, never materialized.
        let dev = art
            .children
            .iter()
            .find(|c| c.metadata.get("type").map(String::as_str) == Some("special"))
            .expect("device child");
        assert!(dev
            .warnings
            .iter()
            .any(|w| w.contains("never materialized")));
        assert_eq!(art.metadata.get("entries").map(String::as_str), Some("6"));
    }

    #[test]
    fn romfs_bad_checksum_downgrades_not_rejects() {
        let mut img = romfs_image();
        // Corrupt the superblock checksum field (offset 12).
        put_be32(&mut img, 12, 0xDEADBEEF);
        let src = ByteSource::from_vec(img);
        let out = validate_at(&src, 0).expect("still parses");
        assert_eq!(out.artifacts[0].confidence, Confidence::Partial);
        assert!(out.artifacts[0]
            .metadata
            .get("superblock_checksum")
            .is_some_and(|v| v == "invalid"));
    }

    #[test]
    fn romfs_hostile_size_rejected() {
        let mut img = romfs_image();
        // full_size larger than the actual source.
        put_be32(&mut img, 8, 1 << 20);
        let src = ByteSource::from_vec(img);
        assert!(validate_at(&src, 0).is_err());
    }

    #[test]
    fn romfs_hard_link_resolves() {
        // Replace /dir with a hard link to /flag.txt's inode at 96.
        let mut img = romfs_image();
        // dir inode at 224: type HRD (0), spec = 96 (flag.txt inode).
        put_be32(&mut img, 224, 0);
        put_be32(&mut img, 228, 96);
        seal_checksum(&mut img, 224);
        let src = ByteSource::from_vec(img);
        let out = validate_at(&src, 0).expect("validates");
        // The linked entry surfaces with flag.txt's data.
        let link = out.artifacts[0]
            .children
            .iter()
            .find(|c| c.metadata.get("path").map(String::as_str) == Some("dir"))
            .expect("hard-linked entry");
        match &link.content {
            ChildContent::Source(r) => assert_eq!(r.read_all().unwrap(), b"FLAG{romfs}".to_vec()),
            _ => panic!("hard link must resolve to real data"),
        }
    }
}
