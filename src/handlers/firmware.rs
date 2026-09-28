//! M3 firmware-container handlers: Device Tree Blob (DTB), Android
//! boot image, TRX (Broadcom), and UEFI firmware volume (FFS).
//!
//! - DTB: FDT header validation (magic 0xD00DFEED, header fields),
//!   device-tree structure block walk (FDT_BEGIN_NODE / FDT_END_NODE /
//!   FDT_PROP / FDT_NOP / FDT_END), memory-reservation block awareness,
//!   strings block metadata. Node names surface in evidence.
//! - Android boot: magic "ANDROID!", kernel/ramdisk/second sizes +
//!   offsets with checked bounds; kernel/ramdisk payloads become
//!   source-backed children.
//! - TRX: magic "HDR0", version, length field as exact boundary;
//!   payload partitioning into source-backed children.
//! - UEFI FV: zero vector + "_FVH" signature at 0x28, GUID/length
//!   metadata; FFS file walking deferred (honest Partial).

use crate::artifact::{Confidence, Evidence, RelationKind};
use crate::bytesource::ByteSource;
use crate::engine::{
    ArtifactDraft, Budget, Candidate, ChildContent, ChildDraft, Handler, HandlerOutput,
};
use crate::error::{Error, Result};
use crate::handlers::find_all;
use std::collections::BTreeMap;

fn be32(src: &ByteSource, off: u64) -> Option<u32> {
    let mut b = [0u8; 4];
    src.read_at(off, &mut b).ok()?;
    Some(u32::from_be_bytes(b))
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
// DTB (Flattened Device Tree)
// ---------------------------------------------------------------------------

pub struct DtbHandler;

const FDT_MAGIC: u32 = 0xD00D_FEED;

impl Handler for DtbHandler {
    fn format(&self) -> &'static str {
        "dtb"
    }

    fn find_candidates(&self, src: &ByteSource) -> Vec<Candidate> {
        find_all(src, &FDT_MAGIC.to_be_bytes())
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
        if base + 40 > src.len() {
            return Err(Error::Validation {
                format: "dtb",
                reason: "header truncated".into(),
            });
        }
        let totalsize = be32(src, base + 4).unwrap_or(0) as u64;
        let off_struct = be32(src, base + 8).unwrap_or(0) as u64;
        let off_strings = be32(src, base + 12).unwrap_or(0) as u64;
        let off_memrsv = be32(src, base + 16).unwrap_or(0) as u64;
        let version = be32(src, base + 20).unwrap_or(0);
        let last_comp = be32(src, base + 24).unwrap_or(0);

        if totalsize == 0 || base + totalsize > src.len() {
            return Err(Error::Validation {
                format: "dtb",
                reason: format!("totalsize {totalsize} inconsistent with source"),
            });
        }
        if off_struct >= totalsize || off_strings >= totalsize || off_struct >= off_strings {
            return Err(Error::Validation {
                format: "dtb",
                reason: format!(
                    "block layout invalid (struct {off_struct}, strings {off_strings})"
                ),
            });
        }
        if version < 17 {
            return Err(Error::Validation {
                format: "dtb",
                reason: format!("unsupported version {version}"),
            });
        }

        // Walk the structure block (bounded): count nodes/properties.
        let mut off = base + off_struct;
        let struct_end = base + off_strings;
        let mut depth = 0i64;
        let mut nodes = 0usize;
        let mut props = 0usize;
        let mut root_name = String::new();
        loop {
            if off + 4 > struct_end || nodes + props > limits.max_records {
                return Err(Error::Validation {
                    format: "dtb",
                    reason: "structure block truncated or too complex".into(),
                });
            }
            let token = be32(src, off).unwrap_or(0);
            off += 4;
            match token {
                0x1 => {
                    // FDT_BEGIN_NODE: name NUL-padded to 4 bytes.
                    depth += 1;
                    nodes += 1;
                    if nodes == 1 {
                        let mut name = Vec::new();
                        while off < struct_end {
                            let mut b = [0u8; 1];
                            src.read_at(off, &mut b)?;
                            off += 1;
                            if b[0] == 0 {
                                break;
                            }
                            name.push(b[0]);
                        }
                        root_name = String::from_utf8_lossy(&name).into_owned();
                        off = (off + 3) & !3;
                    } else {
                        while off < struct_end {
                            let mut b = [0u8; 1];
                            src.read_at(off, &mut b)?;
                            off += 1;
                            if b[0] == 0 {
                                break;
                            }
                        }
                        off = (off + 3) & !3;
                    }
                }
                0x2 => depth -= 1, // FDT_END_NODE
                0x3 => {
                    // FDT_PROP: len(4) nameoff(4) value padded.
                    props += 1;
                    if off + 8 > struct_end {
                        return Err(Error::Validation {
                            format: "dtb",
                            reason: "property header truncated".into(),
                        });
                    }
                    let len = be32(src, off).unwrap_or(0) as u64;
                    off += 8 + len;
                    off = (off + 3) & !3;
                }
                0x4 => {} // FDT_NOP
                0x9 => {
                    // FDT_END
                    break;
                }
                _ => {
                    return Err(Error::Validation {
                        format: "dtb",
                        reason: format!("unknown structure token {token:#x}"),
                    });
                }
            }
            if depth < 0 {
                return Err(Error::Validation {
                    format: "dtb",
                    reason: "unbalanced FDT_END_NODE".into(),
                });
            }
        }

        // Memory reservations.
        let mut reservations = 0usize;
        let mut rsv = base + off_memrsv;
        loop {
            if rsv + 16 > src.len() {
                break;
            }
            let addr = le64(src, rsv).unwrap_or(0);
            let size = le64(src, rsv + 8).unwrap_or(0);
            if addr == 0 && size == 0 {
                break;
            }
            reservations += 1;
            rsv += 16;
            if reservations > 1024 {
                break;
            }
        }

        let mut metadata = BTreeMap::new();
        metadata.insert("version".to_string(), version.to_string());
        metadata.insert("last_compatible_version".to_string(), last_comp.to_string());
        metadata.insert("nodes".to_string(), nodes.to_string());
        metadata.insert("properties".to_string(), props.to_string());
        metadata.insert("memory_reservations".to_string(), reservations.to_string());
        metadata.insert("totalsize".to_string(), totalsize.to_string());

        Ok(HandlerOutput {
            artifacts: vec![ArtifactDraft {
                format: "dtb".to_string(),
                label: format!("Device Tree Blob ({nodes} nodes, {props} properties)"),
                offset: base,
                size: totalsize,
                confidence: Confidence::Validated,
                evidence: Evidence::facts([
                    "FDT magic 0xD00DFEED validated".to_string(),
                    format!("structure block walked: {nodes} nodes / {props} props"),
                    format!(
                        "root node {:?}",
                        if root_name.is_empty() {
                            "/"
                        } else {
                            &root_name
                        }
                    ),
                    format!("{} memory reservation entries", reservations),
                ]),
                metadata,
                warnings: Vec::new(),
                errors: Vec::new(),
                children: Vec::new(),
            }],
        })
    }
}

// ---------------------------------------------------------------------------
// Android boot image
// ---------------------------------------------------------------------------

pub struct AndroidBootHandler;

impl Handler for AndroidBootHandler {
    fn format(&self) -> &'static str {
        "android-boot"
    }

    fn find_candidates(&self, src: &ByteSource) -> Vec<Candidate> {
        find_all(src, b"ANDROID!")
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
        if base + 1660 > src.len() {
            return Err(Error::Validation {
                format: "android-boot",
                reason: "header truncated (v0 needs 1660 bytes)".into(),
            });
        }
        let kernel_size = le32(src, base + 8).unwrap_or(0) as u64;
        let kernel_addr = le32(src, base + 12).unwrap_or(0);
        let ramdisk_size = le32(src, base + 16).unwrap_or(0) as u64;
        let ramdisk_addr = le32(src, base + 20).unwrap_or(0);
        let second_size = le32(src, base + 24).unwrap_or(0) as u64;
        let page_size = le32(src, base + 36).unwrap_or(0) as u64;
        if !matches!(page_size, 512 | 1024 | 2048 | 4096 | 8192 | 16384 | 65536) {
            return Err(Error::Validation {
                format: "android-boot",
                reason: format!("implausible page size {page_size}"),
            });
        }
        // Page-aligned image layout.
        let kernel_off = page_size;
        let ramdisk_off = kernel_off + kernel_size.div_ceil(page_size) * page_size;
        let second_off = ramdisk_off + ramdisk_size.div_ceil(page_size) * page_size;
        let total = second_off + second_size;
        if base + total > src.len() {
            return Err(Error::Validation {
                format: "android-boot",
                reason: format!("image spans {total} bytes; extends past source"),
            });
        }

        let mut children = Vec::new();
        let mut warnings = Vec::new();
        let slots = [
            ("kernel", kernel_size, kernel_off),
            ("ramdisk", ramdisk_size, ramdisk_off),
            ("second-stage", second_size, second_off),
        ];
        for (name, size, off) in slots {
            if size == 0 {
                continue;
            }
            if children.len() >= limits.max_archive_entries {
                break;
            }
            if base + off + size > src.len() {
                warnings.push(format!("{name} extends past source; skipped"));
                continue;
            }
            let region = src.slice(base + off, size)?;
            let mut meta = BTreeMap::new();
            meta.insert("slot".to_string(), name.to_string());
            meta.insert(
                "load_address".to_string(),
                format!("{:#x}", addr_of(name, kernel_addr, ramdisk_addr)),
            );
            children.push(ChildDraft {
                relation: RelationKind::Contains,
                label: format!("android-boot {name} ({size} bytes)"),
                format_hint: "raw",
                content: ChildContent::Source(region),
                size,
                metadata: meta,
                warnings: Vec::new(),
                entry_name: None,
                confidence: Confidence::Validated,
                evidence: vec!["structurally decoded by parent handler".to_string()],
            });
        }

        let cmdline = {
            let mut raw = vec![0u8; 512];
            src.read_at(base + 64, &mut raw)?;
            String::from_utf8_lossy(&raw)
                .trim_end_matches('\0')
                .to_string()
        };

        let mut metadata = BTreeMap::new();
        metadata.insert("kernel_size".to_string(), kernel_size.to_string());
        metadata.insert("ramdisk_size".to_string(), ramdisk_size.to_string());
        metadata.insert("second_size".to_string(), second_size.to_string());
        metadata.insert("page_size".to_string(), page_size.to_string());
        if !cmdline.is_empty() {
            metadata.insert("cmdline".to_string(), cmdline.chars().take(128).collect());
        }

        Ok(HandlerOutput {
            artifacts: vec![ArtifactDraft {
                format: "android-boot".to_string(),
                label: format!("Android boot image (kernel {kernel_size}, ramdisk {ramdisk_size})"),
                offset: base,
                size: total,
                confidence: Confidence::Validated,
                evidence: Evidence::facts([
                    "ANDROID! magic validated".to_string(),
                    "page-aligned layout walked (kernel/ramdisk/second)".to_string(),
                    "payload slots exposed as source-backed slices".to_string(),
                ]),
                metadata,
                warnings,
                errors: Vec::new(),
                children,
            }],
        })
    }
}

fn addr_of(name: &str, kernel: u32, ramdisk: u32) -> u32 {
    match name {
        "kernel" => kernel,
        "ramdisk" => ramdisk,
        _ => 0,
    }
}

// ---------------------------------------------------------------------------
// TRX (Broadcom firmware container)
// ---------------------------------------------------------------------------

pub struct TrxHandler;

impl Handler for TrxHandler {
    fn format(&self) -> &'static str {
        "trx"
    }

    fn find_candidates(&self, src: &ByteSource) -> Vec<Candidate> {
        find_all(src, b"HDR0")
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
        if base + 28 > src.len() {
            return Err(Error::Validation {
                format: "trx",
                reason: "header truncated".into(),
            });
        }
        let version = le32(src, base + 4).unwrap_or(0);
        let size = le32(src, base + 8).unwrap_or(0) as u64;
        let mut offsets = Vec::new();
        let count = if version == 1 { 3usize } else { 4 };
        for i in 0..count {
            offsets.push(le32(src, base + 12 + i as u64 * 4).unwrap_or(0) as u64);
        }
        if size == 0 || base + size > src.len() {
            return Err(Error::Validation {
                format: "trx",
                reason: format!("declared length {size} inconsistent with source"),
            });
        }
        let mut children = Vec::new();
        let mut warnings = Vec::new();
        let mut offsets_f = offsets.clone();
        offsets_f.retain(|&o| o != 0);
        offsets_f.sort_unstable();
        offsets_f.push(size);
        for w in offsets_f.windows(2) {
            if children.len() >= limits.max_partitions {
                break;
            }
            let (start, end) = (w[0], w[1]);
            if end <= start || end > size {
                warnings.push(format!("partition [{start},{end}) invalid; skipped"));
                continue;
            }
            let region = src.slice(base + start, end - start)?;
            children.push(ChildDraft {
                relation: RelationKind::Contains,
                label: format!("TRX payload @{} ({} bytes)", start, end - start),
                format_hint: "raw",
                content: ChildContent::Source(region),
                size: end - start,
                metadata: BTreeMap::new(),
                warnings: Vec::new(),
                entry_name: None,
                confidence: Confidence::Validated,
                evidence: vec!["structurally decoded by parent handler".to_string()],
            });
        }

        let mut metadata = BTreeMap::new();
        metadata.insert("version".to_string(), version.to_string());
        metadata.insert("declared_length".to_string(), size.to_string());

        Ok(HandlerOutput {
            artifacts: vec![ArtifactDraft {
                format: "trx".to_string(),
                label: format!("TRX firmware v{} ({} bytes)", version, size),
                offset: base,
                size,
                confidence: Confidence::Validated,
                evidence: Evidence::facts([
                    "TRX HDR0 magic validated".to_string(),
                    format!("{} partition offsets parsed", offsets.len()),
                    "boundary from declared length".to_string(),
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
// UEFI firmware volume
// ---------------------------------------------------------------------------

pub struct UefiFvHandler;

impl Handler for UefiFvHandler {
    fn format(&self) -> &'static str {
        "uefi-fv"
    }

    fn find_candidates(&self, src: &ByteSource) -> Vec<Candidate> {
        find_all(src, b"_FVH")
            .into_iter()
            .map(|o| Candidate {
                offset: o.saturating_sub(0x28),
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
        if base + 56 > src.len() {
            return Err(Error::Validation {
                format: "uefi-fv",
                reason: "header truncated".into(),
            });
        }
        // Zero vector 16 bytes, then GUID 16, FvLength at 0x20,
        // attributes 0x2C, HeaderLength 0x30, Checksum 0x32,
        // then "_FVH" at 0x28.
        let sig = {
            let mut s = [0u8; 4];
            src.read_at(base + 0x28, &mut s)?;
            s
        };
        if &sig != b"_FVH" {
            return Err(Error::Validation {
                format: "uefi-fv",
                reason: "signature check failed".into(),
            });
        }
        let fv_length = le64(src, base + 0x20).unwrap_or(0);
        if fv_length == 0 || base + fv_length > src.len() {
            return Err(Error::Validation {
                format: "uefi-fv",
                reason: format!("FvLength {fv_length} inconsistent with source"),
            });
        }
        // HeaderLength is a UINT16 at 0x30 (EFI_FIRMWARE_VOLUME_HEADER).
        let header_length = le16(src, base + 0x30).unwrap_or(0) as u64;
        let guid_raw = {
            let mut g = [0u8; 16];
            src.read_at(base + 16, &mut g)?;
            g
        };

        // Walk FFS files (bounded; budget charged per section).
        let mut children = Vec::new();
        let mut warnings = Vec::new();
        self.walk_ffs(
            src,
            base,
            fv_length,
            header_length,
            limits,
            budget,
            &mut warnings,
            &mut children,
        )?;

        let mut metadata = BTreeMap::new();
        metadata.insert("fv_length".to_string(), fv_length.to_string());
        metadata.insert("header_length".to_string(), header_length.to_string());
        metadata.insert("firmware_volume_guid".to_string(), guid_hex(&guid_raw));
        metadata.insert("ffs_files".to_string(), children.len().to_string());

        Ok(HandlerOutput {
            artifacts: vec![ArtifactDraft {
                format: "uefi-fv".to_string(),
                label: format!("UEFI firmware volume ({} bytes)", fv_length),
                offset: base,
                size: fv_length,
                confidence: if children.is_empty() {
                    Confidence::Partial
                } else {
                    Confidence::Validated
                },
                evidence: Evidence::facts([
                    "_FVH signature validated".to_string(),
                    format!("FvLength {fv_length} bytes"),
                    format!("FFS walk: {} files", children.len()),
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
// UEFI FFS traversal (extends the firmware-volume claim above)
// ---------------------------------------------------------------------------

/// FFS file header (EFI_FFS_FILE_HEADER, PiFirmwareFile.h): Name GUID
/// @0..16, IntegrityCheck (hdr checksum @16, file checksum @17),
/// Type@18, Attributes@19, Size[3]@20..23 (LE 24-bit, includes the
/// 24-byte header), State@23. The next file starts at the next 8-byte
/// aligned offset after the file. FFS_ATTRIB_LARGE_FILE (0x01) means
/// a 24-byte extended header carries the real size (EFI_FFS_FILE_HEADER2).
const FFS_HEADER_SIZE: u64 = 24;
const FFS_ATTRIB_LARGE_FILE: u8 = 0x01;
const FFS_TYPE_PAD: u8 = 0xf0;
/// State bits are stored XORed with the erase polarity; images use
/// 0xFF polarity so a live file has all State bits inverted-set. We
/// accept files whose DATA_VALID bit reads as set under either
/// polarity, and skip DELETED files.
const FFS_STATE_DATA_VALID: u8 = 0x04;
const FFS_STATE_DELETED: u8 = 0x10;
/// Section types (PiFirmwareFile.h EFI_SECTION_*).
const SECTION_COMPRESSION: u8 = 0x01;
const SECTION_GUID_DEFINED: u8 = 0x02;
const SECTION_FV_IMAGE: u8 = 0x17;
const SECTION_RAW: u8 = 0x19;
const SECTION_PE32: u8 = 0x10;
const SECTION_TE: u8 = 0x12;
const SECTION_UI: u8 = 0x15;
/// LZMA_CUSTOM_DECOMPRESS_GUID {EE4E5898-3914-4259-9D6E-DC7BD79403CF}
/// (MdePkg/Guid/LzmaCustomDecompressLib.h), byte layout per EFI GUID.
const LZMA_CUSTOM_DECOMPRESS_GUID: [u8; 16] = [
    0x98, 0x58, 0x4E, 0xEE, 0x14, 0x39, 0x59, 0x42, 0x9D, 0x6E, 0xDC, 0x7B, 0xD7, 0x94, 0x03, 0xCF,
];

impl UefiFvHandler {
    /// Walk FFS files inside one firmware volume and emit children.
    #[allow(clippy::too_many_arguments)]
    fn walk_ffs(
        &self,
        src: &ByteSource,
        base: u64,
        fv_length: u64,
        header_length: u64,
        limits: &crate::engine::EngineLimits,
        budget: &mut Budget,
        warnings: &mut Vec<String>,
        out: &mut Vec<ChildDraft>,
    ) -> Result<()> {
        let mut pos = base + header_length;
        // Align up to 8.
        pos = (pos + 7) & !7u64;
        let end = base + fv_length;
        let mut file_count = 0usize;
        while pos + FFS_HEADER_SIZE <= end {
            if out.len() >= limits.max_streams {
                warnings.push("max_streams reached; FFS walk truncated".to_string());
                return Ok(());
            }
            file_count += 1;
            if file_count > limits.max_records {
                warnings.push("FFS file count exceeded max_records; walk truncated".to_string());
                return Ok(());
            }
            let mut hdr = [0u8; FFS_HEADER_SIZE as usize];
            src.read_at(pos, &mut hdr)?;
            // Erased region: stop.
            if hdr.iter().all(|&b| b == 0xFF) {
                break;
            }
            let size24 =
                u32::from(hdr[20]) | (u32::from(hdr[21]) << 8) | (u32::from(hdr[22]) << 16);
            let attributes = hdr[19];
            let state = hdr[23];
            let (file_size, header_size) = if attributes & FFS_ATTRIB_LARGE_FILE != 0 && size24 == 0
            {
                let ext = le64(src, pos + FFS_HEADER_SIZE).unwrap_or(0);
                (ext, FFS_HEADER_SIZE + 8)
            } else {
                (u64::from(size24), FFS_HEADER_SIZE)
            };
            if file_size < header_size || pos + file_size > end {
                warnings.push("FFS file with invalid size; walk stopped".to_string());
                return Ok(());
            }
            // State under 0xFF erase polarity: bits are inverted. A
            // deleted file reads DELETED as 0 under this polarity.
            let deleted = state & FFS_STATE_DELETED == 0;
            let valid = state & FFS_STATE_DATA_VALID == 0;
            let file_type = hdr[18];
            let is_pad = file_type == FFS_TYPE_PAD;
            if !valid || deleted || is_pad {
                pos = (pos + file_size + 7) & !7u64;
                continue;
            }

            let name_guid = &hdr[0..16];
            let data_start = pos + header_size;
            let data_len = file_size - header_size;
            // Sections follow (type RAW has no section wrapper? raw
            // files contain a sequence of sections too, per PI spec).
            let guid_str = guid_hex(name_guid);
            let mut meta = BTreeMap::new();
            meta.insert("ffs_name_guid".to_string(), guid_str.clone());
            meta.insert("ffs_type".to_string(), format!("0x{file_type:02x}"));
            meta.insert("ffs_size".to_string(), file_size.to_string());
            let mut label = format!("UEFI FFS file {guid_str} (type 0x{file_type:02x})");
            let mut content = ChildContent::Owned(Vec::new());
            let mut child_warnings = Vec::new();

            // Walk sections; keep the concatenation of raw/pe32
            // section payloads as the file content when present.
            let mut section_payloads: Vec<Vec<u8>> = Vec::new();
            let mut section_names: Vec<String> = Vec::new();
            let mut spos = data_start;
            let send = data_start + data_len;
            while spos + 4 <= send {
                let mut shdr = [0u8; 4];
                src.read_at(spos, &mut shdr)?;
                if shdr.iter().all(|&b| b == 0xFF) {
                    break;
                }
                let ssize =
                    u32::from(shdr[0]) | (u32::from(shdr[1]) << 8) | (u32::from(shdr[2]) << 16);
                let stype = shdr[3];
                let (ssize, shsize) = if ssize == 0xFF_FFFF {
                    let ext = le32(src, spos + 4).unwrap_or(0);
                    (u64::from(ext), 8u64)
                } else {
                    (u64::from(ssize), 4u64)
                };
                if ssize < shsize || spos + ssize > send {
                    child_warnings.push("invalid section size; sections truncated".to_string());
                    break;
                }
                match stype {
                    SECTION_RAW | SECTION_PE32 | SECTION_TE => {
                        let payload = src.slice(spos + shsize, ssize - shsize)?;
                        let mut buf = vec![0u8; (ssize - shsize) as usize];
                        src.read_at(spos + shsize, &mut buf)?;
                        section_payloads.push(buf);
                        let _ = payload;
                        section_names.push(format!("0x{stype:02x}"));
                        if stype == SECTION_PE32 {
                            label.push_str(" [PE32]");
                        } else if stype == SECTION_TE {
                            label.push_str(" [TE]");
                        }
                    }
                    SECTION_UI => {
                        // UTF-16LE name.
                        let mut raw = vec![0u8; (ssize - shsize) as usize];
                        if src.read_at(spos + shsize, &mut raw).is_ok() {
                            let units: Vec<u16> = raw
                                .chunks_exact(2)
                                .map(|c| u16::from_le_bytes([c[0], c[1]]))
                                .collect();
                            let name = String::from_utf16_lossy(&units);
                            let name = name.trim_end_matches('\0').to_string();
                            if !name.is_empty() {
                                label = format!("UEFI FFS file \"{name}\" ({guid_str})");
                                meta.insert("ui_name".to_string(), name);
                            }
                        }
                    }
                    SECTION_COMPRESSION | SECTION_GUID_DEFINED => {
                        section_names.push(format!("0x{stype:02x} (encapsulated)"));
                        // FINAL-B5: decode the common encapsulated
                        // sections. LZMA-custom-compressed payloads
                        // (compression type 2 / LZMA GUID) are
                        // decompressed and their bytes recursed; Tiano
                        // (type 1) is genuinely unsupported and stays
                        // metadata-only with an honest warning.
                        let decoded = Self::decode_encapsulated(
                            src,
                            spos,
                            ssize,
                            shsize,
                            stype,
                            limits,
                            budget,
                            &mut child_warnings,
                        );
                        if let Some(bytes) = decoded {
                            section_payloads.push(bytes);
                        }
                    }
                    SECTION_FV_IMAGE => {
                        section_names.push(format!("0x{stype:02x} (nested FV)"));
                        child_warnings
                            .push("nested firmware volume image section present".to_string());
                    }
                    _ => {
                        section_names.push(format!("0x{stype:02x}"));
                    }
                }
                spos += ssize;
            }
            let total_payload: usize = section_payloads.iter().map(|p| p.len()).sum();
            if total_payload > 0 && total_payload as u64 <= limits.max_child_size {
                let mut all = Vec::with_capacity(total_payload);
                for p in &section_payloads {
                    all.extend_from_slice(p);
                    if !budget.charge(limits, p.len() as u64) {
                        return Err(Error::LimitExceeded {
                            limit: "max-total-expanded-bytes",
                            detail: "uefi ffs section".into(),
                        });
                    }
                }
                content = ChildContent::Owned(all);
            } else if total_payload as u64 > limits.max_child_size {
                child_warnings
                    .push("section payload exceeds max_child_size; not exposed".to_string());
            }
            if !section_names.is_empty() {
                meta.insert("sections".to_string(), section_names.join(","));
            }
            out.push(ChildDraft {
                relation: RelationKind::FilesystemEntry,
                label,
                format_hint: "raw",
                content,
                size: data_len,
                metadata: meta,
                warnings: child_warnings,
                entry_name: Some(guid_str),
                confidence: Confidence::Validated,
                evidence: vec!["structurally decoded by parent handler".to_string()],
            });
            pos = (pos + file_size + 7) & !7u64;
        }
        Ok(())
    }

    /// FINAL-B5: decode one encapsulated section (COMPRESSION or
    /// GUID_DEFINED). Returns Some(payload bytes) when decoding
    /// succeeded, None when the section stays metadata-only.
    #[allow(clippy::too_many_arguments)]
    fn decode_encapsulated(
        src: &ByteSource,
        spos: u64,
        ssize: u64,
        shsize: u64,
        stype: u8,
        limits: &crate::engine::EngineLimits,
        budget: &mut Budget,
        warnings: &mut Vec<String>,
    ) -> Option<Vec<u8>> {
        let body = spos + shsize;
        let body_len = ssize - shsize;
        if stype == SECTION_COMPRESSION {
            // EFI_COMMON_SECTION_HEADER Compression: u32 Type then
            // the compressed payload. Type 0 = none, 1 = Tiano,
            // 2 = LZMA-custom (13-byte props header + raw LZMA1).
            if body_len < 4 {
                return None;
            }
            let ctype = le32(src, body).unwrap_or(0);
            let payload_off = body + 4;
            let payload_len = body_len - 4;
            match ctype {
                0 => {
                    // Uncompressed.
                    let mut buf = vec![0u8; payload_len.min(limits.max_child_size) as usize];
                    src.read_at(payload_off, &mut buf).ok()?;
                    if !budget.charge(limits, buf.len() as u64) {
                        return None;
                    }
                    Some(buf)
                }
                2 => {
                    Self::decode_uefi_lzma(src, payload_off, payload_len, limits, budget, warnings)
                }
                other => {
                    warnings.push(format!(
                        "COMPRESSION type {other} (Tiano) not supported; kept as metadata"
                    ));
                    None
                }
            }
        } else {
            // GUID_DEFINED: u16 DataOffset, u16 Attributes, then the
            // section GUID.
            if body_len < 16 {
                return None;
            }
            let mut guid = [0u8; 16];
            src.read_at(body, &mut guid).ok()?;
            let data_offset = le16(src, body + 16).unwrap_or(0) as u64;
            let payload_off = spos + data_offset.max(shsize + 20);
            if payload_off >= spos + ssize {
                return None;
            }
            let payload_len = ssize - (payload_off - spos);
            if guid == LZMA_CUSTOM_DECOMPRESS_GUID {
                Self::decode_uefi_lzma(src, payload_off, payload_len, limits, budget, warnings)
            } else {
                warnings.push(format!(
                    "GUID_DEFINED section with GUID {} not supported; kept as metadata",
                    guid_hex(&guid)
                ));
                None
            }
        }
    }

    /// Decode an UEFI LZMA-custom payload: 13-byte LZMA-alone header
    /// (props[1], dict_size[4 LE], uncompressed size[8 LE]) followed
    /// by raw LZMA1. Charges the budget incrementally while decoding.
    fn decode_uefi_lzma(
        src: &ByteSource,
        off: u64,
        len: u64,
        limits: &crate::engine::EngineLimits,
        budget: &mut Budget,
        warnings: &mut Vec<String>,
    ) -> Option<Vec<u8>> {
        const HDR: usize = 13;
        if len < HDR as u64 {
            warnings.push("LZMA payload truncated; kept as metadata".to_string());
            return None;
        }
        let mut hdr = [0u8; HDR];
        if src.read_at(off, &mut hdr).is_err() {
            return None;
        }
        let props = hdr[0];
        let dict_size = u32::from_le_bytes(hdr[1..5].try_into().ok()?);
        let uncomp = u64::from_le_bytes(hdr[5..13].try_into().ok()?);
        if uncomp > limits.max_child_size {
            warnings.push("LZMA declared size exceeds max_child_size; not decoded".to_string());
            return None;
        }
        let mut comp = vec![0u8; (len as usize) - HDR];
        if src.read_at(off + HDR as u64, &mut comp).is_err() {
            return None;
        }
        let mut reader = lzma_rust::LZMAReader::new_with_props(
            std::io::Cursor::new(&comp[..]),
            uncomp,
            props,
            dict_size,
            None,
        )
        .ok()?;
        let mut out = Vec::new();
        let mut chunk = [0u8; 64 * 1024];
        loop {
            match std::io::Read::read(&mut reader, &mut chunk) {
                Ok(0) => break,
                Ok(n) => {
                    out.extend_from_slice(&chunk[..n]);
                    if out.len() as u64 > limits.max_child_size {
                        warnings.push("LZMA output exceeds max_child_size; truncated".to_string());
                        break;
                    }
                    if !budget.charge(limits, n as u64) {
                        return None;
                    }
                }
                Err(_) => break,
            }
        }
        if out.is_empty() {
            warnings.push("LZMA decode produced no output; kept as metadata".to_string());
            return None;
        }
        Some(out)
    }
}

// ---------------------------------------------------------------------------
// Android sparse images
// ---------------------------------------------------------------------------

/// Android sparse image handler: expands sparse chunks into a raw
/// image (RAW copied, FILL replicated, DONT_CARE zero-filled), with
/// the CRC32 chunk checked when present.
pub struct AndroidSparseHandler;

const SPARSE_MAGIC: u32 = 0xed26_ff3a;
const SPARSE_MAJOR: u16 = 1;
const CHUNK_RAW: u16 = 0xCAC1;
const CHUNK_FILL: u16 = 0xCAC2;
const CHUNK_DONT_CARE: u16 = 0xCAC3;
const CHUNK_CRC32: u16 = 0xCAC4;

/// Layout verified against libsparse (system/core/libsparse/
/// sparse_format.h, sparse_read.cpp):
/// - `sparse_header` (28 bytes LE): magic@0 0xed26ff3a, major@4 (1),
///   minor@6, file_hdr_sz@8 (28), chunk_hdr_sz@10 (12), blk_sz@12
///   (multiple of 4), total_blks@16, total_chunks@20,
///   image_checksum@24 (CRC32 of the expanded data, don't-care as 0).
/// - `chunk_header` (12 bytes LE): chunk_type@0, reserved1@2,
///   chunk_sz@4 (blocks in output), total_sz@8 (bytes in input
///   including header). RAW carries chunk_sz*blk_sz data bytes; FILL
///   carries 4 fill bytes (repeated); DONT_CARE carries no data;
///   CRC32 carries 4 bytes of expected CRC and produces no output.
/// - Expansion output size = total_blks * blk_sz.
impl Handler for AndroidSparseHandler {
    fn format(&self) -> &'static str {
        "android-sparse"
    }

    fn find_candidates(&self, src: &ByteSource) -> Vec<Candidate> {
        find_all(src, &SPARSE_MAGIC.to_le_bytes())
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
        if base + 28 > src.len() {
            return Err(Error::Validation {
                format: "android-sparse",
                reason: "header truncated".into(),
            });
        }
        let mut hdr = [0u8; 28];
        src.read_at(base, &mut hdr)?;
        let magic = u32::from_le_bytes(hdr[0..4].try_into().unwrap());
        if magic != SPARSE_MAGIC {
            return Err(Error::Validation {
                format: "android-sparse",
                reason: "bad magic".into(),
            });
        }
        let major = u16::from_le_bytes(hdr[4..6].try_into().unwrap());
        if major != SPARSE_MAJOR {
            return Err(Error::Validation {
                format: "android-sparse",
                reason: format!("unsupported major version {major}"),
            });
        }
        let file_hdr_sz = u16::from_le_bytes(hdr[8..10].try_into().unwrap()) as u64;
        let chunk_hdr_sz = u16::from_le_bytes(hdr[10..12].try_into().unwrap()) as u64;
        let blk_sz = u32::from_le_bytes(hdr[12..16].try_into().unwrap()) as u64;
        let total_blks = u32::from_le_bytes(hdr[16..20].try_into().unwrap()) as u64;
        let total_chunks = u32::from_le_bytes(hdr[20..24].try_into().unwrap()) as u64;
        let stored_crc = u32::from_le_bytes(hdr[24..28].try_into().unwrap());
        if file_hdr_sz < 28 || chunk_hdr_sz < 12 {
            return Err(Error::Validation {
                format: "android-sparse",
                reason: "implausible header sizes".into(),
            });
        }
        if blk_sz == 0 || blk_sz % 4 != 0 || !blk_sz.is_power_of_two() {
            return Err(Error::Validation {
                format: "android-sparse",
                reason: format!("implausible block size {blk_sz}"),
            });
        }
        let out_size = total_blks * blk_sz;
        if out_size > limits.max_child_size {
            return Err(Error::Validation {
                format: "android-sparse",
                reason: format!("expanded size {out_size} exceeds max_child_size"),
            });
        }

        // Expand chunks.
        let mut out = vec![0u8; out_size as usize];
        let mut pos = base + file_hdr_sz;
        let mut cur_block = 0u64;
        let mut crc = crc32fast::Hasher::new();
        let mut chunks_seen = 0u64;
        let mut warnings = Vec::new();
        while chunks_seen < total_chunks {
            chunks_seen += 1;
            if pos + chunk_hdr_sz > src.len() {
                warnings.push("chunk chain truncated at source end".to_string());
                break;
            }
            let mut ch = [0u8; 12];
            src.read_at(pos, &mut ch)?;
            let ctype = u16::from_le_bytes(ch[0..2].try_into().unwrap());
            let chunk_sz = u32::from_le_bytes(ch[4..8].try_into().unwrap()) as u64;
            let total_sz = u32::from_le_bytes(ch[8..12].try_into().unwrap()) as u64;
            if total_sz < chunk_hdr_sz {
                warnings.push("chunk total_sz < header; expansion stopped".to_string());
                break;
            }
            let data_len = total_sz - chunk_hdr_sz;
            let chunk_bytes = chunk_sz * blk_sz;
            match ctype {
                CHUNK_RAW => {
                    let end_block = (cur_block + chunk_sz).min(total_blks);
                    let take_bytes = ((end_block - cur_block) * blk_sz) as usize;
                    let end = cur_block * blk_sz + take_bytes as u64;
                    if end > out_size || pos + chunk_hdr_sz + take_bytes as u64 > src.len() {
                        warnings.push("raw chunk out of bounds; truncated".to_string());
                        break;
                    }
                    src.read_at(
                        pos + chunk_hdr_sz,
                        &mut out[cur_block as usize * blk_sz as usize..end as usize],
                    )?;
                    crc.update(&out[cur_block as usize * blk_sz as usize..end as usize]);
                    cur_block = end_block;
                }
                CHUNK_FILL => {
                    if data_len != 4 {
                        warnings.push("fill chunk without 4-byte fill; skipped".to_string());
                    } else {
                        let mut fill = [0u8; 4];
                        src.read_at(pos + chunk_hdr_sz, &mut fill)?;
                        let end_block = (cur_block + chunk_sz).min(total_blks);
                        let fill_bytes = ((end_block - cur_block) * blk_sz) as usize;
                        let start = cur_block as usize * blk_sz as usize;
                        for (i, b) in out[start..start + fill_bytes].iter_mut().enumerate() {
                            *b = fill[i % 4];
                        }
                        crc.update(&out[start..start + fill_bytes]);
                        cur_block = end_block;
                    }
                }
                CHUNK_DONT_CARE => {
                    // Output stays zero; CRC counts don't-care as 0, so
                    // feed zeros for those blocks.
                    let end_block = (cur_block + chunk_sz).min(total_blks);
                    let n = ((end_block - cur_block) * blk_sz) as usize;
                    crc.update(&vec![0u8; n]);
                    cur_block = end_block;
                }
                CHUNK_CRC32 => {
                    if data_len != 4 {
                        warnings.push("crc32 chunk without 4-byte value; skipped".to_string());
                    } else {
                        // Expected CRC of everything before this point.
                        let expect = {
                            let mut b = [0u8; 4];
                            src.read_at(pos + chunk_hdr_sz, &mut b)?;
                            u32::from_le_bytes(b)
                        };
                        if crc.clone().finalize() != expect {
                            warnings.push("intermediate CRC32 mismatch".to_string());
                        }
                    }
                }
                _ => {
                    warnings.push(format!(
                        "unknown chunk type 0x{ctype:04x}; expansion stopped"
                    ));
                    break;
                }
            }
            if !budget.charge(limits, chunk_bytes) {
                return Err(Error::LimitExceeded {
                    limit: "max-total-expanded-bytes",
                    detail: "android-sparse chunk".into(),
                });
            }
            pos += chunk_hdr_sz + data_len;
        }
        if cur_block < total_blks {
            warnings.push(format!(
                "expansion stopped at block {cur_block} of {total_blks}; tail zero-filled"
            ));
        }
        let final_crc = crc.finalize();
        if stored_crc != 0 && final_crc != stored_crc {
            warnings.push(format!(
                "image checksum mismatch: stored {stored_crc:#010x}, computed {final_crc:#010x}"
            ));
        }

        let mut metadata = BTreeMap::new();
        metadata.insert("block_size".to_string(), blk_sz.to_string());
        metadata.insert("total_blocks".to_string(), total_blks.to_string());
        metadata.insert("total_chunks".to_string(), total_chunks.to_string());
        metadata.insert("expanded_size".to_string(), out_size.to_string());

        Ok(HandlerOutput {
            artifacts: vec![ArtifactDraft {
                format: "android-sparse".to_string(),
                label: format!(
                    "Android sparse image ({} KiB blocks, {total_blks} blocks)",
                    blk_sz / 1024
                ),
                offset: base,
                size: out_size,
                confidence: Confidence::Validated,
                evidence: Evidence::facts([
                    "sparse header validated (magic 0xed26ff3a, version 1)".to_string(),
                    format!("{} chunks expanded to {} bytes", chunks_seen, out_size),
                    format!("computed image CRC32 {final_crc:#010x}"),
                ]),
                metadata,
                warnings,
                errors: Vec::new(),
                // The expanded raw image is exposed as one child so the
                // engine recursively discovers partitions / filesystems
                // inside it.
                children: vec![ChildDraft {
                    relation: RelationKind::ReconstructedFrom,
                    label: format!("expanded raw image ({} bytes)", out.len()),
                    format_hint: "raw",
                    content: ChildContent::Owned(out),
                    size: out_size,
                    metadata: BTreeMap::new(),
                    warnings: Vec::new(),
                    entry_name: Some("expanded.img".to_string()),
                    confidence: Confidence::Validated,
                    evidence: vec!["structurally decoded by parent handler".to_string()],
                }],
            }],
        })
    }
}

// ---------------------------------------------------------------------------
// BCM63xx CFE vendor image tag
// ---------------------------------------------------------------------------

/// Broadcom BCM63xx "imagetag" vendor wrapper: a 256-byte ASCII tag
/// (struct bcm_tag) prepended to the flash image, followed by CFE,
/// kernel and rootfs regions whose sizes are given as ASCII decimal
/// strings. Layout verified against OpenWrt tools/firmware-utils
/// bcm_tag.h.
pub struct Bcm63xxTagHandler;

const BCM_TAG_SIZE: u64 = 256;
const BCM_SIG_1: &[u8] = b"Broadcom Corporatio"; // SIG1_LEN 20 ("Broadcom Corporation" truncated)
const BCM_TAG_VER_OFFSET: u64 = 0;
const BCM_CHIPID_OFFSET: u64 = 38;
const BCM_CHIPID_LEN: usize = 6;
const BCM_BOARDID_OFFSET: u64 = 44;
const BCM_BOARDID_LEN: usize = 16;
const BCM_CFE_LENGTH_OFFSET: u64 = 84;
const BCM_KERNEL_LENGTH_OFFSET: u64 = 128;
const BCM_ROOT_LENGTH_OFFSET: u64 = 232;

/// Parse a big-endian ASCII decimal field (`len` bytes) into a number;
/// returns None when the field is not fully decimal (all-0xFF erased
/// fields also return None).
fn bcm_ascii_number(src: &ByteSource, off: u64, len: usize) -> Option<u64> {
    let mut buf = vec![0u8; len];
    src.read_at(off, &mut buf).ok()?;
    let s = String::from_utf8_lossy(&buf);
    let trimmed = s.trim_end_matches(['\0', ' ']);
    if trimmed.is_empty() || !trimmed.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    trimmed.parse::<u64>().ok()
}

impl Handler for Bcm63xxTagHandler {
    fn format(&self) -> &'static str {
        "bcm63xx-tag"
    }

    fn find_candidates(&self, src: &ByteSource) -> Vec<Candidate> {
        // The tag's sig_1 field starts at offset 4.
        find_all(src, BCM_SIG_1)
            .into_iter()
            .filter(|o| *o >= 4)
            .map(|o| Candidate { offset: o - 4 })
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
        if base + BCM_TAG_SIZE > src.len() {
            return Err(Error::Validation {
                format: "bcm63xx-tag",
                reason: "tag truncated".into(),
            });
        }
        // tagVersion at 0..4: ASCII digits expected ("6" versions).
        let mut ver = [0u8; 4];
        src.read_at(base + BCM_TAG_VER_OFFSET, &mut ver)?;
        if !ver.iter().all(u8::is_ascii_digit) {
            return Err(Error::Validation {
                format: "bcm63xx-tag",
                reason: "tagVersion is not numeric".into(),
            });
        }
        let cfe_len =
            bcm_ascii_number(src, base + BCM_CFE_LENGTH_OFFSET, 10).ok_or(Error::Validation {
                format: "bcm63xx-tag",
                reason: "cfeLength is not a decimal number".into(),
            })?;
        let kernel_len = bcm_ascii_number(src, base + BCM_KERNEL_LENGTH_OFFSET, 10).ok_or(
            Error::Validation {
                format: "bcm63xx-tag",
                reason: "kernelLength is not a decimal number".into(),
            },
        )?;
        let root_len =
            bcm_ascii_number(src, base + BCM_ROOT_LENGTH_OFFSET, 4).ok_or(Error::Validation {
                format: "bcm63xx-tag",
                reason: "rootLength is not a decimal number".into(),
            })?;
        // Layout: tag | cfe | kernel | rootfs.
        let mut region_off = base + BCM_TAG_SIZE;
        let mut regions: Vec<(&str, u64)> = Vec::new();
        if cfe_len > 0 && cfe_len <= limits.max_child_size {
            regions.push(("cfe", cfe_len));
        }
        if kernel_len > 0 && kernel_len <= limits.max_child_size {
            regions.push(("kernel", kernel_len));
        }
        if root_len > 0 && root_len <= limits.max_child_size {
            regions.push(("rootfs", root_len));
        }
        let mut children = Vec::new();
        let mut warnings = Vec::new();
        for (name, len) in regions {
            if region_off + len > src.len() {
                warnings.push(format!(
                    "{name} region ({len} bytes) extends past source; not exposed"
                ));
                break;
            }
            let mut meta = BTreeMap::new();
            meta.insert("region".to_string(), name.to_string());
            meta.insert("declared_size".to_string(), len.to_string());
            children.push(ChildDraft {
                relation: RelationKind::PartitionOf,
                label: format!("BCM63xx {name} region ({len} bytes)"),
                format_hint: "raw",
                content: ChildContent::Source(src.slice(region_off, len)?),
                size: len,
                metadata: meta,
                warnings: Vec::new(),
                entry_name: Some(name.to_string()),
                confidence: Confidence::Validated,
                evidence: vec!["structurally decoded by parent handler".to_string()],
            });
            region_off += len;
        }
        // Chip and board ids for provenance.
        let mut chipid = [0u8; BCM_CHIPID_LEN];
        src.read_at(base + BCM_CHIPID_OFFSET, &mut chipid).ok();
        let mut boardid = [0u8; BCM_BOARDID_LEN];
        src.read_at(base + BCM_BOARDID_OFFSET, &mut boardid).ok();
        let clean = |b: &[u8]| {
            String::from_utf8_lossy(b)
                .trim_end_matches(['\0', ' '])
                .to_string()
        };

        let mut metadata = BTreeMap::new();
        metadata.insert(
            "tag_version".to_string(),
            String::from_utf8_lossy(&ver).into_owned(),
        );
        metadata.insert("chip_id".to_string(), clean(&chipid));
        metadata.insert("board_id".to_string(), clean(&boardid));
        metadata.insert("cfe_length".to_string(), cfe_len.to_string());
        metadata.insert("kernel_length".to_string(), kernel_len.to_string());
        metadata.insert("root_length".to_string(), root_len.to_string());

        Ok(HandlerOutput {
            artifacts: vec![ArtifactDraft {
                format: "bcm63xx-tag".to_string(),
                label: format!(
                    "BCM63xx firmware image (board {}, CFE {} + kernel {} + rootfs {} bytes)",
                    clean(&boardid),
                    cfe_len,
                    kernel_len,
                    root_len
                ),
                offset: base,
                size: BCM_TAG_SIZE + cfe_len + kernel_len + root_len,
                confidence: if children.is_empty() {
                    Confidence::Partial
                } else {
                    Confidence::Validated
                },
                evidence: Evidence::facts([
                    "BCM63xx image tag validated (Broadcom sig_1, numeric fields)".to_string(),
                    format!("regions: {}", children.len()),
                ]),
                metadata,
                warnings,
                errors: Vec::new(),
                children,
            }],
        })
    }
}

fn le16(src: &ByteSource, off: u64) -> Option<u16> {
    let mut b = [0u8; 2];
    src.read_at(off, &mut b).ok()?;
    Some(u16::from_le_bytes(b))
}

fn guid_hex(b: &[u8]) -> String {
    b.iter()
        .map(|x| format!("{x:02x}"))
        .collect::<Vec<_>>()
        .join("")
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

    /// Build a UEFI FV with two FFS files: a UI-named file with a RAW
    /// section, and a pad file that must be skipped.
    fn uefi_fv_image() -> Vec<u8> {
        let mut img = vec![0u8; 0x10000];
        // FV header: zero vector 16, GUID 16, FvLength@0x20, attrs,
        // HeaderLength@0x30 (16-bit), checksum, "_FVH"@0x28.
        img[0x20..0x28].copy_from_slice(&0x10000u64.to_le_bytes());
        img[0x28..0x2c].copy_from_slice(b"_FVH");
        img[0x30..0x32].copy_from_slice(&0x48u16.to_le_bytes()); // header length
        let mut pos = 0x48u64;
        // Pad file (type 0xf0) 0x40 bytes, then aligned.
        let mut pad = vec![0u8; 0x40];
        pad[18] = 0xf0;
        pad[20..23].copy_from_slice(&0x40u32.to_le_bytes()[..3]);
        img[pos as usize..pos as usize + 0x40].copy_from_slice(&pad);
        pos += 0x40;
        pos = (pos + 7) & !7;

        // Real file: UI section "BOOTX64" + RAW section payload.
        let name_guid = [0x11u8; 16];
        let ui_name: Vec<u8> = "BOOTX64"
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect();
        let raw_payload = b"UEFI_RAW_PAYLOAD_1234";
        let sec1_len = 4 + ui_name.len();
        let sec2_len = 4 + raw_payload.len();
        let file_len = 24 + sec1_len + sec2_len;
        let mut file = vec![0u8; file_len];
        file[0..16].copy_from_slice(&name_guid);
        file[16] = 0xAA; // header checksum (placeholder)
        file[18] = 0x01; // RAW file type
        file[20..23].copy_from_slice(&(file_len as u32).to_le_bytes()[..3]);
        file[23] = 0xF8; // state: inverted bits for valid
                         // UI section.
        let off = 24;
        file[off..off + 3].copy_from_slice(&(sec1_len as u32).to_le_bytes()[..3]);
        file[off + 3] = 0x15;
        file[off + 4..off + 4 + ui_name.len()].copy_from_slice(&ui_name);
        // RAW section.
        let off2 = off + sec1_len;
        file[off2..off2 + 3].copy_from_slice(&(sec2_len as u32).to_le_bytes()[..3]);
        file[off2 + 3] = 0x19;
        file[off2 + 4..off2 + 4 + raw_payload.len()].copy_from_slice(raw_payload);
        img[pos as usize..pos as usize + file_len].copy_from_slice(&file);

        img
    }

    /// Build a BCM63xx tagged image: 256-byte ASCII tag, then CFE
    /// (64 bytes), kernel (128 bytes), rootfs (256 bytes) regions.
    fn bcm63xx_image() -> Vec<u8> {
        let mut tag = vec![0u8; 256];
        tag[0..4].copy_from_slice(b"0001"); // tagVersion
        tag[4..24].copy_from_slice(b"Broadcom Corporatio ");
        tag[38..44].copy_from_slice(b"6368  "); // chipid
        tag[44..60].copy_from_slice(b"HW553           "); // boardid
        tag[62..72].copy_from_slice(b"0000000448"); // totalLength 256+64+128
        tag[84..94].copy_from_slice(b"0000000064"); // cfeLength
        tag[128..138].copy_from_slice(b"0000000128"); // kernelLength
        tag[232..236].copy_from_slice(b"0256"); // rootLength (4 chars)
        let mut img = tag;
        img.extend_from_slice(&[0xC0u8; 64]); // CFE
        img.extend_from_slice(&[0x4Bu8; 128]); // kernel
        img.extend_from_slice(&[0x52u8; 256]); // rootfs
        img
    }

    #[test]
    fn bcm63xx_tag_regions() {
        let src = ByteSource::from_vec(bcm63xx_image());
        let out = validate_at(&Bcm63xxTagHandler, &src, 0).expect("tag validates");
        let art = &out.artifacts[0];
        assert_eq!(art.confidence, Confidence::Validated);
        assert_eq!(
            art.metadata.get("board_id").map(String::as_str),
            Some("HW553")
        );
        assert_eq!(
            art.metadata.get("chip_id").map(String::as_str),
            Some("6368")
        );
        let names: Vec<&str> = art
            .children
            .iter()
            .filter_map(|c| c.metadata.get("region").map(String::as_str))
            .collect();
        assert_eq!(names, vec!["cfe", "kernel", "rootfs"]);
        let rootfs = art
            .children
            .iter()
            .find(|c| c.metadata.get("region").map(String::as_str) == Some("rootfs"))
            .expect("rootfs child");
        match &rootfs.content {
            ChildContent::Source(r) => {
                let mut b = [0u8; 4];
                r.read_at(0, &mut b).unwrap();
                assert_eq!(&b, b"RRRR");
            }
            _ => panic!("rootfs must be source-backed"),
        }
    }

    #[test]
    fn uefi_ffs_walk_finds_named_file() {
        let src = ByteSource::from_vec(uefi_fv_image());
        let out = validate_at(&UefiFvHandler, &src, 0).expect("fv validates");
        let art = &out.artifacts[0];
        assert_eq!(art.confidence, Confidence::Validated);
        let ffs = art
            .children
            .iter()
            .find(|c| c.metadata.get("ui_name").map(String::as_str) == Some("BOOTX64"))
            .expect("BOOTX64 ffs child");
        assert_eq!(
            ffs.metadata.get("ffs_type").map(String::as_str),
            Some("0x01")
        );
        match &ffs.content {
            ChildContent::Owned(d) => assert_eq!(d, b"UEFI_RAW_PAYLOAD_1234"),
            _ => panic!("raw section payload must be exposed"),
        }
    }

    /// FINAL-B5: a GUID_DEFINED section carrying an LZMA-custom
    /// payload (LZMA_CUSTOM_DECOMPRESS_GUID) must be DECOMPRESSED and
    /// the decoded bytes become the FFS file content (recurse-ready),
    /// while a Tiano COMPRESSION section stays metadata-only with an
    /// honest warning.
    #[test]
    fn uefi_guid_defined_lzma_section_decoded() {
        // Build the LZMA-custom payload: 13-byte header + raw LZMA1
        // stream produced by lzma-rust's no-header encoder.
        let plaintext = b"UEFI_LZMA_DECODED_PAYLOAD_OK!";
        let options = lzma_rust::LZMA2Options {
            dict_size: 1 << 16,
            ..Default::default()
        };
        let mut comp: Vec<u8> = Vec::new();
        {
            let w = lzma_rust::LZMAWriter::new_no_header(
                lzma_rust::CountingWriter::new(&mut comp),
                &options,
                true, // end marker so the decoder stops without a size
            )
            .expect("encoder");
            // `w` must be finished to flush; restructure: new_no_header
            // returns the writer directly, so use it in a block.
            let mut w = w;
            std::io::Write::write_all(&mut w, plaintext).expect("write");
            w.finish().expect("finish");
        }
        let mut props = [0u8; 1];
        let mut dictb = [0u8; 4];
        // The encoder's props byte: reuse a known-good props byte for
        // default lc/lp/pb (0x5D = lc3/lp0/pb2).
        props[0] = 0x5D;
        dictb.copy_from_slice(&(1u32 << 16).to_le_bytes());
        let mut lzma_payload: Vec<u8> = Vec::new();
        lzma_payload.extend_from_slice(&props);
        lzma_payload.extend_from_slice(&dictb);
        lzma_payload.extend_from_slice(&(plaintext.len() as u64).to_le_bytes());
        lzma_payload.extend_from_slice(&comp);

        // Build a minimal FV with one FFS file containing a
        // GUID_DEFINED section wrapping the LZMA payload.
        let mut img = vec![0u8; 0x1000];
        img[0x20..0x28].copy_from_slice(&0x1000u64.to_le_bytes());
        img[0x28..0x2c].copy_from_slice(b"_FVH");
        img[0x30..0x32].copy_from_slice(&0x48u16.to_le_bytes());
        let mut ffs = Vec::new();
        // FFS header: name GUID(16) + integrity(2) + type(1) +
        // attributes(1) + size(3) + state(1).
        let data_len = 4 + 16 + 2 + 2 + lzma_payload.len(); // hdr+GUID+DataOffset+Attributes+payload
        let file_size = 24 + data_len as u32;
        ffs.extend_from_slice(&[0x11; 16]); // name GUID
        ffs.extend_from_slice(&[0xAA, 0x99]); // integrity
        ffs.push(0x02); // type: FREEFORM
        ffs.push(0x00); // attributes
        ffs.extend_from_slice(&file_size.to_le_bytes()[..3]);
        ffs.push(0xF8); // state: valid under 0xFF polarity
                        // (ffs bytes are copied into the FV at 0x48 below)
                        // GUID_DEFINED section header: size(3) + type(1) + GUID(16) +
                        // DataOffset(2) + Attributes(2).
        let ssize = (4 + 16 + 4 + lzma_payload.len()) as u32;
        ffs.extend_from_slice(&ssize.to_le_bytes()[..3]);
        ffs.push(SECTION_GUID_DEFINED);
        ffs.extend_from_slice(&LZMA_CUSTOM_DECOMPRESS_GUID);
        ffs.extend_from_slice(&(24u16).to_le_bytes()); // DataOffset
        ffs.extend_from_slice(&0u16.to_le_bytes()); // Attributes
                                                    // Payload: 13-byte header + raw stream.
        ffs.extend_from_slice(&lzma_payload);
        // Place the FFS file after the FV header (0x48), inside the FV.
        img[0x48..0x48 + ffs.len()].copy_from_slice(&ffs);
        let src = ByteSource::from_vec(img);
        let out = validate_at(&UefiFvHandler, &src, 0).expect("fv validates");
        let art = &out.artifacts[0];
        if art.children.is_empty() {
            panic!("no ffs children; warnings={:?}", art.warnings);
        }
        let ffs = art
            .children
            .iter()
            .find(|c| c.metadata.contains_key("ffs_name_guid"))
            .expect("ffs child");
        match &ffs.content {
            ChildContent::Owned(bytes) => {
                assert!(
                    bytes.windows(plaintext.len()).any(|w| w == plaintext),
                    "LZMA payload must be decoded into the file content, got {:02x?}",
                    &bytes[..bytes.len().min(16)]
                );
            }
            _ => panic!("decoded content must be owned bytes"),
        }
    }

    /// Android sparse image: 8 blocks of 4096; RAW 2 blocks, FILL
    /// 2 blocks, DONT_CARE 2 blocks, RAW 2 blocks.
    fn sparse_image() -> Vec<u8> {
        let mut img = Vec::new();
        let blk_sz: u32 = 4096;
        img.extend_from_slice(&0xed26ff3au32.to_le_bytes());
        img.extend_from_slice(&1u16.to_le_bytes()); // major
        img.extend_from_slice(&0u16.to_le_bytes()); // minor
        img.extend_from_slice(&28u16.to_le_bytes()); // file hdr
        img.extend_from_slice(&12u16.to_le_bytes()); // chunk hdr
        img.extend_from_slice(&blk_sz.to_le_bytes());
        img.extend_from_slice(&8u32.to_le_bytes()); // total_blks
        img.extend_from_slice(&5u32.to_le_bytes()); // total_chunks (incl CRC)
        img.extend_from_slice(&0u32.to_le_bytes()); // checksum unchecked (0)
                                                    // Chunk 1: RAW 2 blocks.
        img.extend_from_slice(&0xCAC1u16.to_le_bytes());
        img.extend_from_slice(&0u16.to_le_bytes());
        img.extend_from_slice(&2u32.to_le_bytes()); // blocks
        img.extend_from_slice(&(12 + 2 * blk_sz).to_le_bytes());
        img.extend_from_slice(&[0xAAu8; 8192]);
        // Chunk 2: FILL 2 blocks with 0xDEADBEEF.
        img.extend_from_slice(&0xCAC2u16.to_le_bytes());
        img.extend_from_slice(&0u16.to_le_bytes());
        img.extend_from_slice(&2u32.to_le_bytes());
        img.extend_from_slice(&16u32.to_le_bytes());
        img.extend_from_slice(&0xDEADBEEFu32.to_le_bytes());
        // Chunk 3: DONT_CARE 2 blocks (no data).
        img.extend_from_slice(&0xCAC3u16.to_le_bytes());
        img.extend_from_slice(&0u16.to_le_bytes());
        img.extend_from_slice(&2u32.to_le_bytes());
        img.extend_from_slice(&12u32.to_le_bytes());
        // Chunk 4: RAW 2 blocks.
        img.extend_from_slice(&0xCAC1u16.to_le_bytes());
        img.extend_from_slice(&0u16.to_le_bytes());
        img.extend_from_slice(&2u32.to_le_bytes());
        img.extend_from_slice(&(12 + 2 * blk_sz).to_le_bytes());
        img.extend_from_slice(&[0x55u8; 8192]);
        // Chunk 5: CRC32 value (unchecked here).
        img.extend_from_slice(&0xCAC4u16.to_le_bytes());
        img.extend_from_slice(&0u16.to_le_bytes());
        img.extend_from_slice(&0u32.to_le_bytes());
        img.extend_from_slice(&16u32.to_le_bytes());
        img.extend_from_slice(&0u32.to_le_bytes());
        img
    }

    #[test]
    fn android_sparse_expansion() {
        let src = ByteSource::from_vec(sparse_image());
        let out = validate_at(&AndroidSparseHandler, &src, 0).expect("sparse validates");
        let art = &out.artifacts[0];
        assert_eq!(art.confidence, Confidence::Validated);
        assert_eq!(
            art.metadata.get("expanded_size").map(String::as_str),
            Some("32768")
        );
        assert_eq!(art.children.len(), 1);
        match &art.children[0].content {
            ChildContent::Owned(d) => {
                assert_eq!(d.len(), 32768);
                assert_eq!(&d[..8192], &[0xAAu8; 8192]);
                // FILL 0xDEADBEEF repeated.
                assert_eq!(&d[8192..8196], &0xDEADBEEFu32.to_le_bytes());
                assert_eq!(&d[12284..12288], &[0xEF, 0xBE, 0xAD, 0xDE]);
                // DONT_CARE zero-filled.
                assert_eq!(&d[16384..16384 + 16], &[0u8; 16]);
                assert_eq!(&d[24576..24576 + 16], &[0x55u8; 16]);
            }
            _ => panic!("expanded image must be present"),
        }
    }

    #[test]
    fn dtb_structure_walk() {
        let mut dtb = Vec::new();
        dtb.extend(FDT_MAGIC.to_be_bytes());
        dtb.extend(64u32.to_be_bytes()); // totalsize
        dtb.extend(40u32.to_be_bytes()); // struct offset
        dtb.extend(60u32.to_be_bytes()); // strings offset
        dtb.extend(48u32.to_be_bytes()); // memrsv offset (inside totalsize)
        dtb.extend(17u32.to_be_bytes()); // version
        dtb.extend(17u32.to_be_bytes()); // last comp
        dtb.extend(2u32.to_be_bytes()); // boot cpuid
        dtb.extend(40u32.to_be_bytes()); // size of strings block
        dtb.extend(16u32.to_be_bytes()); // size of struct block
                                         // memrsv at 48: one entry + terminator (16 bytes -> 48..64? exceeds!)
                                         // Place a terminator-only rsv: 0,0.
                                         // Fix totalsize: recompute: struct at 40 (16 bytes) ends 56; strings
                                         // at 60; totalsize 64. memrsv at 48 would overlap struct. Use 0-entry.
                                         // Actually memrsv loop stops at zero entry; it's fine.
                                         // Structure block at 40: BEGIN_NODE("/") END_NODE END
        dtb.extend(0x1u32.to_be_bytes());
        dtb.push(0);
        dtb.push(0);
        dtb.push(0);
        dtb.push(0); // root "/"
        dtb.extend(0x9u32.to_be_bytes()); // FDT_END
                                          // pad to 64
        dtb.resize(64, 0);
        let src = ByteSource::from_vec(dtb);
        let out = validate_at(&DtbHandler, &src, 0).expect("dtb validates");
        let art = &out.artifacts[0];
        assert_eq!(art.confidence, Confidence::Validated);
        assert_eq!(art.size, 64);
        assert_eq!(art.metadata.get("nodes").map(String::as_str), Some("1"));
    }

    #[test]
    fn android_boot_kernel_ramdisk_children() {
        let page = 2048usize;
        let kernel = vec![0x11u8; 100];
        let ramdisk = vec![0x22u8; 50];
        let total_pages = 1 + kernel.len().div_ceil(page) + ramdisk.len().div_ceil(page);
        let mut img = vec![0u8; total_pages * page];
        img[0..8].copy_from_slice(b"ANDROID!");
        img[8..12].copy_from_slice(&(kernel.len() as u32).to_le_bytes());
        img[12..16].copy_from_slice(&0x8000u32.to_le_bytes());
        img[16..20].copy_from_slice(&(ramdisk.len() as u32).to_le_bytes());
        img[20..24].copy_from_slice(&0x8100u32.to_le_bytes());
        img[36..40].copy_from_slice(&(page as u32).to_le_bytes());
        img[page..page + 100].copy_from_slice(&kernel);
        img[2 * page..2 * page + 50].copy_from_slice(&ramdisk);
        let src = ByteSource::from_vec(img);
        let out = validate_at(&AndroidBootHandler, &src, 0).expect("boot img validates");
        let art = &out.artifacts[0];
        assert_eq!(art.confidence, Confidence::Validated);
        assert_eq!(art.children.len(), 2);
        match &art.children[1].content {
            ChildContent::Source(r) => {
                let bytes = r.read_all().unwrap();
                assert_eq!(bytes, ramdisk);
            }
            _ => panic!("ramdisk must be source-backed"),
        }
    }

    #[test]
    fn trx_partitions_sliced() {
        let mut img = vec![0u8; 4096];
        img[0..4].copy_from_slice(b"HDR0");
        img[4..8].copy_from_slice(&1u32.to_le_bytes()); // version 1
        img[8..12].copy_from_slice(&4096u32.to_le_bytes()); // length
        img[12..16].copy_from_slice(&28u32.to_le_bytes()); // off 0 (kernel)
        img[16..20].copy_from_slice(&1028u32.to_le_bytes()); // off 1
        img[20..24].copy_from_slice(&0u32.to_le_bytes()); // unused
        img[28..38].copy_from_slice(b"KERNELDATA");
        img[1028..1038].copy_from_slice(b"RAMDISK123");
        let src = ByteSource::from_vec(img);
        let out = validate_at(&TrxHandler, &src, 0).expect("trx validates");
        let art = &out.artifacts[0];
        assert_eq!(art.confidence, Confidence::Validated);
        assert_eq!(art.children.len(), 2);
    }

    #[test]
    fn uefi_fv_partial_detected() {
        let mut img = vec![0u8; 4096];
        img[0x28..0x2C].copy_from_slice(b"_FVH");
        img[0x20..0x28].copy_from_slice(&4096u64.to_le_bytes());
        let src = ByteSource::from_vec(img);
        let out = validate_at(&UefiFvHandler, &src, 0).expect("fv validates");
        let art = &out.artifacts[0];
        assert_eq!(art.confidence, Confidence::Partial);
        assert_eq!(art.size, 4096);
    }
}
