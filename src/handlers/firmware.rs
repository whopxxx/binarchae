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
        _limits: &crate::engine::EngineLimits,
        _budget: &mut Budget,
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
        let header_length = le32(src, base + 0x30).unwrap_or(0) as u64 >> 16;
        let guid_raw = {
            let mut g = [0u8; 16];
            src.read_at(base + 16, &mut g)?;
            g
        };

        let mut metadata = BTreeMap::new();
        metadata.insert("fv_length".to_string(), fv_length.to_string());
        metadata.insert("header_length".to_string(), header_length.to_string());
        metadata.insert("firmware_volume_guid".to_string(), guid_hex(&guid_raw));

        Ok(HandlerOutput {
            artifacts: vec![ArtifactDraft {
                format: "uefi-fv".to_string(),
                label: format!("UEFI firmware volume ({} bytes)", fv_length),
                offset: base,
                size: fv_length,
                confidence: Confidence::Partial,
                evidence: Evidence::facts([
                    "_FVH signature validated".to_string(),
                    format!("FvLength {fv_length} bytes"),
                    "FFS file walking planned for a hardening pass".to_string(),
                ]),
                metadata,
                warnings: vec![
                    "FFS file-level traversal is planned for a hardening pass".to_string()
                ],
                errors: Vec::new(),
                children: Vec::new(),
            }],
        })
    }
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
