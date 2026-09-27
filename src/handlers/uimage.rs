//! U-Boot legacy uImage handler (M2).
//!
//! Legacy image header (64 bytes, all fields big-endian):
//! ```text
//! 0x00  u32  ih_magic      0x27051956
//! 0x04  u32  ih_hcrc       CRC32 of the header with this field zeroed
//! 0x08  u32  ih_time       creation timestamp (Unix)
//! 0x0C  u32  ih_size       payload size in bytes
//! 0x10  u32  ih_load       load address
//! 0x14  u32  ih_ep         entry point
//! 0x18  u32  ih_dcrc       CRC32 of the payload
//! 0x1C  u8   ih_os
//! 0x1D  u8   ih_arch
//! 0x1E  u8   ih_type
//! 0x1F  u8   ih_comp
//! 0x20  [u8; 32] ih_name
//! ```
//!
//! Magic is only a candidate: the complete header must be present, the
//! header CRC must verify (field zeroed), the exact artifact boundary is
//! `64 + ih_size` with checked arithmetic, and the data CRC must verify
//! over exactly the declared payload before the artifact is `Validated`.
//!
//! Multi-file images (`IH_TYPE_MULTI`) begin their payload with a
//! big-endian 32-bit length table terminated by a zero entry; each
//! component is exposed as a separate source-backed child.

use crate::artifact::{Confidence, Evidence, RelationKind};
use crate::bytesource::ByteSource;
use crate::engine::{ChildContent, ChildDraft, Handler, HandlerOutput};
use crate::error::{Error, Result};
use crate::handlers::find_all;
use std::collections::BTreeMap;

pub struct UImageHandler;

const IH_MAGIC: u32 = 0x2705_1956;
const HEADER_LEN: u64 = 64;
const MULTI: u8 = 4; // IH_TYPE_MULTI

/// Magic as a 4-byte big-endian pattern for candidate scanning.
const MAGIC_BE: [u8; 4] = [
    (IH_MAGIC >> 24) as u8,
    (IH_MAGIC >> 16) as u8,
    (IH_MAGIC >> 8) as u8,
    IH_MAGIC as u8,
];

impl Handler for UImageHandler {
    fn format(&self) -> &'static str {
        "uimage"
    }

    fn find_candidates(&self, src: &ByteSource) -> Vec<crate::engine::Candidate> {
        find_all(src, &MAGIC_BE)
            .into_iter()
            .map(|offset| crate::engine::Candidate { offset })
            .collect()
    }

    fn validate(
        &self,
        src: &ByteSource,
        candidate: crate::engine::Candidate,
        limits: &crate::engine::EngineLimits,
        _budget: &mut crate::engine::Budget,
    ) -> Result<HandlerOutput> {
        let base = candidate.offset;
        // Require the complete 64-byte header.
        if base
            .checked_add(HEADER_LEN)
            .map_or(true, |end| end > src.len())
        {
            return Err(Error::Validation {
                format: "uimage",
                reason: "incomplete header".into(),
            });
        }
        let mut hdr = [0u8; 64];
        src.read_at(base, &mut hdr)?;

        // Header CRC: zero the ih_hcrc field, CRC32 the full header.
        let stored_hcrc = u32::from_be_bytes([hdr[4], hdr[5], hdr[6], hdr[7]]);
        let mut zeroed = hdr;
        zeroed[4..8].fill(0);
        let mut h = crc32fast::Hasher::new();
        h.update(&zeroed);
        let computed_hcrc = h.finalize();
        let header_crc_ok = stored_hcrc == computed_hcrc;

        // Declared payload size (checked arithmetic everywhere below).
        let ih_size = u32::from_be_bytes([hdr[12], hdr[13], hdr[14], hdr[15]]) as u64;
        if ih_size > limits.max_child_size {
            return Err(Error::Validation {
                format: "uimage",
                reason: format!("declared payload {ih_size} exceeds max child size"),
            });
        }
        let data_start = base + HEADER_LEN;
        let data_end = data_start.checked_add(ih_size).ok_or(Error::Validation {
            format: "uimage",
            reason: "declared size overflow".into(),
        })?;
        if data_end > src.len() {
            return Err(Error::Validation {
                format: "uimage",
                reason: format!("declared payload extends past source ({ih_size} bytes)"),
            });
        }

        // Data CRC over exactly the declared payload.
        let payload = src.slice(data_start, ih_size)?;
        let stored_dcrc = u32::from_be_bytes([hdr[24], hdr[25], hdr[26], hdr[27]]);
        let mut data_crc_ok = false;
        let mut dcrc_warning = String::new();
        if ih_size == 0 {
            // Zero-size payloads: CRC of nothing matches CRC of nothing.
            let zh = crc32fast::Hasher::new();
            data_crc_ok = stored_dcrc == zh.finalize();
        } else {
            let mut chunk = [0u8; 64 * 1024];
            let mut off = 0u64;
            let mut dh = crc32fast::Hasher::new();
            let mut truncated = false;
            while off < ih_size {
                let n = (ih_size - off).min(chunk.len() as u64) as usize;
                if payload.read_at(off, &mut chunk[..n]).is_err() {
                    truncated = true;
                    break;
                }
                dh.update(&chunk[..n]);
                off += n as u64;
            }
            if !truncated {
                data_crc_ok = stored_dcrc == dh.finalize();
            }
            if !data_crc_ok {
                dcrc_warning = format!("data CRC mismatch (stored {stored_dcrc:#010x})");
            }
        }

        // Confidence: honest, evidence-based.
        let (confidence, warnings) = if header_crc_ok && data_crc_ok {
            (Confidence::Validated, Vec::new())
        } else if header_crc_ok {
            (
                Confidence::Damaged,
                vec![
                    dcrc_warning,
                    "header CRC valid but data CRC failed; payload exposed \
                     as damaged, not recursed"
                        .to_string(),
                ],
            )
        } else {
            return Err(Error::Validation {
                format: "uimage",
                reason: format!("header CRC mismatch (stored {stored_hcrc:#010x})"),
            });
        };

        // Parse enum fields; unknown values stay numeric (no parser failure).
        let os_code = hdr[28];
        let arch_code = hdr[29];
        let type_code = hdr[30];
        let comp_code = hdr[31];
        let name = hdr[32..64].iter().position(|&b| b == 0).map_or_else(
            || String::from_utf8_lossy(&hdr[32..64]).into_owned(),
            |p| String::from_utf8_lossy(&hdr[32..32 + p]).into_owned(),
        );
        let ih_time = u32::from_be_bytes([hdr[8], hdr[9], hdr[10], hdr[11]]);
        let ih_load = u32::from_be_bytes([hdr[16], hdr[17], hdr[18], hdr[19]]);
        let ih_ep = u32::from_be_bytes([hdr[20], hdr[21], hdr[22], hdr[23]]);

        let mut metadata = BTreeMap::new();
        metadata.insert("timestamp".to_string(), ih_time.to_string());
        metadata.insert("load_address".to_string(), format!("{ih_load:#010x}"));
        metadata.insert("entry_point".to_string(), format!("{ih_ep:#010x}"));
        metadata.insert("os".to_string(), os_name(os_code));
        metadata.insert("architecture".to_string(), arch_name(arch_code));
        metadata.insert("image_type".to_string(), type_name(type_code));
        metadata.insert("compression".to_string(), comp_name(comp_code));
        metadata.insert("image_name".to_string(), name.clone());
        metadata.insert("payload_size".to_string(), ih_size.to_string());
        metadata.insert(
            "header_crc".to_string(),
            if header_crc_ok { "valid" } else { "mismatch" }.to_string(),
        );
        metadata.insert(
            "data_crc".to_string(),
            if data_crc_ok { "valid" } else { "mismatch" }.to_string(),
        );

        // Payload children. Validated images only: damaged payloads are
        // exposed but NOT recursed into untrusted boundaries.
        let mut children: Vec<ChildDraft> = Vec::new();
        if confidence == Confidence::Validated && ih_size > 0 {
            if type_code == MULTI {
                children = parse_multi_components(&payload, ih_size)?;
            } else {
                children.push(ChildDraft {
                    relation: RelationKind::Contains,
                    label: format!("uImage payload ({ih_size} bytes)"),
                    format_hint: "raw",
                    content: ChildContent::Source(payload),
                    size: ih_size,
                    metadata: BTreeMap::new(),
                    warnings: Vec::new(),
                    entry_name: None,
                });
            }
        }

        Ok(HandlerOutput {
            artifacts: vec![crate::engine::ArtifactDraft {
                format: "uimage".to_string(),
                label: format!("U-Boot uImage \"{name}\" ({ih_size} bytes)"),
                offset: base,
                size: HEADER_LEN + ih_size,
                confidence,
                evidence: Evidence::facts([
                    "legacy magic + complete 64-byte header".to_string(),
                    if header_crc_ok {
                        "header CRC verified".to_string()
                    } else {
                        "header CRC FAILED".to_string()
                    },
                    if data_crc_ok {
                        "data CRC verified over declared payload".to_string()
                    } else {
                        "data CRC FAILED".to_string()
                    },
                ]),
                metadata,
                warnings,
                errors: Vec::new(),
                children,
            }],
        })
    }
}

/// Parse an IH_TYPE_MULTI payload: big-endian u32 component lengths
/// terminated by a zero entry, followed by the components (4-byte
/// aligned per the legacy format). Malformed tables fail safely.
fn parse_multi_components(payload: &ByteSource, total: u64) -> Result<Vec<ChildDraft>> {
    const MAX_COMPONENTS: usize = 1024;
    let mut lengths: Vec<u64> = Vec::new();
    let mut table_off: u64 = 0;
    loop {
        if lengths.len() > MAX_COMPONENTS {
            return Err(Error::Validation {
                format: "uimage",
                reason: "multi-file table exceeds component limit".into(),
            });
        }
        if table_off + 4 > total {
            return Err(Error::Validation {
                format: "uimage",
                reason: "multi-file size table truncated (no terminator)".into(),
            });
        }
        let mut lb = [0u8; 4];
        payload.read_at(table_off, &mut lb)?;
        let len = u32::from_be_bytes(lb) as u64;
        if len == 0 {
            break; // terminator
        }
        lengths.push(len);
        table_off += 4;
    }

    // Components follow the table (which occupies (n+1) * 4 bytes),
    // 4-byte aligned.
    let table_len = (lengths.len() as u64 + 1) * 4;
    let mut data_off = table_len;
    let mut children = Vec::new();
    for (idx, &len) in lengths.iter().enumerate() {
        let end = data_off.checked_add(len).ok_or(Error::Validation {
            format: "uimage",
            reason: "component offset overflow".into(),
        })?;
        if end > total {
            return Err(Error::Validation {
                format: "uimage",
                reason: format!("component {idx} ({len} bytes) extends past payload"),
            });
        }
        let comp = payload.slice(data_off, len)?;
        let mut meta = BTreeMap::new();
        meta.insert("component_index".to_string(), idx.to_string());
        meta.insert("declared_size".to_string(), len.to_string());
        children.push(ChildDraft {
            relation: RelationKind::Contains,
            label: format!("uImage multi-file component {idx} ({len} bytes)"),
            format_hint: "raw",
            content: ChildContent::Source(comp),
            size: len,
            metadata: meta,
            warnings: Vec::new(),
            entry_name: None,
        });
        // 4-byte alignment between components.
        data_off = end + (4 - (end % 4)) % 4;
    }
    Ok(children)
}

fn os_name(code: u8) -> String {
    match code {
        0 => "invalid".to_string(),
        1 => "OpenBSD".to_string(),
        2 => "NetBSD".to_string(),
        3 => "FreeBSD".to_string(),
        4 => "4.4BSD".to_string(),
        5 => "Linux".to_string(),
        6 => "SVR4".to_string(),
        7 => "Esix".to_string(),
        8 => "Solaris".to_string(),
        9 => "Irix".to_string(),
        10 => "SCO".to_string(),
        11 => "Dell".to_string(),
        12 => "NCR".to_string(),
        13 => "LynxOS".to_string(),
        14 => "VxWorks".to_string(),
        15 => "pSOS".to_string(),
        16 => "QNX".to_string(),
        17 => "u-Boot".to_string(),
        18 => "RTEMS".to_string(),
        19 => "ARTOS".to_string(),
        20 => "Unity OS".to_string(),
        other => format!("unknown({other})"),
    }
}

fn arch_name(code: u8) -> String {
    match code {
        1 => "Alpha".to_string(),
        2 => "ARM".to_string(),
        3 => "x86 (i386)".to_string(),
        4 => "IA64".to_string(),
        5 => "MIPS".to_string(),
        6 => "MIPS64".to_string(),
        7 => "PPC".to_string(),
        8 => "S390".to_string(),
        9 => "SH".to_string(),
        10 => "Sparc".to_string(),
        11 => "Sparc64".to_string(),
        12 => "M68K".to_string(),
        13 => "Nios".to_string(),
        14 => "MicroBlaze".to_string(),
        15 => "Nios II".to_string(),
        16 => "Blackfin".to_string(),
        17 => "AVR32".to_string(),
        18 => "ST200".to_string(),
        19 => "Sandbox".to_string(),
        20 => "NDS32".to_string(),
        21 => "OpenRISC".to_string(),
        22 => "ARM64".to_string(),
        23 => "Arc".to_string(),
        24 => "x86-64".to_string(),
        25 => "Xtensa".to_string(),
        26 => "RISC-V".to_string(),
        other => format!("unknown({other})"),
    }
}

fn type_name(code: u8) -> String {
    match code {
        1 => "standalone".to_string(),
        2 => "kernel".to_string(),
        3 => "ramdisk".to_string(),
        4 => "multi-file".to_string(),
        5 => "firmware".to_string(),
        6 => "script".to_string(),
        7 => "filesystem".to_string(),
        8 => "flat device tree".to_string(),
        9 => "kirkwood boot".to_string(),
        other => format!("unknown({other})"),
    }
}

fn comp_name(code: u8) -> String {
    match code {
        0 => "none".to_string(),
        1 => "gzip".to_string(),
        2 => "bzip2".to_string(),
        3 => "lzma".to_string(),
        4 => "lzo".to_string(),
        5 => "lz4".to_string(),
        6 => "zstd".to_string(),
        other => format!("unknown({other})"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::{Budget, Candidate};

    const PAYLOAD: &[u8] = b"hello initramfs payload 0123456789";

    fn build_header(payload: &[u8], ih_type: u8, name: &str) -> ([u8; 64], Vec<u8>) {
        let mut hdr = [0u8; 64];
        hdr[0..4].copy_from_slice(&IH_MAGIC.to_be_bytes());
        // ih_hcrc zeroed for now.
        hdr[8..12].copy_from_slice(&1_700_000_000u32.to_be_bytes());
        hdr[12..16].copy_from_slice(&(payload.len() as u32).to_be_bytes());
        hdr[16..20].copy_from_slice(&0x8000_0000u32.to_be_bytes()); // load
        hdr[20..24].copy_from_slice(&0x8000_8000u32.to_be_bytes()); // ep
        let mut dh = crc32fast::Hasher::new();
        dh.update(payload);
        hdr[24..28].copy_from_slice(&dh.finalize().to_be_bytes());
        hdr[28] = 5; // Linux
        hdr[29] = 2; // ARM
        hdr[30] = ih_type;
        hdr[31] = 0; // none
        let nb = name.as_bytes();
        hdr[32..32 + nb.len().min(32)].copy_from_slice(&nb[..nb.len().min(32)]);
        // Compute header CRC with the field zeroed.
        let mut zh = [0u8; 64];
        zh.copy_from_slice(&hdr);
        zh[4..8].fill(0);
        let mut hh = crc32fast::Hasher::new();
        hh.update(&zh);
        let hcrc = hh.finalize();
        hdr[4..8].copy_from_slice(&hcrc.to_be_bytes());
        (hdr, payload.to_vec())
    }

    fn assemble(payload: &[u8], ih_type: u8, name: &str, trailing: &[u8]) -> ByteSource {
        let (hdr, data) = build_header(payload, ih_type, name);
        let mut img = hdr.to_vec();
        img.extend_from_slice(&data);
        img.extend_from_slice(trailing);
        ByteSource::from_vec(img)
    }

    #[test]
    fn valid_uimage_validated_with_source_backed_child() {
        let src = assemble(PAYLOAD, 2, "test-image", &[]);
        let h = UImageHandler;
        let mut budget = Budget::default();
        let out = h
            .validate(
                &src,
                Candidate { offset: 0 },
                &crate::engine::EngineLimits::default(),
                &mut budget,
            )
            .expect("valid uImage");
        let art = &out.artifacts[0];
        assert_eq!(art.confidence, Confidence::Validated);
        assert_eq!(art.size, 64 + PAYLOAD.len() as u64);
        // Source-backed child: exact region, no owned copy.
        let child = &art.children[0];
        assert_eq!(child.size, PAYLOAD.len() as u64);
        match &child.content {
            ChildContent::Source(region) => {
                assert_eq!(region.len(), PAYLOAD.len() as u64);
                assert_eq!(region.root_offset(), 64);
                assert_eq!(region.read_all().unwrap(), PAYLOAD);
            }
            ChildContent::Owned(_) => panic!("payload must be source-backed, not owned"),
        }
        assert_eq!(art.metadata.get("os").map(String::as_str), Some("Linux"));
        assert_eq!(
            art.metadata.get("header_crc").map(String::as_str),
            Some("valid")
        );
        assert_eq!(
            art.metadata.get("data_crc").map(String::as_str),
            Some("valid")
        );
    }

    #[test]
    fn bad_header_crc_rejected() {
        let mut img = assemble(PAYLOAD, 2, "x", &[]).read_all().unwrap();
        img[5] ^= 0xff; // corrupt stored header CRC
        let src = ByteSource::from_vec(img);
        let h = UImageHandler;
        let mut budget = Budget::default();
        assert!(h
            .validate(
                &src,
                Candidate { offset: 0 },
                &crate::engine::EngineLimits::default(),
                &mut budget
            )
            .is_err());
    }

    #[test]
    fn bad_data_crc_not_validated() {
        let payload: &[u8] = b"payload that will be corrupted in place 123";
        let (hdr, _data) = build_header(payload, 2, "x");
        let mut img = hdr.to_vec();
        let mut corrupted = payload.to_vec();
        corrupted[3] ^= 0xff;
        img.extend_from_slice(&corrupted);
        let src = ByteSource::from_vec(img);
        let h = UImageHandler;
        let mut budget = Budget::default();
        let out = h
            .validate(
                &src,
                Candidate { offset: 0 },
                &crate::engine::EngineLimits::default(),
                &mut budget,
            )
            .expect("header crc ok, damaged payload exposed");
        let art = &out.artifacts[0];
        assert_eq!(art.confidence, Confidence::Damaged);
        assert_eq!(
            art.metadata.get("data_crc").map(String::as_str),
            Some("mismatch")
        );
        assert!(art.children.is_empty(), "damaged payload must not recurse");
    }

    #[test]
    fn declared_size_truncation_rejected() {
        // Declared size larger than what follows.
        let (mut hdr, _) = build_header(PAYLOAD, 2, "x");
        hdr[12..16].copy_from_slice(&u32::MAX.to_be_bytes());
        let mut img = hdr.to_vec();
        img.extend_from_slice(PAYLOAD);
        let src = ByteSource::from_vec(img);
        let h = UImageHandler;
        let mut budget = Budget::default();
        let res = h.validate(
            &src,
            Candidate { offset: 0 },
            &crate::engine::EngineLimits::default(),
            &mut budget,
        );
        assert!(res.is_err(), "oversized declaration must fail safely");
    }

    #[test]
    fn exact_boundary_with_trailing_bytes() {
        let src = assemble(PAYLOAD, 2, "x", b"TRAILING-JUNK");
        let h = UImageHandler;
        let mut budget = Budget::default();
        let out = h
            .validate(
                &src,
                Candidate { offset: 0 },
                &crate::engine::EngineLimits::default(),
                &mut budget,
            )
            .unwrap();
        assert_eq!(out.artifacts[0].size, 64 + PAYLOAD.len() as u64);
    }

    #[test]
    fn multi_file_components() {
        // Table: [len_a, len_b, 0] then components, 4-byte aligned.
        let comp_a = b"kernel-image-bytes".to_vec();
        let comp_b = b"ramdisk-bytes-xyz".to_vec();
        let mut table = Vec::new();
        table.extend_from_slice(&(comp_a.len() as u32).to_be_bytes());
        table.extend_from_slice(&(comp_b.len() as u32).to_be_bytes());
        table.extend_from_slice(&0u32.to_be_bytes());
        let mut payload = table.clone();
        payload.extend_from_slice(&comp_a);
        // align comp_b start to 4
        while payload.len() % 4 != 0 {
            payload.push(0);
        }
        payload.extend_from_slice(&comp_b);
        let src = assemble(&payload, MULTI, "multi", &[]);
        let h = UImageHandler;
        let mut budget = Budget::default();
        let out = h
            .validate(
                &src,
                Candidate { offset: 0 },
                &crate::engine::EngineLimits::default(),
                &mut budget,
            )
            .expect("multi-file uImage");
        let children = &out.artifacts[0].children;
        assert_eq!(children.len(), 2);
        for (idx, child) in children.iter().enumerate() {
            assert_eq!(
                child.metadata.get("component_index").map(String::as_str),
                Some(idx.to_string().as_str())
            );
            match &child.content {
                ChildContent::Source(r) => assert!(!r.is_empty()),
                ChildContent::Owned(_) => panic!("components must be source-backed"),
            }
        }
    }

    #[test]
    fn malformed_multi_table_fails_safely() {
        // Table without a terminator: all bytes nonzero.
        let payload = vec![0xffu8; 64];
        let src = assemble(&payload, MULTI, "bad", &[]);
        let h = UImageHandler;
        let mut budget = Budget::default();
        let res = h.validate(
            &src,
            Candidate { offset: 0 },
            &crate::engine::EngineLimits::default(),
            &mut budget,
        );
        assert!(res.is_err(), "unterminated table must fail safely");
    }
}
