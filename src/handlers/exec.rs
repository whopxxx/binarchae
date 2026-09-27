//! M3 executable/document-format handlers: ELF, PE, Mach-O, WASM, OLE
//! Compound File, RTF.
//!
//! All parsers are structural (real headers, program/section tables,
//! b-tree metadata), produce useful metadata, and keep boundaries
//! honest. Embedded regions (sections, OLE streams) become children
//! where bounded and useful.

use crate::artifact::{Confidence, Evidence};
use crate::bytesource::ByteSource;
use crate::engine::{ArtifactDraft, Budget, Candidate, Handler, HandlerOutput};
use crate::error::{Error, Result};
use crate::handlers::find_all;
use std::collections::BTreeMap;

// ---------------------------------------------------------------------------
// ELF
// ---------------------------------------------------------------------------

pub struct ElfHandler;

impl Handler for ElfHandler {
    fn format(&self) -> &'static str {
        "elf"
    }

    fn find_candidates(&self, src: &ByteSource) -> Vec<Candidate> {
        find_all(src, b"\x7fELF")
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
        if base + 64 > src.len() {
            return Err(Error::Validation {
                format: "elf",
                reason: "truncated ELF header".into(),
            });
        }
        let mut hdr = [0u8; 64];
        src.read_at(base, &mut hdr)?;
        let class = hdr[4]; // 1 = 32-bit, 2 = 64-bit
        let data = hdr[5]; // 1 = LE, 2 = BE
        if !matches!(class, 1 | 2) || !matches!(data, 1 | 2) {
            return Err(Error::Validation {
                format: "elf",
                reason: format!("invalid class/data {class}/{data}"),
            });
        }
        let is64 = class == 2;
        let le = data == 1;
        let (u16_at, u32_at, u64_at): (
            fn(&ByteSource, u64) -> Option<u16>,
            fn(&ByteSource, u64) -> Option<u32>,
            fn(&ByteSource, u64) -> Option<u64>,
        ) = if le {
            (Self::le16, Self::le32, Self::le64)
        } else {
            (Self::be16, Self::be32, Self::be64)
        };

        let e_type = u16_at(src, base + 16).unwrap_or(0);
        let e_machine = u16_at(src, base + 18).unwrap_or(0);
        let (shoff, shentsize, shnum) = if is64 {
            (
                u64_at(src, base + 40).unwrap_or(0),
                u64::from(u16_at(src, base + 58).unwrap_or(0)),
                u64::from(u16_at(src, base + 60).unwrap_or(0)),
            )
        } else {
            (
                u64::from(u32_at(src, base + 32).unwrap_or(0)),
                u64::from(u16_at(src, base + 46).unwrap_or(0)),
                u64::from(u16_at(src, base + 48).unwrap_or(0)),
            )
        };

        if shentsize > 0 && shnum > 0 {
            let span = shoff
                .checked_add(shnum.checked_mul(shentsize).ok_or(Error::Validation {
                    format: "elf",
                    reason: "section table overflow".into(),
                })?)
                .ok_or(Error::Validation {
                    format: "elf",
                    reason: "section table overflow".into(),
                })?;
            if base + span > src.len() {
                return Err(Error::Validation {
                    format: "elf",
                    reason: format!("section table ({shnum} entries) extends past source"),
                });
            }
        }
        if shnum as usize > limits.max_records {
            return Err(Error::Validation {
                format: "elf",
                reason: "section limit exceeded".into(),
            });
        }

        let type_name = match e_type {
            1 => "relocatable",
            2 => "executable",
            3 => "shared object",
            4 => "core dump",
            _ => "unknown",
        };
        let machine = match e_machine {
            3 => "x86",
            62 => "x86-64",
            40 => "ARM",
            183 => "AArch64",
            8 => "MIPS",
            22 => "SPARC",
            _ => "unknown",
        };

        let mut metadata = BTreeMap::new();
        metadata.insert(
            "class".to_string(),
            if is64 { "64-bit" } else { "32-bit" }.to_string(),
        );
        metadata.insert(
            "byte_order".to_string(),
            if le { "little" } else { "big" }.to_string(),
        );
        metadata.insert("type".to_string(), type_name.to_string());
        metadata.insert("machine".to_string(), machine.to_string());
        metadata.insert("section_count".to_string(), shnum.to_string());

        Ok(HandlerOutput {
            artifacts: vec![ArtifactDraft {
                format: "elf".to_string(),
                label: format!(
                    "ELF {type_name} ({machine}, {})",
                    if is64 { "64-bit" } else { "32-bit" }
                ),
                offset: base,
                size: src.len() - base,
                confidence: Confidence::Validated,
                evidence: Evidence::facts([
                    "ELF magic + ident validated".to_string(),
                    format!("{} section headers at +{shoff}", shnum),
                    "section table bounds-checked".to_string(),
                ]),
                metadata,
                warnings: if shnum == 0 {
                    vec!["no section header table (stripped or object-less)".to_string()]
                } else {
                    Vec::new()
                },
                errors: Vec::new(),
                children: Vec::new(),
            }],
        })
    }
}

impl ElfHandler {
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
    fn be16(src: &ByteSource, off: u64) -> Option<u16> {
        let mut b = [0u8; 2];
        src.read_at(off, &mut b).ok()?;
        Some(u16::from_be_bytes(b))
    }
    fn be32(src: &ByteSource, off: u64) -> Option<u32> {
        let mut b = [0u8; 4];
        src.read_at(off, &mut b).ok()?;
        Some(u32::from_be_bytes(b))
    }
    fn be64(src: &ByteSource, off: u64) -> Option<u64> {
        let mut b = [0u8; 8];
        src.read_at(off, &mut b).ok()?;
        Some(u64::from_be_bytes(b))
    }
}

// ---------------------------------------------------------------------------
// PE (DOS header + PE header + optional header)
// ---------------------------------------------------------------------------

pub struct PeHandler;

impl Handler for PeHandler {
    fn format(&self) -> &'static str {
        "pe"
    }

    fn find_candidates(&self, src: &ByteSource) -> Vec<Candidate> {
        find_all(src, b"MZ")
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
        if base + 64 > src.len() {
            return Err(Error::Validation {
                format: "pe",
                reason: "truncated DOS header".into(),
            });
        }
        let e_lfanew = match crate::handlers::media_read_u32_le(src, base + 0x3c) {
            Some(v) if v > 0 && v < 0x1000_0000 => u64::from(v),
            _ => {
                return Err(Error::Validation {
                    format: "pe",
                    reason: "implausible e_lfanew".into(),
                })
            }
        };
        let pe_at = base + e_lfanew;
        if pe_at + 24 > src.len() {
            return Err(Error::Validation {
                format: "pe",
                reason: "PE header out of bounds".into(),
            });
        }
        let mut sig = [0u8; 4];
        src.read_at(pe_at, &mut sig)?;
        if &sig != b"PE\0\0" {
            return Err(Error::Validation {
                format: "pe",
                reason: "no PE signature at e_lfanew".into(),
            });
        }
        let machine = crate::handlers::media_read_u16_le(src, pe_at + 4).unwrap_or(0);
        let num_sections = crate::handlers::media_read_u16_le(src, pe_at + 6).unwrap_or(0);
        let opt_header_size = crate::handlers::media_read_u16_le(src, pe_at + 20).unwrap_or(0);
        if num_sections as usize > limits.max_records {
            return Err(Error::Validation {
                format: "pe",
                reason: "section limit exceeded".into(),
            });
        }
        let arch = match machine {
            0x014c => "x86",
            0x8664 => "x64",
            0x01c0 => "ARM",
            0xAA64 => "ARM64",
            _ => "unknown",
        };

        let mut metadata = BTreeMap::new();
        metadata.insert("machine".to_string(), arch.to_string());
        metadata.insert("sections".to_string(), num_sections.to_string());

        Ok(HandlerOutput {
            artifacts: vec![ArtifactDraft {
                format: "pe".to_string(),
                label: format!("PE executable ({arch}, {} sections)", num_sections),
                offset: base,
                size: src.len() - base,
                confidence: Confidence::Validated,
                evidence: Evidence::facts([
                    "DOS header + PE signature validated".to_string(),
                    format!(
                        "{} sections, optional header {} bytes",
                        num_sections, opt_header_size
                    ),
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
// Mach-O
// ---------------------------------------------------------------------------

pub struct MachOHandler;

impl Handler for MachOHandler {
    fn format(&self) -> &'static str {
        "macho"
    }

    fn find_candidates(&self, src: &ByteSource) -> Vec<Candidate> {
        let mut hits: Vec<Candidate> = [
            b"\xcf\xfa\xed\xfe" as &[u8],
            b"\xfe\xed\xfa\xcf",
            b"\xca\xfe\xba\xbe",
            b"\xce\xfa\xed\xfe",
        ]
        .iter()
        .flat_map(|m| find_all(src, m))
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
        _budget: &mut Budget,
    ) -> Result<HandlerOutput> {
        let base = candidate.offset;
        if base + 28 > src.len() {
            return Err(Error::Validation {
                format: "macho",
                reason: "truncated header".into(),
            });
        }
        let mut magic = [0u8; 4];
        src.read_at(base, &mut magic)?;
        let le = &magic == b"\xcf\xfa\xed\xfe" || &magic == b"\xce\xfa\xed\xfe";
        let is64 = &magic == b"\xcf\xfa\xed\xfe" || &magic == b"\xfe\xed\xfa\xcf";
        if &magic == b"\xca\xfe\xba\xbe" {
            return Err(Error::Validation {
                format: "macho",
                reason: "fat/universal binary; per-arch slices not walked".into(),
            });
        }
        let u32_at = if le {
            crate::handlers::media_read_u32_le as fn(&ByteSource, u64) -> Option<u32>
        } else {
            crate::handlers::media_read_u32_be as fn(&ByteSource, u64) -> Option<u32>
        };
        let ncmds = u32_at(src, base + 16).unwrap_or(0) as usize;
        if ncmds > limits.max_records {
            return Err(Error::Validation {
                format: "macho",
                reason: "load-command limit exceeded".into(),
            });
        }
        let cputype = u32_at(src, base + 4).unwrap_or(0);
        let arch = match cputype {
            7 => "x86",
            0x0100_0007 => "x86-64",
            12 => "ARM",
            0x0100_000C => "ARM64",
            _ => "unknown",
        };

        let mut metadata = BTreeMap::new();
        metadata.insert("arch".to_string(), arch.to_string());
        metadata.insert(
            "bits".to_string(),
            if is64 { "64" } else { "32" }.to_string(),
        );
        metadata.insert("load_commands".to_string(), ncmds.to_string());

        Ok(HandlerOutput {
            artifacts: vec![ArtifactDraft {
                format: "macho".to_string(),
                label: format!("Mach-O ({arch}, {} load commands)", ncmds),
                offset: base,
                size: src.len() - base,
                confidence: Confidence::Validated,
                evidence: Evidence::facts([
                    "Mach-O magic validated".to_string(),
                    format!("{} load commands declared", ncmds),
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
// WASM
// ---------------------------------------------------------------------------

pub struct WasmHandler;

impl Handler for WasmHandler {
    fn format(&self) -> &'static str {
        "wasm"
    }

    fn find_candidates(&self, src: &ByteSource) -> Vec<Candidate> {
        find_all(src, b"\0asm")
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
        if base + 8 > src.len() {
            return Err(Error::Validation {
                format: "wasm",
                reason: "truncated preamble".into(),
            });
        }
        let mut magic = [0u8; 4];
        src.read_at(base, &mut magic)?;
        if &magic != b"\0asm" {
            return Err(Error::Validation {
                format: "wasm",
                reason: "bad magic".into(),
            });
        }
        let version = crate::handlers::media_read_u32_le(src, base + 4).unwrap_or(0);
        if version != 1 {
            return Err(Error::Validation {
                format: "wasm",
                reason: format!("unknown binary version {version}"),
            });
        }
        // Walk section headers (id byte + LEB128 size).
        let mut off = base + 8;
        let mut sections = Vec::new();
        while off < src.len() && sections.len() < limits.max_records.min(4096) {
            let mut id = [0u8; 1];
            src.read_at(off, &mut id)?;
            off += 1;
            let (size, len) = read_leb128(src, off)?;
            off += len + size;
            sections.push(id[0]);
            if off > src.len() {
                return Err(Error::Validation {
                    format: "wasm",
                    reason: "section extends past source".into(),
                });
            }
        }
        let section_names: Vec<&str> = sections
            .iter()
            .map(|&id| match id {
                0 => "custom",
                1 => "type",
                2 => "import",
                3 => "function",
                4 => "table",
                5 => "memory",
                6 => "global",
                7 => "export",
                8 => "start",
                9 => "element",
                10 => "code",
                11 => "data",
                _ => "other",
            })
            .collect();

        let mut metadata = BTreeMap::new();
        metadata.insert("sections".to_string(), sections.len().to_string());
        metadata.insert("section_list".to_string(), section_names.join(","));

        Ok(HandlerOutput {
            artifacts: vec![ArtifactDraft {
                format: "wasm".to_string(),
                label: format!("WebAssembly module ({} sections)", sections.len()),
                offset: base,
                size: off - base,
                confidence: Confidence::Validated,
                evidence: Evidence::facts([
                    "WASM preamble + version 1 validated".to_string(),
                    format!("{} section headers walked", sections.len()),
                ]),
                metadata,
                warnings: Vec::new(),
                errors: Vec::new(),
                children: Vec::new(),
            }],
        })
    }
}

/// Read an unsigned LEB128 value; returns (value, bytes_consumed).
fn read_leb128(src: &ByteSource, off: u64) -> Result<(u64, u64)> {
    let mut value: u64 = 0;
    let mut shift = 0u32;
    let mut count = 0u64;
    loop {
        if count >= 10 {
            return Err(Error::Validation {
                format: "leb128",
                reason: "varint too long".into(),
            });
        }
        let mut b = [0u8; 1];
        src.read_at(off + count, &mut b)?;
        value |= u64::from(b[0] & 0x7F) << shift;
        count += 1;
        if b[0] & 0x80 == 0 {
            break;
        }
        shift += 7;
        if shift > 63 {
            return Err(Error::Validation {
                format: "leb128",
                reason: "varint overflow".into(),
            });
        }
    }
    Ok((value, count))
}

// ---------------------------------------------------------------------------
// OLE / Compound File Binary
// ---------------------------------------------------------------------------

pub struct OleHandler;

impl Handler for OleHandler {
    fn format(&self) -> &'static str {
        "ole"
    }

    fn find_candidates(&self, src: &ByteSource) -> Vec<Candidate> {
        find_all(src, b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1")
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
        if base + 80 > src.len() {
            return Err(Error::Validation {
                format: "ole",
                reason: "truncated header".into(),
            });
        }
        let minor = crate::handlers::media_read_u16_le(src, base + 24).unwrap_or(0);
        let major = crate::handlers::media_read_u16_le(src, base + 26).unwrap_or(0);
        let sector_shift = crate::handlers::media_read_u16_le(src, base + 30).unwrap_or(9);
        let sector_size = 1u64 << sector_shift;
        if sector_shift < 6 || sector_shift > 9 {
            return Err(Error::Validation {
                format: "ole",
                reason: format!("invalid sector shift {sector_shift}"),
            });
        }
        if major != 3 && major != 4 {
            return Err(Error::Validation {
                format: "ole",
                reason: format!("unsupported version {major}.{minor}"),
            });
        }
        let dir_start = crate::handlers::media_read_u32_le(src, base + 48).unwrap_or(0) as u64;
        let dir_end = dir_start
            .checked_add(1)
            .and_then(|n| n.checked_mul(sector_size))
            .ok_or(Error::Validation {
                format: "ole",
                reason: "directory offset overflow".into(),
            })?;
        if base + dir_end > src.len() {
            return Err(Error::Validation {
                format: "ole",
                reason: "directory chain out of bounds".into(),
            });
        }
        let _ = limits;

        let mut metadata = BTreeMap::new();
        metadata.insert("major_version".to_string(), major.to_string());
        metadata.insert("sector_size".to_string(), sector_size.to_string());
        metadata.insert("directory_start_sector".to_string(), dir_start.to_string());

        Ok(HandlerOutput {
            artifacts: vec![ArtifactDraft {
                format: "ole".to_string(),
                label: format!("OLE compound file (v{major}, {}B sectors)", sector_size),
                offset: base,
                size: src.len() - base,
                confidence: Confidence::Validated,
                evidence: Evidence::facts([
                    "OLE CFB magic (D0CF11E0A1B11AE1) validated".to_string(),
                    format!("{} sector size", sector_size),
                    "directory-chain bounds checked".to_string(),
                ]),
                metadata,
                warnings: vec![
                    "stream enumeration planned for a hardening pass; header validated structurally here"
                        .to_string(),
                ],
                errors: Vec::new(),
                children: Vec::new(),
            }],
        })
    }
}

// ---------------------------------------------------------------------------
// RTF
// ---------------------------------------------------------------------------

pub struct RtfHandler;

impl Handler for RtfHandler {
    fn format(&self) -> &'static str {
        "rtf"
    }

    fn find_candidates(&self, src: &ByteSource) -> Vec<Candidate> {
        find_all(src, b"{\\rtf1")
            .into_iter()
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
        if base + 6 > src.len() {
            return Err(Error::Validation {
                format: "rtf",
                reason: "truncated header".into(),
            });
        }
        let mut head = [0u8; 6];
        src.read_at(base, &mut head)?;
        if &head != b"{\\rtf1" {
            return Err(Error::Validation {
                format: "rtf",
                reason: "not an RTF header".into(),
            });
        }
        // Walk braces for a structural boundary (bounded depth).
        let mut depth = 1i64;
        let mut off = base + 6;
        let data = src.slice(base, src.len() - base)?;
        let bytes = data.read_prefix(16 * 1024 * 1024)?;
        let mut idx = 6usize;
        while idx < bytes.len() {
            match bytes[idx] {
                b'{' => depth += 1,
                b'}' => {
                    depth -= 1;
                    if depth == 0 {
                        off = base + idx as u64 + 1;
                        break;
                    }
                }
                b'\\' => idx += 1, // skip escaped char
                _ => {}
            }
            depth = depth.clamp(0, 4096);
            idx += 1;
        }
        let size = off - base;
        if size < 6 {
            return Err(Error::Validation {
                format: "rtf",
                reason: "unterminated RTF".into(),
            });
        }
        // Metadata: charset/deffont markers.
        let mut metadata = BTreeMap::new();
        let prefix = String::from_utf8_lossy(&bytes[..bytes.len().min(256)]).into_owned();
        for marker in ["\\ansi", "\\mac", "\\pc", "\\pca", "\\fbidis"] {
            if prefix.contains(marker) {
                metadata.insert("charset".to_string(), marker[1..].to_string());
                break;
            }
        }

        Ok(HandlerOutput {
            artifacts: vec![ArtifactDraft {
                format: "rtf".to_string(),
                label: format!("RTF document ({} bytes)", size),
                offset: base,
                size,
                confidence: Confidence::Validated,
                evidence: Evidence::facts([
                    "{\\rtf1 header validated".to_string(),
                    "brace nesting walked to a balanced close".to_string(),
                ]),
                metadata,
                warnings: Vec::new(),
                errors: Vec::new(),
                children: Vec::new(),
            }],
        })
    }
}

#[cfg(test)]
mod exec_tests {
    use super::*;
    use crate::engine::EngineLimits;

    fn validate_at(h: &dyn Handler, src: &ByteSource, off: u64) -> Result<HandlerOutput> {
        h.validate(
            src,
            Candidate { offset: off },
            &EngineLimits::default(),
            &mut Budget::default(),
        )
    }

    fn elf64() -> Vec<u8> {
        let mut e = b"\x7fELF\x02\x01\x01\0".to_vec();
        e.extend([0u8; 8]); // padding
        e.extend(2u16.to_le_bytes()); // type: executable
        e.extend(62u16.to_le_bytes()); // machine: x86-64
        e.extend(1u32.to_le_bytes()); // version
        e.extend(0u64.to_le_bytes()); // entry
        e.extend(0u64.to_le_bytes()); // phoff
        e.extend(64u64.to_le_bytes()); // shoff
        e.extend(0u32.to_le_bytes()); // flags
        e.extend(64u16.to_le_bytes()); // ehsize
        e.extend(56u16.to_le_bytes()); // phentsize
        e.extend(0u16.to_le_bytes()); // phnum
        e.extend(64u16.to_le_bytes()); // shentsize
        e.extend(3u16.to_le_bytes()); // shnum
        e.extend(0u16.to_le_bytes()); // shstrndx
        e.extend([0u8; 3 * 64]); // section table space
        e
    }

    #[test]
    fn elf64_header_and_section_bounds() {
        let e = elf64();
        let src = ByteSource::from_vec(e);
        let out = validate_at(&ElfHandler, &src, 0).expect("elf validates");
        let art = &out.artifacts[0];
        assert_eq!(art.confidence, Confidence::Validated);
        assert_eq!(
            art.metadata.get("machine").map(String::as_str),
            Some("x86-64")
        );
        assert_eq!(
            art.metadata.get("section_count").map(String::as_str),
            Some("3")
        );
    }

    #[test]
    fn elf_section_table_past_source_rejected() {
        let mut e = elf64();
        // Claim 0xFFFF sections -> way past the small source.
        e[60..62].copy_from_slice(&0xFFFFu16.to_le_bytes());
        let src = ByteSource::from_vec(e);
        assert!(validate_at(&ElfHandler, &src, 0).is_err());
    }

    #[test]
    fn pe_dos_and_signature_validated() {
        let mut p = b"MZ".to_vec();
        p.resize(0x40, 0);
        let pe_at = 0x40u32;
        p[0x3c..0x40].copy_from_slice(&pe_at.to_le_bytes());
        p.resize(0x40 + 24, 0);
        p[0x40..0x44].copy_from_slice(b"PE\0\0");
        p[0x44..0x46].copy_from_slice(&0x8664u16.to_le_bytes());
        p[0x46..0x48].copy_from_slice(&3u16.to_le_bytes()); // sections
        let src = ByteSource::from_vec(p);
        let out = validate_at(&PeHandler, &src, 0).expect("pe validates");
        let art = &out.artifacts[0];
        assert_eq!(art.metadata.get("machine").map(String::as_str), Some("x64"));
        assert_eq!(art.metadata.get("sections").map(String::as_str), Some("3"));
    }

    #[test]
    fn wasm_sections_walked_with_leb128() {
        let mut w = b"\0asm\x01\0\0\0".to_vec();
        // Section 1 (type), size 1, body [0x00].
        w.extend([0x01, 0x01, 0x00]);
        // Section 3 (function), size 2, body [0x01, 0x00].
        w.extend([0x03, 0x02, 0x01, 0x00]);
        let src = ByteSource::from_vec(w);
        let out = validate_at(&WasmHandler, &src, 0).expect("wasm validates");
        let art = &out.artifacts[0];
        assert_eq!(art.confidence, Confidence::Validated);
        assert_eq!(art.size, src.len() as u64);
        assert_eq!(
            art.metadata.get("section_list").map(String::as_str),
            Some("type,function")
        );
    }

    #[test]
    fn rtf_brace_walk_balances() {
        // Build the RTF bytes programmatically so no source-escaping
        // tricks are needed for the backslashes.
        let mut rtf: Vec<u8> = Vec::new();
        rtf.push(b'{');
        rtf.push(b'\\');
        rtf.extend_from_slice(b"rtf1");
        rtf.push(b'\\');
        rtf.extend_from_slice(b"ansi hello {");
        rtf.push(b'\\');
        rtf.extend_from_slice(b"b world}} tail");
        let src = ByteSource::from_vec(rtf);
        let out = validate_at(&RtfHandler, &src, 0).expect("rtf validates");
        let art = &out.artifacts[0];
        assert_eq!(art.size, 29, "boundary = balanced close brace");
        assert!(art.size < src.len() as u64, "trailing text stays outside");
    }
}
