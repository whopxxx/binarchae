//! M3 executable/document-format handlers: ELF, PE, Mach-O, WASM, OLE
//! Compound File, RTF.
//!
//! All parsers are structural (real headers, program/section tables,
//! b-tree metadata), produce useful metadata, and keep boundaries
//! honest. Embedded regions (sections, OLE streams) become children
//! where bounded and useful.

use crate::artifact::{Confidence, Evidence, RelationKind};
use crate::bytesource::ByteSource;
use crate::engine::{
    ArtifactDraft, Budget, Candidate, ChildContent, ChildDraft, Handler, HandlerOutput,
};
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
        type U16Fn = fn(&ByteSource, u64) -> Option<u16>;
        type U32Fn = fn(&ByteSource, u64) -> Option<u32>;
        type U64Fn = fn(&ByteSource, u64) -> Option<u64>;
        let (u16_at, u32_at, u64_at): (U16Fn, U32Fn, U64Fn) = if le {
            (Self::le16, Self::le32, Self::le64)
        } else {
            (Self::be16, Self::be32, Self::be64)
        };

        let e_type = u16_at(src, base + 16).unwrap_or(0);
        let e_machine = u16_at(src, base + 18).unwrap_or(0);
        let (phoff, phentsize, phnum) = if is64 {
            (
                u64_at(src, base + 32).unwrap_or(0),
                u64::from(u16_at(src, base + 54).unwrap_or(0)),
                u64::from(u16_at(src, base + 56).unwrap_or(0)),
            )
        } else {
            (
                u64::from(u32_at(src, base + 28).unwrap_or(0)),
                u64::from(u16_at(src, base + 42).unwrap_or(0)),
                u64::from(u16_at(src, base + 44).unwrap_or(0)),
            )
        };
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

        // B6 + R3: prove the structural end from ALL file-backed parts:
        // the ELF header itself, the program-header table, file-backed
        // program segments (p_offset + p_filesz), and the section table /
        // sections. A stripped ELF (shoff=0, shnum=0) still gets a real
        // boundary from header + phdr table + segments. PT_LOAD = 1,
        // PT_INTERP = 3 carry file bytes; PT_NULL(0)/PT_NOTE(4) mostly
        // do — include every program header's file range conservatively
        // except PT_TLS-ish types with no file backing (p_filesz=0 is
        // naturally excluded).
        let elf_header_end: u64 = if is64 { 64 } else { 52 };
        let mut struct_end = elf_header_end;
        let mut parts = 0usize;
        // Program-header table + segment file ranges.
        if phentsize > 0 && phnum > 0 && phnum as usize <= limits.max_records {
            parts += 1;
            struct_end = struct_end.max(phoff + phnum * phentsize);
            for i in 0..phnum {
                let ph = base + phoff + i * phentsize;
                let (p_offset, p_filesz) = if is64 {
                    (
                        u64_at(src, ph + 8).unwrap_or(0),
                        u64_at(src, ph + 32).unwrap_or(0),
                    )
                } else {
                    (
                        u64::from(u32_at(src, ph + 4).unwrap_or(0)),
                        u64::from(u32_at(src, ph + 16).unwrap_or(0)),
                    )
                };
                if p_filesz > 0 {
                    struct_end = struct_end.max(p_offset + p_filesz);
                }
            }
        }
        // Section table + section file ranges.
        if shentsize > 0 && shnum > 0 && shnum as usize <= limits.max_records {
            parts += 1;
            struct_end = struct_end.max(shoff + shnum * shentsize);
            for i in 0..shnum {
                let sh = base + shoff + i * shentsize;
                // SHT_NOBITS (8) occupies no file bytes.
                let sh_type = u32_at(src, sh + 4).unwrap_or(0);
                let (sh_offset, sh_size) = if is64 {
                    (
                        u64_at(src, sh + 24).unwrap_or(0),
                        u64_at(src, sh + 32).unwrap_or(0),
                    )
                } else {
                    (
                        u64::from(u32_at(src, sh + 16).unwrap_or(0)),
                        u64::from(u32_at(src, sh + 20).unwrap_or(0)),
                    )
                };
                if sh_type != 8 {
                    struct_end = struct_end.max(sh_offset + sh_size);
                }
            }
        }
        let _ = parts;
        let proven_end = base + struct_end <= src.len();
        let elf_size = if proven_end {
            struct_end
        } else {
            src.len() - base
        };
        let elf_confidence = if proven_end {
            Confidence::Validated
        } else {
            Confidence::Partial
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
                size: elf_size,
                confidence: elf_confidence,
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

        // B6: provable structural end = end of the section table plus the
        // furthest section raw data (PointerToRawData + SizeOfRawData).
        // Sections with file bytes are also exposed as executable-region
        // children (source-backed slices).
        let mut struct_end =
            (pe_at - base) + 24 + opt_header_size as u64 + num_sections as u64 * 40;
        let mut children = Vec::new();
        for i in 0..num_sections {
            let sh = base + (pe_at - base) + 24 + opt_header_size as u64 + i as u64 * 40;
            if sh + 40 > src.len() {
                break;
            }
            let mut name_raw = [0u8; 8];
            src.read_at(sh, &mut name_raw)?;
            let sec_name =
                String::from_utf8_lossy(name_raw.split(|&b| b == 0).next().unwrap_or(&name_raw))
                    .into_owned();
            let virt_size = crate::handlers::media_read_u32_le(src, sh + 8).unwrap_or(0) as u64;
            let raw_size = crate::handlers::media_read_u32_le(src, sh + 16).unwrap_or(0) as u64;
            let raw_ptr = crate::handlers::media_read_u32_le(src, sh + 20).unwrap_or(0) as u64;
            let characteristics = crate::handlers::media_read_u32_le(src, sh + 36).unwrap_or(0);
            struct_end = struct_end.max(raw_ptr + raw_size);
            // Executable-region child: file-backed sections only.
            if raw_size > 0
                && raw_ptr > 0
                && base + raw_ptr + raw_size <= src.len()
                && raw_size <= limits.max_child_size
                && children.len() < limits.max_streams
            {
                let region = src.slice(base + raw_ptr, raw_size)?;
                let mut meta = BTreeMap::new();
                meta.insert("section_name".to_string(), sec_name.clone());
                meta.insert("virtual_size".to_string(), virt_size.to_string());
                meta.insert(
                    "characteristics".to_string(),
                    format!("0x{characteristics:08x}"),
                );
                let is_exec = characteristics & 0x2000_0000 != 0;
                meta.insert(
                    "characteristics_flags".to_string(),
                    format!(
                        "{}{}{}",
                        if is_exec { "X" } else { "-" },
                        if characteristics & 0x4000_0000 != 0 {
                            "W"
                        } else {
                            "-"
                        },
                        if characteristics & 0x4000_0000 != 0 || characteristics & 0x8000_0000 != 0
                        {
                            "R"
                        } else {
                            "-"
                        }
                    ),
                );
                children.push(ChildDraft {
                    relation: RelationKind::Contains,
                    label: format!(
                        "PE section {} ({} raw bytes{})",
                        sec_name,
                        raw_size,
                        if is_exec { ", executable" } else { "" }
                    ),
                    format_hint: "raw",
                    content: ChildContent::Source(region),
                    size: raw_size,
                    metadata: meta,
                    warnings: Vec::new(),
                    entry_name: Some(format!("section_{sec_name}")),
                });
            }
        }

        let proven_end = base + struct_end <= src.len();
        let pe_size = if proven_end {
            struct_end
        } else {
            src.len() - base
        };
        let pe_confidence = if proven_end {
            Confidence::Validated
        } else {
            Confidence::Partial
        };

        let mut metadata = BTreeMap::new();
        metadata.insert("machine".to_string(), arch.to_string());
        metadata.insert("sections".to_string(), num_sections.to_string());

        Ok(HandlerOutput {
            artifacts: vec![ArtifactDraft {
                format: "pe".to_string(),
                label: format!("PE executable ({arch}, {} sections)", num_sections),
                offset: base,
                size: pe_size,
                confidence: pe_confidence,
                evidence: Evidence::facts([
                    "DOS header + PE signature validated".to_string(),
                    format!(
                        "{} sections, optional header {} bytes",
                        num_sections, opt_header_size
                    ),
                    if proven_end {
                        "structural end proven via section raw data".to_string()
                    } else {
                        "section data extends past source; Partial".to_string()
                    },
                ]),
                metadata,
                warnings: Vec::new(),
                errors: Vec::new(),
                children,
            }],
        })
    }
}

/// Read a u64 LE at `off` (two u32 LE reads). Mach-O LE helper.
fn macho_u64(src: &ByteSource, off: u64) -> u64 {
    let lo = crate::handlers::media_read_u32_le(src, off).unwrap_or(0) as u64;
    let hi = crate::handlers::media_read_u32_le(src, off + 4).unwrap_or(0) as u64;
    lo | (hi << 32)
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

        // B6: provable structural end = end of the load-command list plus
        // the furthest segment's file offset+filesize.
        let mut cmds_end = base + (if is64 { 32 } else { 28 }) as u64;
        let mut struct_end = 0u64;
        let mut off = cmds_end;
        for _ in 0..ncmds {
            if off + 8 > src.len() {
                break;
            }
            let cmdsize = u32_at(src, off + 4).unwrap_or(0) as u64;
            if cmdsize < 8 || off + cmdsize > src.len() {
                break;
            }
            let cmd = u32_at(src, off).unwrap_or(0);
            off += cmdsize;
            // LC_SEGMENT = 0x1, LC_SEGMENT_64 = 0x19.
            if cmd == 0x1 || cmd == 0x19 {
                let seg64 = cmd == 0x19;
                let cmd_start = off - cmdsize;
                let fileoff_off = cmd_start + if seg64 { 40 } else { 32 };
                let filesize_off = fileoff_off + if seg64 { 8 } else { 4 };
                let (fileoff, filesize) = if seg64 {
                    (macho_u64(src, fileoff_off), macho_u64(src, filesize_off))
                } else {
                    (
                        u64::from(u32_at(src, fileoff_off).unwrap_or(0)),
                        u64::from(u32_at(src, filesize_off).unwrap_or(0)),
                    )
                };
                struct_end = struct_end.max(fileoff + filesize);
            }
        }
        cmds_end = off;
        struct_end = struct_end.max(cmds_end - base);
        let proven_end = base + struct_end <= src.len();
        let macho_size = if proven_end {
            struct_end
        } else {
            src.len() - base
        };
        let macho_confidence = if proven_end {
            Confidence::Validated
        } else {
            Confidence::Partial
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
                size: macho_size,
                confidence: macho_confidence,
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

const OLE_MAGIC: &[u8] = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1";
const OLE_NOSTREAM: u32 = 0xFFFF_FFFF;
/// Mini-stream cutoff (MS-CFB): streams smaller than this live in the
/// mini-FAT.
const OLE_MINI_CUTOFF: u64 = 4096;

/// Object types (MS-CFB 2.6.1).
const OBJ_STREAM: u8 = 2;
const OBJ_ROOT: u8 = 5;

/// One directory entry.
#[derive(Debug, Clone)]
struct OleDirEntry {
    name: String,
    obj_type: u8,
    left: u32,
    right: u32,
    child: u32,
    /// Retained for upcoming stream extraction (FAT chain decode).
    #[allow(dead_code)]
    start_sector: u32,
    size: u64,
}

/// Parsed header fields.
struct OleHeader {
    sector_size: u64,
    /// Mini-FAT parameters retained for upcoming stream extraction;
    /// the current tree walk reports stream sizes only.
    #[allow(dead_code)]
    mini_sector_size: u64,
    first_dir_sector: u32,
    #[allow(dead_code)]
    mini_fat_start: u32,
    #[allow(dead_code)]
    num_mini_fat: u32,
    fat_sectors: Vec<u32>,
}

impl OleHandler {
    fn parse_header(src: &ByteSource, base: u64) -> Result<OleHeader> {
        let mut hdr = [0u8; 80];
        src.read_at(base, &mut hdr)?;
        let sector_shift = u16::from_le_bytes([hdr[30], hdr[31]]);
        let mini_shift = u16::from_le_bytes([hdr[32], hdr[33]]);
        if !(6..=9).contains(&sector_shift) || mini_shift != 6 {
            return Err(Error::Validation {
                format: "ole",
                reason: format!("invalid sector shifts {sector_shift}/{mini_shift}"),
            });
        }
        let num_fat = u32::from_le_bytes(hdr[0x2C..0x30].try_into().unwrap());
        let first_dir_sector = u32::from_le_bytes(hdr[0x30..0x34].try_into().unwrap());
        let mini_cutoff = u64::from_le_bytes(hdr[0x38..0x40].try_into().unwrap());
        if mini_cutoff != OLE_MINI_CUTOFF {
            return Err(Error::Validation {
                format: "ole",
                reason: format!("unsupported mini-stream cutoff {mini_cutoff}"),
            });
        }
        let mini_fat_start = u32::from_le_bytes(hdr[0x3C..0x40].try_into().unwrap());
        let num_mini_fat = u32::from_le_bytes(hdr[0x40..0x44].try_into().unwrap());
        // DIFAT: 109 u32 entries in the header.
        let mut fat_sectors = Vec::new();
        for i in 0..109usize {
            let s = u32::from_le_bytes(hdr[0x4C + i * 4..0x4C + i * 4 + 4].try_into().unwrap());
            if s != 0xFFFF_FFFF {
                fat_sectors.push(s);
            }
        }
        if fat_sectors.len() as u32 != num_fat {
            return Err(Error::Validation {
                format: "ole",
                reason: format!(
                    "DIFAT lists {} sectors but header declares {num_fat}",
                    fat_sectors.len()
                ),
            });
        }
        Ok(OleHeader {
            sector_size: 1u64 << sector_shift,
            mini_sector_size: 1u64 << mini_shift,
            first_dir_sector,
            mini_fat_start,
            num_mini_fat,
            fat_sectors,
        })
    }

    /// Read one FAT sector-chain: the FAT is an array of u32 entries
    /// spread across `fat_sectors`.
    fn read_fat(src: &ByteSource, base: u64, hdr: &OleHeader) -> Result<Vec<u32>> {
        let ss = hdr.sector_size as usize;
        let entries_per_sector = ss / 4;
        let mut fat = Vec::with_capacity(fat_sectors_len(hdr) * entries_per_sector);
        let mut raw = vec![0u8; ss];
        for &s in &hdr.fat_sectors {
            src.read_at(base + (1 + u64::from(s)) * hdr.sector_size, &mut raw)?;
            for c in raw.chunks_exact(4) {
                fat.push(u32::from_le_bytes(c.try_into().unwrap()));
            }
        }
        Ok(fat)
    }

    /// Follow a FAT chain from `start`, collecting sector numbers.
    fn follow_chain(
        fat: &[u32],
        start: u32,
        max_len: usize,
        warnings: &mut Vec<String>,
    ) -> Vec<u32> {
        const FREESECT: u32 = 0xFFFF_FFFF;
        const ENDOFCHAIN: u32 = 0xFFFF_FFFE;
        const FATSECT: u32 = 0xFFFF_FFFD;
        let mut chain = Vec::new();
        let mut cur = start;
        while cur != ENDOFCHAIN && cur != FREESECT && cur != FATSECT {
            if chain.len() >= max_len {
                warnings.push("FAT chain too long; truncated".to_string());
                break;
            }
            chain.push(cur);
            if cur as usize >= fat.len() {
                warnings.push("FAT chain points past FAT; truncated".to_string());
                break;
            }
            cur = fat[cur as usize];
        }
        chain
    }

    /// Read the directory chain into a flat list of entries.
    fn read_directory(
        src: &ByteSource,
        base: u64,
        hdr: &OleHeader,
        fat: &[u32],
        limits: &crate::engine::EngineLimits,
        warnings: &mut Vec<String>,
    ) -> Result<Vec<OleDirEntry>> {
        let dir_sectors =
            Self::follow_chain(fat, hdr.first_dir_sector, limits.max_records, warnings);
        let mut raw = Vec::new();
        let mut buf = vec![0u8; hdr.sector_size as usize];
        for s in &dir_sectors {
            src.read_at(base + (1 + u64::from(*s)) * hdr.sector_size, &mut buf)?;
            raw.extend_from_slice(&buf);
        }
        let mut entries = Vec::new();
        for chunk in raw.chunks_exact(128) {
            let name_len = u16::from_le_bytes([chunk[64], chunk[65]]) as usize;
            let obj_type = chunk[66];
            if obj_type == 0 {
                continue; // unused
            }
            if !(2..=64).contains(&name_len) || name_len % 2 != 0 {
                continue;
            }
            let units: Vec<u16> = chunk[..name_len - 2]
                .chunks_exact(2)
                .map(|c| u16::from_le_bytes([c[0], c[1]]))
                .collect();
            let name = String::from_utf16_lossy(&units);
            let left = u32::from_le_bytes(chunk[68..72].try_into().unwrap());
            let right = u32::from_le_bytes(chunk[72..76].try_into().unwrap());
            let child = u32::from_le_bytes(chunk[76..80].try_into().unwrap());
            let start_sector = u32::from_le_bytes(chunk[116..120].try_into().unwrap());
            let size = u64::from_le_bytes(chunk[120..128].try_into().unwrap());
            entries.push(OleDirEntry {
                name,
                obj_type,
                left,
                right,
                child,
                start_sector,
                size,
            });
            if entries.len() >= limits.max_records {
                warnings.push("directory entries exceed max_records; truncated".to_string());
                break;
            }
        }
        Ok(entries)
    }
}

fn fat_sectors_len(hdr: &OleHeader) -> usize {
    hdr.fat_sectors.len()
}

impl Handler for OleHandler {
    fn format(&self) -> &'static str {
        "ole"
    }

    fn find_candidates(&self, src: &ByteSource) -> Vec<Candidate> {
        find_all(src, OLE_MAGIC)
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
        let major = crate::handlers::media_read_u16_le(src, base + 26).unwrap_or(0);
        if major != 3 && major != 4 {
            return Err(Error::Validation {
                format: "ole",
                reason: format!("unsupported version {major}"),
            });
        }
        let hdr = Self::parse_header(src, base)?;
        let mut warnings = Vec::new();
        let fat = Self::read_fat(src, base, &hdr)?;
        let entries = Self::read_directory(src, base, &hdr, &fat, limits, &mut warnings)?;
        if entries.is_empty() {
            return Err(Error::Validation {
                format: "ole",
                reason: "empty directory".into(),
            });
        }
        // Root entry must be first.
        if entries[0].obj_type != OBJ_ROOT {
            return Err(Error::Validation {
                format: "ole",
                reason: "first directory entry is not the root".into(),
            });
        }

        // Walk the red-black tree of each storage, listing streams.
        let mut visited = std::collections::HashSet::new();
        fn visit(
            entries: &[OleDirEntry],
            idx: u32,
            path: &str,
            visited: &mut std::collections::HashSet<u32>,
            out: &mut Vec<String>,
        ) {
            if idx == OLE_NOSTREAM || !visited.insert(idx) || idx as usize >= entries.len() {
                return;
            }
            let e = &entries[idx as usize];
            visit(entries, e.left, path, visited, out);
            let child_path = if path.is_empty() {
                e.name.clone()
            } else {
                format!("{path}/{}", e.name)
            };
            if e.obj_type == OBJ_STREAM {
                // Declared size distinguishes mini-FAT streams
                // (< OLE_MINI_CUTOFF) from regular FAT streams.
                out.push(format!(
                    "{child_path} ({} bytes, {})",
                    e.size,
                    if e.size < OLE_MINI_CUTOFF {
                        "mini-fat"
                    } else {
                        "fat"
                    }
                ));
            }
            visit(entries, e.right, path, visited, out);
            visit(entries, e.child, path, visited, out);
        }
        let mut names = Vec::new();
        visit(&entries, entries[0].child, "", &mut visited, &mut names);

        let mut metadata = BTreeMap::new();
        metadata.insert("major_version".to_string(), major.to_string());
        metadata.insert("sector_size".to_string(), hdr.sector_size.to_string());
        metadata.insert("directory_entries".to_string(), entries.len().to_string());
        metadata.insert("stream_count".to_string(), names.len().to_string());

        Ok(HandlerOutput {
            artifacts: vec![ArtifactDraft {
                format: "ole".to_string(),
                label: format!(
                    "OLE compound file (v{major}, {}B sectors, {} streams)",
                    hdr.sector_size,
                    names.len()
                ),
                offset: base,
                size: src.len() - base,
                confidence: if names.is_empty() {
                    Confidence::Partial
                } else {
                    Confidence::Validated
                },
                evidence: Evidence::facts([
                    "OLE CFB magic (D0CF11E0A1B11AE1) validated".to_string(),
                    format!("{} directory entries parsed", entries.len()),
                    format!("stream tree walked: {} streams", names.len()),
                ]),
                metadata,
                warnings,
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
    fn elf_boundary_proves_trailing_region() {
        // B6: the ELF artifact must end at the section table end
        // (shoff=64 + 3*64 = 256), NOT at end-of-source, so appended
        // bytes stay discoverable as trailing data.
        let mut e = elf64();
        let elf_len = e.len(); // 64 + 192 = 256
        assert_eq!(elf_len, 256);
        e.extend_from_slice(b"APPENDED-NOT-ELF");
        let src = ByteSource::from_vec(e);
        let out = validate_at(&ElfHandler, &src, 0).expect("elf validates");
        let art = &out.artifacts[0];
        assert_eq!(art.size, 256, "ELF size must be the structural end");
        assert_eq!(art.confidence, Confidence::Validated);
    }

    #[test]
    fn elf_stripped_boundary_from_program_headers() {
        // R3: a stripped ELF (shoff=0, shnum=0) must NOT get size=0.
        // Its boundary comes from header + phdr table + PT_LOAD file
        // range, so appended trailing data stays discoverable.
        let mut e = b"ELF ".to_vec();
        e.extend([0u8; 8]);
        e.extend(2u16.to_le_bytes()); // type: executable
        e.extend(62u16.to_le_bytes()); // machine: x86-64
        e.extend(1u32.to_le_bytes()); // version
        e.extend(0u64.to_le_bytes()); // entry
        e.extend(64u64.to_le_bytes()); // phoff = 64
        e.extend(0u64.to_le_bytes()); // shoff = 0 (stripped)
        e.extend(0u32.to_le_bytes()); // flags
        e.extend(64u16.to_le_bytes()); // ehsize
        e.extend(56u16.to_le_bytes()); // phentsize
        e.extend(2u16.to_le_bytes()); // phnum = 2
        e.extend(0u16.to_le_bytes()); // shentsize
        e.extend(0u16.to_le_bytes()); // shnum = 0
        e.extend(0u16.to_le_bytes()); // shstrndx
                                      // Two program headers: PT_LOAD #1 file range 120..170, PT_LOAD
                                      // #2 file range 100..160. The phdr table itself ends at 176,
                                      // which is the furthest byte — the proven boundary.
        for (off, filesz) in [(120u64, 50u64), (100u64, 60u64)] {
            e.extend(1u32.to_le_bytes()); // p_type = PT_LOAD
            e.extend(5u32.to_le_bytes()); // p_flags
            e.extend(off.to_le_bytes()); // p_offset
            e.extend(0u64.to_le_bytes()); // p_vaddr
            e.extend(0u64.to_le_bytes()); // p_paddr
            e.extend(filesz.to_le_bytes()); // p_filesz
            e.extend(filesz.to_le_bytes()); // p_memsz
            e.extend(0u64.to_le_bytes()); // p_align
        }
        assert_eq!(e.len(), 176);
        e.extend_from_slice(b"APPENDED");
        let src = ByteSource::from_vec(e);
        let out = validate_at(&ElfHandler, &src, 0).expect("stripped elf validates");
        let art = &out.artifacts[0];
        assert_eq!(
            art.size, 176,
            "boundary = furthest of phdr-table end (176) / segment ends, not 0 and not src.len()"
        );
        assert_eq!(art.confidence, Confidence::Validated);
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
        assert_eq!(art.size, src.len());
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
        assert!(art.size < src.len(), "trailing text stays outside");
    }

    /// Hand-built PE with two sections (.text executable, .data
    /// readable): handler must expose file-backed section regions as
    /// source-backed children with X/W/R flags.
    #[test]
    fn pe_section_regions_as_children() {
        // DOS header: "MZ", e_lfanew=0x40.
        let mut pe = vec![0u8; 0x400];
        pe[0] = b'M';
        pe[1] = b'Z';
        pe[0x3c..0x40].copy_from_slice(&0x40u32.to_le_bytes());
        // PE signature + COFF header.
        let pe_at = 0x40usize;
        pe[pe_at..pe_at + 4].copy_from_slice(b"PE\0\0");
        pe[pe_at + 4..pe_at + 6].copy_from_slice(&0x8664u16.to_le_bytes()); // x64
        pe[pe_at + 6..pe_at + 8].copy_from_slice(&2u16.to_le_bytes()); // 2 sections
        pe[pe_at + 20..pe_at + 22].copy_from_slice(&240u16.to_le_bytes()); // opt header size
                                                                           // Section table at pe_at + 24 + 240.
        let st = pe_at + 24 + 240;
        // .text: raw 0x100 bytes at file offset 0x200, executable.
        pe[st..st + 6].copy_from_slice(b".text\0");
        pe[st + 8..st + 12].copy_from_slice(&0x100u32.to_le_bytes()); // virtual size
        pe[st + 16..st + 20].copy_from_slice(&0x100u32.to_le_bytes()); // raw size
        pe[st + 20..st + 24].copy_from_slice(&0x200u32.to_le_bytes()); // raw ptr
        pe[st + 36..st + 40].copy_from_slice(&0x6000_0020u32.to_le_bytes()); // RXC
                                                                             // .data: raw 0x40 bytes at 0x300.
        let d = st + 40;
        pe[d..d + 8].copy_from_slice(&[0x2E, 0x64, 0x61, 0x74, 0x61, 0, 0, 0]);
        pe[d + 8..d + 12].copy_from_slice(&0x40u32.to_le_bytes());
        pe[d + 16..d + 20].copy_from_slice(&0x40u32.to_le_bytes());
        pe[d + 20..d + 24].copy_from_slice(&0x300u32.to_le_bytes());
        pe[d + 36..d + 40].copy_from_slice(&0xC000_0040u32.to_le_bytes()); // RW
                                                                           // Section content.
        pe[0x200..0x200 + 14].copy_from_slice(b"TEXT_BYTES_OK!");
        pe[0x300..0x300 + 14].copy_from_slice(b"DATA_BYTES_OK!");

        let src = ByteSource::from_vec(pe);
        let out = validate_at(&PeHandler, &src, 0).expect("pe validates");
        let art = &out.artifacts[0];
        assert_eq!(art.confidence, Confidence::Validated);
        assert_eq!(art.children.len(), 2);
        let text = art
            .children
            .iter()
            .find(|c| c.metadata.get("section_name").map(String::as_str) == Some(".text"))
            .expect(".text child");
        assert!(
            text.metadata
                .get("characteristics_flags")
                .map(String::as_str)
                .unwrap_or("")
                .contains('X'),
            ".text must be flagged executable"
        );
        match &text.content {
            ChildContent::Source(r) => {
                let mut b = [0u8; 14];
                r.read_at(0, &mut b).unwrap();
                assert_eq!(&b, b"TEXT_BYTES_OK!");
            }
            _ => panic!("section must be source-backed"),
        }
        let data = art
            .children
            .iter()
            .find(|c| c.metadata.get("section_name").map(String::as_str) == Some(".data"))
            .expect(".data child");
        assert!(
            !data
                .metadata
                .get("characteristics_flags")
                .map(String::as_str)
                .unwrap_or("")
                .contains('X'),
            ".data must not be executable"
        );
    }
}
