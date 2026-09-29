//! CPIO initramfs handler (M2): `newc` (`070701`) and `crc` (`070702`)
//! variants. Old binary / `odc` formats are NOT claimed or supported.
//!
//! newc header layout (110 bytes of 8-char hex fields, then name/data):
//! ```text
//! magic(6) ino(8) mode(8) uid(8) gid(8) nlink(8) mtime(8)
//! filesize(8) devmajor(8) devminor(8) rdevmajor(8) rdevminor(8)
//! namesize(8) check(8)
//! ```
//! All fields are ASCII hex; parsing is checked (malformed digits /
//! overflow reject the entry). The filename follows and includes its
//! terminating NUL; the name area and data area are each padded to a
//! 4-byte boundary. `TRAILER!!!` structurally terminates the archive;
//! bytes after it remain available to trailing-data discovery.
//!
//! The `crc` variant's `check` field holds a checksum of the file data
//! (sum of all bytes); mismatch is reported honestly (entry flagged),
//! never silently accepted.
//!
//! File contents are exposed as SOURCE-BACKED slices (zero-copy); symlinks
//! keep their target as data; device nodes / FIFOs are metadata only.
//! Nothing here creates host special files — extraction goes through the
//! existing safe-path layer.

use crate::artifact::{Confidence, Evidence, RelationKind};
use crate::bytesource::ByteSource;
use crate::engine::{ArtifactDraft, ChildContent, ChildDraft, Handler, HandlerOutput};
use crate::error::{Error, Result};
use crate::handlers::find_all;
use std::collections::BTreeMap;

pub struct CpioHandler;

const NEWC_MAGIC: &[u8] = b"070701";
const CRC_MAGIC: &[u8] = b"070702";
const ENTRY_HEADER: u64 = 110; // magic(6) + 13 hex fields * 8 chars
const TRAILER_NAME: &str = "TRAILER!!!";
const MAX_ENTRIES: usize = 100_000;

impl Handler for CpioHandler {
    fn format(&self) -> &'static str {
        "cpio"
    }

    fn find_candidates(&self, src: &ByteSource) -> Vec<crate::engine::Candidate> {
        let mut hits: Vec<u64> = find_all(src, NEWC_MAGIC);
        hits.extend(find_all(src, CRC_MAGIC));
        hits.sort_unstable();
        hits.dedup();
        hits.into_iter()
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
        // We walk entries until TRAILER!!! or bounds; work stays finite
        // via the entry cap and bounds checks.
        let mut off = base;
        let mut archive_end: Option<u64> = None;
        let mut is_crc_variant = false;
        let mut entries_scanned: usize = 0;
        let mut checksum_failures: Vec<String> = Vec::new();
        let mut children: Vec<ChildDraft> = Vec::new();
        let mut truncated = false;

        while off + ENTRY_HEADER <= src.len() {
            // Magic + 13 hex fields.
            let mut hdr = [0u8; ENTRY_HEADER as usize];
            src.read_at(off, &mut hdr)?;
            let magic = &hdr[0..6];
            let is_crc = magic == CRC_MAGIC;
            if magic != NEWC_MAGIC && !is_crc {
                break;
            }
            if is_crc {
                is_crc_variant = true;
            }

            // Checked hex parsing of every field.
            let field = |i: usize| -> Result<u64> { parse_hex(&hdr[6 + i * 8..6 + (i + 1) * 8]) };
            // Field order per spec: ino, mode, uid, gid, nlink, mtime,
            // filesize, devmajor, devminor, rdevmajor, rdevminor,
            // namesize, check.
            let filesize = field(6)?;
            let mode = field(1)?;
            let namesize = field(11)?;
            let check = field(12)?;
            let inode = field(0)?;
            let uid = field(2)?;
            let gid = field(3)?;
            let nlink = field(4)?;
            let mtime = field(5)?;
            let _devmajor = field(7)?;
            let _devminor = field(8)?;
            let _rdevmajor = field(9)?;

            // Name area: starts after the header, includes the NUL,
            // padded to 4 bytes. Capped by its OWN sanity bound (a name
            // is not file data; tying it to max_child_size misfires —
            // C2 test: max_child_size=8 rejects "big.bin\0"). Also
            // bounded by the source length below.
            const MAX_NAME: u64 = 4096;
            if namesize == 0 || namesize > MAX_NAME {
                return Err(Error::Validation {
                    format: "cpio",
                    reason: format!("implausible namesize {namesize}"),
                });
            }
            let name_start = off + ENTRY_HEADER;
            let name_end = name_start.checked_add(namesize).ok_or(Error::Validation {
                format: "cpio",
                reason: "name offset overflow".into(),
            })?;
            if name_end > src.len() {
                truncated = true;
                break;
            }
            let mut name_buf = vec![0u8; namesize as usize];
            src.read_at(name_start, &mut name_buf)?;
            // The name INCLUDES its terminating NUL per the format; a
            // buffer with no NUL is a malformed entry, not a name.
            // (Hardening: previously a missing NUL was silently accepted.)
            let Some(name_len) = name_buf.iter().position(|&b| b == 0) else {
                return Err(Error::Validation {
                    format: "cpio",
                    reason: format!("entry {entries_scanned}: name is missing its NUL terminator"),
                });
            };
            // D1: `c_namesize` includes the final NUL and the format
            // allows ADDITIONAL TRAILING NULs — so everything after the
            // first NUL must be 0x00. Anything else (`a\0X`) is a
            // malformed name field, not a name.
            if name_buf[name_len..].iter().any(|&b| b != 0) {
                return Err(Error::Validation {
                    format: "cpio",
                    reason: format!("entry {entries_scanned}: non-NUL byte after name terminator"),
                });
            }
            let name = String::from_utf8_lossy(&name_buf[..name_len]).into_owned();

            // B2: the name area is `110 + namesize` bytes of stream, then
            // the CURRENT POSITION is aligned to 4 (GNU cpio / Linux
            // initramfs: `cpio_header + filename + "\0" + ALGN(4) + data`).
            // The 110-byte header is 2 mod 4, so padding relative to the
            // position differs from padding relative to namesize alone.
            let name_area_abs = ENTRY_HEADER
                .checked_add(namesize)
                .ok_or(Error::Validation {
                    format: "cpio",
                    reason: "name offset overflow".into(),
                })?;
            let name_pad = (4 - (name_area_abs % 4)) % 4;
            let data_start = name_start
                .checked_add(namesize)
                .and_then(|p| p.checked_add(name_pad))
                .ok_or(Error::Validation {
                    format: "cpio",
                    reason: "data offset overflow".into(),
                })?;

            if name == TRAILER_NAME {
                // Archive ends after the trailer's aligned name area.
                archive_end = Some(data_start);
                break;
            }

            entries_scanned += 1;
            // C1: cap on entries SCANNED, not children produced — oversized
            // entries that skip child creation must not bypass the limit.
            if entries_scanned > MAX_ENTRIES || entries_scanned > limits.max_archive_entries {
                return Err(Error::Validation {
                    format: "cpio",
                    reason: format!("entry limit exceeded ({entries_scanned} entries)"),
                });
            }

            let mode_bits = (mode & 0o7777) as u32;
            let ftype = mode & 0o170000;

            // Data area (padded to 4).
            let data_area = pad4(filesize);
            let data_end = data_start.checked_add(data_area).ok_or(Error::Validation {
                format: "cpio",
                reason: "data offset overflow".into(),
            })?;
            if data_end > src.len() {
                truncated = true;
                break;
            }

            let type_name = match ftype {
                0o040000 => "directory",
                0o100000 => "regular file",
                0o120000 => "symlink",
                0o020000 => "character device",
                0o060000 => "block device",
                0o010000 => "FIFO",
                0o140000 => "socket",
                _ => "other",
            };

            let mut meta = BTreeMap::new();
            meta.insert("pathname".to_string(), name.clone());
            meta.insert("mode".to_string(), format!("{mode_bits:o}"));
            meta.insert("inode".to_string(), inode.to_string());
            meta.insert("uid".to_string(), uid.to_string());
            meta.insert("gid".to_string(), gid.to_string());
            meta.insert("nlink".to_string(), nlink.to_string());
            meta.insert("mtime".to_string(), mtime.to_string());
            meta.insert("entry_type".to_string(), type_name.to_string());

            // B3 + C2: in the crc variant the `check` field covers the
            // entry's DATA FIELD — the 32-bit byte sum — and that includes
            // symlinks (whose target bytes ARE the data field). Verify for
            // EVERY entry regardless of max_child_size: `max_child_size`
            // only decides whether a child artifact is exposed, it can
            // never stand in for checksum success. The sum is computed
            // streaming over a bounded slice (no unbounded allocation).
            if is_crc {
                if filesize > limits.max_child_size {
                    // Sum the oversized data field in bounded chunks.
                    let sum = sum_bytes_streaming(src, data_start, filesize)?;
                    if u64::from(sum) != check {
                        checksum_failures
                            .push(format!("{name}: stored {check:#x}, computed {sum:#x}"));
                        meta.insert("cpio_checksum".to_string(), "mismatch".to_string());
                    } else {
                        meta.insert(
                            "cpio_checksum".to_string(),
                            "valid (oversized, not exposed)".to_string(),
                        );
                    }
                } else {
                    let content = src.slice(data_start, filesize)?;
                    let sum = sum_bytes(&content)?;
                    if u64::from(sum) != check {
                        checksum_failures
                            .push(format!("{name}: stored {check:#x}, computed {sum:#x}"));
                        meta.insert("cpio_checksum".to_string(), "mismatch".to_string());
                    } else {
                        meta.insert("cpio_checksum".to_string(), "valid".to_string());
                    }
                }
            }

            match ftype {
                0o100000 => {
                    // Regular file: source-backed slice + recursive target.
                    if filesize > limits.max_child_size {
                        meta.insert("skipped".to_string(), "exceeds max child size".to_string());
                    } else {
                        let content = src.slice(data_start, filesize)?;
                        meta.insert("filesize".to_string(), filesize.to_string());
                        children.push(ChildDraft {
                            relation: RelationKind::Contains,
                            label: format!("cpio file {name}"),
                            format_hint: "raw",
                            content: ChildContent::Source(content),
                            size: filesize,
                            metadata: meta,
                            warnings: Vec::new(),
                            entry_name: Some(name),
                            confidence: Confidence::Validated,
                            evidence: vec!["structurally decoded by parent handler".to_string()],
                        });
                    }
                }
                0o120000 => {
                    // Symlink: target bytes are the "data"; metadata only.
                    let target = if filesize <= 4096 {
                        let mut tb = vec![0u8; filesize as usize];
                        src.read_at(data_start, &mut tb)?;
                        String::from_utf8_lossy(&tb).into_owned()
                    } else {
                        "<too long>".to_string()
                    };
                    meta.insert("link_target".to_string(), target);
                    meta.insert("host_materialization".to_string(), "forbidden".to_string());
                    children.push(ChildDraft {
                        relation: RelationKind::Contains,
                        label: format!("cpio symlink {name}"),
                        format_hint: "metadata",
                        content: ChildContent::Owned(Vec::new()),
                        size: 0,
                        metadata: meta,
                        warnings: vec![
                            "symlink entry: never materialized as a host symlink".to_string()
                        ],
                        entry_name: None,
                        confidence: Confidence::Validated,
                        evidence: vec!["structurally decoded by parent handler".to_string()],
                    });
                }
                0o040000 => {
                    // Directory: metadata only, no filesystem effects.
                    meta.insert(
                        "host_materialization".to_string(),
                        "metadata-only".to_string(),
                    );
                    children.push(ChildDraft {
                        relation: RelationKind::Contains,
                        label: format!("cpio directory {name}"),
                        format_hint: "metadata",
                        content: ChildContent::Owned(Vec::new()),
                        size: 0,
                        metadata: meta,
                        warnings: Vec::new(),
                        entry_name: None,
                        confidence: Confidence::Validated,
                        evidence: vec!["structurally decoded by parent handler".to_string()],
                    });
                }
                0o020000 | 0o060000 | 0o010000 | 0o140000 => {
                    // Device nodes / FIFO / socket: recognized, never created.
                    meta.insert("host_materialization".to_string(), "forbidden".to_string());
                    children.push(ChildDraft {
                        relation: RelationKind::Contains,
                        label: format!("cpio {type_name} {name}"),
                        format_hint: "metadata",
                        content: ChildContent::Owned(Vec::new()),
                        size: 0,
                        metadata: meta,
                        warnings: vec![format!(
                            "{type_name} entry: host special file creation forbidden"
                        )],
                        entry_name: None,
                        confidence: Confidence::Validated,
                        evidence: vec!["structurally decoded by parent handler".to_string()],
                    });
                }
                _ => {
                    meta.insert(
                        "host_materialization".to_string(),
                        "unknown-type".to_string(),
                    );
                    children.push(ChildDraft {
                        relation: RelationKind::Contains,
                        label: format!("cpio entry {name}"),
                        format_hint: "metadata",
                        content: ChildContent::Owned(Vec::new()),
                        size: 0,
                        metadata: meta,
                        warnings: vec!["unknown entry type".to_string()],
                        entry_name: None,
                        confidence: Confidence::Validated,
                        evidence: vec!["structurally decoded by parent handler".to_string()],
                    });
                }
            }

            // Advance past the padded data area to the next entry header.
            off = data_end;
        }

        // The archive is only structurally proven when we saw TRAILER!!!.
        let Some(end) = archive_end else {
            return Err(Error::Validation {
                format: "cpio",
                reason: if truncated {
                    "archive truncated before TRAILER!!!".to_string()
                } else {
                    "no TRAILER!!! found; not a structurally complete archive".to_string()
                },
            });
        };

        let mut metadata = BTreeMap::new();
        metadata.insert(
            "variant".to_string(),
            if is_crc_variant {
                "crc (070702)"
            } else {
                "newc (070701)"
            }
            .to_string(),
        );
        metadata.insert("entries".to_string(), entries_scanned.to_string());
        if !checksum_failures.is_empty() {
            metadata.insert(
                "checksum_failures".to_string(),
                checksum_failures.join("; "),
            );
        }

        let confidence = if is_crc_variant && !checksum_failures.is_empty() {
            Confidence::Damaged
        } else {
            Confidence::Validated
        };

        Ok(HandlerOutput {
            artifacts: vec![ArtifactDraft {
                format: "cpio".to_string(),
                label: format!(
                    "CPIO {} archive ({} entries)",
                    if is_crc_variant { "crc" } else { "newc" },
                    entries_scanned
                ),
                offset: base,
                size: end - base,
                confidence,
                evidence: Evidence::facts([
                    format!("{} entry headers parsed", entries_scanned),
                    "TRAILER!!! structurally terminates the archive".to_string(),
                    if is_crc_variant {
                        format!(
                            "crc variant: {} checksum failure(s)",
                            checksum_failures.len()
                        )
                    } else {
                        "newc variant (no per-entry checksum field)".to_string()
                    },
                ]),
                metadata,
                warnings: if checksum_failures.is_empty() {
                    Vec::new()
                } else {
                    vec![format!(
                        "{} checksum mismatch(es); archive not fully validated",
                        checksum_failures.len()
                    )]
                },
                errors: Vec::new(),
                children,
                entry_names: Vec::new(),
            }],
        })
    }
}

/// Parse 8 ASCII hex chars with full validation (digits only, no
/// overflow: max value 0xFFFFFFFF fits u64 trivially but malformed
/// digits must reject).
fn parse_hex(bytes: &[u8]) -> Result<u64> {
    let mut value: u64 = 0;
    for &b in bytes {
        let d = match b {
            b'0'..=b'9' => u64::from(b - b'0'),
            b'a'..=b'f' => u64::from(b - b'a' + 10),
            b'A'..=b'F' => u64::from(b - b'A' + 10),
            _ => {
                return Err(Error::Validation {
                    format: "cpio",
                    reason: format!("malformed hex digit {:#04x} in header field", b),
                });
            }
        };
        value = value
            .checked_mul(16)
            .and_then(|v| v.checked_add(d))
            .ok_or(Error::Validation {
                format: "cpio",
                reason: "hex field overflow".into(),
            })?;
    }
    Ok(value)
}

/// Round up to a 4-byte boundary (data areas: filesize then pad).
fn pad4(v: u64) -> u64 {
    (4 - (v % 4)) % 4 + v
}

/// Sum of all bytes mod 2^32 (the CPIO `crc` variant checksum).
fn sum_bytes(content: &ByteSource) -> Result<u32> {
    sum_bytes_streaming(content, 0, content.len())
}

/// Streaming byte-sum over `len` bytes of `src` starting at `offset` —
/// bounded memory regardless of `len` (C2: oversized entries still get
/// their checksum verified).
fn sum_bytes_streaming(src: &ByteSource, offset: u64, len: u64) -> Result<u32> {
    let mut sum: u32 = 0;
    let mut chunk = [0u8; 64 * 1024];
    let mut off = 0u64;
    while off < len {
        let n = (len - off).min(chunk.len() as u64) as usize;
        src.read_at(offset + off, &mut chunk[..n])?;
        for &b in &chunk[..n] {
            sum = sum.wrapping_add(u32::from(b));
        }
        off += n as u64;
    }
    Ok(sum)
}
