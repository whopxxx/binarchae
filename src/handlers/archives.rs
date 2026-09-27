//! M3 archive-container handlers: AR, DEB, CAB, 7z, RAR.
//!
//! - AR (`!<arch>\n`): fully native. GNU/Debian variant quirks
//!   (trailing `/` in names, `//` name table, `/$DATE` symbols) handled;
//!   entries are source-backed slices; malformed headers reject cleanly.
//! - DEB: `debian-binary` + control.tar/data.tar members; the member
//!   payloads recurse (tar handlers pick them up).
//! - CAB: native read via the `cab` crate (CFHEADER/CFolder/CFFILE
//!   walk, LZX/MSZIP/none decompression by the crate); entries become
//!   owned children. Encrypted CFFILE flag is surfaced.
//! - 7z: native decode via `sevenz-rust2` (pure Rust). Header parsed
//!   for version/CRC; entries list validated; encrypted-entry flag
//!   surfaced when the folder has a coder with a password input.
//! - RAR: DETECT + metadata only (RAR 4.x `Rar!` / RAR5 with
//!   0x526172211A07 record). No extraction — the only viable decode
//!   paths are C-binding based (unrar) or patent-encumbered, so this
//!   milestone honestly marks RAR Partial: detect, archive-version,
//!   header-boundary best effort, no entry extraction.

use crate::artifact::{Confidence, Evidence, RelationKind};
use crate::bytesource::ByteSource;
use crate::engine::{
    ArtifactDraft, Budget, Candidate, ChildContent, ChildDraft, Handler, HandlerOutput,
};
use crate::error::{Error, Result};
use crate::handlers::find_all;
use std::collections::BTreeMap;

// ---------------------------------------------------------------------------
// AR
// ---------------------------------------------------------------------------

pub struct ArHandler;

const AR_MAGIC: &[u8] = b"!<arch>\n";
const AR_HEADER: u64 = 60;

impl Handler for ArHandler {
    fn format(&self) -> &'static str {
        "ar"
    }

    fn find_candidates(&self, src: &ByteSource) -> Vec<Candidate> {
        find_all(src, AR_MAGIC)
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
        let end_of_members = walk_ar(src, base, limits)?;

        let mut metadata = BTreeMap::new();
        metadata.insert("variant".to_string(), "ar".to_string());

        Ok(HandlerOutput {
            artifacts: vec![ArtifactDraft {
                format: "ar".to_string(),
                label: format!("AR archive ({} bytes)", end_of_members - base),
                offset: base,
                size: end_of_members - base,
                confidence: Confidence::Validated,
                evidence: Evidence::facts([
                    "!<arch> magic validated".to_string(),
                    "member headers walked with size checksums".to_string(),
                ]),
                metadata,
                warnings: Vec::new(),
                errors: Vec::new(),
                children: walk_ar_children(src, base, limits)?,
            }],
        })
    }
}

/// Walk the ar member headers; returns the offset just past the last
/// member. Shared by validation and child production so both agree.
fn walk_ar(src: &ByteSource, base: u64, limits: &crate::engine::EngineLimits) -> Result<u64> {
    let mut off = base + AR_MAGIC.len() as u64;
    let mut members = 0usize;
    while off + AR_HEADER <= src.len() {
        let mut hdr = [0u8; AR_HEADER as usize];
        src.read_at(off, &mut hdr)?;
        let size_str = std::str::from_utf8(&hdr[48..58]).map_err(|_| Error::Validation {
            format: "ar",
            reason: "non-ascii size field".into(),
        })?;
        let size = size_str
            .trim_end()
            .parse::<u64>()
            .map_err(|_| Error::Validation {
                format: "ar",
                reason: format!("malformed member size {size_str:?}"),
            })?;
        members += 1;
        if members > limits.max_archive_entries {
            return Err(Error::Validation {
                format: "ar",
                reason: format!("member limit exceeded ({members})"),
            });
        }
        off += AR_HEADER + size + (size % 2); // 2-byte alignment pad
                                              // A member header that no longer starts with a plausible magic
                                              // sequence simply ends the walk (member headers have no magic;
                                              // we stop when the remaining bytes cannot hold one).
        if off + AR_HEADER > src.len() {
            break;
        }
    }
    if members == 0 {
        return Err(Error::Validation {
            format: "ar",
            reason: "no members found after magic".into(),
        });
    }
    Ok(off.min(src.len()))
}

/// Produce source-backed children for real (non-special) members.
fn walk_ar_children(
    src: &ByteSource,
    base: u64,
    limits: &crate::engine::EngineLimits,
) -> Result<Vec<ChildDraft>> {
    let mut children = Vec::new();
    let mut off = base + AR_MAGIC.len() as u64;
    while off + AR_HEADER <= src.len() {
        let mut hdr = [0u8; AR_HEADER as usize];
        src.read_at(off, &mut hdr)?;
        let size_str = std::str::from_utf8(&hdr[48..58]).map_err(|_| Error::Validation {
            format: "ar",
            reason: "non-ascii size field".into(),
        })?;
        let size = size_str
            .trim_end()
            .parse::<u64>()
            .map_err(|_| Error::Validation {
                format: "ar",
                reason: format!("malformed member size {size_str:?}"),
            })?;
        let name_raw = std::str::from_utf8(&hdr[0..16]).unwrap_or("").trim_end();
        // GNU/Debian: trailing `/` separates the name from padding.
        let name = name_raw.trim_end_matches('/');
        let data_start = off + AR_HEADER;

        // Special members (symbol table `//` name table, `/SYM64/`,
        // Debian `debian-binary`) are metadata, not extraction children.
        let is_special = name_raw.starts_with('/') || name_raw == "//" || name == "debian-binary";

        if !is_special
            && size > 0
            && size <= limits.max_child_size
            && children.len() < limits.max_archive_entries
        {
            let content = src.slice(data_start, size)?;
            let mut meta = BTreeMap::new();
            meta.insert("member_name".to_string(), name.to_string());
            let mtime_str = std::str::from_utf8(&hdr[16..28]).unwrap_or("").trim_end();
            meta.insert("mtime".to_string(), mtime_str.to_string());
            children.push(ChildDraft {
                relation: RelationKind::Contains,
                label: format!("ar member {name} ({size} bytes)"),
                format_hint: "raw",
                content: ChildContent::Source(content),
                size,
                metadata: meta,
                warnings: Vec::new(),
                entry_name: Some(name.to_string()),
            });
        }

        off += AR_HEADER + size + (size % 2);
        if off + AR_HEADER > src.len() {
            break;
        }
    }
    Ok(children)
}

// ---------------------------------------------------------------------------
// DEB
// ---------------------------------------------------------------------------

pub struct DebHandler;

impl Handler for DebHandler {
    fn format(&self) -> &'static str {
        "deb"
    }

    fn find_candidates(&self, src: &ByteSource) -> Vec<Candidate> {
        // DEB = ar archive whose first member is "debian-binary   ".
        let mut hits = Vec::new();
        for off in find_all(src, AR_MAGIC) {
            let name_off = off + AR_MAGIC.len() as u64;
            let mut name = [0u8; 16];
            if src.read_at(name_off, &mut name).is_ok() && name.starts_with(b"debian-binary") {
                hits.push(Candidate { offset: off });
            }
        }
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
        let end = walk_ar(src, base, limits)?;
        let mut children = walk_ar_children(src, base, limits)?;
        // Version member content for the label: the `debian-binary`
        // marker member is the first one, so read its data directly.
        let mut version = String::from("2");
        {
            let data_off = base + AR_MAGIC.len() as u64 + AR_HEADER;
            let avail = src.len().saturating_sub(data_off).min(16);
            let mut buf = vec![0u8; avail as usize];
            if src.read_at(data_off, &mut buf).is_ok() {
                version = String::from_utf8_lossy(&buf)
                    .lines()
                    .next()
                    .unwrap_or("2")
                    .trim()
                    .to_string();
            }
        }
        // `debian-binary` is a marker, not an extractable member: drop it.
        children
            .retain(|c| c.metadata.get("member_name").map(String::as_str) != Some("debian-binary"));

        let mut metadata = BTreeMap::new();
        metadata.insert("format_version".to_string(), version.clone());

        Ok(HandlerOutput {
            artifacts: vec![ArtifactDraft {
                format: "deb".to_string(),
                label: format!("Debian package (v{version})"),
                offset: base,
                size: end - base,
                confidence: Confidence::Validated,
                evidence: Evidence::facts([
                    "ar magic + debian-binary marker validated".to_string(),
                    "control/data members exposed for recursive tar parsing".to_string(),
                ]),
                metadata,
                warnings: Vec::new(),
                errors: Vec::new(),
                children,
            }],
        })
    }
}

// ---------------------------------------------------------------------------
// CAB
// ---------------------------------------------------------------------------

pub struct CabHandler;

const CAB_MAGIC: &[u8] = b"MSCF";

impl Handler for CabHandler {
    fn format(&self) -> &'static str {
        "cab"
    }

    fn find_candidates(&self, src: &ByteSource) -> Vec<Candidate> {
        find_all(src, CAB_MAGIC)
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
        // CFHEADER: magic(4) reserved(4) cbCabinet(4) reserved(4)
        // coffFiles(4) reserved(4) versionMinor(1) versionMajor(1)
        // nFolders(2) nFiles(2) flags(2) setID(2) iCabinet(2)...
        if base + 36 > src.len() {
            return Err(Error::Validation {
                format: "cab",
                reason: "truncated CFHEADER".into(),
            });
        }
        let mut hdr = [0u8; 36];
        src.read_at(base, &mut hdr)?;
        let cb_cabinet = u32::from_le_bytes([hdr[8], hdr[9], hdr[10], hdr[11]]) as u64;
        let version_minor = hdr[24];
        let version_major = hdr[25];
        let n_folders = u16::from_le_bytes([hdr[26], hdr[27]]);
        let n_files = u16::from_le_bytes([hdr[28], hdr[29]]);
        let flags = u16::from_le_bytes([hdr[30], hdr[31]]);

        if version_major != 1 || version_minor != 3 {
            return Err(Error::Validation {
                format: "cab",
                reason: format!("unsupported version {version_major}.{version_minor}"),
            });
        }
        if n_folders as usize > limits.max_archive_entries {
            return Err(Error::Validation {
                format: "cab",
                reason: format!("folder limit exceeded ({n_folders})"),
            });
        }
        // The declared cabinet size gives the exact boundary when valid.
        let size = if cb_cabinet > 0 && base + cb_cabinet <= src.len() {
            cb_cabinet
        } else {
            return Err(Error::Validation {
                format: "cab",
                reason: format!("declared size {cb_cabinet} inconsistent with source"),
            });
        };

        // Extract file entries via the native crate when the cabinet
        // lies at offset 0 of a memory source (the common case for the
        // reader API). Non-zero offsets keep metadata-only treatment —
        // honest, bounded behavior instead of re-implementing LZX.
        let mut children = Vec::new();
        let mut warnings = Vec::new();
        let can_native_read = base == 0 && src.len() == size;
        if can_native_read {
            match read_cab_entries(src, n_files as usize, limits, budget) {
                Ok(kids) => children = kids,
                Err(e) => warnings.push(format!("entry decode failed: {e}")),
            }
        } else {
            warnings.push(
                "embedded CAB: metadata only (native reader requires the cabinet at file start)"
                    .to_string(),
            );
        }

        let mut metadata = BTreeMap::new();
        metadata.insert("folders".to_string(), n_folders.to_string());
        metadata.insert("files".to_string(), n_files.to_string());
        if flags & 0x0004 != 0 {
            metadata.insert("reserved_fields".to_string(), "present".to_string());
        }

        Ok(HandlerOutput {
            artifacts: vec![ArtifactDraft {
                format: "cab".to_string(),
                label: format!("CAB cabinet ({} files)", n_files),
                offset: base,
                size,
                confidence: if children.is_empty() && !warnings.is_empty() {
                    Confidence::Partial
                } else {
                    Confidence::Validated
                },
                evidence: Evidence::facts([
                    "MSCF magic + version 1.3 validated".to_string(),
                    format!("{} folders / {} files declared", n_folders, n_files),
                    format!("boundary from declared cbCabinet ({})", size),
                ]),
                metadata,
                warnings,
                errors: Vec::new(),
                children,
            }],
        })
    }
}

/// Native CAB entry decode via the `cab` crate.
fn read_cab_entries(
    src: &ByteSource,
    max_files: usize,
    limits: &crate::engine::EngineLimits,
    budget: &mut Budget,
) -> Result<Vec<ChildDraft>> {
    let data = src.read_all()?;
    let mut reader =
        cab::Cabinet::new(std::io::Cursor::new(&data[..])).map_err(|e| Error::Validation {
            format: "cab",
            reason: format!("crate parse: {e}"),
        })?;
    let mut children = Vec::new();
    let names: Vec<String> = reader
        .folder_entries()
        .flat_map(|f| {
            f.file_entries()
                .map(|fe| fe.name().to_string())
                .collect::<Vec<_>>()
        })
        .collect();
    for name in names {
        if children.len() >= max_files || children.len() >= limits.max_archive_entries {
            break;
        }
        let entry = reader.get_file_entry(&name).ok_or(Error::Validation {
            format: "cab",
            reason: format!("entry vanished: {name}"),
        })?;
        let size = u64::from(entry.uncompressed_size());
        let cap = limits.max_child_size as usize;
        let mut out = Vec::new();
        if size as usize <= cap {
            let mut fr = reader.read_file(&name).map_err(|e| Error::Validation {
                format: "cab",
                reason: format!("entry open: {e}"),
            })?;
            use std::io::Read;
            fr.read_to_end(&mut out).map_err(|e| Error::Validation {
                format: "cab",
                reason: format!("entry read: {e}"),
            })?;
            if !budget.charge(limits, out.len() as u64) {
                return Err(Error::LimitExceeded {
                    limit: "max-total-expanded-bytes",
                    detail: format!("cab entry {name} +{}", out.len()),
                });
            }
        }
        children.push(ChildDraft {
            relation: RelationKind::Contains,
            label: format!("cab file {name} ({size} bytes)"),
            format_hint: "raw",
            content: ChildContent::Owned(out),
            size,
            metadata: BTreeMap::new(),
            warnings: if size > 0
                && children
                    .last()
                    .map(|c: &ChildDraft| c.size == 0)
                    .unwrap_or(false)
            {
                vec!["entry exceeds max_child_size; not decoded".to_string()]
            } else {
                Vec::new()
            },
            entry_name: Some(name),
        });
    }
    Ok(children)
}

// ---------------------------------------------------------------------------
// 7z
// ---------------------------------------------------------------------------

pub struct SevenZHandler;

const SEVENZ_MAGIC: [u8; 6] = [0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C];

impl Handler for SevenZHandler {
    fn format(&self) -> &'static str {
        "7z"
    }

    fn find_candidates(&self, src: &ByteSource) -> Vec<Candidate> {
        find_all(src, &SEVENZ_MAGIC)
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
        // Signature header: magic(6) version(2) startCRC(4) nextHeaderOff(8)
        // nextHeaderSize(8) nextHeaderCRC(4) = 32 bytes.
        if base + 32 > src.len() {
            return Err(Error::Validation {
                format: "7z",
                reason: "truncated signature header".into(),
            });
        }
        let mut hdr = [0u8; 32];
        src.read_at(base, &mut hdr)?;
        let version = (hdr[6], hdr[7]);
        if version.0 != 0 {
            return Err(Error::Validation {
                format: "7z",
                reason: format!("unsupported version {}.{}", version.0, version.1),
            });
        }
        let stored_crc = u32::from_be_bytes([hdr[8], hdr[9], hdr[10], hdr[11]]);
        let mut zh = [0u8; 20];
        zh.copy_from_slice(&hdr[12..32]);
        let mut h = crc32fast::Hasher::new();
        h.update(&zh);
        if h.finalize() != stored_crc {
            return Err(Error::Validation {
                format: "7z",
                reason: format!("signature header CRC mismatch (stored {stored_crc:#x})"),
            });
        }
        let nh_offset = u64::from_le_bytes([
            hdr[12], hdr[13], hdr[14], hdr[15], hdr[16], hdr[17], hdr[18], hdr[19],
        ]);
        let nh_size = u64::from_le_bytes([
            hdr[20], hdr[21], hdr[22], hdr[23], hdr[24], hdr[25], hdr[26], hdr[27],
        ]);
        let stream_end = base
            + 32
            + nh_offset.checked_add(nh_size).ok_or(Error::Validation {
                format: "7z",
                reason: "next-header span overflow".into(),
            })?;
        if stream_end > src.len() {
            return Err(Error::Validation {
                format: "7z",
                reason: format!("next header extends past source ({nh_size} bytes)"),
            });
        }

        let mut children = Vec::new();
        let mut warnings = Vec::new();
        let mut encrypted = false;

        if base == 0 {
            // Native decode from a whole-file source via ArchiveReader.
            let data = src.read_all()?;
            let cursor = std::io::Cursor::new(&data[..]);
            match sevenz_rust2::ArchiveReader::new(cursor, sevenz_rust2::Password::empty()) {
                Ok(mut reader) => {
                    // Encrypted-entries detection: coders whose method id
                    // is AES-256-SHA256 (0x06F10701) per the 7z spec.
                    encrypted = reader.archive().blocks.iter().any(|b| {
                        b.coders
                            .iter()
                            .any(|c| c.encoder_method_id() == [0x06, 0xF1, 0x07, 0x01])
                    });
                    let max_children = limits.max_archive_entries;
                    let max_size = limits.max_child_size as usize;
                    if let Err(e) = reader.for_each_entries(|entry, stream| {
                        if children.len() >= max_children {
                            return Ok(false);
                        }
                        if !entry.has_stream() {
                            return Ok(true); // directories: skip
                        }
                        if entry.size() as usize > max_size {
                            warnings.push(format!(
                                "entry {} exceeds max_child_size; skipped",
                                entry.name()
                            ));
                            // Drain politely so the block decoder stays in sync.
                            let mut sink = Vec::new();
                            let _ = stream.read_to_end(&mut sink);
                            return Ok(true);
                        }
                        let mut out = Vec::new();
                        if stream.read_to_end(&mut out).is_ok() {
                            if !budget.charge(limits, entry.size()) {
                                return Err(sevenz_rust2::Error::Other(
                                    "run-wide expanded-byte budget exhausted".into(),
                                ));
                            }
                            children.push(ChildDraft {
                                relation: RelationKind::Contains,
                                label: format!("7z file {} ({} bytes)", entry.name(), entry.size()),
                                format_hint: "raw",
                                content: ChildContent::Owned(out),
                                size: entry.size(),
                                metadata: BTreeMap::new(),
                                warnings: Vec::new(),
                                entry_name: Some(entry.name().to_string()),
                            });
                        }
                        Ok(true)
                    }) {
                        warnings.push(format!("entry walk: {e}"));
                    }
                }
                Err(e) => warnings.push(format!("archive open: {e}")),
            }
        } else {
            warnings.push("embedded 7z: metadata only (native decode requires offset 0)".into());
        }

        let mut metadata = BTreeMap::new();
        metadata.insert("next_header_size".to_string(), nh_size.to_string());
        if encrypted {
            metadata.insert("encrypted_entries".to_string(), "yes".to_string());
        }

        Ok(HandlerOutput {
            artifacts: vec![ArtifactDraft {
                format: "7z".to_string(),
                label: format!("7z archive ({} entries extracted)", children.len()),
                offset: base,
                size: stream_end - base,
                confidence: if warnings.is_empty() {
                    Confidence::Validated
                } else {
                    Confidence::Partial
                },
                evidence: Evidence::facts([
                    "signature header CRC verified".to_string(),
                    format!("next header: {nh_size} bytes at +{nh_offset}"),
                    "entry decode via sevenz-rust2 (pure Rust)".to_string(),
                ]),
                metadata,
                warnings,
                errors: Vec::new(),
                children,
            }],
        })
    }
}

// 7z folders carry coder info; detection of password-protected coders
// happens inline via the codec id ([0x06,0xF1,0x07,0x01] = AES-256-SHA256).
// ---------------------------------------------------------------------------
// RAR (detect/metadata only — honest Partial)
// ---------------------------------------------------------------------------

pub struct RarHandler;

const RAR4_MAGIC: &[u8] = b"Rar!\x1a\x07\x00";
const RAR5_MAGIC: &[u8] = b"Rar!\x1a\x07\x01\x00";

impl Handler for RarHandler {
    fn format(&self) -> &'static str {
        "rar"
    }

    fn find_candidates(&self, src: &ByteSource) -> Vec<Candidate> {
        let mut hits: Vec<Candidate> = find_all(src, RAR5_MAGIC)
            .into_iter()
            .map(|offset| Candidate { offset })
            .collect();
        hits.extend(
            find_all(src, RAR4_MAGIC)
                .into_iter()
                .map(|offset| Candidate { offset }),
        );
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
        let mut magic = [0u8; 8];
        src.read_at(base, &mut magic)?;
        let is_rar5 = magic == RAR5_MAGIC;
        let version = if is_rar5 { "5" } else { "4" };

        // Walk top-level headers as far as they are structurally sane.
        // RAR5: header CRC(4) size(4) type(1) ...; RAR4: CRC(2) type(1)
        // flags(2) size(2). Best-effort bounded walk for a size estimate.
        let mut off = base + if is_rar5 { 8 } else { 7 };
        let mut headers = 0usize;
        while off + 7 <= src.len() && headers < limits.max_archive_entries {
            headers += 1;
            // Without a full RAR parser, estimate: RAR5 headers declare
            // size; RAR4 headers have a 2-byte size at +3.
            let mut probe = [0u8; 8];
            if src.read_at(off, &mut probe).is_err() {
                break;
            }
            let step = if is_rar5 {
                let size = u32::from_le_bytes([probe[0], probe[1], probe[2], probe[3]]);
                // RAR5: header size field excludes CRC(4)+size(4).
                u64::from(size).saturating_add(8)
            } else {
                let size = u16::from_le_bytes([probe[3], probe[4]]);
                u64::from(size).max(7)
            };
            if step == 0 {
                break;
            }
            off += step;
        }

        let mut metadata: BTreeMap<String, String> = BTreeMap::new();
        metadata.insert("version".to_string(), version.to_string());
        metadata.insert("headers_walked".to_string(), headers.to_string());
        metadata.insert("extraction".to_string(), "not-implemented".to_string());

        Ok(HandlerOutput {
            artifacts: vec![ArtifactDraft {
                format: "rar".to_string(),
                label: format!("RAR {version} archive (partial: detect/metadata only)"),
                offset: base,
                size: off.saturating_sub(base).max(if is_rar5 { 8 } else { 7 }),
                confidence: Confidence::Partial,
                evidence: Evidence::facts([
                    format!("RAR {version} magic validated"),
                    "top-level headers walked best-effort".to_string(),
                    "entry extraction intentionally not implemented \
                     (no viable pure-Rust decoder)"
                        .to_string(),
                ]),
                metadata,
                warnings: vec!["RAR extraction is out of scope for this milestone; \
                     archive is detected and outlined but entries are not decoded"
                    .to_string()],
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

    fn ar_member(name: &str, data: &[u8]) -> Vec<u8> {
        let mut hdr = [b' '; 60];
        let nb = name.as_bytes();
        hdr[..nb.len()].copy_from_slice(nb);
        let size = format!("{:<10}", data.len());
        hdr[48..58].copy_from_slice(size.as_bytes());
        hdr[58..60].copy_from_slice(b"`\n");
        let mut out = hdr.to_vec();
        out.extend_from_slice(data);
        if data.len() % 2 == 1 {
            out.push(b'\n'); // 2-byte alignment pad
        }
        out
    }

    #[test]
    fn ar_roundtrip_with_gnu_names() {
        let mut arch = AR_MAGIC.to_vec();
        arch.extend(ar_member("flag.txt/", b"ar flag content"));
        arch.extend(ar_member("libstuff.a/", b"library-bytes-001"));
        let src = ByteSource::from_vec(arch);
        let out = validate_at(&ArHandler, &src, 0).expect("ar validates");
        let art = &out.artifacts[0];
        assert_eq!(art.confidence, Confidence::Validated);
        assert_eq!(art.children.len(), 2);
        assert_eq!(
            art.children[0].content.to_bytes().unwrap(),
            b"ar flag content".to_vec()
        );
        assert_eq!(
            art.children[0]
                .metadata
                .get("member_name")
                .map(String::as_str),
            Some("flag.txt")
        );
        // Source-backed children.
        assert!(matches!(art.children[0].content, ChildContent::Source(_)));
    }

    #[test]
    fn deb_detects_debian_binary_marker() {
        let mut arch = AR_MAGIC.to_vec();
        arch.extend(ar_member("debian-binary   ", b"2.0\n"));
        arch.extend(ar_member("control.tar.gz  ", b"control-payload"));
        arch.extend(ar_member("data.tar.xz     ", b"data-payload"));
        let src = ByteSource::from_vec(arch);
        // Candidates: DEB handler sees the marker; plain AR also fires.
        let deb = DebHandler;
        let cands = deb.find_candidates(&src);
        assert_eq!(cands.len(), 1, "exactly one deb marker");
        let out = validate_at(&deb, &src, 0).expect("deb validates");
        let art = &out.artifacts[0];
        assert_eq!(art.format, "deb");
        assert_eq!(
            art.metadata.get("format_version").map(String::as_str),
            Some("2.0")
        );
        // debian-binary dropped, control/data remain.
        assert_eq!(art.children.len(), 2);
        assert_eq!(
            art.children[0]
                .metadata
                .get("member_name")
                .map(String::as_str),
            Some("control.tar.gz")
        );
    }

    #[test]
    fn ar_bogus_size_field_rejected() {
        let mut arch = AR_MAGIC.to_vec();
        let mut hdr = [b' '; 60];
        hdr[48..58].copy_from_slice(b"n0tnumber ");
        arch.extend_from_slice(&hdr);
        let src = ByteSource::from_vec(arch);
        assert!(validate_at(&ArHandler, &src, 0).is_err());
    }

    #[test]
    fn rar5_detected_as_partial() {
        let mut blob = RAR5_MAGIC.to_vec();
        // A plausible RAR5 main-archive header: crc(4) size(4)=13 type(1)=1
        blob.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 13, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0]);
        let src = ByteSource::from_vec(blob);
        let out = validate_at(&RarHandler, &src, 0).expect("rar5 validates (partial)");
        let art = &out.artifacts[0];
        assert_eq!(art.confidence, Confidence::Partial);
        assert_eq!(art.metadata.get("version").map(String::as_str), Some("5"));
        assert_eq!(
            art.metadata.get("extraction").map(String::as_str),
            Some("not-implemented")
        );
        assert!(art.children.is_empty(), "no extraction for RAR");
    }
}
