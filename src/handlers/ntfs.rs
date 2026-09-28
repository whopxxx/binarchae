//! NTFS read-only MFT traversal (Issue #7 §1.2).
//!
//! Layout verified against Linux `fs/ntfs3/{ntfs.h,ntfs_fs.h,run.c}`:
//! - boot sector (512 B): OEM "NTFS    " @3; bytes_per_sector @0x0B;
//!   sectors_per_cluster @0x0D; sectors_per_volume @0x28; mft_clst
//!   @0x30; record_size @0x40 (signed, clusters if >0 else -log2 bytes);
//!   boot magic 0xAA55 @0x1FE;
//! - MFT record ("FILE" @0): fix_off @4, fix_num @6, seq @0x10,
//!   hard_links @0x12, attr_off @0x14, flags @0x16 (bit0 in-use),
//!   used @0x18, total @0x1C, record number @0x2C. Update-sequence
//!   array: fix_num-1 u16 fixups at fix_off replace the last u16 of
//!   each 512-byte stride; the UAS marker at each stride end must match;
//! - attributes: {type u32, size u32, non_res u8, name_len u8, name_off
//!   u16, flags u16, id u16}; resident body: data_size @0x10, data_off
//!   @0x14; nonresident: svcn @0x10, evcn @0x18, run_off @0x20,
//!   c_unit @0x22, alloc @0x28, data_size @0x30, valid @0x38;
//!   type 0x80 = DATA, 0x10 = STANDARD_INFORMATION (timestamps @0x10),
//!   0x30 = FILE_NAME (name_len words @0x40, name @0x42), 0x90 = INDEX_ROOT;
//!   type 0xFFFFFFFF ends the attribute walk;
//! - runlists: per run {header byte: low nibble = size field bytes,
//!   high nibble = offset field bytes}; size is little-endian; offset is
//!   sign-extended little-endian delta from previous LCN; offset 0 =
//!   sparse run;
//! - directory index: INDEX_ROOT attribute (root @0x10: de_off/used/
//!   total/flags) with NTFS_DE entries {ref u64, size u16, key_size u16,
//!   flags u16}; bit1 = last, bit0 = has subnodes (alloc not walked).
//!
//! Deleted records (in-use bit clear) surface as CarvedFrom children.

use crate::artifact::{Confidence, Evidence, RelationKind};
use crate::bytesource::ByteSource;
use crate::engine::{
    ArtifactDraft, Budget, Candidate, ChildContent, ChildDraft, Handler, HandlerOutput,
};
use crate::error::{Error, Result};
use crate::handlers::find_all;
use std::collections::BTreeMap;

pub struct NtfsHandler;

const ATTR_STD: u32 = 0x10;
const ATTR_NAME: u32 = 0x30;
const ATTR_DATA: u32 = 0x80;
const ATTR_ROOT: u32 = 0x90;
const ATTR_END: u32 = 0xFFFF_FFFF;
const FILE_MAGIC: &[u8] = b"FILE";
const IN_USE: u16 = 0x0001;
const IE_LAST: u16 = 0x0002;
const FA_DIRECTORY: u32 = 0x1000_0000;

fn le64(src: &ByteSource, off: u64) -> Option<u64> {
    let mut b = [0u8; 8];
    src.read_at(off, &mut b).ok()?;
    Some(u64::from_le_bytes(b))
}

/// Parsed boot sector geometry.
#[derive(Debug, Clone)]
struct NtfsBoot {
    bytes_per_sector: u64,
    sectors_per_cluster: u64,
    mft_lcn: u64,
    /// Byte size of one MFT record.
    record_size: u64,
    volume_sectors: u64,
}

impl NtfsBoot {
    fn cluster_size(&self) -> u64 {
        self.bytes_per_sector * self.sectors_per_cluster
    }
}

/// One attribute parsed from an MFT record.
#[derive(Debug, Clone)]
struct NtfsAttr {
    typ: u32,
    name: Option<String>,
    /// Resident payload (data_size bytes) when resident.
    resident: Option<Vec<u8>>,
    /// Non-resident run metadata.
    nonres: Option<NonResident>,
}

#[derive(Debug, Clone)]
struct NonResident {
    data_size: u64,
    /// Raw packed runlist bytes (copied at parse time).
    raw_runs: Vec<u8>,
}

impl NtfsAttr {
    /// Data size (either resident payload len or non-resident data_size).
    fn size(&self) -> u64 {
        match (&self.resident, &self.nonres) {
            (Some(r), _) => r.len() as u64,
            (_, Some(n)) => n.data_size,
            _ => 0,
        }
    }
}

/// Parse the update-sequence fixups: returns the fixed record bytes.
fn apply_fixups(rec: &mut [u8]) -> Result<()> {
    if rec.len() < 0x30 {
        return Err(Error::Validation {
            format: "ntfs",
            reason: "MFT record truncated".into(),
        });
    }
    let fix_off = u16::from_le_bytes([rec[4], rec[5]]) as usize;
    let fix_num = u16::from_le_bytes([rec[6], rec[7]]) as usize;
    if fix_off == 0 || fix_num == 0 || fix_off + fix_num * 2 > rec.len() {
        return Err(Error::Validation {
            format: "ntfs",
            reason: format!("bad update-sequence array (off {fix_off}, num {fix_num})"),
        });
    }
    let usn = u16::from_le_bytes([rec[fix_off], rec[fix_off + 1]]);
    let stride = 512usize;
    for i in 1..fix_num {
        let end = i * stride;
        if end > rec.len() || fix_off + 2 + (i - 1) * 2 + 2 > rec.len() {
            return Err(Error::Validation {
                format: "ntfs",
                reason: "update-sequence array overruns record".into(),
            });
        }
        // Each stride's last u16 must equal the USN; replace with fixup.
        let actual = u16::from_le_bytes([rec[end - 2], rec[end - 1]]);
        if actual != usn {
            return Err(Error::Validation {
                format: "ntfs",
                reason: format!("fixup {i} mismatch (record damaged)"),
            });
        }
        let fix = u16::from_le_bytes([rec[fix_off + i * 2], rec[fix_off + i * 2 + 1]]);
        rec[end - 2] = (fix & 0xff) as u8;
        rec[end - 1] = (fix >> 8) as u8;
    }
    Ok(())
}

impl NtfsHandler {
    fn parse_boot(src: &ByteSource, base: u64) -> Result<NtfsBoot> {
        if base + 512 > src.len() {
            return Err(Error::Validation {
                format: "ntfs",
                reason: "boot sector truncated".into(),
            });
        }
        let mut bs = [0u8; 512];
        src.read_at(base, &mut bs)?;
        if &bs[3..11] != b"NTFS    " {
            return Err(Error::Validation {
                format: "ntfs",
                reason: "not an NTFS boot sector".into(),
            });
        }
        if u16::from_le_bytes([bs[0x1FE], bs[0x1FF]]) != 0xAA55 {
            return Err(Error::Validation {
                format: "ntfs",
                reason: "boot signature != 0xAA55".into(),
            });
        }
        let bytes_per_sector = if bs[0x0B] == 0 && bs[0x0C] == 0 {
            return Err(Error::Validation {
                format: "ntfs",
                reason: "zero bytes per sector".into(),
            });
        } else {
            u16::from_le_bytes([bs[0x0B], bs[0x0C]]) as u64
        };
        let spc = bs[0x0D] as u64;
        if spc == 0 || !spc.is_power_of_two() {
            return Err(Error::Validation {
                format: "ntfs",
                reason: format!("bad sectors per cluster {spc}"),
            });
        }
        // NTFS requires bytes_per_sector in [256..65536] and a power of 2.
        if !(256..=65536).contains(&bytes_per_sector) || !bytes_per_sector.is_power_of_two() {
            return Err(Error::Validation {
                format: "ntfs",
                reason: format!("bad bytes per sector {bytes_per_sector}"),
            });
        }
        let mft_lcn = le64(src, base + 0x30).unwrap_or(0);
        let volume_sectors = le64(src, base + 0x28).unwrap_or(0);
        let cluster_bytes = bytes_per_sector * spc;
        let record_size = if bs[0x40] as i8 > 0 {
            cluster_bytes * u64::from(bs[0x40])
        } else {
            let shift = -(bs[0x40] as i32);
            if !(8..=12).contains(&shift) {
                return Err(Error::Validation {
                    format: "ntfs",
                    reason: format!("implausible MFT record size exponent {shift}"),
                });
            }
            1u64 << shift
        };
        if !(128..=4096).contains(&record_size) || !record_size.is_power_of_two() {
            return Err(Error::Validation {
                format: "ntfs",
                reason: format!("implausible MFT record size {record_size}"),
            });
        }
        if mft_lcn == 0 || volume_sectors == 0 {
            return Err(Error::Validation {
                format: "ntfs",
                reason: "zero MFT LCN or volume size".into(),
            });
        }
        Ok(NtfsBoot {
            bytes_per_sector,
            sectors_per_cluster: spc,
            mft_lcn,
            record_size,
            volume_sectors,
        })
    }

    /// Absolute byte offset of MFT record `n`.
    fn mft_record_off(&self, boot: &NtfsBoot, base: u64, n: u64) -> u64 {
        base + boot.mft_lcn * boot.cluster_size() + n * boot.record_size
    }

    /// Read + fixup one MFT record.
    fn read_record(&self, src: &ByteSource, boot: &NtfsBoot, base: u64, n: u64) -> Result<Vec<u8>> {
        let off = self.mft_record_off(boot, base, n);
        if off + boot.record_size > src.len() {
            return Err(Error::Validation {
                format: "ntfs",
                reason: format!("MFT record {n} past source"),
            });
        }
        let mut rec = vec![0u8; boot.record_size as usize];
        src.read_at(off, &mut rec)?;
        if &rec[0..4] != FILE_MAGIC {
            return Err(Error::Validation {
                format: "ntfs",
                reason: format!("MFT record {n} magic != FILE"),
            });
        }
        apply_fixups(&mut rec)?;
        Ok(rec)
    }

    /// Parse the attribute chain of a record.
    fn parse_attrs(rec: &[u8]) -> Vec<NtfsAttr> {
        let mut out = Vec::new();
        let attr_off = u16::from_le_bytes([rec[0x14], rec[0x15]]) as usize;
        let used = u32::from_le_bytes([rec[0x18], rec[0x19], rec[0x1A], rec[0x1B]]) as usize;
        let mut off = attr_off;
        while off + 0x10 <= rec.len().min(used) {
            let typ = u32::from_le_bytes([rec[off], rec[off + 1], rec[off + 2], rec[off + 3]]);
            if typ == ATTR_END {
                break;
            }
            let size = u32::from_le_bytes([rec[off + 4], rec[off + 5], rec[off + 6], rec[off + 7]])
                as usize;
            if size < 0x10 || off + size > rec.len() {
                break; // malformed attribute: stop the walk
            }
            let non_res = rec[off + 8] != 0;
            let name_len = rec[off + 9] as usize;
            let name_off = u16::from_le_bytes([rec[off + 0x0A], rec[off + 0x0B]]) as usize;
            let name = if name_len > 0 && name_off + name_len * 2 <= size {
                let units: Vec<u16> = (0..name_len)
                    .map(|k| {
                        u16::from_le_bytes([
                            rec[off + name_off + k * 2],
                            rec[off + name_off + k * 2 + 1],
                        ])
                    })
                    .collect();
                Some(String::from_utf16_lossy(&units))
            } else {
                None
            };
            let (resident, nonres) = if !non_res {
                if off + 0x18 > rec.len() {
                    break;
                }
                let data_size = u32::from_le_bytes([
                    rec[off + 0x10],
                    rec[off + 0x11],
                    rec[off + 0x12],
                    rec[off + 0x13],
                ]) as usize;
                let data_off = u16::from_le_bytes([rec[off + 0x14], rec[off + 0x15]]) as usize;
                if data_off + data_size <= size && off + data_off + data_size <= rec.len() {
                    (
                        Some(rec[off + data_off..off + data_off + data_size].to_vec()),
                        None,
                    )
                } else {
                    (Some(Vec::new()), None)
                }
            } else {
                if size < 0x40 {
                    break;
                }
                let run_off = u16::from_le_bytes([rec[off + 0x20], rec[off + 0x21]]) as usize;
                let data_size = u64::from_le_bytes([
                    rec[off + 0x30],
                    rec[off + 0x31],
                    rec[off + 0x32],
                    rec[off + 0x33],
                    rec[off + 0x34],
                    rec[off + 0x35],
                    rec[off + 0x36],
                    rec[off + 0x37],
                ]);
                // alloc_size (at +0x28) is implicit from the runs; not needed.
                let _ = &rec[off + 0x28..off + 0x30];
                (
                    None,
                    Some(NonResident {
                        data_size,
                        raw_runs: rec[off + run_off..off + size].to_vec(),
                    }),
                )
            };
            out.push(NtfsAttr {
                typ,
                name,
                resident,
                nonres,
            });
            off += size;
        }
        out
    }

    /// Decode a packed runlist: returns (lcn, len) runs; lcn None = sparse.
    fn unpack_runs(runs: &[u8], cluster_size: u64) -> Vec<(Option<u64>, u64)> {
        let mut out = Vec::new();
        let mut pos = 0usize;
        let mut prev_lcn: i64 = 0;
        while pos < runs.len() {
            let header = runs[pos];
            pos += 1;
            let size_size = (header & 0x0F) as usize;
            let offset_size = (header >> 4) as usize;
            if size_size == 0 {
                break; // end of runlist
            }
            if pos + size_size > runs.len() {
                break;
            }
            let mut len: u64 = 0;
            for k in 0..size_size {
                len |= u64::from(runs[pos + k]) << (8 * k);
            }
            pos += size_size;
            if len == 0 {
                break;
            }
            if offset_size == 0 {
                out.push((None, len * cluster_size)); // sparse
                continue;
            }
            if pos + offset_size > runs.len() {
                break;
            }
            // Little-endian value, sign-extended from offset_size*8
            // bits. FINAL-B2: offset_size == 8 previously computed
            // `1i64 << 64` (shift overflow panic in debug / UB-adjacent
            // behavior); use i128 for the width-sized arithmetic and
            // keep the accumulator in i64 via checked ops.
            let mut val: u128 = 0;
            for k in 0..offset_size {
                val |= u128::from(runs[pos + k]) << (8 * k);
            }
            let width = offset_size * 8;
            let sign_bit = 1u128 << (width - 1);
            let delta: i64 = if val & sign_bit != 0 {
                let ext = (val as i128) - (1i128 << width);
                // A delta beyond i64 is a corrupt runlist; treat as
                // invalid by aborting the walk (i64::MAX sentinel).
                i64::try_from(ext).unwrap_or(i64::MAX)
            } else {
                i64::try_from(val).unwrap_or(i64::MAX)
            };
            pos += offset_size;
            prev_lcn = prev_lcn.wrapping_add(delta);
            if delta == 0 || delta == i64::MAX {
                // Zero delta with nonzero offset field is invalid; stop.
                break;
            }
            out.push((Some(prev_lcn as u64), len * cluster_size));
        }
        out
    }

    /// Read non-resident attribute content (sparse runs zero-filled).
    fn read_nonresident(
        src: &ByteSource,
        base: u64,
        boot: &NtfsBoot,
        attr: &NtfsAttr,
        limits: &crate::engine::EngineLimits,
        budget: &mut Budget,
        warnings: &mut Vec<String>,
    ) -> Result<Vec<u8>> {
        let nr = attr.nonres.as_ref().expect("non-resident");
        let total = nr.data_size.min(limits.max_child_size);
        let mut out = vec![0u8; total as usize];
        let runs = Self::unpack_runs(&nr.raw_runs, boot.cluster_size());
        let mut off_vcn = 0u64;
        for (lcn, len) in runs {
            if off_vcn >= total {
                break;
            }
            match lcn {
                None => {
                    off_vcn += len; // sparse stays zero
                }
                Some(l) => {
                    let take = len.min(total - off_vcn);
                    let off = base + l * boot.cluster_size();
                    if off + take <= src.len() {
                        src.read_at(off, &mut out[off_vcn as usize..(off_vcn + take) as usize])?;
                    } else {
                        warnings.push("run past source; zero-filled".to_string());
                    }
                    if !budget.charge(limits, take) {
                        return Err(Error::LimitExceeded {
                            limit: "max-total-expanded-bytes",
                            detail: "NTFS non-resident read".into(),
                        });
                    }
                    off_vcn += take;
                }
            }
        }
        Ok(out)
    }

    /// Emit a child for a DATA attribute (resident or non-resident).
    #[allow(clippy::too_many_arguments)]
    fn emit_data_child(
        src: &ByteSource,
        base: u64,
        boot: &NtfsBoot,
        rec_n: u64,
        attr: &NtfsAttr,
        stream_label: &str,
        child_path: &str,
        limits: &crate::engine::EngineLimits,
        budget: &mut Budget,
        warnings: &mut Vec<String>,
        out: &mut Vec<ChildDraft>,
    ) -> Result<()> {
        let label_full = format!("{child_path}{stream_label}");
        let meta = {
            let mut m = BTreeMap::new();
            m.insert("path".to_string(), child_path.to_string());
            m.insert("mft_record".to_string(), rec_n.to_string());
            m.insert(
                "stream".to_string(),
                attr.name.clone().unwrap_or_else(|| "default".to_string()),
            );
            m.insert("declared_size".to_string(), attr.size().to_string());
            m
        };
        if let Some(payload) = &attr.resident {
            out.push(ChildDraft {
                relation: RelationKind::FilesystemEntry,
                label: format!("NTFS resident data {label_full} ({} bytes)", payload.len()),
                format_hint: "raw",
                content: ChildContent::Owned(payload.clone()),
                size: payload.len() as u64,
                metadata: meta,
                warnings: Vec::new(),
                entry_name: Some(label_full),
                confidence: Confidence::Validated,
                evidence: vec!["structurally decoded by parent handler".to_string()],
            });
            return Ok(());
        }
        let size = attr.size();
        if size == 0 {
            out.push(ChildDraft {
                relation: RelationKind::FilesystemEntry,
                label: format!("NTFS file {label_full} (0 bytes)"),
                format_hint: "raw",
                content: ChildContent::Owned(Vec::new()),
                size: 0,
                metadata: meta,
                warnings: Vec::new(),
                entry_name: Some(label_full),
                confidence: Confidence::Validated,
                evidence: vec!["structurally decoded by parent handler".to_string()],
            });
            return Ok(());
        }
        if size > limits.max_child_size {
            warnings.push(format!(
                "file {label_full}: {} bytes exceed max_child_size; data not exposed",
                size
            ));
            out.push(ChildDraft {
                relation: RelationKind::FilesystemEntry,
                label: format!("NTFS file {label_full} (metadata only)"),
                format_hint: "metadata",
                content: ChildContent::Owned(Vec::new()),
                size: 0,
                metadata: meta,
                warnings: Vec::new(),
                entry_name: Some(label_full),
                confidence: Confidence::Validated,
                evidence: vec!["structurally decoded by parent handler".to_string()],
            });
            return Ok(());
        }
        let data = Self::read_nonresident(src, base, boot, attr, limits, budget, warnings)?;
        out.push(ChildDraft {
            relation: RelationKind::ReconstructedFrom,
            label: format!("NTFS file {label_full} ({} bytes)", data.len()),
            format_hint: "raw",
            content: ChildContent::Owned(data),
            size,
            metadata: meta,
            warnings: vec!["content reconstructed from non-resident runs".to_string()],
            entry_name: Some(label_full),
            confidence: Confidence::Validated,
            evidence: vec!["structurally decoded by parent handler".to_string()],
        });
        Ok(())
    }

    /// Emit a file/dir child from one MFT record.
    #[allow(clippy::too_many_arguments)]
    fn emit_record(
        &self,
        src: &ByteSource,
        base: u64,
        boot: &NtfsBoot,
        rec_n: u64,
        child_path: Option<String>,
        depth: u32,
        limits: &crate::engine::EngineLimits,
        budget: &mut Budget,
        warnings: &mut Vec<String>,
        out: &mut Vec<ChildDraft>,
    ) -> Result<()> {
        if depth > 16 {
            warnings.push("NTFS directory nesting deeper than 16 not walked".to_string());
            return Ok(());
        }
        let rec = match self.read_record(src, boot, base, rec_n) {
            Ok(r) => r,
            Err(_) => {
                warnings.push(format!("MFT record {rec_n} unreadable; skipped"));
                return Ok(());
            }
        };
        let flags = u16::from_le_bytes([rec[0x16], rec[0x17]]);
        let in_use = flags & IN_USE != 0;
        let attrs = Self::parse_attrs(&rec);

        // File name from the FILE_NAME attribute (longest non-DOS).
        let mut fname: Option<String> = None;
        let mut is_dir = false;
        for a in &attrs {
            if a.typ == ATTR_NAME {
                if let Some(res) = &a.resident {
                    if res.len() > 0x42 {
                        let name_len = res[0x40] as usize;
                        let ftype = res[0x41];
                        if name_len > 0 && res.len() >= 0x42 + name_len * 2 {
                            let units: Vec<u16> = (0..name_len)
                                .map(|k| u16::from_le_bytes([res[0x42 + k * 2], res[0x43 + k * 2]]))
                                .collect();
                            let n = String::from_utf16_lossy(&units);
                            // Prefer WIN32/POSIX names over DOS 8.3.
                            if ftype != 2 && (fname.is_none() || n.len() < 260) {
                                fname = Some(n);
                            }
                        }
                    }
                }
            }
            if a.typ == ATTR_STD {
                if let Some(res) = &a.resident {
                    if res.len() >= 0x24 {
                        let fa = u32::from_le_bytes([res[0x20], res[0x21], res[0x22], res[0x23]]);
                        is_dir = fa & FA_DIRECTORY != 0;
                    }
                }
            }
        }

        // #7 §8: a record whose in-use flag is cleared is a DELETED
        // file/dir. Its attributes (and for small files the resident
        // $DATA payload) usually survive until the clusters are
        // reused, so we still surface it — flagged honestly as
        // deleted content, never as a validated live file.
        let deleted = !in_use;
        let display = child_path
            .or_else(|| fname.clone())
            .unwrap_or_else(|| format!("$MFT record {rec_n}"));

        // DATA attributes: children (default stream for files; named
        // streams = alternate data streams).
        let mut data_attrs: Vec<&NtfsAttr> = attrs.iter().filter(|a| a.typ == ATTR_DATA).collect();
        // Directories typically have no unnamed $DATA; files do.
        if data_attrs.is_empty() && !is_dir {
            warnings.push(format!("record {rec_n} ({display}): no $DATA attribute"));
        }
        if !is_dir {
            let before = out.len();
            for a in data_attrs.drain(..) {
                let stream_label = if a.name.is_some() {
                    format!(":{}", a.name.clone().unwrap_or_default())
                } else {
                    String::new()
                };
                Self::emit_data_child(
                    src,
                    base,
                    boot,
                    rec_n,
                    a,
                    &stream_label,
                    &display,
                    limits,
                    budget,
                    warnings,
                    out,
                )?;
            }
            if deleted {
                // §8: mark everything the deleted record produced. FINAL-B7:
                // the confidence claim must match — deleted records are
                // RECOVERED bytes (clusters may be reused), not Validated.
                for c in &mut out[before..] {
                    c.metadata.insert("deleted".to_string(), "true".to_string());
                    c.warnings
                        .push("deleted MFT record: clusters may be reused; content is best-effort recovery".to_string());
                    c.confidence = Confidence::Recovered;
                    c.evidence = vec![
                        "bytes recovered from a deleted MFT record".to_string(),
                        "clusters may have been reused since deletion".to_string(),
                    ];
                }
            }
        } else {
            // Directory: walk INDEX_ROOT (small dirs) as metadata child.
            for a in &attrs {
                if a.typ == ATTR_ROOT {
                    if let Some(res) = &a.resident {
                        if res.len() >= 0x20 {
                            let de_off =
                                u32::from_le_bytes([res[0x10], res[0x11], res[0x12], res[0x13]])
                                    as usize;
                            let used =
                                u32::from_le_bytes([res[0x14], res[0x15], res[0x16], res[0x17]])
                                    as usize;
                            // Walk entries from de_off while pos + 0x10 <= used.
                            let mut pos = de_off;
                            while pos + 0x10 <= used.min(res.len()) {
                                let e_ref = u64::from_le_bytes([
                                    res[pos],
                                    res[pos + 1],
                                    res[pos + 2],
                                    res[pos + 3],
                                    res[pos + 4],
                                    res[pos + 5],
                                    res[pos + 6],
                                    res[pos + 7],
                                ]);
                                let size =
                                    u16::from_le_bytes([res[pos + 8], res[pos + 9]]) as usize;
                                let eflags = u16::from_le_bytes([res[pos + 12], res[pos + 13]]);
                                if size == 0 {
                                    break;
                                }
                                if eflags & IE_LAST == 0 && e_ref != 0 {
                                    let child_rec = e_ref & 0xFFFF_FFFF;
                                    // The child's own FILE_NAME gives
                                    // its label; pass None so we use it.
                                    let mut sub_out = Vec::new();
                                    self.emit_record(
                                        src,
                                        base,
                                        boot,
                                        child_rec,
                                        None,
                                        depth + 1,
                                        limits,
                                        budget,
                                        warnings,
                                        &mut sub_out,
                                    )?;
                                    out.extend(sub_out);
                                }
                                if eflags & IE_LAST != 0 {
                                    break;
                                }
                                pos += size;
                            }
                        }
                    }
                }
            }
            let mut dmeta = BTreeMap::new();
            dmeta.insert("mft_record".to_string(), rec_n.to_string());
            dmeta.insert("type".to_string(), "directory".to_string());
            let mut dwarn = Vec::new();
            if deleted {
                dmeta.insert("deleted".to_string(), "true".to_string());
                dwarn.push(
                    "deleted MFT record: directory content is best-effort recovery".to_string(),
                );
            }
            out.push(ChildDraft {
                relation: RelationKind::FilesystemEntry,
                label: format!("NTFS directory {display}"),
                format_hint: "metadata",
                content: ChildContent::Owned(Vec::new()),
                size: 0,
                metadata: dmeta,
                warnings: dwarn,
                entry_name: fname,
                confidence: Confidence::Validated,
                evidence: vec!["structurally decoded by parent handler".to_string()],
            });
        }
        Ok(())
    }
}

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
        limits: &crate::engine::EngineLimits,
        budget: &mut Budget,
    ) -> Result<HandlerOutput> {
        let base = candidate.offset;
        let boot = Self::parse_boot(src, base)?;

        // Walk the first max_records MFT records; files/dirs surface.
        let mut children = Vec::new();
        let mut warnings = Vec::new();
        let count = limits.max_records.min(4096);
        for n in 0..count as u64 {
            if children.len() >= limits.max_fs_entries {
                warnings.push("max_fs_entries reached; MFT walk truncated".to_string());
                break;
            }
            let off = self.mft_record_off(&boot, base, n);
            if off + boot.record_size > src.len() {
                break; // honest end of MFT
            }
            // Skip system records 0..16 except when they carry data
            // ($MFT itself etc. are metadata; skipping avoids noise).
            if n < 16 {
                continue;
            }
            let magic_ok = {
                let mut m = [0u8; 4];
                src.read_at(off, &mut m).is_ok() && m == *FILE_MAGIC
            };
            if !magic_ok {
                continue;
            }
            self.emit_record(
                src,
                base,
                &boot,
                n,
                None,
                0,
                limits,
                budget,
                &mut warnings,
                &mut children,
            )?;
        }

        let mut metadata = BTreeMap::new();
        metadata.insert("cluster_size".to_string(), boot.cluster_size().to_string());
        metadata.insert("mft_lcn".to_string(), boot.mft_lcn.to_string());
        metadata.insert("record_size".to_string(), boot.record_size.to_string());
        metadata.insert("entries".to_string(), children.len().to_string());

        Ok(HandlerOutput {
            artifacts: vec![ArtifactDraft {
                format: "ntfs".to_string(),
                label: format!(
                    "NTFS filesystem ({}B clusters, {} entries)",
                    boot.cluster_size(),
                    children.len()
                ),
                offset: base,
                size: boot.volume_sectors * boot.bytes_per_sector,
                confidence: Confidence::Validated,
                evidence: Evidence::facts([
                    "NTFS boot sector validated (OEM, signature, geometry)".to_string(),
                    format!(
                        "MFT at LCN {} (record size {} B); {} records walked",
                        boot.mft_lcn,
                        boot.record_size,
                        limits.max_records.min(4096)
                    ),
                    "update-sequence fixups applied; attributes + runs parsed".to_string(),
                ]),
                metadata,
                warnings,
                errors: Vec::new(),
                children,
            }],
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn validate_at(src: &ByteSource, off: u64) -> Result<HandlerOutput> {
        NtfsHandler.validate(
            src,
            Candidate { offset: off },
            &crate::engine::EngineLimits::default(),
            &mut Budget::default(),
        )
    }

    const CLUSTER: u64 = 512;
    const MFT_LCN: u64 = 4; // cluster 4 = byte 2048
    const REC_SIZE: u64 = 1024;

    /// Apply NTFS update-sequence fixups to a record buffer in place:
    /// fixups at fix_off (10 entries, 512-byte stride).
    fn seal_fixups(rec: &mut [u8], fix_off: usize, fix_num: usize) {
        // The USN marker is already at each stride end (we wrote 0x0001).
        let usn = u16::from_le_bytes([rec[fix_off], rec[fix_off + 1]]);
        for i in 1..fix_num {
            let end = i * 512;
            rec[fix_off + i * 2] = rec[end - 2];
            rec[fix_off + i * 2 + 1] = rec[end - 1];
        }
        let _ = usn;
    }

    /// Build a minimal NTFS image with:
    ///   $MFT at cluster 4; records 0..15 system (skipped);
    ///   record 16: FILE, resident $DATA "NTFS_FLAG_DATA" (14 bytes)
    ///   record 17: FILE, non-resident $DATA with runs: LCN 100, 1 cluster
    fn ntfs_image() -> Vec<u8> {
        let total_clusters = 200u64;
        let mut img = vec![0u8; (total_clusters * CLUSTER) as usize];

        // Boot sector.
        img[3..11].copy_from_slice(b"NTFS    ");
        img[0x0B] = 0x00; // bytes_per_sector = 0x0200 (unaligned le16 0x0B)
        img[0x0C] = 0x02;
        img[0x0D] = 1; // sectors per cluster
        img[0x28..0x30].copy_from_slice(&total_clusters.to_le_bytes()); // volume sectors
        img[0x30..0x38].copy_from_slice(&MFT_LCN.to_le_bytes());
        img[0x40] = (REC_SIZE as i64 / CLUSTER as i64) as u8; // record in clusters
        img[0x1FE..0x200].copy_from_slice(&0xAA55u16.to_le_bytes());

        let mft_off = (MFT_LCN * CLUSTER) as usize;

        // Record 16: resident file.
        {
            let r = mft_off + 16 * REC_SIZE as usize;
            let rec = &mut img[r..r + REC_SIZE as usize];
            rec[0..4].copy_from_slice(b"FILE");
            // fix_off = 0x30, fix_num = 3 (1024-byte record: 2 strides + 1).
            rec[4..6].copy_from_slice(&0x30u16.to_le_bytes());
            rec[6..8].copy_from_slice(&3u16.to_le_bytes());
            // USN marker at stride ends: 512 and 1024.
            rec[510..512].copy_from_slice(&1u16.to_le_bytes());
            rec[1022..1024].copy_from_slice(&1u16.to_le_bytes());
            // Header.
            rec[0x10..0x12].copy_from_slice(&1u16.to_le_bytes()); // seq
            rec[0x14..0x16].copy_from_slice(&0x30u16.to_le_bytes()); // attr_off
            rec[0x16..0x18].copy_from_slice(&1u16.to_le_bytes()); // in use
            rec[0x18..0x1C].copy_from_slice(&0x80u32.to_le_bytes()); // used
            rec[0x1C..0x20].copy_from_slice(&(REC_SIZE as u32).to_le_bytes());
            // Attribute: resident $DATA at 0x30.
            let a = 0x30usize;
            rec[a..a + 4].copy_from_slice(&ATTR_DATA.to_le_bytes());
            let data = b"NTFS_FLAG_DATA";
            let attr_size = 0x18 + data.len();
            rec[a + 4..a + 8].copy_from_slice(&(attr_size as u32).to_le_bytes());
            rec[a + 8] = 0; // resident
            rec[a + 9] = 0; // name_len
            rec[a + 0x10..a + 0x14].copy_from_slice(&(data.len() as u32).to_le_bytes());
            rec[a + 0x14..a + 0x16].copy_from_slice(&0x18u16.to_le_bytes()); // data_off
            rec[a + 0x18..a + 0x18 + data.len()].copy_from_slice(data);
            // End marker.
            rec[a + attr_size..a + attr_size + 4].copy_from_slice(&ATTR_END.to_le_bytes());
            // Fixups: copy stride-end markers into the fixup array.
            let fo = 0x30usize;
            let _ = fo;
            // (fixup array would overlap the attribute; use a separate
            // area: move fix_off to 0x1E instead.)
            rec[4..6].copy_from_slice(&0x1Eu16.to_le_bytes());
            rec[0x1E..0x20].copy_from_slice(&1u16.to_le_bytes()); // USN
            rec[0x20..0x22].copy_from_slice(&1u16.to_le_bytes()); // fixup 1
            rec[0x22..0x24].copy_from_slice(&1u16.to_le_bytes()); // fixup 2
        }

        // Record 17: non-resident file, 1 cluster at LCN 100.
        {
            let r = mft_off + 17 * REC_SIZE as usize;
            let rec = &mut img[r..r + REC_SIZE as usize];
            rec[0..4].copy_from_slice(b"FILE");
            rec[4..6].copy_from_slice(&0x1Eu16.to_le_bytes());
            rec[6..8].copy_from_slice(&3u16.to_le_bytes());
            rec[510..512].copy_from_slice(&1u16.to_le_bytes());
            rec[1022..1024].copy_from_slice(&1u16.to_le_bytes());
            rec[0x10..0x12].copy_from_slice(&1u16.to_le_bytes());
            rec[0x14..0x16].copy_from_slice(&0x30u16.to_le_bytes());
            rec[0x16..0x18].copy_from_slice(&1u16.to_le_bytes());
            rec[0x18..0x1C].copy_from_slice(&0xA0u32.to_le_bytes()); // used
            rec[0x1C..0x20].copy_from_slice(&(REC_SIZE as u32).to_le_bytes());
            let a = 0x30usize;
            rec[a..a + 4].copy_from_slice(&ATTR_DATA.to_le_bytes());
            let attr_size = 0x48usize;
            rec[a + 4..a + 8].copy_from_slice(&(attr_size as u32).to_le_bytes());
            rec[a + 8] = 1; // non-resident
            rec[a + 9] = 0;
            rec[a + 0x10..a + 0x18].copy_from_slice(&0u64.to_le_bytes()); // svcn
            rec[a + 0x18..a + 0x20].copy_from_slice(&0u64.to_le_bytes()); // evcn
            rec[a + 0x20..a + 0x22].copy_from_slice(&0x40u16.to_le_bytes()); // run_off
            rec[a + 0x28..a + 0x30].copy_from_slice(&512u64.to_le_bytes()); // alloc
            rec[a + 0x30..a + 0x38].copy_from_slice(&12u64.to_le_bytes()); // data_size
            rec[a + 0x38..a + 0x40].copy_from_slice(&12u64.to_le_bytes()); // valid
                                                                           // Runlist at 0x40: header 0x11 (1 len byte, 1 offset byte):
                                                                           // len 1 cluster, offset +100.
            rec[a + 0x40] = 0x11;
            rec[a + 0x41] = 1;
            rec[a + 0x42] = 100;
            rec[a + 0x43] = 0x00; // end
            rec[a + attr_size..a + attr_size + 4].copy_from_slice(&ATTR_END.to_le_bytes());
            // Fixups at 0x1E.
            rec[0x1E..0x20].copy_from_slice(&1u16.to_le_bytes());
            rec[0x20..0x22].copy_from_slice(&1u16.to_le_bytes());
            rec[0x22..0x24].copy_from_slice(&1u16.to_le_bytes());
            // Data at LCN 100 => byte offset 100*512 = 51200.
            let data_off = 100 * 512usize;
            img[data_off..data_off + 12].copy_from_slice(b"NONRES_DATA!");
        }

        // Record 18: DELETED file (in_use = 0) with resident data —
        // #7 §8: content survives until clusters are reused.
        {
            let r = mft_off + 18 * REC_SIZE as usize;
            let rec = &mut img[r..r + REC_SIZE as usize];
            rec[0..4].copy_from_slice(b"FILE");
            rec[4..6].copy_from_slice(&0x1Eu16.to_le_bytes());
            rec[6..8].copy_from_slice(&3u16.to_le_bytes());
            rec[510..512].copy_from_slice(&1u16.to_le_bytes());
            rec[1022..1024].copy_from_slice(&1u16.to_le_bytes());
            rec[0x10..0x12].copy_from_slice(&1u16.to_le_bytes());
            rec[0x14..0x16].copy_from_slice(&0x30u16.to_le_bytes());
            rec[0x16..0x18].copy_from_slice(&0u16.to_le_bytes()); // NOT in use
            rec[0x18..0x1C].copy_from_slice(&0x80u32.to_le_bytes());
            rec[0x1C..0x20].copy_from_slice(&(REC_SIZE as u32).to_le_bytes());
            let a = 0x30usize;
            rec[a..a + 4].copy_from_slice(&ATTR_DATA.to_le_bytes());
            let data = b"DELETED payload";
            let attr_size = 0x18 + data.len();
            rec[a + 4..a + 8].copy_from_slice(&(attr_size as u32).to_le_bytes());
            rec[a + 8] = 0; // resident
            rec[a + 9] = 0;
            rec[a + 0x10..a + 0x14].copy_from_slice(&(data.len() as u32).to_le_bytes());
            rec[a + 0x14..a + 0x16].copy_from_slice(&0x18u16.to_le_bytes());
            rec[a + 0x18..a + 0x18 + data.len()].copy_from_slice(data);
            rec[a + attr_size..a + attr_size + 4].copy_from_slice(&ATTR_END.to_le_bytes());
            rec[0x1E..0x20].copy_from_slice(&1u16.to_le_bytes());
            rec[0x20..0x22].copy_from_slice(&1u16.to_le_bytes());
            rec[0x22..0x24].copy_from_slice(&1u16.to_le_bytes());
        }

        // Fixup seal for both records (markers already at stride ends).
        for n in [16usize, 17usize, 18usize] {
            let r = mft_off + n * REC_SIZE as usize;
            let rec = &mut img[r..r + REC_SIZE as usize];
            seal_fixups(rec, 0x1E, 3);
        }

        img
    }

    /// FINAL-B2 regression: an 8-byte negative run delta previously
    /// computed `1i64 << 64` (shift overflow). Wide deltas must decode
    /// with correct sign extension.
    #[test]
    fn ntfs_runlist_wide_negative_delta() {
        // Header: size field 1 byte, offset field 8 bytes.
        // len = 1 cluster; delta = -1 as 8-byte LE two's complement.
        let mut runs = vec![0x81u8];
        runs.push(1); // len = 1
        runs.extend_from_slice(&(-1i64).to_le_bytes()); // offset = -1
        let cluster_size = 512;
        let parsed = NtfsHandler::unpack_runs(&runs, cluster_size);
        assert_eq!(parsed.len(), 1, "one run parsed");
        let (lcn, len) = parsed[0];
        // Length is in BYTES; LCN is the raw cluster number.
        assert_eq!(len, cluster_size);
        // prev LCN starts at 0; delta -1 => LCN -1 (wraps as u64::MAX).
        assert_eq!(lcn, Some(u64::MAX));
    }

    /// FINAL-B2: sparse run (offset field 0) plus a following wide run.
    #[test]
    fn ntfs_runlist_sparse_then_normal() {
        let mut runs = vec![0x01u8]; // size only, sparse
        runs.push(2); // len 2 clusters
        runs.push(0x81); // 1-byte len, 8-byte offset
        runs.push(3); // len 3
        runs.extend_from_slice(&5i64.to_le_bytes()); // delta +5
        let parsed = NtfsHandler::unpack_runs(&runs, 512);
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0], (None, 1024), "sparse run");
        // LCN raw (5), length in bytes (3 * 512).
        assert_eq!(parsed[1], (Some(5), 3 * 512), "normal run");
    }

    #[test]
    fn ntfs_resident_and_nonresident_data() {
        let src = ByteSource::from_vec(ntfs_image());
        let out = validate_at(&src, 0).expect("ntfs validates");
        let art = &out.artifacts[0];
        assert_eq!(art.confidence, Confidence::Validated);
        // Resident file at record 16.
        let res = art
            .children
            .iter()
            .find(|c| c.metadata.get("mft_record").map(String::as_str) == Some("16"))
            .expect("record 16 child");
        match &res.content {
            ChildContent::Owned(d) => assert_eq!(*d, b"NTFS_FLAG_DATA".to_vec()),
            _ => panic!("resident data"),
        }
        // Non-resident file at record 17: run reconstruction.
        let non = art
            .children
            .iter()
            .find(|c| c.metadata.get("mft_record").map(String::as_str) == Some("17"))
            .expect("record 17 child");
        match &non.content {
            ChildContent::Owned(d) => assert_eq!(*d, b"NONRES_DATA!".to_vec()),
            _ => panic!("non-resident data"),
        }
    }

    /// #7 §8: a deleted (not-in-use) MFT record still yields its
    /// resident content, flagged deleted=true with an honest warning.
    #[test]
    fn ntfs_deleted_record_content_surfaced() {
        let src = ByteSource::from_vec(ntfs_image());
        let out = validate_at(&src, 0).expect("ntfs validates");
        let art = &out.artifacts[0];
        let del = art
            .children
            .iter()
            .find(|c| c.metadata.get("mft_record").map(String::as_str) == Some("18"))
            .expect("deleted record still surfaced");
        assert_eq!(
            del.metadata.get("deleted").map(String::as_str),
            Some("true"),
            "record must be flagged deleted"
        );
        match &del.content {
            ChildContent::Owned(d) => assert_eq!(*d, b"DELETED payload".to_vec()),
            _ => panic!("resident deleted data expected"),
        }
        // Live records are NOT flagged.
        assert!(art
            .children
            .iter()
            .find(|c| c.metadata.get("mft_record").map(String::as_str) == Some("16"))
            .map(|c| !c.metadata.contains_key("deleted"))
            .unwrap_or(true));
        // FINAL-B7: deleted-record children must claim Recovered, and
        // the evidence must say so — never Validated.
        assert_eq!(
            del.confidence,
            Confidence::Recovered,
            "deleted-record content is recovered bytes, not validated"
        );
        assert!(del
            .evidence
            .iter()
            .any(|e| e.contains("recovered from a deleted MFT record")));
        // The live record keeps Validated.
        assert!(art
            .children
            .iter()
            .find(|c| c.metadata.get("mft_record").map(String::as_str) == Some("16"))
            .map(|c| c.confidence == Confidence::Validated)
            .unwrap_or(false));
    }

    #[test]
    fn ntfs_bad_fixup_rejects_record() {
        let mut img = ntfs_image();
        // Corrupt the USN marker of record 16's second stride.
        let r = (MFT_LCN * CLUSTER) as usize + 16 * REC_SIZE as usize + 1022;
        img[r] ^= 0xFF;
        let src = ByteSource::from_vec(img);
        let out = validate_at(&src, 0).expect("volume still validates");
        // Record 16 now fails to parse: no child for it.
        assert!(out.artifacts[0].children.iter().all(|c| c
            .metadata
            .get("mft_record")
            .map(String::as_str)
            != Some("16")));
    }

    #[test]
    fn ntfs_boot_signature_rejected() {
        let mut img = ntfs_image();
        img[0x1FE] = 0;
        let src = ByteSource::from_vec(img);
        assert!(validate_at(&src, 0).is_err());
    }

    #[test]
    fn ntfs_hostile_record_size_rejected() {
        let mut img = ntfs_image();
        img[0x40] = 0x80; // negative encoding: 1<<(-128) nonsense
        img[0x40] = 0b1000_0000; // i8 negative => 1 << 128 → huge
        let src = ByteSource::from_vec(img);
        assert!(validate_at(&src, 0).is_err());
    }

    #[test]
    fn ntfs_runlist_sparse_decode() {
        // Sparse run: header 0x01 (1 length byte, 0 offset bytes).
        let runs = [0x01u8, 0x04, 0x00];
        let parsed = NtfsHandler::unpack_runs(&runs, 512);
        assert_eq!(parsed, vec![(None, 4 * 512)]);
    }

    #[test]
    fn ntfs_runlist_negative_offset_decode() {
        // Header 0x21: 1 length byte, 2 offset bytes. len 2, delta -3
        // (0xFD 0xFF little-endian, sign-extended 16-bit).
        let runs = [0x21u8, 0x02, 0xFD, 0xFF, 0x00];
        let parsed = NtfsHandler::unpack_runs(&runs, 512);
        assert_eq!(parsed, vec![(Some((-3i64) as u64), 2 * 512)]);
    }
}
