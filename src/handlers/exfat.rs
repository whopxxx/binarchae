//! exFAT read-only traversal (Issue #7 §1.1).
//!
//! Layout verified against Linux `fs/exfat/{exfat_raw.h,exfat_fs.h,
//! super.c,dir.c,misc.c,nls.c}`:
//! - boot sector (512 bytes): jmp(3), fs_name "EXFAT   " (8), zeroed old
//!   BPB (53), partition_offset(8), vol_length(8), fat_offset(4),
//!   fat_length(4), clu_offset(4), clu_count(4), root_cluster(4),
//!   vol_serial(4), fs_revision(2), vol_flags(2), sect_size_bits(1),
//!   sect_per_clus_bits(1), num_fats(1), drv_sel(1), percent_in_use(1),
//!   reserved(7), boot_code(390), signature 0xAA55(2);
//! - boot checksum: rotate-left-31 word sum over sectors 0..10 (sector-0
//!   bytes 106,107,112 skipped), stored as every u32 of sector 11;
//! - cluster N (N >= 2) byte offset = clu_offset*sect_size + (N-2)*clus;
//!   FAT entries u32; EOF 0xFFFFFFFF, bad 0xFFFFFFF7;
//! - directory entries: 32 bytes; type 0x00 unused (end), 0x01..0x7F
//!   deleted, 0x85 file, 0xC0 stream, 0xC1 name;
//! - entry set: File {num_ext, checksum, attr} + Stream {flags, name_len,
//!   name_hash, valid_size, start_clu, size} + num_ext-1 Name entries;
//!   entry-set checksum = rotate-left-15 word sum (skipping the File
//!   entry's checksum bytes 2..3);
//! - stream flags bit1 (NoFatChain) set => contiguous data;
//! - file names: UTF-16LE, 15 chars per Name entry, terminated by 0x0000.

use crate::artifact::{Confidence, Evidence, RelationKind};
use crate::bytesource::ByteSource;
use crate::engine::{
    ArtifactDraft, Budget, Candidate, ChildContent, ChildDraft, Handler, HandlerOutput,
};
use crate::error::{Error, Result};
use crate::handlers::find_all;
use std::collections::BTreeMap;

pub struct ExfatHandler;

const EOF_CLUSTER: u32 = 0xFFFF_FFFF;
const BAD_CLUSTER: u32 = 0xFFFF_FFF7;
/// Stream GeneralSecondaryFlags: bit0 AllocationPossible, bit1 NoFatChain.
const FLAG_NO_FAT_CHAIN: u8 = 0x02;
/// Directory attribute.
const ATTR_SUBDIR: u16 = 0x0010;

fn le32(src: &ByteSource, off: u64) -> Option<u32> {
    let mut b = [0u8; 4];
    src.read_at(off, &mut b).ok()?;
    Some(u32::from_le_bytes(b))
}

/// Kernel `exfat_calc_chksum16` (rotate-left-15 word sum).
fn chksum16(data: &[u8], mut chksum: u16, skip_2_3: bool) -> u16 {
    for (i, &b) in data.iter().enumerate() {
        if skip_2_3 && (i == 2 || i == 3) {
            continue;
        }
        chksum = chksum.rotate_left(15).wrapping_add(u16::from(b));
    }
    chksum
}

/// Parsed exFAT boot-sector geometry (all byte offsets).
#[derive(Debug, Clone)]
struct ExfatBpb {
    sect_size: u64,
    cluster_size: u64,
    fat_offset: u64,
    fat_length: u64,
    clu_offset: u64,
    clu_count: u32,
    root_cluster: u32,
    num_fats: u8,
    vol_length: u64,
}

impl ExfatBpb {
    /// Byte offset of cluster `clu` (clu >= 2).
    fn cluster_offset(&self, clu: u32) -> u64 {
        self.clu_offset * self.sect_size + (u64::from(clu) - 2) * self.cluster_size
    }

    /// FAT entry for `clu` (relative to `base`).
    fn fat_entry(&self, src: &ByteSource, base: u64, clu: u32) -> Option<u32> {
        le32(
            src,
            base + self.fat_offset * self.sect_size + u64::from(clu) * 4,
        )
    }

    /// Follow the FAT chain from `start`, returning cluster numbers.
    /// Bounded by `max_clusters` and cycle-checked by visited-set size.
    fn chain(
        &self,
        src: &ByteSource,
        base: u64,
        start: u32,
        max_clusters: usize,
        warnings: &mut Vec<String>,
    ) -> Result<Vec<u32>> {
        let mut out = Vec::new();
        let mut clu = start;
        loop {
            if clu == EOF_CLUSTER || clu == 0 {
                break;
            }
            if clu == BAD_CLUSTER {
                warnings.push("FAT chain hits a bad cluster".to_string());
                break;
            }
            out.push(clu);
            if out.len() >= max_clusters {
                warnings.push("FAT chain exceeds max_fs_entries; truncated".to_string());
                break;
            }
            let next = self
                .fat_entry(src, base, clu)
                .ok_or_else(|| Error::Validation {
                    format: "exfat",
                    reason: format!("FAT entry for cluster {clu} unreadable"),
                })?;
            clu = next;
        }
        Ok(out)
    }
}

/// One assembled file entry set.
struct EntrySet {
    attr: u16,
    name: String,
    /// Stream flags (bit1 NoFatChain).
    flags: u8,
    start_clu: u32,
    size: u64,
    checksum_ok: bool,
}

impl ExfatHandler {
    fn parse_bpb(src: &ByteSource, base: u64) -> Result<ExfatBpb> {
        if base + 512 > src.len() {
            return Err(Error::Validation {
                format: "exfat",
                reason: "boot sector truncated".into(),
            });
        }
        let mut bs = [0u8; 512];
        src.read_at(base, &mut bs)?;
        if &bs[3..11] != b"EXFAT   " {
            return Err(Error::Validation {
                format: "exfat",
                reason: "fs_name is not EXFAT".into(),
            });
        }
        if bs[11..64].iter().any(|&b| b != 0) {
            return Err(Error::Validation {
                format: "exfat",
                reason: "old-BPB must_be_zero region not zeroed".into(),
            });
        }
        if u16::from_le_bytes([bs[510], bs[511]]) != 0xAA55 {
            return Err(Error::Validation {
                format: "exfat",
                reason: "boot signature != 0xAA55".into(),
            });
        }
        let num_fats = bs[110];
        if num_fats != 1 && num_fats != 2 {
            return Err(Error::Validation {
                format: "exfat",
                reason: format!("bogus num_fats {num_fats}"),
            });
        }
        let sect_bits = bs[108];
        if !(9..=12).contains(&sect_bits) {
            return Err(Error::Validation {
                format: "exfat",
                reason: format!("bogus sector size bits {sect_bits}"),
            });
        }
        let spc_bits = bs[109];
        if spc_bits > 25 - sect_bits {
            return Err(Error::Validation {
                format: "exfat",
                reason: format!("bogus sectors-per-cluster bits {spc_bits}"),
            });
        }
        let sect_size = 1u64 << sect_bits;
        let cluster_size = 1u64 << (sect_bits + spc_bits);
        let rd32 = |o: usize| u32::from_le_bytes([bs[o], bs[o + 1], bs[o + 2], bs[o + 3]]);
        let rd64 = |o: usize| {
            u64::from_le_bytes([
                bs[o],
                bs[o + 1],
                bs[o + 2],
                bs[o + 3],
                bs[o + 4],
                bs[o + 5],
                bs[o + 6],
                bs[o + 7],
            ])
        };
        let bpb = ExfatBpb {
            sect_size,
            cluster_size,
            fat_offset: u64::from(rd32(80)),
            fat_length: u64::from(rd32(84)),
            clu_offset: u64::from(rd32(88)),
            clu_count: rd32(92),
            root_cluster: rd32(96),
            num_fats,
            vol_length: rd64(72),
        };
        // Geometry consistency: data region must sit inside the volume.
        let fat_end = bpb.fat_offset + bpb.fat_length * u64::from(bpb.num_fats);
        if bpb.vol_length == 0
            || fat_end > bpb.clu_offset
            || bpb.clu_offset > bpb.vol_length
            || base + bpb.vol_length > src.len()
        {
            return Err(Error::Validation {
                format: "exfat",
                reason: format!(
                    "inconsistent geometry (fat {}+{}, clu {}, vol {})",
                    bpb.fat_offset, bpb.fat_length, bpb.clu_offset, bpb.vol_length
                ),
            });
        }
        if bpb.clu_count < 1 {
            return Err(Error::Validation {
                format: "exfat",
                reason: "empty cluster heap".into(),
            });
        }
        Ok(bpb)
    }

    /// Optional boot checksum verification (sectors 0..10 vs sector 11).
    /// Downgrades confidence when it fails; never masks structure.
    fn boot_checksum_ok(&self, src: &ByteSource, base: u64, sect_size: u64) -> bool {
        if base + 12 * sect_size > src.len() {
            return false; // checksum sector not present: cannot verify
        }
        let mut chksum: u32 = 0;
        for sn in 0..11u64 {
            let mut sector = vec![0u8; sect_size as usize];
            if src.read_at(base + sn * sect_size, &mut sector).is_err() {
                return false;
            }
            for (i, &b) in sector.iter().enumerate() {
                if sn == 0 && (i == 106 || i == 107 || i == 112) {
                    continue;
                }
                chksum = chksum.rotate_left(1).wrapping_add(u32::from(b));
            }
        }
        let mut stored = vec![0u8; 4];
        if src.read_at(base + 11 * sect_size, &mut stored).is_err() {
            return false;
        }
        chksum == u32::from_le_bytes([stored[0], stored[1], stored[2], stored[3]])
    }

    /// Read `len` bytes of a directory chain into a flat buffer.
    fn dir_bytes(
        bpb: &ExfatBpb,
        src: &ByteSource,
        base: u64,
        start: u32,
        size: u64,
        max_clusters: usize,
        warnings: &mut Vec<String>,
    ) -> Result<Vec<u8>> {
        // Directories with size == 0 use an unbounded FAT chain; with a
        // declared size we can stop once we have enough bytes.
        let chain = if size > 0 {
            let need = size.div_ceil(bpb.cluster_size) as usize;
            bpb.chain(src, base, start, need, warnings)?
        } else {
            bpb.chain(src, base, start, max_clusters, warnings)?
        };
        let mut out = Vec::new();
        for clu in &chain {
            let off = bpb.cluster_offset(*clu);
            if base + off + bpb.cluster_size > src.len() {
                warnings.push(format!("directory cluster {clu} past source; truncated"));
                break;
            }
            let mut block = vec![0u8; bpb.cluster_size as usize];
            src.read_at(base + off, &mut block)?;
            out.extend_from_slice(&block);
            if size > 0 && out.len() as u64 >= size {
                break;
            }
        }
        if size > 0 {
            out.truncate(size as usize);
        }
        Ok(out)
    }

    /// Decode UTF-16LE name entries (15 u16 chars each, 0x0000 ends).
    fn decode_name(units: &[u16]) -> String {
        let chars: Vec<u16> = units.iter().copied().take_while(|&u| u != 0).collect();
        String::from_utf16_lossy(&chars)
    }

    /// Parse one entry set starting at dentry index `idx` within `bytes`.
    /// Returns the entry and the number of dentries consumed.
    fn parse_entry_set(bytes: &[u8], idx: usize) -> Option<(EntrySet, usize)> {
        let at = |i: usize| -> Option<&[u8]> { bytes.get(i * 32..i * 32 + 32) };
        let file = at(idx)?;
        if file[0] != 0x85 {
            return None;
        }
        let num_ext = file[1] as usize;
        let stored_ck = u16::from_le_bytes([file[2], file[3]]);
        let attr = u16::from_le_bytes([file[4], file[5]]);
        if num_ext < 2 || idx + 1 + num_ext > bytes.len() / 32 {
            return None;
        }
        let stream = at(idx + 1)?;
        if stream[0] != 0xC0 {
            return None;
        }
        let flags = stream[1];
        let name_len = stream[2] as usize;
        let start_clu = u32::from_le_bytes([stream[20], stream[21], stream[22], stream[23]]);
        let size = u64::from_le_bytes([
            stream[24], stream[25], stream[26], stream[27], stream[28], stream[29], stream[30],
            stream[31],
        ]);
        // Name entries: num_ext - 1 of them.
        let mut units = Vec::with_capacity(name_len * 2);
        for k in 0..num_ext - 1 {
            let ne = at(idx + 2 + k)?;
            if ne[0] != 0xC1 {
                return None;
            }
            for c in 0..15 {
                let off = 2 + c * 2;
                units.push(u16::from_le_bytes([ne[off], ne[off + 1]]));
            }
        }
        // Entry-set checksum: rotate-15 sum over all set dentries with
        // the File entry's checksum bytes 2..3 skipped (kernel
        // exfat_calc_chksum16 with CS_DIR_ENTRY on the File entry).
        let mut chksum: u16 = 0;
        for k in 0..=num_ext {
            let d = at(idx + k)?;
            chksum = chksum16(d, chksum, k == 0);
        }
        let checksum_ok = chksum == stored_ck;
        let name = Self::decode_name(&units);
        Some((
            EntrySet {
                attr,
                name,
                flags,
                start_clu,
                size,
                checksum_ok,
            },
            num_ext + 1,
        ))
    }

    /// Walk a directory's entry set buffer, emitting children.
    #[allow(clippy::too_many_arguments)]
    fn walk_entries(
        bpb: &ExfatBpb,
        src: &ByteSource,
        base: u64,
        bytes: &[u8],
        path: &str,
        depth: u32,
        limits: &crate::engine::EngineLimits,
        budget: &mut Budget,
        warnings: &mut Vec<String>,
        out: &mut Vec<ChildDraft>,
    ) -> Result<()> {
        if depth > 16 {
            warnings.push("directory nesting deeper than 16 not walked".to_string());
            return Ok(());
        }
        let mut idx = 0usize;
        while (idx + 1) * 32 <= bytes.len() {
            if out.len() >= limits.max_fs_entries {
                warnings.push("max_fs_entries reached; directory walk truncated".to_string());
                return Ok(());
            }
            let t = bytes[idx * 32];
            if t == 0x85 {
                let (entry, used) = match Self::parse_entry_set(bytes, idx) {
                    Some(v) => v,
                    None => {
                        // Malformed set: skip just this File dentry so one
                        // bad set cannot poison the rest of the walk.
                        warnings.push(format!("malformed file entry set at dentry {idx}; skipped"));
                        idx += 1;
                        continue;
                    }
                };
                if !entry.checksum_ok {
                    warnings.push(format!(
                        "entry-set checksum mismatch at dentry {idx} ({})",
                        entry.name
                    ));
                }
                let child_path = if path.is_empty() {
                    entry.name.clone()
                } else {
                    format!("{path}/{}", entry.name)
                };
                let is_dir = entry.attr & ATTR_SUBDIR != 0;
                let mut meta = BTreeMap::new();
                meta.insert("path".to_string(), child_path.clone());
                meta.insert("attr".to_string(), format!("{:#06x}", entry.attr));
                meta.insert(
                    "checksum".to_string(),
                    if entry.checksum_ok { "ok" } else { "invalid" }.to_string(),
                );
                if is_dir {
                    meta.insert("type".to_string(), "directory".to_string());
                    out.push(ChildDraft {
                        relation: RelationKind::FilesystemEntry,
                        label: format!("exFAT directory {child_path}"),
                        format_hint: "metadata",
                        content: ChildContent::Owned(Vec::new()),
                        size: 0,
                        metadata: meta,
                        warnings: Vec::new(),
                        entry_name: Some(entry.name.clone()),
                    });
                    // Recurse: directory content = its cluster chain.
                    let dir_data = Self::dir_bytes(
                        bpb,
                        src,
                        base,
                        entry.start_clu,
                        entry.size,
                        limits.max_fs_entries,
                        warnings,
                    )?;
                    if !dir_data.is_empty() {
                        Self::walk_entries(
                            bpb,
                            src,
                            base,
                            &dir_data,
                            &child_path,
                            depth + 1,
                            limits,
                            budget,
                            warnings,
                            out,
                        )?;
                    }
                } else {
                    meta.insert("type".to_string(), "file".to_string());
                    meta.insert("declared_size".to_string(), entry.size.to_string());
                    meta.insert("first_cluster".to_string(), entry.start_clu.to_string());
                    let contiguous = entry.flags & FLAG_NO_FAT_CHAIN != 0;
                    meta.insert(
                        "allocation".to_string(),
                        if contiguous {
                            "contiguous"
                        } else {
                            "fat-chain"
                        }
                        .to_string(),
                    );
                    Self::emit_file(
                        bpb,
                        src,
                        base,
                        &entry,
                        &child_path,
                        contiguous,
                        meta,
                        warnings,
                        out,
                        limits,
                        budget,
                    )?;
                }
                idx += used;
                continue;
            }
            // 0x81 bitmap / 0x82 upcase / 0x83 volume label / deleted /
            // invalid / vendor: skip this dentry (their content is never
            // materialized).
            idx += 1;
        }
        Ok(())
    }

    /// Emit a regular file. Contiguous => source-backed region; FAT
    /// chain => reconstructed owned bytes (budget-charged).
    #[allow(clippy::too_many_arguments)]
    fn emit_file(
        bpb: &ExfatBpb,
        src: &ByteSource,
        base: u64,
        entry: &EntrySet,
        child_path: &str,
        contiguous: bool,
        mut meta: BTreeMap<String, String>,
        warnings: &mut Vec<String>,
        out: &mut Vec<ChildDraft>,
        limits: &crate::engine::EngineLimits,
        budget: &mut Budget,
    ) -> Result<()> {
        let name = entry.name.clone();
        if entry.size == 0 {
            out.push(ChildDraft {
                relation: RelationKind::FilesystemEntry,
                label: format!("exFAT file {child_path} (0 bytes)"),
                format_hint: "raw",
                content: ChildContent::Owned(Vec::new()),
                size: 0,
                metadata: meta,
                warnings: Vec::new(),
                entry_name: Some(name),
            });
            return Ok(());
        }
        if entry.size > limits.max_child_size {
            warnings.push(format!(
                "file {child_path}: {} bytes exceed max_child_size; data not exposed",
                entry.size
            ));
            out.push(ChildDraft {
                relation: RelationKind::FilesystemEntry,
                label: format!("exFAT file {child_path} (metadata only)"),
                format_hint: "metadata",
                content: ChildContent::Owned(Vec::new()),
                size: 0,
                metadata: meta,
                warnings: Vec::new(),
                entry_name: Some(name),
            });
            return Ok(());
        }
        if contiguous {
            // NoFatChain: data is physically sequential from start_clu.
            let start = base + bpb.cluster_offset(entry.start_clu);
            if start + entry.size <= src.len() {
                let region = match src.slice(start, entry.size) {
                    Ok(r) => r,
                    Err(_) => {
                        warnings.push(format!("exFAT file {child_path}: data extent unreadable"));
                        return Ok(());
                    }
                };
                out.push(ChildDraft {
                    relation: RelationKind::FilesystemEntry,
                    label: format!("exFAT file {child_path} ({} bytes)", entry.size),
                    format_hint: "raw",
                    content: ChildContent::Source(region),
                    size: entry.size,
                    metadata: meta,
                    warnings: Vec::new(),
                    entry_name: Some(name),
                });
                return Ok(());
            }
            warnings.push(format!(
                "file {child_path}: contiguous extent past source; reconstructing"
            ));
        }
        // FAT-chain reconstruction (bounded by max_fs_entries clusters).
        let max_clusters = limits.max_fs_entries;
        let chain = match bpb.chain(src, base, entry.start_clu, max_clusters, warnings) {
            Ok(c) => c,
            Err(_) => {
                warnings.push(format!("file {child_path}: FAT chain unreadable"));
                return Ok(());
            }
        };
        let mut data = Vec::with_capacity(entry.size as usize);
        for clu in &chain {
            let off = bpb.cluster_offset(*clu);
            if base + off + bpb.cluster_size > src.len() {
                warnings.push(format!(
                    "file {child_path}: cluster {clu} past source; truncated"
                ));
                break;
            }
            let remaining = entry.size - data.len() as u64;
            let take = remaining.min(bpb.cluster_size) as usize;
            let mut block = vec![0u8; take];
            src.read_at(base + off, &mut block)?;
            data.extend_from_slice(&block);
            if data.len() as u64 >= entry.size {
                break;
            }
        }
        if !budget.charge(limits, data.len() as u64) {
            warnings.push("run-wide byte budget exhausted during reconstruction".to_string());
            return Ok(());
        }
        meta.insert("reconstructed".to_string(), "true".to_string());
        out.push(ChildDraft {
            relation: RelationKind::ReconstructedFrom,
            label: format!(
                "exFAT file {child_path} ({} bytes, reconstructed)",
                data.len()
            ),
            format_hint: "raw",
            content: ChildContent::Owned(data),
            size: entry.size,
            metadata: meta,
            warnings: vec![
                "cluster chain non-contiguous: content reconstructed from the FAT".to_string(),
            ],
            entry_name: Some(name),
        });
        Ok(())
    }
}

impl Handler for ExfatHandler {
    fn format(&self) -> &'static str {
        "exfat"
    }

    fn find_candidates(&self, src: &ByteSource) -> Vec<Candidate> {
        find_all(src, b"EXFAT   ")
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
        let bpb = Self::parse_bpb(src, base)?;
        let boot_ok = self.boot_checksum_ok(src, base, bpb.sect_size);

        // Root directory: walk its entry set.
        let root_data = Self::dir_bytes(
            &bpb,
            src,
            base,
            bpb.root_cluster,
            0,
            limits.max_fs_entries,
            &mut Vec::new(),
        )?;
        let mut children = Vec::new();
        let mut warnings = Vec::new();
        Self::walk_entries(
            &bpb,
            src,
            base,
            &root_data,
            "",
            0,
            limits,
            budget,
            &mut warnings,
            &mut children,
        )?;

        let mut metadata = BTreeMap::new();
        metadata.insert("sector_size".to_string(), bpb.sect_size.to_string());
        metadata.insert("cluster_size".to_string(), bpb.cluster_size.to_string());
        metadata.insert("clusters".to_string(), bpb.clu_count.to_string());
        metadata.insert("num_fats".to_string(), bpb.num_fats.to_string());
        metadata.insert("entries".to_string(), children.len().to_string());
        if !boot_ok {
            metadata.insert("boot_checksum".to_string(), "invalid".to_string());
        }

        let confidence = if boot_ok {
            Confidence::Validated
        } else {
            // Structure validated; boot checksum (or its presence) failed.
            Confidence::Partial
        };
        let mut evidence = vec![
            "exFAT boot sector validated (fs_name, signature 0xAA55, geometry)".to_string(),
            format!(
                "cluster heap at {} ({} clusters of {} B)",
                bpb.clu_offset, bpb.clu_count, bpb.cluster_size
            ),
            format!(
                "root directory at cluster {}; {} entries walked",
                bpb.root_cluster,
                children.len()
            ),
        ];
        if !boot_ok {
            evidence.push("boot checksum unverified/mismatched".to_string());
        }

        Ok(HandlerOutput {
            artifacts: vec![ArtifactDraft {
                format: "exfat".to_string(),
                label: format!("exFAT filesystem ({} entries)", children.len()),
                offset: base,
                size: bpb.vol_length,
                confidence,
                evidence: Evidence::facts(evidence),
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
        ExfatHandler.validate(
            src,
            Candidate { offset: off },
            &crate::engine::EngineLimits::default(),
            &mut Budget::default(),
        )
    }

    const SECT: u64 = 512;

    /// Kernel boot checksum: rotate-left-31 over sectors 0..10 with
    /// sector-0 bytes 106/107/112 skipped; stored in every u32 of
    /// sector 11.
    fn seal_boot_checksum(img: &mut [u8], base: usize) {
        let mut chksum: u32 = 0;
        for sn in 0..11u64 {
            let s = base + (sn * SECT) as usize;
            for i in 0..SECT as usize {
                if sn == 0 && (i == 106 || i == 107 || i == 112) {
                    continue;
                }
                chksum = chksum.rotate_left(1).wrapping_add(u32::from(img[s + i]));
            }
        }
        let cs = base + (11 * SECT) as usize;
        for i in 0..(SECT as usize / 4) {
            img[cs + i * 4..cs + i * 4 + 4].copy_from_slice(&chksum.to_le_bytes());
        }
    }

    /// Build a minimal exFAT image:
    ///   boot sectors 0..11 (+checksum sector 11)
    ///   FAT sectors 12..13 (256 entries)
    ///   cluster heap from sector 24 (clu_offset = 24); cluster 2 = root.
    /// Root: FLAG.TXT (contiguous, 11 bytes @cluster 4)
    ///       SUB (dir, cluster 5) -> inner.txt "INNER_OK" (chain-allocated)
    fn exfat_image() -> Vec<u8> {
        let fat_offset_sect: u64 = 12;
        let clu_offset_sect: u64 = 24;
        let total_clusters: u32 = 32;
        // Volume: 12 boot sectors + 2 FAT + 32 clusters = 46 sectors.
        let total_sectors = clu_offset_sect + u64::from(total_clusters);
        let mut img = vec![0u8; (total_sectors * SECT) as usize];
        let base = 0usize;

        // Boot sector.
        img[base..base + 3].copy_from_slice(&[0xEB, 0x76, 0x90]);
        img[base + 3..base + 11].copy_from_slice(b"EXFAT   ");
        img[base + 72..base + 80].copy_from_slice(&total_sectors.to_le_bytes()); // vol_length
        img[base + 80..base + 84].copy_from_slice(&(fat_offset_sect as u32).to_le_bytes());
        img[base + 84..base + 88].copy_from_slice(&2u32.to_le_bytes()); // fat_length
        img[base + 88..base + 92].copy_from_slice(&(clu_offset_sect as u32).to_le_bytes());
        img[base + 92..base + 96].copy_from_slice(&total_clusters.to_le_bytes());
        img[base + 96..base + 100].copy_from_slice(&2u32.to_le_bytes()); // root cluster
        img[base + 108] = 9; // sect_size_bits = 512
        img[base + 109] = 0; // sect_per_clus_bits
        img[base + 110] = 1; // num_fats
        img[base + 510..base + 512].copy_from_slice(&0xAA55u16.to_le_bytes());
        seal_boot_checksum(&mut img, base);

        fn clu_off(clu: u32) -> usize {
            ((24u64 + u64::from(clu) - 2) * SECT) as usize
        }

        // FAT: root chain (cluster 2) -> EOF; cluster 4 (flag data) -> EOF.
        let fat = fat_offset_sect as usize * SECT as usize;
        macro_rules! fat_set {
            ($clu:expr, $v:expr) => {{
                let clu: u32 = $clu;
                let val: u32 = $v;
                img[fat + clu as usize * 4..fat + clu as usize * 4 + 4]
                    .copy_from_slice(&val.to_le_bytes());
            }};
        }
        fat_set!(2, EOF_CLUSTER);
        fat_set!(4, EOF_CLUSTER);

        // Root directory (cluster 2): entry set for FLAG.TXT then SUB.
        let root = clu_off(2);
        // File entry @0: FLAG.TXT, attr 0x20, num_ext 2, checksum computed.
        img[root] = 0x85;
        img[root + 1] = 2; // num_ext
        img[root + 4..root + 6].copy_from_slice(&0x20u16.to_le_bytes());
        // Stream entry @1: contiguous (flags 0x03? NoFatChain bit1=0x02 |
        // AllocationPossible 0x01 => 0x03), name_len 8, cluster 4, size 11.
        img[root + 32] = 0xC0;
        img[root + 33] = 0x03; // alloc possible + no FAT chain (contiguous)
        img[root + 34] = 8; // name_len
        img[root + 52..root + 56].copy_from_slice(&4u32.to_le_bytes()); // start_clu
        img[root + 56..root + 64].copy_from_slice(&11u64.to_le_bytes()); // size
                                                                         // Name entry @2: "FLAG.TXT" UTF-16LE + NUL.
        img[root + 64] = 0xC1;
        let flag_name: Vec<u8> = "FLAG.TXT"
            .encode_utf16()
            .chain(std::iter::once(0))
            .flat_map(|u| u.to_le_bytes())
            .collect();
        img[root + 66..root + 66 + flag_name.len()].copy_from_slice(&flag_name);

        // Entry set for SUB (dir): dentries 3..5.
        img[root + 96] = 0x85;
        img[root + 97] = 2;
        img[root + 100..root + 102].copy_from_slice(&0x10u16.to_le_bytes()); // subdir
        img[root + 128] = 0xC0;
        img[root + 129] = 0x03;
        img[root + 130] = 3; // "SUB"
        img[root + 148..root + 152].copy_from_slice(&5u32.to_le_bytes()); // cluster 5
        img[root + 152..root + 160].copy_from_slice(&512u64.to_le_bytes()); // dir size 1 cluster
        img[root + 160] = 0xC1;
        let sub_name: Vec<u8> = "SUB"
            .encode_utf16()
            .chain(std::iter::once(0))
            .flat_map(|u| u.to_le_bytes())
            .collect();
        img[root + 162..root + 162 + sub_name.len()].copy_from_slice(&sub_name);

        // Entry-set checksums (File dentry checksum bytes 2..3 skipped).
        fn seal(img: &mut [u8], root: usize, idx: usize) {
            let mut chksum: u16 = 0;
            for k in 0..3usize {
                let d = &img[root + (idx + k) * 32..root + (idx + k) * 32 + 32];
                for (i, &b) in d.iter().enumerate() {
                    if k == 0 && (i == 2 || i == 3) {
                        continue;
                    }
                    chksum = chksum.rotate_left(15).wrapping_add(u16::from(b));
                }
            }
            img[root + idx * 32 + 2..root + idx * 32 + 4].copy_from_slice(&chksum.to_le_bytes());
        }
        seal(&mut img, root, 0);
        seal(&mut img, root, 3);
        // End-of-directory marker: 0x00 at dentry 6 (already zero).

        // FLAG.TXT data (cluster 4, contiguous).
        let flag_data = clu_off(4);
        // 11 bytes declared; 10-char string + one 0x00 pad byte.
        img[flag_data..flag_data + 10].copy_from_slice(b"HELLOexFAT");

        // SUB directory (cluster 5): inner.txt, FAT-chained (flags 0x01).
        let sub = clu_off(5);
        img[sub] = 0x85;
        img[sub + 1] = 2;
        img[sub + 4..sub + 6].copy_from_slice(&0x20u16.to_le_bytes());
        img[sub + 32] = 0xC0;
        img[sub + 33] = 0x01; // allocation possible, FAT CHAIN (bit1 clear)
        img[sub + 34] = 9; // "INNER.TXT"
        img[sub + 52..sub + 56].copy_from_slice(&6u32.to_le_bytes()); // first cluster 6
        img[sub + 56..sub + 64].copy_from_slice(&520u64.to_le_bytes());
        img[sub + 64] = 0xC1;
        let inner_name: Vec<u8> = "INNER.TXT"
            .encode_utf16()
            .chain(std::iter::once(0))
            .flat_map(|u| u.to_le_bytes())
            .collect();
        img[sub + 66..sub + 66 + inner_name.len()].copy_from_slice(&inner_name);
        // inner.txt entry-set checksum.
        let mut chksum: u16 = 0;
        for k in 0..3 {
            let d = &img[sub + k * 32..sub + k * 32 + 32];
            for (i, &b) in d.iter().enumerate() {
                if k == 0 && (i == 2 || i == 3) {
                    continue;
                }
                chksum = chksum.rotate_left(15).wrapping_add(u16::from(b));
            }
        }
        img[sub + 2..sub + 4].copy_from_slice(&chksum.to_le_bytes());

        // INNER.TXT data: FAT chain cluster 6 -> 7 -> EOF (fragmented).
        // File bytes are contiguous across the chain: cluster 6 holds
        // bytes 0..511 ("A" x512), cluster 7 bytes 512..519 ("B" x8).
        fat_set!(6, 7);
        fat_set!(7, EOF_CLUSTER);
        let c6 = clu_off(6);
        let c7 = clu_off(7);
        for b in img[c6..c6 + 512].iter_mut() {
            *b = b'A';
        }
        for b in img[c7..c7 + 8].iter_mut() {
            *b = b'B';
        }

        img
    }

    #[test]
    fn exfat_full_traversal() {
        let src = ByteSource::from_vec(exfat_image());
        let out = validate_at(&src, 0).expect("exfat validates");
        let art = &out.artifacts[0];
        eprintln!("XWARN {:?}", art.warnings);
        for c in &art.children {
            eprintln!("XCHILD {:?} path={:?}", c.label, c.metadata.get("path"));
        }
        eprintln!("XIDX dump done");
        {
            // raw root-dir slice via region handle is not accessible here;
            // instead re-validate and dump from walk: use bytes indirectly.
        }
        let raw = art.children.first().map(|_| ());
        let _ = raw;
        // dump root dir dentries 3..6
        {
            let rd = art; // placeholder
            let _ = rd;
        }
        assert_eq!(art.confidence, Confidence::Validated);
        assert_eq!(
            art.metadata.get("entries").map(String::as_str),
            Some("3") // FLAG.TXT + SUB + SUB/INNER.TXT
        );
        // Contiguous file is source-backed.
        let flag = art
            .children
            .iter()
            .find(|c| c.metadata.get("path").map(String::as_str) == Some("FLAG.TXT"))
            .expect("flag child");
        match &flag.content {
            ChildContent::Source(r) => assert_eq!(
                r.read_all().unwrap(),
                vec![72, 69, 76, 76, 79, 101, 120, 70, 65, 84, 0]
            ),
            _ => panic!("contiguous file must be source-backed"),
        }
        // Fragmented inner file reconstructed through the FAT chain.
        let inner = art
            .children
            .iter()
            .find(|c| c.metadata.get("path").map(String::as_str) == Some("SUB/INNER.TXT"))
            .expect("inner child");
        assert_eq!(inner.size, 520);
        match &inner.content {
            ChildContent::Owned(d) => {
                assert_eq!(d.len(), 520);
                assert!(d.iter().take(512).all(|&b| b == b'A'));
                assert!(d.iter().skip(512).all(|&b| b == b'B'));
            }
            _ => panic!("chain file must reconstruct"),
        }
        assert!(inner.warnings.iter().any(|w| w.contains("FAT")));
    }

    #[test]
    fn exfat_boot_checksum_mismatch_downgrades() {
        let mut img = exfat_image();
        // Corrupt one checksum word in sector 11.
        let cs = (11 * SECT) as usize;
        img[cs] ^= 0xFF;
        let src = ByteSource::from_vec(img);
        let out = validate_at(&src, 0).expect("still validates");
        assert_eq!(out.artifacts[0].confidence, Confidence::Partial);
        assert_eq!(
            out.artifacts[0]
                .metadata
                .get("boot_checksum")
                .map(String::as_str),
            Some("invalid")
        );
    }

    #[test]
    fn exfat_bad_signature_rejected() {
        let mut img = exfat_image();
        img[510] = 0x00;
        let src = ByteSource::from_vec(img);
        assert!(validate_at(&src, 0).is_err());
    }

    #[test]
    fn exfat_nonzero_old_bpb_rejected() {
        let mut img = exfat_image();
        img[20] = 0x01; // must_be_zero region
        let src = ByteSource::from_vec(img);
        assert!(validate_at(&src, 0).is_err());
    }

    #[test]
    fn exfat_hostile_geometry_rejected() {
        let mut img = exfat_image();
        // vol_length beyond the actual source.
        let vlen = 1u64 << 30;
        img[72..80].copy_from_slice(&vlen.to_le_bytes());
        let src = ByteSource::from_vec(img);
        assert!(validate_at(&src, 0).is_err());
    }
}
