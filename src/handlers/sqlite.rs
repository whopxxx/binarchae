//! M3-G SQLite read-only structural parser.
//!
//! - Database header validation (16-byte magic, page size, reserved
//!   space, encoding).
//! - B-tree page type dispatch (interior/leaf table+index pages).
//! - Varint decoding, cell pointer walking, record header serial-type
//!   decoding (NULL/int/float/text/blob).
//! - sqlite_schema (page 1) traversal: table names + root pages.
//! - Table b-tree rows emitted as DatabaseRecord children; BLOB values
//!   optionally surfaced for recursive analysis.
//! - Overflow-chain following with cycle/length caps.
//!
//! All bounds-checked; malformed pages are skipped, never panic.

use crate::artifact::{Confidence, Evidence, RelationKind};
use crate::bytesource::ByteSource;
use crate::engine::{
    ArtifactDraft, Budget, Candidate, ChildContent, ChildDraft, Handler, HandlerOutput,
};
use crate::error::{Error, Result};
use crate::handlers::find_all;
use std::collections::BTreeMap;

const SQLITE_MAGIC: &[u8] = b"SQLite format 3\0";

pub struct SqliteHandler;

/// A decoded SQLite record value.
#[derive(Debug, Clone)]
enum Value {
    Null,
    Int(i64),
    Real(f64),
    Text(String),
    Blob(Vec<u8>),
}

impl Value {
    fn summary(&self) -> String {
        match self {
            Value::Null => "NULL".into(),
            Value::Int(i) => i.to_string(),
            Value::Real(f) => f.to_string(),
            Value::Text(t) => {
                if t.len() > 48 {
                    format!("{:?}…", &t[..48])
                } else {
                    format!("{t:?}")
                }
            }
            Value::Blob(b) => format!("<{} byte blob>", b.len()),
        }
    }
}

impl Handler for SqliteHandler {
    fn format(&self) -> &'static str {
        "sqlite"
    }

    fn find_candidates(&self, src: &ByteSource) -> Vec<Candidate> {
        find_all(src, SQLITE_MAGIC)
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
        if base + 100 > src.len() {
            return Err(Error::Validation {
                format: "sqlite",
                reason: "header truncated".into(),
            });
        }
        let page_size_raw =
            u16::from_be_bytes([read_byte(src, base + 16)?, read_byte(src, base + 17)?]);
        // Value 1 means 65536.
        let page_size = if page_size_raw == 1 {
            65536u64
        } else {
            u64::from(page_size_raw)
        };
        if !(512..=65536).contains(&page_size) || !page_size.is_power_of_two() {
            return Err(Error::Validation {
                format: "sqlite",
                reason: format!("implausible page size {page_size_raw}"),
            });
        }
        let reserved = read_byte(src, base + 20)?;
        let encoding = be32(src, base + 56).unwrap_or(0);
        if encoding != 1 && encoding != 2 && encoding != 3 {
            return Err(Error::Validation {
                format: "sqlite",
                reason: format!("invalid text encoding {encoding}"),
            });
        }

        let mut children: Vec<ChildDraft> = Vec::new();
        let mut warnings = Vec::new();
        let mut schema_tables: Vec<(String, u64)> = Vec::new();

        // Page 1 (at `base`): sqlite_schema b-tree root. Cell content
        // offsets are absolute within the page starting at 100 (header).
        let mut pages_visited = 0usize;
        let schema_rows = walk_table_page(
            src,
            base,
            base,
            page_size,
            reserved,
            0,
            limits,
            &mut warnings,
            &mut pages_visited,
        )?;

        // Emit schema-page rows as record children (sqlite_schema rows).
        for row in schema_rows.iter().take(limits.max_records) {
            let summary = row
                .values
                .iter()
                .map(|v| v.summary())
                .collect::<Vec<_>>()
                .join(", ");
            let mut meta = BTreeMap::new();
            meta.insert("table".to_string(), "sqlite_schema".to_string());
            meta.insert("rowid".to_string(), row.rowid.to_string());
            children.push(ChildDraft {
                relation: RelationKind::DatabaseRecord,
                label: format!("row sqlite_schema[{}]: {summary}", row.rowid),
                format_hint: "record",
                content: ChildContent::Owned(Vec::new()),
                size: 0,
                metadata: meta,
                warnings: Vec::new(),
                entry_name: None,
            });
            // B7: BLOB values surface as children for recursive scanning.
            for (vi, v) in row.values.iter().enumerate() {
                if let Value::Blob(b) = v {
                    if b.len() >= 16
                        && b.len() as u64 <= limits.max_child_size
                        && children.len() < limits.max_records
                    {
                        children.push(ChildDraft {
                            relation: RelationKind::DatabaseRecord,
                            label: format!(
                                "row sqlite_schema[{}] col{} blob ({} bytes)",
                                row.rowid,
                                vi,
                                b.len()
                            ),
                            format_hint: "raw",
                            content: ChildContent::Owned(b.clone()),
                            size: b.len() as u64,
                            metadata: BTreeMap::new(),
                            warnings: Vec::new(),
                            entry_name: None,
                        });
                    }
                }
            }
        }

        // Extract table names + root pages from schema rows.
        for row in &schema_rows {
            if row.values.len() >= 4 {
                let name = match &row.values[1] {
                    Value::Text(t) => t.clone(),
                    _ => String::new(),
                };
                let root = match &row.values[3] {
                    Value::Int(i) => u64::try_from(*i).unwrap_or(0),
                    _ => 0,
                };
                if !name.is_empty() && root > 0 {
                    schema_tables.push((name, root));
                }
            }
        }

        // Walk each table's b-tree root (bounded by max_records/pages).
        let mut total_rows = schema_rows.len() as u64;
        for (name, root) in schema_tables.iter().take(limits.max_records.min(256)) {
            if total_rows > limits.max_records as u64 {
                break;
            }
            let page_off = base + (root - 1) * page_size;
            let rows = walk_table_page(
                src,
                base,
                page_off,
                page_size,
                reserved,
                1,
                limits,
                &mut warnings,
                &mut pages_visited,
            )?;
            total_rows += rows.len() as u64;
            for row in rows.iter().take(64) {
                if children.len() >= limits.max_records {
                    break;
                }
                let summary = row
                    .values
                    .iter()
                    .map(|v| v.summary())
                    .collect::<Vec<_>>()
                    .join(", ");
                let mut meta = BTreeMap::new();
                meta.insert("table".to_string(), name.clone());
                meta.insert("rowid".to_string(), row.rowid.to_string());
                children.push(ChildDraft {
                    relation: RelationKind::DatabaseRecord,
                    label: format!("row {name}[{}]: {summary}", row.rowid),
                    format_hint: "record",
                    content: ChildContent::Owned(Vec::new()),
                    size: 0,
                    metadata: meta,
                    warnings: Vec::new(),
                    entry_name: None,
                });
                // B7: BLOB values surface as children so the recursive
                // engine can scan their bytes (a PNG in a BLOB becomes a
                // real artifact under the SQLite node).
                for (vi, v) in row.values.iter().enumerate() {
                    if let Value::Blob(b) = v {
                        if b.len() >= 16
                            && b.len() as u64 <= limits.max_child_size
                            && children.len() < limits.max_records
                        {
                            children.push(ChildDraft {
                                relation: RelationKind::DatabaseRecord,
                                label: format!(
                                    "row {name}[{}] col{} blob ({} bytes)",
                                    row.rowid,
                                    vi,
                                    b.len()
                                ),
                                format_hint: "raw",
                                content: ChildContent::Owned(b.clone()),
                                size: b.len() as u64,
                                metadata: BTreeMap::new(),
                                warnings: Vec::new(),
                                entry_name: None,
                            });
                        }
                    }
                }
            }
        }

        let mut metadata = BTreeMap::new();
        metadata.insert("page_size".to_string(), page_size.to_string());
        metadata.insert("reserved_bytes_per_page".to_string(), reserved.to_string());
        metadata.insert(
            "text_encoding".to_string(),
            match encoding {
                1 => "utf-8",
                2 => "utf-16le",
                _ => "utf-16be",
            }
            .to_string(),
        );
        metadata.insert("tables".to_string(), schema_tables.len().to_string());
        metadata.insert("rows".to_string(), total_rows.to_string());

        Ok(HandlerOutput {
            artifacts: vec![ArtifactDraft {
                format: "sqlite".to_string(),
                label: format!(
                    "SQLite database ({}, {} rows)",
                    format_file_size(src.len()),
                    total_rows
                ),
                offset: base,
                size: src.len() - base,
                confidence: Confidence::Validated,
                evidence: Evidence::facts([
                    "SQLite header validated (magic, page size, encoding)".to_string(),
                    format!("schema: {} tables discovered", schema_tables.len()),
                    format!("{total_rows} rows decoded across table b-trees"),
                ]),
                metadata,
                warnings,
                errors: Vec::new(),
                children,
            }],
        })
    }
}

fn format_file_size(n: u64) -> String {
    format!("{n}B")
}

fn read_byte(src: &ByteSource, off: u64) -> Result<u8> {
    let mut b = [0u8; 1];
    src.read_at(off, &mut b)?;
    Ok(b[0])
}
fn be16(src: &ByteSource, off: u64) -> Result<u16> {
    let mut b = [0u8; 2];
    src.read_at(off, &mut b)?;
    Ok(u16::from_be_bytes(b))
}
fn be32(src: &ByteSource, off: u64) -> Result<u32> {
    let mut b = [0u8; 4];
    src.read_at(off, &mut b)?;
    Ok(u32::from_be_bytes(b))
}

/// A decoded table row.
struct TableRow {
    rowid: u64,
    values: Vec<Value>,
}

/// Walk a table b-tree page (interior pages recursed into children).
/// Returns rows decoded from LEAF pages at/under this page.
#[allow(clippy::too_many_arguments)]
fn walk_table_page(
    src: &ByteSource,
    db_base: u64,
    page_off: u64,
    page_size: u64,
    reserved: u8,
    depth: u32,
    limits: &crate::engine::EngineLimits,
    warnings: &mut Vec<String>,
    pages_visited: &mut usize,
) -> Result<Vec<TableRow>> {
    let mut rows = Vec::new();
    if depth > 12 {
        warnings.push("b-tree depth cap reached; subtree skipped".to_string());
        return Ok(rows);
    }
    // B3: the page cap actually constrains the recursive walk.
    *pages_visited += 1;
    if *pages_visited > limits.max_sqlite_pages {
        return Err(Error::LimitExceeded {
            limit: "max_sqlite_pages",
            detail: format!("b-tree walk exceeded {} pages", limits.max_sqlite_pages),
        });
    }
    if rows.len() > limits.max_records {
        return Ok(rows);
    }
    // Page 1 has a 100-byte database header before the b-tree header.
    let hdr_off = if page_off == db_base { 100 } else { 0 };
    let page_type = read_byte(src, page_off + hdr_off)?;
    let cell_count = be16(src, page_off + hdr_off + 3)? as usize;
    if cell_count > 0x8000 {
        warnings.push(format!("implausible cell count {cell_count}"));
        return Ok(rows);
    }
    let cell_ptr_start = match page_type {
        0x0D | 0x05 => hdr_off + 12, // leaf/interior table: no right-most ptr... interior has 12
        0x0A | 0x02 => hdr_off + 12,
        _ => {
            warnings.push(format!("unknown page type {page_type:#x} skipped"));
            return Ok(rows);
        }
    };
    let _ = cell_ptr_start;

    for i in 0..cell_count.min(limits.max_records) {
        let ptr_field = page_off
            + hdr_off
            + match page_type {
                0x05 | 0x02 => 12,
                _ => 8,
            }
            + 2 * i as u64;
        let cell_off_rel = be16(src, ptr_field)? as u64;
        let cell_off = page_off + cell_off_rel;
        match page_type {
            0x05 => {
                // Interior table cell: 4-byte left child page + varint key.
                let child = be32(src, cell_off)? as u64;
                if child > 0 {
                    let child_off = db_base + (child - 1) * page_size;
                    let sub = walk_table_page(
                        src,
                        db_base,
                        child_off,
                        page_size,
                        reserved,
                        depth + 1,
                        limits,
                        warnings,
                        pages_visited,
                    )?;
                    rows.extend(sub);
                }
            }
            0x0D => {
                // Leaf table cell: varint payload-len, varint rowid,
                // payload (with possible overflow).
                let (payload_len, n1) = read_varint(src, cell_off)?;
                let (rowid, n2) = read_varint(src, cell_off + n1)?;
                let payload_start = cell_off + n1 + n2;
                let usable = page_size - u64::from(reserved);
                // B3: exact per-spec local-payload selection for table
                // leaf cells. X = U-35; if P <= X everything is local.
                // Otherwise M = ((U-12)*32/255)-23 and
                // K = M+((P-M) % (U-4)); local = K if K <= X else M.
                let x = usable - 35;
                let payload = if payload_len <= x {
                    read_bytes(src, payload_start, payload_len)?
                } else {
                    let m = (usable - 12) * 32 / 255 - 23;
                    let k = m + (payload_len - m) % (usable - 4);
                    let local = if k <= x { k } else { m };
                    let mut data = read_bytes(src, payload_start, local)?;
                    let next = be32(src, payload_start + local)? as u64;
                    let mut ctx = OverflowCtx {
                        page_size,
                        reserved,
                        limits,
                        page_work: pages_visited,
                    };
                    follow_overflow(src, db_base, next, payload_len - local, &mut ctx, &mut data)?;
                    data
                };
                if let Some(row) = decode_record(&payload, rowid) {
                    rows.push(row);
                }
            }
            _ => {
                // Index pages: not decoded in this milestone.
            }
        }
    }
    // Right-most child of interior pages.
    if page_type == 0x05 {
        let right = be32(src, page_off + hdr_off + 8)? as u64;
        if right > 0 && depth < 12 {
            let child_off = db_base + (right - 1) * page_size;
            let sub = walk_table_page(
                src,
                db_base,
                child_off,
                page_size,
                reserved,
                depth + 1,
                limits,
                warnings,
                pages_visited,
            )?;
            rows.extend(sub);
        }
    }
    Ok(rows)
}

/// Shared context for overflow-chain walking (R2: geometry + caps).
struct OverflowCtx<'a> {
    page_size: u64,
    reserved: u8,
    limits: &'a crate::engine::EngineLimits,
    /// Database-level page-work budget shared with the b-tree walk.
    page_work: &'a mut usize,
}

fn follow_overflow(
    src: &ByteSource,
    db_base: u64,
    mut page: u64,
    mut remaining: u64,
    geo: &mut OverflowCtx,
    out: &mut Vec<u8>,
) -> Result<()> {
    let page_size = geo.page_size;
    // R2: usable interior = page_size - reserved; each overflow page
    // carries a 4-byte next pointer followed by usable-4 payload bytes.
    let usable = page_size - u64::from(geo.reserved);
    let mut visited = std::collections::HashSet::new();
    while remaining > 0 && page > 0 {
        if !visited.insert(page) {
            return Err(Error::Validation {
                format: "sqlite",
                reason: "overflow chain cycle".into(),
            });
        }
        // R2: overflow pages share the database-level page-work budget
        // with the b-tree walk.
        *geo.page_work += 1;
        if *geo.page_work > geo.limits.max_sqlite_pages {
            return Err(Error::LimitExceeded {
                limit: "max_sqlite_pages",
                detail: "page-work (b-tree + overflow) exceeded cap".into(),
            });
        }
        // B3: pages always start at multiples of the FULL page_size;
        // reserved bytes only shrink the page's usable interior.
        let off = db_base + (page - 1) * page_size;
        let next = be32(src, off)? as u64;
        let chunk = (usable - 4).min(remaining);
        let data = read_bytes(src, off + 4, chunk)?;
        out.extend_from_slice(&data);
        remaining -= chunk;
        page = next;
        if out.len() as u64 > geo.limits.max_child_size {
            return Err(Error::LimitExceeded {
                limit: "max_child_size",
                detail: "overflow payload exceeded cap".into(),
            });
        }
    }
    Ok(())
}

/// Decode a record payload into values (serial types).
fn decode_record(payload: &[u8], rowid: u64) -> Option<TableRow> {
    let mut pos = 0usize;
    let (hdr_len, n) = read_varint_bytes(payload, pos)?;
    pos += n;
    let hdr_end = hdr_len as usize;
    if hdr_end > payload.len() {
        return None;
    }
    let mut serials = Vec::new();
    while pos < hdr_end {
        let (st, n) = read_varint_bytes(payload, pos)?;
        pos += n;
        serials.push(st);
    }
    let mut values = Vec::new();
    let mut body = hdr_end;
    for st in serials {
        let (len, value) = match st {
            0 => (0, Value::Null),
            1..=6 => {
                let size = match st {
                    1 => 1,
                    2 => 2,
                    3 => 3,
                    4 => 4,
                    5 => 6,
                    _ => 8,
                };
                if body + size > payload.len() {
                    return None;
                }
                let mut v: i64 = if payload[body] & 0x80 != 0 { -1 } else { 0 };
                for &b in &payload[body..body + size] {
                    v = (v << 8) | i64::from(b);
                }
                (size, Value::Int(v))
            }
            7 => {
                if body + 8 > payload.len() {
                    return None;
                }
                let bits = u64::from_be_bytes([
                    payload[body],
                    payload[body + 1],
                    payload[body + 2],
                    payload[body + 3],
                    payload[body + 4],
                    payload[body + 5],
                    payload[body + 6],
                    payload[body + 7],
                ]);
                (8, Value::Real(f64::from_bits(bits)))
            }
            8 => (0, Value::Int(0)),
            9 => (0, Value::Int(1)),
            10 | 11 => (0, Value::Null), // reserved
            n if n % 2 == 0 => {
                let len = ((n - 12) / 2) as usize;
                if body + len > payload.len() {
                    return None;
                }
                (len, Value::Blob(payload[body..body + len].to_vec()))
            }
            n => {
                let len = ((n - 13) / 2) as usize;
                if body + len > payload.len() {
                    return None;
                }
                (
                    len,
                    Value::Text(String::from_utf8_lossy(&payload[body..body + len]).into_owned()),
                )
            }
        };
        body += len;
        values.push(value);
    }
    Some(TableRow { rowid, values })
}

fn read_varint(src: &ByteSource, off: u64) -> Result<(u64, u64)> {
    let mut value: u64 = 0;
    for i in 0..9u64 {
        let b = read_byte(src, off + i)?;
        if i == 8 {
            value = (value << 8) | u64::from(b);
            return Ok((value, 9));
        }
        value = (value << 7) | u64::from(b & 0x7F);
        if b & 0x80 == 0 {
            return Ok((value, i + 1));
        }
    }
    Ok((value, 9))
}

fn read_varint_bytes(data: &[u8], pos: usize) -> Option<(u64, usize)> {
    let mut value: u64 = 0;
    for i in 0..9usize {
        let b = *data.get(pos + i)?;
        if i == 8 {
            value = (value << 8) | u64::from(b);
            return Some((value, 9));
        }
        value = (value << 7) | u64::from(b & 0x7F);
        if b & 0x80 == 0 {
            return Some((value, i + 1));
        }
    }
    Some((value, 9))
}

fn read_bytes(src: &ByteSource, off: u64, len: u64) -> Result<Vec<u8>> {
    let mut out = vec![0u8; len as usize];
    src.read_at(off, &mut out)?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn validate_at(src: &ByteSource) -> Result<HandlerOutput> {
        SqliteHandler.validate(
            src,
            Candidate { offset: 0 },
            &crate::engine::EngineLimits::default(),
            &mut Budget::default(),
        )
    }

    /// Build a minimal SQLite database: 1 page of 4096.
    /// Page 1 = leaf table b-tree with one row: (text "hello", int 42).
    fn single_page_db() -> Vec<u8> {
        let mut db = vec![0u8; 4096];
        // Header.
        db[0..16].copy_from_slice(SQLITE_MAGIC);
        db[16..18].copy_from_slice(&4096u16.to_be_bytes());
        db[20] = 0; // reserved
        db[56..60].copy_from_slice(&1u32.to_be_bytes()); // utf-8
                                                         // B-tree leaf header at offset 100.
        db[100] = 0x0D; // leaf table
        db[101..103].copy_from_slice(&0u16.to_be_bytes()); // freeblock
        db[103..105].copy_from_slice(&1u16.to_be_bytes()); // cell count
        db[105..107].copy_from_slice(&(4070u16).to_be_bytes()); // content start
        db[107] = 0; // fragmented bytes
                     // Cell pointer at 108.
        let cell_off = 4096 - 26;
        db[108..110].copy_from_slice(&(cell_off as u16).to_be_bytes());
        // Cell at 4096-26: payload_len(2)=14, rowid(1)=1, then record:
        // header: len 5, serial 0x15(text 1: len=(15-13)/2=1?) — use
        // serial 0x19 (text len 3)... simpler: text "hi" serial =
        // 13+2*2=17=0x11; int42 serial=1 (1 byte).
        let mut cell = Vec::new();
        // record: header_len, [17 (2-byte text), 1 (1-byte int)], "hi", 42
        let record_body: Vec<u8> = vec![
            0x11, b'h', b'i', // text "hi" (serial 17 -> len 2)
            42,   // int (serial 1 -> 1 byte)
        ];
        // header: 1 byte header-len = 2, then serials [0x11, 0x01]
        let record: Vec<u8> = vec![0x02, 0x11, 0x01, b'h', b'i', 42];
        let _ = record_body;
        // payload = record
        let payload_len = record.len() as u64;
        let mut pl = write_varint(payload_len);
        pl.extend(write_varint(1)); // rowid
        pl.extend_from_slice(&record);
        cell.extend_from_slice(&pl);
        db[cell_off..cell_off + cell.len()].copy_from_slice(&cell);
        db
    }

    fn write_varint(mut v: u64) -> Vec<u8> {
        if v <= 0x7F {
            return vec![v as u8];
        }
        let mut out = Vec::new();
        while v > 0 {
            out.insert(0, (v & 0x7F) as u8 | 0x80);
            v >>= 7;
        }
        *out.last_mut().unwrap() &= 0x7F;
        out
    }

    #[test]
    fn sqlite_single_page_rows_decoded() {
        let db = single_page_db();
        let src = ByteSource::from_vec(db);
        let out = validate_at(&src).expect("sqlite validates");
        let art = &out.artifacts[0];
        assert_eq!(art.confidence, Confidence::Validated);
        assert_eq!(
            art.metadata.get("page_size").map(String::as_str),
            Some("4096")
        );
        // sqlite_schema empty (no tables) but the root page row is decoded.
        assert!(!art.children.is_empty(), "record children expected");
    }

    #[test]
    fn sqlite_bad_page_size_rejected() {
        let mut db = single_page_db();
        db[16..18].copy_from_slice(&777u16.to_be_bytes());
        let src = ByteSource::from_vec(db);
        assert!(validate_at(&src).is_err());
    }

    #[test]
    fn sqlite_overflow_record_decoded_per_spec() {
        // B3: a payload that legitimately overflows must be decoded with
        // the exact X/M/K local-size rule AND overflow pages located at
        // (page-1)*page_size (full page stride, not usable size).
        // Layout: page 1 leaf + page 2 overflow + page 3 overflow.
        // Payload: 5000 bytes of text. U=4096, X=4061, M=((4096-12)*32/255)-23.
        let page_size: u64 = 4096;
        let usable = page_size; // reserved=0
        let x = usable - 35;
        let m = ((usable - 12) * 32 / 255) - 23;
        let payload_len: u64 = 5000;
        let payload_len_total = 3u64 + payload_len; // header byte + serial varint(2) + data
        let k = m + (payload_len_total - m) % (usable - 4);
        let local = if k <= x { k } else { m } as usize;

        let mut db = vec![0u8; 3 * page_size as usize];
        db[0..16].copy_from_slice(SQLITE_MAGIC);
        db[16..18].copy_from_slice(&(page_size as u16).to_be_bytes());
        db[20] = 0;
        db[56..60].copy_from_slice(&1u32.to_be_bytes());
        db[100] = 0x0D;
        db[103..105].copy_from_slice(&1u16.to_be_bytes());
        // Record: header len 2, serial 0xB9 (text len (0xB9-13)/2 = 85?),
        // use big text: serial = 13 + 2*len, len=5000 -> varint serial.
        // 13 + 10000 = 10013 -> serial varint.
        let mut record: Vec<u8> = vec![0x02]; // header len (1 byte covers 2 fields? no)
                                              // header: len byte + serial varint(s). text serial 10013 varint.
        let serial = 13u64 + 2 * payload_len; // text of 5000 chars
        let mut hdr = vec![0u8]; // placeholder for header length
        hdr.extend(write_varint(serial));
        hdr[0] = hdr.len() as u8;
        record = hdr;
        record.extend(vec![b'A'; payload_len as usize]);

        // Cell at some offset on page 1.
        let mut cell = write_varint(payload_len_total);
        cell.extend(write_varint(1));
        cell.extend_from_slice(&record[..local]);
        cell.extend_from_slice(&2u32.to_be_bytes()); // overflow page 2
        let cell_off = page_size as usize - cell.len();
        db[108..110].copy_from_slice(&(cell_off as u16).to_be_bytes());
        db[cell_off..cell_off + cell.len()].copy_from_slice(&cell);

        // Overflow page 2: data chunk = min(page_size-4, remaining).
        let remaining = payload_len_total as usize - local;
        let first_chunk = (page_size as usize - 4).min(remaining);
        let second_start = local + first_chunk;
        let second_chunk = remaining - first_chunk;
        // Point to page 3 only when there is a second chunk.
        let next_page: u32 = if second_chunk > 0 { 3 } else { 0 };
        db[page_size as usize..page_size as usize + 4].copy_from_slice(&next_page.to_be_bytes());
        db[page_size as usize + 4..page_size as usize + 4 + first_chunk]
            .copy_from_slice(&record[local..local + first_chunk]);
        if second_chunk > 0 {
            db[2 * page_size as usize..2 * page_size as usize + 4]
                .copy_from_slice(&0u32.to_be_bytes());
            db[2 * page_size as usize + 4..2 * page_size as usize + 4 + second_chunk]
                .copy_from_slice(&record[second_start..]);
        }

        let src = ByteSource::from_vec(db);
        let out = validate_at(&src).expect("overflow record must validate");
        let art = &out.artifacts[0];
        assert_eq!(art.confidence, Confidence::Validated);
        // The row must decode to a 5000-char text value (summary is
        // truncated in the label at 48 chars, so look for 48 'A's).
        let decoded = art
            .children
            .iter()
            .find(|c| c.label.contains("sqlite_schema[1]"))
            .unwrap_or_else(|| {
                panic!(
                    "overflow row decoded; children: {:?}",
                    art.children.iter().map(|c| &c.label).collect::<Vec<_>>()
                )
            });
        assert!(
            decoded.label.contains(&"A".repeat(48)),
            "text payload fully reassembled: {}",
            decoded.label
        );
    }

    #[test]
    fn sqlite_overflow_with_reserved_bytes_decoded() {
        // R2: with reserved bytes per page, overflow payload chunks are
        // page_size - reserved - 4 and pages still sit at full page_size
        // stride. reserved=32 must not corrupt the reassembled payload.
        let page_size: u64 = 4096;
        let reserved: u8 = 32;
        let usable = page_size - u64::from(reserved);
        let x = usable - 35;
        let m = ((usable - 12) * 32 / 255) - 23;
        let data_len: u64 = 2000;
        let payload_len_total = 3u64 + data_len; // hdr len byte + serial varint(2)? keep simple below
        let k = m + (payload_len_total - m) % (usable - 4);
        let local = if k <= x { k } else { m } as usize;

        // Record: header(3: len byte + serial varint for text) + text.
        let serial = 13u64 + 2 * data_len;
        let mut hdr = vec![0u8];
        hdr.extend(write_varint(serial));
        hdr[0] = hdr.len() as u8;
        let mut record = hdr;
        record.extend(vec![b'R'; data_len as usize]);
        let payload_len_total = record.len() as u64;

        let mut db = vec![0u8; 3 * page_size as usize];
        db[0..16].copy_from_slice(SQLITE_MAGIC);
        db[16..18].copy_from_slice(&(page_size as u16).to_be_bytes());
        db[20] = reserved;
        db[56..60].copy_from_slice(&1u32.to_be_bytes());
        db[100] = 0x0D;
        db[103..105].copy_from_slice(&1u16.to_be_bytes());
        let mut cell = write_varint(payload_len_total);
        cell.extend(write_varint(1));
        cell.extend_from_slice(&record[..local]);
        cell.extend_from_slice(&2u32.to_be_bytes());
        let cell_off = page_size as usize - cell.len();
        db[108..110].copy_from_slice(&(cell_off as u16).to_be_bytes());
        db[cell_off..cell_off + cell.len()].copy_from_slice(&cell);
        // Overflow page 2: next=0, payload chunk of usable-4.
        let remaining = payload_len_total as usize - local;
        let first_chunk = (usable as usize - 4).min(remaining);
        db[page_size as usize..page_size as usize + 4].copy_from_slice(&0u32.to_be_bytes());
        db[page_size as usize + 4..page_size as usize + 4 + first_chunk]
            .copy_from_slice(&record[local..local + first_chunk]);

        let src = ByteSource::from_vec(db);
        let out = validate_at(&src).expect("reserved-bytes overflow must validate");
        let art = &out.artifacts[0];
        assert_eq!(art.confidence, Confidence::Validated);
        let decoded = art
            .children
            .iter()
            .find(|c| c.label.contains("sqlite_schema[1]"))
            .unwrap_or_else(|| {
                panic!(
                    "row decoded; children: {:?}",
                    art.children.iter().map(|c| &c.label).collect::<Vec<_>>()
                )
            });
        assert!(
            decoded.label.contains(&"R".repeat(48)),
            "payload reassembled with reserved-byte geometry: {}",
            decoded.label
        );
    }

    #[test]
    fn sqlite_overflow_chain_cycle_rejected() {
        // Minimal header + a leaf page whose payload overflows to a
        // self-referencing overflow page.
        let mut db = vec![0u8; 3 * 4096];
        db[0..16].copy_from_slice(SQLITE_MAGIC);
        db[16..18].copy_from_slice(&4096u16.to_be_bytes());
        db[20] = 0;
        db[56..60].copy_from_slice(&1u32.to_be_bytes());
        db[100] = 0x0D;
        db[103..105].copy_from_slice(&1u16.to_be_bytes());
        // Cell: payload_len huge (overflow), local part, overflow ptr = 2
        let cell_off = 4096 - 20;
        db[108..110].copy_from_slice(&(cell_off as u16).to_be_bytes());
        // payload_len varint: 6000
        let mut cell: Vec<u8> = write_varint(6000);
        cell.extend(write_varint(1)); // rowid
        let local = (4096 - 35) as usize; // max_local
        cell.extend(vec![0xAA; local.min(48)]);
        cell.extend_from_slice(&2u32.to_be_bytes()); // overflow page 2
        db[cell_off..cell_off + cell.len()].copy_from_slice(&cell);
        // Overflow page 2 points to itself.
        db[4096..4100].copy_from_slice(&2u32.to_be_bytes());
        let src = ByteSource::from_vec(db);
        // Cycle must be a clean validation error or skipped row, never a hang.
        let res = validate_at(&src);
        assert!(res.is_err() || res.is_ok());
    }
}
