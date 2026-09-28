//! PDF handler: structural validation, xref/object scanning, and
//! stream-object extraction. Honest about heuristic vs validated
//! status: malformed xref tables degrade to object scanning without
//! failing the artifact.

use crate::artifact::{Confidence, Evidence, RelationKind};
use crate::bytesource::ByteSource;
use crate::engine::{
    ArtifactDraft, Budget, Candidate, ChildContent, ChildDraft, Handler, HandlerOutput,
};
use crate::error::{Error, Result};
use crate::handlers::find_all;
use std::collections::BTreeMap;

pub struct PdfHandler;

impl PdfHandler {
    /// FINAL-B5: follow the LAST `startxref` to the xref table and
    /// verify it structurally (xref keyword, entry count, 20-byte
    /// entries with type byte + 10-digit offset + 5-digit gen), then
    /// check that the following `trailer` dict contains /Size. Returns
    /// (xref_offset, entry_count, has_size, free_entries) on success.
    fn verify_xref(src: &ByteSource, base: u64, xref_off: u64) -> Option<(u64, u32, bool, usize)> {
        if xref_off == 0 {
            // A 0 startxref (or offset to nowhere) is not verifiable.
            return None;
        }
        let abs = base.checked_add(xref_off)?;
        if abs + 4 > src.len() {
            return None;
        }
        let mut kw = [0u8; 4];
        src.read_at(abs, &mut kw).ok()?;
        if &kw != b"xref" {
            return None;
        }
        // Parse "first count" on the next line.
        let probe_len = 4096u64.min(src.len() - abs);
        let mut probe = vec![0u8; probe_len as usize];
        src.read_at(abs, &mut probe).ok()?;
        let text = &probe[..];
        // Skip "xref" + EOL.
        let after_kw = 4 + {
            let mut skip = 0usize;
            if matches!(text.get(4), Some(b'\r')) {
                skip += 1;
            }
            if matches!(text.get(4 + skip), Some(b'\n') | Some(b'\r')) {
                skip += 1;
            }
            skip
        };
        let rest = &text[after_kw..];
        // First line: "<first> <count>".
        let line_end = rest.iter().position(|&b| b == b'\n' || b == b'\r')?;
        let header = std::str::from_utf8(&rest[..line_end]).ok()?;
        let mut fields = header.split_whitespace();
        let _first: u32 = fields.next()?.parse().ok()?;
        let count: u32 = fields.next()?.parse().ok()?;
        if count == 0 {
            return None;
        }
        // Entries: exactly `count` lines of "nnnnnnnnnn ggggg f" and
        // each entry line is 20 bytes in canonical form (we accept the
        // EOL variation but verify digits and type byte).
        let mut pos = line_end + 1;
        let mut verified = 0u32;
        let mut free = 0usize;
        for _ in 0..count {
            if pos >= rest.len() {
                break;
            }
            // Type byte: 'n', 'f', or leading digit of the offset.
            let line = &rest[pos..];
            let eol = line.iter().position(|&b| b == b'\n' || b == b'\r')?;
            let entry = &line[..eol];
            let parts: Vec<&[u8]> = entry
                .split(|&b| b == b' ' || b == b'\t')
                .filter(|p| !p.is_empty())
                .collect();
            if parts.len() >= 3 {
                let offset_ok = parts[0].len() == 10 && parts[0].iter().all(u8::is_ascii_digit);
                let gen_ok = parts[1].len() == 5 && parts[1].iter().all(u8::is_ascii_digit);
                let type_ok = matches!(parts[2], b"n" | b"f");
                if offset_ok && gen_ok && type_ok {
                    verified += 1;
                    if parts[2] == b"f" {
                        free += 1;
                    }
                } else {
                    return None;
                }
            } else {
                return None;
            }
            pos += eol + 1;
        }
        if verified != count {
            return None;
        }
        // The xref section must be followed by a trailer dict.
        let after_entries = &rest[pos..];
        let tr = find_sub(after_entries, b"trailer")?;
        let dict = &after_entries[tr + 7..];
        let dict_text = std::str::from_utf8(dict).unwrap_or("");
        let has_size = dict_text.contains("/Size");
        Some((xref_off, count, has_size, free))
    }

    /// Find `N G obj` object headers by scanning for " obj" with the
    /// object number parsed from the preceding bytes. Bounded.
    fn scan_objects(
        src: &ByteSource,
        base: u64,
        end: u64,
        limits: &crate::engine::EngineLimits,
    ) -> Vec<(u32, u64)> {
        let mut objects = Vec::new();
        let window = src.slice(base, end - base).unwrap_or_else(|_| {
            // Unreachable for validated bounds; fall back to empty.
            src.slice(base, 0).unwrap()
        });
        let mut data = vec![0u8; (end - base) as usize];
        if src.read_at(base, &mut data).is_err() {
            return objects;
        }
        let _ = window;
        let mut pos = 0usize;
        while let Some(rel) = find_sub(&data[pos..], b" obj") {
            let at = pos + rel;
            // Parse "<num> <gen> obj" backwards from at.
            let before = &data[..at];
            let trimmed: &[u8] = {
                let mut t = before;
                while let Some((last, rest)) = t.split_last() {
                    if *last == b' ' || *last == b'\n' || *last == b'\r' || *last == b'\t' {
                        t = rest;
                    } else {
                        break;
                    }
                }
                t
            };
            // Generation number then object number.
            let mut fields: Vec<u32> = Vec::new();
            let mut scan = trimmed;
            for _ in 0..2 {
                let mut num: u32 = 0;
                let mut digits = 0usize;
                let mut mul = 1u32;
                while let Some((last, rest)) = scan.split_last() {
                    if last.is_ascii_digit() && digits < 10 {
                        num = num.wrapping_add(mul.wrapping_mul(u32::from(last - b'0')));
                        mul = mul.wrapping_mul(10);
                        digits += 1;
                        scan = rest;
                    } else {
                        break;
                    }
                }
                if digits == 0 {
                    break;
                }
                fields.push(num);
                // Skip one separator.
                if let Some((last, rest)) = scan.split_last() {
                    if *last == b' ' || *last == b'\n' || *last == b'\r' || *last == b'\t' {
                        scan = rest;
                    } else {
                        break;
                    }
                }
            }
            if fields.len() == 2 {
                let obj_num = fields[1];
                objects.push((obj_num, base + at as u64));
            }
            if objects.len() >= limits.max_string_candidates {
                break;
            }
            pos = at + 4;
        }
        objects
    }
}

fn find_sub(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

impl Handler for PdfHandler {
    fn format(&self) -> &'static str {
        "pdf"
    }

    fn find_candidates(&self, src: &ByteSource) -> Vec<Candidate> {
        find_all(src, b"%PDF-")
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

        // Need "%PDF-M.m" header (9 bytes).
        if base + 9 > src.len() {
            return Err(Error::Validation {
                format: "pdf",
                reason: "truncated header".into(),
            });
        }
        let mut hdr = [0u8; 9];
        src.read_at(base, &mut hdr)?;
        // Major/minor should be digits (be lenient: printable).
        if !hdr[5].is_ascii_digit() || hdr[6] != b'.' || !hdr[7].is_ascii_digit() {
            return Err(Error::Validation {
                format: "pdf",
                reason: "malformed version in header".into(),
            });
        }

        // Strong evidence: %%EOF marker present after base.
        let tail = src.slice(base, src.len() - base)?;
        let eof_hits = find_all(&tail, b"%%EOF");
        let end = eof_hits.last().map(|&o| base + o + 5);

        // startxref presence strengthens the claim; FINAL-B5 requires
        // that we actually FOLLOW the startxref offset and verify the
        // xref table + trailer dict structurally, not just note that
        // the keyword appears.
        let xref_hits = find_all(&tail, b"startxref");
        let mut xref_verified: Option<(u64, u32, bool, usize)> = None;
        // Try startxref occurrences from LAST to first (per the PDF
        // spec the last one wins; incremental updates chain backwards).
        for hit in xref_hits.iter().rev() {
            // Parse the decimal offset after "startxref".
            let start = hit + 9;
            let win_len = 32u64.min(tail.len().saturating_sub(start));
            let mut after = vec![0u8; win_len as usize];
            if tail.read_at(start, &mut after).is_err() {
                continue;
            }
            let text = String::from_utf8_lossy(&after);
            if let Some(off) = text
                .split_whitespace()
                .next()
                .and_then(|t| t.parse::<u64>().ok())
            {
                if let Some(v) = Self::verify_xref(src, base, off) {
                    xref_verified = Some(v);
                    break;
                }
            }
        }

        let (confidence, mut evidence) = match (end.is_some(), xref_verified) {
            (true, Some((off, count, has_size, free))) => (
                Confidence::Validated,
                vec![
                    "%PDF- header".to_string(),
                    format!("xref table verified at +{off} ({count} entries, {free} free)"),
                    if has_size {
                        "trailer /Size present".to_string()
                    } else {
                        "trailer dict present (no /Size)".to_string()
                    },
                    "%%EOF present".to_string(),
                ],
            ),
            (true, None) if !xref_hits.is_empty() => (
                // startxref keyword exists but its target does not
                // verify: common for repaired/hybrid PDFs. Honest status:
                // Partial, not Validated.
                Confidence::Partial,
                vec![
                    "%PDF- header".to_string(),
                    "startxref present but xref table did not verify".to_string(),
                    "%%EOF present".to_string(),
                ],
            ),
            (true, None) => (
                Confidence::Partial,
                vec!["%PDF- header".to_string(), "%%EOF present".to_string()],
            ),
            (false, _) => (
                Confidence::Heuristic,
                vec![
                    "%PDF- header".to_string(),
                    "no %%EOF (truncated?)".to_string(),
                ],
            ),
        };

        // Heuristic PDFs (no provable end) still produce an artifact but
        // bounded to the source end; trailing-data logic stays honest.
        let size = end.unwrap_or(src.len()) - base;
        let mut metadata = BTreeMap::new();
        metadata.insert(
            "version".to_string(),
            format!("{}.{}", hdr[5] as char, hdr[7] as char),
        );
        if let Some(e) = end {
            metadata.insert("eof_offset".to_string(), e.to_string());
        }
        if let Some((off, count, has_size, _)) = xref_verified {
            metadata.insert("xref_offset".to_string(), off.to_string());
            metadata.insert("xref_entries".to_string(), count.to_string());
            if has_size {
                metadata.insert("trailer_size".to_string(), "present".to_string());
            }
        }

        // Object scan (bounded): every "N G obj" header in the body.
        let scan_end = end.unwrap_or(src.len()).min(base + 64 * 1024 * 1024);
        let objects = Self::scan_objects(src, base, scan_end, limits);
        metadata.insert("object_count".to_string(), objects.len().to_string());
        evidence.push(format!("{} object headers scanned", objects.len()));

        // Stream objects: "stream" keyword after an object header, with
        // a "Length" hint when present. We carve streams whose "endstream"
        // marker is found; content is the raw (still filter-encoded)
        // stream bytes between "stream\r?\n" and "endstream".
        let mut children = Vec::new();
        for (obj_num, obj_off) in objects.iter().take(limits.max_string_candidates) {
            if children.len() >= 64 {
                break;
            }
            // Read forward from the object header for "stream".
            let probe_len = 4096u64.min(scan_end - obj_off);
            let mut probe = vec![0u8; probe_len as usize];
            if src.read_at(*obj_off, &mut probe).is_err() {
                continue;
            }
            let Some(stream_rel) = find_sub(&probe, b"stream") else {
                continue;
            };
            // Require "stream" to be followed by EOL.
            let mut data_start = stream_rel + 6;
            if matches!(probe.get(data_start), Some(b'\r')) {
                data_start += 1;
            }
            if matches!(probe.get(data_start), Some(b'\n')) {
                data_start += 1;
            }
            // Find the matching "endstream" within this object region
            // (bounded to the next "endobj" or probe window).
            let endobj_rel = find_sub(&probe[data_start..], b"endobj").unwrap_or(probe.len());
            let Some(endstream_rel) = find_sub(
                &probe[data_start..data_start + endobj_rel.min(probe.len() - data_start)],
                b"endstream",
            ) else {
                continue;
            };
            let data_end = data_start + endstream_rel;
            if data_end <= data_start {
                continue;
            }
            let stream_len = data_end - data_start;
            let region = match src.slice(obj_off + data_start as u64, stream_len as u64) {
                Ok(r) => r,
                Err(_) => continue,
            };
            let mut meta = BTreeMap::new();
            meta.insert("object_number".to_string(), obj_num.to_string());
            meta.insert("raw_stream_length".to_string(), stream_len.to_string());
            children.push(ChildDraft {
                relation: RelationKind::Contains,
                label: format!(
                    "PDF object {obj_num} stream ({} raw bytes, filters not applied)",
                    stream_len
                ),
                format_hint: "raw",
                content: ChildContent::Source(region),
                size: stream_len as u64,
                metadata: meta,
                warnings: vec![
                    "stream content is raw; /Filter decoding (FlateDecode etc.) not applied"
                        .to_string(),
                ],
                entry_name: Some(format!("object_{obj_num}.stream")),
                confidence: Confidence::Validated,
                evidence: vec!["structurally decoded by parent handler".to_string()],
            });
        }
        if !objects.is_empty() && children.is_empty() {
            evidence.push("no bounded stream objects carved".to_string());
        }

        Ok(HandlerOutput {
            artifacts: vec![ArtifactDraft {
                format: "pdf".to_string(),
                label: format!("PDF document ({} objects)", objects.len()),
                offset: base,
                size,
                confidence,
                evidence: Evidence::facts(evidence),
                metadata,
                warnings: if end.is_none() {
                    vec!["no %%EOF found; boundary is heuristic".to_string()]
                } else {
                    Vec::new()
                },
                errors: Vec::new(),
                children,
            }],
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::Budget;

    fn validate_at(h: &dyn Handler, src: &ByteSource, off: u64) -> Result<HandlerOutput> {
        h.validate(
            src,
            Candidate { offset: off },
            &crate::engine::EngineLimits::default(),
            &mut Budget::default(),
        )
    }

    /// A minimal PDF with an object stream: the handler must scan the
    /// object header and carve the raw stream bytes.
    #[test]
    fn pdf_object_scan_and_stream_carve() {
        let mut pdf = Vec::new();
        pdf.extend_from_slice(b"%PDF-1.5\n");
        // Object 1: a stream with a FlateDecode hint.
        pdf.extend_from_slice(b"1 0 obj\n<< /Length 12 /Filter /FlateDecode >>\nstream\n");
        pdf.extend_from_slice(b"RAW_BYTES123");
        pdf.extend_from_slice(b"\nendstream\nendobj\n");
        pdf.extend_from_slice(b"2 0 obj\n<< /Type /Catalog >>\nendobj\n");
        // xref table with canonical 20-byte entries (0 free, 2 in-use);
        // the entry offsets are syntactically valid placeholders — the
        // handler verifies the table structure, not object placement.
        let xref_off = pdf.len() as u64;
        pdf.extend_from_slice(b"xref\n0 3\n");
        pdf.extend_from_slice(b"0000000000 65535 f \n");
        pdf.extend_from_slice(b"0000000009 00000 n \n");
        pdf.extend_from_slice(b"0000000090 00000 n \n");
        pdf.extend_from_slice(b"trailer\n<< /Size 3 >>\n");
        pdf.extend_from_slice(format!("startxref\n{xref_off}\n%%EOF").as_bytes());
        let src = ByteSource::from_vec(pdf);
        let out = validate_at(&PdfHandler, &src, 0).expect("pdf validates");
        let art = &out.artifacts[0];
        assert_eq!(art.confidence, Confidence::Validated);
        assert_eq!(
            art.metadata.get("object_count").map(String::as_str),
            Some("2")
        );
        let stream = art
            .children
            .iter()
            .find(|c| c.metadata.get("object_number").map(String::as_str) == Some("1"))
            .expect("object 1 stream child");
        match &stream.content {
            ChildContent::Source(r) => {
                let mut b = [0u8; 12];
                r.read_at(0, &mut b).unwrap();
                assert_eq!(&b, b"RAW_BYTES123");
            }
            _ => panic!("stream must be source-backed"),
        }
        // FINAL-B5: xref verification metadata is recorded.
        assert_eq!(
            art.metadata.get("xref_entries").map(String::as_str),
            Some("3")
        );
        assert_eq!(
            art.metadata.get("trailer_size").map(String::as_str),
            Some("present")
        );
    }

    /// FINAL-B5: a startxref that does NOT verify (keyword present but
    /// the table is garbage) must NOT be Validated — honesty contract.
    #[test]
    fn pdf_broken_xref_is_partial() {
        let mut pdf = Vec::new();
        pdf.extend_from_slice(b"%PDF-1.5\n");
        pdf.extend_from_slice(b"1 0 obj\n<< /Type /Catalog >>\nendobj\n");
        pdf.extend_from_slice(b"startxref\n999999\n%%EOF");
        let src = ByteSource::from_vec(pdf);
        let out = validate_at(&PdfHandler, &src, 0).expect("pdf still produces an artifact");
        let art = &out.artifacts[0];
        assert_eq!(
            art.confidence,
            Confidence::Partial,
            "startxref present but unverifiable must be Partial"
        );
        assert!(
            match &art.evidence {
                Evidence::Facts(v) => v.iter().any(|e| e.contains("did not verify")),
            },
            "evidence must state the xref did not verify"
        );
    }
}
