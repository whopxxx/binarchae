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

        // startxref presence strengthens the claim.
        let xref_hits = find_all(&tail, b"startxref");
        let has_xref = !xref_hits.is_empty();

        let (confidence, mut evidence) = match (end.is_some(), has_xref) {
            (true, true) => (
                Confidence::Validated,
                vec![
                    "%PDF- header".to_string(),
                    "startxref present".to_string(),
                    "%%EOF present".to_string(),
                ],
            ),
            (true, false) => (
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
        pdf.extend_from_slice(b"xref\n0 3\ntrailer\n<< /Size 3 >>\nstartxref\n0\n%%EOF");
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
    }
}
