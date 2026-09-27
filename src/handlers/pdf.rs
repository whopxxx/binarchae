//! PDF handler: basic structural validation sufficient to control obvious
//! false positives. Honest about heuristic vs validated status.

use crate::artifact::{Confidence, Evidence};
use crate::bytesource::ByteSource;
use crate::engine::{ArtifactDraft, Budget, Candidate, Handler, HandlerOutput};
use crate::error::{Error, Result};
use crate::handlers::find_all;
use std::collections::BTreeMap;

pub struct PdfHandler;

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
        _limits: &crate::engine::EngineLimits,
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

        let (confidence, evidence) = match (end.is_some(), has_xref) {
            (true, true) => (
                Confidence::Validated,
                Evidence::facts([
                    "%PDF- header".to_string(),
                    "startxref present".to_string(),
                    "%%EOF present".to_string(),
                ]),
            ),
            (true, false) => (
                Confidence::Partial,
                Evidence::facts(["%PDF- header".to_string(), "%%EOF present".to_string()]),
            ),
            (false, _) => (
                Confidence::Heuristic,
                Evidence::facts([
                    "%PDF- header".to_string(),
                    "no %%EOF (truncated?)".to_string(),
                ]),
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

        let bytes = src.slice(base, size)?.read_all()?;
        Ok(HandlerOutput {
            artifacts: vec![ArtifactDraft {
                format: "pdf".to_string(),
                label: "PDF document".to_string(),
                offset: base,
                size,
                confidence,
                evidence,
                metadata,
                warnings: if end.is_none() {
                    vec!["no %%EOF found; boundary is heuristic".to_string()]
                } else {
                    Vec::new()
                },
                errors: Vec::new(),
                inline_bytes: Some(bytes),
                children: Vec::new(),
            }],
        })
    }
}
