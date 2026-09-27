//! gzip handler: structural detection + native decompression with
//! resource limits (expansion ratio, child size).

use crate::artifact::{Confidence, Evidence, RelationKind};
use crate::bytesource::ByteSource;
use crate::engine::{ArtifactDraft, Budget, Candidate, ChildDraft, Handler, HandlerOutput};
use crate::error::{Error, Result};
use crate::handlers::find_all;
use std::collections::BTreeMap;
use std::io::Read;

pub struct GzipHandler;

/// Tracks how many compressed bytes the decoder consumed.
struct CountingReader<'a> {
    inner: &'a [u8],
    read: usize,
}

impl<'a> CountingReader<'a> {
    fn new(inner: &'a [u8]) -> Self {
        CountingReader { inner, read: 0 }
    }
    fn count(&self) -> usize {
        self.read
    }
}

impl<'a> Read for CountingReader<'a> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = self.inner.get(self.read..).map_or(0, |rest| {
            let n = n_min(rest.len(), buf.len());
            buf[..n].copy_from_slice(&rest[..n]);
            n
        });
        self.read += n;
        Ok(n)
    }
}

fn n_min(a: usize, b: usize) -> usize {
    if a < b {
        a
    } else {
        b
    }
}

impl Handler for GzipHandler {
    fn format(&self) -> &'static str {
        "gzip"
    }

    fn find_candidates(&self, src: &ByteSource) -> Vec<Candidate> {
        find_all(src, &[0x1f, 0x8b, 0x08])
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
        // Header: magic(2) method(1) flags(1) mtime(4) xfl(1) os(1) = 10.
        if base + 10 > src.len() {
            return Err(Error::Validation {
                format: "gzip",
                reason: "truncated header".into(),
            });
        }
        let mut hdr = [0u8; 10];
        src.read_at(base, &mut hdr)?;
        if hdr[0] != 0x1f || hdr[1] != 0x8b || hdr[2] != 0x08 {
            return Err(Error::Validation {
                format: "gzip",
                reason: "bad magic/method".into(),
            });
        }
        let flags = hdr[3];
        let reserved = flags & 0xE0;
        if reserved != 0 {
            return Err(Error::Validation {
                format: "gzip",
                reason: "reserved flag bits set".into(),
            });
        }

        let payload = src.slice(base, src.len() - base)?;
        let data = payload.read_all()?;
        let mut counting = CountingReader::new(&data[..]);
        let mut decoder = flate2::read::MultiGzDecoder::new(&mut counting);

        // Decompress with a hard cap so bombs fail fast.
        let cap = limits
            .max_child_size
            .min(limits.max_expansion_ratio.saturating_mul(data.len() as u64))
            .min(u64::from(u32::MAX - 1));
        let mut out = Vec::new();
        let mut chunk = [0u8; 64 * 1024];
        loop {
            match decoder.read(&mut chunk) {
                Ok(0) => break,
                Ok(n) => {
                    if out.len() as u64 + n as u64 > cap {
                        return Err(Error::LimitExceeded {
                            limit: "compression-expansion-ratio/child-size",
                            detail: format!(
                                "gzip output exceeded {cap} bytes (compressed {})",
                                data.len()
                            ),
                        });
                    }
                    if !budget.charge(limits, n as u64) {
                        return Err(Error::LimitExceeded {
                            limit: "max-total-expanded-bytes",
                            detail: format!("gzip stream +{n}"),
                        });
                    }
                    out.extend_from_slice(&chunk[..n]);
                }
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(e) => {
                    return Err(Error::Decompression(format!("gzip stream: {e}")));
                }
            }
        }
        if out.is_empty() {
            return Err(Error::Validation {
                format: "gzip",
                reason: "stream decoded to zero bytes".into(),
            });
        }

        // Trailer: ISIZE = uncompressed size mod 2^32.
        let consumed = counting.count();
        let isize_off = base as usize + consumed + 4;
        let mut metadata = BTreeMap::new();
        metadata.insert("uncompressed_size".to_string(), out.len().to_string());
        if isize_off + 4 <= data.len() {
            let isize_val = u32::from_le_bytes([
                data[isize_off],
                data[isize_off + 1],
                data[isize_off + 2],
                data[isize_off + 3],
            ]);
            metadata.insert("isize_field".to_string(), isize_val.to_string());
        }

        // Boundary: header + consumed deflate data + 8-byte trailer.
        let size = (consumed + 18) as u64;

        Ok(HandlerOutput {
            artifacts: vec![ArtifactDraft {
                format: "gzip".to_string(),
                label: "gzip stream".to_string(),
                offset: base,
                size,
                confidence: Confidence::Validated,
                evidence: Evidence::facts([
                    "gzip header + flags valid".to_string(),
                    "deflate stream + CRC32/ISIZE trailer consumed".to_string(),
                ]),
                metadata,
                warnings: Vec::new(),
                errors: Vec::new(),
                inline_bytes: None,
                children: vec![ChildDraft {
                    relation: RelationKind::DecompressedFrom,
                    label: format!("decompressed payload ({} bytes)", out.len()),
                    format_hint: "raw",
                    bytes: out,
                    metadata: BTreeMap::new(),
                    warnings: Vec::new(),
                    entry_name: None,
                }],
            }],
        })
    }
}
