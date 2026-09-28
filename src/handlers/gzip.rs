//! gzip handler: structural detection + native decompression with
//! resource limits (expansion ratio, child size).
//!
//! Boundary logic (B7): the header layout is parsed explicitly
//! (FEXTRA/FNAME/FCOMMENT variable fields), then the deflate stream is
//! decoded with an exact consumed-byte count, and the 8-byte trailer
//! (CRC32 + ISIZE) is verified against the decompressed output. The
//! artifact boundary is therefore `header_end + deflate_bytes + 8`,
//! which supports trailing data after the gzip member.

use crate::artifact::{Confidence, Evidence, RelationKind};
use crate::bytesource::ByteSource;
use crate::engine::{
    ArtifactDraft, Budget, Candidate, ChildContent, ChildDraft, Handler, HandlerOutput,
};
use crate::error::{Error, Result};
use crate::handlers::find_all;
use std::collections::BTreeMap;
use std::io::Read;

pub struct GzipHandler;

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
        if flags & 0xE0 != 0 {
            return Err(Error::Validation {
                format: "gzip",
                reason: "reserved flag bits set".into(),
            });
        }
        if flags & 0x02 != 0 {
            // FHCRC would need its own verification; treat as unsupported
            // rather than silently mis-parsing the layout.
            return Err(Error::Validation {
                format: "gzip",
                reason: "FHCRC members not supported".into(),
            });
        }

        // Walk the optional header fields in order (RFC 1952 §2.3.1).
        let mut off = base + 10u64;
        if flags & 0x04 != 0 {
            // FEXTRA: 2-byte XLEN + XLEN bytes.
            if off + 2 > src.len() {
                return Err(Error::Validation {
                    format: "gzip",
                    reason: "FEXTRA truncated".into(),
                });
            }
            let mut xb = [0u8; 2];
            src.read_at(off, &mut xb)?;
            let xlen = u16::from_le_bytes(xb) as u64;
            off += 2 + xlen;
        }
        if flags & 0x08 != 0 {
            // FNAME: zero-terminated.
            off = skip_cstring(src, off)?;
        }
        if flags & 0x10 != 0 {
            // FCOMMENT: zero-terminated.
            off = skip_cstring(src, off)?;
        }
        if off > src.len() {
            return Err(Error::Validation {
                format: "gzip",
                reason: "optional header fields truncated".into(),
            });
        }
        let header_end = off;

        // Decode the deflate stream with exact consumed-byte accounting.
        let compressed_len = src.len() - header_end;
        let cap = limits
            .max_child_size
            .min(
                limits
                    .max_expansion_ratio
                    .saturating_mul(compressed_len.max(1)),
            )
            .min(u64::from(u32::MAX - 1));

        let deflate_region = src.slice(header_end, compressed_len)?;
        let deflate_data = deflate_region.read_all()?;
        let mut counting = CountingReader::new(&deflate_data);
        let mut decoder = flate2::read::DeflateDecoder::new(&mut counting);

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
                                "gzip output exceeded {cap} bytes (compressed {compressed_len})"
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
                    return Err(Error::Decompression(format!("deflate stream: {e}")));
                }
            }
        }
        // total_in() counts only the bytes the deflate stream actually
        // consumed (the reader's read count includes read-ahead over the
        // trailer, which would corrupt boundary math).
        let deflate_consumed = decoder.total_in() as usize;
        drop(decoder);
        if out.is_empty() {
            return Err(Error::Validation {
                format: "gzip",
                reason: "stream decoded to zero bytes".into(),
            });
        }

        // Trailer: CRC32(4) + ISIZE(4), verified against the output.
        let trailer_start = header_end + deflate_consumed as u64;
        if trailer_start + 8 > src.len() {
            return Err(Error::Validation {
                format: "gzip",
                reason: "trailer truncated".into(),
            });
        }
        let mut trailer = [0u8; 8];
        src.read_at(trailer_start, &mut trailer)?;
        let stored_crc = u32::from_le_bytes([trailer[0], trailer[1], trailer[2], trailer[3]]);
        let stored_isize = u32::from_le_bytes([trailer[4], trailer[5], trailer[6], trailer[7]]);
        let mut h = crc32fast::Hasher::new();
        h.update(&out);
        let actual_crc = h.finalize();
        if stored_crc != actual_crc {
            return Err(Error::Validation {
                format: "gzip",
                reason: format!(
                    "trailer CRC32 mismatch: stored {stored_crc:#x}, got {actual_crc:#x}"
                ),
            });
        }
        if stored_isize != (out.len() as u32) {
            return Err(Error::Validation {
                format: "gzip",
                reason: format!(
                    "ISIZE mismatch: stored {stored_isize}, actual {}",
                    out.len() as u32
                ),
            });
        }

        let mut metadata = BTreeMap::new();
        metadata.insert("uncompressed_size".to_string(), out.len().to_string());
        metadata.insert("isize_field".to_string(), stored_isize.to_string());
        if flags & 0x08 != 0 {
            metadata.insert("has_name_field".to_string(), "true".to_string());
        }

        // B7: exact boundary = header_end + deflate + 8-byte trailer.
        // Bytes after this belong to the parent region's trailing data.
        let out_size = out.len() as u64;
        let size = trailer_start + 8 - base;

        Ok(HandlerOutput {
            artifacts: vec![ArtifactDraft {
                format: "gzip".to_string(),
                label: "gzip stream".to_string(),
                offset: base,
                size,
                confidence: Confidence::Validated,
                evidence: Evidence::facts([
                    "gzip header + optional fields walked".to_string(),
                    "deflate stream consumed exactly".to_string(),
                    "trailer CRC32 + ISIZE verified".to_string(),
                ]),
                metadata,
                warnings: Vec::new(),
                errors: Vec::new(),
                children: vec![ChildDraft {
                    relation: RelationKind::DecompressedFrom,
                    label: format!("decompressed payload ({out_size} bytes)"),
                    format_hint: "raw",
                    content: ChildContent::Owned(out),
                    size: out_size,
                    metadata: BTreeMap::new(),
                    warnings: Vec::new(),
                    entry_name: None,
                    confidence: Confidence::Validated,
                    evidence: vec!["structurally decoded by parent handler".to_string()],
                }],
            }],
        })
    }
}

/// Skip a NUL-terminated string starting at `off`. Returns the offset
/// just past the terminator.
fn skip_cstring(src: &ByteSource, mut off: u64) -> Result<u64> {
    loop {
        if off >= src.len() {
            return Err(Error::Validation {
                format: "gzip",
                reason: "unterminated string in header".into(),
            });
        }
        let mut b = [0u8; 1];
        src.read_at(off, &mut b)?;
        off += 1;
        if b[0] == 0 {
            return Ok(off);
        }
    }
}

/// Tracks how many compressed bytes the decoder consumed.
struct CountingReader<'a> {
    inner: &'a [u8],
    read: usize,
}

impl<'a> CountingReader<'a> {
    fn new(inner: &'a [u8]) -> Self {
        CountingReader { inner, read: 0 }
    }
}

impl Read for CountingReader<'_> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = match self.inner.get(self.read..) {
            Some(rest) => {
                let n = rest.len().min(buf.len());
                buf[..n].copy_from_slice(&rest[..n]);
                n
            }
            None => 0,
        };
        self.read += n;
        Ok(n)
    }
}
