//! ByteSource: bounds-checked random access over whole files, in-memory
//! bytes, or cheap bounded ranges of a parent source. Never forces
//! intermediate temp files.
//!
//! Slices are genuinely zero-copy: the backing bytes/file are shared via
//! `Arc`, and a child view is just (shared backing, base offset, len).

use crate::error::{Error, Result};
use std::fs::File;
use std::path::{Path, PathBuf};
use std::sync::Arc;

/// A readable, randomly addressable byte region.
#[derive(Debug, Clone)]
pub struct ByteSource {
    backing: Backing,
    /// Absolute offset of this source's first byte within its ultimate
    /// root (0 for root sources).
    root_offset: u64,
    len: u64,
    /// Cursor for the `std::io::Read` streaming impl. Random-access
    /// `read_at` is unaffected; clones start at position 0.
    stream_pos: u64,
}

#[derive(Debug, Clone)]
enum Backing {
    /// Shared in-memory buffer. `base` is where this view starts.
    Memory { data: Arc<Vec<u8>>, base: u64 },
    /// Shared file. `base` is where this view starts within the file.
    File { path: Arc<PathBuf>, base: u64 },
}

impl ByteSource {
    /// Source backed by an in-memory buffer.
    pub fn from_vec(data: Vec<u8>) -> Self {
        let len = data.len() as u64;
        ByteSource {
            backing: Backing::Memory {
                data: Arc::new(data),
                base: 0,
            },
            root_offset: 0,
            len,
            stream_pos: 0,
        }
    }

    /// Source backed by a file on disk.
    pub fn from_file(path: &Path) -> Result<Self> {
        let meta = std::fs::metadata(path)?;
        let len = meta.len();
        Ok(ByteSource {
            backing: Backing::File {
                path: Arc::new(path.to_path_buf()),
                base: 0,
            },
            root_offset: 0,
            len,
            stream_pos: 0,
        })
    }

    /// Cheap, zero-copy bounded slice of this source. Bounds-checked
    /// eagerly; cloning shares the backing via `Arc` (no byte copying).
    pub fn slice(&self, offset: u64, len: u64) -> Result<Self> {
        if offset.checked_add(len).map_or(true, |end| end > self.len) {
            return Err(Error::OutOfBounds {
                offset,
                len,
                source_len: self.len,
            });
        }
        let backing = match &self.backing {
            Backing::Memory { data, base } => Backing::Memory {
                data: Arc::clone(data),
                base: base + offset,
            },
            Backing::File { path, base } => Backing::File {
                path: Arc::clone(path),
                base: base + offset,
            },
        };
        Ok(ByteSource {
            backing,
            root_offset: self.root_offset + offset,
            len,
            stream_pos: 0,
        })
    }

    /// Total byte length of this source.
    pub fn len(&self) -> u64 {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Offset of this region within its ultimate root source.
    pub fn root_offset(&self) -> u64 {
        self.root_offset
    }

    /// Backing file path if this source is a (view of a) file.
    pub fn file_path(&self) -> Option<&Path> {
        match &self.backing {
            Backing::File { path, .. } => Some(path),
            _ => None,
        }
    }

    /// Read `buf.len()` bytes starting at `offset` within this region.
    /// Bounds-checked; never panics on attacker-controlled offsets.
    pub fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<()> {
        let need = buf.len() as u64;
        if offset.checked_add(need).map_or(true, |end| end > self.len) {
            return Err(Error::OutOfBounds {
                offset,
                len: need,
                source_len: self.len,
            });
        }
        match &self.backing {
            Backing::Memory { data, base } => {
                let start = (base + offset) as usize;
                buf.copy_from_slice(&data[start..start + buf.len()]);
                Ok(())
            }
            Backing::File { path, base } => {
                use std::io::{Read, Seek, SeekFrom};
                let mut file = File::open(path.as_ref())?;
                file.seek(SeekFrom::Start(base + offset))?;
                file.read_exact(buf)?;
                Ok(())
            }
        }
    }

    /// Read the whole region into memory. Callers must respect engine
    /// byte budgets before invoking this on untrusted sizes.
    pub fn read_all(&self) -> Result<Vec<u8>> {
        let mut out = vec![0u8; self.len as usize];
        self.read_at(0, &mut out)?;
        Ok(out)
    }

    /// Read at most `max` bytes; returns what was actually available.
    pub fn read_prefix(&self, max: u64) -> Result<Vec<u8>> {
        let n = max.min(self.len);
        let mut out = vec![0u8; n as usize];
        self.read_at(0, &mut out)?;
        Ok(out)
    }

    /// Current streaming-read cursor (bytes consumed by the `Read` impl
    /// so far). Decompressors use this to compute exact frame ends.
    pub fn stream_pos(&self) -> u64 {
        self.stream_pos
    }

    /// Reset the streaming-read cursor to 0.
    pub fn rewind(&mut self) {
        self.stream_pos = 0;
    }

    /// Hash the entire region with BLAKE3 (streaming; works for any size).
    pub fn hash_all(&self) -> String {
        use blake3::Hasher;
        let mut hasher = Hasher::new();
        if let Backing::Memory { data, base } = &self.backing {
            // Fast path: direct slice access, no per-read bounds overhead.
            let start = *base as usize;
            hasher.update(&data[start..start + self.len as usize]);
        } else {
            let mut chunk = [0u8; 64 * 1024];
            let mut off = 0u64;
            while off < self.len {
                let n = (self.len - off).min(chunk.len() as u64) as usize;
                if self.read_at(off, &mut chunk[..n]).is_err() {
                    break;
                }
                hasher.update(&chunk[..n]);
                off += n as u64;
            }
        }
        hasher.finalize().to_hex().to_string()
    }
}

/// Streaming reads over the region. This is the bounded-memory path for
/// decompressors: they pull chunk-by-chunk through `read_at` instead of
/// forcing a whole-region `read_all()` before any limit check.
impl std::io::Read for ByteSource {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if self.stream_pos >= self.len {
            return Ok(0); // EOF
        }
        // Cap the chunk: file-backed `read_at` re-opens the file per
        // call, so a huge single read would be both unbounded work and a
        // giant read_exact. 64 KiB matches the decoder chunk sizes.
        const MAX_CHUNK: u64 = 64 * 1024;
        let want = (buf.len() as u64)
            .min(MAX_CHUNK)
            .min(self.len - self.stream_pos) as usize;
        if want == 0 {
            return Ok(0);
        }
        self.read_at(self.stream_pos, &mut buf[..want])
            .map_err(std::io::Error::other)?;
        self.stream_pos += want as u64;
        Ok(want)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slice_is_bounds_checked() {
        let src = ByteSource::from_vec(vec![1, 2, 3, 4, 5]);
        assert!(src.slice(3, 2).is_ok());
        assert!(src.slice(4, 2).is_err());
        assert!(src.slice(u64::MAX, 1).is_err());
    }

    #[test]
    fn nested_slices_track_root_offset() {
        let src = ByteSource::from_vec((0u8..10).collect::<Vec<u8>>());
        let a = src.slice(2, 8).unwrap();
        let b = a.slice(2, 4).unwrap();
        assert_eq!(b.root_offset(), 4);
        let mut buf = [0u8; 4];
        b.read_at(0, &mut buf).unwrap();
        assert_eq!(buf, [4, 5, 6, 7]);
    }

    #[test]
    fn read_prefix_clamps() {
        let src = ByteSource::from_vec(vec![9, 8, 7]);
        assert_eq!(src.read_prefix(10).unwrap(), vec![9, 8, 7]);
        assert_eq!(src.read_prefix(2).unwrap(), vec![9, 8]);
    }

    /// Regression (B6): slicing a memory-backed source must not copy the
    /// backing buffer. Many child views share one allocation.
    #[test]
    fn slices_share_backing_zero_copy() {
        let src = ByteSource::from_vec(vec![7u8; 1_000_000]);
        let child = src.slice(10, 999_990).unwrap();
        let grandchild = child.slice(5, 999_985).unwrap();
        let mut first = [0u8; 3];
        grandchild.read_at(0, &mut first).unwrap();
        assert_eq!(first, [7, 7, 7]);
        // Structural check: backing is shared (same Arc allocation count).
        match (&src.backing, &grandchild.backing) {
            (Backing::Memory { data: d1, .. }, Backing::Memory { data: d2, .. }) => {
                assert!(Arc::ptr_eq(d1, d2), "backing must be shared, not copied");
            }
            _ => panic!("expected memory backing"),
        }
    }

    /// Regression (B2): hash covers the full region, not a prefix.
    #[test]
    fn hash_covers_full_region() {
        let mut a_vec = vec![0u8; 128 * 1024];
        let ia = 200_000 % a_vec.len();
        a_vec[ia] = 1; // differ beyond 64 KiB
        let mut b_vec = vec![0u8; 128 * 1024];
        let ib = 200_000 % b_vec.len();
        b_vec[ib] = 2;
        let a = ByteSource::from_vec(a_vec);
        let b = ByteSource::from_vec(b_vec);
        assert_ne!(a.hash_all(), b.hash_all());
    }
}
