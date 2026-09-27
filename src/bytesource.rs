//! ByteSource: bounds-checked random access over whole files, in-memory
//! bytes, or cheap bounded ranges of a parent source. Never forces
//! intermediate temp files.

use crate::error::{Error, Result};
use std::fs::File;
use std::path::{Path, PathBuf};

/// A readable, randomly addressable byte region.
#[derive(Debug, Clone)]
pub struct ByteSource {
    inner: SourceInner,
    /// Absolute offset of this source's first byte within its ultimate
    /// root (0 for root sources).
    root_offset: u64,
    /// Offset of this source within its direct parent (0 for roots).
    parent_offset: u64,
    len: u64,
}

#[derive(Debug, Clone)]
enum SourceInner {
    Memory(Vec<u8>),
    File {
        path: PathBuf,
        // Not opened eagerly; each read opens/positions via a file handle.
    },
    Child {
        parent: Box<ByteSource>,
    },
}

impl ByteSource {
    /// Source backed by an in-memory buffer.
    pub fn from_vec(data: Vec<u8>) -> Self {
        let len = data.len() as u64;
        ByteSource {
            inner: SourceInner::Memory(data),
            root_offset: 0,
            parent_offset: 0,
            len,
        }
    }

    /// Source backed by a file on disk.
    pub fn from_file(path: &Path) -> Result<Self> {
        let meta = std::fs::metadata(path)?;
        let len = meta.len();
        Ok(ByteSource {
            inner: SourceInner::File {
                path: path.to_path_buf(),
            },
            root_offset: 0,
            parent_offset: 0,
            len,
        })
    }

    /// Cheap bounded slice of a parent source. Bounds-checked eagerly.
    pub fn slice(&self, offset: u64, len: u64) -> Result<Self> {
        if offset.checked_add(len).map_or(true, |end| end > self.len) {
            return Err(Error::OutOfBounds {
                offset,
                len,
                source_len: self.len,
            });
        }
        Ok(ByteSource {
            inner: SourceInner::Child {
                parent: Box::new(self.clone()),
            },
            root_offset: self.root_offset + offset,
            parent_offset: offset,
            len,
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

    /// Backing file path if this source came directly from disk.
    pub fn file_path(&self) -> Option<&Path> {
        match &self.inner {
            SourceInner::File { path } => Some(path),
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
        match &self.inner {
            SourceInner::Memory(data) => {
                let start = offset as usize;
                buf.copy_from_slice(&data[start..start + buf.len()]);
                Ok(())
            }
            SourceInner::File { path } => {
                use std::io::{Read, Seek, SeekFrom};
                let mut file = File::open(path)?;
                file.seek(SeekFrom::Start(offset))?;
                file.read_exact(buf)?;
                Ok(())
            }
            SourceInner::Child { parent } => parent.read_at(self.parent_offset + offset, buf),
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
}
