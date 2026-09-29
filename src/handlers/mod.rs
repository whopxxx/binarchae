//! Format handlers. Each owns its candidate discovery, structural
//! validation, boundary determination, and child production.

pub mod archives;
pub mod compression;
pub mod cpio;
pub mod cramfs;
pub mod disk;
pub mod exec;
pub mod exfat;
pub mod ext;
pub mod fat;
pub mod filesystems;
pub mod firmware;
pub mod forensics;
pub mod gzip;
pub mod jpeg;
pub mod media;
pub mod net;
pub mod ntfs;
pub mod pdf;
pub mod png;
pub mod recovery;
pub mod romfs;
pub mod sqlite;
pub mod tar;
pub mod uimage;
pub mod xz;
pub mod zip;

/// Shared helper: read a u32 big-endian at `off`, bounds-safe.
pub(crate) fn read_u32_be(src: &crate::bytesource::ByteSource, off: u64) -> Option<u32> {
    let mut b = [0u8; 4];
    src.read_at(off, &mut b).ok()?;
    Some(u32::from_be_bytes(b))
}

/// Shared helper: find all occurrences of `needle` (cheap scan; handlers
/// may use this for footers such as IEND/EOI).
pub(crate) fn find_all(src: &crate::bytesource::ByteSource, needle: &[u8]) -> Vec<u64> {
    let data = match src.read_prefix(64 * 1024 * 1024) {
        Ok(d) => d,
        Err(_) => return Vec::new(),
    };
    let mut hits = Vec::new();
    if needle.is_empty() || data.len() < needle.len() {
        return hits;
    }
    for i in 0..=(data.len() - needle.len()) {
        if &data[i..i + needle.len()] == needle {
            hits.push(i as u64);
        }
    }
    hits
}

/// u16 LE read used by exec/document handlers (kept here for sharing).
pub(crate) fn media_read_u16_le(src: &crate::bytesource::ByteSource, off: u64) -> Option<u16> {
    let mut b = [0u8; 2];
    src.read_at(off, &mut b).ok()?;
    Some(u16::from_le_bytes(b))
}

/// u32 LE read used by exec/document handlers.
pub(crate) fn media_read_u32_le(src: &crate::bytesource::ByteSource, off: u64) -> Option<u32> {
    let mut b = [0u8; 4];
    src.read_at(off, &mut b).ok()?;
    Some(u32::from_le_bytes(b))
}

/// u32 BE read used by exec/document handlers.
pub(crate) fn media_read_u32_be(src: &crate::bytesource::ByteSource, off: u64) -> Option<u32> {
    let mut b = [0u8; 4];
    src.read_at(off, &mut b).ok()?;
    Some(u32::from_be_bytes(b))
}
