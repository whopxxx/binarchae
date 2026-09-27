//! Format handlers. Each owns its candidate discovery, structural
//! validation, boundary determination, and child production.

pub mod gzip;
pub mod jpeg;
pub mod pdf;
pub mod png;
pub mod tar;
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
