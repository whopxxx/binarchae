//! Fuzz target: archive family (ZIP / 7z / RAR / TAR / CPIO) -
//! candidate + validate + salvage paths on hostile headers.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.len() < 8 {
        return;
    }
    let (off_bytes, body) = data.split_at(4);
    let offset = u32::from_le_bytes(off_bytes.try_into().unwrap()) as u64 % 4096;
    let mut body = body.to_vec();
    // Sprinkle archive magics so candidate discovery actually fires.
    let magics: [&[u8]; 5] = [
        &b"PK\x03\x04"[..],
        &b"PK\x05\x06"[..],
        &b"7z\xBC\xAF\x27\x1C"[..],
        &b"Rar!\x1A\x07\x00"[..],
        b"070701",
    ];
    for magic in magics {
        if body.len() > magic.len() + 16 {
            let at = (offset as usize) % (body.len() - magic.len());
            body[at..at + magic.len()].copy_from_slice(magic);
        }
    }
    // ustar magic must be at 257 for TAR to be considered.
    if body.len() > 262 {
        body[257..262].copy_from_slice(b"ustar");
    }
    let src = binwalkx::bytesource::ByteSource::from_vec(body);
    let limits = binwalkx::engine::EngineLimits {
        max_child_size: 64 * 1024,
        max_total_expanded_bytes: 1 << 20,
        max_records: 256,
        max_archive_entries: 128,
        ..Default::default()
    };
    let mut budget = binwalkx::engine::Budget::default();
    const FORMATS: &[&str] = &["zip", "zip-salvage", "7z", "rar", "tar", "cpio"];
    for handler in binwalkx::engine::builtin_handlers() {
        if FORMATS.contains(&handler.format()) {
            for off in [0u64, offset] {
                let c = binwalkx::engine::Candidate { offset: off };
                let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    let _ = handler.validate(&src, c, &limits, &mut budget);
                }));
            }
        }
    }
});
