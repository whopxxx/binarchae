//! Fuzz target: memory forensics - Minidump streams and PAGEDU64
//! physical-run tables on hostile headers.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.len() < 8192 {
        return;
    }
    let mut body = data.to_vec();
    // Minidump header: 3 streams, directory at 32.
    body[0..4].copy_from_slice(b"MDMP");
    body[4..8].copy_from_slice(&42899u32.to_le_bytes());
    body[8..12].copy_from_slice(&3u32.to_le_bytes());
    body[12..16].copy_from_slice(&32u32.to_le_bytes());
    // PAGEDU64 signature + 2 runs at 0x88 (different region).
    if body.len() > 0x3000 {
        body[0x2000..0x2008].copy_from_slice(b"PAGEDU64");
        body[0x2088..0x208C].copy_from_slice(&2u32.to_le_bytes());
    }
    let src = binwalkx::bytesource::ByteSource::from_vec(body);
    let limits = binwalkx::engine::EngineLimits {
        max_child_size: 64 * 1024,
        max_total_expanded_bytes: 1 << 20,
        max_records: 256,
        ..Default::default()
    };
    let mut budget = binwalkx::engine::Budget::default();
    const FORMATS: &[&str] = &["minidump", "pagedu64"];
    for handler in binwalkx::engine::builtin_handlers() {
        if FORMATS.contains(&handler.format()) {
            let c = binwalkx::engine::Candidate { offset: 0 };
            let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let _ = handler.validate(&src, c, &limits, &mut budget);
            }));
        }
    }
});
