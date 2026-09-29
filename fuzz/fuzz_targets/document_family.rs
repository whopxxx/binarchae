//! Fuzz target: documents - PDF object scan/stream carving and OLE
//! directory/FAT chains on hostile structures.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.len() < 64 {
        return;
    }
    let mut body = data.to_vec();
    body[0..5].copy_from_slice(b"%PDF-");
    if body.len() > 11 {
        body[5..11].copy_from_slice(b"1.5\n%\xe2"); // version + comment
    }
    if body.len() > 20 {
        body[10..16].copy_from_slice(&[0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1]); // OLE
    }
    let src = binwalkx::bytesource::ByteSource::from_vec(body);
    let limits = binwalkx::engine::EngineLimits {
        max_child_size: 64 * 1024,
        max_total_expanded_bytes: 1 << 20,
        max_records: 256,
        ..Default::default()
    };
    let mut budget = binwalkx::engine::Budget::default();
    const FORMATS: &[&str] = &["pdf", "ole", "rtf"];
    for handler in binwalkx::engine::builtin_handlers() {
        if FORMATS.contains(&handler.format()) {
            let c = binwalkx::engine::Candidate { offset: 0 };
            let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let _ = handler.validate(&src, c, &limits, &mut budget);
            }));
        }
    }
});
