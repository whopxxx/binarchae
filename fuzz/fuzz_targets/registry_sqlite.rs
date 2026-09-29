//! Fuzz target: structured databases - Registry hive cells and SQLite
//! pages/overflow (hostile record/blob payloads).

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.len() < 8192 {
        return;
    }
    let mut body = data.to_vec();
    // Registry: regf header + hbin at 4096 with hostile cells.
    body[0..4].copy_from_slice(b"regf");
    body[4096..4100].copy_from_slice(b"hbin");
    body[4104..4108].copy_from_slice(&4096u32.to_le_bytes());
    for at in [4128usize, 4200, 4300, 4400] {
        if at + 4 <= body.len() {
            body[at..at + 2].copy_from_slice(if at % 2 == 0 { b"nk" } else { b"vk" });
        }
    }
    // SQLite header.
    if body.len() > 2048 {
        body[2048..2064].copy_from_slice(b"SQLite format 3\0");
        body[2048 + 100] = 0x0D;
    }
    let src = binwalkx::bytesource::ByteSource::from_vec(body);
    let limits = binwalkx::engine::EngineLimits {
        max_child_size: 64 * 1024,
        max_total_expanded_bytes: 1 << 20,
        max_records: 256,
        max_sqlite_pages: 128,
        max_registry_cells: 4096,
        ..Default::default()
    };
    let mut budget = binwalkx::engine::Budget::default();
    const FORMATS: &[&str] = &["registry", "sqlite"];
    for handler in binwalkx::engine::builtin_handlers() {
        if FORMATS.contains(&handler.format()) {
            let c = binwalkx::engine::Candidate { offset: 0 };
            let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let _ = handler.validate(&src, c, &limits, &mut budget);
            }));
        }
    }
});
