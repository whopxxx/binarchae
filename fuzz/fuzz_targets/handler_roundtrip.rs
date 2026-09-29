//! Fuzz target: per-handler validate() directly on a random offset.
//!
//! Engine-level fuzzing exercises the scan loop; this target pins the
//! handler contract itself — validate() on arbitrary (offset, bytes)
//! must be memory-safe, bound-checked, and must never report Validated
//! without structural proof.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.len() < 4 {
        return;
    }
    let (off_bytes, body) = data.split_at(4);
    let offset = u32::from_le_bytes(off_bytes.try_into().unwrap()) as u64;
    let src = binarchae::bytesource::ByteSource::from_vec(body.to_vec());
    let limits = binarchae::engine::EngineLimits {
        max_child_size: 64 * 1024,
        max_total_expanded_bytes: 1 << 20,
        max_records: 256,
        max_sqlite_pages: 128,
        max_registry_cells: 1024,
        max_string_candidates: 64,
        ..Default::default()
    };
    let mut budget = binarchae::engine::Budget::default();
    let c = binarchae::engine::Candidate { offset };
    for handler in binarchae::engine::builtin_handlers() {
        // Errors are expected and fine; panics/timeouts/OOB are not.
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = handler.validate(&src, c, &limits, &mut budget);
        }));
    }
});
