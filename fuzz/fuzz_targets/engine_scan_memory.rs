//! Fuzz target: the full recursive engine over arbitrary bytes.
//!
//! The invariant: analysis must never panic, never abort, never read
//! out of bounds — any input is either analyzed into a bounded artifact
//! graph or rejected, under default (tight) limits. Time/size caps come
//! from EngineLimits; libFuzzer's -rss_limit and -max_len add an outer
//! belt on top.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let limits = binwalkx::engine::EngineLimits {
        // Tighter than production defaults so the fuzzer explores deep
        // paths instead of drowning in one huge expansion.
        max_total_expanded_bytes: 1 << 20,
        max_child_size: 128 * 1024,
        max_depth: 6,
        max_artifacts: 256,
        max_records: 512,
        max_partitions: 32,
        max_streams: 32,
        max_reconstructed_bytes: 128 * 1024,
        max_sqlite_pages: 256,
        max_registry_cells: 2048,
        max_string_candidates: 128,
        max_fs_entries: 256,
        ..Default::default()
    };
    let max_artifacts = limits.max_artifacts;
    let src = binwalkx::bytesource::ByteSource::from_vec(data.to_vec());
    let mut engine = binwalkx::engine::RecursiveEngine::new(limits);
    // The engine is panic-isolated by contract; a panic here is a bug
    // and libFuzzer records it via the panic hook.
    let graph = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
        engine.analyze(&src, true)
    }));
    if let Ok(g) = graph {
        // Basic sanity: graph never exceeds the artifact cap.
        assert!(g.len() <= max_artifacts + 1);
    }
});
