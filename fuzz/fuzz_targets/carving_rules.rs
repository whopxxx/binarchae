//! Fuzz target: user TOML carving rules + rule application.
//!
//! Covers the config-parsing surface (untrusted rule files) and the
//! carving loop itself, including malformed hex, empty headers, and
//! max_size floods.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }
    let (rule_bytes, body) = if data.len() > 16 {
        data.split_at(data.len() / 2)
    } else {
        (data, data)
    };
    let Ok(rule_text) = std::str::from_utf8(rule_bytes) else {
        return;
    };
    // Rule parsing must never panic on arbitrary text.
    if let Ok(rules) = binarchae::carving::parse_user_rules(rule_text) {
        let src = binarchae::bytesource::ByteSource::from_vec(body.to_vec());
        let limits = binarchae::engine::EngineLimits::default();
        let mut budget = binarchae::engine::Budget::default();
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = binarchae::carving::carve_with_rules(&src, &limits, &mut budget, &rules);
        }));
    }
});
