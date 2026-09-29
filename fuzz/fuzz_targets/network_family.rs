//! Fuzz target: capture formats - PCAP/PCAPNG packet walks and the
//! TCP/HTTP/DNS/USB reconstruction pipeline on hostile frames.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.len() < 64 {
        return;
    }
    let mut body = data.to_vec();
    // Classic PCAP magic + Ethernet linktype.
    body[0..4].copy_from_slice(&[0xD4, 0xC3, 0xB2, 0xA1]);
    body[20..24].copy_from_slice(&1u32.to_le_bytes());
    if body.len() > 200 {
        body[100..104].copy_from_slice(&[0x0A, 0x0D, 0x0D, 0x0A]); // PCAPNG SHB
    }
    let src = binarchae::bytesource::ByteSource::from_vec(body);
    let limits = binarchae::engine::EngineLimits {
        max_child_size: 64 * 1024,
        max_total_expanded_bytes: 1 << 20,
        max_records: 256,
        max_streams: 16,
        max_reconstructed_bytes: 1 << 18,
        ..Default::default()
    };
    let mut budget = binarchae::engine::Budget::default();
    const FORMATS: &[&str] = &["pcap", "pcapng"];
    for handler in binarchae::engine::builtin_handlers() {
        if FORMATS.contains(&handler.format()) {
            let c = binarchae::engine::Candidate { offset: 0 };
            let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let _ = handler.validate(&src, c, &limits, &mut budget);
            }));
        }
    }
});
