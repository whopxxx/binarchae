//! Fuzz target: firmware headers - UEFI FV, Android sparse, BCM63xx
//! tag, Android boot, TRX, DTB, uImage on hostile structures.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.len() < 512 {
        return;
    }
    let (off_bytes, body_bytes) = data.split_at(4);
    let offset = u32::from_le_bytes(off_bytes.try_into().unwrap()) as u64 % 512;
    let mut body = body_bytes.to_vec();
    if body.len() > 8 {
        body[0..4].copy_from_slice(&0xED26FF3Au32.to_le_bytes()); // sparse
    }
    if body.len() > 24 {
        body[4..23].copy_from_slice(b"Broadcom Corporatio");
    }
    if body.len() > 0x2C {
        body[0x28..0x2C].copy_from_slice(b"_FVH"); // UEFI FV
    }
    let src = ctf_tools::bytesource::ByteSource::from_vec(body);
    let limits = ctf_tools::engine::EngineLimits {
        max_child_size: 64 * 1024,
        max_total_expanded_bytes: 1 << 20,
        max_records: 256,
        ..Default::default()
    };
    let mut budget = ctf_tools::engine::Budget::default();
    const FORMATS: &[&str] = &[
        "android-sparse", "bcm63xx-tag", "android-boot", "trx", "uefi-fv",
        "dtb", "uimage",
    ];
    for handler in ctf_tools::engine::builtin_handlers() {
        if FORMATS.contains(&handler.format()) {
            let c = ctf_tools::engine::Candidate { offset };
            let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let _ = handler.validate(&src, c, &limits, &mut budget);
            }));
        }
    }
});
