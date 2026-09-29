//! Fuzz target: filesystem metadata (FAT / exFAT / NTFS / ext /
//! SquashFS / ISO / JFFS2 / UBI / UBIFS / YAFFS2 / ROMFS / cramfs).

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.len() < 512 {
        return;
    }
    let (off_bytes, body) = data.split_at(4);
    let offset = u32::from_le_bytes(off_bytes.try_into().unwrap()) as u64 % 4096;
    let mut body = body.to_vec();
    if body.len() > 11 {
        body[0..3].copy_from_slice(&[0xEB, 0x3C, 0x90]); // FAT jump
        body[3..11].copy_from_slice(b"NTFS    ");
    }
    if body.len() > 0x43A {
        body[0x438..0x43A].copy_from_slice(&0xEF53u16.to_le_bytes()); // ext
    }
    if body.len() > 0x21 {
        body[0x1D..0x21].copy_from_slice(b"hsqs"); // squashfs LE
    }
    if body.len() > 0x9015 {
        body[0x9001..0x9006].copy_from_slice(b"CD001"); // ISO PVD
    }
    let src = ctf_tools::bytesource::ByteSource::from_vec(body);
    let limits = ctf_tools::engine::EngineLimits {
        max_child_size: 64 * 1024,
        max_total_expanded_bytes: 1 << 20,
        max_records: 256,
        max_fs_entries: 128,
        max_registry_cells: 1024,
        ..Default::default()
    };
    let mut budget = ctf_tools::engine::Budget::default();
    const FORMATS: &[&str] = &[
        "fat", "exfat", "ntfs", "ext", "squashfs", "iso9660", "jffs2",
        "ubi", "ubifs", "yaffs2", "romfs", "cramfs",
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
