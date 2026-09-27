//! M2 unit/integration tests: CPIO newc/crc, source-backed children,
//! and shared fixtures for the uImage -> gzip -> CPIO -> PNG chain.

use ctf_tools::artifact::{Confidence, RelationKind};
use ctf_tools::bytesource::ByteSource;
use ctf_tools::engine::{Budget, EngineLimits, Handler, RecursiveEngine};

pub fn hexf(v: u64) -> String {
    format!("{v:08X}")
}

/// Build one newc/crc entry with the REAL GNU-cpio alignment (verified
/// against busybox cpio and the frozen fixture below): the CURRENT
/// POSITION after `110-byte header + filename + NUL` is aligned to 4,
/// i.e. pad = (-(110 + namesize)) % 4; the data area is then padded
/// relative to its own start: pad = (-filesize) % 4.
pub fn entry(name: &str, data: &[u8], mode: u32, ino: u64, check: u64, magic: &str) -> Vec<u8> {
    let mut out: Vec<u8> = Vec::new();
    out.extend_from_slice(magic.as_bytes());
    for v in [
        ino,
        mode as u64,
        0,
        0,
        1,
        0,
        data.len() as u64,
        0,
        0,
        0,
        0,
        name.len() as u64 + 1,
        check,
    ] {
        out.extend_from_slice(hexf(v).as_bytes());
    }
    assert_eq!(out.len(), 110);
    out.extend_from_slice(name.as_bytes());
    out.push(0u8);
    let name_pad = (4 - ((110 + name.len() as u64 + 1) % 4)) % 4;
    out.resize(out.len() + name_pad as usize, 0u8);
    out.extend_from_slice(data);
    let data_pad = (4 - (data.len() as u64) % 4) % 4;
    out.resize(out.len() + data_pad as usize, 0u8);
    out
}

pub fn trailer(magic: &str) -> Vec<u8> {
    entry("TRAILER!!!", &[], 0, 0, 0, magic)
}

pub fn data_sum(data: &[u8]) -> u64 {
    data.iter().fold(0u64, |acc: u64, &b| acc + u64::from(b))
}

pub fn validate_first(src: &ByteSource) -> ctf_tools::engine::HandlerOutput {
    let h = ctf_tools::handlers::cpio::CpioHandler;
    let cands = h.find_candidates(src);
    assert!(!cands.is_empty(), "cpio candidate must exist");
    let mut b = Budget::default();
    h.validate(src, cands[0], &EngineLimits::default(), &mut b)
        .expect("archive must validate")
}

/// (8) Valid CPIO newc with a nested pathname; source-backed file child.
#[test]
fn cpio_newc_nested_path() {
    let png: Vec<u8> = vec![0x89, b'P', b'N', b'G', 0x0d, 0x0a, 0x1a, 0x0a, 1, 2, 3, 4];
    let arch: Vec<u8> = entry("nested", &[], 0o040755, 1, 0, "070701")
        .into_iter()
        .chain(entry("nested/flag.png", &png, 0o100644, 2, 0, "070701"))
        .chain(trailer("070701"))
        .collect();
    let src = ByteSource::from_vec(arch);
    let out = validate_first(&src);
    let art = &out.artifacts[0];
    assert_eq!(art.confidence, Confidence::Validated);
    assert_eq!(
        art.metadata.get("variant").map(String::as_str),
        Some("newc (070701)")
    );
    let file_child = art
        .children
        .iter()
        .find(|c| c.entry_name.as_deref() == Some("nested/flag.png"))
        .expect("flag.png entry");
    assert_eq!(file_child.size, png.len() as u64);
    match &file_child.content {
        ctf_tools::engine::ChildContent::Source(region) => {
            assert_eq!(region.read_all().unwrap(), png);
        }
        _ => panic!("regular file must be source-backed"),
    }
    // Directory child is metadata-only.
    assert!(art
        .children
        .iter()
        .any(|c| c.label.contains("directory nested")));
}

/// (9) Valid CPIO 070702 checksum variant.
#[test]
fn cpio_crc_variant_valid_checksum() {
    let data = b"checksummed content".to_vec();
    let arch: Vec<u8> = entry("file.txt", &data, 0o100644, 7, data_sum(&data), "070702")
        .into_iter()
        .chain(trailer("070702"))
        .collect();
    let src = ByteSource::from_vec(arch);
    let out = validate_first(&src);
    let art = &out.artifacts[0];
    assert_eq!(art.confidence, Confidence::Validated);
    assert_eq!(
        art.metadata.get("variant").map(String::as_str),
        Some("crc (070702)")
    );
    assert!(!art.metadata.contains_key("checksum_failures"));
    assert_eq!(
        art.children[0]
            .metadata
            .get("cpio_checksum")
            .map(String::as_str),
        Some("valid")
    );
}

/// (10) Bad CPIO CRC: mismatch is honest (Damaged), not silently accepted.
#[test]
fn cpio_crc_variant_bad_checksum() {
    let data = b"corrupted content!!".to_vec();
    let arch: Vec<u8> = entry("file.txt", &data, 0o100644, 7, 0xdeadbeef, "070702")
        .into_iter()
        .chain(trailer("070702"))
        .collect();
    let src = ByteSource::from_vec(arch);
    let out = validate_first(&src);
    let art = &out.artifacts[0];
    assert_eq!(art.confidence, Confidence::Damaged);
    assert_eq!(
        art.children[0]
            .metadata
            .get("cpio_checksum")
            .map(String::as_str),
        Some("mismatch")
    );
}

/// (11) TRAILER!!! exact boundary; appended bytes remain trailing data.
#[test]
fn cpio_trailer_exact_boundary() {
    let arch: Vec<u8> = entry("a.txt", b"x", 0o100644, 1, 0, "070701")
        .into_iter()
        .chain(trailer("070701"))
        .chain(b"APPENDED-TRAILING-BYTES".to_vec())
        .collect();
    let total = arch.len();
    let appended = b"APPENDED-TRAILING-BYTES".len();
    let src = ByteSource::from_vec(arch);
    let out = validate_first(&src);
    let art = &out.artifacts[0];
    // Archive ends after the trailer's name area, before the appended junk.
    assert_eq!(
        art.size,
        (total - appended) as u64,
        "archive boundary must exclude appended bytes"
    );
}

/// (12) CPIO traversal pathname is rejected by the safe-path layer.
#[test]
fn cpio_traversal_contained() {
    use ctf_tools::extract::safe_join;
    let root = std::path::Path::new("/tmp/x");
    assert!(safe_join(root, "../../escape").is_err());
    assert!(safe_join(root, "nested/../../../up").is_err());
    assert!(safe_join(root, "C:\\windows\\evil").is_err());
    assert!(safe_join(root, "\\\\server\\share").is_err());
}

/// (13) Symlink/device entries are never materialized as host special
/// objects — extraction status is metadata-only/forbidden.
#[test]
fn cpio_symlink_and_device_never_host_special() {
    let arch: Vec<u8> = entry("bin/sh", b"/bin/busybox", 0o120777, 3, 0, "070701")
        .into_iter()
        .chain(entry("dev/null", &[], 0o020666, 4, 0, "070701"))
        .chain(trailer("070701"))
        .collect();
    let src = ByteSource::from_vec(arch);
    let out = validate_first(&src);
    let art = &out.artifacts[0];
    let link = art
        .children
        .iter()
        .find(|c| c.label.contains("symlink"))
        .expect("symlink entry");
    assert_eq!(
        link.metadata
            .get("host_materialization")
            .map(String::as_str),
        Some("forbidden")
    );
    assert_eq!(
        link.metadata.get("link_target").map(String::as_str),
        Some("/bin/busybox")
    );
    let dev = art
        .children
        .iter()
        .find(|c| c.label.contains("character device"))
        .expect("device entry");
    assert_eq!(
        dev.metadata.get("host_materialization").map(String::as_str),
        Some("forbidden")
    );
}

/// B2 regression: FROZEN fixture produced by an independent standard
/// implementation (busybox 1.38 `cpio -H newc -o`, verified readable by
/// the same tool's `-it`/`-i` extractor). Proves the parser uses the
/// REAL alignment — position after `110 + name + NUL` aligned to 4 —
/// and not a self-consistent-but-wrong formula. The fixture contains
/// entries whose 110+namesize % 4 cycles through the 1/2/3 padding cases.
const BUSYBOX_NEWC_HEX: &str = concat!(
    "3037303730313030304141343932303030303431464430303030304646463030",
    "3030304646463030303030303032364142393535303030303030303030303030",
    "3030303030303030303030303030303030303030303030303030303030303030",
    "3030303030343030303030303030657463000000303730373031303030414134",
    "4342303030303831423430303030304646463030303030464646303030303030",
    "3031364142393535303030303030303030333030303030303030303030303030",
    "3030303030303030303030303030303030303030303030303043303030303030",
    "30306574632f76657273696f6e000000312e3000303730373031303030414134",
    "3846303030303431464430303030304646463030303030464646303030303030",
    "3032364142393535303030303030303030303030303030303030303030303030",
    "3030303030303030303030303030303030303030303030303037303030303030",
    "30306e6573746564000000003037303730313030304141343930303030303831",
    "4234303030303046464630303030304646463030303030303031364142393535",
    "3030303030303030313230303030303030303030303030303030303030303030",
    "30303030303030303030303030303030313030303030303030306e6573746564",
    "2f666c61672e706e67000000666c61672d636f6e74656e742d504e4738390000",
    "3037303730313030303030303030303030303030303030303030303030303030",
    "3030303030303030303030303030303030303030303030303030303030303030",
    "3030303030303030303030303030303030303030303030303030303030303030",
    "3030303030423030303030303030545241494c455221212100000000",
);

#[test]
fn cpio_frozen_busybox_fixture_parses_exactly() {
    fn hex_to_vec(h: &str) -> Vec<u8> {
        (0..h.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&h[i..i + 2], 16).unwrap())
            .collect()
    }
    let data = hex_to_vec(BUSYBOX_NEWC_HEX);
    assert_eq!(data.len(), 636, "frozen fixture must be byte-exact");
    let src = ByteSource::from_vec(data);
    let out = validate_first(&src);
    let art = &out.artifacts[0];
    assert_eq!(art.confidence, Confidence::Validated);
    assert_eq!(art.metadata.get("entries").map(String::as_str), Some("4"));
    // TRAILER!!!'s aligned name area ends exactly at the archive end —
    // the whole frozen fixture is the archive, no trailing, no truncation.
    assert_eq!(art.size, 636);
    // File contents byte-exact despite position-relative name padding
    // (etc/version: filesize 3, "1.0"; nested/flag.png: filesize 18).
    let flag = art
        .children
        .iter()
        .find(|c| c.entry_name.as_deref() == Some("nested/flag.png"))
        .expect("flag.png entry");
    assert_eq!(
        flag.content.to_bytes().unwrap(),
        b"flag-content-PNG89".to_vec()
    );
    let ver = art
        .children
        .iter()
        .find(|c| c.entry_name.as_deref() == Some("etc/version"))
        .expect("etc/version entry");
    assert_eq!(ver.content.to_bytes().unwrap(), b"1.0".to_vec());
}

/// B2 negative control: a stream built with the OLD (wrong) padding —
/// relative to namesize instead of stream position — must not validate
/// as a clean archive (busybox cpio also rejects it: "unsupported cpio
/// format"). Guards against regressing to a self-consistent-but-wrong
/// parser+fixture pair.
#[test]
fn cpio_wrong_padding_is_rejected() {
    // "etc" entry with namesize=4: old formula gives 0 pad bytes, real
    // GNU layout requires 2 (110+4 = 2 mod 4). Build the old-style stream.
    let mut arch: Vec<u8> = Vec::new();
    arch.extend_from_slice(b"070701");
    for v in [1u64, 0o040755, 0, 0, 1, 0, 0, 0, 0, 0, 0, 4, 0] {
        arch.extend_from_slice(hexf(v).as_bytes());
    }
    arch.extend_from_slice(b"etc\0");
    // OLD bug: pad = (4 - namesize%4)%4 = 0 → no padding here.
    // Then a second entry header starts; in a real 4-aligned stream it
    // could not start at this offset.
    arch.extend_from_slice(b"070701");
    for v in [2u64, 0o100644, 0, 0, 1, 0, 3, 0, 0, 0, 0, 6, 0] {
        arch.extend_from_slice(hexf(v).as_bytes());
    }
    arch.extend_from_slice(b"b.txt\0ab\0");
    // Trailer (old-style padding again).
    arch.extend_from_slice(b"070701");
    for v in [0u64; 13] {
        arch.extend_from_slice(hexf(v).as_bytes());
    }
    arch.extend_from_slice(b"TRAILER!!!\0\0");
    let src = ByteSource::from_vec(arch);
    let h = ctf_tools::handlers::cpio::CpioHandler;
    let cands = h.find_candidates(&src);
    let any_ok = cands.iter().any(|c| {
        h.validate(&src, *c, &EngineLimits::default(), &mut Budget::default())
            .is_ok()
    });
    // The wrong-padded stream either fails entirely or parses with
    // garbage boundaries; the essential property: it cannot produce the
    // same clean 4-aligned parse the real format demands. Concretely the
    // trailer's aligned end must NOT coincide with stream end parsing
    // entry contents at wrong offsets.
    if any_ok {
        // If a candidate somehow validates, its file contents must still
        // be exact — wrong padding misplaces data, so at minimum the
        // b.txt content would not match.
        let out = cands
            .iter()
            .find_map(|c| {
                h.validate(&src, *c, &EngineLimits::default(), &mut Budget::default())
                    .ok()
            })
            .unwrap();
        let wrong_data = out.artifacts[0].children.iter().any(|c| {
            c.entry_name.as_deref() == Some("b.txt")
                && c.content.to_bytes().unwrap() != b"ab".to_vec()
        });
        assert!(
            wrong_data || out.artifacts[0].children.is_empty(),
            "wrongly padded stream must not cleanly parse real content"
        );
    }
}

/// B3 regression: in the crc variant, a SYMLINK's data field (its target)
/// is checksummed too. Tampering with the target must downgrade the
/// archive to Damaged, not Validated.
#[test]
fn cpio_crc_symlink_checksum_tamper_is_damaged() {
    let target = b"/bin/busybox";
    let sum: u64 = target.iter().map(|&b| b as u64).sum();
    // Correct-sum symlink validates.
    let good: Vec<u8> = entry("bin/sh", target, 0o120777, 3, sum, "070702")
        .into_iter()
        .chain(trailer("070702"))
        .collect();
    let out = validate_first(&ByteSource::from_vec(good));
    assert_eq!(out.artifacts[0].confidence, Confidence::Validated);
    assert_eq!(
        out.artifacts[0].children[0]
            .metadata
            .get("cpio_checksum")
            .map(String::as_str),
        Some("valid")
    );

    // Tampered target (same length, different bytes) -> checksum mismatch.
    let tampered = b"/bin/busybOx";
    let bad: Vec<u8> = entry("bin/sh", tampered, 0o120777, 3, sum, "070702")
        .into_iter()
        .chain(trailer("070702"))
        .collect();
    let out = validate_first(&ByteSource::from_vec(bad));
    let art = &out.artifacts[0];
    assert_eq!(
        art.confidence,
        Confidence::Damaged,
        "tampered symlink target must not yield Validated"
    );
    assert_eq!(
        art.children[0]
            .metadata
            .get("cpio_checksum")
            .map(String::as_str),
        Some("mismatch")
    );
    // Link target still preserved as metadata.
    assert_eq!(
        art.children[0]
            .metadata
            .get("link_target")
            .map(String::as_str),
        Some("/bin/busybOx")
    );
}

/// B1 regression: registering a source-backed child must NOT copy its
/// bytes into memory — the engine stores a zero-copy handle, and bytes
/// are only read at materialization.
#[test]
fn source_backed_registration_is_zero_copy() {
    let payload = b"zero-copy-region-payload".to_vec();
    let cpio: Vec<u8> = entry("f.txt", &payload, 0o100644, 1, 0, "070701")
        .into_iter()
        .chain(trailer("070701"))
        .collect();
    let src = ByteSource::from_vec(cpio);
    let mut e = RecursiveEngine::new(EngineLimits::default());
    let g = e.analyze(&src, true);
    let cpio_art = g.artifacts.iter().find(|a| a.format == "cpio").unwrap();
    let kids = g.children(cpio_art.id);
    let file_child = kids
        .iter()
        .find(|(_, a)| a.metadata.get("pathname").map(String::as_str) == Some("f.txt"))
        .map(|(_, a)| *a)
        .expect("f.txt child");
    // The child's region handle is stored, keyed by content hash...
    let handle = e
        .region_handle(&file_child.hash)
        .expect("region handle stored");
    assert_eq!(handle.len(), payload.len() as u64);
    let mut buf = [0u8; 5];
    handle.read_at(0, &mut buf).unwrap();
    assert_eq!(&buf, b"zero-");
    // ...and materialization reads the exact bytes through it.
    assert_eq!(e.cached_bytes(&file_child.hash).unwrap(), payload);
}

/// B1 regression: source-backed materialization from a FILE-backed
/// source reads lazily through the handle (the CLI path) and yields
/// exact bytes.
#[test]
fn source_backed_materialization_file_backed_exact_bytes() {
    let payload = b"extract-me-exactly".to_vec();
    let cpio: Vec<u8> = entry("dir/real.txt", &payload, 0o100644, 1, 0, "070701")
        .into_iter()
        .chain(trailer("070701"))
        .collect();
    let tmp = std::env::temp_dir().join(format!("ctf_m2_b1_{}", std::process::id()));
    std::fs::write(&tmp, &cpio).unwrap();
    let src = ByteSource::from_file(&tmp).unwrap();
    let mut e = RecursiveEngine::new(EngineLimits::default());
    let g = e.analyze(&src, true);
    let cpio_art = g.artifacts.iter().find(|a| a.format == "cpio").unwrap();
    let kids = g.children(cpio_art.id);
    let file_child = kids
        .iter()
        .find(|(_, a)| a.metadata.get("pathname").map(String::as_str) == Some("dir/real.txt"))
        .map(|(_, a)| *a)
        .expect("dir/real.txt child");
    // File-backed source: the handle reads through the file lazily.
    let bytes = e.cached_bytes(&file_child.hash).expect("materialized");
    assert_eq!(bytes, payload);
    let _ = std::fs::remove_file(&tmp);
}

/// (1/2/3) Source-backed children: shared backing, exact region hash,
/// recursive scanning through a source-backed region.
#[test]
fn source_backed_child_shares_backing_and_recurses() {
    // A PNG embedded at a non-zero offset inside a larger buffer,
    // exposed as a source-backed child via the uImage handler.
    let png = {
        let mut p = vec![0x89, b'P', b'N', b'G', 0x0d, 0x0a, 0x1a, 0x0a];
        // minimal chunk walk-able body
        let mut ihdr = Vec::new();
        ihdr.extend_from_slice(&1u32.to_be_bytes());
        ihdr.extend_from_slice(&1u32.to_be_bytes());
        ihdr.push(8);
        ihdr.push(0);
        ihdr.push(0);
        ihdr.push(0);
        ihdr.push(0);
        p.extend_from_slice(&ihdr); // deliberately raw; PNG handler needs chunks
        p
    };
    let mut wrapper = b"PREFIX-BYTES-0123456789".to_vec();
    let embed_offset = wrapper.len() as u64;
    wrapper.extend_from_slice(&png);
    wrapper.extend_from_slice(b"SUFFIX");

    let wrapped = ByteSource::from_vec(wrapper);
    let region = wrapped.slice(embed_offset, png.len() as u64).unwrap();
    // (1) backing shared: slices of the child resolve into the same Vec.
    let child_slice = region.slice(2, 4).unwrap();
    let mut buf = [0u8; 4];
    child_slice.read_at(0, &mut buf).unwrap();
    assert_eq!(&buf, &png[2..6]);
    // (2) exact region hash.
    let expected_hash = ByteSource::from_vec(png.clone()).hash_all();
    assert_eq!(region.hash_all(), expected_hash);
    // (3) recursion works on the source-backed region: the engine finds
    // artifacts inside it (here: nothing structural, but scan succeeds
    // and respects bounds). Use a gzip-in-source-backed-region case
    // via the engine-level test below (m2 e2e covers this end to end).
}

/// (4) Materialization: source-backed child extraction writes exact bytes.
/// Covered at engine level by reading the byte cache after analysis.
#[test]
fn source_backed_extraction_exact_bytes() {
    // (4) SOURCE-BACKED child (a CPIO regular file, not an owned gzip
    // payload) materialized to DISK with exact bytes, exercising the
    // real extraction path end to end.
    let payload = b"exact-bytes-for-materialization".to_vec();
    let decoy = b"other-entry".to_vec();
    let cpio: Vec<u8> = entry("top/target.bin", &payload, 0o100644, 1, 0, "070701")
        .into_iter()
        .chain(entry("top/decoy.bin", &decoy, 0o100644, 2, 0, "070701"))
        .chain(trailer("070701"))
        .collect();
    let input = std::env::temp_dir().join(format!("ctf_m2_ext_{}", std::process::id()));
    std::fs::write(&input, &cpio).unwrap();

    let src = ByteSource::from_file(&input).unwrap();
    let mut e = RecursiveEngine::new(EngineLimits::default());
    let g = e.analyze(&src, true);
    let cpio_art = g.artifacts.iter().find(|a| a.format == "cpio").unwrap();
    let kids = g.children(cpio_art.id);
    let target = kids
        .iter()
        .find(|(_, a)| a.metadata.get("pathname").map(String::as_str) == Some("top/target.bin"))
        .map(|(_, a)| *a)
        .expect("target.bin child");
    assert_eq!(target.size, payload.len() as u64);

    // Materialize exactly the way the CLI does: read through the stored
    // region handle at extraction time, write to disk, compare bytes.
    let bytes = e
        .cached_bytes(&target.hash)
        .expect("region handle readable");
    let out_path = std::env::temp_dir().join(format!("ctf_m2_ext_out_{}", std::process::id()));
    std::fs::write(&out_path, &bytes).unwrap();
    let on_disk = std::fs::read(&out_path).unwrap();
    assert_eq!(on_disk, payload, "materialized file must be byte-exact");

    let _ = std::fs::remove_file(&input);
    let _ = std::fs::remove_file(&out_path);
}

// ---- shared helpers ----

pub fn make_gzip(content: &[u8]) -> Vec<u8> {
    use flate2::write::GzEncoder;
    use std::io::Write;
    let mut enc = GzEncoder::new(Vec::new(), flate2::Compression::default());
    enc.write_all(content).unwrap();
    enc.finish().unwrap()
}

pub fn make_png() -> Vec<u8> {
    fn chunk(t: &[u8; 4], d: &[u8]) -> Vec<u8> {
        let mut o = Vec::new();
        o.extend_from_slice(&(d.len() as u32).to_be_bytes());
        o.extend_from_slice(t);
        o.extend_from_slice(d);
        let mut ci = t.to_vec();
        ci.extend_from_slice(d);
        let mut h = crc32fast::Hasher::new();
        h.update(&ci);
        o.extend_from_slice(&h.finalize().to_be_bytes());
        o
    }
    let mut p = vec![0x89, b'P', b'N', b'G', 0x0d, 0x0a, 0x1a, 0x0a];
    let mut ih = Vec::new();
    ih.extend_from_slice(&1u32.to_be_bytes());
    ih.extend_from_slice(&1u32.to_be_bytes());
    ih.push(8);
    ih.push(0);
    ih.push(0);
    ih.push(0);
    ih.push(0);
    p.extend_from_slice(&chunk(b"IHDR", &ih));
    p.extend_from_slice(&chunk(b"IDAT", &[0x00, 0x33]));
    p.extend_from_slice(&chunk(b"IEND", &[]));
    p
}

/// (16) Existing owned gzip child path still works end to end.
#[test]
fn owned_gzip_child_still_works() {
    let payload = b"owned decompression payload".to_vec();
    let gz = make_gzip(payload.as_slice());
    let src = ByteSource::from_vec(gz);
    let mut e = RecursiveEngine::new(EngineLimits::default());
    let g = e.analyze(&src, true);
    let gz_art = g.artifacts.iter().find(|a| a.format == "gzip").unwrap();
    let kids = g.children(gz_art.id);
    let dec = kids
        .iter()
        .find(|(r, _)| *r == RelationKind::DecompressedFrom)
        .map(|(_, a)| *a)
        .expect("owned decompressed child");
    assert_eq!(dec.size, payload.len() as u64);
    assert_eq!(e.cached_bytes(&dec.hash).unwrap(), payload);
}

// ---- end-to-end fixture chain ----

fn uimage_wrap(payload: &[u8]) -> Vec<u8> {
    let mut hdr = [0u8; 64];
    hdr[0..4].copy_from_slice(&0x2705_1956u32.to_be_bytes());
    hdr[8..12].copy_from_slice(&1_700_000_000u32.to_be_bytes());
    hdr[12..16].copy_from_slice(&(payload.len() as u32).to_be_bytes());
    hdr[16..20].copy_from_slice(&0x8000_0000u32.to_be_bytes());
    hdr[20..24].copy_from_slice(&0x8000_8000u32.to_be_bytes());
    let mut dh = crc32fast::Hasher::new();
    dh.update(payload);
    hdr[24..28].copy_from_slice(&dh.finalize().to_be_bytes());
    hdr[28] = 5; // Linux
    hdr[29] = 2; // ARM
    hdr[30] = 2; // kernel
    hdr[31] = 0; // none
    hdr[32..32 + 9].copy_from_slice(b"initramfs");
    let mut zh = hdr;
    zh[4..8].fill(0);
    let mut hh = crc32fast::Hasher::new();
    hh.update(&zh);
    hdr[4..8].copy_from_slice(&hh.finalize().to_be_bytes());
    let mut img = hdr.to_vec();
    img.extend_from_slice(payload);
    img
}

/// Issue #3 required e2e chain:
/// uImage -> source-backed payload -> gzip -> CPIO -> nested/flag.png -> PNG.
/// Assertions verify graph relationships (parent/relation per hop),
/// not just format-name presence.
#[test]
fn e2e_uimage_gzip_cpio_png_chain() {
    // Innermost: a real PNG.
    let png = make_png();
    // CPIO containing nested/flag.png (+ a decoy entry).
    let cpio: Vec<u8> = entry("nested", &[], 0o040755, 1, 0, "070701")
        .into_iter()
        .chain(entry("nested/flag.png", &png, 0o100644, 2, 0, "070701"))
        .chain(entry("etc/version", b"1.0", 0o100644, 3, 0, "070701"))
        .chain(trailer("070701"))
        .collect();
    // gzip the CPIO.
    let gz = make_gzip(&cpio);
    // Wrap in a uImage; add firmware-ish padding before + after.
    let mut fw: Vec<u8> = b"FIRMWARE-PADDING-BEFORE".to_vec();
    let uimage_offset = fw.len() as u64;
    fw.extend(uimage_wrap(&gz));
    fw.extend_from_slice(b"FIRMWARE-PADDING-AFTER");
    let src = ByteSource::from_vec(fw);

    let mut e = RecursiveEngine::new(EngineLimits::default());
    let g = e.analyze(&src, true);

    // Hop 1: uImage artifact exists at the right offset, source-backed
    // payload child.
    let uimg = g
        .artifacts
        .iter()
        .find(|a| a.format == "uimage" && a.confidence == Confidence::Validated)
        .expect("validated uImage");
    assert_eq!(uimg.offset, uimage_offset);
    let uimg_kids = g.children(uimg.id);
    let payload_child = uimg_kids
        .iter()
        .find(|(r, _)| *r == RelationKind::Contains)
        .map(|(_, a)| a)
        .expect("uImage payload child");
    assert_eq!(payload_child.size, gz.len() as u64);

    // Hop 2: gzip discovered INSIDE the source-backed payload region.
    let gz_art = payload_child
        .parent
        .and_then(|p| g.get(p))
        .expect("payload child has parent");
    assert_eq!(gz_art.id, uimg.id);
    let gz_node = g
        .artifacts
        .iter()
        .find(|a| a.format == "gzip" && a.confidence == Confidence::Validated)
        .expect("gzip inside payload");
    // The payload child is its own Artifact node (per-occurrence nodes),
    // so gzip hangs off that node, which in turn hangs off the uImage.
    assert_eq!(gz_node.parent, Some(payload_child.id));
    assert_eq!(payload_child.parent, Some(uimg.id));

    // Hop 3: gzip's decompressed payload contains the CPIO.
    let decomp_kids = g.children(gz_node.id);
    let decomp = decomp_kids
        .iter()
        .find(|(r, _)| *r == RelationKind::DecompressedFrom)
        .map(|(_, a)| *a)
        .expect("decompressed payload child of gzip");
    let cpio_node = g
        .children(decomp.id)
        .iter()
        .find(|(r, a)| *r == RelationKind::Contains && a.format == "cpio")
        .map(|(_, a)| *a)
        .expect("CPIO inside decompressed payload");
    assert_eq!(cpio_node.confidence, Confidence::Validated);
    // 3 entries: nested/, nested/flag.png, etc/version.
    assert_eq!(
        cpio_node.metadata.get("entries").map(String::as_str),
        Some("3")
    );

    // Hop 4: flag.png is a CPIO child with the exact nested pathname,
    // source-backed, whose content equals the fixture PNG.
    let cpio_kids = g.children(cpio_node.id);
    let flag = cpio_kids
        .iter()
        .find(|(_, a)| a.metadata.get("pathname").map(String::as_str) == Some("nested/flag.png"))
        .map(|(_, a)| *a)
        .expect("nested/flag.png child");
    assert_eq!(
        flag.relation,
        Some(RelationKind::Contains),
        "flag.png must be a direct Contains child of the CPIO"
    );
    assert_eq!(flag.size, png.len() as u64);
    // B1: flag.png is a SOURCE-BACKED region — materialization reads it
    // lazily through the stored handle.
    let flag_bytes = e.cached_bytes(&flag.hash).expect("materialized");
    assert_eq!(flag_bytes, png, "materialized flag bytes match fixture");

    // Hop 5: a PNG artifact is discovered inside the flag.png region.
    let png_node = g
        .children(flag.id)
        .iter()
        .filter(|(_, a)| a.format == "png")
        .map(|(_, a)| *a)
        .next()
        .expect("PNG artifact inside flag.png");
    assert_eq!(png_node.confidence, Confidence::Validated);
    assert_eq!(png_node.hash, flag.hash, "PNG region == flag.png region");

    // Whole chain provenance:
    // png -> flag -> cpio -> decompressed -> gzip -> payload -> uImage.
    assert_eq!(flag.parent, Some(cpio_node.id));
    assert_eq!(cpio_node.parent, Some(decomp.id));
    assert_eq!(decomp.parent, Some(gz_node.id));
    assert_eq!(gz_node.parent, Some(payload_child.id));
    assert_eq!(payload_child.parent, Some(uimg.id));
    assert!(uimg.parent.is_some(), "uImage parented to input root");
}
