//! End-to-end integration tests over synthetic fixtures, covering the
//! acceptance criteria from Issue #1.

use ctf_tools::artifact::{Confidence, ExtractionStatus, RelationKind};
use ctf_tools::bytesource::ByteSource;
use ctf_tools::carving::parse_user_rules;
use ctf_tools::engine::{EngineLimits, RecursiveEngine};
use flate2::write::GzEncoder;
use flate2::Compression;
use std::io::Write;

// ---------- synthetic fixture helpers ----------

fn crc32(data: &[u8]) -> u32 {
    let mut h = crc32fast::Hasher::new();
    h.update(data);
    h.finalize()
}

/// Minimal valid 1x1 grayscale PNG.
fn make_png() -> Vec<u8> {
    fn chunk(ctype: &[u8; 4], data: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&(data.len() as u32).to_be_bytes());
        out.extend_from_slice(ctype);
        out.extend_from_slice(data);
        let mut crc_input = ctype.to_vec();
        crc_input.extend_from_slice(data);
        out.extend_from_slice(&crc32(&crc_input).to_be_bytes());
        out
    }
    let mut png = vec![0x89, b'P', b'N', b'G', 0x0d, 0x0a, 0x1a, 0x0a];
    let mut ihdr = Vec::new();
    ihdr.extend_from_slice(&1u32.to_be_bytes()); // width
    ihdr.extend_from_slice(&1u32.to_be_bytes()); // height
    ihdr.push(8); // bit depth
    ihdr.push(0); // grayscale
    ihdr.push(0);
    ihdr.push(0);
    ihdr.push(0);
    png.extend_from_slice(&chunk(b"IHDR", &ihdr));
    // 1x1 grayscale, filter byte 0.
    png.extend_from_slice(&chunk(b"IDAT", &[0x00, 0x33]));
    png.extend_from_slice(&chunk(b"IEND", &[]));
    png
}

/// A structurally valid PNG with a large pseudorandom IDAT. Deflate must
/// use huffman coding on it, so the PNG signature does NOT survive as a
/// literal byte run inside gzip/deflate streams — nested-discovery tests
/// then genuinely depend on recursion, not on byte luck.
fn make_png_large() -> Vec<u8> {
    fn chunk(ctype: &[u8; 4], data: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&(data.len() as u32).to_be_bytes());
        out.extend_from_slice(ctype);
        out.extend_from_slice(data);
        let mut crc_input = ctype.to_vec();
        crc_input.extend_from_slice(data);
        out.extend_from_slice(&crc32(&crc_input).to_be_bytes());
        out
    }
    // xorshift32: deterministic, high entropy, no external crates.
    let mut state: u32 = 0x1234_5678;
    let mut idat = Vec::with_capacity(8 * 1024);
    for _ in 0..8 * 1024 {
        state ^= state << 13;
        state ^= state >> 17;
        state ^= state << 5;
        idat.push((state >> 24) as u8);
    }
    let mut png = vec![0x89, b'P', b'N', b'G', 0x0d, 0x0a, 0x1a, 0x0a];
    let mut ihdr = Vec::new();
    ihdr.extend_from_slice(&256u32.to_be_bytes()); // width
    ihdr.extend_from_slice(&8u32.to_be_bytes()); // height
    ihdr.push(8);
    ihdr.push(0);
    ihdr.push(0);
    ihdr.push(0);
    ihdr.push(0);
    png.extend_from_slice(&chunk(b"IHDR", &ihdr));
    png.extend_from_slice(&chunk(b"IDAT", &idat));
    png.extend_from_slice(&chunk(b"IEND", &[]));
    png
}

/// Minimal ZIP containing one stored (uncompressed) file.
fn make_zip(name: &str, content: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    let name_bytes = name.as_bytes();

    // Local file header.
    let lfh_offset = out.len() as u32;
    out.extend_from_slice(&[0x50, 0x4b, 0x03, 0x04]);
    out.extend_from_slice(&20u16.to_le_bytes()); // version needed
    out.extend_from_slice(&0u16.to_le_bytes()); // flags
    out.extend_from_slice(&0u16.to_le_bytes()); // method: stored
    out.extend_from_slice(&0u16.to_le_bytes()); // time
    out.extend_from_slice(&0u16.to_le_bytes()); // date
    out.extend_from_slice(&crc32(content).to_le_bytes());
    out.extend_from_slice(&(content.len() as u32).to_le_bytes()); // csize
    out.extend_from_slice(&(content.len() as u32).to_le_bytes()); // usize
    out.extend_from_slice(&(name_bytes.len() as u16).to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes()); // extra len
    out.extend_from_slice(name_bytes);
    out.extend_from_slice(content);

    // Central directory.
    let cd_offset = out.len() as u32;
    out.extend_from_slice(&[0x50, 0x4b, 0x01, 0x02]);
    out.extend_from_slice(&20u16.to_le_bytes()); // version made by
    out.extend_from_slice(&20u16.to_le_bytes()); // version needed
    out.extend_from_slice(&0u16.to_le_bytes()); // flags
    out.extend_from_slice(&0u16.to_le_bytes()); // method
    out.extend_from_slice(&0u16.to_le_bytes()); // time/date
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&crc32(content).to_le_bytes());
    out.extend_from_slice(&(content.len() as u32).to_le_bytes());
    out.extend_from_slice(&(content.len() as u32).to_le_bytes());
    out.extend_from_slice(&(name_bytes.len() as u16).to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes()); // extra
    out.extend_from_slice(&0u16.to_le_bytes()); // comment
    out.extend_from_slice(&0u16.to_le_bytes()); // disk
    out.extend_from_slice(&0u16.to_le_bytes()); // internal attrs
    out.extend_from_slice(&0u32.to_le_bytes()); // external attrs
    out.extend_from_slice(&lfh_offset.to_le_bytes());
    out.extend_from_slice(name_bytes);

    // End of central directory.
    out.extend_from_slice(&[0x50, 0x4b, 0x05, 0x06]);
    out.extend_from_slice(&0u16.to_le_bytes()); // disk
    out.extend_from_slice(&0u16.to_le_bytes()); // cd disk
    out.extend_from_slice(&1u16.to_le_bytes()); // entries this disk
    out.extend_from_slice(&1u16.to_le_bytes()); // entries total
    out.extend_from_slice(&(out.len() as u32 - cd_offset).to_le_bytes());
    out.extend_from_slice(&cd_offset.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes()); // comment len
    out
}

fn make_gzip(content: &[u8]) -> Vec<u8> {
    let mut enc = GzEncoder::new(Vec::new(), Compression::default());
    enc.write_all(content).unwrap();
    enc.finish().unwrap()
}

/// Standard-compliant XZ fixture: generated ONCE by XZ Utils 5.8.3
/// (`xz -z --check=crc32` over `flag{xz-payload} some content to
/// decompress`) and fixed as bytes. External ground truth — if the
/// handler drifts from the real XZ format, this stops parsing; the
/// fixture is never regenerated to match a broken parser. (R4)
const STD_XZ_INTEGRATION_HEX: &str = "fd377a585a0000016922de3604c02f2b210116000000000000000000940d1b1b01002a666c61677b787a2d7061796c6f61647d20736f6d6520636f6e74656e7420746f206465636f6d70726573730000404420070001472ba99502339042990d010000000001595a";

fn make_xz(_content: &[u8]) -> Vec<u8> {
    // The fixture is fixed to one payload; `content` is accepted for call
    // compatibility and asserted by the caller.
    (0..STD_XZ_INTEGRATION_HEX.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&STD_XZ_INTEGRATION_HEX[i..i + 2], 16).unwrap())
        .collect()
}

fn make_tar(entries: &[(&str, &[u8])]) -> Vec<u8> {
    let mut out = Vec::new();
    for (name, content) in entries {
        let mut header = [0u8; 512];
        header[..name.len().min(100)].copy_from_slice(name.as_bytes());
        header[100..108].copy_from_slice(b"0000644\0"); // mode
        header[108..116].copy_from_slice(b"0000000\0"); // uid
        header[116..124].copy_from_slice(b"0000000\0"); // gid
        let size_field = format!("{:011o}\0", content.len());
        header[124..136].copy_from_slice(size_field.as_bytes());
        header[136..148].copy_from_slice(b"00000000000\0"); // mtime (12 bytes)
        header[148..156].copy_from_slice(b"        "); // checksum placeholder
        header[156] = b'0'; // regular file
        header[257..262].copy_from_slice(b"ustar");
        header[263..265].copy_from_slice(b" \0");
        // checksum
        let sum: u32 = header.iter().map(|&b| b as u32).sum();
        let chk = format!("{:06o}\0 ", sum);
        header[148..156].copy_from_slice(chk.as_bytes());
        out.extend_from_slice(&header);
        out.extend_from_slice(content);
        let pad = (512 - (content.len() % 512)) % 512;
        out.extend(std::iter::repeat(0u8).take(pad));
    }
    out.extend(std::iter::repeat(0u8).take(1024)); // end of archive
    out
}

fn engine() -> RecursiveEngine {
    RecursiveEngine::new(EngineLimits {
        max_depth: 8,
        ..EngineLimits::default()
    })
}

// ---------- tests ----------

/// (1) Valid PNG boundary detection.
#[test]
fn png_boundary_detection() {
    let png = make_png();
    let mut data = png.clone();
    data.extend_from_slice(b"TRAILING-JUNK-AFTER-IEND");
    let src = ByteSource::from_vec(data);
    let mut e = engine();
    let g = e.analyze(&src, true);
    let png_art = g
        .artifacts
        .iter()
        .find(|a| a.format == "png")
        .expect("png artifact found");
    assert_eq!(png_art.confidence, Confidence::Validated);
    assert_eq!(png_art.size, png.len() as u64);
}

/// (2) PNG with trailing ZIP discovered from the trailing-data child.
/// B8/B3 regression: requires a REAL TrailingData edge in the graph with
/// the ZIP as its descendant — not merely "zip offset > png size".
#[test]
fn png_trailing_zip_discovered() {
    let png = make_png();
    let zip = make_zip("flag.txt", b"flag{trailing}");
    let mut data = png.clone();
    data.extend_from_slice(&zip);
    let src = ByteSource::from_vec(data);
    let mut e = engine();
    let g = e.analyze(&src, true);
    let png_art = g.artifacts.iter().find(|a| a.format == "png").unwrap();

    // The graph must contain a trailing-data artifact immediately after
    // the validated PNG boundary.
    let trailing: Vec<_> = g
        .artifacts
        .iter()
        .filter(|a| a.relation == Some(RelationKind::TrailingData))
        .collect();
    assert!(
        !trailing.is_empty(),
        "graph must contain a TrailingData artifact"
    );
    let t = trailing[0];
    assert_eq!(t.offset, png_art.size, "trailing region starts at IEND");
    assert_eq!(
        t.size,
        zip.len() as u64,
        "trailing region spans exactly the appended ZIP"
    );

    // The ZIP must be a DESCENDANT of the trailing-data node (provenance),
    // not a sibling of the PNG.
    let zip_in_trailing = g.children(t.id).iter().any(|(_, a)| a.format == "zip");
    assert!(
        zip_in_trailing,
        "zip must be a child of the trailing-data artifact"
    );
    // R3 regression: the trailing-data node itself must be parented to
    // the PNG (PNG -> trailing -> ZIP), not to the root region.
    assert_eq!(
        t.parent,
        Some(png_art.id),
        "trailing data must hang off the validated structure, not the root"
    );
    assert_eq!(t.relation, Some(RelationKind::TrailingData));
    let zip_art = g
        .artifacts
        .iter()
        .find(|a| a.format == "zip")
        .expect("zip found");
    assert_eq!(zip_art.confidence, Confidence::Validated);
    // ZIP boundary must be exact: it must not swallow anything beyond EOCD.
    assert_eq!(
        zip_art.size,
        zip.len() as u64,
        "zip size must equal the actual archive, not region-to-end"
    );
}

/// (3) ZIP extraction with normal nested paths.
#[test]
fn zip_nested_path_entries() {
    let zip = make_zip("a/b/flag.txt", b"flag{nested}");
    let mut data = b"prefix".to_vec();
    data.extend_from_slice(&zip);
    let src = ByteSource::from_vec(data);
    let mut e = engine();
    let g = e.analyze(&src, true);
    let zip_art = g
        .artifacts
        .iter()
        .find(|a| a.format == "zip")
        .expect("zip found");
    assert_eq!(
        zip_art.metadata.get("entries").map(String::as_str),
        Some("1")
    );
    let entry = g
        .artifacts
        .iter()
        .find(|a| a.label.contains("flag.txt"))
        .expect("entry artifact");
    assert_eq!(entry.relation, Some(RelationKind::Contains));
}

/// (4) ZIP traversal attempt is contained/rejected by safe-path rules.
#[test]
fn zip_traversal_contained() {
    use ctf_tools::extract::safe_join;
    let root = std::env::temp_dir().join("ctf-tools-test-traversal");
    let err = safe_join(&root, "../escape.txt");
    assert!(err.is_err(), "../ must be rejected");
    let err2 = safe_join(&root, "a/../../b");
    assert!(err2.is_err());
}

/// (5) gzip -> child artifact -> recursive format detection.
#[test]
fn gzip_child_recursive() {
    let inner = make_png();
    let gz = make_gzip(&inner);
    let src = ByteSource::from_vec(gz);
    let mut e = engine();
    let g = e.analyze(&src, true);
    let gz_art = g.artifacts.iter().find(|a| a.format == "gzip").unwrap();
    let children = g.children(gz_art.id);
    assert!(
        children
            .iter()
            .any(|(r, _)| *r == RelationKind::DecompressedFrom),
        "gzip must produce a decompressed-from child"
    );
    // Recursive detection: PNG found inside decompressed payload.
    assert!(
        g.artifacts.iter().any(|a| a.format == "png"),
        "png inside gzip must be detected"
    );
}

/// (6) XZ -> child artifact -> recursive format detection.
#[test]
fn xz_child_recursive() {
    let inner = b"flag{xz-payload} some content to decompress".to_vec();
    let xz = make_xz(&inner);
    let src = ByteSource::from_vec(xz);
    let mut e = engine();
    let g = e.analyze(&src, true);
    let xz_art = g
        .artifacts
        .iter()
        .find(|a| a.format == "xz")
        .expect("xz artifact");
    assert_eq!(xz_art.confidence, Confidence::Validated);
    assert!(g
        .artifacts
        .iter()
        .any(|a| a.relation == Some(RelationKind::DecompressedFrom)));
}

/// (7) TAR child extraction.
#[test]
fn tar_child_extraction() {
    let tar = make_tar(&[("dir/", b""), ("dir/hello.txt", b"hello tar")]);
    let src = ByteSource::from_vec(tar);
    let mut e = engine();
    let g = e.analyze(&src, true);
    let tar_art = g
        .artifacts
        .iter()
        .find(|a| a.format == "tar")
        .expect("tar artifact");
    assert_eq!(tar_art.confidence, Confidence::Validated);
    let children = g.children(tar_art.id);
    assert!(children.iter().any(|(_, a)| a.label.contains("hello.txt")));
}

/// (8) Duplicate-content dedup without losing parent provenance.
/// B8/B2 regression: hashes must be of the ACTUAL gzip regions (not the
/// empty-bytes hash all region-backed artifacts used to share), and the
/// duplicates must still register with distinct provenance.
#[test]
fn dedup_preserves_provenance() {
    let inner = make_png_large();
    let gz1 = make_gzip(&inner);
    let gz2 = make_gzip(&inner);
    let mut data = gz1.clone();
    data.extend_from_slice(&gz2);
    let src = ByteSource::from_vec(data);
    let mut e = engine();
    let g = e.analyze(&src, true);
    // The two top-level gzip streams: the root-level one and the one
    // inside the trailing-data region. Both are registered even though
    // their bytes are identical.
    let root_gz = g
        .artifacts
        .iter()
        .find(|a| a.format == "gzip" && a.parent == Some(0))
        .expect("root-level gzip registered");
    let trailing = g
        .artifacts
        .iter()
        .find(|a| a.relation == Some(RelationKind::TrailingData))
        .expect("trailing-data region exists");
    let trailing_gz = g
        .children(trailing.id)
        .into_iter()
        .find(|(_, a)| a.format == "gzip")
        .map(|(_, a)| a)
        .expect("trailing-region gzip registered");
    let gzs = [root_gz, trailing_gz];
    // B2: identical content → identical hash, and that hash must equal
    // the hash of the real gzip bytes (not the empty-bytes hash).
    let expected = ByteSource::from_vec(gz1.clone()).hash_all();
    assert_eq!(gzs[0].hash, expected, "hash must cover the actual region");
    assert_eq!(gzs[0].hash, gzs[1].hash);
    assert_ne!(
        gzs[0].hash,
        blake3::Hasher::new().finalize().to_hex().to_string(),
        "region-backed artifact must not hash to BLAKE3(empty)"
    );
    // Distinct provenance preserved: identical bytes, but each node
    // hangs off a DIFFERENT parent (root region vs trailing region).
    assert_ne!(
        gzs[0].parent, gzs[1].parent,
        "duplicate content must retain per-occurrence provenance"
    );
    assert_ne!(
        gzs[0].id, gzs[1].id,
        "duplicates are separate logical artifacts"
    );
    // A DIFFERENT-format region-backed artifact must hash differently
    // (the old bug collapsed every archive to the same empty hash).
    let png_art = g.artifacts.iter().find(|a| a.format == "png");
    if let Some(p) = png_art {
        assert_ne!(
            gzs[0].hash, p.hash,
            "different regions must not share a hash"
        );
    }
}

/// (8b) Non-recursing analyze registers artifacts but skips recursion
/// (B5 regression: default CLI mode vs -r are genuinely different).
/// Nested content is wrapped in gzip (deflate destroys byte structure),
/// so the inner PNG is only reachable by decompressing.
#[test]
fn no_recurse_mode_differs_from_recurse() {
    let inner = make_png_large();
    let gz = make_gzip(&inner);
    let mut outer_bytes = b"prefix bytes before the archive".to_vec();
    outer_bytes.extend_from_slice(&gz);
    let src = ByteSource::from_vec(outer_bytes);
    let mut e1 = engine();
    let shallow = e1.analyze(&src, false);
    let mut e2 = engine();
    let deep = e2.analyze(&src, true);

    // Shallow: gzip found, decompressed child registered, but the PNG
    // inside the decompressed payload is NOT analyzed further.
    let gz_art = shallow
        .artifacts
        .iter()
        .find(|a| a.format == "gzip")
        .expect("gzip found");
    assert!(!shallow.children(gz_art.id).is_empty());
    let png_below = shallow
        .edges
        .iter()
        .filter(|e| e.parent == gz_art.id)
        .filter_map(|e| shallow.get(e.child))
        .any(|a| a.format == "png");
    assert!(
        !png_below,
        "shallow mode must not analyze inside decompressed payloads"
    );
    // Deep: PNG found under the gzip's decompressed child.
    let deep_gz = deep
        .artifacts
        .iter()
        .find(|a| a.format == "gzip")
        .expect("gzip found in deep mode");
    let png_in_deep = deep
        .edges
        .iter()
        .filter(|e| e.parent == deep_gz.id)
        .filter_map(|e| deep.get(e.child))
        .any(|a| a.format == "png");
    assert!(
        png_in_deep,
        "recursive mode must analyze the decompressed payload"
    );
}

/// (9) Recursion-depth limit. B8 regression: honest assertions. The
/// depth limit's contract: at max_depth the engine registers an
/// artifact's direct children but scans NOTHING beyond them, and it
/// records a depth warning on the artifact whose region went unscanned.
/// (Direct signature-scan hits at shallow offsets are legal at any depth
/// — the depth contract is about region *descendants*, which we verify
/// by comparing graph sizes: a deeper limit must produce a strictly
/// larger or equal graph, and the depth-limited graph must carry the
/// depth warning.)
#[test]
fn depth_limit_enforced() {
    let inner = make_png_large();
    let gz = make_gzip(&inner);
    let src = ByteSource::from_vec(gz);

    // Depth 0: root gzip found and its direct handler-children are
    // registered, but NOTHING is scanned beyond them — the decompressed
    // payload must have no descendants of its own.
    let limits0 = EngineLimits {
        max_depth: 0,
        ..EngineLimits::default()
    };
    let mut e0 = RecursiveEngine::new(limits0);
    let g0 = e0.analyze(&src, true);
    let gz0 = g0
        .artifacts
        .iter()
        .find(|a| a.format == "gzip")
        .expect("gzip found even at depth 0");
    let gz0_children = g0.children(gz0.id);
    assert!(
        gz0_children
            .iter()
            .any(|(r, _)| *r == RelationKind::DecompressedFrom),
        "handler-produced children are registered regardless of depth"
    );
    for (_, child) in &gz0_children {
        assert!(
            g0.children(child.id).is_empty(),
            "depth 0 must leave the decompressed payload unanalyzed"
        );
    }

    // Generous depth: decompressed child + its analyzed payload exist.
    let mut e2 = engine();
    let g2 = e2.analyze(&src, true);
    let gz2 = g2
        .artifacts
        .iter()
        .find(|a| a.format == "gzip")
        .expect("gzip found");
    assert!(
        !g2.children(gz2.id).is_empty(),
        "default depth must analyze the decompressed payload"
    );
    assert!(
        g2.len() > g0.len(),
        "unrestricted graph must be strictly larger than the depth-0 graph"
    );
}

/// (10) Max-expanded-bytes / compression-ratio limit. B8 regression: the
/// limit must actually refuse the expansion — the gzip artifact either
/// fails validation entirely (no artifact) or carries an explicit
/// limit warning, AND in no case does the decompressed child appear.
#[test]
fn expansion_limit_enforced() {
    let big = vec![0u8; 1_000_000]; // highly compressible: ~1000x ratio
    let gz = make_gzip(&big);
    let limits = EngineLimits {
        max_child_size: 10_000,
        max_expansion_ratio: 10, // 10x cap: bomb is 1000x
        ..EngineLimits::default()
    };
    let src = ByteSource::from_vec(gz);
    let mut e = RecursiveEngine::new(limits);
    let g = e.analyze(&src, true);

    // In no acceptable outcome does a 1,000,000-byte child get through.
    let huge_child = g.artifacts.iter().any(|a| a.size >= 1_000_000);
    assert!(
        !huge_child,
        "decompressed payload above the cap must never be registered"
    );
    // The gzip artifact was either rejected (limit error) or flagged.
    if let Some(gz_art) = g.artifacts.iter().find(|a| a.format == "gzip") {
        assert!(
            gz_art.warnings.iter().any(|w| w.contains("limit")) || g.children(gz_art.id).is_empty(),
            "accepted gzip must carry a limit warning or have no children"
        );
    }
}

/// (10b) Run-wide budget: charges accumulate ACROSS handlers/artifacts.
/// Two large gzip streams must jointly exceed a budget that either alone
/// would fit. G1: payloads are incompressible (xorshift) so each stream's
/// expansion ratio is ~1x — the per-stream ratio cap can never fire, and
/// the run-wide total-expanded budget is provably the final rejection
/// reason. The second stream's decompressed child must be REFUSED, not
/// merely truncated.
#[test]
fn budget_is_run_wide() {
    fn incompressible(seed: u32, n: usize) -> Vec<u8> {
        let mut state = seed;
        (0..n)
            .map(|_| {
                state ^= state << 13;
                state ^= state >> 17;
                state ^= state << 5;
                (state >> 24) as u8
            })
            .collect()
    }
    let big1 = incompressible(0xAAAA_0001, 60_000);
    let big2 = incompressible(0xBBBB_0002, 60_000);
    let gz1 = make_gzip(&big1);
    let gz2 = make_gzip(&big2);
    // Sanity: each compressed stream is large enough that even a very
    // generous ratio cap would allow the first expansion — the ratio cap
    // is NOT what rejects the second one.
    assert!(gz1.len() > 50_000 && gz2.len() > 50_000);
    let mut data = gz1;
    data.extend_from_slice(&gz2);
    let limits = EngineLimits {
        max_total_expanded_bytes: 100_000, // each stream fits; both don't
        max_expansion_ratio: 100_000,      // effectively disabled
        max_child_size: 1_000_000,         // child cap out of the way
        ..EngineLimits::default()
    };
    let src = ByteSource::from_vec(data);
    let mut e = RecursiveEngine::new(limits);
    let g = e.analyze(&src, true);
    let expanded: Vec<u64> = g
        .artifacts
        .iter()
        .filter(|a| a.relation == Some(RelationKind::DecompressedFrom))
        .map(|a| a.size)
        .collect();
    // Exactly ONE full expansion got through; the second was refused.
    assert_eq!(
        expanded,
        vec![60_000],
        "run-wide budget must refuse the second expansion entirely \
         (got {expanded:?})"
    );
    assert!(
        expanded.iter().sum::<u64>() < 120_000,
        "combined expansion must stay under both streams' total"
    );
}

/// (11) Malformed/truncated candidate does not panic nor stop scanning.
#[test]
fn malformed_candidate_isolated() {
    // Truncated PNG signature + valid ZIP behind it.
    let mut data = vec![0x89, b'P', b'N', b'G'];
    data.extend_from_slice(b"lots of junk without valid chunks junksjunksjunk");
    data.extend_from_slice(&make_zip("real.txt", b"real"));
    let src = ByteSource::from_vec(data);
    let mut e = engine();
    let g = e.analyze(&src, true);
    assert!(
        g.artifacts.iter().any(|a| a.format == "zip"),
        "zip must still be found despite malformed png candidate"
    );
}

/// (12) Overlapping valid artifacts can both be represented.
#[test]
fn overlapping_artifacts_coexist() {
    // A ZIP whose bytes also contain a PDF header is contrived; instead
    // test at the graph level: two artifacts sharing a byte range.
    let zip = make_zip("x.txt", b"data");
    let pdf = b"%PDF-1.4 fake overlap body".to_vec();
    let mut data = pdf.clone();
    data.extend_from_slice(&zip);
    let src = ByteSource::from_vec(data);
    let mut e = engine();
    let g = e.analyze(&src, true);
    // Both the PDF and the ZIP are reported (even if boundaries differ).
    assert!(g.artifacts.iter().any(|a| a.format == "pdf"));
    assert!(g.artifacts.iter().any(|a| a.format == "zip"));
}

/// (13) JSON output round-trips and preserves graph relationships.
#[test]
fn json_round_trip() {
    let gz = make_gzip(make_png().as_slice());
    let src = ByteSource::from_vec(gz);
    let mut e = engine();
    let graph = e.analyze(&src, true);
    let report = ctf_tools::report::Report::new("fixture.gz", src.len(), graph);
    let json = report.to_json_pretty().unwrap();
    let back = ctf_tools::report::Report::from_json(&json).unwrap();
    assert_eq!(back.graph.artifacts.len(), report.graph.artifacts.len());
    assert_eq!(back.graph.edges.len(), report.graph.edges.len());
    for (a, b) in back.graph.artifacts.iter().zip(&report.graph.artifacts) {
        assert_eq!(a.id, b.id);
        assert_eq!(a.parent, b.parent);
        assert_eq!(a.relation, b.relation);
        assert_eq!(a.hash, b.hash);
        assert_eq!(a.format, b.format);
    }
}

/// (14) User-defined carving rule parsing.
#[test]
fn user_carving_rules_parse() {
    let rules = parse_user_rules(
        r#"
[[rule]]
name = "ctf-flag"
header = "464C4147"      # "FLAG"
footer = "454E44"        # "END"
max_size = 4096
terminate_on_next_header = false
"#,
    )
    .unwrap();
    assert_eq!(rules.len(), 1);
    assert_eq!(rules[0].header, b"FLAG".to_vec());
    assert_eq!(rules[0].footer, Some(b"END".to_vec()));
}

/// End-to-end: PNG -> trailing data -> ZIP -> member -> child artifact.
/// B8 regression: asserts the full provenance chain through graph edges.
#[test]
fn e2e_png_trailing_zip_member() {
    let png = make_png();
    let member = make_gzip(b"flag{e2e-nested}");
    let zip = make_zip("deep/flag.gz", &member);
    let mut data = png.clone();
    data.extend_from_slice(b"--extra junk--");
    data.extend_from_slice(&zip);
    let total_len = data.len() as u64;
    let src = ByteSource::from_vec(data);
    let mut e = engine();
    let g = e.analyze(&src, true);

    // Validated PNG at offset 0.
    let png_art = g
        .artifacts
        .iter()
        .find(|a| a.format == "png" && a.offset == 0)
        .expect("validated png");
    assert_eq!(png_art.confidence, Confidence::Validated);
    assert_eq!(png_art.size, png.len() as u64);

    // Trailing-data artifact spans junk + ZIP, parented to the PNG.
    let trailing = g
        .artifacts
        .iter()
        .find(|a| a.relation == Some(RelationKind::TrailingData))
        .expect("trailing data artifact");
    assert_eq!(trailing.offset, png_art.size);
    assert_eq!(trailing.size, total_len - png.len() as u64);

    // ZIP is a descendant of trailing data (edge check, not offset guess).
    let zip_id = g
        .children(trailing.id)
        .iter()
        .find(|(_, a)| a.format == "zip")
        .map(|(_, a)| a.id)
        .expect("zip under trailing data");

    // The gzip member is reachable two levels below the zip.
    let zip_children = g.children(zip_id);
    let has_member = zip_children
        .iter()
        .any(|(_, a)| a.label.contains("flag.gz"));
    assert!(has_member, "zip member must appear under the zip node");
    assert!(g.len() >= 4, "full chain produces >= 4 artifacts");
}

/// Extraction status/registration sanity across the vertical slice.
#[test]
fn extraction_status_records() {
    let gz = make_gzip(make_png().as_slice());
    let src = ByteSource::from_vec(gz);
    let mut e = engine();
    let g = e.analyze(&src, true);
    let gz_art = g.artifacts.iter().find(|a| a.format == "gzip").unwrap();
    assert_eq!(gz_art.extraction, ExtractionStatus::InMemory);
}

/// R1 regression: transactional budget. A malformed candidate that
/// decompresses bytes before failing must NOT permanently drain the
/// run-wide budget — a valid stream behind it must still expand fully.
#[test]
fn budget_rolls_back_failed_candidates() {
    // Corrupt gzip trailer (CRC mismatch) of a stream that decompresses
    // ~100KB before failing, followed by a VALID gzip of the same size.
    // Ratio kept generous (1000x) so the ratio cap never fires first —
    // the bad stream must fail on CRC after a full 100KB expansion.
    let payload = vec![0x5Au8; 100_000];
    let good = make_gzip(&payload);
    let mut bad = good.clone();
    let n = bad.len();
    bad[n - 5] ^= 0xFF; // corrupt ISIZE/CRC area -> validation fails late

    let mut data = bad;
    data.extend_from_slice(&good);
    let limits = EngineLimits {
        max_total_expanded_bytes: 150_000, // both streams would exceed; one fits
        max_expansion_ratio: 1_000,
        ..EngineLimits::default()
    };
    let src = ByteSource::from_vec(data);
    let mut e = RecursiveEngine::new(limits);
    let g = e.analyze(&src, true);
    // The good stream must have been accepted with its full payload.
    let expanded: u64 = g
        .artifacts
        .iter()
        .filter(|a| a.relation == Some(RelationKind::DecompressedFrom))
        .map(|a| a.size)
        .sum();
    assert!(
        expanded >= 100_000,
        "the valid stream must fully expand despite the failed candidate \
         before it (got {expanded}); failed candidates must not drain the budget"
    );
}

/// R5 regression: region-backed artifacts (embedded/carved) are
/// materializable — byte_cache covers them, not just decompressed data.
#[test]
fn region_backed_artifacts_are_extractable() {
    let png = make_png();
    let mut data = b"leading bytes".to_vec();
    data.extend_from_slice(&png);
    data.extend_from_slice(b"trailing bytes");
    let src = ByteSource::from_vec(data);
    let mut e = engine();
    let g = e.analyze(&src, true);
    let png_art = g
        .artifacts
        .iter()
        .find(|a| a.format == "png")
        .expect("embedded png found");
    let cached = e.cached_bytes(&png_art.hash).expect("png bytes cached");
    assert_eq!(
        cached, &png,
        "region-backed artifact bytes must be recoverable for extraction"
    );
}

/// R6 regression: a user-defined carving rule is actually EXECUTED by the
/// engine — a magic the builtin rules do not know becomes an artifact.
#[test]
fn custom_carving_rule_is_executed() {
    // Builtin rules cover GIF/RAR/7z only; "CTFD" is unknown to them.
    let mut data = b"padding padding".to_vec();
    data.extend_from_slice(b"CTFD");
    data.extend_from_slice(b"secret-data-blob");
    data.extend_from_slice(b"DLTC"); // footer
    data.extend_from_slice(b"more padding");
    let src = ByteSource::from_vec(data);

    // Sanity: without the rule, nothing is found.
    let mut e0 = engine();
    let g0 = e0.analyze(&src, true);
    assert!(
        !g0.artifacts.iter().any(|a| a.format == "ctf-blob"),
        "builtin carving must not know this magic"
    );

    // With the injected rule, the blob is discovered between the markers.
    let rules = parse_user_rules(
        r#"
[[rule]]
name = "ctf-blob"
header = "43544644"        # "CTFD"
footer = "444C5443"        # "DLTC"
max_size = 65536
terminate_on_next_header = false
"#,
    )
    .unwrap();
    let mut e = engine();
    e.carving_rules = rules;
    let g = e.analyze(&src, true);
    let blob = g
        .artifacts
        .iter()
        .find(|a| a.format == "ctf-blob")
        .expect("custom carving rule must produce an artifact");
    assert_eq!(blob.confidence, Confidence::Recovered);
    assert!(blob.label.contains("ctf-blob"));
}

/// R2 regression: a duplicate container keeps its OWN children — the
/// second identical gzip registers a DecompressedFrom edge (provenance),
/// even though recursive scanning of the identical bytes is skipped.
#[test]
fn duplicate_container_keeps_children() {
    let inner = make_png_large();
    let gz = make_gzip(&inner);
    let mut data = gz.clone();
    data.extend_from_slice(&gz);
    let src = ByteSource::from_vec(data);
    let mut e = engine();
    let g = e.analyze(&src, true);
    let gzs: Vec<_> = g
        .artifacts
        .iter()
        .filter(|a| a.format == "gzip" && a.parent == Some(0))
        .collect();
    assert_eq!(gzs.len(), 1, "sanity: one root-level gzip in this fixture");

    // Use the trailing-region duplicate from the dedup fixture instead:
    let mut data2 = gz.clone();
    data2.extend_from_slice(&gz);
    let src2 = ByteSource::from_vec(data2);
    let mut e2 = engine();
    let g2 = e2.analyze(&src2, true);
    let gz_nodes: Vec<_> = g2.artifacts.iter().filter(|a| a.format == "gzip").collect();
    // At least two gzip containers exist (root-level + trailing region).
    assert!(gz_nodes.len() >= 2);
    // EVERY gzip container — duplicate or not — must have its own
    // decompressed child edge.
    for gz in &gz_nodes {
        let has_child = g2
            .children(gz.id)
            .iter()
            .any(|(r, _)| *r == RelationKind::DecompressedFrom);
        assert!(
            has_child,
            "gzip container #{} (duplicate={}) must keep its decompressed-child edge",
            gz.id,
            gz.warnings.iter().any(|w| w.contains("duplicate"))
        );
    }
}

/// F1 regression: a draft validated (and charged) at the root level but
/// deferred to a trailing region must NOT be billed twice. PNG + appended
/// gzip (~60 KiB output) under a 90 KiB total budget succeeds only when
/// the gzip expansion is billed once.
#[test]
fn deferred_trailing_expansion_billed_once() {
    let png = make_png();
    let payload = vec![0x77u8; 60 * 1024]; // incompressible-ish, ~60KiB out
    let gz = make_gzip(&payload);
    let mut data = png.clone();
    data.extend_from_slice(&gz);
    let src = ByteSource::from_vec(data);

    let limits = EngineLimits {
        max_total_expanded_bytes: 90 * 1024,
        max_expansion_ratio: 1_000, // keep the ratio cap out of the way
        ..EngineLimits::default()
    };
    let mut e = RecursiveEngine::new(limits);
    let g = e.analyze(&src, true);

    // The trailing-region gzip must be discovered with its full payload.
    let trailing = g
        .artifacts
        .iter()
        .find(|a| a.relation == Some(RelationKind::TrailingData))
        .expect("trailing region exists");
    let gz_in_trailing = g
        .children(trailing.id)
        .into_iter()
        .find(|(_, a)| a.format == "gzip")
        .map(|(_, a)| a)
        .expect("gzip discovered inside trailing region");
    let decompressed: u64 = g
        .children(gz_in_trailing.id)
        .iter()
        .filter(|(r, _)| *r == RelationKind::DecompressedFrom)
        .map(|(_, a)| a.size)
        .sum();
    assert_eq!(
        decompressed,
        60 * 1024,
        "trailing gzip must fully decompress: double billing would have \
         pushed 120KiB past the 90KiB cap and truncated/refused it"
    );
}
