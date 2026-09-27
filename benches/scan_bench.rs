//! Scan benchmarks (criterion): engine throughput on representative
//! fixture classes — single image, nested containers, archive with many
//! entries, and high-entropy blob (worst case for signature scanning).

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use ctf_tools::bytesource::ByteSource;
use ctf_tools::engine::{EngineLimits, RecursiveEngine};
use flate2::write::GzEncoder;
use flate2::Compression;
use std::io::Write;

fn crc32(data: &[u8]) -> u32 {
    let mut h = crc32fast::Hasher::new();
    h.update(data);
    h.finalize()
}

fn make_gzip(content: &[u8]) -> Vec<u8> {
    let mut enc = GzEncoder::new(Vec::new(), Compression::default());
    enc.write_all(content).unwrap();
    enc.finish().unwrap()
}

fn make_png(size_kb: usize) -> Vec<u8> {
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
    ihdr.extend_from_slice(&64u32.to_be_bytes());
    ihdr.extend_from_slice(&64u32.to_be_bytes());
    ihdr.extend([8, 0, 0, 0, 0]);
    png.extend_from_slice(&chunk(b"IHDR", &ihdr));
    // Pseudorandom high-entropy IDAT of the requested size.
    let mut seed = 0x1234_5678u32;
    let mut idat = Vec::with_capacity(size_kb * 1024);
    while idat.len() < size_kb * 1024 {
        seed = seed.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
        idat.extend_from_slice(&seed.to_le_bytes());
    }
    png.extend_from_slice(&chunk(b"IDAT", &idat));
    png.extend_from_slice(&chunk(b"IEND", &[]));
    png
}

fn make_zip_many(entries: usize) -> Vec<u8> {
    let mut z = Vec::new();
    let mut offsets: Vec<(String, u32, u32, u32)> = Vec::new();
    for i in 0..entries {
        let name = format!("file_{i}.txt");
        let content = format!("contents of entry {i}").into_bytes();
        let crc = crc32(&content);
        let offset = z.len() as u32;
        z.extend_from_slice(b"PK\x03\x04");
        z.extend(20u16.to_le_bytes());
        z.extend(0u16.to_le_bytes());
        z.extend(0u16.to_le_bytes());
        z.extend(0u32.to_le_bytes());
        z.extend(0u32.to_le_bytes());
        z.extend(crc.to_le_bytes());
        z.extend((content.len() as u32).to_le_bytes());
        z.extend((content.len() as u32).to_le_bytes());
        z.extend((name.len() as u16).to_le_bytes());
        z.extend(0u16.to_le_bytes());
        z.extend_from_slice(name.as_bytes());
        z.extend_from_slice(&content);
        offsets.push((name, crc, content.len() as u32, offset));
    }
    let cd_offset = z.len() as u32;
    let cd_start = z.len();
    for (name, crc, size, offset) in &offsets {
        z.extend_from_slice(b"PK\x01\x02");
        z.extend(20u16.to_le_bytes());
        z.extend(20u16.to_le_bytes());
        z.extend(0u16.to_le_bytes());
        z.extend(0u16.to_le_bytes());
        z.extend(0u16.to_le_bytes());
        z.extend(0u32.to_le_bytes());
        z.extend(crc.to_le_bytes());
        z.extend(size.to_le_bytes());
        z.extend(size.to_le_bytes());
        z.extend((name.len() as u16).to_le_bytes());
        z.extend(0u16.to_le_bytes());
        z.extend(0u16.to_le_bytes());
        z.extend(0u16.to_le_bytes());
        z.extend(0u16.to_le_bytes());
        z.extend(0u32.to_le_bytes());
        z.extend(offset.to_le_bytes());
        z.extend_from_slice(name.as_bytes());
    }
    let cd_size = (z.len() - cd_start) as u32;
    z.extend_from_slice(b"PK\x05\x06");
    z.extend(0u16.to_le_bytes());
    z.extend(0u16.to_le_bytes());
    z.extend((offsets.len() as u16).to_le_bytes());
    z.extend((offsets.len() as u16).to_le_bytes());
    z.extend(cd_size.to_le_bytes());
    z.extend(cd_offset.to_le_bytes());
    z.extend(0u16.to_le_bytes());
    z
}

fn bench(c: &mut Criterion) {
    let mut group = c.benchmark_group("scan");

    group.throughput(criterion::Throughput::Bytes(make_png(256).len() as u64));
    group.bench_function("png_256k", |b| {
        let data = make_png(256);
        b.iter(|| {
            let mut engine = RecursiveEngine::new(EngineLimits::default());
            let g = engine.analyze(&ByteSource::from_vec(data.clone()), true);
            black_box(g.len())
        })
    });

    let gz = make_gzip(&make_png(64));
    group.throughput(criterion::Throughput::Bytes(gz.len() as u64));
    group.bench_function("gzip_png_nested", |b| {
        b.iter(|| {
            let mut engine = RecursiveEngine::new(EngineLimits::default());
            let g = engine.analyze(&ByteSource::from_vec(gz.clone()), true);
            black_box(g.len())
        })
    });

    let zip = make_zip_many(500);
    group.throughput(criterion::Throughput::Bytes(zip.len() as u64));
    group.bench_function("zip_500_entries", |b| {
        b.iter(|| {
            let mut engine = RecursiveEngine::new(EngineLimits::default());
            let g = engine.analyze(&ByteSource::from_vec(zip.clone()), true);
            black_box(g.len())
        })
    });

    // High-entropy blob: worst case for signature scanning (no hits).
    let mut seed = 0xDEAD_BEEFu32;
    let mut blob = Vec::with_capacity(1024 * 1024);
    while blob.len() < 1024 * 1024 {
        seed = seed.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
        blob.extend_from_slice(&seed.to_le_bytes());
    }
    group.throughput(criterion::Throughput::Bytes(blob.len() as u64));
    group.bench_function("entropy_1m_no_hits", |b| {
        b.iter(|| {
            let mut engine = RecursiveEngine::new(EngineLimits::default());
            let g = engine.analyze(&ByteSource::from_vec(blob.clone()), false);
            black_box(g.len())
        })
    });

    group.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
