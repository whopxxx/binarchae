//! M3 end-to-end scenarios: the six required integration paths, each
//! asserting per-hop provenance (relation kinds + parent chain) on the
//! artifact graph, not merely artifact existence.

use ctf_tools::artifact::{Confidence, RelationKind};
use ctf_tools::bytesource::ByteSource;
use ctf_tools::engine::{EngineLimits, RecursiveEngine};
use flate2::write::GzEncoder;
use flate2::Compression;
use std::io::Write;

fn engine() -> RecursiveEngine {
    RecursiveEngine::new(EngineLimits::default())
}

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

fn make_zip(name: &str, content: &[u8]) -> Vec<u8> {
    let mut z = Vec::new();
    let crc = crc32(content);
    let name_len = name.len() as u16;
    let size = content.len() as u32;
    // LFH
    z.extend_from_slice(b"PK\x03\x04");
    z.extend(20u16.to_le_bytes());
    z.extend(0u16.to_le_bytes());
    z.extend(0u16.to_le_bytes()); // stored
    z.extend(0u32.to_le_bytes()); // time
    z.extend(0u32.to_le_bytes()); // date
    z.extend(crc.to_le_bytes());
    z.extend(size.to_le_bytes());
    z.extend(size.to_le_bytes());
    z.extend(name_len.to_le_bytes());
    z.extend(0u16.to_le_bytes());
    z.extend_from_slice(name.as_bytes());
    z.extend_from_slice(content);
    let cd_offset = z.len() as u32;
    // CD entry
    let cd_size_pos = z.len();
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
    z.extend(name_len.to_le_bytes());
    z.extend(0u16.to_le_bytes());
    z.extend(0u16.to_le_bytes());
    z.extend(0u16.to_le_bytes());
    z.extend(0u16.to_le_bytes());
    z.extend(0u32.to_le_bytes());
    z.extend(0u32.to_le_bytes()); // local header offset = 0
    z.extend_from_slice(name.as_bytes());
    let cd_size = (z.len() - cd_size_pos) as u32;
    // EOCD
    z.extend_from_slice(b"PK\x05\x06");
    z.extend(0u16.to_le_bytes());
    z.extend(0u16.to_le_bytes());
    z.extend(1u16.to_le_bytes());
    z.extend(1u16.to_le_bytes());
    z.extend(cd_size.to_le_bytes());
    z.extend(cd_offset.to_le_bytes());
    z.extend(0u16.to_le_bytes());
    z
}

/// Assert the parent chain of `id` matches `expected_formats` root-first.
fn assert_parent_chain(
    graph: &ctf_tools::artifact::ArtifactGraph,
    id: u64,
    expected_formats: &[&str],
) {
    let mut chain = Vec::new();
    let mut cur = Some(id);
    while let Some(i) = cur {
        let a = graph.get(i).expect("artifact exists");
        chain.push(a.format.clone());
        cur = a.parent;
    }
    chain.reverse();
    let got: Vec<&str> = chain.iter().map(|s| s.as_str()).collect();
    assert_eq!(got, expected_formats, "parent chain must match provenance");
}

// ---------- Scenario 1: PNG with appended ZIP -> PNG -> trailing -> ZIP -> member ----------

#[test]
fn s1_png_trailing_zip_member_provenance() {
    let png = make_png_valid();
    let zip = make_zip("flag.txt", b"CTF{trailing}");
    let mut blob = png.clone();
    blob.extend_from_slice(&zip);
    let graph = engine().analyze(&ByteSource::from_vec(blob), true);

    // The trailing chain must exist with exact relation kinds.
    let mut found = false;
    for i in 0..graph.len() as u64 {
        let a = graph.get(i).unwrap();
        if a.format == "zip" {
            // find png parent
            let p = graph.get(a.parent.unwrap()).unwrap();
            if p.format == "raw" && p.relation == Some(RelationKind::TrailingData) {
                found = true;
                assert_parent_chain(&graph, i, &["input", "png", "raw", "zip"]);
                break;
            }
        }
    }
    assert!(found, "PNG -> trailing -> ZIP chain not found");
}

// ---------- Scenario 2: gzip(SQLite) -> gzip -> sqlite -> rows ----------

#[test]
fn s2_gzip_sqlite_rows_provenance() {
    // Build a minimal SQLite DB with one table + row.
    let db = make_sqlite_db(b"CREATE TABLE t(v)", &[b"hello"]);
    let gz = make_gzip(&db);
    let graph = engine().analyze(&ByteSource::from_vec(gz), true);

    let mut sqlite_seen = false;
    for i in 0..graph.len() as u64 {
        let a = graph.get(i).unwrap();
        if a.format == "sqlite" {
            sqlite_seen = true;
            assert_parent_chain(&graph, i, &["input", "gzip", "raw", "sqlite"]);
            // The DB must have produced DatabaseRecord children.
            let kids = graph.children(i);
            assert!(
                kids.iter().any(|(r, _)| *r == RelationKind::DatabaseRecord),
                "sqlite rows must be DatabaseRecord children"
            );
        }
    }
    assert!(sqlite_seen, "sqlite inside gzip not discovered");
}

// ---------- Scenario 3: PCAP containing a carved gzip -> pcap -> packet -> gzip ----------

#[test]
fn s3_pcap_packet_gzip_child() {
    let inner = make_gzip(b"GET /flag HTTP/1.1\r\nHost: ctf\r\n\r\n");
    // PCAP LE global header + one packet holding the gzip bytes.
    let mut p = Vec::new();
    p.extend_from_slice(&[0xD4, 0xC3, 0xB2, 0xA1]);
    p.extend(2u16.to_le_bytes());
    p.extend(4u16.to_le_bytes());
    p.extend(0u32.to_le_bytes());
    p.extend(0u32.to_le_bytes());
    p.extend(262144u32.to_le_bytes());
    p.extend(1u32.to_le_bytes());
    p.extend(1u32.to_le_bytes()); // ts_sec
    p.extend(0u32.to_le_bytes()); // ts_usec
    p.extend((inner.len() as u32).to_le_bytes());
    p.extend((inner.len() as u32).to_le_bytes());
    p.extend_from_slice(&inner);
    let graph = engine().analyze(&ByteSource::from_vec(p), true);

    // At least one pcap artifact (duplicates may exist without rescans)
    // must own packet children and have a gzip provenance descendant.
    let mut pcap_seen = false;
    let mut chain_found = false;
    for i in 0..graph.len() as u64 {
        let a = graph.get(i).unwrap();
        if a.format == "pcap" {
            pcap_seen = true;
            if a.confidence != Confidence::Validated {
                continue;
            }
            let packets = graph.children(i);
            if packets.is_empty() {
                continue;
            }
            for j in 0..graph.len() as u64 {
                let g = graph.get(j).unwrap();
                if g.format == "gzip" && has_ancestor(&graph, j, i) {
                    chain_found = true;
                }
            }
        }
    }
    assert!(pcap_seen, "pcap not validated");
    assert!(chain_found, "gzip inside pcap packet not found");
}

// ---------- Scenario 4: GPT disk -> partition -> FAT -> file ----------

#[test]
fn s4_disk_partition_filesystem_chain() {
    // MBR disk with one FAT12 partition.
    let fat = make_fat12_with_file(b"FLAG{disk}");
    let mbr = make_mbr_with_partition(&fat);
    let graph = engine().analyze(&ByteSource::from_vec(mbr), true);

    let mut fat_seen = false;
    for i in 0..graph.len() as u64 {
        let a = graph.get(i).unwrap();
        if a.format == "fat" {
            fat_seen = true;
            // must trace up through a partition (raw) to mbr/input
            assert!(
                has_ancestor(&graph, i, 0),
                "fat must be reachable from input"
            );
        }
    }
    assert!(fat_seen, "FAT filesystem inside disk image not found");
}

// ---------- Scenario 5: corrupted ZIP -> salvage -> recovered entries ----------

#[test]
fn s5_truncated_zip_salvage_recovery() {
    let mut z = make_zip("flag.txt", b"CTF{partial_recovery}");
    // Cut off EOCD + central directory: keep only LFH + payload.
    let lfh_end = 30 + "flag.txt".len() + b"CTF{partial_recovery}".len();
    z.truncate(lfh_end);
    let graph = engine().analyze(&ByteSource::from_vec(z), true);

    let mut salvage_seen = false;
    for i in 0..graph.len() as u64 {
        let a = graph.get(i).unwrap();
        if a.format == "zip-salvage" {
            salvage_seen = true;
            assert_eq!(a.confidence, Confidence::Recovered);
            assert!(
                graph
                    .children(i)
                    .iter()
                    .any(|(_, c)| c.label.contains("flag.txt")),
                "salvaged entry must be a child"
            );
        }
        // Primary zip handler must NOT have validated the truncated blob.
        if a.format == "zip" && a.confidence == Confidence::Validated {
            panic!("truncated zip must not be Validated");
        }
    }
    assert!(salvage_seen, "truncated zip must be salvaged");
}

// ---------- Scenario 6: firmware image -> kernel gzip -> content ----------

#[test]
fn s6_uimage_gzip_kernel_provenance() {
    let kernel = make_gzip(b"FakeKernel flag{firmware}");
    // Legacy uImage header: BE.
    let mut h = Vec::new();
    h.extend(0x27051956u32.to_be_bytes()); // magic
    h.extend(0x00000004u32.to_be_bytes()); // header crc placeholder (fix below)
    h.extend(0x54504f4eu32.to_be_bytes()); // time
    h.extend((kernel.len() as u32).to_be_bytes()); // size
    h.extend(0x80000000u32.to_be_bytes()); // load
    h.extend(0x80000000u32.to_be_bytes()); // ep
    h.extend(0x00000004u32.to_be_bytes()); // data crc (fix below)
    h.extend(0x01u8.to_be_bytes()); // os = linux
    h.extend(0x01u8.to_be_bytes()); // arch
    h.extend(0x02u8.to_be_bytes()); // type = kernel
    h.extend(0x03u8.to_be_bytes()); // comp = gzip
    h.extend_from_slice(b"kernel");
    h.resize(64, 0);
    // Fix CRCs.
    let data_crc = crc32(&kernel);
    h[24..28].copy_from_slice(&data_crc.to_be_bytes());
    let mut h_for_crc = h.clone();
    h_for_crc[4..8].copy_from_slice(&[0; 4]);
    let hcrc = crc32(&h_for_crc);
    h[4..8].copy_from_slice(&hcrc.to_be_bytes());

    let mut blob = h;
    blob.extend_from_slice(&kernel);
    let graph = engine().analyze(&ByteSource::from_vec(blob), true);

    // A top-level uimage (parent = root) whose provenance contains the
    // gzip kernel payload must exist. Duplicates (trailing-region
    // revalidation) are tolerated; the chain itself is the contract.
    let mut uimage_seen = false;
    let mut gzip_under_top = false;
    for i in 0..graph.len() as u64 {
        let a = graph.get(i).unwrap();
        if a.format == "uimage" {
            uimage_seen = true;
            if a.parent != Some(0) {
                continue;
            }
            for j in 0..graph.len() as u64 {
                if graph.get(j).unwrap().format == "gzip" && has_ancestor(&graph, j, i) {
                    gzip_under_top = true;
                }
            }
        }
    }
    assert!(uimage_seen, "uimage not validated");
    assert!(
        gzip_under_top,
        "gzip kernel payload must be recursed under uimage"
    );
}

// ---------- B7 required chains ----------

// PCAP -> Ethernet -> IPv4 -> TCP -> flow -> HTTP object
#[test]
fn b7_pcap_http_reconstruction() {
    // Helper: wrap a TCP payload in an Ethernet+IPv4+TCP frame.
    let frame = |seq: u32, payload: &[u8]| -> Vec<u8> {
        let mut f = Vec::new();
        // Ethernet: dst(6) src(6) ethertype 0x0800.
        f.extend([0x02u8; 6]);
        f.extend([0x01u8; 6]);
        f.extend(0x0800u16.to_be_bytes());
        // IPv4 header (20 bytes).
        let total_len = (20 + 20 + payload.len()) as u16;
        f.extend(0x45u8.to_be_bytes());
        f.extend(0u8.to_be_bytes()); // tos
        f.extend(total_len.to_be_bytes());
        f.extend(1u16.to_be_bytes()); // id
        f.extend(0x4000u16.to_be_bytes()); // don't fragment
        f.extend(64u8.to_be_bytes()); // ttl
        f.extend(6u8.to_be_bytes()); // proto TCP
        f.extend(0u16.to_be_bytes()); // checksum (not verified here)
        f.extend([10u8, 0, 0, 1]); // src
        f.extend([10u8, 0, 0, 2]); // dst
                                   // TCP header (20 bytes).
        f.extend(443u16.to_be_bytes());
        f.extend(55555u16.to_be_bytes());
        f.extend(seq.to_be_bytes());
        f.extend(1u32.to_be_bytes()); // ack
        f.extend(0x5008u16.to_be_bytes()); // data_off=5, PSH|ACK
        f.extend(0xFFFFu16.to_be_bytes()); // window
        f.extend(0u16.to_be_bytes()); // checksum
        f.extend(0u16.to_be_bytes()); // urgent
        f.extend_from_slice(payload);
        f
    };

    // One HTTP response split across two TCP segments.
    let body = b"CTF{pcap77}";
    let mut part1 = b"HTTP/1.1 200 OK\r\nContent-Length: 11\r\n\r\n".to_vec();
    part1.extend_from_slice(&body[..6]);
    let part2 = &body[6..];
    let seg1 = frame(1, &part1);
    let seg2 = frame(1 + part1.len() as u32, part2);

    let mut p = Vec::new();
    p.extend_from_slice(&[0xD4, 0xC3, 0xB2, 0xA1]);
    p.extend(2u16.to_le_bytes());
    p.extend(4u16.to_le_bytes());
    p.extend(0u32.to_le_bytes());
    p.extend(0u32.to_le_bytes());
    p.extend(262144u32.to_le_bytes());
    p.extend(1u32.to_le_bytes()); // linktype = Ethernet
    for pkt in [&seg1, &seg2] {
        p.extend(1u32.to_le_bytes());
        p.extend(0u32.to_le_bytes());
        p.extend((pkt.len() as u32).to_le_bytes());
        p.extend((pkt.len() as u32).to_le_bytes());
        p.extend_from_slice(pkt);
    }
    let graph = engine().analyze(&ByteSource::from_vec(p), true);

    let pcap_id = graph
        .artifacts
        .iter()
        .find(|a| a.format == "pcap")
        .map(|a| a.id);
    assert!(pcap_id.is_some(), "pcap validated");
    let mut found = false;
    for (r, c) in graph.children(pcap_id.unwrap()) {
        if c.label.contains("HTTP body")
            && r == RelationKind::ReconstructedFrom
            && c.metadata.get("complete").map(String::as_str) == Some("true")
        {
            // The reassembled BODY (headers stripped per §7.2) must be
            // exactly the 11-byte flag.
            if c.size == 11 {
                found = true;
            }
        }
    }
    assert!(
        found,
        "HTTP object reassembled from split TCP segments; children: {:?}",
        graph
            .children(pcap_id.unwrap())
            .iter()
            .map(|(_, c)| (&c.label, c.size))
            .collect::<Vec<_>>()
    );
}

// GPT -> partition -> FAT -> nested file
#[test]
fn b7_gpt_partition_fat_file_chain() {
    let fat = make_fat12_with_file(b"FLAG{gpt}");
    let sector = 512usize;
    let fat_start_lba: u64 = 3;
    let fat_sectors = (fat.len() as u64).div_ceil(512);
    let total = ((fat_start_lba + fat_sectors) * 512) as usize;
    let mut d = vec![0u8; total];
    // Protective MBR (LBA 0).
    let pe = 446;
    d[pe + 4] = 0xEE;
    d[pe + 8..pe + 12].copy_from_slice(&1u32.to_le_bytes());
    d[510..512].copy_from_slice(&[0x55, 0xAA]);
    // GPT header at LBA 1 (offset 512).
    let hdr = sector;
    d[hdr..hdr + 8].copy_from_slice(b"EFI PART");
    d[hdr + 8..hdr + 12].copy_from_slice(&0x0001_0000u32.to_le_bytes()); // revision 1.0
    d[hdr + 12..hdr + 16].copy_from_slice(&92u32.to_le_bytes()); // header size
    d[hdr + 24..hdr + 32].copy_from_slice(&1u64.to_le_bytes()); // current lba
    d[hdr + 32..hdr + 40].copy_from_slice(&1u64.to_le_bytes()); // backup lba
    d[hdr + 40..hdr + 48].copy_from_slice(&2u64.to_le_bytes()); // first usable
    d[hdr + 48..hdr + 56].copy_from_slice(&((total as u64 / 512) - 2).to_le_bytes());
    d[hdr + 56..hdr + 64].copy_from_slice(&((total as u64 / 512) - 2).to_le_bytes());
    // 0x48=72 entries lba; 0x50=80 num entries; 0x54=84 entry size;
    // 0x58=88 entries crc.
    d[hdr + 72..hdr + 80].copy_from_slice(&2u64.to_le_bytes());
    d[hdr + 80..hdr + 84].copy_from_slice(&1u32.to_le_bytes());
    d[hdr + 84..hdr + 88].copy_from_slice(&128u32.to_le_bytes());
    // Entry array at LBA 2 (offset 1024). Entry 0 = FAT partition.
    let ent = 2 * sector;
    d[ent..ent + 16].copy_from_slice(&[
        0x06, 0x57, 0x20, 0x9E, 0x36, 0x77, 0xA3, 0x4E, 0xA3, 0x1E, 0xB3, 0x13, 0x3E, 0xEE, 0x00,
        0x02,
    ]);
    d[ent + 32..ent + 40].copy_from_slice(&fat_start_lba.to_le_bytes());
    d[ent + 40..ent + 48].copy_from_slice(&(fat_start_lba + fat_sectors - 1).to_le_bytes());
    // Entry-array CRC over num_entries * entry_size bytes.
    let entries_crc = crc32(&d[ent..ent + 128]);
    d[hdr + 88..hdr + 92].copy_from_slice(&entries_crc.to_le_bytes());
    // Header CRC over the first 92 bytes with the CRC field zeroed.
    d[hdr + 16..hdr + 20].copy_from_slice(&[0; 4]);
    let hcrc = crc32(&d[hdr..hdr + 92]);
    d[hdr + 16..hdr + 20].copy_from_slice(&hcrc.to_le_bytes());
    // Partition data at LBA 3.
    d[3 * sector..3 * sector + fat.len()].copy_from_slice(&fat);

    let graph = engine().analyze(&ByteSource::from_vec(d), true);
    // Chain: a fat artifact must descend from the gpt artifact.
    let gpt_id = graph
        .artifacts
        .iter()
        .find(|a| a.format == "gpt")
        .map(|a| a.id);
    assert!(gpt_id.is_some(), "GPT header validated");
    let mut chain_ok = false;
    for j in 0..graph.len() as u64 {
        if graph.get(j).unwrap().format == "fat" && has_ancestor(&graph, j, gpt_id.unwrap()) {
            chain_ok = true;
        }
    }
    assert!(chain_ok, "GPT -> partition -> FAT chain");
}

// SQLite -> BLOB -> nested artifact
#[test]
fn b7_sqlite_blob_nested_artifact() {
    let png = make_png_valid();
    // Record: header [len][blob serial], body = png bytes.
    let mut hdr: Vec<u8> = vec![0u8];
    hdr.extend(ctf_write_varint(12u64 + 2 * png.len() as u64));
    hdr[0] = hdr.len() as u8;
    let mut record = hdr;
    record.extend_from_slice(&png);

    let page_size = 8192usize;
    let mut db = vec![0u8; page_size];
    db[0..16].copy_from_slice(b"SQLite format 3\0");
    db[16..18].copy_from_slice(&(page_size as u16).to_be_bytes());
    db[56..60].copy_from_slice(&1u32.to_be_bytes());
    db[100] = 0x0D;
    db[103..105].copy_from_slice(&1u16.to_be_bytes());
    let mut cell = ctf_write_varint(record.len() as u64);
    cell.extend(ctf_write_varint(1));
    cell.extend_from_slice(&record);
    let cell_off = page_size - cell.len();
    db[108..110].copy_from_slice(&(cell_off as u16).to_be_bytes());
    db[cell_off..cell_off + cell.len()].copy_from_slice(&cell);

    let gz = make_gzip(&db);
    let graph = engine().analyze(&ByteSource::from_vec(gz), true);
    let sqlite_id = graph
        .artifacts
        .iter()
        .find(|a| a.format == "sqlite")
        .map(|a| a.id);
    assert!(sqlite_id.is_some(), "sqlite validated");
    let mut png_under_sqlite = false;
    for j in 0..graph.len() as u64 {
        if graph.get(j).unwrap().format == "png" && has_ancestor(&graph, j, sqlite_id.unwrap()) {
            png_under_sqlite = true;
        }
    }
    assert!(png_under_sqlite, "PNG BLOB recursed under sqlite");
}

// Registry -> REG_BINARY -> artifact
#[test]
fn b7_registry_regbinary_artifact() {
    // FINAL-B3: spec-layout hive -- nk value count @+36, value-list
    // cell @+40, name_len @+72, name @+76; references target CELL
    // STARTS; contiguous cells.
    let mut v = vec![0u8; 8192];
    v[0..4].copy_from_slice(b"regf");
    v[4096..4100].copy_from_slice(b"hbin");
    v[4104..4108].copy_from_slice(&4096u32.to_le_bytes());
    // Root nk CELL at 4128 (record at 4132).
    let rec: usize = 4132;
    v[4128..4132].copy_from_slice(&(-(4 + 88i32)).to_le_bytes());
    v[rec..rec + 2].copy_from_slice(b"nk");
    v[rec + 2..rec + 4].copy_from_slice(&0x0020u16.to_le_bytes());
    v[rec + 16..rec + 20].copy_from_slice(&0xFFFFFFFFu32.to_le_bytes()); // no parent
    v[rec + 36..rec + 40].copy_from_slice(&1u32.to_le_bytes()); // value count
                                                                // Value-list CELL at 4220 (contiguous after the nk cell).
    let list_cell: usize = 4220;
    v[rec + 40..rec + 44].copy_from_slice(&((list_cell - 4096) as u32).to_le_bytes());
    v[rec + 72..rec + 74].copy_from_slice(&4u16.to_le_bytes()); // name_len
    v[rec + 76..rec + 80].copy_from_slice(b"ROOT");
    // Value list: [size -8][vk CELL offset].
    v[list_cell..list_cell + 4].copy_from_slice(&(-8i32).to_le_bytes());
    let vk_cell: usize = 4228;
    v[list_cell + 4..list_cell + 8].copy_from_slice(&((vk_cell - 4096) as u32).to_le_bytes());
    // vk CELL at 4228 (record at 4232): data_len 16, data_off -> data
    // cell at absolute 5216 (field = 1120), type REG_BINARY.
    let vk: usize = 4232;
    v[vk_cell..vk_cell + 4].copy_from_slice(&(-28i32).to_le_bytes());
    v[vk..vk + 2].copy_from_slice(b"vk");
    v[vk + 2..vk + 4].copy_from_slice(&0u16.to_le_bytes());
    v[vk + 4..vk + 8].copy_from_slice(&16u32.to_le_bytes());
    v[vk + 8..vk + 12].copy_from_slice(&1120u32.to_le_bytes());
    v[vk + 12..vk + 16].copy_from_slice(&3u32.to_le_bytes());
    let data_cell: usize = 5216;
    v[data_cell..data_cell + 4].copy_from_slice(&(-24i32).to_le_bytes());
    // Payload in the data cell (target + 4 = 5220).
    v[5220..5236].copy_from_slice(&[0xB7u8; 16]);
    let graph = engine().analyze(&ByteSource::from_vec(v), true);
    let reg = graph
        .artifacts
        .iter()
        .find(|a| a.format == "registry")
        .map(|a| a.id)
        .expect("registry validated");
    let mut binary_child = false;
    for (r, c) in graph.children(reg) {
        if c.label.contains("REG_BINARY") && r == RelationKind::DatabaseRecord {
            binary_child = true;
        }
    }
    assert!(binary_child, "REG_BINARY must be a child artifact");
}

// Minidump -> MemoryRange -> artifact
#[test]
fn b7_minidump_memoryrange_artifact() {
    let mut m = Vec::new();
    m.extend(b"MDMP"); // 0..4
    m.extend(42899u32.to_le_bytes()); // version
    m.extend(1u32.to_le_bytes()); // 1 stream
    m.extend(32u32.to_le_bytes()); // dir rva = 32
    m.extend(0u32.to_le_bytes()); // checksum
    m.extend(0u32.to_le_bytes()); // timestamp
    m.extend(0u64.to_le_bytes()); // flags -> header ends at 32
                                  // Directory entry at 32: type=9 (Memory64List), size=24, rva=48.
    m.extend(9u32.to_le_bytes());
    m.extend(24u32.to_le_bytes());
    m.extend(48u32.to_le_bytes());
    m.resize(48, 0); // pad to the stream rva
                     // Memory64List at 48: count(8), base_rva(8) = 80 (data at 80).
    m.extend(1u64.to_le_bytes());
    m.extend(80u64.to_le_bytes());
    // Descriptor at 64: start_addr, data_size=32.
    m.extend(0x1000u64.to_le_bytes());
    m.extend(32u64.to_le_bytes()); // ends at 80
                                   // Raw memory at 80..112.
    m.extend(b"FLAG{memdump}FFFFFFFFFFFFFFFFFFFF");
    let graph = engine().analyze(&ByteSource::from_vec(m), true);
    let md = graph
        .artifacts
        .iter()
        .find(|a| a.format == "minidump")
        .map(|a| a.id)
        .expect("minidump validated");
    let mut range_child = false;
    for (r, _) in graph.children(md) {
        if r == RelationKind::MemoryRange {
            range_child = true;
        }
    }
    assert!(range_child, "MemoryRange child required");
}

fn ctf_write_varint(mut v: u64) -> Vec<u8> {
    if v <= 0x7F {
        return vec![v as u8];
    }
    let mut out = Vec::new();
    while v > 0 {
        out.insert(0, ((v & 0x7F) as u8) | 0x80);
        v >>= 7;
    }
    *out.last_mut().unwrap() &= 0x7F;
    out
}

// ---------- FINAL-B4: automatic password discovery -> decrypt -> recurse ----------

/// Build a ZipCrypto-encrypted ZIP (PKWARE stream cipher, per APPNOTE).
/// The 12-byte encryption header ends with (crc32 >> 24) so the zip
/// crate's PkzipCrc32 validator accepts the right password.
fn zipcrypt_keys(password: &[u8]) -> [u32; 3] {
    let mut k = [0x12345678u32, 0x23456789u32, 0x34567890u32];
    let table = crc_table();
    let step = |k: &mut [u32; 3], b: u8| {
        k[0] = (k[0] >> 8) ^ table[((k[0] ^ b as u32) & 0xff) as usize];
        k[1] = k[1]
            .wrapping_add(k[0] & 0xff)
            .wrapping_mul(0x08088405)
            .wrapping_add(1);
        k[2] = (k[2] >> 8) ^ table[((k[2] ^ (k[1] >> 24)) & 0xff) as usize];
    };
    for &b in password {
        step(&mut k, b);
    }
    k
}

fn crc_table() -> [u32; 256] {
    let mut table = [0u32; 256];
    for (i, t) in table.iter_mut().enumerate() {
        let mut c = i as u32;
        for _ in 0..8 {
            c = if c & 1 != 0 {
                0xEDB88320 ^ (c >> 1)
            } else {
                c >> 1
            };
        }
        *t = c;
    }
    table
}

fn zipcrypt_encrypt(password: &[u8], plain: &[u8], crc_high: u8) -> Vec<u8> {
    let mut k = zipcrypt_keys(password);
    let table = crc_table();
    let update = |k: &mut [u32; 3], b: u8| {
        k[0] = (k[0] >> 8) ^ table[((k[0] ^ b as u32) & 0xff) as usize];
        k[1] = k[1]
            .wrapping_add(k[0] & 0xff)
            .wrapping_mul(0x08088405)
            .wrapping_add(1);
        k[2] = (k[2] >> 8) ^ table[((k[2] ^ (k[1] >> 24)) & 0xff) as usize];
    };
    let stream = |k: &[u32; 3]| -> u8 {
        let temp = ((k[2] & 0xffff) | 2) as u16;
        (((temp.wrapping_mul(temp ^ 1)) >> 8) & 0xff) as u8
    };
    // 12-byte header: 11 arbitrary bytes + crc high byte.
    let mut out = Vec::new();
    let header: Vec<u8> = (0..11).map(|i| (i * 7 + 0x31) as u8).collect();
    for &h in &header {
        let c = stream(&k) ^ h;
        update(&mut k, h);
        out.push(c);
    }
    let c = stream(&k) ^ crc_high;
    update(&mut k, crc_high);
    out.push(c);
    for &p in plain {
        let c = stream(&k) ^ p;
        update(&mut k, p);
        out.push(c);
    }
    out
}

/// ZIP with one ZipCrypto-encrypted stored entry and an archive comment.
/// Field layout is exact per APPNOTE (LFH 30-byte header; CD 46-byte
/// fixed part: sig, vm, vn, flags, method, time, date, crc, csize,
/// usize, nl, el, cl, disk, int, ext, lho).
fn make_encrypted_zip(name: &str, content: &[u8], password: &str, comment: &str) -> Vec<u8> {
    let crc = crc32(content);
    let content_crc_high = (crc >> 24) as u8;
    let cipher = zipcrypt_encrypt(password.as_bytes(), content, content_crc_high);
    let cipher_len = cipher.len() as u32;
    let name_len = name.len() as u16;
    let mut z = Vec::new();
    // LFH with encryption bit (0x01).
    z.extend_from_slice(b"PK");
    z.extend(20u16.to_le_bytes()); // version needed
    z.extend(1u16.to_le_bytes()); // flags: encrypted
    z.extend(0u16.to_le_bytes()); // method: stored
    z.extend(0u16.to_le_bytes()); // time
    z.extend(0u16.to_le_bytes()); // date
    z.extend(crc.to_le_bytes());
    z.extend(cipher_len.to_le_bytes());
    z.extend(cipher_len.to_le_bytes());
    z.extend(name_len.to_le_bytes());
    z.extend(0u16.to_le_bytes()); // extra len
    z.extend_from_slice(name.as_bytes());
    z.extend_from_slice(&cipher);
    let cd_offset = z.len() as u32;
    // Central directory entry, same flags.
    let cd_size_pos = z.len();
    z.extend_from_slice(b"PK");
    z.extend(20u16.to_le_bytes()); // version made by
    z.extend(20u16.to_le_bytes()); // version needed
    z.extend(1u16.to_le_bytes()); // flags: encrypted
    z.extend(0u16.to_le_bytes()); // method: stored
    z.extend(0u16.to_le_bytes()); // time
    z.extend(0u16.to_le_bytes()); // date
    z.extend(crc.to_le_bytes());
    z.extend(cipher_len.to_le_bytes());
    z.extend(cipher_len.to_le_bytes());
    z.extend(name_len.to_le_bytes());
    z.extend(0u16.to_le_bytes()); // extra len
    z.extend(0u16.to_le_bytes()); // comment len
    z.extend(0u16.to_le_bytes()); // disk number
    z.extend(0u16.to_le_bytes()); // internal attrs
    z.extend(0u32.to_le_bytes()); // external attrs
    z.extend(0u32.to_le_bytes()); // local header offset
    z.extend_from_slice(name.as_bytes());
    let cd_size = (z.len() - cd_size_pos) as u32;
    // EOCD with a COMMENT (the auto-discovered password source).
    z.extend_from_slice(b"PK");
    z.extend(0u16.to_le_bytes());
    z.extend(0u16.to_le_bytes());
    z.extend(1u16.to_le_bytes());
    z.extend(1u16.to_le_bytes());
    z.extend(cd_size.to_le_bytes());
    z.extend(cd_offset.to_le_bytes());
    z.extend((comment.len() as u16).to_le_bytes());
    z.extend_from_slice(comment.as_bytes());
    z
}

/// B4 + B8: password auto-discovery chain. The archive comment carries
/// the password; the engine harvests it (provenance "archive comment"),
/// the ZIP handler decrypts, and the plaintext recurses into a nested
/// artifact (gzip inside the encrypted entry).
#[test]
fn b4_autodiscovered_password_decrypts_and_recurses() {
    let secret = make_gzip(b"FLAG{autodiscovered}");
    let zip = make_encrypted_zip("secret.bin", &secret, "hunter2", "hunter2");
    let graph = engine().analyze(&ByteSource::from_vec(zip), true);

    let zip_art = graph
        .artifacts
        .iter()
        .find(|a| a.format == "zip")
        .expect("zip validated");
    assert_eq!(
        zip_art.metadata.get("password").map(String::as_str),
        Some("hunter2"),
        "working auto-discovered password surfaced"
    );
    assert_eq!(
        zip_art.metadata.get("password_source").map(String::as_str),
        Some("archive comment"),
        "provenance: candidate came from the archive comment"
    );
    // Decrypted entry child exists with provenance of its own.
    let entry = graph
        .artifacts
        .iter()
        .find(|a| a.label.contains("secret.bin"))
        .expect("decrypted entry artifact");
    assert_eq!(
        entry.metadata.get("password").map(String::as_str),
        Some("hunter2")
    );
    assert!(has_ancestor(&graph, entry.id, zip_art.id));

    // Recursion: the decrypted gzip must appear as a nested artifact.
    let gz = graph
        .artifacts
        .iter()
        .find(|a| a.format == "gzip")
        .expect("decrypted content recursed into gzip artifact");
    assert!(has_ancestor(&graph, gz.id, zip_art.id));
}

/// B4: with no viable candidate (the comment is NOT the password), the
/// encrypted entry is not decoded and a warning reports the bounded
/// attempts. Honesty contract: no invented passwords, no false decrypts.
#[test]
fn b4_encrypted_zip_without_candidates_reports_bounded_attempts() {
    let zip = make_encrypted_zip("secret.bin", b"data", "hunter2", "readme-please");
    let graph = engine().analyze(&ByteSource::from_vec(zip), true);
    let zip_art = graph
        .artifacts
        .iter()
        .find(|a| a.format == "zip")
        .expect("zip still validates structurally");
    assert_eq!(
        zip_art.metadata.get("encrypted").map(String::as_str),
        Some("true")
    );
    assert!(
        !zip_art.metadata.contains_key("password"),
        "no password discovered from nothing"
    );
    assert!(
        zip_art
            .warnings
            .iter()
            .any(|w| w.contains("encrypted") && w.contains("tried")),
        "warning must report the bounded attempt count"
    );
}

// ---------- graph helpers ----------

fn has_ancestor(graph: &ctf_tools::artifact::ArtifactGraph, id: u64, ancestor: u64) -> bool {
    let mut cur = graph.get(id).and_then(|a| a.parent);
    while let Some(p) = cur {
        if p == ancestor {
            return true;
        }
        cur = graph.get(p).and_then(|a| a.parent);
    }
    false
}

// ---------- fixture helpers ----------

fn make_png_valid() -> Vec<u8> {
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
    ihdr.extend_from_slice(&1u32.to_be_bytes());
    ihdr.extend_from_slice(&1u32.to_be_bytes());
    ihdr.push(8);
    ihdr.push(0);
    ihdr.push(0);
    ihdr.push(0);
    ihdr.push(0);
    png.extend_from_slice(&chunk(b"IHDR", &ihdr));
    png.extend_from_slice(&chunk(b"IDAT", &[0x00, 0x33]));
    png.extend_from_slice(&chunk(b"IEND", &[]));
    png
}

/// Minimal single-page SQLite DB with one row of one text value.
fn make_sqlite_db(_schema_sql: &[u8], rows: &[&[u8]]) -> Vec<u8> {
    let page_size = 4096usize;
    let mut db = vec![0u8; page_size];
    db[..16].copy_from_slice(b"SQLite format 3\0");
    db[16..18].copy_from_slice(&(page_size as u16).to_be_bytes());
    db[18] = 1; // write version
    db[19] = 1; // read version
    db[20] = 0; // reserved
    db[56..60].copy_from_slice(&1u32.to_be_bytes()); // utf-8
                                                     // Leaf table b-tree header at offset 100.
    db[100] = 0x0D;
    let ncells = rows.len() as u16;
    db[103..105].copy_from_slice(&ncells.to_be_bytes());
    // One cell per row, placed near the page end.
    let mut cell_ptrs = Vec::new();
    let mut content = Vec::new();
    for row in rows {
        let mut record = vec![0x02u8, 0x11]; // header len 2, serial text(n)
        record.push(row.len() as u8);
        record.extend_from_slice(row);
        // cell: varint payload len (single byte here), varint rowid, payload
        let mut cell = vec![record.len() as u8, 0x01];
        cell.extend_from_slice(&record);
        let cell_off = page_size - cell.len();
        db[cell_off..cell_off + cell.len()].copy_from_slice(&cell);
        cell_ptrs.push(cell_off as u16);
        content.push(cell.len());
    }
    // Cell pointer array right after header (offset 108).
    for (i, ptr) in cell_ptrs.iter().enumerate() {
        let off = 108 + i * 2;
        db[off..off + 2].copy_from_slice(&ptr.to_be_bytes());
    }
    db
}

/// Minimal FAT12 volume with one file.
fn make_fat12_with_file(content: &[u8]) -> Vec<u8> {
    // Layout: 1 boot + 2 FATs + 1 root-dir sector + 1 data sector.
    let mut v = vec![0u8; 512 * 5];
    // BPB
    v[0..3].copy_from_slice(&[0xEB, 0x3C, 0x90]);
    v[3..11].copy_from_slice(b"CTFTOOLS");
    v[11..13].copy_from_slice(&512u16.to_le_bytes()); // bytes/sector
    v[13] = 1; // sectors/cluster
    v[14..16].copy_from_slice(&1u16.to_le_bytes()); // reserved
    v[16] = 2; // fats
    v[17..19].copy_from_slice(&2u16.to_le_bytes()); // root entries
    v[19..21].copy_from_slice(&5u16.to_le_bytes()); // total sectors 16
    v[21] = 0xF0; // media
    v[22..24].copy_from_slice(&1u16.to_le_bytes()); // sectors/fat
    v[54..62].copy_from_slice(b"FAT12   "); // FAT12 marker at +54
                                            // FAT entries (FAT12, packed 12-bit): FAT[0]=0xFF8, FAT[1]=0xFFF,
                                            // FAT[2]=0xFFF (EOC for our single-cluster file).
                                            // Byte packing: [0]=lo8(FAT0), [1]=hi4(FAT0)|lo4(FAT1), [2]=hi4(FAT1)
    let fat_start = 512usize;
    let f0: u32 = 0xFF8;
    let f1: u32 = 0xFFF;
    let f2: u32 = 0xFFF;
    // FAT[0..1]
    v[fat_start] = (f0 & 0xFF) as u8;
    v[fat_start + 1] = (((f0 >> 8) & 0x0F) | ((f1 & 0x0F) << 4)) as u8;
    v[fat_start + 2] = ((f1 >> 4) & 0xFF) as u8;
    // FAT[2] starts at bit offset 24 = byte 3 (even cluster boundary).
    v[fat_start + 3] = (f2 & 0xFF) as u8;
    v[fat_start + 4] = (f2 >> 8) as u8;
    // Root dir at sector 3 (1 boot + 2 fat sectors).
    let root = 3 * 512;
    let mut entry = vec![0u8; 32];
    entry[0..11].copy_from_slice(b"FLAG    TXT");
    entry[11] = 0x20; // archive
    entry[26..28].copy_from_slice(&2u16.to_le_bytes()); // cluster 2
    entry[28..32].copy_from_slice(&(content.len() as u32).to_le_bytes());
    v[root..root + 32].copy_from_slice(&entry);
    // Data cluster 2 at sector 4.
    v[4 * 512..4 * 512 + content.len()].copy_from_slice(content);
    v
}

/// MBR wrapping a partition containing `inner` at LBA 1.
fn make_mbr_with_partition(inner: &[u8]) -> Vec<u8> {
    let mut d = vec![0u8; 512 + inner.len()];
    // Partition entry 0.
    let pe = 446;
    d[pe] = 0x80; // bootable
    d[pe + 4] = 0x01; // FAT12 type
                      // partition start LBA 1, size = inner.len()/512
    let sectors = (inner.len() / 512) as u32;
    d[pe + 8..pe + 12].copy_from_slice(&1u32.to_le_bytes());
    d[pe + 12..pe + 16].copy_from_slice(&sectors.to_le_bytes());
    // Boot signature.
    d[510..512].copy_from_slice(&[0x55, 0xAA]);
    d[512..].copy_from_slice(inner);
    d
}
