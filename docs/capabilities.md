# Capabilities

Current state through Issue #7 (feature-complete baseline). Nothing on
this page claims support that is not implemented. Formats marked
**Partial** are structurally parsed but do not reconstruct full
internal structure; the limits are stated explicitly.

## Format matrix

### Images / documents

| Format | Detect | Validate | Size | Extract | Recurse | Metadata |
|---|---:|---:|---:|---:|---:|---|
| PNG | yes | yes | yes (IEND-proven) | chunks/metadata | yes | dimensions, chunk types |
| JPEG | yes | yes (EOI-proven) | yes | metadata | yes | dimensions, segments |
| GIF | yes | yes (block walk, trailer) | yes | yes | yes | dimensions, frames |
| BMP | yes | yes (header fields, data size) | yes | yes | yes | dimensions, depth |
| TIFF | yes | yes (IFD walk, endian) | yes | yes | yes | dimensions, IFD entries |
| WebP | yes | yes (RIFF/VP8 container walk) | yes | yes | yes | dimensions, chunk list |
| PDF | yes | yes (xref verified via startxref: keyword, entry count, canonical entries, trailer /Size) | stream-bounded | raw streams | yes | xref offset/entries + trailer size metadata; object scan; streams carved raw (filters not applied — honest warning); unverifiable startxref degrades to Partial |

### Compression / archives

| Format | Detect | Validate | Size | Extract | Recurse | Notes |
|---|---:|---:|---:|---:|---:|---|
| ZIP | yes | yes (central directory, EOCD boundary) | yes | yes | yes | encrypted entries DECRYPTED via the shared password queue (ZipCrypto); working candidate + provenance surfaced |
| gzip | yes | yes (CRC32/ISIZE) | yes | yes | yes | |
| XZ | yes | yes (container + LZMA2) | yes | yes | yes | |
| zlib/deflate | yes / no-sig | yes | yes | yes | yes | raw deflate is no-signature (discovered via nesting) |
| bzip2 | yes | yes (CRC) | yes | yes | yes | |
| Zstd | yes | yes (frame walk) | yes | yes | yes | skippable frames handled |
| LZ4 | yes | yes (frame walk) | yes | yes | yes | |
| Brotli | no-sig | yes | yes | yes | yes | no signature exists; discovered via nesting only |
| LZMA-alone | yes | yes (props+size plausibility) | yes | yes | yes | `.lzma` 13-byte header format |
| TAR | yes | yes (ustar/salvage walk) | yes | yes (salvage) | yes | complete entries before corruption; truncated entries flagged |
| CPIO newc/crc | yes | yes (TRAILER!!!/checksum) | yes | yes | yes | busybox-verified fixtures |
| AR | yes | yes (member walk) | yes | yes | yes | source-backed members |
| DEB | yes | yes (ar + control/data) | yes | member-level | yes | |
| CAB | yes | yes (CFHEADER + entries) | yes | yes | yes | |
| 7z | yes | yes (sevenz-rust2) | yes | yes | yes | password candidates via `--password` + auto-discovery (shared bounded queue) |
| RAR (1.3–7) | yes | yes (rars decode) | yes | yes | yes | password candidates via `--password` + auto-discovery; recovery-record parsing not included |

### Media

| Format | Detect | Validate | Size | Extract | Recurse | Notes |
|---|---:|---:|---:|---:|---:|---|
| RIFF (WAV/AVI) | yes | yes (chunk walk) | yes | chunks | yes | |
| MP3 | yes | yes (strict frame sync + chaining) | yes | yes | yes | |
| FLAC | yes | yes (STREAMINFO + metadata) | yes | yes | yes | |
| OLE (CFB) | yes | yes (header + FAT + dir tree) | yes | stream bytes via FAT and mini-FAT chains | yes | mini-stream resolved through the root entry; extraction budget-capped and size-truncated; storage provenance (fat/mini-fat) recorded |
| RTF | yes | yes (brace balance) | partial | metadata | yes | |

### Executables / binaries

| Format | Detect | Validate | Size | Extract | Recurse | Notes |
|---|---:|---:|---:|---:|---:|---|
| ELF | yes | yes (header + sections) | yes (section-table-proven) | sections | yes | |
| PE | yes | yes (DOS+NT headers) | yes | sections | yes | file-backed sections as children (name/characteristics) |
| Mach-O | yes | yes (header + load commands + segments) | yes | metadata | yes | |
| WASM | yes | yes (magic + section walk) | yes | sections | yes | |
| RTF | yes | yes | partial | metadata | yes | |

### Disk / filesystems

| Format | Detect | Validate | Size | Extract | Recurse | Notes |
|---|---:|---:|---:|---:|---:|---|
| MBR | yes | yes (sig + entries + EBR chain) | n/a | partitions | yes | PartitionOf relation |
| GPT | yes | yes (header CRC + entry CRC) | n/a | partitions | yes | |
| FAT12/16/32 | yes | yes (BPB + FAT + dirs) | n/a | files + deleted entries | yes | LFN; deleted dir entries surfaced (CarvedFrom); fragmented files via ReconstructedFrom |
| exFAT | yes | yes (BPB + bitmap + dirs) | n/a | files | yes | |
| NTFS | yes | yes (boot + MFT walk) | yes | resident + run data | yes | deleted (not-in-use) records surfaced with `deleted=true`; update-sequence fixups |
| ext2/3/4 | yes | yes (superblock + group desc + inode walk) | yes | files | yes | |
| SquashFS | yes | yes (superblock + metadata blocks + dir walk) | yes | files | yes | |
| ISO9660 | yes | yes (PVD + recursive dir walk) | yes | files | yes | Joliet (UCS-2BE) supplementary volumes |
| UBI | yes | yes (EC/VID headers + volume table CRC) | yes | volume images | yes | volumes as ReconstructedFrom children |
| UBIFS | yes | yes (superblock/master/index walk) | yes | files | yes | none/zlib/zstd decode; LEB layout |
| JFFS2 | yes | yes (CRC-validated node scan + tree) | yes | files | yes | RTIME + zlib compression; deleted-node handling |
| YAFFS2 | yes | yes (aligned chunk-stride candidate scan + packed tags2 validation, tree walk) | yes | files | yes | mkyaffs2image layout (2048+64); highest-seq wins per (obj, chunk); extra-header parents/types |
| cramfs | yes | yes (superblock + dir walk) | yes | files | yes | |
| ROMFS | yes | yes (superblock + entry chain) | yes | files | yes | |

### Firmware

| Format | Detect | Validate | Size | Extract | Recurse | Notes |
|---|---:|---:|---:|---:|---:|---|
| uImage (legacy) | yes | yes (header+data CRC) | yes | payload | yes | MULTI type supported |
| FIT/DTB | yes | yes (structure token walk) | yes | nodes | yes | |
| Android boot | yes | yes (magic + page layout) | yes | slots | yes | source-backed kernel/ramdisk |
| Android sparse | yes | yes (chunk walk) | yes | expanded image | yes | RAW/FILL/DONT_CARE/CRC32 chunks; CRC verified |
| TRX | yes | yes (header + offsets) | yes | partitions | yes | |
| BCM63xx tag | yes | yes (ASCII struct + region bounds) | yes | CFE/kernel/rootfs regions | yes | |
| UEFI firmware volume | yes | yes (FV + FFS files + sections) | yes | RAW/PE32/TE payloads + UI names | yes | COMPRESSION/GUID_DEFINED sections detected |
| U-Boot FIT images (itb) | via DTB | yes | yes | yes | yes | |

### Databases / forensics

| Format | Detect | Validate | Size | Extract | Recurse | Notes |
|---|---:|---:|---:|---:|---:|---|
| SQLite | yes | yes (header + b-tree walk) | yes | records + BLOBs | yes | overflow chains; BLOB values recurse |
| Registry (regf) | yes | yes (hbin cell walk + nk tree) | yes | typed values | yes | key paths via parent links; REG_DWORD/QWORD/SZ/MULTI_SZ decoded, REG_BINARY as children |
| PCAP | yes | yes (record walk) | yes | packets + TCP streams + HTTP + DNS + HID | yes | all 4 magic variants; sequence-aware reassembly; gaps reported |
| PCAPNG | yes | yes (block chain) | yes | same as PCAP | yes | IDB linktype honored; full reconstruction parity |
| DNS | via PCAP/PCAPNG | yes (RFC 1035 walk) | n/a | TXT/NULL rdata children | yes | query/answer metadata; payloads recurse |
| USB HID | via linktype 220 | yes (usbmon header) | n/a | keystroke text | yes | key-down edge detection; bounded to 4096 chars |
| Minidump | yes | yes (stream directory) | yes | memory ranges + module/thread/system metadata | yes | streams 3/4/5/7/9 |
| PAGEDU64 | yes | yes (physical run table) | yes | packed run regions | yes | dump types 1/5/6/8/9/0xA named |
| Strings/URL/flag hints | yes | heuristic | n/a | n/a | no | Heuristic confidence — never claims validation |

## Required cross-domain chains (verified in tests/)

| Chain | Status |
|---|---|
| PNG → trailing data → ZIP → member | yes (per-hop provenance asserted) |
| gzip → SQLite → DatabaseRecord rows | yes |
| PCAP/PCAPNG → sequence-aware TCP stream → HTTP body → archive/image | yes |
| GPT → PartitionOf → filesystem (FAT) → nested file | yes |
| SQLite → DatabaseRecord BLOB → nested artifact (e.g. PNG) | yes |
| Registry → REG_BINARY value → artifact | yes |
| Registry → REG_BINARY → nested artifact (payload recursed) | yes |
| Minidump → MemoryRange → artifact | yes |
| MBR → partition → FAT → file (incl. deleted entries) | yes |
| uImage → gzip kernel → payload | yes |
| Truncated ZIP/TAR → salvage → Recovered entries | yes |
| DNS exfil → TXT rdata → payload child | yes |
| USB HID reports → keystroke text | yes |
| Polyglot (PNG+ZIP) → both members validated + provenance | yes |

## Recovery

| Capability | Status |
|---|---|
| Truncated ZIP salvage (local-entry structural salvage) | yes — `Confidence::Recovered`, never masks intact archives |
| Partial deflate output on corrupt streams | yes (partial bytes kept with warning) |
| TAR salvage (entries before corruption; truncated final entry) | yes (`truncated=true`, declared size kept) |
| NTFS deleted records (resident data recovered, flagged) | yes |
| FAT deleted directory entries (metadata + cluster hint) | yes |
| Encrypted/streaming-entry handling in salvage | yes (skipped with warnings) |
| Generic carving (header/footer/next-header/max) | yes (builtin + user TOML rules) |

## Owned vs source-backed child content

Handler-produced children are one of:

- **Owned** — freshly generated bytes (decompression output, decoded
  archive members, reconstructed TCP streams). Bounded by the run-wide
  expansion budget.
- **Source-backed** — a bounded `ByteSource` region referencing bytes
  already present in the parent input. Zero-copy: registration stores
  a region **handle**, not bytes. Extraction streams source-backed
  artifacts to disk in 64 KiB chunks — a multi-gigabyte partition is
  never materialized in memory (§11).

## Cross-cutting capabilities

| Capability | Status |
|---|---|
| Trailing-data detection after validated structures | yes (recursive) |
| Leading-data before first structure | yes |
| Interior gaps between validated structures (#7 §9) | yes (`InteriorGap` artifacts) |
| Overlap edges for distinct validated overlapping artifacts (polyglots) | yes |
| Generic carving (builtin + user TOML rules) | yes |
| Bounded entropy analysis | yes |
| Classified entropy regions (sparse/mixed/high, transition-grouped) | yes (`regions:` line, JSONL) |
| Content dedup (BLAKE3) with provenance preservation | yes |
| Resource limits (depth/artifacts/bytes/entries/ratio/records/fs-entries/streams) | yes, configurable |
| Safe extraction (traversal/UNC/drive/symlink/dup-name) | yes |
| Streaming extraction of source-backed artifacts (#7 §11) | yes (64 KiB bounded copy) |
| Human compact tree output | yes |
| Stable JSON output (serde round-trip) | yes |
| JSONL output — one record/line, stable IDs (#7 §12.1) | yes (`--jsonl`) |
| Automatic password discovery (comments/strings/filenames) + provenance (`password_source`) | yes |
| Dedicated `max_password_attempts` limit bounding trial decryption | yes |
| Fuzzing harness (cargo-fuzz, 10 targets incl. per-format-family) | yes |
| Fuzz-smoke CI job (bounded, per-PR) | yes |
| Benchmarks (criterion: 4 scan + 7 expanded scenarios) | yes |
| Package + install smoke CI (cargo package / install / analyze fixture) | yes |
| External executables required | **none** |

## Explicitly not supported / known limits

- LZFSE decode — deliberately excluded: only C-binding crate exists
  (see docs/dependencies.md dependency policy).
- PDF stream *filter* decoding (streams are carved raw with an honest
  warning; FlateDecode etc. not applied).
- 7z/RAR recovery-record parsing.
- Full TCP stack semantics: sequence-aware reassembly handles
  out-of-order/duplicates/gaps within capture bounds; no handshake
  state machine, no OS-fingerprint-style heuristics.
- USB request/setup-stage decoding beyond interrupt-IN HID reports.
- GUI/web UI, MCP, plugin ecosystem.

Each "not supported" above is a deliberate scoping decision documented
here; none of the shipped formats degrade to magic-only detection.
