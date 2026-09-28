# Capabilities

Current state through milestone M3 (core roadmap completion). Nothing on
this page claims support that is not implemented. Formats marked
**Partial** are structurally parsed but do not yet reconstruct full
internal structure; the limits are stated explicitly.

## Format matrix

### Images / documents (M1)

| Format | Detect | Validate | Size | Extract | Recurse | Metadata |
|---|---:|---:|---:|---:|---:|---|
| PNG | yes | yes | yes (IEND-proven) | chunks/metadata | yes | dimensions, chunk types |
| JPEG | yes | yes | yes (EOI-proven) | metadata | yes | dimensions, segments |
| PDF | yes | partial | partial (%%EOF-based) | metadata | yes | version |
| GIF | yes | yes (block walk, trailer) | yes | yes | yes | dimensions, frames |
| BMP | yes | yes (header fields, data size) | yes | yes | yes | dimensions, depth |
| TIFF | yes | yes (IFD walk, endian) | yes | yes | yes | dimensions, IFD entries |
| WebP | yes | yes (RIFF/VP8 container walk) | yes | yes | yes | dimensions, chunk list |

### Compression / archives (M1+M3)

| Format | Detect | Validate | Size | Extract | Recurse | Notes |
|---|---:|---:|---:|---:|---:|---|
| ZIP | yes | yes (central directory) | yes | yes | yes | encrypted entries flagged |
| gzip | yes | yes (CRC32/ISIZE) | yes | yes | yes | |
| XZ | yes | yes (container + LZMA2) | yes | yes | yes | |
| zlib/deflate | yes / no-sig | yes | yes | yes | yes | raw deflate is no-signature (explicit opt-in via nesting) |
| bzip2 | yes | yes (CRC) | yes | yes | yes | |
| Zstd | yes | yes (frame walk) | yes | yes | yes | skippable frames handled |
| LZ4 | yes | yes (frame walk) | yes | yes | yes | |
| Brotli | no-sig | yes | yes | yes | yes | no signature exists; discovered via nesting only |
| TAR | yes | yes (ustar) | yes | yes | yes | |
| CPIO newc/crc | yes | yes (TRAILER!!!/checksum) | yes | yes | yes | busybox-verified fixtures |
| AR | yes | yes (member walk) | yes | yes | yes | source-backed members |
| DEB | yes | yes (ar + control/data) | yes | member-level | yes | |
| CAB | yes | yes (CFHEADER + entries) | yes | yes | yes | |
| 7z | yes | yes (via sevenz-rust2) | yes | yes | yes | encrypted archives detected |
| RAR | carved | no | bounded | no | no | honest recovery-only |

### Media (M3)

| Format | Detect | Validate | Size | Extract | Recurse | Notes |
|---|---:|---:|---:|---:|---:|---|
| RIFF (WAV/AVI) | yes | yes (chunk walk) | yes | chunks | yes | |
| MP3 | yes | yes (strict frame sync + chaining) | yes | yes | yes | MPEG1 field validation prevents compressed-data false positives |
| FLAC | yes | yes (STREAMINFO + metadata) | yes | yes | yes | |
| OLE (CFB) | yes | yes (header + FAT) | partial | metadata | yes | Partial: full stream tree not reconstructed |
| RTF | yes | yes (brace balance) | partial | metadata | yes | |

### Executables / binaries (M3)

| Format | Detect | Validate | Size | Extract | Recurse | Notes |
|---|---:|---:|---:|---:|---:|---|
| ELF | yes | yes (header + sections) | yes (section-table-proven) | sections | yes | section/program headers |
| PE | yes | yes (DOS+NT headers + section raw data) | yes (proven boundary) | metadata | yes | sections not carved individually |
| Mach-O | yes | yes (header + load commands + segments) | yes (proven boundary) | metadata | yes | |
| WASM | yes | yes (magic + section walk) | yes | sections | yes | |

### Disk / filesystems (M3)

| Format | Detect | Validate | Size | Extract | Recurse | Notes |
|---|---:|---:|---:|---:|---:|---|
| MBR | yes | yes (sig + partition entries + EBR chain) | n/a | partitions | yes | PartitionOf relation |
| GPT | yes | yes (header CRC + entry CRC) | n/a | partitions | yes | CRC-verified |
| FAT12/16/32 | yes | yes (BPB + FAT + dirs) | n/a | files | yes | LFN; fragmented files via ReconstructedFrom |
| exFAT | no | no | no | no | no | not implemented |
| NTFS | yes | partial (boot sector) | no | no | no | Partial (documented) |
| ext2/3/4 | yes | partial (superblock) | no | no | no | Partial (documented) |
| SquashFS | yes | partial (superblock) | partial | no | no | Partial (documented) |
| ISO9660 | yes | yes (PVD + root extent) | yes | root listing | yes | |
| UBI/UBIFS | yes | partial (EC headers) | no | no | no | Partial (documented) |
| JFFS2/cramfs/ROMFS | no | no | no | no | no | not implemented |

### Firmware (M3)

| Format | Detect | Validate | Size | Extract | Recurse | Notes |
|---|---:|---:|---:|---:|---:|---|
| uImage (legacy) | yes | yes (header+data CRC) | yes | payload | yes | MULTI type supported |
| FIT/DTB | yes | yes (structure token walk) | yes | nodes | yes | DTB properties |
| Android boot | yes | yes (magic + page layout) | yes | slots | yes | source-backed kernel/ramdisk |
| Android sparse | yes | yes (chunk walk) | partial | no | no | Partial |
| TRX | yes | yes (header + offsets) | yes | partitions | yes | |
| UEFI firmware volume | yes | partial (FV header + GUID) | partial | no | no | Partial |
| U-Boot FIT images (itb) | via DTB | yes | yes | yes | yes | |

### Databases / forensics (M3)

| Format | Detect | Validate | Size | Extract | Recurse | Notes |
|---|---:|---:|---:|---:|---:|---|
| SQLite | yes | yes (header + b-tree walk) | yes | records + BLOBs | yes | schema + table rows as DatabaseRecord children; BLOB values recurse (nested artifacts); overflow chains per X/M/K rule |
| Registry (regf) | yes | partial (hbin/cell walk) | n/a | REG_BINARY values | no | Partial: nk/vk cell counting; REG_BINARY values surface as source-backed children |
| PCAP | yes | yes (record walk) | yes | packets + HTTP | yes | all 4 magic endianness variants (us/ns); truncated captures → Partial; TCP/HTTP object reconstruction (ReconstructedFrom children) |
| PCAPNG | yes | yes (block chain) | yes | packets | yes | SHB/EPB walk |
| Minidump | yes | yes (stream directory) | yes | memory ranges | yes | MemoryList/Memory64List → MemoryRange children |
| Strings/URL/flag hints | yes | heuristic | n/a | n/a | no | Heuristic confidence — never claims validation |

## Required cross-domain chains (Issue #5, verified in tests/m3_integration.rs)

| Chain | Status |
|---|---|
| PNG → trailing data → ZIP → member | yes (per-hop provenance asserted) |
| gzip → SQLite → DatabaseRecord rows | yes |
| PCAP → TCP/HTTP reconstruction → HTTP object artifact | yes |
| GPT → PartitionOf → filesystem (FAT) → nested file | yes |
| SQLite → DatabaseRecord BLOB → nested artifact (e.g. PNG) | yes |
| Registry → REG_BINARY value → artifact | yes |
| Minidump → MemoryRange → artifact | yes |
| MBR → partition → FAT → file | yes |
| uImage → gzip kernel → payload | yes |
| Truncated ZIP → salvage → Recovered entries | yes |

## Recovery (M3)

| Capability | Status |
|---|---|
| Truncated ZIP salvage (local-entry structural salvage) | yes — `Confidence::Recovered`, never masks intact archives |
| Partial deflate output on corrupt streams | yes (partial bytes kept with warning) |
| Encrypted/streaming-entry handling in salvage | yes (skipped with warnings) |
| CPIO/tar damaged-archive honesty | Damaged/Partial confidence in primary handlers |
| Generic carving (header/footer/next-header/max) | yes (builtin + user TOML rules) |

## Owned vs source-backed child content

Handler-produced children are one of:

- **Owned** — freshly generated bytes (decompression output such as
  gzip/XZ payloads, decoded archive members). These participate in the
  run-wide expansion budget.
- **Source-backed** — a bounded `ByteSource` region referencing bytes
  already present in the parent input (uImage payloads, CPIO file
  contents, ZIP/TAR members, PCAP packets, minidump memory ranges,
  Android boot slots). Zero-copy: slices over one memory input share
  the original backing allocation. Registration stores a region
  **handle**, not bytes — copying happens only when extraction
  materializes the artifact.

Source-backed children are not falsely billed as decompression expansion —
they represent bytes that already existed in the input.

## Cross-cutting capabilities

| Capability | Status |
|---|---|
| Trailing-data detection after validated structures | yes (recursive) |
| Leading-data before first structure | yes |
| Generic carving (builtin + user TOML rules) | yes |
| Bounded entropy analysis | yes |
| Content dedup (BLAKE3) with provenance preservation | yes |
| Resource limits (depth/artifacts/bytes/entries/ratio/records/fs-entries) | yes, configurable |
| Safe extraction (traversal/UNC/drive/symlink/dup-name) | yes |
| Human compact tree output | yes |
| Stable JSON output (serde round-trip) | yes |
| Fuzzing harness (cargo-fuzz, 3 targets) | yes |
| Benchmarks (criterion, 4 scenarios) | yes |
| External executables required | **none** |

## Explicitly not yet supported / known limits

- RAR/7z *recovery-record* parsing; RAR extraction (recovery-only).
- exFAT, JFFS2, cramfs, ROMFS filesystems.
- NTFS/ext/SquashFS/UBI full-entry extraction (superblock-level only).
- Registry key-tree reconstruction (REG_BINARY value extraction works;
  full key hierarchy and REG_SZ/REG_MULTI_SZ decoding remain).
- Per-flow TCP stream reassembly (sequence-number based, multi-packet
  retransmission handling); HTTP carving over capture-order payload
  concatenation works today.
- GUI/web UI, MCP, plugin ecosystem.

Each "not yet" above is a deliberate scoping decision documented here;
none of the shipped formats degrade to magic-only detection.
