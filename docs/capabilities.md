# Capabilities

Current state of the first milestone (M0/M1). Nothing on this page claims
support that is not implemented.

## Format matrix

| Format | Detect | Validate | Size | Extract | Recurse | Salvage | Metadata |
|---|---:|---:|---:|---:|---:|---:|---:|
| PNG | yes | yes | yes (IEND-proven) | chunks/metadata | yes | no | yes (dimensions, chunk types) |
| JPEG | yes | yes | yes (EOI-proven) | metadata | yes | no | yes (dimensions, segments) |
| PDF | yes | partial | partial (%%EOF-based; heuristic when absent) | metadata | yes | no | yes (version) |
| ZIP | yes | yes (central directory) | yes | yes | yes | limited | yes (entries, encryption flag) |
| gzip | yes | yes (CRC32/ISIZE trailer) | yes | yes | yes | no | yes (sizes) |
| XZ | yes | yes (container walk + LZMA2) | yes (footer-anchored) | yes | yes | no | yes (sizes, blocks) |
| TAR | yes | yes (ustar headers) | yes | yes | yes | limited | yes (entry names) |
| GIF | carved | footer-bounded | yes | bytes only | no | yes | no |
| RAR | carved | no | bounded | no (recovery only) | no | yes | no |
| 7z | carved | no | bounded | no (recovery only) | no | yes | no |

## Cross-cutting capabilities

| Capability | Status |
|---|---|
| Trailing-data detection after validated structures | yes (recursive) |
| Leading-data before first structure | basic (via region scanning) |
| Generic carving (header/footer/next-header/max-size) | yes (builtin + user TOML rules) |
| Bounded entropy analysis | yes (16 sampled blocks, compact output) |
| Content dedup (BLAKE3) with provenance preservation | yes |
| Resource limits (depth/artifacts/bytes/entries/ratio) | yes, configurable |
| Safe extraction (traversal/UNC/drive/symlink/dup-name) | yes |
| Human compact tree output | yes |
| Stable JSON output (serde round-trip) | yes |
| External executables required | **none** |

## Explicitly not yet supported

RAR/7z extraction, filesystems (FAT/NTFS/ext/SquashFS), firmware
containers, Registry/MFT/SQLite deep parsing, PCAP reconstruction,
minidumps, GUI/web UI, MCP, plugin ecosystem. These are follow-up work on
top of this foundation.
