# Changelog

All notable changes to binarchae. Format based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versioning is
`0.x` until the first stable tag.

## [Unreleased] — Issue #7 feature-complete baseline

### Added

- Filesystems: exFAT, NTFS (MFT walk, resident + non-resident runs,
  deleted-record recovery), ext, SquashFS, ISO9660 + Joliet (recursive
  dir walk), UBI (EC/VID walk, volume table) + UBIFS (index walk,
  compressed data), JFFS2 (CRC-validated nodes, RTIME/zlib decode,
  unlink handling), cramfs, ROMFS, YAFFS2 (mkyaffs2image layout,
  version-ordered assembly), Android sparse image expansion, UEFI FFS
  section walk, BCM63xx tag regions.
- Archives: RAR extraction incl. password candidates via `rars`,
  7z password-candidate loop, LZMA-alone decode, LZFSE deliberately
  excluded (C-binding-only dependency; documented in
  docs/dependencies.md).
- Formats: PDF object scan + raw stream carving, OLE stream tree,
  ELF/PE/Mach-O/WASM region exposure (PE sections as children),
  SQLite row/BLOB traversal, LZMA-alone.
- Memory forensics: Minidump ModuleList/ThreadList/SystemInfo
  metadata streams, PAGEDU64 physical-run exposure, string hints.
- Registry: full hive walk (hbin cells, nk/vk records), key-path
  reconstruction via parent links, typed value decoding (DWORD/QWORD/
  SZ/MULTI_SZ as text-or-number, BINARY as children).
- Network (#7 §7): sequence-aware bounded TCP reassembly (out-of-order,
  retransmission, honest gap reporting), HTTP framing (Content-Length +
  chunked decoding, body-only children the engine recurses into),
  DNS-over-UDP parsing (TXT/NULL rdata as children), USB HID keystroke
  reconstruction (usbmon-mmapped linktype 220). PCAP and PCAPNG share
  the same pipeline.
- Recovery (#7 §8): TAR salvage (complete entries before corruption,
  truncated final entries flagged truncated), NTFS deleted records
  (resident content + `deleted=true`), existing ZIP salvage retained.
- Artifact graph (#7 §9): InteriorGap relation for unexplained bytes
  between validated structures, Overlap edges for distinct validated
  overlapping artifacts (polyglots), generic carving still cannot erase
  stronger structural claims.
- Entropy (#7 §10): transition-grouped classified regions
  (sparse/mixed/high) with compact `regions:` line.
- Streaming (#7 §11): source-backed artifacts extract via 64 KiB
  chunked copies through zero-copy region handles (no whole-artifact
  allocation).
- Output (#7 §12): `--jsonl` mode (one record per line, stable IDs),
  entropy regions in JSON/JSONL, candidate provenance (passwords,
  gaps, deleted status, flow identity, key paths) in metadata.
- CLI: `--password` (repeatable, propagated to 7z/RAR/ZIP), `--jsonl`.
- Testing: per-family fuzz targets (archive, filesystem,
  registry+sqlite, network, memory-forensics, firmware, document),
  fuzz-smoke CI job, package + install smoke CI job, expanded
  criterion benchmarks (signature scan, file-backed source, nested
  archives, SQLite, Registry, PCAP reassembly, entropy mapping).
- Docs: docs/dependencies.md (provenance/license/native footprint +
  why each crate exists), CHANGELOG.md.

### Changed

- TAR handler: manual salvage walk replaces the tar-crate
  all-or-nothing parse.
- PcapHandler: capture-order concatenation replaced by sequence-aware
  reassembly; HTTP children are body-only (headers become metadata).
- Registry: values are DatabaseRecord children carrying key_path.
- Human output: `regions:` line replaces raw entropy blocks when
  grouping is available.

### Security

- Path sanitization unchanged (no traversal, no absolute paths, no
  Windows device names); symlink/materialization policies unchanged.
- Fuzz targets exercise candidate + validate + salvage paths for all
  high-risk format families.

## [0.1.x] — earlier

See git history (development milestones: artifact graph, recursion +
dedup, extraction safety, first 20 handlers).
