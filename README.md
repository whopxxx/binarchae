# binwalkx

Recursive binary archaeology for extraction, recovery, and artifact analysis in Rust.

Core invariant: **every useful thing discovered from input data is an
Artifact, and every parser/extractor exists to discover additional
artifacts.** The engine builds a provenance-preserving artifact graph over
nested containers, trailing data, and carved regions — the typical shape
of CTF binary challenges.

> The normal supported path does **not** shell out to external extraction
> programs (`7z`, `unrar`, `foremost`, `cabextract`, `unsquashfs`, Python
> packages, ...). All parsing and extraction is native Rust.

## Build / install from source

Requires a current stable Rust toolchain.

```bash
git clone https://github.com/whopxxx/binwalkx
cd binwalkx
cargo build --release
# binary at target/release/binwalkx
```

## CLI examples

```bash
# Analyze and print a compact artifact tree
binwalkx file.bin

# Materialize recoverable/extractable artifacts under file.bin.extracted/
binwalkx -e file.bin

# Recursively analyze child artifacts
binwalkx -r file.bin

# Recursive analysis + extraction
binwalkx -er file.bin

# Stable JSON output (graph with IDs, provenance, offsets, hashes, evidence)
binwalkx --json file.bin

# Verbose diagnostics (warnings + evidence facts)
binwalkx -v file.bin

# Custom carving rules
binwalkx --carving-rules rules.toml file.bin
```

Example output on a PNG with an appended ZIP:

```text
#0 input challenge.png 192 bytes @0
  #1 png PNG image 1x1 59 bytes @0
  #3 zip ZIP archive (1 entries) 133 bytes @59
    #4 raw zip entry flag.txt 19 bytes @0
entropy: 0x0(4.05)
```

## Supported formats

Structural parsing across the core CTF format space — no magic-only
stubs for the major formats:

- **Archives/compression**: ZIP (incl. ZipCrypto decryption with
  auto-discovered or `--password` candidates), gzip, XZ, zlib, bzip2,
  Zstd, LZ4, LZMA-alone, TAR (incl. truncated-entry salvage), CPIO
  (newc/crc), AR, DEB, CAB, RAR (via `rars`; encrypted candidates
  tried), 7z (extraction; encrypted candidates tried); Brotli/deflate
  via nesting (no signature exists — stated honestly).
- **Images/media**: PNG, JPEG, GIF, BMP, TIFF, WebP, RIFF (WAV/AVI),
  MP3 (strict frame validation), FLAC.
- **Executables/documents**: ELF, PE, Mach-O, WASM, OLE/CFB (stream
  extraction via FAT and mini-FAT chains), RTF.
- **Disks/filesystems**: MBR (+EBR chains), GPT (CRC-verified), FAT12/16/32
  (LFN, fragmented-file reconstruction), ISO9660, exFAT, NTFS (fixups,
  runlists incl. sparse/wide deltas, deleted-MFT recovery), ext2/3/4
  (extent trees, gapped extents), SquashFS (contiguous multi-block
  files), JFFS2 (node walk, compressed fragments), YAFFS2 (packed
  tags2, tree walk), UBI/UBIFS, cramfs, ROMFS, Android sparse.
- **Firmware**: uImage (legacy, CRC-verified), DTB/FIT, Android boot,
  TRX, UEFI firmware volume incl. FFS section walk and LZMA
  COMPRESSION/GUID_DEFINED section decoding (Tiano type 1 stays
  metadata-only, stated honestly).
- **Forensics**: SQLite (b-tree walk, records, overflow chains), PCAP
  (all endianness variants), PCAPNG (per-interface linktypes), Windows
  Minidump (+ PAGEDU64 memory ranges), Registry hive (regf-spec cell
  walk, subkey lists li/lf/lh/ri), sequence-aware TCP reassembly with
  HTTP framing and DNS-over-UDP/TCP, base64/hex channel decoding, USB
  HID keystroke reconstruction, entropy regions, string/URL/flag hints
  (heuristic).
- **Documents**: PDF (xref verification against the startxref table,
  raw stream carving — /Filter decoding not applied, stated honestly).
- **Recovery**: truncated-ZIP local-entry salvage — partial data beats
  none; recovered children are labeled `Recovered`, never `Validated`,
  and recovery never masks honest validation of intact archives.

Password candidates propagate automatically: archive comments,
printable strings, and entry filenames harvested from every scanned
region feed one deterministic bounded queue (`--password` candidates
keep priority); a working candidate is surfaced with its provenance
(`password_source`) on the artifact.

Child artifacts carry a confidence claim (`Validated`, `Recovered`,
`Partial`, `Heuristic`) with structural evidence facts — recovered
bytes are always distinguishable from structurally decoded ones.

Handler children are either **owned bytes** (decompression output,
bounded by expansion limits) or **source-backed regions** (zero-copy
views into the parent input). Source-backed artifacts stream to disk in
bounded chunks at extraction time — large partitions/files are never
materialized in memory.

Dependency provenance, licenses, and the native/unsafe footprint are
documented in [docs/dependencies.md](docs/dependencies.md); release
history in [CHANGELOG.md](CHANGELOG.md).

## Development

```bash
cargo test --workspace          # unit + integration scenarios
cargo bench                     # criterion scan + expanded benchmarks
cargo install cargo-fuzz && cargo fuzz run handler_roundtrip     # fuzzing (nightly)
```

`fuzz/` includes per-format-family targets (archives, filesystems,
registry/sqlite, network, memory forensics, firmware, documents) and a
bounded fuzz-smoke job in CI; long campaigns remain manual.

## Resource limits

Analysis of untrusted input is bounded by configurable limits
(recursion depth, artifact count, total expanded bytes, child size,
archive entries, compression ratio) — see `--help` and
[docs/security.md](docs/security.md).

## License

Dual-licensed under MIT or Apache-2.0 (see LICENSE-MIT / LICENSE-APACHE).
