# ctf-tools

CTF-first binary analysis and extraction tool in Rust.

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
git clone https://github.com/whopxxx/ctf-tools
cd ctf-tools
cargo build --release
# binary at target/release/ctf-tools
```

## CLI examples

```bash
# Analyze and print a compact artifact tree
ctf-tools file.bin

# Materialize recoverable/extractable artifacts under file.bin.extracted/
ctf-tools -e file.bin

# Recursively analyze child artifacts
ctf-tools -r file.bin

# Recursive analysis + extraction
ctf-tools -er file.bin

# Stable JSON output (graph with IDs, provenance, offsets, hashes, evidence)
ctf-tools --json file.bin

# Verbose diagnostics (warnings + evidence facts)
ctf-tools -v file.bin

# Custom carving rules
ctf-tools --carving-rules rules.toml file.bin
```

Example output on a PNG with an appended ZIP:

```text
#0 input challenge.png 192 bytes @0
  #1 png PNG image 1x1 59 bytes @0
  #3 zip ZIP archive (1 entries) 133 bytes @59
    #4 raw zip entry flag.txt 19 bytes @0
entropy: 0x0(4.05)
```

## Supported formats (M3 core roadmap)

Structural parsing across the core CTF format space — no magic-only
stubs for the major formats:

- **Archives/compression**: ZIP, gzip, XZ, zlib, bzip2, Zstd, LZ4, TAR,
  CPIO (newc/crc), AR, DEB, CAB, 7z (extraction; encrypted detected);
  Brotli/deflate via nesting (no signature exists — stated honestly).
- **Images/media**: PNG, JPEG, GIF, BMP, TIFF, WebP, RIFF (WAV/AVI),
  MP3 (strict frame validation), FLAC.
- **Executables**: ELF, PE, Mach-O, WASM, OLE/CFB, RTF.
- **Disks/filesystems**: MBR (+EBR chains), GPT (CRC-verified), FAT12/16/32
  (LFN, fragmented-file reconstruction), ISO9660; NTFS/ext/SquashFS/UBI
  superblock-level (documented Partial).
- **Firmware**: uImage (legacy, CRC-verified), DTB/FIT, Android boot,
  TRX, UEFI firmware volume (Partial).
- **Forensics**: SQLite (b-tree walk, records, overflow chains), PCAP
  (all endianness variants), PCAPNG, Windows Minidump, Registry hive
  (hbin/cell walk, Partial), string/URL/flag hints (heuristic).
- **Recovery**: truncated-ZIP local-entry salvage — partial data beats
  none, and recovery never masks honest validation of intact archives.

Handler children are either **owned bytes** (decompression output) or
**source-backed regions** (zero-copy views into the parent input) — the
latter is what makes firmware images, disk images, and packet captures
cheap to analyze.
See [docs/capabilities.md](docs/capabilities.md) for the full matrix,
[docs/architecture.md](docs/architecture.md) for the engine design, and
[docs/security.md](docs/security.md) for the extraction safety model.

Handler children are either **owned bytes** (decompression output) or
**source-backed regions** (zero-copy views into the parent input) — the
latter is what makes firmware/initramfs containers cheap to analyze.
See [docs/capabilities.md](docs/capabilities.md) for the full matrix,
[docs/architecture.md](docs/architecture.md) for the engine design, and
[docs/security.md](docs/security.md) for the extraction safety model.

## Development

```bash
cargo test --workspace          # unit + integration scenarios
cargo bench                     # criterion scan benchmarks
cargo install cargo-fuzz && cargo fuzz run engine_scan_memory   # fuzzing (nightly)
```

`fuzz/` targets the whole engine, per-handler validation, and the
carving-rule parser; `benches/` tracks scan throughput regressions.

## Resource limits

Analysis of untrusted input is bounded by configurable limits
(recursion depth, artifact count, total expanded bytes, child size,
archive entries, compression ratio) — see `--help` and
[docs/security.md](docs/security.md).

## License

Dual-licensed under MIT or Apache-2.0 (see LICENSE-MIT / LICENSE-APACHE).
