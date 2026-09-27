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

## Current supported formats

| Format | Support level |
|---|---|
| PNG | structural chunk walk, IEND-proven boundary, trailing-data detection |
| JPEG | marker-aware validation, EOI boundary |
| PDF | structural validation, honest validated/heuristic status |
| ZIP | native inspection + extraction, encrypted-entry recognition |
| gzip | native decompression, resource limits |
| XZ | native container walk + LZMA2, resource limits |
| TAR | native entry extraction, safe-path rules |
| GIF/RAR/7z | generic carving fallback (recovery only) |

See [docs/capabilities.md](docs/capabilities.md) for the full matrix,
[docs/architecture.md](docs/architecture.md) for the engine design, and
[docs/security.md](docs/security.md) for the extraction safety model.

## Resource limits

Analysis of untrusted input is bounded by configurable limits
(recursion depth, artifact count, total expanded bytes, child size,
archive entries, compression ratio) — see `--help` and
[docs/security.md](docs/security.md).

## License

Dual-licensed under MIT or Apache-2.0 (see LICENSE-MIT / LICENSE-APACHE).
