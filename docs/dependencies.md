# Dependencies

Why each dependency exists, its license, and its native/unsafe
footprint. Kept current with `Cargo.toml`; the authoritative license
inventory for a release is the SBOM (`cargo cyclonedx` JSON attached to
release assets by the release workflow, alongside the resolved
lockfile and a `cargo tree` dump).

Policy: pure-Rust dependencies are strongly preferred. A C-backed
dependency is accepted only when no maintained pure-Rust alternative
exists AND the format is high-value for CTF work; each such case is
documented below. LZFSE, for example, is intentionally NOT supported:
the only available crate is a C binding (`lzfse-sys`) and the format
is rare enough in CTF corpora to skip rather than take on a C toolchain
dependency for Windows/musl cross builds.

## CLI / serialization

| Crate | License | Native? | Why |
|---|---|---|---|
| clap | MIT/Apache-2.0 | no | CLI argument parsing (`--extract`, `--json`, `--jsonl`, limits). |
| serde + serde_json | MIT/Apache-2.0 | no | Stable JSON/JSONL output of the artifact graph. |
| toml | MIT/Apache-2.0 | no | User-defined carving-rule files. |
| termcolor | MIT/Apache-2.0 | no | Terminal coloring (compact human output). |

## Hashing / checksums

| Crate | License | Native? | Why |
|---|---|---|---|
| blake3 | MIT/Apache-2.0 | SIMD via runtime detect; safe Rust core | Content identity / dedup of every artifact. |
| crc32fast | MIT/Apache-2.0 | no | ZIP/PNG/NCP/UBI/FAT-style CRC-32 checks. |
| crc | MIT/Apache-2.0 | no | Non-standard CRC variants used by some firmware headers. |

## Compression / archive decoding

| Crate | License | Native? | Why |
|---|---|---|---|
| flate2 (rust_backend) | MIT/Apache-2.0 | no | gzip/zlib/deflate decode. |
| bzip2 | MIT | **C** (bzip2) | bzip2 decode; no pure-Rust decoder with comparable robustness when introduced. |
| zstd | BSD-3 | **C** (zstd) | Zstandard decode (UBIFS, XZ-less firmware). |
| lz4_flex | MIT | no | LZ4 block/frame decode (pure Rust, chosen over lz4-sys). |
| brotli | MIT/Apache-2.0/ BSD-3 | no | Brotli decode. |
| lzma-rust | MIT | no | LZMA-alone decode; pure Rust port of the Java LZMA SDK. |
| xz | MIT | no (via lzma-rust) | XZ/LZMA2 container decode where present. |
| tar | MIT/Apache-2.0 | no | (superseded by the native salvage walker; retained for entry-name round-trips.) |
| zip | MIT | no (deflate via flate2) | ZIP entry decode; `default-features = false`, deflate only. |
| sevenz-rust2 | MIT | no | 7z archive decode incl. password candidates. |
| cab | MIT/Apache-2.0 | no | MS Cabinet decode. |
| rars | MIT/Apache-2.0 | no | RAR 1.3-7 decode incl. password candidates (pure-Rust; replaced the C unrar option deliberately). |

## Native/unsafe inventory (summary)

- C code compiled: bzip2 (libbz2), zstd (libzstd) — only under their
  respective features; both are exercised by `cargo build` on Linux
  GNU, Linux musl, and Windows MSVC in CI.
- `unsafe` in our own crate: none (enforced by review; `ByteSource`
  bounds-checks every access).
- Runtime-detected SIMD: blake3 (no build-time target coupling).

## Platform notes

- Windows MSVC, Linux GNU, Linux musl are the supported targets
  (release assets for all three + SHA256; musl build is CI-gated).
- The C-backed crates are the only portability risk; they are exercised
  in all three CI targets so a breakage is caught on PR.

## Integrity

- `Cargo.lock` is NOT committed (the crate is an end-user binary and
  `.gitignore` excludes it); version pins come from the exact
  dependency declarations and CI resolves them fresh on every build.
- Releases attach `Cargo.lock` and a dependency inventory generated at
  release time by the release workflow (`cargo generate-lockfile` +
  `cargo tree`), not a pre-committed lockfile.
