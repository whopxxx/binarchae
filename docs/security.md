# Security notes

## Threat model / malicious-input assumptions

ctf-tools is built to parse **untrusted, possibly hostile binary data**:

- Input bytes are attacker-controlled: malformed structures, depth bombs,
  ratio bombs, and hostile embedded paths are expected, not exceptional.
- The analysis process must survive arbitrary input without panicking:
  parsing paths use bounds-checked reads, overflow-checked arithmetic,
  and typed errors; there is no casual `unwrap()`/`expect()` on
  attacker-influenced values in production paths.
- One handler failing on a malformed candidate must never abort unrelated
  scanning.

## Extraction path model

Archive entry names and carved labels are attacker-controlled strings.
Every name passes `extract::safe_join` before any filesystem write:

| Attack | Defense |
|---|---|
| `../` traversal (any component) | `ParentDir` components rejected |
| absolute paths | rejected (`is_absolute`, `RootDir`) |
| Windows drive letters (`C:\...`) | prefix/drive components rejected |
| UNC paths (`\\server\share`) | rejected (backslashes normalized to `/`, root components rejected) |
| reserved device names (`CON`, `NUL`, `COM1`, ...) | rejected |
| control characters / weird Unicode | stripped before path construction |
| excessive depth | >24 components rejected |
| duplicate names | deterministic `name__2.ext` suffixing |
| symlink/hardlink escape | entries are written as plain files; link semantics are never preserved |

Additionally:

- Extraction happens only under the deterministic
  `<input>.extracted/artifacts/NNNNNN_<format>/` root.
- Extracted content is **never executed** and no executable permission,
  xattrs, or ownership is preserved.

## Archive-bomb / resource-limit model

Compression bombs are bounded by `EngineLimits`, enforced during
decompression (not after):

- `max_child_size` caps any single expanded stream or archive entry.
- `max_expansion_ratio` caps expanded/compressed ratio per stream —
  a zip/gzip/xz claiming petabytes is cut off at the cap, and the
  refusal is recorded as a typed limit error, not a hang or OOM.
- `max_total_expanded_bytes` is a run-wide budget: every decompressed or
  carved byte is charged to it, so many small bombs cannot add up.
- `max_archive_entries` bounds entry-count inflation.
- `max_depth` and `max_artifacts` bound graph growth from nested
  recursion (zip → gzip → zip → ...).
- M3 additions bound format-specific walks: `max_records` (PCAP
  packets, minidump streams, SQLite rows), `max_partitions` (GPT/MBR),
  `max_streams`, `max_reconstructed_bytes` (fragmented FAT chains),
  `max_sqlite_pages`, `max_registry_cells`, `max_string_candidates`,
  and `max_fs_entries` (directory-entry walks). A hostile filesystem
  image or database cannot spin a walker past the cap.

Work is additionally deduplicated by content hash (BLAKE3): identical
bytes are recursively processed once, which also bounds self-referential
quines and repeated payloads.

## Firmware/initramfs handlers (M2)

The uImage and CPIO handlers follow the same rules, with format-specific
hardening:

- **uImage**: all offsets/sizes use checked arithmetic; `ih_size` must
  both fit the limits and lie inside the source, so a declared petabyte
  payload is rejected instead of truncating trailing scanning. Header CRC
  is verified with the CRC field zeroed before anything else is trusted.
  A data-CRC failure yields an honestly-marked `Damaged` artifact whose
  payload is *not* recursed. Unknown enum values stay numeric — no parser
  path can panic on them.
- **CPIO**: every header field is ASCII hex parsed with a checked decoder
  (malformed digits and overflow reject the entry, not the run).
  Alignment follows the real GNU/Linux layout — stream position after
  `110 + name + NUL` aligned to 4 — verified against a frozen fixture
  from an independent implementation. `namesize` has its own sanity cap
  (names are not file data) and a name without its NUL terminator
  rejects the entry. Entry walking is bounded by a hard internal cap AND
  `max_archive_entries` counted over entries **scanned** — oversized
  entries that skip child creation cannot bypass the limit. The
  `TRAILER!!!` entry structurally anchors the end so a hostile archive
  cannot spin the walker. Archive truncation mid-entry ends the walk and
  fails validation rather than emitting unchecked children.
- **CPIO crc variant**: stored per-entry checksums cover every entry's
  data field — regular files AND symlinks (whose target is the data) —
  verified before type dispatch, **regardless of `max_child_size`**
  (oversized entries are checksummed streaming in bounded chunks;
  `max_child_size` only decides child exposure, never checksum success).
  Mismatch marks the entry and downgrades the archive to `Damaged`:
  corruption is reported, never silently accepted, and a tampered
  symlink target cannot yield `Validated`.
- **Special entries are never materialized**: symlinks keep their target
  as metadata; device nodes, FIFOs, and sockets are recognized and carry
  `host_materialization: forbidden`. No host special file is ever created.
- **Source-backed children are zero-copy views**, so exposing a huge
  embedded file as an artifact costs no allocation and cannot be used to
  inflate memory via dedup or recursion — the bytes already existed in the
  input. Registration stores only a handle; bytes are read at
  materialization time, so analysis memory does not scale with the number
  or size of embedded files. They are not charged as decompression
  expansion; owned children (decompression output) continue to use the
  run-wide expansion budget.

## Forensics & recovery handlers (M3)

The forensics and recovery additions follow the same contract:

- **SQLite**: page sizes must be powers of two in [512, 65536] (or the
  1→65536 encoding); text encoding must be one of the three defined
  values. B-tree walking is depth-capped (12) and page-bounded
  (`max_sqlite_pages`); overflow chains are followed with cycle
  detection and a hard visited-set cap, so a cyclic chain terminates
  with a typed validation error rather than a hang.
- **PCAP/PCAPNG**: record/block lengths are bounds-checked against the
  source before any slice; a record claiming more bytes than remain
  ends the walk with the complete packets still reported (honest
  truncation, not a crash). PCAPNG block chains reject lengths < 12
  that would loop.
- **Minidump**: stream counts are capped before the directory walk;
  memory-range descriptors are bounds-checked before slicing.
- **Registry**: hive-bin sizes are bounds-checked; cell sizes are
  signed per the format and a cell that overruns its bin ends the bin
  walk; the cell count is capped by `max_registry_cells`.
- **ZIP salvage (recovery)**: runs *last* and stands down whenever an
  intact EOCD exists — recovery never masks honest validation of
  undamaged archives. Inflate output is hard-capped and charged to the
  run-wide budget mid-stream; a corrupt stream keeps partial output and
  reports the truncation rather than failing the whole salvage.
- **Strings/hints**: output is always `Confidence::Heuristic` and
  bounded by `max_string_candidates`; string hints are metadata, never
  validated artifacts, and never materialized as files.

## M3 hardening (round 2)

- **FAT**: BPB layout arithmetic is fully checked — reserved + FAT
  sectors + root-directory sectors must fit `total_sectors`; a hostile
  BPB is rejected instead of wrapping into a huge cluster count.
- **Compression**: zlib/bzip2/Zstd/LZ4 stream chunk-by-chunk through the
  source (no candidate-to-EOF `read_all()` before limits apply); frame
  ends are exact (zlib ADLER, zstd `findFrameCompressedSize`, LZ4
  EndMark), so trailing data after a frame stays discoverable.
- **SQLite**: overflow pages use full `page_size` stride; the per-spec
  X/M/K local-payload rule is implemented; `max_sqlite_pages` bounds the
  b-tree walk and overflow chains.
- **Minidump**: RVAs resolve relative to the dump start; Memory64List
  uses its real layout (u64 count, u64 BaseRva, contiguous memory).
- **ELF/PE/Mach-O**: artifact size is the provable structural end
  (section table / section raw data / load commands + segment files),
  never "rest of input" — trailing-data provenance stays correct.

## Fuzzing

`fuzz/` contains three cargo-fuzz targets exercising the engine, every
handler's `validate()` on arbitrary (offset, bytes), and the user TOML
carving-rule parser. The invariant under fuzz: arbitrary input may be
rejected or analyzed, but must never panic, read out of bounds, or
hang. Run on a nightly toolchain with `cargo fuzz run <target>`.

## Out of scope for the analysis process

- No shell-outs to external extraction tools on any supported path.
- No network access, no process spawning, no dynamic code loading.
