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
  `namesize` is sanity-capped before any allocation; entry walking is
  bounded by both a hard internal cap and `max_archive_entries`; the
  `TRAILER!!!` entry structurally anchors the end so a hostile archive
  cannot spin the walker. Archive truncation mid-entry ends the walk and
  fails validation rather than emitting unchecked children.
- **CPIO crc variant**: stored per-entry checksums are verified; mismatch
  marks entries and downgrades the archive to `Damaged` — corruption is
  reported, never silently accepted.
- **Special entries are never materialized**: symlinks keep their target
  as metadata; device nodes, FIFOs, and sockets are recognized and carry
  `host_materialization: forbidden`. No host special file is ever created.
- **Source-backed children are zero-copy views**, so exposing a huge
  embedded file as an artifact costs no allocation and cannot be used to
  inflate memory via dedup or recursion — the bytes already existed in the
  input. They are not charged as decompression expansion; owned children
  (decompression output) continue to use the run-wide expansion budget.

## Out of scope for the analysis process

- No shell-outs to external extraction tools on any supported path.
- No network access, no process spawning, no dynamic code loading.
