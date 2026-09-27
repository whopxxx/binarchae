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

## Out of scope for the analysis process

- No shell-outs to external extraction tools on any supported path.
- No network access, no process spawning, no dynamic code loading.
