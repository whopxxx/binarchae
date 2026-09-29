//! Handler abstraction and the recursive engine.
//!
//! Staged model:
//!   fast candidate discovery -> structural validation -> boundary
//!   determination -> artifact creation -> optional extraction/child
//!   discovery -> recursive analysis.
//!
//! Magic bytes are candidates, not proof. Malformed candidates never abort
//! unrelated scanning; each handler failure is contained.

use crate::artifact::{
    Artifact, ArtifactGraph, ArtifactId, Confidence, Evidence, ExtractionStatus, RelationKind,
};
use crate::bytesource::ByteSource;
use crate::content_hash;
use crate::error::Result;
use crate::handlers;
use std::collections::BTreeMap;

/// Configurable resource limits, enforced from the very beginning.
#[derive(Debug, Clone)]
pub struct EngineLimits {
    /// Maximum recursion depth below the root artifact.
    pub max_depth: u32,
    /// Maximum number of artifacts in the graph.
    pub max_artifacts: usize,
    /// Maximum total decompressed/carved bytes across the run.
    pub max_total_expanded_bytes: u64,
    /// Maximum size of any single child artifact.
    pub max_child_size: u64,
    /// Maximum entries extracted from one archive.
    pub max_archive_entries: usize,
    /// Maximum decompressed/compressed expansion ratio.
    pub max_expansion_ratio: u64,
    /// M3/A2: maximum parser records (MFT entries, SQLite rows, PCAP
    /// packets, FAT dir entries...) per artifact.
    pub max_records: usize,
    /// M3/A2: maximum partitions per disk image.
    pub max_partitions: usize,
    /// M3/A2: maximum network streams per capture.
    pub max_streams: usize,
    /// M3/A2: maximum reconstructed stream bytes per run.
    pub max_reconstructed_bytes: u64,
    /// M3/A2: maximum SQLite pages walked per database.
    pub max_sqlite_pages: usize,
    /// M3/A2: maximum registry cells visited per hive.
    pub max_registry_cells: usize,
    /// M3/A2: maximum string/candidate hints reported per region.
    pub max_string_candidates: usize,
    /// M3/A2: maximum filesystem entries per filesystem.
    pub max_fs_entries: usize,
    /// #7: password candidates for encrypted containers (7z/RAR/ZIP).
    /// Users supply them via CLI `--password` (repeatable); handlers
    /// try each candidate against password-protected entries and
    /// surface the working one as artifact metadata.
    pub passwords: Vec<String>,
    /// FINAL-B4: maximum password attempts per encrypted artifact
    /// across the shared candidate queue (CLI + auto-discovered).
    /// Bounds the cost of trial decryption against untrusted data.
    pub max_password_attempts: usize,
    /// FINAL-R4: container entry filenames reported by handlers during
    /// this run (ZIP central directory, 7z/RAR member tables). The
    /// engine harvests password candidates from them with
    /// PasswordSource::Filename provenance.
    pub entry_names: Vec<String>,
}

impl Default for EngineLimits {
    fn default() -> Self {
        EngineLimits {
            max_depth: 8,
            max_artifacts: 512,
            max_total_expanded_bytes: 512 * 1024 * 1024,
            max_child_size: 64 * 1024 * 1024,
            max_archive_entries: 4_096,
            max_expansion_ratio: 200,
            max_records: 100_000,
            max_partitions: 128,
            max_streams: 1_024,
            max_reconstructed_bytes: 64 * 1024 * 1024,
            max_sqlite_pages: 65_536,
            max_registry_cells: 1_000_000,
            max_string_candidates: 4_096,
            max_fs_entries: 65_536,
            passwords: Vec::new(),
            max_password_attempts: 32,
            entry_names: Vec::new(),
        }
    }
}

/// Run-wide byte budget shared by the whole analysis. Handlers charge it
/// *during* decompression (per chunk), never after the fact; it is passed
/// by `&mut` and never cloned, so every charge is visible run-wide.
#[derive(Debug, Default)]
pub struct Budget {
    pub expanded_bytes: u64,
}

impl Budget {
    /// Charge `n` expanded bytes. Fails (without partial accounting)
    /// when the run-wide limit would be exceeded.
    pub(crate) fn charge(&mut self, limits: &EngineLimits, n: u64) -> bool {
        let Some(next) = self.expanded_bytes.checked_add(n) else {
            return false;
        };
        if next > limits.max_total_expanded_bytes {
            return false;
        }
        self.expanded_bytes = next;
        true
    }
}

/// What a handler produced for one candidate region.
#[derive(Debug, Default)]
pub struct HandlerOutput {
    /// Artifact fields for the validated (or partially validated) region.
    pub artifacts: Vec<ArtifactDraft>,
}

/// Artifact fields before graph registration (ids assigned by engine).
#[derive(Debug)]
pub struct ArtifactDraft {
    pub format: String,
    pub label: String,
    /// Offset within the scanned source.
    pub offset: u64,
    pub size: u64,
    pub confidence: Confidence,
    pub evidence: Evidence,
    pub metadata: BTreeMap<String, String>,
    pub warnings: Vec<String>,
    pub errors: Vec<String>,
    /// Child artifacts decompressed/extracted by this handler.
    pub children: Vec<ChildDraft>,
    /// FINAL-R4: container entry filenames seen by the handler (ZIP
    /// central directory, 7z/RAR member tables). The engine harvests
    /// password candidates from them with PasswordSource::Filename
    /// provenance.
    pub entry_names: Vec<String>,
}

/// Content of a handler-produced child. Firmware containers (uImage,
/// CPIO) reference byte ranges that ALREADY exist contiguously in the
/// parent source; decompressors produce fresh owned bytes. Source-backed
/// children must not require a full copy merely to become artifacts.
#[derive(Debug)]
pub enum ChildContent {
    /// Owned/generated bytes (decompression, archive decode).
    Owned(Vec<u8>),
    /// A cheap bounded region referencing bytes already present in a
    /// parent source. Shares the backing allocation; no copying.
    Source(ByteSource),
}

/// A child produced by a handler (decompressed stream, archive member,
/// firmware payload range...).
#[derive(Debug)]
pub struct ChildDraft {
    pub relation: RelationKind,
    pub label: String,
    pub format_hint: &'static str,
    pub content: ChildContent,
    /// Size of the content in bytes (for both variants).
    pub size: u64,
    pub metadata: BTreeMap<String, String>,
    pub warnings: Vec<String>,
    /// Name if extracted from an archive (used by the extraction layer).
    pub entry_name: Option<String>,
    /// FINAL-B7: the handler's honest claim about these bytes. A
    /// handler that RECOVERED (rather than structurally decoded) the
    /// content must say so — the engine no longer stamps every child
    /// as Validated on the handler's behalf.
    pub confidence: Confidence,
    /// Structural facts backing the confidence claim.
    pub evidence: Vec<String>,
}

impl ChildDraft {
    /// Convenience constructor: structurally decoded child. Handlers
    /// that recovered damaged content should override `confidence`
    /// afterwards (or build the struct directly).
    #[allow(clippy::too_many_arguments)]
    pub fn decoded(
        relation: RelationKind,
        label: String,
        format_hint: &'static str,
        content: ChildContent,
        size: u64,
        metadata: BTreeMap<String, String>,
        warnings: Vec<String>,
        entry_name: Option<String>,
    ) -> Self {
        ChildDraft {
            relation,
            label,
            format_hint,
            content,
            size,
            metadata,
            warnings,
            entry_name,
            confidence: Confidence::Validated,
            evidence: vec!["structurally decoded by parent handler".to_string()],
        }
    }

    /// Convenience constructor: RECOVERED bytes (salvaged from damaged
    /// input — deleted records, heuristic carving). Honest by default.
    #[allow(clippy::too_many_arguments)]
    pub fn recovered(
        relation: RelationKind,
        label: String,
        format_hint: &'static str,
        content: ChildContent,
        size: u64,
        metadata: BTreeMap<String, String>,
        warnings: Vec<String>,
        entry_name: Option<String>,
    ) -> Self {
        ChildDraft {
            confidence: Confidence::Recovered,
            evidence: vec!["bytes recovered from damaged/erased source".to_string()],
            ..ChildDraft::decoded(
                relation,
                label,
                format_hint,
                content,
                size,
                metadata,
                warnings,
                entry_name,
            )
        }
    }
}

impl ChildContent {
    /// Hash of the content: exact region hash for source-backed
    /// children, in-memory BLAKE3 for owned bytes.
    pub fn hash(&self) -> String {
        match self {
            ChildContent::Owned(bytes) => content_hash(bytes),
            ChildContent::Source(src) => src.hash_all(),
        }
    }

    /// Materialize the content into memory. Callers must respect limits
    /// before invoking this on untrusted sizes.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        match self {
            ChildContent::Owned(bytes) => Ok(bytes.clone()),
            ChildContent::Source(src) => src.read_all(),
        }
    }
}

/// A candidate hit: "there might be format X at offset O".
#[derive(Debug, Clone, Copy)]
pub struct Candidate {
    pub offset: u64,
}

/// One format handler. Implementations own their validation/boundary logic.
pub trait Handler: Send + Sync {
    /// Short format id, e.g. "png".
    fn format(&self) -> &'static str;

    /// Fast candidate discovery over the source. Must be cheap and must
    /// not itself validate structure.
    fn find_candidates(&self, src: &ByteSource) -> Vec<Candidate>;

    /// Structural validation + boundary determination for one candidate.
    /// Returns Err on validation failure (false positive candidate) —
    /// the engine records this and moves on without aborting.
    ///
    /// Implementations must charge `budget` incrementally while expanding
    /// attacker-controlled data, so bombs are cut off mid-stream.
    fn validate(
        &self,
        src: &ByteSource,
        candidate: Candidate,
        limits: &EngineLimits,
        budget: &mut Budget,
    ) -> Result<HandlerOutput>;
}

/// All builtin handlers, in priority order.
pub fn builtin_handlers() -> Vec<Box<dyn Handler>> {
    vec![
        Box::new(handlers::png::PngHandler),
        Box::new(handlers::jpeg::JpegHandler),
        Box::new(handlers::uimage::UImageHandler),
        Box::new(handlers::zip::ZipHandler),
        Box::new(handlers::gzip::GzipHandler),
        Box::new(handlers::xz::XzHandler),
        Box::new(handlers::compression::ZlibHandler),
        Box::new(handlers::compression::Bzip2Handler),
        Box::new(handlers::compression::ZstdHandler),
        Box::new(handlers::compression::Lz4Handler),
        Box::new(handlers::compression::LzmaAloneHandler),
        Box::new(handlers::archives::ArHandler),
        Box::new(handlers::archives::DebHandler),
        Box::new(handlers::archives::CabHandler),
        Box::new(handlers::archives::SevenZHandler),
        Box::new(handlers::archives::RarHandler),
        Box::new(handlers::media::GifHandler),
        Box::new(handlers::media::BmpHandler),
        Box::new(handlers::media::TiffHandler),
        Box::new(handlers::media::WebPHandler),
        Box::new(handlers::media::RiffHandler),
        Box::new(handlers::media::Mp3Handler),
        Box::new(handlers::media::FlacHandler),
        Box::new(handlers::exec::ElfHandler),
        Box::new(handlers::exec::PeHandler),
        Box::new(handlers::exec::MachOHandler),
        Box::new(handlers::exec::WasmHandler),
        Box::new(handlers::exec::OleHandler),
        Box::new(handlers::exec::RtfHandler),
        Box::new(handlers::disk::GptHandler),
        Box::new(handlers::disk::MbrHandler),
        Box::new(handlers::fat::FatHandler),
        Box::new(handlers::exfat::ExfatHandler),
        Box::new(handlers::filesystems::SquashfsHandler),
        Box::new(handlers::filesystems::Iso9660Handler),
        Box::new(handlers::filesystems::Jffs2Handler),
        Box::new(handlers::ext::ExtHandler),
        Box::new(handlers::filesystems::ExtHandler),
        Box::new(handlers::ntfs::NtfsHandler),
        Box::new(handlers::filesystems::NtfsHandler),
        Box::new(handlers::filesystems::UbiVolumeHandler),
        Box::new(handlers::filesystems::UbifsHandler),
        Box::new(handlers::filesystems::Yaffs2Handler),
        Box::new(handlers::romfs::RomfsHandler),
        Box::new(handlers::cramfs::CramfsHandler),
        Box::new(handlers::firmware::DtbHandler),
        Box::new(handlers::firmware::AndroidSparseHandler),
        Box::new(handlers::firmware::Bcm63xxTagHandler),
        Box::new(handlers::firmware::AndroidBootHandler),
        Box::new(handlers::firmware::TrxHandler),
        Box::new(handlers::firmware::UefiFvHandler),
        Box::new(handlers::sqlite::SqliteHandler),
        Box::new(handlers::forensics::RegistryHandler),
        Box::new(handlers::forensics::PcapHandler),
        Box::new(handlers::forensics::PcapngHandler),
        Box::new(handlers::forensics::MinidumpHandler),
        Box::new(handlers::forensics::Pagedu64Handler),
        Box::new(handlers::cpio::CpioHandler),
        Box::new(handlers::tar::TarHandler),
        Box::new(handlers::pdf::PdfHandler),
        // Recovery handlers run last: they stand down whenever a primary
        // handler validated the region and only fire on damaged input.
        Box::new(handlers::recovery::ZipSalvageHandler),
    ]
}

/// Recursive analysis engine. Same engine for root and child artifacts.
pub struct RecursiveEngine {
    pub limits: EngineLimits,
    pub handlers: Vec<Box<dyn Handler>>,
    /// Extra user-defined carving rules (CLI --carving-rules).
    pub carving_rules: Vec<crate::carving::CarveRule>,
    /// Content hashes already recursively processed (dedup). Multiple
    /// logical artifacts may share bytes; recursive work happens once.
    processed_hashes: std::collections::HashSet<String>,
    /// In-memory bytes for handler-produced children, keyed by content
    /// hash. Powers extraction without re-parsing.
    pub byte_cache: std::collections::HashMap<String, Vec<u8>>,
    /// B1: handles for materializable byte regions (handler children and
    /// region-backed artifacts), keyed by content hash. Registration is
    /// zero-copy: the engine stores the ByteSource view, and bytes are
    /// only read when extraction actually materializes them.
    pub region_cache: std::collections::HashMap<String, ByteSource>,
    /// F1: expansion spend per source-region content hash. Guarantees a
    /// given byte region's decompression is billed to the run-wide budget
    /// exactly once, even when the region is validated multiple times
    /// (root pass, then trailing-region pass) or its draft is deferred.
    spends_by_region: std::collections::HashMap<String, u64>,
    /// FINAL-B4: shared password-candidate vault. CLI candidates are
    /// seeded first; handlers/engine harvest further candidates from
    /// every scanned region (comments, strings, filenames) with
    /// provenance. One deterministic attempt queue serves all handlers.
    pub password_vault: crate::passwords::PasswordVault,
}

impl RecursiveEngine {
    pub fn new(limits: EngineLimits) -> Self {
        let mut password_vault = crate::passwords::PasswordVault::new();
        // FINAL-B4: operator-supplied candidates keep highest priority —
        // they are seeded first and the queue is order-preserving.
        password_vault.seed_from_cli(&limits.passwords);
        RecursiveEngine {
            limits,
            handlers: builtin_handlers(),
            carving_rules: Vec::new(),
            processed_hashes: std::collections::HashSet::new(),
            byte_cache: std::collections::HashMap::new(),
            region_cache: std::collections::HashMap::new(),
            spends_by_region: std::collections::HashMap::new(),
            password_vault,
        }
    }

    /// Bytes recorded for an artifact hash, if any. Reads the stored
    /// region handle lazily; used by tests and extraction. Prefer
    /// [`RecursiveEngine::region_handle`] when a streaming write is
    /// possible — this materializes the full region in memory.
    pub fn cached_bytes(&self, hash: &str) -> Option<Vec<u8>> {
        self.byte_cache
            .get(hash)
            .cloned()
            .or_else(|| self.region_cache.get(hash).and_then(|r| r.read_all().ok()))
    }

    /// Zero-copy handle for a materializable region, keyed by content
    /// hash. Extraction reads through this handle (or streams it) at
    /// materialization time — analysis never copies the bytes.
    pub fn region_handle(&self, hash: &str) -> Option<&ByteSource> {
        self.region_cache.get(hash)
    }

    /// Analyze a root source and return the full artifact graph.
    ///
    /// With `recurse = false` only the top-level region is scanned;
    /// children and trailing/leading regions are registered but not
    /// recursively analyzed. This is the CLI default (`-r` enables
    /// recursion).
    pub fn analyze(&mut self, src: &ByteSource, recurse: bool) -> ArtifactGraph {
        let mut graph = ArtifactGraph::new();
        let mut budget = Budget::default();
        let root_id = self.register_root_stub(&mut graph, src);
        self.scan_region(src, root_id, 0, recurse, &mut graph, &mut budget, 0);
        graph
    }

    fn register_root_stub(&mut self, graph: &mut ArtifactGraph, src: &ByteSource) -> ArtifactId {
        // B2: content identity covers the WHOLE source, streamed.
        let hash = src.hash_all();
        let artifact = Artifact {
            id: 0,
            parent: None,
            relation: None,
            format: "input".to_string(),
            label: src
                .file_path()
                .map(|p| p.display().to_string())
                .unwrap_or_else(|| "<memory>".to_string()),
            offset: 0,
            size: src.len(),
            hash,
            confidence: Confidence::Validated,
            evidence: Evidence::facts(["root input region"]),
            extraction: ExtractionStatus::NotExtracted,
            metadata: BTreeMap::new(),
            warnings: Vec::new(),
            errors: Vec::new(),
        };
        graph.push_root(artifact)
    }

    /// Scan one region of the source with all handlers, register results,
    /// and recurse into children. Never panics on malformed candidates:
    /// every handler call is error-isolated.
    #[allow(clippy::too_many_arguments)]
    fn scan_region(
        &mut self,
        src: &ByteSource,
        parent_id: ArtifactId,
        depth: u32,
        recurse: bool,
        graph: &mut ArtifactGraph,
        budget: &mut Budget,
        // `region_start`: absolute offset of this region within the
        // ROOT source (0 at root; > 0 for nested region scans).
        region_start: u64,
    ) {
        if depth > self.limits.max_depth {
            if let Some(p) = graph.get_mut(parent_id) {
                p.warnings.push(format!(
                    "recursion depth limit {} reached; region not scanned",
                    self.limits.max_depth
                ));
            }
            return;
        }
        if graph.len() >= self.limits.max_artifacts {
            return;
        }

        // FINAL-B4: harvest password candidates from this region into
        // the shared vault (comments, strings). CLI candidates were
        // seeded first and keep queue priority. Dedup + caps keep this
        // deterministic and bounded regardless of region content.
        let harvested = crate::passwords::harvest_from_region(src, &self.limits);
        self.password_vault.merge(harvested);

        // FINAL-S2: entry-filename candidates merge AFTER the region
        // scan loop below accepts drafts (accepted drafts carry
        // `entry_names`). Deferred there: filenames only exist once a
        // container handler parsed its directory.

        // Effective limits for this region's handler calls: the shared
        // vault queue is exposed through `passwords` so every encrypted-
        // container handler (ZIP / 7z / RAR) sees ONE deterministic,
        // bounded candidate queue without per-handler discovery.
        let mut effective_limits = self.limits.clone();
        effective_limits.passwords = self
            .password_vault
            .candidates()
            .iter()
            .take(self.limits.max_password_attempts)
            .map(|c| c.password.clone())
            .collect();
        // Provenance lookup for accepted drafts (built before the
        // `spends_by_region` borrow so it can be read inside the loop).
        let password_sources: std::collections::HashMap<String, &'static str> = self
            .password_vault
            .candidates()
            .iter()
            .map(|c| (c.password.clone(), c.source.as_str()))
            .collect();

        // Collect drafts from every handler; handler errors are isolated.
        // R1 (transactional accounting): each candidate is validated with
        // a SHADOW of the run-wide budget. Charges commit only when the
        // candidate is accepted; a rejected/malformed/limit-hit candidate
        // rolls back. Additionally (F1): every ACCEPTED candidate's spend
        // is recorded per source-region hash. When a draft is later
        // dropped by the region decomposition (rediscovered inside a
        // trailing region), the rescan looks up the region's recorded
        // spend, re-applies it as a SHADOW (so handler-side ratio caps
        // still work), and commits nothing — one logical expansion is
        // billed exactly once run-wide.
        let mut drafts: Vec<ArtifactDraft> = Vec::new();
        let spends_by_region = &mut self.spends_by_region;
        for handler in &self.handlers {
            for candidate in handler.find_candidates(src) {
                // F1: candidates are validated against a SHADOW budget
                // seeded at zero. This keeps every handler-side protection
                // active (per-stream ratio caps, child-size caps) while
                // making the shadow's run-wide accounting independent of
                // whatever was billed earlier in the run. After validation:
                //   - a REJECTED candidate commits nothing (its shadow
                //     spend is discarded — malformed candidates can never
                //     permanently drain the run-wide budget);
                //   - an ACCEPTED candidate commits the shadow spend only
                //     for source regions not already billed (one logical
                //     expansion is billed exactly once, even when a draft
                //     is deferred to a trailing region and re-validated).
                let mut shadow = Budget::default();
                match handler.validate(src, candidate, &effective_limits, &mut shadow) {
                    Ok(output) => {
                        for mut draft in output.artifacts {
                            // Commit against the run-wide budget under the
                            // real limits; regions already billed commit 0.
                            // G1: when the run-wide commit FAILS, the draft
                            // is refused outright — expanded children must
                            // never enter the graph on an unbilled charge.
                            let region_hash = src
                                .slice(draft.offset, draft.size)
                                .map(|r| r.hash_all())
                                .ok();
                            let already_billed = region_hash
                                .as_ref()
                                .is_some_and(|h| spends_by_region.contains_key(h));
                            // FINAL-B4: enrich any working-password
                            // metadata with vault provenance (where the
                            // candidate came from). Handlers that already
                            // recorded `password_source` are left alone.
                            if let Some(p) = draft.metadata.get("password").cloned() {
                                if !draft.metadata.contains_key("password_source") {
                                    if let Some(s) = password_sources.get(&p) {
                                        let source = (*s).to_string();
                                        draft
                                            .metadata
                                            .insert("password_source".to_string(), source);
                                    }
                                }
                            }
                            if already_billed {
                                // One logical expansion per region: no new
                                // charge. The draft's children still get
                                // registered downstream, but the child loop
                                // deduplicates byte-identical nodes via the
                                // content hash (edge reuse), so no unbilled
                                // bytes can enter the graph twice.
                                drafts.push(draft);
                            } else {
                                let spend = shadow.expanded_bytes;
                                if budget.charge(&self.limits, spend) {
                                    if let Some(h) = region_hash {
                                        spends_by_region.insert(h, spend);
                                    }
                                    drafts.push(draft);
                                }
                                // else: run-wide budget exhausted — this
                                // candidate's expansion is refused. The
                                // shadow's partial bytes are discarded;
                                // unrelated scanning continues.
                            }
                        }
                    }
                    Err(_e) => {
                        // Rejected candidate: shadow spend discarded, real
                        // budget untouched.
                    }
                }
            }
        }

        // FINAL-S2: entry filenames from accepted drafts feed the shared
        // vault with `Filename` provenance. Merged AFTER the candidate
        // loop so a candidate derived from this container's own entries
        // can still serve any LATER encrypted sibling/handler in this
        // run; the vault dedups and caps attempts. Clones are bounded:
        // entry_names come from parsed directory listings that handlers
        // already capped.
        let names: Vec<String> = drafts
            .iter()
            .flat_map(|d| d.entry_names.iter().cloned())
            .take(1024)
            .collect();
        if !names.is_empty() {
            let had = self.password_vault.candidates().len();
            let harvested_names = crate::passwords::harvest_from_names(&names);
            self.password_vault.merge(harvested_names);
            if self.password_vault.candidates().len() > had {
                // New filename-derived candidates exist. Re-validate the
                // encrypted drafts of THIS region that failed without a
                // working password (chicken-and-egg: the container's own
                // entry names only exist after its first parse). Bounded
                // by the same shadow-budget accounting as the main loop.
                for handler in &self.handlers {
                    for candidate in handler.find_candidates(src) {
                        // Only re-run candidates that produced a failed
                        // encrypted draft at this offset.
                        let retry_worthy = drafts.iter().any(|d| {
                            d.offset == candidate.offset
                                && d.metadata.get("encrypted").map(String::as_str) == Some("true")
                                && !d.metadata.contains_key("password")
                        });
                        if !retry_worthy {
                            continue;
                        }
                        let mut refreshed = effective_limits.clone();
                        refreshed.passwords = self
                            .password_vault
                            .candidates()
                            .iter()
                            .take(self.limits.max_password_attempts)
                            .map(|c| c.password.clone())
                            .collect();
                        let mut shadow = Budget::default();
                        if let Ok(output) =
                            handler.validate(src, candidate, &refreshed, &mut shadow)
                        {
                            for mut redraft in output.artifacts {
                                // Replace the failed draft in place.
                                if let Some(slot) = drafts.iter_mut().find(|d| {
                                    d.offset == redraft.offset
                                        && d.format == redraft.format
                                        && !d.metadata.contains_key("password")
                                }) {
                                    let spend = shadow.expanded_bytes;
                                    if spend > 0 && !budget.charge(&self.limits, spend) {
                                        continue;
                                    }
                                    redraft.warnings.push(
                                        "decrypted after filename-derived password                                          candidates were harvested"
                                            .to_string(),
                                    );
                                    // Provenance enrichment (same as the
                                    // main loop): name the vault source.
                                    if let Some(p) = redraft.metadata.get("password").cloned() {
                                        if !redraft.metadata.contains_key("password_source") {
                                            if let Some(c) = self
                                                .password_vault
                                                .candidates()
                                                .iter()
                                                .find(|c| c.password == p)
                                            {
                                                redraft.metadata.insert(
                                                    "password_source".to_string(),
                                                    c.source.as_str().to_string(),
                                                );
                                            }
                                        }
                                    }
                                    *slot = redraft;
                                }
                            }
                        }
                    }
                }
            }
        }

        // Generic carving fallback only when structural handlers found
        // nothing in this region.
        if drafts.is_empty() {
            let mut rules = crate::carving::builtin_rules();
            rules.extend(self.carving_rules.iter().cloned());
            if let Ok(extra) = crate::carving::carve_with_rules(src, &self.limits, budget, &rules) {
                for draft in extra {
                    drafts.push(draft);
                }
            }
        }

        // Register artifacts + recurse. Region decomposition model:
        //   [0, first.offset)               -> LeadingData of parent
        //   first structure (+ overlaps)    -> Contains of parent
        //   [first.end, len)                -> TrailingData of first
        // Drafts beyond the first structure's end are NOT registered at
        // this level — they are rediscovered inside the trailing region,
        // which keeps provenance hierarchical (PNG -> trailing -> ZIP).
        drafts.sort_by_key(|d| (d.offset, u64::MAX - d.size));

        // Leading data before the first structure. At the root level
        // (region_start == 0) this is genuine leading data; inside a
        // nested region (trailing data scan etc.) unexplained bytes
        // before the first structure sit BETWEEN earlier structures and
        // this one — an INTERIOR GAP (#7 §9), labeled as such.
        if let Some(first) = drafts.first() {
            if recurse && first.offset > 0 && depth < self.limits.max_depth {
                let relation = if region_start == 0 {
                    RelationKind::LeadingData
                } else {
                    RelationKind::InteriorGap
                };
                self.register_unexplained(
                    src,
                    parent_id,
                    0,
                    first.offset,
                    relation,
                    depth,
                    recurse,
                    graph,
                    budget,
                );
            }
        }

        let mut first_end: Option<u64> = None;
        let mut first_artifact: Option<ArtifactId> = None;
        // #7 §9: registered validated structures this level, for overlap
        // edge emission (distinct VALIDATED drafts sharing bytes).
        let mut placed: Vec<(u64, u64, ArtifactId)> = Vec::new();

        for draft in drafts {
            if graph.len() >= self.limits.max_artifacts {
                break;
            }
            // Only drafts overlapping the FIRST structure's extent belong
            // to this level; later ones live in the trailing region. Their
            // expansion spend was already recorded in `spends_by_region`
            // during validation, so the trailing-region rescan re-runs the
            // handler but commits no new charge (F1).
            if let Some(end) = first_end {
                if draft.offset >= end {
                    break;
                }
            }

            // #7 §9: unexplained INTERIOR gap between the end of the
            // previous validated structure and this one becomes a
            // first-class artifact (parented to the region owner) when
            // meaningful (> 0 bytes; tiny alignment gaps are noise).
            if let (Some(prev_end), Some(prev_id)) = (first_end, first_artifact) {
                if draft.offset > prev_end && recurse && depth < self.limits.max_depth {
                    self.register_unexplained(
                        src,
                        prev_id,
                        prev_end,
                        draft.offset,
                        RelationKind::InteriorGap,
                        depth,
                        recurse,
                        graph,
                        budget,
                    );
                }
            }

            // B2/R2: content identity = hash of the artifact's actual
            // source region (streamed, zero-copy via shared backing).
            let region = src.slice(draft.offset, draft.size);
            let hash = match &region {
                Ok(r) => r.hash_all(),
                Err(_) => content_hash(&[]),
            };
            let duplicate = graph.has_hash(&hash) || self.processed_hashes.contains(&hash);
            let mut artifact = Artifact {
                id: 0,
                parent: Some(parent_id),
                relation: Some(RelationKind::Contains),
                format: draft.format,
                label: draft.label,
                offset: draft.offset,
                size: draft.size,
                hash,
                confidence: draft.confidence,
                evidence: draft.evidence,
                extraction: if !draft.children.is_empty() {
                    ExtractionStatus::InMemory
                } else {
                    ExtractionStatus::NotExtracted
                },
                metadata: draft.metadata,
                warnings: draft.warnings,
                errors: draft.errors,
            };
            if duplicate {
                artifact.warnings.push(
                    "duplicate content; recursion skipped (provenance preserved)".to_string(),
                );
            }
            let child_id = graph.push_child(parent_id, RelationKind::Contains, artifact);

            let end = draft.offset + draft.size;
            // §9: an overlapping VALIDATED artifact coexists via an
            // Overlap edge to the structure it overlaps (polyglots:
            // PNG+ZIP hybrid whose ZIP starts inside the PNG chunk
            // stream). Distinct drafts only — the dedup contract
            // already suppresses byte-identical re-registrations.
            if draft.confidence == Confidence::Validated {
                for (po, pend, pid) in &placed {
                    let overlap = draft.offset.max(*po) < end.min(*pend);
                    if overlap {
                        if graph.len() < self.limits.max_artifacts {
                            graph.edges.push(crate::artifact::GraphEdge {
                                parent: child_id,
                                child: *pid,
                                relation: RelationKind::Overlap,
                            });
                        }
                        break;
                    }
                }
                placed.push((draft.offset, end, child_id));
            }
            first_end = Some(match first_end {
                Some(e) => e.max(end),
                None => end,
            });
            first_artifact = Some(first_artifact.unwrap_or(child_id));

            // R2: a duplicate container still registers its OWN children
            // (decompressed payloads, archive entries) so provenance edges
            // survive. The hash STILL goes into processed_hashes either
            // way: duplicates must not re-scan (layered re-registration),
            // and skipping the scan is exactly the dedup contract.
            self.processed_hashes.insert(
                graph
                    .get(child_id)
                    .map(|a| a.hash.clone())
                    .unwrap_or_default(),
            );

            // R5 + B1: region-backed artifacts (embedded PNG/JPEG/PDF,
            // carved GIF/RAR/7z, custom rules) must be materializable by
            // `-e`. Store the zero-copy region handle; bytes are read only
            // when extraction materializes them.
            if draft.size <= self.limits.max_child_size {
                if let Ok(r) = &region {
                    self.region_cache
                        .entry(
                            graph
                                .get(child_id)
                                .map(|a| a.hash.clone())
                                .unwrap_or_default(),
                        )
                        .or_insert_with(|| r.clone());
                }
            }

            // Register + recurse into handler-produced children.
            for child in draft.children {
                if graph.len() >= self.limits.max_artifacts {
                    break;
                }
                let chash = child.content.hash();
                // B1 + H1: the region cache stays keyed by content hash, so
                // the real payload handle exists exactly once regardless of
                // how many logical occurrences reference it. Owned bytes
                // still go to byte_cache (they exist in memory anyway);
                // source-backed regions store a handle with NO read.
                match &child.content {
                    ChildContent::Owned(bytes) => {
                        self.byte_cache.insert(chash.clone(), bytes.clone());
                    }
                    ChildContent::Source(src) => {
                        self.region_cache
                            .entry(chash.clone())
                            .or_insert_with(|| src.clone());
                    }
                }
                let cdup = graph.has_hash(&chash) || self.processed_hashes.contains(&chash);
                let mut ca = Artifact {
                    id: 0,
                    parent: Some(child_id),
                    relation: Some(child.relation),
                    format: "raw".to_string(),
                    label: child.label,
                    offset: 0,
                    size: child.size,
                    hash: chash,
                    // FINAL-B7: honor the handler's confidence claim.
                    confidence: child.confidence,
                    evidence: Evidence::facts(child.evidence.clone()),
                    extraction: ExtractionStatus::InMemory,
                    metadata: child.metadata,
                    warnings: child.warnings,
                    errors: Vec::new(),
                };
                if cdup {
                    // R2 + G1 + H1: a byte-identical child already exists.
                    // This occurrence still gets its OWN artifact node (so
                    // `parent`/`relation` always match the graph edge), but
                    // its recursion is skipped — identical bytes were
                    // already scanned under the first occurrence, and no
                    // additional expansion is billed for them.
                    ca.warnings
                        .push("duplicate content; recursion skipped".to_string());
                }
                let cid = graph.push_child(child_id, child.relation, ca);
                if recurse && !cdup && depth < self.limits.max_depth {
                    // Source-backed children scan their existing source
                    // region directly (zero-copy); owned bytes scan a new
                    // in-memory source.
                    match child.content {
                        ChildContent::Source(src) => {
                            let cs = src.root_offset();
                            self.scan_region(&src, cid, depth + 1, recurse, graph, budget, cs);
                        }
                        ChildContent::Owned(bytes) => {
                            let region = ByteSource::from_vec(bytes);
                            self.scan_region(&region, cid, depth + 1, recurse, graph, budget, 0);
                        }
                    }
                }
            }

            // Recurse into the artifact's own source region (finds
            // structures inside structurally-claimed regions). Gated on
            // `recurse` like every other recursion; duplicates skip it —
            // identical bytes were already scanned under their first
            // occurrence and re-scanning would re-register the same
            // nested artifacts layer after layer.
            if recurse && !duplicate && depth < self.limits.max_depth {
                if let Ok(r) = region {
                    let cs = r.root_offset();
                    self.scan_region(&r, child_id, depth + 1, recurse, graph, budget, cs);
                }
            }
        }

        // R3: trailing data after the first structure's extent is a
        // first-class artifact parented to THAT STRUCTURE (PNG -> trailing
        // -> ZIP), not to the region's parent node.
        if recurse && depth < self.limits.max_depth {
            if let (Some(end), Some(owner_id)) = (first_end, first_artifact) {
                if end < src.len() {
                    self.register_unexplained(
                        src,
                        owner_id,
                        end,
                        src.len(),
                        RelationKind::TrailingData,
                        depth,
                        recurse,
                        graph,
                        budget,
                    );
                }
            }
        }
    }

    /// Register an unexplained region (leading/trailing data) as a
    /// first-class artifact and recursively scan it. The child artifacts
    /// found inside (e.g. an appended ZIP) become descendants of the
    /// trailing/leading node, preserving provenance.
    #[allow(clippy::too_many_arguments)]
    fn register_unexplained(
        &mut self,
        src: &ByteSource,
        parent_id: ArtifactId,
        start: u64,
        end: u64,
        relation: RelationKind,
        depth: u32,
        recurse: bool,
        graph: &mut ArtifactGraph,
        budget: &mut Budget,
    ) {
        if end <= start || graph.len() >= self.limits.max_artifacts {
            return;
        }
        let Ok(region) = src.slice(start, end - start) else {
            return;
        };
        let hash = region.hash_all();
        let artifact = Artifact {
            id: 0,
            parent: Some(parent_id),
            relation: Some(relation),
            format: "raw".to_string(),
            label: format!(
                "{} region ({} bytes @{})",
                match relation {
                    RelationKind::TrailingData => "trailing data",
                    RelationKind::LeadingData => "leading data",
                    RelationKind::InteriorGap => "interior gap",
                    _ => "unexplained",
                },
                end - start,
                start
            ),
            offset: start,
            size: end - start,
            hash,
            confidence: Confidence::Heuristic,
            evidence: Evidence::facts([
                "unexplained bytes outside validated structures".to_string()
            ]),
            extraction: ExtractionStatus::NotExtracted,
            metadata: BTreeMap::new(),
            warnings: Vec::new(),
            errors: Vec::new(),
        };
        let id = graph.push_child(parent_id, relation, artifact);
        if depth < self.limits.max_depth {
            self.scan_region(&region, id, depth + 1, recurse, graph, budget, start);
        }
    }
}
