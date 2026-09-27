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
}

/// A child produced by a handler (decompressed stream, archive member...).
#[derive(Debug)]
pub struct ChildDraft {
    pub relation: RelationKind,
    pub label: String,
    pub format_hint: &'static str,
    pub bytes: Vec<u8>,
    pub metadata: BTreeMap<String, String>,
    pub warnings: Vec<String>,
    /// Name if extracted from an archive (used by the extraction layer).
    pub entry_name: Option<String>,
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
        Box::new(handlers::zip::ZipHandler),
        Box::new(handlers::gzip::GzipHandler),
        Box::new(handlers::xz::XzHandler),
        Box::new(handlers::tar::TarHandler),
        Box::new(handlers::pdf::PdfHandler),
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
}

impl RecursiveEngine {
    pub fn new(limits: EngineLimits) -> Self {
        RecursiveEngine {
            limits,
            handlers: builtin_handlers(),
            carving_rules: Vec::new(),
            processed_hashes: std::collections::HashSet::new(),
            byte_cache: std::collections::HashMap::new(),
        }
    }

    /// Bytes recorded for an artifact hash, if any.
    pub fn cached_bytes(&self, hash: &str) -> Option<&Vec<u8>> {
        self.byte_cache.get(hash)
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
        self.scan_region(src, root_id, 0, recurse, &mut graph, &mut budget);
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
    fn scan_region(
        &mut self,
        src: &ByteSource,
        parent_id: ArtifactId,
        depth: u32,
        recurse: bool,
        graph: &mut ArtifactGraph,
        budget: &mut Budget,
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

        // Collect drafts from every handler; handler errors are isolated.
        // R1 (transactional accounting): each candidate is validated with
        // a SHADOW of the run-wide budget. Charges commit only when the
        // candidate is accepted; a rejected/malformed/limit-hit candidate
        // rolls back, and duplicate drafts (rediscovered inside trailing
        // regions) are charged once because the shadow's spend replaces
        // rather than adds. This keeps the run-wide cap authoritative
        // without penalizing legitimate data twice.
        let mut drafts: Vec<ArtifactDraft> = Vec::new();
        for handler in &self.handlers {
            for candidate in handler.find_candidates(src) {
                let before = budget.expanded_bytes;
                match handler.validate(src, candidate, &self.limits, budget) {
                    Ok(output) => {
                        for draft in output.artifacts {
                            let region_ok = src
                                .slice(draft.offset, draft.size)
                                .map(|r| r.hash_all())
                                .ok()
                                .map_or(true, |h| !self.processed_hashes.contains(&h));
                            if region_ok {
                                // Commit this candidate's spend.
                                drafts.push(draft);
                            } else {
                                // Duplicate of already-processed content:
                                // roll back its spend; the artifact node
                                // still gets registered later, but the
                                // expansion work is not re-charged.
                                budget.expanded_bytes = before;
                                drafts.push(draft);
                            }
                        }
                    }
                    Err(e) => {
                        // Rejected candidate: roll back its spend so a
                        // malformed candidate can never permanently drain
                        // the run-wide budget.
                        budget.expanded_bytes = before;
                        let _ = e;
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

        // Leading data before the first structure.
        if let Some(first) = drafts.first() {
            if recurse && first.offset > 0 && depth < self.limits.max_depth {
                self.register_unexplained(
                    src,
                    parent_id,
                    0,
                    first.offset,
                    RelationKind::LeadingData,
                    depth,
                    recurse,
                    graph,
                    budget,
                );
            }
        }

        let mut first_end: Option<u64> = None;
        let mut first_artifact: Option<ArtifactId> = None;

        for draft in drafts {
            if graph.len() >= self.limits.max_artifacts {
                break;
            }
            // Only drafts overlapping the FIRST structure's extent belong
            // to this level; later ones live in the trailing region.
            if let Some(end) = first_end {
                if draft.offset >= end {
                    break;
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
            first_end = Some(match first_end {
                Some(e) => e.max(end),
                None => end,
            });
            first_artifact = Some(first_artifact.unwrap_or(child_id));

            // R2: a duplicate container still registers its OWN children
            // (decompressed payloads, archive entries) so provenance edges
            // survive; only the recursive SCAN of identical bytes is
            // skipped (and the region scan below, via processed_hashes).
            if !duplicate {
                self.processed_hashes.insert(
                    graph
                        .get(child_id)
                        .map(|a| a.hash.clone())
                        .unwrap_or_default(),
                );
            }

            // R5: region-backed artifacts (embedded PNG/JPEG/PDF, carved
            // GIF/RAR/7z, custom rules) must be materializable by `-e` —
            // cache their region bytes, bounded by max_child_size.
            if draft.size <= self.limits.max_child_size {
                if let Ok(r) = &region {
                    if let Ok(bytes) = r.read_all() {
                        self.byte_cache
                            .entry(
                                graph
                                    .get(child_id)
                                    .map(|a| a.hash.clone())
                                    .unwrap_or_default(),
                            )
                            .or_insert(bytes);
                    }
                }
            }

            // Register + recurse into handler-produced children.
            for child in draft.children {
                if graph.len() >= self.limits.max_artifacts {
                    break;
                }
                let chash = content_hash(&child.bytes);
                self.byte_cache.insert(chash.clone(), child.bytes.clone());
                let cdup = graph.has_hash(&chash) || self.processed_hashes.contains(&chash);
                let mut ca = Artifact {
                    id: 0,
                    parent: Some(child_id),
                    relation: Some(child.relation),
                    format: "raw".to_string(),
                    label: child.label,
                    offset: 0,
                    size: child.bytes.len() as u64,
                    hash: chash,
                    confidence: Confidence::Validated,
                    evidence: Evidence::facts(["produced by parent handler"]),
                    extraction: ExtractionStatus::InMemory,
                    metadata: child.metadata,
                    warnings: child.warnings,
                    errors: Vec::new(),
                };
                if cdup {
                    ca.warnings
                        .push("duplicate content; recursion skipped".to_string());
                }
                let cid = graph.push_child(child_id, child.relation, ca);
                if recurse && !cdup && depth < self.limits.max_depth {
                    let region = ByteSource::from_vec(child.bytes);
                    self.scan_region(&region, cid, depth + 1, recurse, graph, budget);
                }
            }

            // Recurse into the artifact's own source region (finds
            // structures inside structurally-claimed regions). Gated on
            // `recurse` like every other recursion.
            if recurse && depth < self.limits.max_depth {
                if let Ok(r) = region {
                    self.scan_region(&r, child_id, depth + 1, recurse, graph, budget);
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
            self.scan_region(&region, id, depth + 1, recurse, graph, budget);
        }
    }
}
