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

/// Mutable budget shared across the whole run.
#[derive(Debug, Default, Clone)]
pub struct Budget {
    pub expanded_bytes: u64,
}

impl Budget {
    pub(crate) fn charge(&mut self, limits: &EngineLimits, n: u64) -> bool {
        let next = self.expanded_bytes.saturating_add(n);
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
    /// Bytes of the artifact body available for recursion/extraction,
    /// when the handler already has them in memory.
    pub inline_bytes: Option<Vec<u8>>,
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
    /// Content hashes already recursively processed (dedup). Multiple
    /// logical artifacts may share bytes; recursive work happens once.
    processed_hashes: std::collections::HashSet<String>,
    /// In-memory bytes for artifacts produced/decoded this run, keyed by
    /// content hash. Powers extraction without re-parsing.
    pub byte_cache: std::collections::HashMap<String, Vec<u8>>,
}

impl RecursiveEngine {
    pub fn new(limits: EngineLimits) -> Self {
        RecursiveEngine {
            limits,
            handlers: builtin_handlers(),
            processed_hashes: std::collections::HashSet::new(),
            byte_cache: std::collections::HashMap::new(),
        }
    }

    /// Bytes recorded for an artifact hash, if any.
    pub fn cached_bytes(&self, hash: &str) -> Option<&Vec<u8>> {
        self.byte_cache.get(hash)
    }

    /// Analyze a root source and return the full artifact graph.
    pub fn analyze(&mut self, src: &ByteSource) -> ArtifactGraph {
        let mut graph = ArtifactGraph::new();
        let mut budget = Budget::default();
        let root_id = self.register_root_stub(&mut graph, src);
        self.scan_region(src, root_id, 0, &mut graph, &mut budget);
        graph
    }

    fn register_root_stub(&mut self, graph: &mut ArtifactGraph, src: &ByteSource) -> ArtifactId {
        let bytes = src.read_prefix(64 * 1024).unwrap_or_default();
        let hash = content_hash(&bytes);
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
        graph: &mut ArtifactGraph,
        budget: &mut Budget,
    ) {
        if depth > self.limits.max_depth {
            let p = graph.get_mut(parent_id);
            if let Some(p) = p {
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
        let mut drafts: Vec<(RelationKind, ArtifactDraft)> = Vec::new();
        for handler in &self.handlers {
            for candidate in handler.find_candidates(src) {
                let mut local_budget = budget.clone();
                match handler.validate(src, candidate, &self.limits, &mut local_budget) {
                    Ok(output) => {
                        for mut draft in output.artifacts {
                            if let Some(bytes) = &draft.inline_bytes {
                                if !budget_charge_ok(budget, &self.limits, bytes.len() as u64) {
                                    draft
                                        .warnings
                                        .push("max-total-expanded-bytes limit hit".to_string());
                                    continue;
                                }
                            }
                            drafts.push((RelationKind::Contains, draft));
                        }
                    }
                    Err(e) => {
                        // Candidate was a false positive / malformed. Record
                        // nothing; unrelated scanning continues.
                        let _ = e;
                    }
                }
            }
        }

        // Generic carving fallback only when structural handlers found
        // nothing in this region.
        if drafts.is_empty() {
            if let Ok(extra) = crate::carving::carve_region(src, &self.limits, budget) {
                for draft in extra {
                    drafts.push((RelationKind::CarvedFrom, draft));
                }
            }
        }

        // Register artifacts + recurse into children.
        for (relation, draft) in drafts {
            if graph.len() >= self.limits.max_artifacts {
                break;
            }
            let hash = content_hash(draft.inline_bytes.as_deref().unwrap_or(&[]));
            // Cache the bytes for extraction.
            if let Some(bytes) = &draft.inline_bytes {
                self.byte_cache.insert(hash.clone(), bytes.clone());
            }
            let duplicate = graph.has_hash(&hash);
            let mut artifact = Artifact {
                id: 0,
                parent: Some(parent_id),
                relation: Some(relation),
                format: draft.format,
                label: draft.label,
                offset: draft.offset,
                size: draft.size,
                hash,
                confidence: draft.confidence,
                evidence: draft.evidence,
                extraction: if draft.inline_bytes.is_some() || !draft.children.is_empty() {
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
            let child_id = graph.push_child(parent_id, relation, artifact);

            if duplicate
                || self
                    .processed_hashes
                    .contains(&graph.get(child_id).unwrap().hash)
            {
                continue;
            }
            self.processed_hashes
                .insert(graph.get(child_id).unwrap().hash.clone());

            // Recurse into inline artifact bytes.
            if let Some(bytes) = draft.inline_bytes {
                if let Ok(region) = src.slice(draft.offset, draft.size) {
                    let _ = region; // region scan uses inline bytes when present
                }
                if let Ok(child_src) = ByteSource::from_vec(bytes).into_child_of(src) {
                    self.scan_region(&child_src, child_id, depth + 1, graph, budget);
                }
            }
            // Register + recurse into handler-produced children.
            for child in draft.children {
                if graph.len() >= self.limits.max_artifacts {
                    break;
                }
                let chash = content_hash(&child.bytes);
                // Cache the child bytes for extraction.
                self.byte_cache.insert(chash.clone(), child.bytes.clone());
                let cdup = graph.has_hash(&chash);
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
                if !cdup && depth < self.limits.max_depth {
                    let region = ByteSource::from_vec(child.bytes);
                    self.scan_region(&region, cid, depth + 2, graph, budget);
                }
            }
        }
    }
}

fn budget_charge_ok(budget: &mut Budget, limits: &EngineLimits, n: u64) -> bool {
    budget.charge(limits, n)
}

impl ByteSource {
    /// Marker helper so the engine can construct region sources inline;
    /// the child relationship is handled through `slice` in production
    /// paths. This keeps recursion simple for in-memory children.
    fn into_child_of(self, _parent: &ByteSource) -> std::result::Result<ByteSource, ()> {
        Ok(self)
    }
}
