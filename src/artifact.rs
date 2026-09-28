//! Artifact model: every useful thing discovered from input data is an
//! Artifact. The graph preserves provenance and allows overlapping
//! artifacts — one structurally valid artifact is never silently dropped
//! merely because another overlaps it.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fmt;

/// Stable identifier assigned by the engine in discovery order.
pub type ArtifactId = u64;

/// Relationship between a child artifact and its source.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RelationKind {
    /// Child lives inside a validated container.
    Contains,
    /// Child was found embedded in (possibly unstructured) parent data.
    EmbeddedIn,
    /// Child was recovered by generic signature carving.
    CarvedFrom,
    /// Child is the decompressed payload of a compressed parent.
    DecompressedFrom,
    /// Unexplained data after a validated structure.
    TrailingData,
    /// Unexplained data before the first validated structure.
    LeadingData,
    /// #7 §9: unexplained bytes BETWEEN two validated structures.
    InteriorGap,
    /// Coexists with another artifact over the same bytes.
    Overlap,
    /// M3: child is one partition of a disk/container (MBR/GPT slice).
    PartitionOf,
    /// M3: child is a filesystem entry (file/dir node under its fs).
    FilesystemEntry,
    /// M3: child was reconstructed from parent structure (TCP stream
    /// reassembly, FAT cluster chains, SQLite overflow chains...).
    ReconstructedFrom,
    /// M3: child is a memory range out of a dump/capture.
    MemoryRange,
    /// M3: child is a database record or BLOB value.
    DatabaseRecord,
}

impl fmt::Display for RelationKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            RelationKind::Contains => "contains",
            RelationKind::EmbeddedIn => "embedded-in",
            RelationKind::CarvedFrom => "carved-from",
            RelationKind::DecompressedFrom => "decompressed-from",
            RelationKind::TrailingData => "trailing-data",
            RelationKind::LeadingData => "leading-data",
            RelationKind::InteriorGap => "interior-gap",
            RelationKind::Overlap => "overlap",
            RelationKind::PartitionOf => "partition-of",
            RelationKind::FilesystemEntry => "filesystem-entry",
            RelationKind::ReconstructedFrom => "reconstructed-from",
            RelationKind::MemoryRange => "memory-range",
            RelationKind::DatabaseRecord => "database-record",
        };
        f.write_str(s)
    }
}

/// Evidence-grade confidence. Deliberately not a floating-point score:
/// claims are explainable states, not magic numbers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Confidence {
    /// Structure fully walked and boundaries proven (e.g. PNG via IEND).
    Validated,
    /// Recovered despite structural damage (e.g. carved footer match).
    Recovered,
    /// Boundary heuristic; structure plausible but not fully proven.
    Partial,
    /// Damaged: signature matched but validation found corruption.
    Damaged,
    /// Signature-only match; may be a false positive.
    Heuristic,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Evidence {
    /// Human-readable structural facts backing the confidence level.
    Facts(Vec<String>),
}

impl Evidence {
    pub fn facts<I: IntoIterator<Item = impl Into<String>>>(items: I) -> Self {
        Evidence::Facts(items.into_iter().map(Into::into).collect())
    }
}

/// Whether/how an artifact's bytes were materialized or recovered.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ExtractionStatus {
    /// Nothing extracted (analysis only).
    NotExtracted,
    /// Bytes available in-memory for recursion but not written to disk.
    InMemory,
    /// Written to the controlled extraction root.
    Written,
    /// Extraction attempted and refused (unsafe, limits, encrypted...).
    Refused,
}

/// One discovered artifact.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Artifact {
    pub id: ArtifactId,
    /// Parent artifact id, if any (root artifacts have none).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent: Option<ArtifactId>,
    /// How this artifact relates to its parent.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub relation: Option<RelationKind>,
    /// Format identifier, e.g. "png", "zip", "gzip", "raw".
    pub format: String,
    /// Short human label, e.g. "PNG image 64x64".
    pub label: String,
    /// Offset of this artifact's first byte within the *parent source*.
    pub offset: u64,
    /// Byte length of the artifact.
    pub size: u64,
    /// BLAKE3 content hash (dedup identity).
    pub hash: String,
    pub confidence: Confidence,
    pub evidence: Evidence,
    pub extraction: ExtractionStatus,
    /// Format-specific metadata (chunk counts, entry names, dimensions...).
    pub metadata: BTreeMap<String, String>,
    /// Non-fatal diagnostics.
    pub warnings: Vec<String>,
    /// Fatal-for-this-artifact diagnostics (validation failure etc.).
    pub errors: Vec<String>,
}

impl Artifact {
    /// Offset of this artifact within the ultimate root source.
    pub fn root_offset(&self, parent_root: u64) -> u64 {
        parent_root + self.offset
    }
}

/// Edge in the artifact graph.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GraphEdge {
    pub parent: ArtifactId,
    pub child: ArtifactId,
    pub relation: RelationKind,
}

/// Provenance-preserving artifact graph. Overlapping artifacts coexist.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct ArtifactGraph {
    pub artifacts: Vec<Artifact>,
    pub edges: Vec<GraphEdge>,
    next_id: ArtifactId,
}

impl ArtifactGraph {
    pub fn new() -> Self {
        ArtifactGraph {
            artifacts: Vec::new(),
            edges: Vec::new(),
            next_id: 0,
        }
    }

    /// Register a root artifact (no parent).
    pub fn push_root(&mut self, mut a: Artifact) -> ArtifactId {
        a.id = self.next_id;
        self.next_id += 1;
        let id = a.id;
        self.artifacts.push(a);
        id
    }

    /// Register a child artifact and its provenance edge.
    pub fn push_child(
        &mut self,
        parent: ArtifactId,
        relation: RelationKind,
        mut a: Artifact,
    ) -> ArtifactId {
        a.id = self.next_id;
        self.next_id += 1;
        let id = a.id;
        self.edges.push(GraphEdge {
            parent,
            child: id,
            relation,
        });
        self.artifacts.push(a);
        id
    }

    pub fn get(&self, id: ArtifactId) -> Option<&Artifact> {
        self.artifacts.iter().find(|a| a.id == id)
    }

    pub fn get_mut(&mut self, id: ArtifactId) -> Option<&mut Artifact> {
        self.artifacts.iter_mut().find(|a| a.id == id)
    }

    pub fn len(&self) -> usize {
        self.artifacts.len()
    }

    pub fn is_empty(&self) -> bool {
        self.artifacts.is_empty()
    }

    /// Children of `id` with their relationship kinds.
    pub fn children(&self, id: ArtifactId) -> Vec<(RelationKind, &Artifact)> {
        self.edges
            .iter()
            .filter(|e| e.parent == id)
            .filter_map(|e| self.get(e.child).map(|a| (e.relation, a)))
            .collect()
    }

    /// True if a non-root artifact with identical content hash already
    /// exists. The root stub is excluded: an artifact spanning exactly
    /// the root region (e.g. a gzip over the whole file) legitimately
    /// shares the root's hash without being a duplicate of it.
    pub fn has_hash(&self, hash: &str) -> bool {
        self.artifacts
            .iter()
            .any(|a| a.parent.is_some() && a.hash == hash)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(format: &str, hash: &str) -> Artifact {
        Artifact {
            id: 0,
            parent: None,
            relation: None,
            format: format.to_string(),
            label: format.to_string(),
            offset: 0,
            size: 10,
            hash: hash.to_string(),
            confidence: Confidence::Validated,
            evidence: Evidence::facts(["test"]),
            extraction: ExtractionStatus::NotExtracted,
            metadata: BTreeMap::new(),
            warnings: Vec::new(),
            errors: Vec::new(),
        }
    }

    #[test]
    fn overlapping_artifacts_coexist() {
        let mut g = ArtifactGraph::new();
        let a = g.push_root(sample("png", "aa"));
        // Same byte range, different format claim — both survive.
        let _b = g.push_child(a, RelationKind::Overlap, sample("zip", "bb"));
        assert_eq!(g.len(), 2);
    }

    #[test]
    fn provenance_round_trips_through_serde() {
        let mut g = ArtifactGraph::new();
        let root = g.push_root(sample("gzip", "hh"));
        g.push_child(root, RelationKind::DecompressedFrom, sample("tar", "tt"));
        let json = serde_json::to_string(&g).unwrap();
        let back: ArtifactGraph = serde_json::from_str(&json).unwrap();
        assert_eq!(back.edges.len(), 1);
        assert_eq!(back.edges[0].relation, RelationKind::DecompressedFrom);
    }
}
