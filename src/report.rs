//! Report assembly: artifact graph + trailing/leading unexplained regions
//! + entropy summary, serializable to stable JSON.

use crate::artifact::ArtifactGraph;
use crate::entropy::EntropyBlock;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct Report {
    /// Source file name (or "<memory>").
    pub source: String,
    /// Total source size in bytes.
    pub source_size: u64,
    /// Full artifact graph (IDs, provenance, hashes, evidence, status).
    pub graph: ArtifactGraph,
    /// Coarse entropy summary (bounded block count).
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub entropy: Vec<EntropyBlock>,
    /// Non-fatal engine diagnostics.
    pub warnings: Vec<String>,
}

impl Report {
    pub fn new(source: impl Into<String>, source_size: u64, graph: ArtifactGraph) -> Self {
        Report {
            source: source.into(),
            source_size,
            graph,
            entropy: Vec::new(),
            warnings: Vec::new(),
        }
    }

    pub fn to_json_pretty(&self) -> crate::error::Result<String> {
        serde_json::to_string_pretty(self)
            .map_err(|e| crate::error::Error::Decompression(format!("json: {e}")))
    }

    pub fn from_json(text: &str) -> crate::error::Result<Self> {
        serde_json::from_str(text)
            .map_err(|e| crate::error::Error::Decompression(format!("json: {e}")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::artifact::{Artifact, ArtifactGraph, Confidence, Evidence};

    #[test]
    fn json_round_trip_preserves_graph() {
        let mut g = ArtifactGraph::new();
        let root = g.push_root(Artifact {
            id: 0,
            parent: None,
            relation: None,
            format: "input".into(),
            label: "x.bin".into(),
            offset: 0,
            size: 100,
            hash: "abc".into(),
            confidence: Confidence::Validated,
            evidence: Evidence::facts(["root"]),
            extraction: crate::artifact::ExtractionStatus::NotExtracted,
            metadata: Default::default(),
            warnings: vec![],
            errors: vec![],
        });
        g.push_child(
            root,
            crate::artifact::RelationKind::TrailingData,
            Artifact {
                id: 0,
                parent: Some(root),
                relation: Some(crate::artifact::RelationKind::TrailingData),
                format: "raw".into(),
                label: "trailing".into(),
                offset: 50,
                size: 50,
                hash: "def".into(),
                confidence: Confidence::Heuristic,
                evidence: Evidence::facts(["unexplained"]),
                extraction: crate::artifact::ExtractionStatus::NotExtracted,
                metadata: Default::default(),
                warnings: vec![],
                errors: vec![],
            },
        );
        let report = Report::new("x.bin", 100, g);
        let json = report.to_json_pretty().unwrap();
        let back = Report::from_json(&json).unwrap();
        assert_eq!(back.graph.edges.len(), 1);
        assert_eq!(
            back.graph.edges[0].relation,
            crate::artifact::RelationKind::TrailingData
        );
    }
}
