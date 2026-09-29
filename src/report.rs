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
    /// #7 §10: classified entropy regions (transition-grouped).
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub entropy_regions: Vec<crate::entropy::EntropyRegion>,
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
            entropy_regions: Vec::new(),
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

impl Report {
    /// #7 §12.1: JSONL — one JSON record per line, stable IDs and
    /// provenance. Suitable for very large graphs (stream-processable
    /// with line-oriented tools); the existing JSON mode is unchanged.
    pub fn to_jsonl(&self) -> crate::error::Result<String> {
        use std::fmt::Write;
        let mut out = String::new();
        // Header record: run-level info.
        writeln!(
            out,
            "{{\"type\":\"run\",\"source\":{:?},\"source_size\":{}}}",
            self.source, self.source_size
        )
        .map_err(jsonl_err)?;
        // Artifact records: id/provenance/claims per line.
        for a in &self.graph.artifacts {
            let json = serde_json::to_string(a).map_err(json_err)?;
            writeln!(out, "{{\"type\":\"artifact\",\"artifact\":{}}}", json).map_err(jsonl_err)?;
        }
        // Edge records: one provenance edge per line.
        for e in &self.graph.edges {
            let json = serde_json::to_string(e).map_err(json_err)?;
            writeln!(out, "{{\"type\":\"edge\",\"edge\":{}}}", json).map_err(jsonl_err)?;
        }
        // Entropy regions (§10) if present.
        for r in &self.entropy_regions {
            let json = serde_json::to_string(r).map_err(json_err)?;
            writeln!(out, "{{\"type\":\"entropy_region\",\"region\":{}}}", json)
                .map_err(jsonl_err)?;
        }
        Ok(out)
    }
}

fn jsonl_err(e: std::fmt::Error) -> crate::error::Error {
    crate::error::Error::Decompression(format!("jsonl: {e}"))
}

fn json_err(e: serde_json::Error) -> crate::error::Error {
    crate::error::Error::Decompression(format!("jsonl: {e}"))
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
