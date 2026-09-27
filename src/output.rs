//! Output: compact human artifact tree + tree.txt rendering.

use crate::artifact::{ArtifactGraph, ArtifactId, Confidence};
use std::fmt::Write as _;

/// Render the graph as an indented tree. Compact by default; diagnostics
/// (warnings/errors/evidence) appear only with `verbose`.
pub fn render_tree(graph: &ArtifactGraph, verbose: bool) -> String {
    let mut out = String::new();
    let roots: Vec<ArtifactId> = graph
        .artifacts
        .iter()
        .filter(|a| a.parent.is_none())
        .map(|a| a.id)
        .collect();
    for root in roots {
        render_node(graph, root, 0, &mut out, verbose);
    }
    out
}

fn render_node(
    graph: &ArtifactGraph,
    id: ArtifactId,
    depth: usize,
    out: &mut String,
    verbose: bool,
) {
    let Some(a) = graph.get(id) else { return };
    let indent = "  ".repeat(depth);
    let conf_tag = match a.confidence {
        Confidence::Validated => "",
        Confidence::Recovered => " [recovered]",
        Confidence::Partial => " [partial]",
        Confidence::Damaged => " [damaged]",
        Confidence::Heuristic => " [heuristic]",
    };
    let _ = writeln!(
        out,
        "{indent}#{id} {} {}{conf_tag} {} bytes @{}",
        a.format, a.label, a.size, a.offset
    );
    if verbose {
        for w in &a.warnings {
            let _ = writeln!(out, "{indent}  ! warning: {w}");
        }
        for e in &a.errors {
            let _ = writeln!(out, "{indent}  ! error: {e}");
        }
        let crate::artifact::Evidence::Facts(facts) = &a.evidence;
        for f in facts {
            let _ = writeln!(out, "{indent}  · {f}");
        }
    }
    for (relation, child) in graph.children(id) {
        let _ = relation; // overlap edges render inline with their parent
        render_node(graph, child.id, depth + 1, out, verbose);
    }
}

/// Render `tree.txt` style layout for the extraction directory.
pub fn render_tree_txt(graph: &ArtifactGraph) -> String {
    render_tree(graph, false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::artifact::*;

    #[test]
    fn tree_renders_nested() {
        let mut g = ArtifactGraph::new();
        let root = g.push_root(Artifact {
            id: 0,
            parent: None,
            relation: None,
            format: "input".into(),
            label: "x".into(),
            offset: 0,
            size: 10,
            hash: "h".into(),
            confidence: Confidence::Validated,
            evidence: Evidence::facts(["r"]),
            extraction: ExtractionStatus::NotExtracted,
            metadata: Default::default(),
            warnings: vec![],
            errors: vec![],
        });
        g.push_child(
            root,
            RelationKind::Contains,
            Artifact {
                id: 0,
                parent: Some(root),
                relation: Some(RelationKind::Contains),
                format: "png".into(),
                label: "PNG image 1x1".into(),
                offset: 0,
                size: 10,
                hash: "h2".into(),
                confidence: Confidence::Validated,
                evidence: Evidence::facts(["e"]),
                extraction: ExtractionStatus::NotExtracted,
                metadata: Default::default(),
                warnings: vec![],
                errors: vec![],
            },
        );
        let s = render_tree(&g, false);
        assert!(s.contains("png"));
        assert!(s.contains("PNG image 1x1"));
    }
}
