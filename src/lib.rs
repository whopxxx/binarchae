//! ctf-tools: CTF-first binary analysis and extraction engine.
//!
//! Core invariant: every useful thing discovered from input data is an
//! [`Artifact`], and every parser/extractor exists to discover additional
//! artifacts.

pub mod artifact;
pub mod bytesource;
pub mod carving;
pub mod engine;
pub mod entropy;
pub mod error;
pub mod extract;
pub mod handlers;
pub mod output;
pub mod passwords;
pub mod report;

pub use artifact::{Artifact, ArtifactGraph, ArtifactId, Confidence, Evidence, RelationKind};
pub use bytesource::ByteSource;
pub use engine::{EngineLimits, RecursiveEngine};
pub use error::{Error, Result};

use blake3::Hasher;

/// Compute a BLAKE3 hash of a byte range, used as content identity.
pub(crate) fn content_hash(data: &[u8]) -> String {
    let mut hasher = Hasher::new();
    hasher.update(data);
    hasher.finalize().to_hex().to_string()
}
