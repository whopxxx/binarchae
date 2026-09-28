//! FINAL-B4: automatic password-candidate discovery and propagation.
//!
//! CTF containers are routinely encrypted with passwords left in plain
//! sight: the archive comment, an entry filename, a nearby text string.
//! The engine harvests such candidates from every scanned region into a
//! SHARED VAULT, records WHERE each candidate came from (provenance), and
//! hands a deterministic, deduplicated, bounded queue to the encrypted-
//! container handlers (ZIP / 7z / RAR). A working candidate is surfaced
//! back as `password` + `password_source` artifact metadata, and the
//! decrypted bytes recurse like any other child.
//!
//! Guarantees:
//! - deterministic order: explicit CLI candidates first (in order), then
//!   harvested candidates in discovery order (region scan order);
//! - deduplicated: one attempt queue shared by all handlers in a run;
//! - bounded: attempts are capped by
//!   [`EngineLimits::max_password_attempts`] and each candidate length
//!   by [`MAX_CANDIDATE_LEN`].

use std::collections::BTreeMap;

/// Longest harvested candidate accepted (passwords are short; anything
/// longer is noise and would let untrusted data drive long compares).
pub const MAX_CANDIDATE_LEN: usize = 64;

/// Where a password candidate was found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PasswordSource {
    /// Supplied by the operator via `--password` (highest trust).
    CommandLine,
    /// The archive's own comment field (e.g. ZIP EOCD comment).
    Comment,
    /// An entry filename inside a container.
    Filename,
    /// A printable string found in the surrounding byte region.
    String,
}

impl PasswordSource {
    pub fn as_str(&self) -> &'static str {
        match self {
            PasswordSource::CommandLine => "command-line",
            PasswordSource::Comment => "archive comment",
            PasswordSource::Filename => "entry filename",
            PasswordSource::String => "region string",
        }
    }
}

/// One candidate plus its provenance.
#[derive(Debug, Clone)]
pub struct PasswordCandidate {
    pub password: String,
    pub source: PasswordSource,
}

/// Shared, deterministic, bounded candidate queue.
#[derive(Debug, Default)]
pub struct PasswordVault {
    /// Insertion-ordered queue (CLI candidates are inserted first).
    queue: Vec<PasswordCandidate>,
    /// Dedup set over candidate strings.
    seen: std::collections::HashSet<String>,
}

impl PasswordVault {
    pub fn new() -> Self {
        PasswordVault::default()
    }

    /// Seed the vault with operator-supplied candidates (in order).
    pub fn seed_from_cli(&mut self, passwords: &[String]) {
        for p in passwords {
            self.push(p.clone(), PasswordSource::CommandLine);
        }
    }

    /// Vault seeded from a plain candidate list (used by handlers that
    /// receive the queue via `EngineLimits::passwords`).
    pub fn from_passwords(passwords: &[String]) -> Self {
        let mut v = PasswordVault::new();
        v.seed_from_cli(passwords);
        v
    }

    /// Add a candidate. Deterministic: first occurrence wins; CLI
    /// candidates keep priority because they are seeded first.
    pub fn push(&mut self, password: String, source: PasswordSource) {
        if password.is_empty() || password.len() > MAX_CANDIDATE_LEN {
            return;
        }
        if self.seen.insert(password.clone()) {
            self.queue.push(PasswordCandidate { password, source });
        }
    }

    /// Merge candidates from another vault preserving queue order.
    pub fn merge(&mut self, other: PasswordVault) {
        for c in other.queue {
            self.push(c.password, c.source);
        }
    }

    /// The deterministic attempt queue (CLI first, then discovery).
    pub fn candidates(&self) -> &[PasswordCandidate] {
        &self.queue
    }

    /// Look up the provenance of a candidate that succeeded.
    pub fn source_of(&self, password: &str) -> Option<&PasswordSource> {
        self.queue
            .iter()
            .find(|c| c.password == password)
            .map(|c| &c.source)
    }

    /// How many attempts one handler may make for one artifact.
    pub fn attempt_budget(&self, limits: &crate::engine::EngineLimits) -> usize {
        limits.max_password_attempts
    }

    /// Provenance metadata for a working password.
    pub fn provenance(&self, password: &str) -> Vec<(String, String)> {
        let mut out = Vec::new();
        out.push(("password".to_string(), password.to_string()));
        if let Some(s) = self.source_of(password) {
            out.push(("password_source".to_string(), s.as_str().to_string()));
        }
        out
    }
}

/// Extract printable ASCII runs of length >= `min` from `data` (a
/// bounded prefix of a region), returning up to `max` candidates.
pub fn printable_strings(data: &[u8], min: usize, max: usize) -> Vec<String> {
    let mut out = Vec::new();
    let mut start: Option<usize> = None;
    for (i, b) in data.iter().enumerate() {
        if b.is_ascii_graphic() || *b == b' ' {
            if start.is_none() {
                start = Some(i);
            }
        } else if let Some(s) = start.take() {
            if i - s >= min && out.len() < max {
                out.push(String::from_utf8_lossy(&data[s..i]).into_owned());
            }
        }
        if out.len() >= max {
            break;
        }
    }
    if let Some(s) = start {
        if data.len() - s >= min && out.len() < max {
            out.push(String::from_utf8_lossy(&data[s..]).into_owned());
        }
    }
    out
}

/// Harvest password-like candidates from a byte region: the ZIP EOCD
/// comment (when present), printable strings, and entry filenames.
/// Returns candidates in a fresh vault for the engine to merge.
pub fn harvest_from_region(
    src: &crate::bytesource::ByteSource,
    limits: &crate::engine::EngineLimits,
) -> PasswordVault {
    let mut vault = PasswordVault::new();
    // Read a bounded prefix: candidate discovery must be cheap and
    // attacker-independent.
    let len = src.len().min(
        crate::engine::EngineLimits::default()
            .max_child_size
            .min(1 << 20),
    );
    let Ok(data) = src.read_prefix(len) else {
        return vault;
    };

    // 1. Archive comment: ZIP EOCD "PK\x05\x06" comment field.
    if let Some(pos) = find_eocd(&data) {
        let comment_len = u16::from_le_bytes([data[pos + 20], data[pos + 21]]) as usize;
        let start = pos + 22;
        if start + comment_len <= data.len() && comment_len > 0 && comment_len <= MAX_CANDIDATE_LEN
        {
            vault.push(
                String::from_utf8_lossy(&data[start..start + comment_len]).into_owned(),
                PasswordSource::Comment,
            );
        }
    }

    // 2. Printable strings (skip the shortest; they are noise).
    for s in printable_strings(&data, 4, limits.max_string_candidates.min(32)) {
        vault.push(s, PasswordSource::String);
    }
    vault
}

fn find_eocd(data: &[u8]) -> Option<usize> {
    if data.len() < 22 {
        return None;
    }
    let mut i = data.len() - 22;
    loop {
        if data[i..i + 4] == [0x50, 0x4b, 0x05, 0x06] {
            let comment_len = u16::from_le_bytes([data[i + 20], data[i + 21]]) as usize;
            if i + 22 + comment_len <= data.len() {
                return Some(i);
            }
        }
        if i == 0 {
            return None;
        }
        i -= 1;
    }
}

/// Helper for handlers: build the bounded attempt queue for one artifact
/// (empty candidate first, then the vault queue capped by
/// `max_password_attempts`), with provenance carried alongside.
pub fn attempt_queue(
    limits: &crate::engine::EngineLimits,
    vault: Option<&PasswordVault>,
) -> Vec<PasswordCandidate> {
    let mut out = Vec::new();
    // The empty password always gets the first (cheap) attempt.
    out.push(PasswordCandidate {
        password: String::new(),
        source: PasswordSource::CommandLine,
    });
    if let Some(v) = vault {
        for c in v.candidates() {
            if out.len() >= limits.max_password_attempts {
                break;
            }
            out.push(c.clone());
        }
    }
    out
}

/// Metadata helper: record a working password + provenance on an
/// artifact's metadata map.
pub fn record_working(metadata: &mut BTreeMap<String, String>, candidate: &PasswordCandidate) {
    if !candidate.password.is_empty() {
        metadata.insert("password".to_string(), candidate.password.clone());
        metadata.insert(
            "password_source".to_string(),
            candidate.source.as_str().to_string(),
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vault_is_deduped_and_deterministic() {
        let mut v = PasswordVault::new();
        v.seed_from_cli(&["b".to_string(), "a".to_string()]);
        v.push("a".to_string(), PasswordSource::String);
        v.push("c".to_string(), PasswordSource::Comment);
        let q: Vec<&str> = v.candidates().iter().map(|c| c.password.as_str()).collect();
        assert_eq!(q, ["b", "a", "c"], "CLI order first, then discovery");
        assert_eq!(v.source_of("a"), Some(&PasswordSource::CommandLine));
        assert_eq!(v.source_of("c"), Some(&PasswordSource::Comment));
    }

    #[test]
    fn vault_rejects_oversized_and_empty() {
        let mut v = PasswordVault::new();
        v.push(String::new(), PasswordSource::String);
        v.push("x".repeat(MAX_CANDIDATE_LEN + 1), PasswordSource::String);
        v.push("ok".to_string(), PasswordSource::String);
        assert_eq!(v.candidates().len(), 1);
        assert_eq!(v.candidates()[0].password, "ok");
    }

    #[test]
    fn attempt_queue_is_bounded() {
        let mut v = PasswordVault::new();
        for i in 0..100 {
            v.push(format!("pw{i}"), PasswordSource::String);
        }
        let limits = crate::engine::EngineLimits {
            max_password_attempts: 5,
            ..Default::default()
        };
        let q = attempt_queue(&limits, Some(&v));
        assert_eq!(q.len(), 5, "empty first + 4 harvested");
        assert!(q[0].password.is_empty());
        assert_eq!(q[1].password, "pw0");
    }

    #[test]
    fn printable_strings_finds_runs() {
        let data = b"xx password123 \x00\x01 another-one yy";
        let s = printable_strings(data, 4, 16);
        assert_eq!(s, vec!["xx password123 ", " another-one yy"]);
    }

    #[test]
    fn zip_comment_harvested() {
        use crate::bytesource::ByteSource;
        // Minimal ZIP EOCD with a comment "hunter2".
        let mut v = Vec::new();
        v.extend_from_slice(b"PK\x05\x06");
        v.extend(0u16.to_le_bytes());
        v.extend(0u16.to_le_bytes());
        v.extend(0u16.to_le_bytes());
        v.extend(0u16.to_le_bytes());
        v.extend(0u32.to_le_bytes());
        v.extend(0u32.to_le_bytes());
        v.extend(7u16.to_le_bytes());
        v.extend_from_slice(b"hunter2");
        let src = ByteSource::from_vec(v);
        let limits = crate::engine::EngineLimits::default();
        let vault = harvest_from_region(&src, &limits);
        let q: Vec<&str> = vault
            .candidates()
            .iter()
            .map(|c| c.password.as_str())
            .collect();
        assert!(
            q.contains(&"hunter2"),
            "EOCD comment must be harvested: {q:?}"
        );
        let c = vault
            .candidates()
            .iter()
            .find(|c| c.password == "hunter2")
            .unwrap();
        assert_eq!(c.source, PasswordSource::Comment);
    }
}
