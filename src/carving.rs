//! Foremost-style generic carving fallback. Extensible via builtin rules
//! plus user-defined TOML rules. Never replaces structural handlers: the
//! engine only carves regions where no structural handler produced an
//! artifact.

use crate::artifact::{Confidence, Evidence};
use crate::bytesource::ByteSource;
use crate::engine::{ArtifactDraft, Budget};
use crate::error::Result;
use serde::Deserialize;
use std::collections::BTreeMap;

/// One carving rule.
#[derive(Debug, Clone)]
pub struct CarveRule {
    pub name: String,
    pub header: Vec<u8>,
    pub footer: Option<Vec<u8>>,
    pub max_size: u64,
    /// If true, a match ends where the *next* header begins (when no
    /// footer is given or footer missing).
    pub terminate_on_next_header: bool,
}

/// User-facing TOML schema:
///
/// ```toml
/// [[rule]]
/// name = "custom"
/// header = "52617221"          # hex
/// footer = "C43D7B00"          # optional hex
/// max_size = 1048576
/// terminate_on_next_header = false
/// ```
#[derive(Debug, Deserialize)]
struct RulesFile {
    #[serde(default)]
    rule: Vec<RuleToml>,
}

#[derive(Debug, Deserialize)]
struct RuleToml {
    name: String,
    header: String,
    footer: Option<String>,
    #[serde(default = "default_max")]
    max_size: u64,
    #[serde(default)]
    terminate_on_next_header: bool,
}

fn default_max() -> u64 {
    8 * 1024 * 1024
}

impl RuleToml {
    fn into_rule(self) -> Result<CarveRule> {
        let header = decode_hex(&self.header)?;
        let footer = match self.footer {
            Some(f) => Some(decode_hex(&f)?),
            None => None,
        };
        Ok(CarveRule {
            name: self.name,
            header,
            footer,
            max_size: self.max_size,
            terminate_on_next_header: self.terminate_on_next_header,
        })
    }
}

fn decode_hex(s: &str) -> Result<Vec<u8>> {
    let s: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    if s.len() % 2 != 0 {
        return Err(crate::error::Error::Validation {
            format: "carving",
            reason: format!("odd-length hex string {s:?}"),
        });
    }
    (0..s.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&s[i..i + 2], 16).map_err(|e| crate::error::Error::Validation {
                format: "carving",
                reason: format!("bad hex at {i}: {e}"),
            })
        })
        .collect()
}

/// Parse user-defined TOML carving rules.
pub fn parse_user_rules(toml_text: &str) -> Result<Vec<CarveRule>> {
    let parsed: RulesFile =
        toml::from_str(toml_text).map_err(|e| crate::error::Error::Validation {
            format: "carving",
            reason: format!("TOML parse: {e}"),
        })?;
    parsed.rule.into_iter().map(|r| r.into_rule()).collect()
}

/// Builtin fallback rules (formats without structural handlers yet).
pub fn builtin_rules() -> Vec<CarveRule> {
    vec![
        // GIF: header + terminator footer.
        CarveRule {
            name: "gif".to_string(),
            header: b"GIF8".to_vec(),
            footer: Some(vec![0x00, 0x3b]),
            max_size: 16 * 1024 * 1024,
            terminate_on_next_header: false,
        },
        // RAR signature: carve to next header or max size (no native
        // extraction yet — recovery only).
        CarveRule {
            name: "rar".to_string(),
            header: b"Rar!\x1a\x07".to_vec(),
            footer: None,
            max_size: 32 * 1024 * 1024,
            terminate_on_next_header: true,
        },
        // 7z signature.
        CarveRule {
            name: "7z".to_string(),
            header: b"7z\xbc\xaf\x27\x1c".to_vec(),
            footer: None,
            max_size: 32 * 1024 * 1024,
            terminate_on_next_header: true,
        },
    ]
}

/// Carve a region with builtin + user rules. Only invoked when no
/// structural handler claimed anything in this region.
pub fn carve_region(
    src: &ByteSource,
    limits: &crate::engine::EngineLimits,
    budget: &mut Budget,
) -> Result<Vec<ArtifactDraft>> {
    carve_with_rules(src, limits, budget, &builtin_rules())
}

pub fn carve_with_rules(
    src: &ByteSource,
    limits: &crate::engine::EngineLimits,
    budget: &mut Budget,
    rules: &[CarveRule],
) -> Result<Vec<ArtifactDraft>> {
    let data = src.read_prefix(64 * 1024 * 1024)?;
    if data.is_empty() {
        return Ok(Vec::new());
    }

    let mut drafts = Vec::new();
    for rule in rules {
        if rule.header.is_empty() {
            continue;
        }
        let mut starts: Vec<usize> = Vec::new();
        if data.len() >= rule.header.len() {
            for i in 0..=(data.len() - rule.header.len()) {
                if &data[i..i + rule.header.len()] == rule.header.as_slice() {
                    starts.push(i);
                }
            }
        }
        if starts.len() > 64 {
            continue; // implausible density; skip
        }
        for &start in &starts {
            let end = rule_end(&data, rule, start);
            let len = end - start;
            if len == 0 || len as u64 > rule.max_size || len as u64 > limits.max_child_size {
                continue;
            }
            if !budget.charge(limits, len as u64) {
                break;
            }
            let bytes = data[start..end].to_vec();
            drafts.push(ArtifactDraft {
                format: rule.name.clone(),
                label: format!("carved {} ({} bytes)", rule.name, len),
                offset: start as u64,
                size: len as u64,
                confidence: if rule.footer.is_some() {
                    Confidence::Recovered
                } else {
                    Confidence::Heuristic
                },
                evidence: Evidence::facts(vec![
                    format!("header {} matched", hex_short(&rule.header)),
                    if rule.footer.is_some() {
                        "footer matched".to_string()
                    } else {
                        "bounded by size/next-header".to_string()
                    },
                ]),
                metadata: BTreeMap::new(),
                warnings: vec!["recovered by generic carving".to_string()],
                errors: Vec::new(),
                inline_bytes: Some(bytes),
                children: Vec::new(),
            });
        }
    }
    Ok(drafts)
}

fn rule_end(data: &[u8], rule: &CarveRule, start: usize) -> usize {
    if let Some(footer) = &rule.footer {
        // Search for footer within max_size window.
        let window_end = (start + rule.max_size as usize).min(data.len());
        if let Some(pos) = find_from(data, start + rule.header.len(), window_end, footer) {
            return pos + footer.len();
        }
    }
    if rule.terminate_on_next_header {
        if let Some(next) = find_next_header(data, start + 1, &rule.header) {
            return next;
        }
    }
    (start + rule.max_size as usize).min(data.len())
}

fn find_from(hay: &[u8], from: usize, to: usize, needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || to < needle.len() {
        return None;
    }
    (from..=to - needle.len()).find(|&i| &hay[i..i + needle.len()] == needle)
}

fn find_next_header(data: &[u8], from: usize, header: &[u8]) -> Option<usize> {
    if header.is_empty() || data.len() < header.len() {
        return None;
    }
    (from..=data.len() - header.len()).find(|&i| &data[i..i + header.len()] == header)
}

fn hex_short(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bytesource::ByteSource;

    #[test]
    fn user_rule_parsing() {
        let rules = parse_user_rules(
            r#"
[[rule]]
name = "custom-bin"
header = "CAFEBABE"
footer = "DEADC0DE"
max_size = 65536
terminate_on_next_header = false
"#,
        )
        .unwrap();
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].header, vec![0xca, 0xfe, 0xba, 0xbe]);
        assert_eq!(rules[0].footer, Some(vec![0xde, 0xad, 0xc0, 0xde]));
    }

    #[test]
    fn carves_gif_with_footer() {
        let mut data = b"not-a-gif-just-padding".to_vec();
        data.extend_from_slice(b"GIF89a");
        data.extend_from_slice(&[0u8; 100]);
        data.extend_from_slice(&[0x00, 0x3b]);
        data.extend_from_slice(b"trailing garbage");
        let src = ByteSource::from_vec(data);
        let mut budget = Budget::default();
        let limits = crate::engine::EngineLimits::default();
        let drafts = carve_with_rules(&src, &limits, &mut budget, &builtin_rules()).unwrap();
        assert!(drafts.iter().any(|d| d.format == "gif"));
        let gif = drafts.iter().find(|d| d.format == "gif").unwrap();
        assert_eq!(gif.confidence, Confidence::Recovered);
    }
}
