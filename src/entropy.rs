//! Bounded entropy analysis: coarse block-level Shannon entropy suitable
//! for spotting transitions (plaintext -> compressed) without spamming
//! one line per tiny block.

/// Shannon entropy of a byte slice, in bits/byte (0.0..=8.0).
pub fn shannon(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut counts = [0u64; 256];
    for &b in data {
        counts[b as usize] += 1;
    }
    let n = data.len() as f64;
    counts
        .iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = c as f64 / n;
            -p * p.log2()
        })
        .sum()
}

/// One entropy block summary.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct EntropyBlock {
    pub offset: u64,
    pub size: u64,
    /// Bits per byte, rounded to 2 decimals.
    pub entropy: f64,
}

/// Analyze at most `max_blocks` blocks of `block_size`, sampling evenly
/// if the source has more blocks than the budget allows.
pub fn analyze_bounded(
    src: &crate::bytesource::ByteSource,
    block_size: u64,
    max_blocks: usize,
) -> Vec<EntropyBlock> {
    if block_size == 0 || src.is_empty() {
        return Vec::new();
    }
    let total_blocks = src.len().div_ceil(block_size) as usize;
    let step = total_blocks.div_ceil(max_blocks.max(1));
    let mut out = Vec::new();
    let mut index = 0usize;
    while index < total_blocks {
        let offset = index as u64 * block_size;
        let size = block_size.min(src.len() - offset);
        if let Ok(data) = src.slice(offset, size).and_then(|s| s.read_all()) {
            out.push(EntropyBlock {
                offset,
                size,
                entropy: (shannon(&data) * 100.0).round() / 100.0,
            });
        }
        index += step;
    }
    out
}

/// Compact one-line rendering for terminal output, e.g.
/// `entropy: 0x0-0x10000 7.98 | 0x10000-0x11000 2.31 | ...`
pub fn compact_line(blocks: &[EntropyBlock]) -> String {
    blocks
        .iter()
        .map(|b| format!("{:#x}({:.2})", b.offset, b.entropy))
        .collect::<Vec<_>>()
        .join(" ")
}

/// #7 §10: classified, grouped entropy region. Consecutive blocks with
/// the same classification merge into one region so output stays
/// compact regardless of source size.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct EntropyRegion {
    pub offset: u64,
    pub size: u64,
    /// Mean entropy over the constituent blocks (2 decimals).
    pub entropy: f64,
    /// sparse (< 3.0), mixed (3.0..6.5), high (> 6.5) bits/byte.
    pub class: EntropyClass,
}

/// Sparse/low-entropy vs high-entropy classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum EntropyClass {
    /// Sparse/low: plaintext, padding, zeros, indices.
    Sparse,
    /// Mixed: structured data with some compressed fragments.
    Mixed,
    /// High: compressed/encrypted/uniform-random content.
    High,
}

fn classify(bits: f64) -> EntropyClass {
    if bits < 3.0 {
        EntropyClass::Sparse
    } else if bits > 6.5 {
        EntropyClass::High
    } else {
        EntropyClass::Mixed
    }
}

/// Group bounded entropy blocks into classified regions at
/// classification transitions. Output is bounded by the transitions
/// actually present (never one region per block).
pub fn group_regions(blocks: &[EntropyBlock]) -> Vec<EntropyRegion> {
    let mut out: Vec<EntropyRegion> = Vec::new();
    for b in blocks {
        let class = classify(b.entropy);
        match out.last_mut() {
            Some(r) if r.class == class => {
                let merged_entropy = (r.entropy * r.size as f64 + b.entropy * b.size as f64)
                    / (r.size + b.size) as f64;
                r.entropy = (merged_entropy * 100.0).round() / 100.0;
                r.size += b.size;
            }
            _ => out.push(EntropyRegion {
                offset: b.offset,
                size: b.size,
                entropy: b.entropy,
                class,
            }),
        }
    }
    out
}

/// Compact one-line rendering of the classified regions, e.g.
/// `regions: 0x0-0x10000 high(7.98) | 0x10000-0x11000 sparse(2.31)`
pub fn regions_line(regions: &[EntropyRegion]) -> String {
    regions
        .iter()
        .map(|r| {
            let name = match r.class {
                EntropyClass::Sparse => "sparse",
                EntropyClass::Mixed => "mixed",
                EntropyClass::High => "high",
            };
            format!("{:#x}+{:#x} {}({:.2})", r.offset, r.size, name, r.entropy)
        })
        .collect::<Vec<_>>()
        .join(" | ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constant_and_random_bounded() {
        assert_eq!(shannon(&[0x41; 1000]), 0.0);
        let rising: Vec<u8> = (0..=255u8).collect();
        assert_eq!(shannon(&rising), 8.0);
    }

    /// #7 §10: blocks group at classification transitions only.
    #[test]
    fn region_grouping_merges_same_class() {
        let blocks = vec![
            EntropyBlock {
                offset: 0,
                size: 4096,
                entropy: 7.9,
            },
            EntropyBlock {
                offset: 4096,
                size: 4096,
                entropy: 7.8,
            },
            EntropyBlock {
                offset: 8192,
                size: 4096,
                entropy: 1.2,
            },
            EntropyBlock {
                offset: 12288,
                size: 4096,
                entropy: 4.0,
            },
        ];
        let regions = group_regions(&blocks);
        assert_eq!(regions.len(), 3, "two adjacent high blocks merge");
        assert_eq!(regions[0].class, EntropyClass::High);
        assert_eq!(regions[0].size, 8192, "merged size");
        assert_eq!(regions[1].class, EntropyClass::Sparse);
        assert_eq!(regions[2].class, EntropyClass::Mixed);
    }
}
