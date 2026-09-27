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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constant_and_random_bounded() {
        assert_eq!(shannon(&[0x41; 1000]), 0.0);
        let rising: Vec<u8> = (0..=255u8).collect();
        assert_eq!(shannon(&rising), 8.0);
    }
}
