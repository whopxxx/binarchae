//! ctf-tools CLI: analyze / extract / recurse over binary artifacts.

use clap::Parser;
use ctf_tools::artifact::{ExtractionStatus, RelationKind};
use ctf_tools::bytesource::ByteSource;
use ctf_tools::entropy;
use ctf_tools::extract::{dedup_path, safe_join};
use ctf_tools::output;
use ctf_tools::report::Report;
use ctf_tools::{EngineLimits, RecursiveEngine};
use std::io::Write;
use std::path::PathBuf;

#[derive(Parser)]
#[command(
    name = "ctf-tools",
    version,
    about = "CTF-first binary analysis and extraction (artifact graph over nested/trailing/carved data)"
)]
struct Cli {
    /// Input file to analyze.
    input: PathBuf,

    /// Materialize recoverable/extractable artifacts under <input>.extracted/.
    #[arg(short = 'e', long)]
    extract: bool,

    /// Recursively analyze child artifacts.
    #[arg(short = 'r', long)]
    recurse: bool,

    /// Emit stable JSON to stdout instead of the compact tree.
    #[arg(long)]
    json: bool,

    /// #7 §12.1: emit JSONL (one record per line) instead of JSON.
    /// Stream-processable for very large graphs.
    #[arg(long)]
    jsonl: bool,

    /// Verbose diagnostics (warnings, evidence) in human output.
    #[arg(short = 'v', long)]
    verbose: bool,

    /// Max recursion depth.
    #[arg(long, default_value_t = 8)]
    max_depth: u32,

    /// Max artifacts in the graph.
    #[arg(long, default_value_t = 512)]
    max_artifacts: usize,

    /// Max total expanded (decompressed/carved) bytes.
    #[arg(long, default_value_t = 512 * 1024 * 1024)]
    max_expanded_bytes: u64,

    /// Optional TOML file with user-defined carving rules.
    #[arg(long)]
    carving_rules: Option<PathBuf>,

    /// Password candidate for encrypted containers (7z/RAR). Repeatable.
    #[arg(long = "password")]
    passwords: Vec<String>,
}

fn main() {
    let cli = Cli::parse();
    let code = run(&cli);
    std::process::exit(code);
}

fn run(cli: &Cli) -> i32 {
    let src = match ByteSource::from_file(&cli.input) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("error: cannot open {}: {e}", cli.input.display());
            return 2;
        }
    };

    let limits = EngineLimits {
        max_depth: cli.max_depth,
        max_artifacts: cli.max_artifacts,
        max_total_expanded_bytes: cli.max_expanded_bytes,
        passwords: cli.passwords.clone(),
        ..EngineLimits::default()
    };

    let mut engine = RecursiveEngine::new(limits);
    // B5: --carving-rules is real — TOML is loaded and fed to the engine.
    if let Some(rules_path) = &cli.carving_rules {
        match std::fs::read_to_string(rules_path) {
            Ok(text) => match ctf_tools::carving::parse_user_rules(&text) {
                Ok(rules) => engine.carving_rules = rules,
                Err(e) => {
                    eprintln!("error: invalid carving rules {}: {e}", rules_path.display());
                    return 2;
                }
            },
            Err(e) => {
                eprintln!("error: cannot read {}: {e}", rules_path.display());
                return 2;
            }
        }
    }
    // B5: recursion only with -r/--recurse. Default = top-level scan.
    let graph = engine.analyze(&src, cli.recurse);

    let mut report = Report::new(
        cli.input
            .file_name()
            .map(|s| s.to_string_lossy().to_string())
            .unwrap_or_else(|| cli.input.display().to_string()),
        src.len(),
        graph,
    );
    report.entropy = entropy::analyze_bounded(&src, 64 * 1024, 16);
    // #7 §10: transition-grouped classified regions (compact; no spam).
    report.entropy_regions = entropy::group_regions(&report.entropy);

    if cli.jsonl {
        let jsonl = report.to_jsonl().unwrap_or_else(|e| {
            eprintln!("error: jsonl serialization failed: {e}");
            String::new()
        });
        print!("{jsonl}");
        let _ = std::io::stdout().flush();
        return 0;
    }

    if cli.json {
        let json = report.to_json_pretty().unwrap_or_else(|e| {
            eprintln!("error: json serialization failed: {e}");
            String::from("{}")
        });
        println!("{json}");
        return 0;
    }

    // Compact human tree.
    print!("{}", output::render_tree(&report.graph, cli.verbose));
    if !report.entropy_regions.is_empty() {
        // §10: classified regions replace the raw block list for
        // compactness; the full block list stays in JSON/JSONL.
        println!(
            "regions: {}",
            entropy::regions_line(&report.entropy_regions)
        );
    } else if !report.entropy.is_empty() {
        println!("entropy: {}", entropy::compact_line(&report.entropy));
    }
    let _ = std::io::stdout().flush();

    if cli.extract {
        match materialize(cli, &report, &engine) {
            Ok(dir) => println!("extracted to {}", dir.display()),
            Err(e) => {
                eprintln!("error: extraction failed: {e}");
                return 1;
            }
        }
    }
    0
}

/// Materialize artifacts under `<input>.extracted/` with a deterministic
/// layout, plus report.json and tree.txt.
fn materialize(cli: &Cli, report: &Report, engine: &RecursiveEngine) -> std::io::Result<PathBuf> {
    let out_root = PathBuf::from(format!("{}.extracted", cli.input.display()));
    std::fs::create_dir_all(&out_root)?;
    let artifacts_dir = out_root.join("artifacts");
    std::fs::create_dir_all(&artifacts_dir)?;

    let mut index: usize = 0;
    for artifact in &report.graph.artifacts {
        // Only materialize artifacts that carry recoverable bytes:
        // decompressed payloads and archive entries are recomputed here
        // from the analysis; inline artifacts are written from the source.
        let extractable = matches!(
            artifact.extraction,
            ExtractionStatus::InMemory | ExtractionStatus::Written
        ) || artifact.format != "input";
        if !extractable {
            continue;
        }
        index += 1;
        let dir_name = format!("{index:06}_{}", artifact.format);
        let dir = artifacts_dir.join(&dir_name);
        std::fs::create_dir_all(&dir)?;

        // Entry names (archive children) go under their parent dir with
        // safe-path enforcement; unknown/unnamed artifacts get body.bin.
        let mut wrote_any = false;
        for (relation, child) in report.graph.children(artifact.id) {
            if let Some(name) = child_label_name(child) {
                if let Ok(dest) = safe_join(&dir, &name) {
                    if let Some(parent) = dest.parent() {
                        std::fs::create_dir_all(parent)?;
                    }
                    let dest = dedup_path(&dest);
                    if stream_artifact(child, engine, &dest)? {
                        wrote_any = true;
                    }
                }
            }
            let _ = relation;
        }
        if !wrote_any {
            let dest = dedup_path(&dir.join("body.bin"));
            if !stream_artifact(artifact, engine, &dest)? {
                // Fallback: owned bytes only (byte_cache).
                if let Some(bytes) = read_artifact_bytes(artifact, engine) {
                    std::fs::write(dest, bytes)?;
                }
            }
        }
    }

    // report.json + tree.txt
    if let Ok(json) = report.to_json_pretty() {
        let _ = std::fs::write(out_root.join("report.json"), json);
    }
    let _ = std::fs::write(
        out_root.join("tree.txt"),
        output::render_tree_txt(&report.graph),
    );

    Ok(out_root)
}

/// #7 §11: stream a source-backed artifact to `dest` with a bounded
/// copy buffer (no whole-artifact Vec). Owned (decompressed) content
/// still goes through the bounded byte cache. Returns true when bytes
/// were written. Hash/provenance are preserved: the analysis-time
/// BLAKE3 hash was computed over these same bytes.
fn stream_artifact(
    a: &ctf_tools::artifact::Artifact,
    engine: &RecursiveEngine,
    dest: &std::path::Path,
) -> std::io::Result<bool> {
    // Source-backed: stream chunk-by-chunk through the region handle.
    if let Some(region) = engine.region_handle(&a.hash) {
        const CHUNK: u64 = 64 * 1024;
        let mut file = std::fs::File::create(dest)?;
        let mut off: u64 = 0;
        let mut buf = vec![0u8; CHUNK as usize];
        while off < region.len() {
            let n = region.len().saturating_sub(off).min(CHUNK) as usize;
            region
                .read_at(off, &mut buf[..n])
                .map_err(std::io::Error::other)?;
            file.write_all(&buf[..n])?;
            off += n as u64;
        }
        return Ok(true);
    }
    // Owned bytes: bounded by expansion limits at capture time; single
    // write is fine (they already exist in memory).
    if let Some(bytes) = engine.cached_bytes(&a.hash) {
        std::fs::write(dest, bytes)?;
        return Ok(true);
    }
    Ok(false)
}

fn child_label_name(a: &ctf_tools::artifact::Artifact) -> Option<String> {
    // Prefer an explicit entry name recorded in metadata by handlers.
    a.metadata
        .get("entry_name")
        .cloned()
        .or_else(|| {
            // zip/tar entry names were joined with \n; single-entry only.
            a.metadata
                .get("entry_names")
                .and_then(|n| n.lines().next().map(|s| s.to_string()))
                .filter(|_| a.format == "raw")
        })
        .or_else(|| {
            if a.relation == Some(RelationKind::Contains) && a.format == "raw" {
                Some(
                    a.label
                        .rsplit_once(' ')
                        .map(|(_, n)| n.to_string())
                        .unwrap_or_else(|| "entry.bin".to_string()),
                )
            } else {
                None
            }
        })
}

fn read_artifact_bytes(
    a: &ctf_tools::artifact::Artifact,
    engine: &RecursiveEngine,
) -> Option<Vec<u8>> {
    // B1: bytes are pulled lazily at materialization time. Owned
    // decompressed payloads come from byte_cache; source-backed regions
    // (firmware payloads, CPIO files, embedded/carved regions) are read
    // through their stored zero-copy handle — analysis never copied them.
    engine.cached_bytes(&a.hash)
}
