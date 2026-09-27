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
        ..EngineLimits::default()
    };

    let mut engine = RecursiveEngine::new(limits);
    let graph = engine.analyze(&src);
    let byte_cache = engine.byte_cache.clone();

    let mut report = Report::new(
        cli.input
            .file_name()
            .map(|s| s.to_string_lossy().to_string())
            .unwrap_or_else(|| cli.input.display().to_string()),
        src.len(),
        graph,
    );
    report.entropy = entropy::analyze_bounded(&src, 64 * 1024, 16);

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
    if !report.entropy.is_empty() {
        println!("entropy: {}", entropy::compact_line(&report.entropy));
    }
    let _ = std::io::stdout().flush();

    if cli.extract {
        match materialize(cli, &report, &byte_cache) {
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
fn materialize(
    cli: &Cli,
    report: &Report,
    byte_cache: &std::collections::HashMap<String, Vec<u8>>,
) -> std::io::Result<PathBuf> {
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
                    if let Some(bytes) = read_artifact_bytes(report, child, byte_cache) {
                        std::fs::write(dest, bytes)?;
                        wrote_any = true;
                    }
                }
            }
            let _ = relation;
        }
        if !wrote_any {
            if let Some(bytes) = read_artifact_bytes(report, artifact, byte_cache) {
                let dest = dedup_path(&dir.join("body.bin"));
                std::fs::write(dest, bytes)?;
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
    _report: &Report,
    a: &ctf_tools::artifact::Artifact,
    byte_cache: &std::collections::HashMap<String, Vec<u8>>,
) -> Option<Vec<u8>> {
    // Byte materialization comes from the engine's in-memory byte cache,
    // keyed by content hash. See docs/architecture.md for the streaming
    // extraction roadmap.
    byte_cache.get(&a.hash).cloned()
}
