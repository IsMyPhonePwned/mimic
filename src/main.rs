//! CLI for mimic: scan files/directories for maliciously crafted DNG (and future formats).

#![cfg(feature = "cli")]

use clap::Parser;
use indexmap::IndexMap;
use mimic::{analyze, detect_file_type, AnalysisResult, Verdict, TrustLevel};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::Path;
use walkdir::WalkDir;

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("{:x}", hasher.finalize())
}

#[derive(Parser)]
#[command(name = "mimic")]
#[command(about = "Detect maliciously crafted files (DNG, RTF exploit detection)", long_about = None)]
struct Args {
    /// Path to a file or directory to scan (use -d/--directory to scan a whole directory)
    path: Option<String>,

    /// Scan a whole directory (optionally with -r to recurse into subdirectories)
    #[arg(short = 'd', long = "directory", value_name = "DIR")]
    directory: Option<String>,

    /// When scanning a directory, recurse into subdirectories
    #[arg(short, long)]
    recursive: bool,

    /// File extensions to scan (comma-separated). Default: dng,tif,tiff,jpg,jpeg,rtf,doc,ttf,otf,pdf,rar. No-extension files are always scanned (type guessed from content). Use --all to ignore extension filter.
    #[arg(short, long, default_value = "dng,tif,tiff,jpg,jpeg,rtf,doc,ttf,otf,pdf,rar")]
    extensions: String,

    /// Scan all files and guess type from content (ignore extension filter)
    #[arg(long)]
    all: bool,

    /// Output JSON per result (one line per file unless --pretty)
    #[arg(long)]
    json: bool,

    /// Pretty-print JSON (use with --json)
    #[arg(long)]
    pretty: bool,

    /// Quiet: only print malicious/suspicious paths
    #[arg(short, long)]
    quiet: bool,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    let exts: std::collections::HashSet<String> = args
        .extensions
        .split(',')
        .map(|s| s.trim().to_lowercase())
        .collect();

    let path_str = args
        .directory
        .as_ref()
        .or(args.path.as_ref())
        .ok_or("Missing path: give a file/directory as argument or use -d/--directory <DIR>")?;
    let path = Path::new(path_str.as_str());

    if !path.exists() {
        eprintln!("Not found: {}", path.display());
        std::process::exit(1);
    }

    if path.is_file() {
        if args.directory.is_some() {
            eprintln!("--directory expects a directory, not a file: {}", path.display());
            std::process::exit(1);
        }
        scan_file(path, &args, &exts)?;
        return Ok(());
    }

    if path.is_dir() {
        if !args.quiet {
            eprintln!("Scanning directory: {} {}", path.display(), if args.recursive { "(recursive)" } else { "" });
        }
        scan_dir(path, &args, &exts)?;
        return Ok(());
    }

    eprintln!("Not a file or directory: {}", path.display());
    std::process::exit(1);
}

fn scan_file(
    path: &Path,
    args: &Args,
    exts: &std::collections::HashSet<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_lowercase();
    // Skip only when: not --all, file has an extension, and it's not in the list. No extension => always scan (guess from content).
    if !args.all && !ext.is_empty() && !exts.is_empty() && !exts.contains(&ext) {
        if !args.quiet {
            eprintln!("Skip (extension): {}", path.display());
        }
        return Ok(());
    }
    let bytes = fs::read(path)?;
    let result = analyze(&bytes);
    let no_extension = path.extension().is_none();
    print_result(path.display().to_string(), &result, args, no_extension, &bytes)?;
    Ok(())
}

fn scan_dir(
    dir: &Path,
    args: &Args,
    exts: &std::collections::HashSet<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    let walker = if args.recursive {
        WalkDir::new(dir).into_iter()
    } else {
        WalkDir::new(dir).max_depth(1).into_iter()
    };

    let mut total = 0u64;
    let mut malicious = 0u64;
    let mut suspicious = 0u64;

    for entry in walker.filter_entry(|e| !e.path().starts_with(".")) {
        let entry = entry?;
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        let ext = path
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or("")
            .to_lowercase();
        if !args.all && !ext.is_empty() && !exts.is_empty() && !exts.contains(&ext) {
            continue;
        }
        total += 1;
        let bytes = match fs::read(path) {
            Ok(b) => b,
            Err(_) => continue,
        };
        let result = analyze(&bytes);
        match result.verdict {
            Verdict::Malicious => malicious += 1,
            Verdict::Suspicious => suspicious += 1,
            Verdict::Benign => {}
        }
        let no_extension = path.extension().is_none();
        print_result(path.display().to_string(), &result, args, no_extension, &bytes)?;
    }

    if !args.quiet {
        eprintln!(
            "Scanned {} files, {} malicious, {} suspicious",
            total, malicious, suspicious
        );
    }
    Ok(())
}

fn print_result(
    path: String,
    result: &AnalysisResult,
    args: &Args,
    no_extension: bool,
    bytes: &[u8],
) -> Result<(), Box<dyn std::error::Error>> {
    if args.quiet && result.verdict == Verdict::Benign {
        return Ok(());
    }
    if args.json {
        let sha256 = sha256_hex(bytes);
        let guessed = no_extension.then(|| detect_file_type(bytes).label());
        let mut out = IndexMap::<String, serde_json::Value>::new();
        out.insert("sha256".to_string(), serde_json::Value::String(sha256));
        out.insert("path".to_string(), serde_json::Value::String(path.clone()));
        out.insert("verdict".to_string(), serde_json::Value::String(format!("{:?}", result.verdict)));
        out.insert("threats".to_string(), serde_json::to_value(&result.threats)?);
        out.insert("size_bytes".to_string(), serde_json::to_value(&result.size_bytes)?);
        out.insert("format".to_string(), serde_json::Value::String(result.comprehension.format.clone()));
        out.insert("guessed_type".to_string(), serde_json::to_value(&guessed)?);
        out.insert("details".to_string(), serde_json::to_value(&result.comprehension.details)?);
        out.insert("warnings".to_string(), serde_json::to_value(&result.comprehension.warnings)?);
        out.insert("extraction_rtf".to_string(), serde_json::to_value(&result.comprehension.extraction_rtf)?);
        out.insert("extraction_dng_tile".to_string(), serde_json::to_value(&result.comprehension.extraction_dng_tile)?);
        let json_str = if args.pretty {
            serde_json::to_string_pretty(&out)?
        } else {
            serde_json::to_string(&out)?
        };
        println!("{}", json_str);
        return Ok(());
    }
    // Human-readable output: sha256 first
    let sha256 = sha256_hex(bytes);
    println!("  sha256: {}", sha256);
    let size_str = result
        .size_bytes
        .map(|n| format!(" ({} bytes)", n))
        .unwrap_or_default();
    match result.verdict {
        Verdict::Malicious => {
            println!("MALICIOUS {} {}", path, size_str);
            for t in &result.threats {
                let trust_str = match t.trust {
                    TrustLevel::High => "high",
                    TrustLevel::Low => "low",
                };
                println!("  threat: {} [trust: {}] — {}", t.id, trust_str, t.description);
                if let Some(ref u) = t.reference {
                    println!("    ref: {}", u);
                }
            }
        }
        Verdict::Suspicious => {
            println!("SUSPICIOUS {} {}", path, size_str);
            for w in &result.comprehension.warnings {
                println!("  - {}", w);
            }
        }
        Verdict::Benign => {
            if !args.quiet {
                println!("OK {} {}", path, size_str);
            }
        }
    }
    if !args.quiet {
        if no_extension {
            let guessed = detect_file_type(bytes);
            println!("  guessed type: {} (no extension)", guessed.label());
        }
        println!("  format: {}", result.comprehension.format);
        for d in &result.comprehension.details {
            println!("  - {}", d);
        }
    }
    if !result.comprehension.warnings.is_empty() && result.verdict != Verdict::Suspicious {
        for w in &result.comprehension.warnings {
            println!("  warning: {}", w);
        }
    }
    if let Some(ref ext) = result.comprehension.extraction_rtf {
        println!("  RTF extraction ({} object(s)):", ext.object_count);
        for obj in &ext.objects {
            let class = obj.objclass.as_deref().unwrap_or("-");
            println!("    object #{}: class={} kind={} size={} bytes", obj.index, class, obj.kind, obj.size);
            if let Some(ref entries) = obj.ole_entries {
                for e in entries {
                    println!("      ole: {}", e);
                }
            }
            if let Some(ref links) = obj.links {
                for u in links {
                    println!("      link: {}", u);
                }
            }
        }
    }
    if let Some(ref t) = result.comprehension.extraction_dng_tile {
        println!("  DNG tile config:");
        println!("    image: {}x{}", t.image_width.map(|w| w.to_string()).unwrap_or_else(|| "-".into()), t.image_height.map(|h| h.to_string()).unwrap_or_else(|| "-".into()));
        println!("    tile: {}x{}", t.tile_width.map(|w| w.to_string()).unwrap_or_else(|| "-".into()), t.tile_height.map(|h| h.to_string()).unwrap_or_else(|| "-".into()));
        println!("    offsets={}, byte_counts={}, compressed={}", t.tile_offsets_count, t.tile_byte_counts_count, t.is_compressed);
        if let (Some(e), Some(h), Some(v)) = (t.expected_tiles, t.tiles_horizontal, t.tiles_vertical) {
            println!("    grid {}x{} => expected {} tiles", h, v, e);
        }
        if let Some(ref r) = t.validation_reason {
            println!("    validation: {}", r);
        } else {
            println!("    validation: ok");
        }
    }
    Ok(())
}
