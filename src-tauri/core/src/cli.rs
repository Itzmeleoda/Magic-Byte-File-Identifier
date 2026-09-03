//! CLI passthrough mode:
//!   filetypeid --scan "C:\path" [--csv out.csv] [--json out.json]
//!              [--no-recursive] [--no-hash] [--header-len 8192]
//!              [--signatures custom.json]
//!   filetypeid "C:\path\file.bin"          (single file, prints to stdout)
//!
//! The GUI binary forwards to this when arguments are present.

use crate::scan::{self, ScanOptions};
use crate::signatures;
use std::path::PathBuf;


const USAGE: &str = "filetypeid — magic-byte file identifier

USAGE:
  filetypeid <file>                  Identify a single file
  filetypeid --scan <path> [flags]   Scan a file or folder recursively

FLAGS:
  --csv <file>          Export results to CSV
  --json <file>         Export results to JSON ('-' for stdout)
  --no-recursive        Do not descend into subfolders
  --no-hash             Skip MD5/SHA-1/SHA-256 (faster on large trees)
  --header-len <n>      Header bytes to read per file (default 4096)
  --signatures <file>   Extra/override signature table (JSON)
  -m, --mismatches-only Print only rows where extension != content
  -h, --help            Show this help
";

pub fn run(args: &[String]) -> i32 {
    let mut scan_path: Option<PathBuf> = None;
    let mut csv_out: Option<PathBuf> = None;
    let mut json_out: Option<String> = None;
    let mut opts = ScanOptions::default();
    let mut sig_path: Option<PathBuf> = None;
    let mut mismatches_only = false;

    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "-h" | "--help" => {
                print!("{USAGE}");
                return 0;
            }
            "--scan" => match it.next() {
                Some(p) => scan_path = Some(PathBuf::from(p)),
                None => return fail("--scan requires a path"),
            },
            "--csv" => match it.next() {
                Some(p) => csv_out = Some(PathBuf::from(p)),
                None => return fail("--csv requires a file"),
            },
            "--json" => match it.next() {
                Some(p) => json_out = Some(p.clone()),
                None => return fail("--json requires a file (or '-')"),
            },
            "--no-recursive" => opts.recursive = false,
            "--no-hash" => opts.hash = false,
            "--mismatches-only" | "-m" => mismatches_only = true,
            "--header-len" => match it.next().and_then(|v| v.parse().ok()) {
                Some(n) => opts.header_len = n,
                None => return fail("--header-len requires a number"),
            },
            "--signatures" => match it.next() {
                Some(p) => sig_path = Some(PathBuf::from(p)),
                None => return fail("--signatures requires a file"),
            },
            other if !other.starts_with('-') && scan_path.is_none() => {
                scan_path = Some(PathBuf::from(other));
            }
            other => return fail(&format!("unknown argument: {other}\n\n{USAGE}")),
        }
    }

    let Some(path) = scan_path else {
        eprint!("{USAGE}");
        return 1;
    };
    if !path.exists() {
        return fail(&format!("path does not exist: {}", path.display()));
    }

    let formats = signatures::merged(sig_path.as_deref());
    opts.on_progress = Some(Box::new(|done, cur| {
        eprint!("\r{done} files… {cur}   ");
    }));

    let mut rows = scan::scan(&[path], &formats, &opts);
    eprintln!(); // end progress line

    if mismatches_only {
        rows.retain(|r| r.ext_match == Some(false));
    }

    // Default stdout summary when no export is requested.
    if csv_out.is_none() && json_out.is_none() {
        for r in &rows {
            let flag = match r.ext_match {
                Some(false) => "  <-- MISMATCH",
                _ => "",
            };
            if let Some(err) = &r.error {
                println!("{}\tERROR: {err}", r.path);
            } else {
                println!(
                    "{}\t{}\t{}\t{} ({}){}",
                    r.path, r.extension, r.detected_name, r.mime, r.confidence, flag
                );
            }
        }
        let mismatches = rows.iter().filter(|r| r.ext_match == Some(false)).count();
        eprintln!("{} file(s), {mismatches} mismatch(es)", rows.len());
    }

    if let Some(p) = csv_out {
        if let Err(e) = std::fs::write(&p, scan::to_csv(&rows)) {
            return fail(&format!("cannot write {}: {e}", p.display()));
        }
        eprintln!("wrote {}", p.display());
    }
    if let Some(p) = json_out {
        let data = scan::to_json(&rows);
        if p == "-" {
            println!("{data}");
        } else if let Err(e) = std::fs::write(&p, &data) {
            return fail(&format!("cannot write {p}: {e}"));
        }
    }
    0
}

fn fail(msg: &str) -> i32 {
    eprintln!("error: {msg}");
    1
}
