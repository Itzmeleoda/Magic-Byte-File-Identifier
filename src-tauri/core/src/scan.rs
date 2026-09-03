//! Recursive scanning with progress + cancellation, and CSV/JSON export.

use crate::engine::{self, Detection};
use crate::hash::{hash_file, Hashes};
use crate::signatures::CompiledFormat;
use serde::Serialize;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use walkdir::WalkDir;

#[derive(Debug, Clone, Serialize)]
pub struct FileRow {
    pub path: String,
    pub size: u64,
    pub extension: String,
    pub detected_name: String,
    pub mime: String,
    pub category: String,
    pub confidence: String,
    pub ext_match: Option<bool>, // None = no extension / N/A
    pub note: Option<String>,
    pub error: Option<String>,
    pub match_offset: Option<usize>,
    pub match_len: Option<usize>,
    pub match_hex: Option<String>,
    pub header_hex: String,
    pub hashes: Option<Hashes>,
}

impl FileRow {
    fn error_row(path: &Path, msg: String) -> Self {
        FileRow {
            path: path.to_string_lossy().into_owned(),
            size: 0,
            extension: engine::file_extension(path),
            detected_name: "Error".into(),
            mime: String::new(),
            category: "Error".into(),
            confidence: "none".into(),
            ext_match: None,
            note: None,
            error: Some(msg),
            match_offset: None,
            match_len: None,
            match_hex: None,
            header_hex: String::new(),
            hashes: None,
        }
    }

    fn from_detection(path: &Path, size: u64, d: Detection, hashes: Option<Hashes>) -> Self {
        FileRow {
            path: path.to_string_lossy().into_owned(),
            size,
            extension: engine::file_extension(path),
            detected_name: d.name,
            mime: d.mime,
            category: d.category,
            confidence: serde_json::to_value(&d.confidence)
                .ok()
                .and_then(|v| v.as_str().map(String::from))
                .unwrap_or_else(|| "none".into()),
            ext_match: d.ext_match,
            note: d.note,
            error: None,
            match_offset: d.match_offset,
            match_len: d.match_len,
            match_hex: d.match_hex,
            header_hex: d.header_hex,
            hashes,
        }
    }
}

pub struct ScanOptions {
    pub recursive: bool,
    pub hash: bool,
    pub header_len: usize,
    /// Optional progress callback: (files_done, current_path).
    pub on_progress: Option<Box<dyn Fn(usize, &str) + Send>>,
    /// Checked between files; set to true to cancel.
    pub cancel: Option<Arc<AtomicBool>>,
}

impl Default for ScanOptions {
    fn default() -> Self {
        ScanOptions {
            recursive: true,
            hash: true,
            header_len: engine::DEFAULT_HEADER_LEN,
            on_progress: None,
            cancel: None,
        }
    }
}

fn is_cancelled(opts: &ScanOptions) -> bool {
    opts.cancel
        .as_ref()
        .map(|c| c.load(Ordering::Relaxed))
        .unwrap_or(false)
}

/// Identify one file (with hashing). Used by both single-file mode and scans.
pub fn identify_file(
    path: &Path,
    formats: &[CompiledFormat],
    hash: bool,
    header_len: usize,
) -> FileRow {
    let meta = match std::fs::symlink_metadata(path) {
        Ok(m) => m,
        Err(e) => return FileRow::error_row(path, format!("cannot stat: {e}")),
    };
    if meta.file_type().is_symlink() {
        return FileRow::error_row(path, "symbolic link / junction (not followed)".into());
    }
    if meta.is_dir() {
        return FileRow::error_row(path, "is a directory".into());
    }
    let size = meta.len();

    match engine::identify(path, formats, header_len) {
        Ok(d) => {
            let hashes = if hash {
                hash_file(path).ok()
            } else {
                None
            };
            FileRow::from_detection(path, size, d, hashes)
        }
        Err(e) => FileRow::error_row(path, e),
    }
}

/// Scan a file or folder. Errors on individual files become rows, so one
/// locked/unreadable file never aborts the batch.
pub fn scan(paths: &[PathBuf], formats: &[CompiledFormat], opts: &ScanOptions) -> Vec<FileRow> {
    let mut rows = Vec::new();
    let mut done = 0usize;

    for root in paths {
        if is_cancelled(opts) {
            break;
        }
        let meta = std::fs::symlink_metadata(root);
        let is_dir = meta.as_ref().map(|m| m.is_dir()).unwrap_or(false);

        if !is_dir {
            rows.push(identify_file(root, formats, opts.hash, opts.header_len));
            done += 1;
            if let Some(cb) = &opts.on_progress {
                cb(done, &root.to_string_lossy());
            }
            continue;
        }

        let walker = if opts.recursive {
            WalkDir::new(root).follow_links(false)
        } else {
            WalkDir::new(root).max_depth(1).follow_links(false)
        };
        for entry in walker {
            if is_cancelled(opts) {
                break;
            }
            match entry {
                Ok(e) => {
                    if e.file_type().is_dir() {
                        continue;
                    }
                    if is_cancelled(opts) {
                        break;
                    }
                    rows.push(identify_file(e.path(), formats, opts.hash, opts.header_len));
                    done += 1;
                    if let Some(cb) = &opts.on_progress {
                        cb(done, &e.path().to_string_lossy());
                    }
                }
                Err(err) => {
                    let p = err
                        .path()
                        .map(PathBuf::from)
                        .unwrap_or_else(|| root.clone());
                    rows.push(FileRow::error_row(&p, format!("walk error: {err}")));
                }
            }
        }
    }
    rows
}

pub fn to_csv(rows: &[FileRow]) -> String {
    fn esc(s: &str) -> String {
        if s.contains([',', '"', '\n']) {
            format!("\"{}\"", s.replace('"', "\"\""))
        } else {
            s.to_string()
        }
    }
    let mut out = String::from(
        "path,size,extension,detected_type,mime,category,confidence,ext_match,md5,sha1,sha256,note,error\n",
    );
    for r in rows {
        let em = match r.ext_match {
            Some(true) => "match",
            Some(false) => "MISMATCH",
            None => "",
        };
        let (md5, sha1, sha256) = r
            .hashes
            .as_ref()
            .map(|h| (h.md5.as_str(), h.sha1.as_str(), h.sha256.as_str()))
            .unwrap_or(("", "", ""));
        out.push_str(&format!(
            "{},{},{},{},{},{},{},{},{},{},{},{},{}\n",
            esc(&r.path),
            r.size,
            esc(&r.extension),
            esc(&r.detected_name),
            esc(&r.mime),
            esc(&r.category),
            esc(&r.confidence),
            em,
            md5,
            sha1,
            sha256,
            esc(r.note.as_deref().unwrap_or("")),
            esc(r.error.as_deref().unwrap_or("")),
        ));
    }
    out
}

pub fn to_json(rows: &[FileRow]) -> String {
    serde_json::to_string_pretty(rows).unwrap_or_else(|_| "[]".into())
}
