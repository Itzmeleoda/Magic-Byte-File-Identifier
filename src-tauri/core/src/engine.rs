//! Detection engine: reads a file's header and matches it against the
//! compiled signature table. Never loads whole files into memory.

use crate::signatures::CompiledFormat;
use crate::zip_detect;
use serde::Serialize;
use std::io::Read;
use std::path::Path;

pub const DEFAULT_HEADER_LEN: usize = 4096;
pub const MAX_HEADER_LEN: usize = 1 << 20; // hard cap: 1 MiB
pub const HEADER_PREVIEW_LEN: usize = 512; // bytes kept for the hex detail pane

#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum Confidence {
    High,
    Medium,
    Low,
    None,
}

#[derive(Debug, Clone, Serialize)]
pub struct Detection {
    pub name: String,
    pub mime: String,
    pub category: String,
    pub extensions: Vec<String>,
    pub confidence: Confidence,
    /// Offset and length (in bytes) of the matched signature in the header.
    pub match_offset: Option<usize>,
    pub match_len: Option<usize>,
    /// Hex dump of the actual matched bytes.
    pub match_hex: Option<String>,
    /// Extra detail, e.g. which ZIP member identified a DOCX.
    pub note: Option<String>,
    /// true = extension agrees with detection, false = mismatch, None = no extension.
    pub ext_match: Option<bool>,
    /// First HEADER_PREVIEW_LEN bytes of the file as a hex string.
    pub header_hex: String,
    pub is_text: bool,
}

pub fn file_extension(path: &Path) -> String {
    path.extension()
        .map(|e| e.to_string_lossy().to_lowercase())
        .unwrap_or_default()
}

pub fn read_header(path: &Path, len: usize) -> std::io::Result<Vec<u8>> {
    let mut f = std::fs::File::open(path)?;
    let mut buf = vec![0u8; len.min(MAX_HEADER_LEN)];
    let mut filled = 0;
    loop {
        let n = f.read(&mut buf[filled..])?;
        if n == 0 {
            break;
        }
        filled += n;
        if filled == buf.len() {
            break;
        }
    }
    buf.truncate(filled);
    Ok(buf)
}

/// Bytes needed by the deepest signature in the table.
pub fn required_header_len(formats: &[CompiledFormat], configured: usize) -> usize {
    let deepest = formats
        .iter()
        .flat_map(|f| f.sigs.iter().map(|s| s.end()))
        .max()
        .unwrap_or(0);
    configured.max(deepest).min(MAX_HEADER_LEN)
}

fn to_hex(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|b| format!("{b:02X}"))
        .collect::<Vec<_>>()
        .join(" ")
}

/// Heuristic text check: no NUL bytes and decodes as UTF-8.
fn looks_like_text(header: &[u8]) -> bool {
    !header.is_empty() && !header.contains(&0) && std::str::from_utf8(header).is_ok()
}

fn ext_match(extensions: &[String], ext: &str) -> Option<bool> {
    if ext.is_empty() {
        None
    } else {
        Some(extensions.iter().any(|e| e == ext))
    }
}

fn unknown(header: &[u8], ext: &str, reason: &str) -> Detection {
    let (name, mime, is_text, confidence) = if header.is_empty() {
        ("Empty file".into(), "inode/x-empty".into(), false, Confidence::High)
    } else if looks_like_text(header) {
        (
            "Plain text (UTF-8)".into(),
            "text/plain".into(),
            true,
            Confidence::Low,
        )
    } else {
        (
            "Unknown / binary data".into(),
            "application/octet-stream".into(),
            false,
            Confidence::None,
        )
    };
    let text_exts = [
        "txt", "log", "md", "csv", "tsv", "json", "xml", "yaml", "yml", "ini", "cfg", "toml",
        "html", "htm", "css", "js", "ts", "jsx", "tsx", "py", "rs", "c", "h", "cpp", "hpp",
        "java", "go", "rb", "php", "sh", "bat", "ps1", "sql", "svg",
    ];
    let ext_match = if is_text {
        if ext.is_empty() {
            None
        } else {
            Some(text_exts.contains(&ext))
        }
    } else {
        None
    };
    let _ = reason;
    Detection {
        name,
        mime,
        category: if is_text { "Document".into() } else { "Other".into() },
        extensions: vec![],
        confidence,
        match_offset: None,
        match_len: None,
        match_hex: None,
        note: None,
        ext_match,
        header_hex: to_hex(&header[..header.len().min(HEADER_PREVIEW_LEN)]),
        is_text,
    }
}

/// Identify a single file. `header_len` is user-configurable; the table's
/// deepest signature may raise it (capped at MAX_HEADER_LEN).
pub fn identify(path: &Path, formats: &[CompiledFormat], header_len: usize) -> Result<Detection, String> {
    let meta = std::fs::symlink_metadata(path).map_err(|e| format!("cannot stat: {e}"))?;
    if meta.file_type().is_symlink() {
        return Err("symbolic link / junction (not followed)".into());
    }

    let need = required_header_len(formats, header_len);
    let header = read_header(path, need).map_err(|e| format!("cannot read header: {e}"))?;
    if header.is_empty() {
        return Ok(unknown(&header, &file_extension(path), "empty"));
    }
    let ext = file_extension(path);

    for fmt in formats {
        // Table is sorted by specificity; first full match wins.
        let matched = fmt.sigs.iter().find(|s| !s.matches(&header));
        if matched.is_some() {
            continue;
        }

        if fmt.is_zip_container {
            if let Some(cm) = zip_detect::sniff_container(path) {
                let sig = &fmt.sigs[0];
                return Ok(Detection {
                    name: cm.name.into(),
                    mime: cm.mime.into(),
                    category: fmt.category.clone(),
                    extensions: cm.extensions.iter().map(|s| s.to_string()).collect(),
                    confidence: Confidence::High,
                    match_offset: Some(sig.offset),
                    match_len: Some(sig.bytes.len()),
                    match_hex: Some(sig.actual_hex(&header)),
                    note: Some(cm.note),
                    ext_match: ext_match(
                        &cm.extensions.iter().map(|s| s.to_string()).collect::<Vec<_>>(),
                        &ext,
                    ),
                    header_hex: to_hex(&header[..header.len().min(HEADER_PREVIEW_LEN)]),
                    is_text: false,
                });
            }
            // Plain ZIP: fall through and report the container entry itself.
        }

        // Generic ZIP subtypes with wildcard sigs report medium confidence.
        let has_wildcard = fmt.sigs.iter().any(|s| s.mask.iter().any(|&m| m != 0xFF));
        let sig = fmt
            .sigs
            .iter()
            .max_by_key(|s| s.bytes.len())
            .expect("compiled formats have signatures");
        return Ok(Detection {
            name: fmt.name.clone(),
            mime: fmt.mime.clone(),
            category: fmt.category.clone(),
            extensions: fmt.extensions.clone(),
            confidence: if has_wildcard {
                Confidence::Medium
            } else {
                Confidence::High
            },
            match_offset: Some(sig.offset),
            match_len: Some(sig.bytes.len()),
            match_hex: Some(sig.actual_hex(&header)),
            note: if fmt.is_zip_container {
                Some("ZIP container: inner structure not recognized".into())
            } else {
                None
            },
            ext_match: ext_match(&fmt.extensions, &ext),
            header_hex: to_hex(&header[..header.len().min(HEADER_PREVIEW_LEN)]),
            is_text: false,
        });
    }

    Ok(unknown(&header, &ext, "no signature matched"))
}
