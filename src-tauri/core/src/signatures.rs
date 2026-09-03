//! Signature table types: loading the default table and user-supplied JSON.
//!
//! JSON format (also used by the built-in signature editor):
//! ```json
//! {
//!   "formats": [
//!     {
//!       "name": "PNG image",
//!       "mime": "image/png",
//!       "extensions": ["png"],
//!       "category": "Image",
//!       "signatures": [ { "offset": 0, "hex": "89504E470D0A1A0A" } ]
//!     }
//!   ]
//! }
//! ```
//! `hex` is case-insensitive, may contain spaces, and supports `??` wildcard
//! bytes. All signatures in one format must match (AND semantics), which lets
//! the table express things like RIFF....WAVE vs RIFF....AVI.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignatureFile {
    pub formats: Vec<FormatEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FormatEntry {
    pub name: String,
    pub mime: String,
    #[serde(default)]
    pub extensions: Vec<String>,
    #[serde(default = "default_category")]
    pub category: String,
    #[serde(default)]
    pub container: Option<String>, // "zip" enables inner-structure sniffing
    pub signatures: Vec<SigEntry>,
}

fn default_category() -> String {
    "Other".into()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SigEntry {
    #[serde(default)]
    pub offset: usize,
    pub hex: String,
}

/// A compiled signature: concrete bytes plus a per-byte mask (0x00 = wildcard).
#[derive(Debug, Clone)]
pub struct CompiledSig {
    pub offset: usize,
    pub bytes: Vec<u8>,
    pub mask: Vec<u8>,
}

impl CompiledSig {
    pub fn end(&self) -> usize {
        self.offset + self.bytes.len()
    }

    pub fn matches(&self, header: &[u8]) -> bool {
        if header.len() < self.end() {
            return false;
        }
        let window = &header[self.offset..self.end()];
        window
            .iter()
            .zip(&self.bytes)
            .zip(&self.mask)
            .all(|((&h, &b), &m)| (h & m) == (b & m))
    }

    /// Hex string of the *actual* header bytes this signature would cover.
    pub fn actual_hex(&self, header: &[u8]) -> String {
        if header.len() < self.end() {
            return String::new();
        }
        header[self.offset..self.end()]
            .iter()
            .map(|b| format!("{b:02X}"))
            .collect::<Vec<_>>()
            .join(" ")
    }
}

#[derive(Debug, Clone)]
pub struct CompiledFormat {
    pub name: String,
    pub mime: String,
    pub extensions: Vec<String>,
    pub category: String,
    pub is_zip_container: bool,
    pub sigs: Vec<CompiledSig>,
    /// Total concrete (non-wildcard) bytes; longer = more specific.
    pub specificity: usize,
}

pub fn parse_hex(s: &str) -> Result<(Vec<u8>, Vec<u8>), String> {
    let cleaned: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    if cleaned.len() % 2 != 0 {
        return Err(format!("odd number of hex digits in '{s}'"));
    }
    let mut bytes = Vec::new();
    let mut mask = Vec::new();
    let chars: Vec<char> = cleaned.chars().collect();
    for pair in chars.chunks(2) {
        if pair[0] == '?' && pair[1] == '?' {
            bytes.push(0);
            mask.push(0);
        } else {
            let byte_str: String = pair.iter().collect();
            let b = u8::from_str_radix(&byte_str, 16)
                .map_err(|_| format!("invalid hex byte '{byte_str}' (use ?? for wildcards)"))?;
            bytes.push(b);
            mask.push(0xFF);
        }
    }
    if bytes.is_empty() {
        return Err("empty signature".into());
    }
    Ok((bytes, mask))
}

pub fn compile(file: &SignatureFile) -> Result<Vec<CompiledFormat>, String> {
    let mut out = Vec::new();
    for f in &file.formats {
        if f.signatures.is_empty() {
            return Err(format!("format '{}' has no signatures", f.name));
        }
        let mut sigs = Vec::new();
        let mut specificity = 0;
        for s in &f.signatures {
            let (bytes, mask) =
                parse_hex(&s.hex).map_err(|e| format!("format '{}': {e}", f.name))?;
            specificity += mask.iter().filter(|&&m| m == 0xFF).count();
            sigs.push(CompiledSig {
                offset: s.offset,
                bytes,
                mask,
            });
        }
        out.push(CompiledFormat {
            name: f.name.clone(),
            mime: f.mime.clone(),
            extensions: f.extensions.iter().map(|e| e.to_lowercase()).collect(),
            category: f.category.clone(),
            is_zip_container: f.container.as_deref() == Some("zip"),
            sigs,
            specificity,
        });
    }
    // Most specific first so generic fallbacks (e.g. bare "ftyp") lose.
    out.sort_by(|a, b| b.specificity.cmp(&a.specificity));
    Ok(out)
}

pub fn default_table() -> Vec<CompiledFormat> {
    let file: SignatureFile = serde_json::from_str(include_str!("../signatures/default.json"))
        .expect("embedded default signature table must be valid");
    compile(&file).expect("embedded default signature table must compile")
}

pub fn load_custom(path: &std::path::Path) -> Result<Vec<CompiledFormat>, String> {
    let text = std::fs::read_to_string(path).map_err(|e| format!("cannot read {path:?}: {e}"))?;
    let file: SignatureFile =
        serde_json::from_str(&text).map_err(|e| format!("invalid signature JSON: {e}"))?;
    compile(&file)
}

/// Merge default + custom. A custom entry whose name matches a default entry
/// replaces it (case-insensitive), letting users override built-ins.
pub fn merged(custom: Option<&std::path::Path>) -> Vec<CompiledFormat> {
    let mut formats = default_table();
    if let Some(p) = custom {
        if p.exists() {
            if let Ok(extra) = load_custom(p) {
                for cf in extra {
                    formats.retain(|f| !f.name.eq_ignore_ascii_case(&cf.name));
                    formats.push(cf);
                }
                formats.sort_by(|a, b| b.specificity.cmp(&a.specificity));
            }
        }
    }
    formats
}
