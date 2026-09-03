//! ZIP container sniffing: docx/xlsx/pptx/odt/jar/apk/epub are all ZIPs.
//! Walks local file headers from the start of the archive (no external zip
//! crate needed) and classifies by well-known member names.

use std::io::{Read, Seek, SeekFrom};

pub struct ContainerMatch {
    pub name: String,
    pub mime: String,
    pub extensions: Vec<String>,
    pub note: String,
}

const LOCAL_HDR_SIG: u32 = 0x0403_4b50;
const MAX_ENTRIES: usize = 64;
const MAX_SEEK: u64 = 4 * 1024 * 1024; // give up walking after 4 MB

fn le_u16(b: &[u8]) -> u16 {
    u16::from_le_bytes([b[0], b[1]])
}
fn le_u32(b: &[u8]) -> u32 {
    u32::from_le_bytes([b[0], b[1], b[2], b[3]])
}

/// Inspect a file known to start with PK\x03\x04. Returns a refined
/// container identity when recognized, otherwise None (plain ZIP).
pub fn sniff_container(path: &std::path::Path) -> Option<ContainerMatch> {
    let mut f = std::fs::File::open(path).ok()?;
    let mut names: Vec<String> = Vec::new();
    let mut mimetype_content: Option<String> = None;
    let mut offset: u64 = 0;

    for _ in 0..MAX_ENTRIES {
        let mut hdr = [0u8; 30];
        if f.seek(SeekFrom::Start(offset)).is_err() {
            break;
        }
        if f.read_exact(&mut hdr).is_err() {
            break;
        }
        if le_u32(&hdr[0..4]) != LOCAL_HDR_SIG {
            break;
        }
        let flags = le_u16(&hdr[6..8]);
        let method = le_u16(&hdr[8..10]);
        let comp_size = le_u32(&hdr[18..22]) as u64;
        let name_len = le_u16(&hdr[26..28]) as u64;
        let extra_len = le_u16(&hdr[28..30]) as u64;

        let mut name_buf = vec![0u8; name_len as usize];
        if f.read_exact(&mut name_buf).is_err() {
            break;
        }
        let name = String::from_utf8_lossy(&name_buf).to_string();
        let data_start = offset + 30 + name_len + extra_len;

        // ODF/EPUB: first entry is "mimetype", stored uncompressed.
        if name == "mimetype" && method == 0 && comp_size > 0 && comp_size < 512 {
            let mut buf = vec![0u8; comp_size as usize];
            if f.seek(SeekFrom::Start(data_start)).is_ok() && f.read_exact(&mut buf).is_ok() {
                mimetype_content = Some(String::from_utf8_lossy(&buf).trim().to_string());
            }
        }
        names.push(name);

        // If the data-descriptor flag is set, sizes may be zero in the local
        // header and we can't reliably skip to the next entry — stop walking.
        if flags & 0x08 != 0 {
            break;
        }
        offset = data_start + comp_size;
        if offset > MAX_SEEK {
            break;
        }
    }

    classify(&names, mimetype_content.as_deref())
}

fn has(names: &[String], needle: &str) -> bool {
    names.iter().any(|n| n.eq_ignore_ascii_case(needle))
}
fn has_prefix(names: &[String], prefix: &str) -> bool {
    let p = prefix.to_lowercase();
    names.iter().any(|n| n.to_lowercase().starts_with(&p))
}

fn classify(names: &[String], mimetype: Option<&str>) -> Option<ContainerMatch> {
    let found = |what: &str| format!("ZIP container: found {what}");

    // EPUB / OpenDocument carry a "mimetype" member.
    if let Some(mt) = mimetype {
        let (name, mime, exts): (&str, &str, &[&str]) = match mt {
            "application/epub+zip" => ("EPUB e-book", "application/epub+zip", &["epub"]),
            "application/vnd.oasis.opendocument.text" => {
                ("OpenDocument text (ODT)", mt, &["odt", "fodt"])
            }
            "application/vnd.oasis.opendocument.spreadsheet" => {
                ("OpenDocument spreadsheet (ODS)", mt, &["ods", "fods"])
            }
            "application/vnd.oasis.opendocument.presentation" => {
                ("OpenDocument presentation (ODP)", mt, &["odp", "fodp"])
            }
            "application/vnd.oasis.opendocument.graphics" => {
                ("OpenDocument drawing (ODG)", mt, &["odg"])
            }
            _ => ("OpenDocument / mimetype-typed ZIP", "application/zip", &["zip"]),
        };
        return Some(ContainerMatch {
            name: name.into(),
            mime: mime.into(),
            extensions: exts.iter().map(|s| s.to_string()).collect(),
            note: format!("ZIP container: mimetype member = {mt}"),
        });
    }

    // Android package.
    if has(names, "AndroidManifest.xml") || has(names, "classes.dex") {
        return Some(ContainerMatch {
            name: "Android package (APK)".into(),
            mime: "application/vnd.android.package-archive".into(),
            extensions: vec!["apk".into()],
            note: found("AndroidManifest.xml / classes.dex"),
        });
    }

    // OOXML family.
    if has(names, "[Content_Types].xml") {
        let (name, mime, exts): (&str, &str, &[&str]) = if has_prefix(names, "word/") {
            (
                "Word document (DOCX)",
                "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
                &["docx", "docm", "dotx"],
            )
        } else if has_prefix(names, "xl/") {
            (
                "Excel workbook (XLSX)",
                "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                &["xlsx", "xlsm", "xltx"],
            )
        } else if has_prefix(names, "ppt/") {
            (
                "PowerPoint presentation (PPTX)",
                "application/vnd.openxmlformats-officedocument.presentationml.presentation",
                &["pptx", "pptm", "potx", "ppsx"],
            )
        } else {
            ("Office Open XML package", "application/zip", &["zip"])
        };
        return Some(ContainerMatch {
            name: name.into(),
            mime: mime.into(),
            extensions: exts.iter().map(|s| s.to_string()).collect(),
            note: found("[Content_Types].xml"),
        });
    }

    // Java archive.
    if has(names, "META-INF/MANIFEST.MF") || has_prefix(names, "META-INF/") {
        return Some(ContainerMatch {
            name: "Java archive (JAR)".into(),
            mime: "application/java-archive".into(),
            extensions: vec!["jar".into(), "war".into(), "ear".into()],
            note: found("META-INF/"),
        });
    }

    None
}

