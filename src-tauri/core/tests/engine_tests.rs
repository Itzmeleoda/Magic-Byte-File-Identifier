use fid_core::engine::{self, Confidence};
use fid_core::signatures;
use std::io::Write;
use std::path::PathBuf;

fn tmpdir() -> PathBuf {
    let d = std::env::temp_dir().join(format!("fid-test-{}", std::process::id()));
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn write_file(name: &str, bytes: &[u8]) -> PathBuf {
    let p = tmpdir().join(name);
    let mut f = std::fs::File::create(&p).unwrap();
    f.write_all(bytes).unwrap();
    p
}

fn id(p: &PathBuf) -> engine::Detection {
    let formats = signatures::merged(None);
    engine::identify(p, &formats, 4096).unwrap()
}

/// Minimal valid ZIP writer (store method, no compression) for building
/// fake docx/apk/jar fixtures.
fn make_zip(entries: &[(&str, &[u8])]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut central = Vec::new();
    for (name, data) in entries {
        let offset = out.len() as u32;
        let crc = crc32(data);
        // local header
        out.extend_from_slice(&0x04034b50u32.to_le_bytes());
        out.extend_from_slice(&20u16.to_le_bytes()); // version
        out.extend_from_slice(&0u16.to_le_bytes()); // flags
        out.extend_from_slice(&0u16.to_le_bytes()); // method = store
        out.extend_from_slice(&0u16.to_le_bytes()); // time
        out.extend_from_slice(&0u16.to_le_bytes()); // date
        out.extend_from_slice(&crc.to_le_bytes());
        out.extend_from_slice(&(data.len() as u32).to_le_bytes()); // comp size
        out.extend_from_slice(&(data.len() as u32).to_le_bytes()); // uncomp size
        out.extend_from_slice(&(name.len() as u16).to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes()); // extra len
        out.extend_from_slice(name.as_bytes());
        out.extend_from_slice(data);
        // central directory entry
        central.extend_from_slice(&0x02014b50u32.to_le_bytes());
        central.extend_from_slice(&20u16.to_le_bytes());
        central.extend_from_slice(&20u16.to_le_bytes());
        central.extend_from_slice(&0u16.to_le_bytes());
        central.extend_from_slice(&0u16.to_le_bytes());
        central.extend_from_slice(&0u16.to_le_bytes());
        central.extend_from_slice(&0u16.to_le_bytes());
        central.extend_from_slice(&crc.to_le_bytes());
        central.extend_from_slice(&(data.len() as u32).to_le_bytes());
        central.extend_from_slice(&(data.len() as u32).to_le_bytes());
        central.extend_from_slice(&(name.len() as u16).to_le_bytes());
        central.extend_from_slice(&[0u8; 12]); // extra/comment/attrs…
        central.extend_from_slice(&0u32.to_le_bytes()); // ext attrs
        central.extend_from_slice(&offset.to_le_bytes());
        central.extend_from_slice(name.as_bytes());
    }
    let cd_offset = out.len() as u32;
    let cd_size = central.len() as u32;
    out.extend_from_slice(&central);
    // end of central directory
    out.extend_from_slice(&0x06054b50u32.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&(entries.len() as u16).to_le_bytes());
    out.extend_from_slice(&(entries.len() as u16).to_le_bytes());
    out.extend_from_slice(&cd_size.to_le_bytes());
    out.extend_from_slice(&cd_offset.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out
}

fn crc32(data: &[u8]) -> u32 {
    // Simple CRC32 (IEEE) — table-free, fine for tests.
    let mut crc: u32 = 0xFFFF_FFFF;
    for &b in data {
        crc ^= b as u32;
        for _ in 0..8 {
            crc = if crc & 1 != 0 { (crc >> 1) ^ 0xEDB8_8320 } else { crc >> 1 };
        }
    }
    !crc
}

#[test]
fn detects_png() {
    let p = write_file("a.png", &[0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 0, 0, 0]);
    let d = id(&p);
    assert_eq!(d.mime, "image/png");
    assert_eq!(d.ext_match, Some(true));
    assert_eq!(d.confidence, Confidence::High);
    assert_eq!(d.match_offset, Some(0));
}

#[test]
fn flags_renamed_exe_as_mismatch() {
    // The headline feature: a PE executable renamed to .jpg
    let p = write_file("photo.jpg", b"MZ\x90\x00\x03\x00\x00\x00 fake pe");
    let d = id(&p);
    assert!(d.mime.contains("portable-executable"));
    assert_eq!(d.ext_match, Some(false));
}

#[test]
fn detects_jpeg_with_wrong_extension() {
    let p = write_file("song.mp3", &[0xFF, 0xD8, 0xFF, 0xE0, 0, 0, 0]);
    let d = id(&p);
    assert_eq!(d.mime, "image/jpeg");
    assert_eq!(d.ext_match, Some(false));
}

#[test]
fn distinguishes_riff_subtypes() {
    let wav = write_file("a.wav", b"RIFF\x24\x00\x00\x00WAVEfmt ");
    assert_eq!(id(&wav).mime, "audio/wav");
    let avi = write_file("b.avi", b"RIFF\x24\x00\x00\x00AVI LIST");
    assert_eq!(id(&avi).mime, "video/x-msvideo");
    let webp = write_file("c.webp", b"RIFF\x24\x00\x00\x00WEBPVP8 ");
    assert_eq!(id(&webp).mime, "image/webp");
}

#[test]
fn distinguishes_mp4_brands() {
    let mov = write_file("a.mov", b"\x00\x00\x00\x18ftypqt  \x00\x00\x00\x00");
    assert_eq!(id(&mov).mime, "video/quicktime");
    let mp4 = write_file("b.mp4", b"\x00\x00\x00\x18ftypisom\x00\x00\x00\x00");
    assert_eq!(id(&mp4).mime, "video/mp4");
    let heic = write_file("c.heic", b"\x00\x00\x00\x18ftypheic\x00\x00\x00\x00");
    assert_eq!(id(&heic).mime, "image/heic");
}

#[test]
fn sniffs_docx_inside_zip() {
    let zip = make_zip(&[
        ("[Content_Types].xml", b"<?xml version=\"1.0\"?>".as_slice()),
        ("word/document.xml", b"<w:document/>".as_slice()),
    ]);
    let p = write_file("report.docx", &zip);
    let d = id(&p);
    assert!(d.name.contains("DOCX"), "got {}", d.name);
    assert_eq!(d.ext_match, Some(true));
}

#[test]
fn sniffs_apk_jar_odt() {
    let apk = write_file(
        "app.apk",
        &make_zip(&[("AndroidManifest.xml", b"\x03\x00\x08\x00".as_slice())]),
    );
    assert!(id(&apk).name.contains("APK"));

    let jar = write_file(
        "lib.jar",
        &make_zip(&[("META-INF/MANIFEST.MF", b"Manifest-Version: 1.0".as_slice())]),
    );
    assert!(id(&jar).name.contains("JAR"));

    let odt = write_file(
        "notes.odt",
        &make_zip(&[(
            "mimetype",
            b"application/vnd.oasis.opendocument.text".as_slice(),
        )]),
    );
    assert!(id(&odt).name.contains("ODT"), "got {}", id(&odt).name);
}

#[test]
fn plain_zip_stays_zip() {
    let zip = make_zip(&[("random.bin", b"\x01\x02\x03".as_slice())]);
    let p = write_file("archive.zip", &zip);
    let d = id(&p);
    assert_eq!(d.mime, "application/zip");
    assert!(d.note.as_deref().unwrap_or("").contains("not recognized"));
}

#[test]
fn handles_zero_byte_file() {
    let p = write_file("empty.bin", &[]);
    let d = id(&p);
    assert_eq!(d.name, "Empty file");
    assert_eq!(d.confidence, Confidence::High);
}

#[test]
fn unknown_binary_falls_back() {
    let p = write_file("mystery.dat", &[0x00, 0x11, 0x22, 0x33, 0x44, 0x00]);
    let d = id(&p);
    assert_eq!(d.name, "Unknown / binary data");
    assert_eq!(d.confidence, Confidence::None);
}

#[test]
fn text_heuristic() {
    let p = write_file("readme.abc", b"hello world, this is plain text\n");
    let d = id(&p);
    assert!(d.is_text);
    assert_eq!(d.mime, "text/plain");
}

#[test]
fn tar_at_offset_257() {
    let mut tar = vec![0u8; 600];
    tar[257..262].copy_from_slice(b"ustar");
    let p = write_file("backup.tar", &tar);
    assert_eq!(id(&p).mime, "application/x-tar");
}

#[test]
fn hashes_work() {
    let p = write_file("hashme.bin", b"abc");
    let h = fid_core::hash::hash_file(&p).unwrap();
    assert_eq!(h.md5, "900150983cd24fb0d6963f7d28e17f72");
    assert_eq!(h.sha1, "a9993e364706816aba3e25717850c26c9cd0d89d");
    assert_eq!(
        h.sha256,
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
}

#[test]
fn scan_collects_and_flags() {
    let dir = tmpdir().join("scan-root");
    std::fs::create_dir_all(dir.join("sub")).unwrap();
    std::fs::write(dir.join("ok.png"), &[0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]).unwrap();
    std::fs::write(dir.join("sub").join("evil.png"), b"MZ pretend exe").unwrap();

    let formats = signatures::merged(None);
    let rows = fid_core::scan::scan(
        &[dir],
        &formats,
        &fid_core::scan::ScanOptions::default(),
    );
    assert_eq!(rows.len(), 2);
    let mismatches: Vec<_> = rows.iter().filter(|r| r.ext_match == Some(false)).collect();
    assert_eq!(mismatches.len(), 1);
    assert!(mismatches[0].path.ends_with("evil.png"));

    let csv = fid_core::scan::to_csv(&rows);
    assert!(csv.contains("MISMATCH"));
    assert!(csv.lines().count() == 3); // header + 2 rows
}

#[test]
fn custom_signatures_override() {
    let json = r#"{"formats":[{"name":"PNG image","mime":"image/x-custom-png",
        "extensions":["png"],"category":"Image",
        "signatures":[{"offset":0,"hex":"89504E47"}]}]}"#;
    let sig_path = tmpdir().join("custom.json");
    std::fs::write(&sig_path, json).unwrap();
    let formats = signatures::merged(Some(&sig_path));
    let p = write_file("x.png", &[0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]);
    let d = engine::identify(&p, &formats, 4096).unwrap();
    assert_eq!(d.mime, "image/x-custom-png");
}

#[test]
fn wildcard_signatures_parse() {
    let (bytes, mask) = signatures::parse_hex("FF D8 ?? E0").unwrap();
    assert_eq!(bytes.len(), 4);
    assert_eq!(mask, vec![0xFF, 0xFF, 0x00, 0xFF]);
    assert!(signatures::parse_hex("FFD8F").is_err()); // odd length
}
