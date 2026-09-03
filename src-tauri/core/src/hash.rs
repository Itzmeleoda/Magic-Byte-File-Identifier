//! Streaming MD5 / SHA-1 / SHA-256 — files are hashed in 64 KiB chunks,
//! never loaded whole.

use serde::Serialize;
use std::io::Read;

#[derive(Debug, Clone, Serialize)]
pub struct Hashes {
    pub md5: String,
    pub sha1: String,
    pub sha256: String,
}

pub fn hash_file(path: &std::path::Path) -> std::io::Result<Hashes> {
    use sha1::Digest as _; // shared Digest trait, used by both sha1 and sha2
    let mut f = std::fs::File::open(path)?;
    let mut md5_ctx = md5::Context::new();
    let mut sha1_ctx = sha1::Sha1::new();
    let mut sha256_ctx = sha2::Sha256::new();
    let mut buf = [0u8; 65536];
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        md5_ctx.consume(&buf[..n]);
        sha1_ctx.update(&buf[..n]);
        sha256_ctx.update(&buf[..n]);
    }
    Ok(Hashes {
        md5: format!("{:x}", md5_ctx.compute()),
        sha1: format!("{:x}", sha1_ctx.finalize()),
        sha256: format!("{:x}", sha256_ctx.finalize()),
    })
}
