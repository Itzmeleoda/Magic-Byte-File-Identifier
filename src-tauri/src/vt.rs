//! Optional VirusTotal hash-only lookup (v3 API). The file itself is never
//! uploaded — only its SHA-256. Requires the user's own free API key.

use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub struct VtResult {
    pub found: bool,
    pub malicious: u64,
    pub suspicious: u64,
    pub total_engines: u64,
    pub permalink: String,
    pub error: Option<String>,
}

pub fn lookup_hash(sha256: &str, api_key: &str) -> VtResult {
    let permalink = format!("https://www.virustotal.com/gui/file/{sha256}");
    let url = format!("https://www.virustotal.com/api/v3/files/{sha256}");
    let resp = ureq::get(&url)
        .set("x-apikey", api_key)
        .set("accept", "application/json")
        .timeout(std::time::Duration::from_secs(15))
        .call();

    match resp {
        Ok(r) => {
            let body: serde_json::Value = match r.into_json() {
                Ok(v) => v,
                Err(e) => return err(&permalink, &format!("invalid VT response: {e}")),
            };
            let stats = &body["data"]["attributes"]["last_analysis_stats"];
            let malicious = stats["malicious"].as_u64().unwrap_or(0);
            let suspicious = stats["suspicious"].as_u64().unwrap_or(0);
            let harmless = stats["harmless"].as_u64().unwrap_or(0);
            let undetected = stats["undetected"].as_u64().unwrap_or(0);
            VtResult {
                found: true,
                malicious,
                suspicious,
                total_engines: malicious + suspicious + harmless + undetected,
                permalink,
                error: None,
            }
        }
        Err(ureq::Error::Status(404, _)) => VtResult {
            found: false,
            malicious: 0,
            suspicious: 0,
            total_engines: 0,
            permalink,
            error: Some("hash not known to VirusTotal".into()),
        },
        Err(ureq::Error::Status(401, _)) => {
            err(&permalink, "invalid API key (check Settings)")
        }
        Err(ureq::Error::Status(429, _)) => {
            err(&permalink, "rate limit hit (free key: 4 lookups/min)")
        }
        Err(e) => err(&permalink, &format!("request failed: {e}")),
    }
}

fn err(permalink: &str, msg: &str) -> VtResult {
    VtResult {
        found: false,
        malicious: 0,
        suspicious: 0,
        total_engines: 0,
        permalink: permalink.to_string(),
        error: Some(msg.to_string()),
    }
}
