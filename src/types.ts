// Mirrors the Rust structs in fid-core (scan.rs / engine.rs / vt.rs).

export interface Hashes {
  md5: string;
  sha1: string;
  sha256: string;
}

export interface FileRow {
  path: string;
  size: number;
  extension: string;
  detected_name: string;
  mime: string;
  category: string;
  confidence: "high" | "medium" | "low" | "none" | string;
  ext_match: boolean | null;
  note: string | null;
  error: string | null;
  match_offset: number | null;
  match_len: number | null;
  match_hex: string | null;
  header_hex: string;
  hashes: Hashes | null;
}

export interface SigEntry {
  offset: number;
  hex: string;
}

export interface FormatEntry {
  name: string;
  mime: string;
  extensions: string[];
  category: string;
  container?: string | null;
  signatures: SigEntry[];
}

export interface Settings {
  header_len: number | null;
  hash_enabled: boolean | null;
  vt_api_key: string | null;
  custom_signatures: { formats: FormatEntry[] } | null;
}

export interface VtResult {
  found: boolean;
  malicious: number;
  suspicious: number;
  total_engines: number;
  permalink: string;
  error: string | null;
}

export interface ScanProgress {
  done: number;
  current: string;
}
