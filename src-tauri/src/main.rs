// GUI entry point. CLI passthrough: if the first argument starts with '-'
// (e.g. --scan/--csv/--json/--help), run fid-core's CLI and exit without
// opening a window. Plain path arguments (e.g. from the Explorer context
// menu) open the GUI pre-loaded with those files.

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod vt;

use fid_core::scan::{self, FileRow, ScanOptions};
use fid_core::signatures::{self, SignatureFile};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex};
use tauri::{AppHandle, Emitter, Manager, State};

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Settings {
    pub header_len: Option<usize>,
    pub hash_enabled: Option<bool>,
    pub vt_api_key: Option<String>,
    /// User-supplied signature entries (same shape as the default table).
    pub custom_signatures: Option<SignatureFile>,
}

struct AppState {
    cancel: Mutex<Option<Arc<AtomicBool>>>,
    preload: Vec<String>,
    data_dir: PathBuf,
}

impl AppState {
    fn settings_path(&self) -> PathBuf {
        self.data_dir.join("settings.json")
    }
    fn custom_sig_path(&self) -> PathBuf {
        self.data_dir.join("custom-signatures.json")
    }
    fn load_settings(&self) -> Settings {
        std::fs::read_to_string(self.settings_path())
            .ok()
            .and_then(|t| serde_json::from_str(&t).ok())
            .unwrap_or_default()
    }
    fn formats(&self) -> Vec<signatures::CompiledFormat> {
        signatures::merged(Some(&self.custom_sig_path()))
    }
}

#[tauri::command]
fn get_preload_paths(state: State<AppState>) -> Vec<String> {
    state.preload.clone()
}

#[tauri::command]
fn identify_files(state: State<AppState>, paths: Vec<String>) -> Vec<FileRow> {
    let settings = state.load_settings();
    let formats = state.formats();
    let hash = settings.hash_enabled.unwrap_or(true);
    let header_len = settings.header_len.unwrap_or(fid_core::engine::DEFAULT_HEADER_LEN);
    paths
        .iter()
        .map(PathBuf::from)
        .map(|p| scan::identify_file(&p, &formats, hash, header_len))
        .collect()
}

#[tauri::command]
async fn start_scan(
    app: AppHandle,
    state: State<'_, AppState>,
    paths: Vec<String>,
    recursive: bool,
) -> Result<Vec<FileRow>, String> {
    let settings = state.load_settings();
    let cancel = Arc::new(AtomicBool::new(false));
    *state.cancel.lock().unwrap() = Some(cancel.clone());

    let formats = state.formats();
    let mut opts = ScanOptions {
        recursive,
        hash: settings.hash_enabled.unwrap_or(true),
        header_len: settings.header_len.unwrap_or(fid_core::engine::DEFAULT_HEADER_LEN),
        cancel: Some(cancel.clone()),
        on_progress: None,
    };
    let app2 = app.clone();
    let counter = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let counter2 = counter.clone();
    opts.on_progress = Some(Box::new(move |done, cur| {
        // Throttle events: every file is too chatty on huge trees.
        let last = counter2.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        if last % 8 == 0 {
            let _ = app2.emit(
                "scan-progress",
                serde_json::json!({ "done": done, "current": cur }),
            );
        }
    }));

    let roots: Vec<PathBuf> = paths.iter().map(PathBuf::from).collect();
    let rows = tauri::async_runtime::spawn_blocking(move || scan::scan(&roots, &formats, &opts))
        .await
        .map_err(|e| format!("scan task failed: {e}"))?;

    let was_cancelled = cancel.load(std::sync::atomic::Ordering::Relaxed);
    let _ = app.emit(
        "scan-done",
        serde_json::json!({ "total": rows.len(), "cancelled": was_cancelled }),
    );
    *state.cancel.lock().unwrap() = None;
    Ok(rows)
}

#[tauri::command]
fn cancel_scan(state: State<AppState>) {
    if let Some(c) = state.cancel.lock().unwrap().as_ref() {
        c.store(true, std::sync::atomic::Ordering::Relaxed);
    }
}

#[tauri::command]
fn export_file(path: String, content: String) -> Result<(), String> {
    std::fs::write(&path, content).map_err(|e| format!("cannot write {path}: {e}"))
}

#[tauri::command]
fn load_settings(state: State<AppState>) -> Settings {
    state.load_settings()
}

#[tauri::command]
fn save_settings(state: State<AppState>, settings: Settings) -> Result<(), String> {
    std::fs::create_dir_all(&state.data_dir).map_err(|e| e.to_string())?;
    let json = serde_json::to_string_pretty(&settings).map_err(|e| e.to_string())?;
    std::fs::write(state.settings_path(), json).map_err(|e| e.to_string())?;
    // Persist custom signatures in the file the engine merges from.
    if let Some(sigs) = &settings.custom_signatures {
        let json = serde_json::to_string_pretty(sigs).map_err(|e| e.to_string())?;
        std::fs::write(state.custom_sig_path(), json).map_err(|e| e.to_string())?;
    }
    Ok(())
}

#[tauri::command]
async fn vt_lookup(hash: String, api_key: String) -> vt::VtResult {
    tauri::async_runtime::spawn_blocking(move || vt::lookup_hash(&hash, &api_key))
        .await
        .unwrap_or_else(|e| vt::VtResult {
            found: false,
            malicious: 0,
            suspicious: 0,
            total_engines: 0,
            permalink: String::new(),
            error: Some(format!("lookup task failed: {e}")),
        })
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();

    // CLI passthrough: any flag-style argument → headless mode, no window.
    if args.iter().any(|a| a.starts_with('-')) {
        std::process::exit(fid_core::cli::run(&args));
    }

    let data_dir = std::env::var("APPDATA")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("."))
        .join("filetypeid");

    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .manage(AppState {
            cancel: Mutex::new(None),
            preload: args, // plain paths (Explorer context menu) pre-load the GUI
            data_dir,
        })
        .invoke_handler(tauri::generate_handler![
            get_preload_paths,
            identify_files,
            start_scan,
            cancel_scan,
            export_file,
            load_settings,
            save_settings,
            vt_lookup,
        ])
        .run(tauri::generate_context!())
        .expect("error while running FileTypeID");
}
