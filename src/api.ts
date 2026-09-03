import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import { open, save } from "@tauri-apps/plugin-dialog";
import type { FileRow, ScanProgress, Settings, VtResult } from "./types";

export const getPreloadPaths = () => invoke<string[]>("get_preload_paths");
export const identifyFiles = (paths: string[]) =>
  invoke<FileRow[]>("identify_files", { paths });
export const startScan = (paths: string[], recursive: boolean) =>
  invoke<FileRow[]>("start_scan", { paths, recursive });
export const cancelScan = () => invoke<void>("cancel_scan");
export const exportFile = (path: string, content: string) =>
  invoke<void>("export_file", { path, content });
export const loadSettings = () => invoke<Settings>("load_settings");
export const saveSettings = (settings: Settings) =>
  invoke<void>("save_settings", { settings });
export const vtLookup = (hash: string, apiKey: string) =>
  invoke<VtResult>("vt_lookup", { hash, apiKey });

export const onScanProgress = (cb: (p: ScanProgress) => void) =>
  listen<ScanProgress>("scan-progress", (e) => cb(e.payload));

export async function pickFiles(): Promise<string[]> {
  const r = await open({ multiple: true, directory: false });
  if (!r) return [];
  return Array.isArray(r) ? r : [r];
}

export async function pickFolder(): Promise<string[]> {
  const r = await open({ directory: true, multiple: false });
  return r ? [r as string] : [];
}

export async function pickSavePath(
  defaultName: string,
  ext: string
): Promise<string | null> {
  return save({
    defaultPath: defaultName,
    filters: [{ name: ext.toUpperCase(), extensions: [ext] }],
  });
}
