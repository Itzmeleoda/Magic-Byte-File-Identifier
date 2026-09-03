import { useCallback, useEffect, useRef, useState } from "react";
import { getCurrentWebview } from "@tauri-apps/api/webview";
import * as api from "./api";
import type { FileRow, ScanProgress, Settings } from "./types";
import DropZone from "./components/DropZone";
import ResultsGrid from "./components/ResultsGrid";
import DetailPane from "./components/DetailPane";
import SettingsDialog from "./components/SettingsDialog";

export default function App() {
  const [rows, setRows] = useState<FileRow[]>([]);
  const [selected, setSelected] = useState<FileRow | null>(null);
  const [scanning, setScanning] = useState(false);
  const [progress, setProgress] = useState<ScanProgress | null>(null);
  const [settingsOpen, setSettingsOpen] = useState(false);
  const [settings, setSettings] = useState<Settings | null>(null);
  const [mismatchesOnly, setMismatchesOnly] = useState(false);
  const [filter, setFilter] = useState("");
  const unlistenRef = useRef<(() => void) | null>(null);

  useEffect(() => {
    api.loadSettings().then(setSettings).catch(() => {});
    api.onScanProgress(setProgress).then((un) => (unlistenRef.current = un));

    // Native drag & drop gives real filesystem paths (browser File objects don't).
    let unDrop: (() => void) | undefined;
    getCurrentWebview()
      .onDragDropEvent((event) => {
        if (event.payload.type === "drop") {
          const paths = event.payload.paths;
          if (paths.length) void addPaths(paths);
        }
      })
      .then((un) => (unDrop = un));

    // Explorer "Identify file type" launches us with plain path arguments.
    api.getPreloadPaths().then((paths) => {
      if (paths.length) void addPaths(paths);
    });

    return () => {
      unlistenRef.current?.();
      unDrop?.();
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const addPaths = useCallback(
    async (paths: string[]) => {
      if (scanning) return;
      setScanning(true);
      setProgress({ done: 0, current: "starting…" });
      try {
        // A single existing file → instant single-file mode; anything else
        // (folders, multiple paths) → batch scan with progress.
        const isSingleFile =
          paths.length === 1 && !/\\$/.test(paths[0]) && paths[0].includes(".");
        const result = isSingleFile
          ? await api.identifyFiles(paths)
          : await api.startScan(paths, true);
        setRows((prev) => mergeRows(prev, result));
        if (result.length === 1) setSelected(result[0]);
      } catch (e) {
        alert(`Scan failed: ${e}`);
      } finally {
        setScanning(false);
        setProgress(null);
      }
    },
    [scanning]
  );

  const onCancel = () => void api.cancelScan();

  const doExport = async (format: "csv" | "json") => {
    const visible = visibleRows(rows, mismatchesOnly, filter);
    if (!visible.length) return;
    const path = await api.pickSavePath(`filetypeid-results.${format}`, format);
    if (!path) return;
    const content = format === "csv" ? rowsToCsv(visible) : JSON.stringify(visible, null, 2);
    await api.exportFile(path, content);
  };

  const mismatchCount = rows.filter((r) => r.ext_match === false).length;
  const visible = visibleRows(rows, mismatchesOnly, filter);

  return (
    <div className="app">
      <header className={rows.length ? "topbar slim" : "topbar"}>
        <DropZone
          compact={rows.length > 0}
          scanning={scanning}
          progress={progress}
          onBrowseFiles={async () => addPaths(await api.pickFiles())}
          onBrowseFolder={async () => addPaths(await api.pickFolder())}
          onCancel={onCancel}
        />
      </header>

      {rows.length > 0 && (
        <>
          <div className="toolbar">
            <span className="stat">
              {rows.length} file{rows.length !== 1 && "s"}
            </span>
            <span className={mismatchCount ? "stat bad" : "stat ok"}>
              {mismatchCount} mismatch{mismatchCount !== 1 && "es"}
            </span>
            <label className="check">
              <input
                type="checkbox"
                checked={mismatchesOnly}
                onChange={(e) => setMismatchesOnly(e.target.checked)}
              />
              Mismatches only
            </label>
            <input
              className="search"
              placeholder="Filter by path or type…"
              value={filter}
              onChange={(e) => setFilter(e.target.value)}
            />
            <button onClick={() => doExport("csv")}>Export CSV</button>
            <button onClick={() => doExport("json")}>Export JSON</button>
            <button onClick={() => { setRows([]); setSelected(null); }}>Clear</button>
            <button className="gear" title="Settings" onClick={() => setSettingsOpen(true)}>
              ⚙
            </button>
          </div>

          <div className="content">
            <ResultsGrid rows={visible} selected={selected} onSelect={setSelected} />
            {selected && (
              <DetailPane
                row={selected}
                vtApiKey={settings?.vt_api_key ?? null}
                onClose={() => setSelected(null)}
              />
            )}
          </div>
        </>
      )}

      {rows.length === 0 && !scanning && (
        <button className="gear floating" title="Settings" onClick={() => setSettingsOpen(true)}>
          ⚙
        </button>
      )}

      {settingsOpen && settings && (
        <SettingsDialog
          settings={settings}
          onSave={async (s) => {
            await api.saveSettings(s);
            setSettings(s);
            setSettingsOpen(false);
          }}
          onClose={() => setSettingsOpen(false)}
        />
      )}
    </div>
  );
}

function mergeRows(prev: FileRow[], next: FileRow[]): FileRow[] {
  const byPath = new Map(prev.map((r) => [r.path, r]));
  for (const r of next) byPath.set(r.path, r);
  return [...byPath.values()];
}

function visibleRows(rows: FileRow[], mismatchesOnly: boolean, filter: string): FileRow[] {
  const q = filter.toLowerCase();
  return rows.filter((r) => {
    if (mismatchesOnly && r.ext_match !== false) return false;
    if (q && !r.path.toLowerCase().includes(q) && !r.detected_name.toLowerCase().includes(q))
      return false;
    return true;
  });
}

function rowsToCsv(rows: FileRow[]): string {
  const esc = (s: string) =>
    /[",\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
  const head = "path,size,extension,detected_type,mime,category,confidence,ext_match,md5,sha1,sha256,note,error\n";
  const body = rows
    .map((r) =>
      [
        esc(r.path),
        r.size,
        esc(r.extension),
        esc(r.detected_name),
        esc(r.mime),
        esc(r.category),
        r.confidence,
        r.ext_match === null ? "" : r.ext_match ? "match" : "MISMATCH",
        r.hashes?.md5 ?? "",
        r.hashes?.sha1 ?? "",
        r.hashes?.sha256 ?? "",
        esc(r.note ?? ""),
        esc(r.error ?? ""),
      ].join(",")
    )
    .join("\n");
  return head + body + "\n";
}
