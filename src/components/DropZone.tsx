import type { ScanProgress } from "../types";

interface Props {
  compact: boolean;
  scanning: boolean;
  progress: ScanProgress | null;
  onBrowseFiles: () => void;
  onBrowseFolder: () => void;
  onCancel: () => void;
}

export default function DropZone({
  compact,
  scanning,
  progress,
  onBrowseFiles,
  onBrowseFolder,
  onCancel,
}: Props) {
  if (scanning) {
    return (
      <div className="dropzone scanning">
        <div className="progress-line">
          <div className="progress-bar indeterminate" />
        </div>
        <div className="progress-text">
          <span>
            Scanning… {progress?.done ?? 0} files — {truncate(progress?.current ?? "", 70)}
          </span>
          <button className="cancel" onClick={onCancel}>
            Cancel
          </button>
        </div>
      </div>
    );
  }

  if (compact) {
    return (
      <div className="dropzone compact">
        <span className="hint">Drop files or folders anywhere, or</span>
        <button onClick={onBrowseFiles}>Open files…</button>
        <button onClick={onBrowseFolder}>Open folder…</button>
      </div>
    );
  }

  return (
    <div className="dropzone hero">
      <div className="hero-inner">
        <div className="hero-icon">🔍</div>
        <h1>Drop a file or folder here</h1>
        <p>
          Identifies real file types by magic bytes — catches renamed files,
          sniffs inside ZIP-based formats (docx · apk · jar · odt), and hashes
          everything along the way. Fully offline.
        </p>
        <div className="hero-buttons">
          <button className="primary" onClick={onBrowseFiles}>
            Open file…
          </button>
          <button onClick={onBrowseFolder}>Open folder…</button>
        </div>
      </div>
    </div>
  );
}

function truncate(s: string, n: number) {
  return s.length > n ? "…" + s.slice(-n) : s;
}
