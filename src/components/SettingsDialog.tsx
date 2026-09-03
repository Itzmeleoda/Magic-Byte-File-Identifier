import { useState } from "react";
import type { FormatEntry, Settings } from "../types";

interface Props {
  settings: Settings;
  onSave: (s: Settings) => void;
  onClose: () => void;
}

const EMPTY_ENTRY: FormatEntry = {
  name: "",
  mime: "application/octet-stream",
  extensions: [],
  category: "Other",
  container: null,
  signatures: [{ offset: 0, hex: "" }],
};

export default function SettingsDialog({ settings, onSave, onClose }: Props) {
  const [s, setS] = useState<Settings>({
    ...settings,
    header_len: settings.header_len ?? 4096,
    hash_enabled: settings.hash_enabled ?? true,
  });
  const [editing, setEditing] = useState<FormatEntry | null>(null);
  const [editIndex, setEditIndex] = useState<number | null>(null);
  const [sigError, setSigError] = useState<string | null>(null);

  const formats = s.custom_signatures?.formats ?? [];

  const setFormats = (f: FormatEntry[]) =>
    setS({ ...s, custom_signatures: { formats: f } });

  const startEdit = (i: number | null) => {
    setEditIndex(i);
    setEditing(i === null ? { ...EMPTY_ENTRY } : { ...formats[i] });
    setSigError(null);
  };

  const commitEdit = () => {
    if (!editing) return;
    if (!editing.name.trim()) return setSigError("Name is required.");
    for (const sig of editing.signatures) {
      const cleaned = sig.hex.replace(/\s/g, "");
      if (!cleaned.length || cleaned.length % 2 !== 0 || !/^([0-9A-Fa-f]{2}|\?\?)+$/.test(cleaned))
        return setSigError(`Invalid hex signature: "${sig.hex}" (use ?? for wildcards)`);
    }
    const next = [...formats];
    if (editIndex === null) next.push(editing);
    else next[editIndex] = editing;
    setFormats(next);
    setEditing(null);
  };

  return (
    <div className="modal-backdrop" onClick={onClose}>
      <div className="modal" onClick={(e) => e.stopPropagation()}>
        <h2>Settings</h2>

        <div className="field">
          <label>Header bytes read per file</label>
          <input
            type="number"
            min={256}
            max={1048576}
            value={s.header_len ?? 4096}
            onChange={(e) => setS({ ...s, header_len: Number(e.target.value) })}
          />
          <span className="dim">Large files are never read in full — only this many bytes.</span>
        </div>

        <div className="field">
          <label className="check">
            <input
              type="checkbox"
              checked={s.hash_enabled ?? true}
              onChange={(e) => setS({ ...s, hash_enabled: e.target.checked })}
            />
            Compute MD5 / SHA-1 / SHA-256 (disable for faster scans of huge trees)
          </label>
        </div>

        <div className="field">
          <label>VirusTotal API key (optional — hash lookup only, files are never uploaded)</label>
          <input
            type="password"
            placeholder="leave empty to disable"
            value={s.vt_api_key ?? ""}
            onChange={(e) => setS({ ...s, vt_api_key: e.target.value || null })}
          />
        </div>

        <h3>Custom signatures</h3>
        <p className="dim">
          These merge with the built-in table; an entry with the same name replaces a built-in.
        </p>
        <ul className="sig-list">
          {formats.map((f, i) => (
            <li key={i}>
              <span>
                <strong>{f.name}</strong> <span className="dim">{f.mime}</span>
              </span>
              <span>
                <button className="mini" onClick={() => startEdit(i)}>edit</button>
                <button
                  className="mini"
                  onClick={() => setFormats(formats.filter((_, j) => j !== i))}
                >
                  delete
                </button>
              </span>
            </li>
          ))}
          {formats.length === 0 && <li className="dim">None yet.</li>}
        </ul>
        <button className="mini" onClick={() => startEdit(null)}>+ Add signature</button>

        {editing && (
          <div className="sig-editor">
            <h4>{editIndex === null ? "New signature" : `Edit "${editing.name}"`}</h4>
            <div className="sig-grid">
              <label>Name</label>
              <input
                value={editing.name}
                onChange={(e) => setEditing({ ...editing, name: e.target.value })}
              />
              <label>MIME type</label>
              <input
                value={editing.mime}
                onChange={(e) => setEditing({ ...editing, mime: e.target.value })}
              />
              <label>Extensions</label>
              <input
                placeholder="png, apng"
                value={editing.extensions.join(", ")}
                onChange={(e) =>
                  setEditing({
                    ...editing,
                    extensions: e.target.value
                      .split(",")
                      .map((x) => x.trim().toLowerCase())
                      .filter(Boolean),
                  })
                }
              />
              <label>Category</label>
              <input
                value={editing.category}
                onChange={(e) => setEditing({ ...editing, category: e.target.value })}
              />
              <label>Offset</label>
              <input
                type="number"
                min={0}
                value={editing.signatures[0].offset}
                onChange={(e) =>
                  setEditing({
                    ...editing,
                    signatures: [{ ...editing.signatures[0], offset: Number(e.target.value) }],
                  })
                }
              />
              <label>Magic bytes (hex)</label>
              <input
                className="mono"
                placeholder="89 50 4E 47  (?? = wildcard byte)"
                value={editing.signatures[0].hex}
                onChange={(e) =>
                  setEditing({
                    ...editing,
                    signatures: [{ ...editing.signatures[0], hex: e.target.value }],
                  })
                }
              />
            </div>
            {sigError && <div className="err">{sigError}</div>}
            <div className="sig-editor-actions">
              <button className="primary" onClick={commitEdit}>Save entry</button>
              <button onClick={() => setEditing(null)}>Cancel</button>
            </div>
          </div>
        )}

        <div className="modal-actions">
          <button className="primary" onClick={() => onSave(s)}>Save</button>
          <button onClick={onClose}>Close</button>
        </div>
      </div>
    </div>
  );
}
