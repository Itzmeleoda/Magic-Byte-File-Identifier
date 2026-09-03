import { useState } from "react";
import type { FileRow, VtResult } from "../types";
import { vtLookup } from "../api";
import { formatSize } from "./ResultsGrid";

interface Props {
  row: FileRow;
  vtApiKey: string | null;
  onClose: () => void;
}

export default function DetailPane({ row, vtApiKey, onClose }: Props) {
  const [vt, setVt] = useState<VtResult | null>(null);
  const [vtBusy, setVtBusy] = useState(false);
  const [copied, setCopied] = useState<string | null>(null);

  const copy = (label: string, text: string) => {
    navigator.clipboard.writeText(text);
    setCopied(label);
    setTimeout(() => setCopied(null), 1200);
  };

  const runVt = async () => {
    if (!row.hashes || !vtApiKey) return;
    setVtBusy(true);
    try {
      setVt(await vtLookup(row.hashes.sha256, vtApiKey));
    } finally {
      setVtBusy(false);
    }
  };

  return (
    <aside className="detail">
      <div className="detail-head">
        <strong>{fileName(row.path)}</strong>
        <button className="close" onClick={onClose}>✕</button>
      </div>

      <div className="detail-body">
        <dl>
          <dt>Detected</dt>
          <dd>
            {row.detected_name}
            {row.ext_match === false && <span className="flag">extension mismatch</span>}
            {row.ext_match === true && <span className="flag ok">extension matches</span>}
          </dd>
          <dt>MIME</dt>
          <dd className="mono">{row.mime || "—"}</dd>
          <dt>Size</dt>
          <dd>{formatSize(row.size)}</dd>
          {row.note && (
            <>
              <dt>Container</dt>
              <dd>{row.note}</dd>
            </>
          )}
          {row.match_hex && (
            <>
              <dt>Signature</dt>
              <dd className="mono">
                {row.match_hex}
                <span className="dim"> @ offset {row.match_offset}</span>
              </dd>
            </>
          )}
        </dl>

        {row.hashes && (
          <>
            <h4>Hashes</h4>
            {(["md5", "sha1", "sha256"] as const).map((k) => (
              <div className="hash-row" key={k}>
                <span className="hash-label">{k.toUpperCase()}</span>
                <code>{row.hashes![k]}</code>
                <button className="mini" onClick={() => copy(k, row.hashes![k])}>
                  {copied === k ? "✓" : "copy"}
                </button>
              </div>
            ))}

            {vtApiKey && (
              <div className="vt">
                <button onClick={runVt} disabled={vtBusy}>
                  {vtBusy ? "Looking up…" : "Look up SHA-256 on VirusTotal"}
                </button>
                {vt && (
                  <div className={vt.malicious > 0 ? "vt-result bad" : "vt-result"}>
                    {vt.error
                      ? vt.error
                      : `${vt.malicious}/${vt.total_engines} engines flagged this file` +
                        (vt.suspicious ? ` (+${vt.suspicious} suspicious)` : "")}
                  </div>
                )}
              </div>
            )}
          </>
        )}

        <h4>Header bytes {row.match_offset != null && "(signature highlighted)"}</h4>
        <HexView
          hex={row.header_hex}
          highlightStart={row.match_offset}
          highlightLen={row.match_len}
        />
      </div>
    </aside>
  );
}

export function HexView({
  hex,
  highlightStart,
  highlightLen,
}: {
  hex: string;
  highlightStart: number | null;
  highlightLen: number | null;
}) {
  if (!hex) return <div className="dim">(no header bytes)</div>;
  const bytes = hex.split(" ");
  const rows: JSX.Element[] = [];
  for (let i = 0; i < bytes.length; i += 16) {
    const chunk = bytes.slice(i, i + 16);
    const hexCells = chunk.map((b, j) => {
      const idx = i + j;
      const hl =
        highlightStart != null &&
        highlightLen != null &&
        idx >= highlightStart &&
        idx < highlightStart + highlightLen;
      return (
        <span key={j} className={hl ? "hx hl" : "hx"}>
          {b}
        </span>
      );
    });
    const ascii = chunk
      .map((b) => {
        const c = parseInt(b, 16);
        return c >= 32 && c < 127 ? String.fromCharCode(c) : "·";
      })
      .join("");
    rows.push(
      <div className="hexline" key={i}>
        <span className="offset">{i.toString(16).padStart(8, "0")}</span>
        <span className="hexcells">{hexCells}</span>
        <span className="ascii">{ascii}</span>
      </div>
    );
  }
  return <div className="hexview">{rows}</div>;
}

function fileName(p: string): string {
  return p.split(/[\\/]/).pop() ?? p;
}
