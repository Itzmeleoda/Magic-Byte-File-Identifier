import { useState } from "react";
import type { FileRow } from "../types";

interface Props {
  rows: FileRow[];
  selected: FileRow | null;
  onSelect: (r: FileRow) => void;
}

type SortKey = "path" | "extension" | "detected_name" | "size" | "confidence";

export default function ResultsGrid({ rows, selected, onSelect }: Props) {
  const [sortKey, setSortKey] = useState<SortKey>("path");
  const [asc, setAsc] = useState(true);

  const sorted = [...rows].sort((a, b) => {
    // Mismatches always float to the top regardless of sort column.
    const am = a.ext_match === false ? 0 : 1;
    const bm = b.ext_match === false ? 0 : 1;
    if (am !== bm) return am - bm;
    const av = a[sortKey];
    const bv = b[sortKey];
    const cmp =
      typeof av === "number" && typeof bv === "number"
        ? av - bv
        : String(av).localeCompare(String(bv));
    return asc ? cmp : -cmp;
  });

  const header = (key: SortKey, label: string) => (
    <th
      onClick={() => {
        if (sortKey === key) setAsc(!asc);
        else {
          setSortKey(key);
          setAsc(true);
        }
      }}
    >
      {label} {sortKey === key ? (asc ? "▲" : "▼") : ""}
    </th>
  );

  return (
    <div className="grid-wrap">
      <table className="grid">
        <thead>
          <tr>
            <th style={{ width: 26 }}></th>
            {header("path", "Path")}
            {header("extension", "Ext")}
            {header("detected_name", "Detected type")}
            {header("size", "Size")}
            {header("confidence", "Confidence")}
          </tr>
        </thead>
        <tbody>
          {sorted.map((r) => (
            <tr
              key={r.path}
              className={rowClass(r, selected)}
              onClick={() => onSelect(r)}
            >
              <td>{r.ext_match === false ? "⚠" : r.error ? "✖" : ""}</td>
              <td className="mono path" title={r.path}>
                {r.path}
              </td>
              <td className="mono">.{r.extension || "—"}</td>
              <td>
                {r.error ? <span className="err">{r.error}</span> : r.detected_name}
                {r.note && <span className="note" title={r.note}> ⓘ</span>}
              </td>
              <td className="num">{formatSize(r.size)}</td>
              <td>
                <span className={`badge ${r.confidence}`}>{r.confidence}</span>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
      {sorted.length === 0 && <div className="empty-grid">No rows match the current filter.</div>}
    </div>
  );
}

function rowClass(r: FileRow, selected: FileRow | null): string {
  const c: string[] = [];
  if (r.ext_match === false) c.push("mismatch");
  if (r.error) c.push("error-row");
  if (selected?.path === r.path) c.push("selected");
  return c.join(" ");
}

export function formatSize(n: number): string {
  if (n < 1024) return `${n} B`;
  if (n < 1024 ** 2) return `${(n / 1024).toFixed(1)} KB`;
  if (n < 1024 ** 3) return `${(n / 1024 ** 2).toFixed(1)} MB`;
  return `${(n / 1024 ** 3).toFixed(2)} GB`;
}
