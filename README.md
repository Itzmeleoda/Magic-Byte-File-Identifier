# FileTypeID — Magic-Byte File Identifier

A native Windows GUI (with CLI passthrough) that tells you what a file
**actually is**, not what its extension claims. Drag in a file or a whole
folder and instantly see detected type, confidence, the matching signature
bytes, hashes — and a red flag on every file whose extension lies about its
contents.

Fully offline. No `file.exe`, no Cygwin, no DLLs. One binary.

![stack](https://img.shields.io/badge/stack-Tauri%20v2%20%C2%B7%20Rust%20%C2%B7%20React-blue)

## Features

- **Native detection engine** — reads only the first ~4 KB (configurable) of
  each file and matches it against a compiled signature table (magic bytes +
  offset + `??` wildcards, AND-combined for things like `RIFF····WAVE` vs
  `RIFF····AVI`). ~55 built-in formats: images, audio, video, archives,
  executables, documents, databases, disk images.
- **Mismatch flagging** — a `.jpg` that's really a renamed `.exe` gets a red
  row, floats to the top of the grid, and is one checkbox away ("Mismatches
  only"). This is the feature the tool exists for.
- **Compound-format awareness** — docx / xlsx / pptx / odt / ods / odp / jar /
  apk / epub are ZIP containers; FileTypeID walks the local headers and
  reports the real type (e.g. *"Word document (DOCX)"*, not *"ZIP archive"*).
- **Single-file mode** — drag one file in: MIME type, human-readable name,
  matched signature bytes (hex + offset), size, MD5/SHA-1/SHA-256.
- **Batch mode** — drag a folder: recursive scan, live progress, cancel
  button, results grid (sortable, filterable).
- **Hex detail pane** — slide-out panel showing the file header as a classic
  hex dump with the matched signature bytes highlighted.
- **Hashes everywhere** — MD5 / SHA-1 / SHA-256 streamed in 64 KB chunks,
  shown per-row, copied with one click, included in exports.
- **Export** — CSV and JSON (grid-filtered, so export what you see).
- **VirusTotal hash lookup** *(optional, off by default)* — paste your own
  free API key in Settings; looks up the SHA-256 only, **never uploads the
  file**. Free keys allow 4 lookups/minute.
- **CLI passthrough** — one binary, two personalities (see below).
- **Custom signature editor** — Settings → *Custom signatures*: add, edit,
  delete entries in a form; no hand-editing JSON. Entries with the same name
  as a built-in **override** it. (The JSON file at
  `%APPDATA%\filetypeid\custom-signatures.json` can also be edited directly.)
- **Explorer integration** — `installer\context-menu.reg` adds
  *"Identify file type"* to the right-click menu of every file and folder.

## Edge cases handled

| Case | Behavior |
|---|---|
| Zero-byte file | Reported as `Empty file`, high confidence |
| No signature match | UTF-8 text heuristic → `Plain text (UTF-8)`, else `Unknown / binary data` |
| Locked / in-use file | Becomes an error row; batch scan continues |
| Very large files | Only the header is read for ID; hashing streams in 64 KB chunks |
| Symlinks / junctions | Not followed; reported as skipped rows |
| Non-UTF-8 file names | Handled via lossy path conversion; never crashes the scan |

## CLI passthrough

Any flag-style argument switches the same `.exe` to headless mode:

```bat
filetypeid.exe --scan "C:\Users\me\Downloads" --csv report.csv
filetypeid.exe --scan "D:\photos" --json - --no-hash
filetypeid.exe --scan "C:\suspect" --mismatches-only
filetypeid.exe --scan . --header-len 8192 --signatures my-sigs.json
filetypeid.exe --help
```

Plain paths (no flags) open the GUI pre-loaded instead — that's what makes
the Explorer context menu work:

```bat
filetypeid.exe "C:\path\to\file.bin"
```

## Build from source (Windows)

Prerequisites: [Rust](https://rustup.rs), [Node.js](https://nodejs.org),
and the [WebView2 runtime](https://developer.microsoft.com/microsoft-edge/webview2/)
(already present on Windows 11 and most Windows 10 machines).

```bat
git clone <this repo>; cd filetypeid
npm install
npm run tauri dev      :: develop with hot reload
npm run tauri build    :: produce installer + portable .exe in src-tauri\target\release
```

Optional: `npx tauri icon path\to\icon.png` to generate app icons, then merge
`installer\context-menu.reg` (edit the exe path inside first).

## Project layout

```
filetypeid/
├── src/                      React + TypeScript frontend
│   ├── App.tsx               drop handling, scan orchestration, export
│   └── components/           DropZone · ResultsGrid · DetailPane (hex view) · SettingsDialog
├── src-tauri/                Tauri v2 app crate
│   ├── src/main.rs           GUI commands, progress events, CLI forwarding
│   ├── src/vt.rs             VirusTotal hash-only lookup
│   └── core/                 fid-core: standalone detection engine crate
│       ├── src/engine.rs     signature matching, text heuristic
│       ├── src/zip_detect.rs ZIP container sniffing (docx/apk/jar/odt…)
│       ├── src/scan.rs       recursive walker, cancel, CSV/JSON export
│       ├── src/hash.rs       streaming MD5/SHA-1/SHA-256
│       ├── src/cli.rs        CLI passthrough implementation
│       ├── signatures/default.json   the built-in signature table
│       └── tests/            16 integration tests (cargo test -p fid-core)
└── installer/context-menu.reg
```

## Signature JSON format

```json
{
  "formats": [
    {
      "name": "PNG image",
      "mime": "image/png",
      "extensions": ["png"],
      "category": "Image",
      "container": null,
      "signatures": [ { "offset": 0, "hex": "89504E470D0A1A0A" } ]
    }
  ]
}
```

- `hex` is case-insensitive, whitespace-tolerant; `??` = wildcard byte.
- All signatures in one entry must match (AND) — that's how `RIFF`+`WAVE`
  vs `RIFF`+`AVI` and the MP4 brand variants (`ftyp`+`isom`/`qt  `/`heic`…)
  are expressed.
- `"container": "zip"` enables inner-structure sniffing for that entry.
- More concrete bytes = higher priority; specific entries beat generic ones.
