# Larvix — Static Worm Scanner

Early detection, total protection. Larvix is a lightweight static analysis tool that scans binaries and arbitrary files for worm/malware indicators without running them.

It extracts strings, detects embedded URLs/IPs, computes entropy (packing/obfuscation hints), inspects PE (Windows executables) imports, and applies heuristic scoring to produce a human-readable verdict and a structured report.

Developed and Customized by: Janaranshini P
Project: Larvix – Static Worm Malware Scanner


## Key features

- Fast static scan — no execution/sandbox required
- Hashing: MD5, SHA1, SHA256
- String extraction (ASCII + UTF‑16-LE)
- Indicators of compromise:
  - Embedded URLs and IPv4 addresses
  - Autorun/removable-media patterns
  - Common packer signatures (e.g., UPX)
  - Suspicious shell/command tokens (cmd.exe, powershell, etc.)
- Entropy analysis (Shannon entropy, including per‑section for PE files)
- PE inspection via `pefile` (imports, basic metadata)
- Heuristic scoring with configurable weights and thresholds
- Clear verdicts: CLEAN, SUSPICIOUS, MALICIOUS
- Multiple export formats: JSON, TXT, PDF, DOCX (exported to `export_files/`)
- CLI and interactive modes


## How it works (at a glance)

1. Read file bytes and compute hashes (MD5/SHA1/SHA256)
2. Extract strings (ASCII + UTF‑16-LE)
3. Detect URLs and IPv4s from strings
4. Compute global Shannon entropy (packing/obfuscation hint)
5. If the file is a PE (Windows EXE/DLL), parse imports via `pefile`
6. Apply heuristic scoring (configurable in `config.yaml`):
   - URLs/IPs, suspicious PE imports, entropy thresholds, autorun/packer tokens, etc.
7. Map score to verdict using thresholds (CLEAN/SUSPICIOUS/MALICIOUS)
8. Print a summary to the console and optionally export a full report


## Requirements

- Python 3.8+
- Required (from `requirements.txt`):
  - PyYAML (config file support)
  - pefile (PE inspection)
  - python-magic, yara-python (present in requirements for future/optional features; not required for basic scan)
- Optional for exports:
  - PDF export: `reportlab`
  - DOCX export: `python-docx`

Tips (Linux): ReportLab may require system packages (e.g., libfreetype, libjpeg). Install via your distro’s package manager if needed.


## Installation

```bash
# 1) (Recommended) create a virtual environment
python3 -m venv .venv
source .venv/bin/activate

# 2) Install dependencies
pip install -r requirements.txt

# 3) To enable PDF/DOCX exports
pip install reportlab python-docx
```


## Quick start

Run a one-off scan and print a console summary:

```bash
python3 scanner.py path/to/file.bin
```

Export a structured JSON report (saved under `export_files/` when you give just a name):

```bash
python3 scanner.py path/to/file.bin --json report.json
```

Export in a specific format by choosing the extension: `.json`, `.txt`, `.pdf`, or `.docx`.

```bash
python3 scanner.py path/to/file.bin --export full.txt
python3 scanner.py path/to/file.bin --export report.pdf   # needs reportlab
python3 scanner.py path/to/file.bin --export report.docx  # needs python-docx
```

Interactive mode (prompts for a file and optional export):

```bash
python3 scanner.py --interactive
```

Use a custom config file:

```bash
python3 scanner.py path/to/file.bin --config config.yaml
```

Notes:
- If you specify `--json` with a bare filename (no path), it’s written to `export_files/<name>.json`.
- A deprecated alias `--intractive` is accepted for `--interactive` and prints a notice.


## Configuration

Larvix reads weights/thresholds from `config.yaml` if present (or when passed via `--config`). Missing keys fall back to sensible defaults.

Example (`config.yaml`):

```yaml
scoring:
  url_score: 30
  ip_score: 20
  suspicious_api_factor: 8   # per suspicious import (capped)
  high_entropy_threshold: 7.5
  high_entropy_score: 20
  elevated_entropy_threshold: 6.5
  elevated_entropy_score: 8
  autorun_score: 15
  packer_score: 10
  small_exe_bonus: 5
  suspicious_token_score: 10
thresholds:
  malicious: 60
  suspicious: 30
```

Verdict mapping:
- score >= `thresholds.malicious` → MALICIOUS (likely worm/malware)
- score >= `thresholds.suspicious` → SUSPICIOUS
- otherwise → CLEAN


## Report fields

All export formats contain the same core data:

- timestamp (UTC ISO‑8601)
- path, filesize (bytes)
- md5, sha1, sha256
- entropy (global Shannon entropy)
- num_strings
- urls: list of URLs detected in strings
- ips: list of IPv4 addresses detected in strings
- pe_info (for Windows PE files):
  - is_pe: bool
  - imports: list of "dll:function"
  - suspicious_apis: matched subset of imports
  - sections_entropy: map of section name → entropy
- score (0–100)
- reasons: list of human-readable rationales for the score
- verdict: CLEAN | SUSPICIOUS | MALICIOUS

Example (truncated):

```json
{
  "timestamp": "2025-09-18T12:57:37.465Z",
  "path": "/abs/path/sample.bin",
  "filesize": 63,
  "md5": "...",
  "sha1": "...",
  "sha256": "...",
  "entropy": 4.4552,
  "num_strings": 1,
  "urls": ["http://example.com"],
  "ips": ["192.168.1.100"],
  "pe_info": { "is_pe": false, "imports": [], "suspicious_apis": [], "sections_entropy": {} },
  "score": 55,
  "reasons": [
    "Embedded URLs found (1)",
    "Embedded IPs found (1)",
    "Small executable with network indicators (suspicious)"
  ],
  "verdict": "SUSPICIOUS"
}
```


## Exporting reports

You can write reports in multiple formats. The output path can be absolute, or just a filename — in the latter case, the file is written under `export_files/`.

- JSON: `--json <path|name.json>` or `--export <path|name.json>`
- TXT: `--export <path|name.txt>`
- PDF: `--export <path|name.pdf>` (requires `reportlab`)
- DOCX: `--export <path|name.docx>` (requires `python-docx`)


## Project layout

```
scanner.py                # CLI / interactive entry point and main flow
config.yaml               # Default scoring/thresholds (optional)
core/
  strings.py              # ASCII + UTF-16 string extraction
  entropy.py              # Shannon entropy
  indicators.py           # URL/IP/autorun/packer/suspicious token detectors
  pe_inspector.py         # PE parsing via pefile (imports, section entropy)
  heuristics.py           # Scoring + verdict mapping
reports/
  __init__.py             # Pretty console printer + exporter re-exports
  exporters.py            # JSON/TXT/PDF/DOCX exporters
utils/
  hashes.py               # Streaming hash helpers (MD5/SHA1/SHA256)
export_files/             # Default export destination (auto-created)
sample.bin                # Tiny sample file for trying the scanner
sample_report.json        # Example report output
```

Note: A legacy top-level `reports.py` also exists; the scanner uses the `reports/` package (`reports.__init__` and `reports.exporters`).


## Troubleshooting

- "PyYAML not installed; cannot load config" warning
  - Install PyYAML: `pip install PyYAML` (or avoid `--config` to use defaults).
- PDF/DOCX export fails
  - Install extras: `pip install reportlab python-docx` (system libs may be needed for ReportLab on Linux).
- PE features missing (no imports shown)
  - Ensure `pefile` is installed; non-PE files will show `is_pe: false` (expected).
- Permission errors when exporting
  - The tool writes to `export_files/` by default and will create it if needed. Verify write permissions to the project folder or use an absolute output path you can write to.
- Large files / memory
  - The scanner reads entire file contents. For extremely large files, consider scanning on a machine with adequate memory.


## Security and privacy notes

- This is a static scanner; it does not execute samples. Nevertheless, handle suspected malware with care (scan offline or inside a disposable VM/container).
- Reports may include embedded indicators (URLs/IPs) extracted from files; treat outputs as potentially sensitive.


## Roadmap ideas

- Optional YARA rule scanning (dependency already listed)
- MIME/type detection via `python-magic`
- Additional file format parsers and deeper PE metadata


## Credits

Customized and maintained by Janaranshini P

Original project and source code:
Ratheesh Sekar

Project: Larvix – Static Worm Malware Scanner
