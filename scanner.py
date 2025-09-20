#!/usr/bin/env python3
"""
Larvix - Static Worm Scanner
Supports:
- CLI scan: python3 scanner.py file.bin [--json report.json]
- Interactive mode: python3 scanner.py --interactive
"""

from __future__ import annotations
import argparse
import os
from datetime import datetime
from typing import Any, Dict, Optional
from reports.exporters import json_report, txt_report, pdf_report, docx_report
import logging

try:
    import yaml  # for config
except ImportError:
    yaml = None

# Core imports (make sure you implemented these modules)
from core.strings import extract_strings_from_bytes
from core.entropy import shannon_entropy
from core.pe_inspector import inspect_pe
from core.indicators import detect_urls_ips, has_autorun_patterns, packer_hits, suspicious_tokens_count
from core.heuristics import score_indicators, human_verdict
from utils.hashes import compute_hashes
from reports import print_report

# Logging setup
logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
logger = logging.getLogger("Larvix")

# Banner
LARVIX_BANNER = r"""
 █████                                        ███             
░░███                                        ░░░              
 ░███         ██████   ████████  █████ █████ ████  █████ █████
 ░███        ░░░░░███ ░░███░░███░░███ ░░███ ░░███ ░░███ ░░███ 
 ░███         ███████  ░███ ░░░  ░███  ░███  ░███  ░░░█████░  
 ░███      █ ███░░███  ░███      ░░███ ███   ░███   ███░░░███ 
 ███████████░░████████ █████      ░░█████    █████ █████ █████
░░░░░░░░░░░  ░░░░░░░░ ░░░░░        ░░░░░    ░░░░░ ░░░░░ ░░░░░ 
                                                              
                                                              
"""

# Default config
DEFAULT_CONFIG_PATH = os.path.join(os.path.dirname(__file__), "config.yaml")
DEFAULT_CONFIG: Dict[str, Any] = {
    "scoring": {
        "url_score": 30,
        "ip_score": 20,
        "suspicious_api_factor": 8,
        "high_entropy_threshold": 7.5,
        "high_entropy_score": 20,
        "elevated_entropy_threshold": 6.5,
        "elevated_entropy_score": 8,
        "autorun_score": 15,
        "packer_score": 10,
        "small_exe_bonus": 5,
        "suspicious_token_score": 10,
    },
    "thresholds": {
        "malicious": 60,
        "suspicious": 30
    }
}

# Export directory
EXPORT_DIR_NAME = "export_files"

def get_export_dir() -> str:
    """Return absolute path to export directory, creating it if needed."""
    base = os.path.abspath(os.path.dirname(__file__))
    path = os.path.join(base, EXPORT_DIR_NAME)
    if not os.path.isdir(path):
        try:
            os.makedirs(path, exist_ok=True)
        except OSError as e:
            logger.error("Failed to create export directory %s: %s", path, e)
    return path

SUPPORTED_EXPORT_EXTS = {".json", ".txt", ".pdf", ".docx"}

def export_report_auto(report: Dict[str, Any], filename: str) -> str:
    """Export report choosing the correct exporter based on file extension.

    If filename is bare (no path), it is stored under EXPORT_DIR_NAME.
    Returns absolute output path.
    """
    root, ext = os.path.splitext(filename)
    if ext.lower() not in SUPPORTED_EXPORT_EXTS:
        raise ValueError(f"Unsupported export extension '{ext}'. Supported: {', '.join(sorted(SUPPORTED_EXPORT_EXTS))}")
    # If user gave just a name, put it inside export dir.
    if os.path.basename(filename) == filename:
        filename = os.path.join(get_export_dir(), filename)
    ext_l = ext.lower()
    if ext_l == ".json":
        json_report(report, filename)
    elif ext_l == ".txt":
        txt_report(report, filename)
    elif ext_l == ".pdf":
        pdf_report(report, filename)
    elif ext_l == ".docx":
        docx_report(report, filename)
    return os.path.abspath(filename)


def load_config(path: Optional[str]) -> Dict[str, Any]:
    """Load YAML config if available.

    Behavior:
    - If user passed --config (path not None) we attempt to load that path.
    - If user did not specify a path we silently try default config.yaml if it exists.
    - Missing PyYAML only logged if user explicitly requested a config file.
    """
    cfg = DEFAULT_CONFIG.copy()
    user_explicit = path is not None
    if path is None:
        # Auto-discover default only silently
        path = DEFAULT_CONFIG_PATH if os.path.isfile(DEFAULT_CONFIG_PATH) else None
    if not path:
        return cfg
    if not os.path.isfile(path):
        if user_explicit:
            logger.warning("Config file not found: %s — using defaults", path)
        return cfg
    if yaml is None:
        if user_explicit:
            logger.warning("PyYAML not installed; cannot load config %s — using defaults", path)
        return cfg
    try:
        with open(path, "r") as fh:
            user_cfg = yaml.safe_load(fh) or {}
            if "scoring" in user_cfg:
                merged_scoring = cfg["scoring"].copy()
                merged_scoring.update(user_cfg.get("scoring") or {})
                cfg["scoring"] = merged_scoring
            if "thresholds" in user_cfg:
                merged_thr = cfg["thresholds"].copy()
                merged_thr.update(user_cfg.get("thresholds") or {})
                cfg["thresholds"] = merged_thr
            return cfg
    except Exception as e:
        if user_explicit:
            logger.error("Failed to parse config file %s: %s — using defaults", path, e)
        return cfg


def read_file_bytes(path: str, max_size: Optional[int] = None) -> bytes:
    with open(path, "rb") as f:
        if max_size:
            return f.read(max_size)
        return f.read()


def analyze_file(path: str, config: Dict[str, Any], max_bytes: Optional[int] = None) -> Dict[str, Any]:
    if not os.path.isfile(path):
        raise FileNotFoundError(path)
    filesize = os.path.getsize(path)
    md5, sha1, sha256 = compute_hashes(path)
    data = read_file_bytes(path, max_size=max_bytes)
    strings = extract_strings_from_bytes(data, min_len=4)
    urls, ips = detect_urls_ips(strings)
    entropy = shannon_entropy(data)
    pe_info = inspect_pe(path)
    autorun_found = has_autorun_patterns(strings)
    packers_count = packer_hits(strings)
    token_count = suspicious_tokens_count(strings)
    score, reasons = score_indicators(
        strings=strings,
        urls=urls,
        ips=ips,
        pe_info=pe_info,
        entropy=entropy,
        filesize=filesize,
        autorun_found=autorun_found,
        packer_hits_count=packers_count,
        suspicious_token_count=token_count,
        config=config
    )
    verdict = human_verdict(score, config=config)
    report = {
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "path": os.path.abspath(path),
        "filesize": filesize,
        "md5": md5,
        "sha1": sha1,
        "sha256": sha256,
        "entropy": round(float(entropy), 4),
        "num_strings": len(strings),
        "urls": urls,
        "ips": ips,
        "pe_info": pe_info,
        "score": score,
        "reasons": reasons,
        "verdict": verdict,
    }
    return report


def parse_args(argv: Optional[list] = None):
    p = argparse.ArgumentParser(description="Larvix - Static Worm/Malware Scanner")
    p.add_argument("file", nargs="?", help="File path to analyze (CLI mode)")
    p.add_argument("--config", "-c", help="Path to YAML config")
    # Accept common misspelling --intractive as an alias (deprecated)
    p.add_argument("--interactive", "--intractive", "-i", dest="interactive", action="store_true", help="Run interactive mode")
    p.add_argument("--json", help="Write JSON report to the specified file (or bare name -> stored in export_files/)")
    p.add_argument("--export", help="Write report to specified file (extension: .json/.txt/.pdf/.docx)")
    if argv and "--intractive" in argv:
        print("[Notice] '--intractive' is deprecated; use '--interactive' instead.")
    return p.parse_args(argv)


def interactive_mode(config: Dict[str, Any]) -> None:
    try:
        path = input("Enter the full path to the file to scan: ").strip()
        print("\n")
        if not path:
            print("No file path provided. Exiting.")
            return
        report = analyze_file(path, config=config)
        print_report(report)

        export = input("Do you want to export the report? (y/n): ").strip().lower()
        if export == "y":
            out_file = input("Enter output file name or path (.json/.txt/.pdf/.docx) [default: report.json]: ").strip()
            if not out_file:
                out_file = "report.json"
            try:
                final_path = export_report_auto(report, out_file)
                print(f"Export completed: {final_path}")
            except Exception as e:
                print(f"Export failed: {e}")
        print("Scan complete. Exiting.")
    except KeyboardInterrupt:  # Graceful Ctrl+C in interactive mode
        print("\n[Interrupted] Exiting interactive mode.")
    except Exception as e:
        print(f"Error: {e}")


def main(argv: Optional[list] = None) -> None:
    try:
        print(LARVIX_BANNER)
        print("        Larvix - Static Worm Scanner")
        print("        Early detection, total protection\n")
        print("        Authored by: Ratheesh Sekar\n")

        args = parse_args(argv)
        config = load_config(args.config)

        if args.interactive:
            interactive_mode(config)
            return

        # CLI mode
        if not args.file:
            print("Error: No file provided. Use --interactive or provide a file path.")
            return

        report = analyze_file(args.file, config=config)
        print_report(report)
        if args.json:
            # Support bare filename (no directory)
            json_target = args.json
            if os.path.basename(json_target) == json_target:
                if not json_target.lower().endswith('.json'):
                    json_target += '.json'
                json_target = os.path.join(get_export_dir(), json_target)
            json_report(report, json_target)
            print(f"JSON report written to: {os.path.abspath(json_target)}")
        if args.export:
            out_path = export_report_auto(report, args.export)
            print(f"Report exported to: {out_path}")
    except KeyboardInterrupt:
        print("\n[Interrupted] Scan aborted by user.")
    except Exception as e:
        print(f"Error scanning file: {e}")


if __name__ == "__main__":
    main()
