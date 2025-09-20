"""Reporting utilities package.

Exposes convenience functions for exporting reports in multiple formats
and provides a simple pretty printer for console output.
"""

from typing import Dict, Any

# Re-export exporter helpers so callers can `from reports import json_report` etc.
from .exporters import json_report, txt_report, pdf_report, docx_report  # noqa: F401


def print_report(report: Dict[str, Any]) -> None:
	"""Pretty-print a single analysis report to stdout.

	Keeps output stable for both interactive and CLI usage. This avoids
	duplication of formatting logic scattered across the code base.
	"""
	lines = [
		"================ Larvix Report ================",
		f"File: {report.get('path')}",
		f"Size: {report.get('filesize')} bytes",
		f"MD5: {report.get('md5')}",
		f"SHA1: {report.get('sha1')}",
		f"SHA256: {report.get('sha256')}",
		f"Entropy: {report.get('entropy')}",
		f"Strings found: {report.get('num_strings')}",
		f"Embedded URLs: {report.get('urls')}",
		f"Embedded IPs: {report.get('ips')}",
		f"Score: {report.get('score')}",
		f"Verdict: {report.get('verdict')}",
		"Reasons: " + (", ".join(report.get('reasons') or []) if report.get('reasons') else "None"),
		f"Report time: {report.get('timestamp')}",
		"================================================\n",
	]
	print("\n".join(lines))

