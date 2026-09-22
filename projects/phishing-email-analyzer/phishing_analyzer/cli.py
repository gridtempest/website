"""Command-line interface: python -m phishing_analyzer.cli <file.eml> [file2.eml ...]"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .analyzer import analyze_email

RISK_COLOR = {"Low": "\033[32m", "Medium": "\033[33m", "High": "\033[31m"}
RESET = "\033[0m"


def _format_text_report(path: Path, result) -> str:
    color = RISK_COLOR.get(result.risk_level, "")
    lines = [
        f"=== {path.name} ===",
        f"Risk: {color}{result.risk_level}{RESET}  (score: {result.score})",
    ]
    if not result.findings:
        lines.append("  No indicators found.")
    else:
        for finding in sorted(result.findings, key=lambda f: -f.weight):
            lines.append(f"  [+{finding.weight:>2}] ({finding.category}) {finding.description}")
    return "\n".join(lines)


def _to_json(path: Path, result) -> dict:
    return {
        "file": path.name,
        "score": result.score,
        "risk_level": result.risk_level,
        "findings": [
            {"category": f.category, "description": f.description, "weight": f.weight}
            for f in result.findings
        ],
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Static phishing-indicator analysis for .eml files")
    parser.add_argument("files", nargs="+", type=Path, help="One or more .eml files to analyze")
    parser.add_argument("--json", action="store_true", help="Output JSON instead of a text report")
    args = parser.parse_args(argv)

    results = []
    for path in args.files:
        raw = path.read_bytes()
        result = analyze_email(raw)
        results.append((path, result))

    if args.json:
        print(json.dumps([_to_json(p, r) for p, r in results], indent=2))
    else:
        for path, result in results:
            print(_format_text_report(path, result))
            print()

    return 0


if __name__ == "__main__":
    sys.exit(main())
