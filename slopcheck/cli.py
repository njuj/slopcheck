"""Command-line entry point. Exit codes: 0 nothing at/above --fail-on · 1 findings at/above it · 2 error."""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from dataclasses import asdict
from pathlib import Path

from . import __version__
from .model import SEVERITIES, rank
from .scanner import Report, scan

COLORS = {"critical": "1;31", "high": "31", "medium": "33", "low": "36"}
UNICODE = {"critical": "✖", "high": "✖", "medium": "⚠", "low": "•", "sep": "·", "fix": "└", "arrow": "→"}
ASCII = {"critical": "X", "high": "x", "medium": "!", "low": "-", "sep": "|", "fix": "`-", "arrow": "->"}
SECTIONS = (("dependency", "DEPENDENCIES"), ("secret", "SECRETS"), ("code", "CODE"), ("config", "CONFIG"))


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        prog="slopcheck",
        description="Catch hallucinated packages, typosquats, leaked secrets and the classic security slips of "
                    "AI-written code.")
    ap.add_argument("path", nargs="?", default=".", type=Path, help="project directory (default: .)")
    ap.add_argument("--offline", action="store_true", help="skip registry lookups; name and code checks only")
    ap.add_argument("--fail-on", choices=SEVERITIES, default="high",
                    help="lowest severity that makes the exit code 1 (default: high)")
    ap.add_argument("--exclude", action="append", default=[], metavar="GLOB",
                    help="skip paths matching this glob, relative to PATH (repeatable)")
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    ap.add_argument("--no-color", action="store_true", help="disable ANSI colours")
    ap.add_argument("-V", "--version", action="version", version=f"%(prog)s {__version__}")
    return ap


def _glyphs(stream) -> dict:
    try:
        "".join(UNICODE.values()).encode(getattr(stream, "encoding", None) or "ascii")
        return UNICODE
    except (UnicodeEncodeError, LookupError):
        return ASCII


def render(report: Report, elapsed: float, color: bool, g: dict) -> str:
    def paint(text, code):
        return f"\033[{code}m{text}\033[0m" if color else text

    sep = f"  {g['sep']}  "
    mode = "online" if report.online else "offline"
    lines = [paint(f" slopcheck v{__version__}", "1;35") + paint(
        f"{sep}{len(report.dependencies)} dependencies{sep}{report.files_scanned} files{sep}{mode}{sep}{elapsed:.1f}s",
        "2"), ""]
    for category, heading in SECTIONS:
        items = [f for f in report.findings if f.category == category]
        if not items:
            continue
        lines.append(paint(f" {heading}", "1"))
        width = max(len(f"{f.file}:{f.line}") for f in items)
        for f in items:
            badge = paint(f"{g[f.severity]} {f.severity.upper():<8}", COLORS[f.severity])
            where = paint(f"{f.file}:{f.line}".ljust(width), "2")
            subject = paint(f.subject, "1") + "  " if f.subject else ""
            lines.append(f"  {badge} {where}  {subject}{f.title}")
            if f.detail:
                lines.append(paint(f"  {' ' * 10} {' ' * width}  {f.detail}", "2"))
            if f.fix:
                lines.append(f"  {' ' * 10} {' ' * width}  " + paint(f"{g['fix']} fix: {f.fix}", "32"))
        lines.append("")
    if not report.findings:
        lines.append(paint(" nothing found: no hallucinated packages, no leaked secrets, no classic slips", "32"))
    else:
        counts = [paint(f"{sum(f.severity == s for f in report.findings)} {s}", COLORS[s]) for s in reversed(SEVERITIES)]
        lines.append(" " + paint(sep, "2").join(counts))
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if not args.path.is_dir():
        print(f"slopcheck: not a directory: {args.path}", file=sys.stderr)
        return 2
    started = time.perf_counter()
    report = scan(args.path, online=not args.offline, exclude=args.exclude)
    elapsed = time.perf_counter() - started

    if args.json:
        print(json.dumps({"version": __version__, "root": report.root, "online": report.online,
                          "dependencies": [asdict(d) for d in report.dependencies],
                          "findings": [asdict(f) for f in report.findings]}, indent=2))
    else:
        if hasattr(sys.stdout, "reconfigure"):
            sys.stdout.reconfigure(errors="replace")
        color = not args.no_color and "NO_COLOR" not in os.environ and sys.stdout.isatty()
        print(render(report, elapsed, color, _glyphs(sys.stdout)))

    worst = report.worst()
    return 1 if worst and rank(worst) >= rank(args.fail_on) else 0
