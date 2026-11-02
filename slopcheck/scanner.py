"""Walk a project, collect dependencies and source lines, and produce findings."""

from __future__ import annotations

import fnmatch
import json
import os
from dataclasses import dataclass, field
from pathlib import Path

from . import deps as dep_checks
from .manifests import is_manifest, parse_manifest
from .model import Dependency, Finding, rank
from .names import is_popular
from .registry import Registry
from .rules import JS, PY, scan_line

SKIP_DIRS = {".git", ".hg", ".svn", "node_modules", "venv", ".venv", "env", ".env", "__pycache__", "dist", "build",
             ".next", ".nuxt", ".tox", ".nox", ".mypy_cache", ".pytest_cache", ".ruff_cache", "site-packages",
             "vendor", "coverage", ".idea", ".vscode", "out", "target"}
SOURCE_SUFFIXES = set(PY) | set(JS) | {".json", ".yml", ".yaml", ".toml", ".ini", ".cfg", ".conf", ".properties",
                                       ".sh", ".ps1", ".tf", ".xml", ".php", ".rb", ".go", ".java", ".cs", ".kt"}
MAX_FILE_BYTES = 1_000_000


@dataclass
class Report:
    root: str
    files_scanned: int = 0
    dependencies: list[Dependency] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    online: bool = True

    def worst(self) -> str | None:
        return max((f.severity for f in self.findings), key=rank, default=None)


def is_env_file(path: Path) -> bool:
    return path.name == ".env" or (path.name.startswith(".env.") and not path.name.endswith((".example", ".sample",
                                                                                              ".template", ".dist")))


def _excluded(rel: str, patterns: list[str]) -> bool:
    return any(fnmatch.fnmatch(rel, p) or fnmatch.fnmatch(rel, p.rstrip("/") + "/*") for p in patterns)


def iter_files(root: Path, exclude: list[str]):
    for dirpath, dirnames, filenames in os.walk(root):
        rel_dir = Path(dirpath).relative_to(root).as_posix()
        dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS and
                             not _excluded(d if rel_dir == "." else f"{rel_dir}/{d}", exclude))
        for name in sorted(filenames):
            path = Path(dirpath, name)
            rel = path.relative_to(root).as_posix()
            if not _excluded(rel, exclude):
                yield path, rel


def _gitignore_covers(root: Path, rel: str) -> bool:
    """Good-enough .gitignore matching for the one question we ask: is this .env file ignored?"""
    name = Path(rel).name
    for gitignore in (root / ".gitignore", root / Path(rel).parent / ".gitignore"):
        if not gitignore.is_file():
            continue
        for raw in gitignore.read_text(encoding="utf-8", errors="replace").splitlines():
            pattern = raw.strip()
            if not pattern or pattern.startswith(("#", "!")):
                continue
            pattern = pattern.lstrip("/").rstrip("/")
            if fnmatch.fnmatch(name, pattern) or fnmatch.fnmatch(rel, pattern) or fnmatch.fnmatch(rel, f"**/{pattern}"):
                return True
    return False


def _read_text(path: Path) -> str | None:
    try:
        if path.stat().st_size > MAX_FILE_BYTES:
            return None
        raw = path.read_bytes()
    except OSError:
        return None
    if b"\0" in raw[:1024]:
        return None
    return raw.decode("utf-8", errors="replace")


def _notebook_lines(text: str) -> list[str]:
    """Code cells of a Jupyter notebook, so line rules see source rather than JSON."""
    try:
        cells = json.loads(text).get("cells", [])
    except (json.JSONDecodeError, AttributeError):
        return text.splitlines()
    lines = []
    for cell in cells:
        source = cell.get("source", [])
        lines += ("".join(source) if isinstance(source, list) else str(source)).splitlines()
    return lines


def scan_code(path: Path, rel: str) -> list[Finding]:
    suffix = ".env" if is_env_file(path) else path.suffix.lower()
    if suffix not in SOURCE_SUFFIXES and suffix != ".env":
        return []
    text = _read_text(path)
    if text is None:
        return []
    lines = _notebook_lines(text) if suffix == ".ipynb" else text.splitlines()
    out = []
    for lineno, line in enumerate(lines, 1):
        for rule, subject in scan_line(line, suffix):
            out.append(Finding(rule.severity, rule.category, rule.title, rel, lineno, fix=rule.fix, subject=subject))
    return out


def scan(root: Path, *, online: bool = True, exclude: list[str] | None = None,
         registry: Registry | None = None) -> Report:
    root = root.resolve()
    exclude = exclude or []
    report = Report(root=str(root), online=online)
    for path, rel in iter_files(root, exclude):
        if is_manifest(path):
            try:
                report.dependencies += parse_manifest(path, rel)
            except (ValueError, OSError) as e:  # broken JSON / TOML
                report.findings.append(Finding("low", "config", "could not parse manifest", rel, 1, str(e)))
        report.files_scanned += 1
        if is_env_file(path):
            if _gitignore_covers(root, rel):
                continue  # an ignored .env is exactly where secrets belong
            report.findings.append(Finding("high", "config", ".env file not in .gitignore", rel, 1,
                                           "one `git add .` away from publishing every secret in it",
                                           "add `.env` to .gitignore and commit a `.env.example` instead"))
        report.findings += scan_code(path, rel)

    # popular packages are known to exist and to be what they claim: no need to ask the registry
    to_check = [d for d in report.dependencies if d.from_registry and not is_popular(d.name, d.ecosystem)]
    infos = (registry or Registry()).lookup_all(to_check) if online and to_check else {}
    for dep in report.dependencies:
        report.findings += dep_checks.assess(dep, infos.get((dep.ecosystem, dep.name)) if online else None)
    report.findings.sort(key=lambda f: (-rank(f.severity), f.category != "dependency", f.file, f.line))
    return report
