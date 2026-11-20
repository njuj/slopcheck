"""Read the exact installed versions out of lockfiles: npm, yarn, pnpm, poetry, uv and Pipenv.

A lockfile lists every package that gets installed, the dependencies of dependencies included, so these
are what the known-malware and known-vulnerability checks run on.
"""

from __future__ import annotations

import json
import re
import tomllib
from pathlib import Path

from .model import Dependency

LOCKFILES = {"package-lock.json": "npm", "npm-shrinkwrap.json": "npm", "yarn.lock": "npm", "pnpm-lock.yaml": "npm",
             "poetry.lock": "pypi", "uv.lock": "pypi", "Pipfile.lock": "pypi"}


def is_lockfile(path: Path) -> bool:
    return path.name in LOCKFILES


class _Lines:
    """Line numbers for `name` + `version` pairs, found once and cached."""

    def __init__(self, text: str):
        self.text = text

    def of(self, *needles: str) -> int:
        pos = 0
        for needle in needles:
            i = self.text.find(needle, pos)
            if i < 0:
                break
            pos = i
        return self.text.count("\n", 0, pos) + 1


def _dep(name, ecosystem, file, line, version, from_registry=True):
    return Dependency(name, ecosystem, file, line, from_registry, version=version, direct=False)


def parse_package_lock(text: str, file: str) -> list[Dependency]:
    doc, lines, out = json.loads(text), _Lines(text), []
    packages = doc.get("packages")
    if isinstance(packages, dict):                            # lockfileVersion 2 and 3
        for key, meta in packages.items():
            if not key or not isinstance(meta, dict) or meta.get("link") or "node_modules/" not in key:
                continue
            name = meta.get("name") or key.rsplit("node_modules/", 1)[1]
            version = meta.get("version")
            resolved = str(meta.get("resolved") or "")
            registry = not resolved or resolved.startswith("https://registry.") or "/-/" in resolved
            if version:
                out.append(_dep(name, "npm", file, lines.of(f'"{key}"'), version, registry))
        return out

    def walk(deps):                                          # lockfileVersion 1: nested "dependencies"
        for name, meta in (deps or {}).items():
            if isinstance(meta, dict) and meta.get("version"):
                version = str(meta["version"])
                registry = not version.startswith(("file:", "git", "http", "github:", "link:"))
                out.append(_dep(name, "npm", file, lines.of(f'"{name}"', f'"{version}"'), version, registry))
                walk(meta.get("dependencies"))
    walk(doc.get("dependencies"))
    return out


_YARN_ENTRY = re.compile(r'^"?((?:@[^@/\s"]+/)?[^@\s",]+)@[^\n]*:\n(?:[ \t]+[^\n]*\n)*?[ \t]+version:?\s+"?([^"\s]+)"?',
                         re.M)


def parse_yarn_lock(text: str, file: str) -> list[Dependency]:
    out = []
    for m in _YARN_ENTRY.finditer(text):
        header = text[m.start():text.find("\n", m.start())]
        registry = not re.search(r"@(?:file:|link:|portal:|workspace:|patch:|git|https?:)", header)
        out.append(_dep(m.group(1), "npm", file, text.count("\n", 0, m.start()) + 1, m.group(2), registry))
    return out


_PNPM_KEY = re.compile(r"^  ['\"]?/?((?:@[^@/\s'\"]+/)?[^@/\s'\"(]+)[@/]([0-9][^\s'\"():]*)", re.M)


def parse_pnpm_lock(text: str, file: str) -> list[Dependency]:
    start = re.search(r"^packages:\s*$", text, re.M)
    if not start:
        return []
    end = re.search(r"^\S", text[start.end():], re.M)
    body_end = start.end() + end.start() if end else len(text)
    return [_dep(m.group(1), "npm", file, text.count("\n", 0, m.start()) + 1, m.group(2))
            for m in _PNPM_KEY.finditer(text, start.end(), body_end)]


def parse_toml_lock(text: str, file: str) -> list[Dependency]:
    """poetry.lock and uv.lock: a [[package]] table each, with name, version and where it came from."""
    lines, out = _Lines(text), []
    for pkg in tomllib.loads(text).get("package", []):
        name, version = pkg.get("name"), pkg.get("version")
        if not name or not version:
            continue
        source = pkg.get("source") or {}
        if not source:
            registry = True
        elif "type" in source:                                   # poetry: git | directory | file | url | legacy
            registry = source["type"] in ("legacy", "pypi", "supplemental")
        else:                                                    # uv: registry | git | path | editable | virtual | url
            registry = "registry" in source
        out.append(_dep(name, "pypi", file, lines.of(f'name = "{name}"', f'version = "{version}"'), version, registry))
    return out


def parse_pipfile_lock(text: str, file: str) -> list[Dependency]:
    doc, lines, out = json.loads(text), _Lines(text), []
    for section in ("default", "develop"):
        for name, meta in (doc.get(section) or {}).items():
            version = str((meta or {}).get("version", ""))
            if version.startswith("=="):
                out.append(_dep(name, "pypi", file, lines.of(f'"{name}"'), version[2:]))
    return out


PARSERS = {"package-lock.json": parse_package_lock, "npm-shrinkwrap.json": parse_package_lock,
           "yarn.lock": parse_yarn_lock, "pnpm-lock.yaml": parse_pnpm_lock, "poetry.lock": parse_toml_lock,
           "uv.lock": parse_toml_lock, "Pipfile.lock": parse_pipfile_lock}


def parse_lockfile(path: Path, display: str) -> list[Dependency]:
    return PARSERS[path.name](path.read_text(encoding="utf-8", errors="replace"), display)
