"""Read dependency names out of requirements files, pyproject.toml and package.json."""

from __future__ import annotations

import json
import re
import tomllib
from pathlib import Path

from .model import Dependency

# PEP 508 name at the start of a requirement; everything after (extras, specifiers, markers, URL) is ignored.
_REQ_NAME = re.compile(r"^\s*([A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?)")
_DIRECT_REF = re.compile(r"\s*(?:\[[^\]]*\])?\s*@")
_NON_REGISTRY_NPM = ("file:", "link:", "workspace:", "portal:", "git", "http:", "https:", "github:", "npm:")
_GITHUB_SHORTHAND = re.compile(r"^[\w.-]+/[\w.-]+")  # "user/repo#tag"
NPM_SECTIONS = ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies")


def is_requirements_file(path: Path) -> bool:
    name = path.name.lower()
    return name.endswith(".txt") and (name.startswith("requirements") or path.parent.name == "requirements")


_PIN = re.compile(r"==\s*([0-9][\w.+!-]*)\s*(?:[;,#]|$)")
_NPM_EXACT = re.compile(r"^=?v?(\d+\.\d+\.\d+(?:[-+][\w.+-]*)?)$")


def pinned_version(spec: str) -> str | None:
    m = _PIN.search(spec.split("#", 1)[0].strip())
    return m.group(1) if m and "*" not in m.group(1) else None


def parse_requirement(spec: str) -> tuple[str, bool] | None:
    """(name, comes-from-registry) for one PEP 508 string, or None if it names no package."""
    spec = spec.split("#", 1)[0].strip()
    if not spec or spec.startswith(("-", "git+", "http:", "https:", "file:", ".", "/")):
        return None
    m = _REQ_NAME.match(spec)
    if not m:
        return None
    direct_reference = _DIRECT_REF.match(spec, m.end())  # "name[extra] @ https://…" is not fetched from PyPI
    return m.group(1), direct_reference is None


def parse_requirements(text: str, file: str) -> list[Dependency]:
    deps = []
    for lineno, line in enumerate(text.splitlines(), 1):
        parsed = parse_requirement(line)
        if parsed:
            deps.append(Dependency(parsed[0], "pypi", file, lineno, parsed[1], version=pinned_version(line)))
    return deps


def _line_of(text: str, needle: str) -> int:
    """Best-effort line number of a dependency inside a structured file."""
    m = re.search(r"(?<![\w.-])" + re.escape(needle) + r"(?![\w.-])", text)
    return text.count("\n", 0, m.start()) + 1 if m else 1


def parse_pyproject(text: str, file: str) -> list[Dependency]:
    doc = tomllib.loads(text)
    specs: list[str] = list(doc.get("project", {}).get("dependencies", []))
    for group in doc.get("project", {}).get("optional-dependencies", {}).values():
        specs += group
    for group in doc.get("dependency-groups", {}).values():  # PEP 735
        specs += [s for s in group if isinstance(s, str)]
    deps = []
    for spec in specs:
        parsed = parse_requirement(spec)
        if parsed:
            deps.append(Dependency(parsed[0], "pypi", file, _line_of(text, parsed[0]), parsed[1],
                                   version=pinned_version(spec)))
    poetry = doc.get("tool", {}).get("poetry", {})
    tables = [poetry.get("dependencies", {}), poetry.get("dev-dependencies", {})]
    tables += [g.get("dependencies", {}) for g in poetry.get("group", {}).values()]
    for table in tables:
        for name, value in table.items():
            if name.lower() == "python":
                continue
            local = isinstance(value, dict) and any(k in value for k in ("git", "path", "url"))
            deps.append(Dependency(name, "pypi", file, _line_of(text, name), not local))
    return deps


def parse_package_json(text: str, file: str) -> list[Dependency]:
    doc = json.loads(text)
    deps = []
    for section in NPM_SECTIONS:
        for name, version in (doc.get(section) or {}).items():
            version = str(version)
            from_registry = not (version.startswith(_NON_REGISTRY_NPM) or _GITHUB_SHORTHAND.match(version))
            exact = _NPM_EXACT.match(version.strip())
            deps.append(Dependency(name, "npm", file, _line_of(text, f'"{name}"'), from_registry,
                                   version=exact.group(1) if exact else None))
    return deps


def parse_manifest(path: Path, display: str) -> list[Dependency]:
    text = path.read_text(encoding="utf-8", errors="replace")
    if path.name == "package.json":
        return parse_package_json(text, display)
    if path.name == "pyproject.toml":
        return parse_pyproject(text, display)
    if is_requirements_file(path):
        return parse_requirements(text, display)
    return []


def is_manifest(path: Path) -> bool:
    return path.name in ("package.json", "pyproject.toml") or is_requirements_file(path)
