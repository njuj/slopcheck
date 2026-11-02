from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime

SEVERITIES = ("low", "medium", "high", "critical")


def rank(severity: str) -> int:
    return SEVERITIES.index(severity)


@dataclass(frozen=True)
class Dependency:
    name: str
    ecosystem: str  # "pypi" | "npm"
    file: str
    line: int
    from_registry: bool = True  # False for git / file / workspace / URL specs


@dataclass
class PackageInfo:
    exists: bool
    created: datetime | None = None
    releases: int = 0
    weekly_downloads: int | None = None
    install_scripts: list[str] = field(default_factory=list)
    error: str | None = None


@dataclass
class Finding:
    severity: str
    category: str  # dependency | secret | code | config
    title: str
    file: str
    line: int
    detail: str = ""
    fix: str = ""
    subject: str = ""  # package name, masked secret or matched snippet
