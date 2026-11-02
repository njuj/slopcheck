"""Read-only lookups against the public PyPI and npm registries."""

from __future__ import annotations

import json
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime

from . import __version__
from .model import Dependency, PackageInfo

USER_AGENT = f"slopcheck/{__version__} (+https://github.com/njuj/slopcheck)"
INSTALL_HOOKS = ("preinstall", "install", "postinstall")


def _parse_time(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def pypi_info(doc: dict) -> PackageInfo:
    uploads = [f["upload_time_iso_8601"] for files in doc.get("releases", {}).values() for f in files
               if f.get("upload_time_iso_8601")]
    released = sum(1 for files in doc.get("releases", {}).values() if files)
    return PackageInfo(exists=released > 0, created=_parse_time(min(uploads)) if uploads else None, releases=released)


def npm_info(doc: dict, weekly_downloads: int | None) -> PackageInfo:
    """Works on both the full packument and the abbreviated (install-v1) one."""
    versions = doc.get("versions") or {}
    if not versions:  # unpublished: the name is free to be re-registered
        return PackageInfo(exists=False)
    latest = versions.get((doc.get("dist-tags") or {}).get("latest", ""), {})
    created = (doc.get("time") or {}).get("created")
    hooks = [h for h in INSTALL_HOOKS if h in (latest.get("scripts") or {})]
    if not hooks and latest.get("hasInstallScript"):
        hooks = ["install"]
    return PackageInfo(
        exists=True,
        created=_parse_time(created) if created else None,
        releases=len(versions),
        weekly_downloads=weekly_downloads,
        install_scripts=hooks,
    )


# Abbreviated npm metadata is tiny but has no creation date. Packages with this many versions have
# clearly been around for a while, so the full (sometimes multi-MB) document isn't worth fetching.
MANY_VERSIONS = 20
NPM_ABBREVIATED = "application/vnd.npm.install-v1+json"


class Registry:
    def __init__(self, timeout: float = 10, workers: int = 16):
        self.timeout = timeout
        self.workers = workers

    def _get_json(self, url: str, accept: str = "application/json") -> dict | None:
        req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, "Accept": accept})
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                return json.load(resp)
        except urllib.error.HTTPError as e:
            if e.code == 404:
                return None
            raise

    def lookup(self, dep: Dependency) -> PackageInfo:
        try:
            if dep.ecosystem == "pypi":
                doc = self._get_json(f"https://pypi.org/pypi/{urllib.parse.quote(dep.name)}/json")
                return pypi_info(doc) if doc else PackageInfo(exists=False)
            quoted = urllib.parse.quote(dep.name, safe="@")  # @scope/name -> @scope%2Fname
            url = f"https://registry.npmjs.org/{quoted}"
            doc = self._get_json(url, accept=NPM_ABBREVIATED)
            if doc is None:
                return PackageInfo(exists=False)
            if 0 < len(doc.get("versions") or {}) < MANY_VERSIONS:
                doc = self._get_json(url) or doc  # young-looking package: the creation date matters
            downloads = self._get_json(f"https://api.npmjs.org/downloads/point/last-week/{quoted}")
            return npm_info(doc, (downloads or {}).get("downloads"))
        except (urllib.error.URLError, TimeoutError, OSError, ValueError) as e:
            return PackageInfo(exists=True, error=str(getattr(e, "reason", e)))

    def lookup_all(self, deps: list[Dependency]) -> dict[tuple[str, str], PackageInfo]:
        unique = {(d.ecosystem, d.name): d for d in deps}
        with ThreadPoolExecutor(self.workers) as pool:
            infos = pool.map(self.lookup, unique.values())
        return dict(zip(unique.keys(), infos))
