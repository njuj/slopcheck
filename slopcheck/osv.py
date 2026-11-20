"""Known malicious packages and known vulnerabilities, from the OSV.dev database (no key, no account).

OSV merges the OpenSSF malicious-packages list (MAL-… ids), GitHub's advisories and PyPA's. Each package goes in
one batch query: with its exact version when pinned or locked (every advisory that affects that version), or
by name alone (then only malware counts, since a vulnerability depends on the version).
"""

from __future__ import annotations

import json
import re
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor

from .model import Dependency, Finding, rank
from .registry import USER_AGENT

API = "https://api.osv.dev/v1"
ECOSYSTEM = {"pypi": "PyPI", "npm": "npm"}
BATCH = 1000                 # OSV's limit per querybatch call
MALWARE_CWE = "CWE-506"      # "embedded malicious code": how GitHub marks its malware advisories
SEVERITY = {"CRITICAL": "critical", "HIGH": "high", "MODERATE": "medium", "MEDIUM": "medium", "LOW": "low"}


class OSVError(Exception):
    pass


def canonical(name: str, ecosystem: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower() if ecosystem == "pypi" else name


def _version_key(v: str):
    # shortcut: numeric release parts, then a pre-release sorts before the release; not full PEP 440 / semver,
    # good enough to pick the highest "fixed in" version among a package's advisories
    release = re.match(r"v?(\d+(?:\.\d+)*)(.*)", v or "")
    if not release:
        return ((), 0, v)
    nums = tuple(int(x) for x in release.group(1).split("."))
    nums += (0,) * (6 - len(nums))
    return (nums, 0 if release.group(2) else 1, release.group(2))


def is_malware(vuln: dict) -> bool:
    ids = [vuln.get("id", "")] + list(vuln.get("aliases") or [])
    cwes = (vuln.get("database_specific") or {}).get("cwe_ids") or []
    return any(i.startswith("MAL-") for i in ids) or MALWARE_CWE in cwes


def severity_of(vuln: dict) -> str:
    return SEVERITY.get(str((vuln.get("database_specific") or {}).get("severity", "")).upper(), "medium")


def fixed_versions(vuln: dict, dep: Dependency) -> list[str]:
    """The 'fixed' versions this advisory names for `dep`'s package that are newer than the installed one."""
    out = []
    for aff in vuln.get("affected") or []:
        pkg = aff.get("package") or {}
        if pkg.get("ecosystem") != ECOSYSTEM[dep.ecosystem] or \
                canonical(pkg.get("name", ""), dep.ecosystem) != canonical(dep.name, dep.ecosystem):
            continue
        for rng in aff.get("ranges") or []:
            for ev in rng.get("events") or []:
                if "fixed" in ev and (not dep.version or _version_key(ev["fixed"]) > _version_key(dep.version)):
                    out.append(ev["fixed"])
    return out


class OSV:
    def __init__(self, timeout: float = 20, workers: int = 16):
        self.timeout, self.workers = timeout, workers

    def _call(self, url: str, body: dict | None = None) -> dict:
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(url, data=data, headers={"User-Agent": USER_AGENT, "Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                return json.load(resp)
        except (urllib.error.URLError, TimeoutError, OSError, ValueError) as e:
            raise OSVError(str(getattr(e, "reason", e))) from None

    def query(self, deps: list[Dependency]) -> dict[tuple, list[str]]:
        """{(ecosystem, canonical name, version or None): [advisory ids]}"""
        keys = list(dict.fromkeys((d.ecosystem, canonical(d.name, d.ecosystem), d.version) for d in deps))
        out = {}
        for i in range(0, len(keys), BATCH):
            chunk = keys[i:i + BATCH]
            queries = [{"package": {"name": n, "ecosystem": ECOSYSTEM[e]}, **({"version": v} if v else {})}
                       for e, n, v in chunk]
            # shortcut: a package with more advisories than one response holds gets a next_page_token, which is
            # not followed; the first page already decides "vulnerable" and holds the malware entries in practice
            results = self._call(f"{API}/querybatch", {"queries": queries}).get("results", [])
            for key, res in zip(chunk, results):
                out[key] = [v["id"] for v in (res or {}).get("vulns", [])]
        return out

    def details(self, ids) -> dict[str, dict]:
        ids = sorted(set(ids))
        with ThreadPoolExecutor(self.workers) as pool:
            docs = list(pool.map(lambda i: self._call(f"{API}/vulns/{i}"), ids))
        return dict(zip(ids, docs))


def _short(ids: list[str], docs: dict) -> str:
    """'CVE-2021-23337, CVE-2020-8203 and 3 more': the most widely known name of each advisory."""
    names = []
    for i in ids:
        aliases = (docs.get(i) or {}).get("aliases") or []
        names.append(next((a for a in aliases if a.startswith("CVE-")), i))
    names = list(dict.fromkeys(names))
    return ", ".join(names[:3]) + (f" and {len(names) - 3} more" if len(names) > 3 else "")


def findings(deps: list[Dependency], hits: dict, docs: dict) -> list[Finding]:
    out, seen = [], set()
    for dep in deps:
        key = (dep.ecosystem, canonical(dep.name, dep.ecosystem), dep.version)
        if key in seen or not hits.get(key):
            continue
        seen.add(key)
        vulns = [docs[i] for i in hits[key] if i in docs]
        where = "" if dep.direct else " (installed through the lockfile)"
        malware = [v for v in vulns if is_malware(v)]
        if malware:
            out.append(Finding("critical", "dependency", "known malicious package", dep.file, dep.line,
                               f"{malware[0].get('summary') or 'reported as malware'} "
                               f"({_short([v['id'] for v in malware], docs)}){where}",
                               "remove it now, and treat any machine that installed it as compromised: rotate the "
                               "secrets it could read", dep.name))
            continue
        if not dep.version:
            continue                  # by name alone, only malware is meaningful
        # an advisory listed under several ids (GHSA + PYSEC + CVE) is one problem
        ids = {v["id"] for v in vulns}
        vulns = [v for v in vulns if not (v["id"].startswith("PYSEC-") and ids & set(v.get("aliases") or []))]
        worst = max((severity_of(v) for v in vulns), key=rank)
        # each advisory's nearest fix above the installed version (not a later major line's), then the highest
        fixes = [min(f, key=_version_key) for v in vulns if (f := fixed_versions(v, dep))]
        top = sorted(vulns, key=lambda v: -rank(severity_of(v)))
        n = len(vulns)
        out.append(Finding(worst, "dependency", f"{n} known vulnerabilit{'y' if n == 1 else 'ies'} in {dep.version}",
                           dep.file, dep.line,
                           f"{top[0].get('summary') or top[0]['id']}: {_short([v['id'] for v in top], docs)}{where}",
                           f"upgrade to {max(fixes, key=_version_key)} or later" if fixes else
                           "no fixed version is published yet: check the advisories for a workaround",
                           dep.name))
    return out


def check(deps: list[Dependency], client: OSV | None = None) -> list[Finding]:
    deps = [d for d in deps if d.from_registry and d.ecosystem in ECOSYSTEM]
    if not deps:
        return []
    client = client or OSV()
    try:
        hits = client.query(deps)
        # by name alone the answer holds every advisory the package ever had: fetch only what can be reported
        wanted = {i for (e, n, v), ids in hits.items() for i in ids if v or i.startswith("MAL-") or i.startswith("GHSA-")}
        docs = client.details(wanted)
    except OSVError as e:
        return [Finding("low", "dependency", "could not check OSV.dev for known malware and vulnerabilities",
                        deps[0].file, 1, e.args[0] if e.args else "")]
    return findings(deps, hits, docs)
