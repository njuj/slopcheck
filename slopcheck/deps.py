"""Turn a dependency plus what the registry says about it into findings."""

from __future__ import annotations

from datetime import datetime, timezone

from .model import Dependency, Finding, PackageInfo
from .names import import_name_mixup, is_popular, lookalike
from .registry import MANY_VERSIONS

NEW_DAYS = 30           # younger than this: someone registered it very recently
ESTABLISHED_DAYS = 180  # older than this with real history: probably a legitimate project
LOW_DOWNLOADS = 100     # npm weekly downloads below which nobody really uses it
REGISTRY_NAME = {"pypi": "PyPI", "npm": "npm"}


def _finding(dep: Dependency, severity: str, title: str, detail: str = "", fix: str = "") -> Finding:
    return Finding(severity, "dependency", title, dep.file, dep.line, detail, fix, dep.name)


def offline_findings(dep: Dependency) -> list[Finding]:
    """Name-only checks: no network needed."""
    out = []
    mixup = import_name_mixup(dep.name, dep.ecosystem)
    if mixup:
        out.append(_finding(dep, "medium", f"'{dep.name}' is an import name, not the package",
                            f"the library you import as `{dep.name}` is published as `{mixup}`; whatever is (or "
                            f"will be) registered as `{dep.name}` belongs to someone else",
                            f"depend on `{mixup}` instead"))
    return out


def assess(dep: Dependency, info: PackageInfo | None, now: datetime | None = None) -> list[Finding]:
    """Findings for one dependency. `info` is None in offline mode."""
    out = offline_findings(dep)
    if not dep.from_registry or is_popular(dep.name, dep.ecosystem):
        return out
    registry = REGISTRY_NAME[dep.ecosystem]
    target = lookalike(dep.name, dep.ecosystem)
    mixup = import_name_mixup(dep.name, dep.ecosystem)
    suggestion = target or mixup

    if info is None:
        if target:
            out.append(_finding(dep, "medium", f"looks like '{target}'",
                                "one typo away from a popular package (run online to check who owns this name)",
                                f"did you mean `{target}`?"))
        return out
    if info.error:
        out.append(_finding(dep, "low", "could not verify on " + registry, info.error))
        return out

    if not info.exists:
        if mixup:
            why = f"`{dep.name}` is the import name of `{mixup}`, and nobody owns it on {registry} yet"
        elif target:
            why = f"a look-alike of `{target}` that nobody owns yet"
        else:
            why = "the name is unregistered (or was removed), so an AI likely invented it"
        return [_finding(dep, "critical", f"does not exist on {registry}",
                         why + ": anyone can register it and ship malware to everyone who copies this file",
                         f"did you mean `{suggestion}`?" if suggestion else
                         "remove it, or find the real package name in the library's own docs")]

    now = now or datetime.now(timezone.utc)
    age = (now - info.created).days if info.created else None
    young = age is not None and age < NEW_DAYS
    has_history = info.releases >= MANY_VERSIONS or (age is not None and age >= ESTABLISHED_DAYS and info.releases >= 3)
    established = has_history and (info.weekly_downloads is None or info.weekly_downloads >= LOW_DOWNLOADS)
    created = info.created.date().isoformat() if info.created else "unknown date"

    if young:
        out.append(_finding(dep, "high", f"registered {age} day(s) ago",
                            f"first published {created} with {info.releases} release(s); brand-new names are how "
                            "slopsquatting and typosquatting attacks start",
                            "check the project's source and maintainer before installing"))
    if target and not established:
        out.append(_finding(dep, "high", f"impersonates '{target}'?",
                            f"one typo away from the popular `{target}`, but little-known "
                            f"({info.releases} release(s), first published {created})",
                            f"did you mean `{target}`?"))
    elif target:
        out.append(_finding(dep, "low", f"similar to '{target}'",
                            "an established package, but its name is one typo away from a popular one",
                            f"make sure you meant `{dep.name}` and not `{target}`"))
    if info.install_scripts:
        risky = young or (target and not established)
        out.append(_finding(dep, "high" if risky else "medium", "runs code at install time",
                            f"`{', '.join(info.install_scripts)}` script executes on `npm install`, before you "
                            "ever import the package",
                            "review the script, or install with `--ignore-scripts`"))
    if info.weekly_downloads is not None and info.weekly_downloads < LOW_DOWNLOADS and not young and not target:
        out.append(_finding(dep, "low", "barely used",
                            f"{info.weekly_downloads} downloads last week",
                            "make sure this is the package you meant"))
    return out
