"""Line rules for leaked secrets and the security slips AI assistants make most often.

Every rule is a regex over a single line. A line ending in a `slopcheck: ignore` comment is skipped.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

PY = (".py", ".ipynb")
JS = (".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".vue", ".svelte")
ANY = ()  # secrets: every scanned text file

PLACEHOLDER = re.compile(r"(?i)^(your|<|\$\{|\{\{|xxx|\*\*\*|example|placeholder|changeme|change[-_]me|dummy|test|"
                         r"fake|sample|todo|none|null|undefined|os\.environ|process\.env)")


@dataclass(frozen=True)
class Rule:
    id: str
    category: str  # secret | code
    severity: str
    title: str
    pattern: re.Pattern
    extensions: tuple
    fix: str
    secret_group: int = 0  # for secrets: which group holds the value to mask (0 = whole match)

    def applies_to(self, suffix: str) -> bool:
        return not self.extensions or suffix in self.extensions


def _r(rule_id, category, severity, title, pattern, extensions, fix, secret_group=0, flags=0):
    return Rule(rule_id, category, severity, title, re.compile(pattern, flags), extensions, fix, secret_group)


RULES = [
    # ── secrets ─────────────────────────────────────────────────────────────
    _r("aws-access-key", "secret", "critical", "AWS access key", r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b", ANY,
       "revoke it in IAM, then load credentials from the environment or a secrets manager"),
    _r("github-token", "secret", "critical", "GitHub token",
       r"\b(?:gh[pousr]_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{60,})\b", ANY,
       "revoke it at github.com/settings/tokens and read it from an environment variable"),
    _r("anthropic-key", "secret", "critical", "Anthropic API key", r"\bsk-ant-[A-Za-z0-9_-]{20,}", ANY,
       "rotate it in the Anthropic console and read it from an environment variable"),
    _r("openai-key", "secret", "critical", "OpenAI API key", r"\bsk-(?!ant-)(?:proj-|svcacct-)?[A-Za-z0-9_-]{32,}",
       ANY, "rotate it in the OpenAI dashboard and read it from an environment variable"),
    _r("stripe-live-key", "secret", "critical", "Stripe live key", r"\b[sr]k_live_[A-Za-z0-9]{20,}", ANY,
       "roll the key in the Stripe dashboard"),
    _r("slack-token", "secret", "critical", "Slack token", r"\bxox[abprs]-[A-Za-z0-9-]{10,}", ANY,
       "revoke it in the Slack app settings"),
    _r("google-api-key", "secret", "high", "Google API key", r"\bAIza[0-9A-Za-z_-]{35}\b", ANY,
       "restrict or regenerate it in Google Cloud console"),
    _r("private-key", "secret", "critical", "private key", r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY",
       ANY, "remove it from the repository and rotate the key pair"),
    _r("hardcoded-credential", "secret", "medium", "hard-coded credential",
       r"(?i)\b(?:password|passwd|pwd|api[_-]?key|access[_-]?token|auth[_-]?token|client[_-]?secret)\b"
       r"[\"']?\s*[:=]\s*[\"']([^\"'\s]{8,})[\"']", ANY,
       "move it to an environment variable or a secrets manager", secret_group=1),
    # ── python ──────────────────────────────────────────────────────────────
    _r("flask-debug", "code", "high", "Flask debug mode in code", r"\.run\([^)#]*debug\s*=\s*True", PY,
       "the Werkzeug debugger runs arbitrary code for anyone who can reach it; drive it from an env var"),
    _r("django-debug", "code", "medium", "Django DEBUG on", r"^\s*DEBUG\s*=\s*True\b", PY,
       "read it from the environment so production never ships with tracebacks on"),
    _r("hardcoded-secret-key", "code", "high", "hard-coded framework secret key",
       r"\b(?:SECRET_KEY|secret_key|JWT_SECRET|jwt_secret)\s*=\s*[\"'][^\"']+[\"']", PY + JS,
       "anyone with this value can forge sessions or tokens; load it from the environment"),
    _r("requests-verify-false", "code", "high", "TLS verification turned off", r"\bverify\s*=\s*False\b", PY,
       "fix the certificate chain (or pass a CA bundle) instead of disabling verification"),
    _r("yaml-unsafe-load", "code", "high", "yaml.load without a safe loader",
       r"\byaml\.load\((?![^)]*Loader\s*=\s*(?:yaml\.)?C?SafeLoader)", PY,
       "use yaml.safe_load(): yaml.load can build arbitrary Python objects"),
    _r("pickle-load", "code", "medium", "unpickling data", r"\bpickle\.loads?\(", PY,
       "never unpickle data you did not produce yourself; use JSON"),
    _r("subprocess-shell", "code", "medium", "shell=True", r"\bsubprocess\.\w+\([^)]*shell\s*=\s*True", PY,
       "pass an argument list without shell=True so input cannot inject commands"),
    _r("sql-string-building", "code", "high", "SQL built from strings",
       r"\.execute\(\s*(?:f[\"']|[\"'][^\"']*[\"']\s*(?:%|\+|\.format\())", PY,
       "use parameters: cursor.execute(\"... WHERE id = %s\", (user_id,))"),
    _r("eval-user-input", "code", "critical", "eval/exec on user input",
       r"\b(?:eval|exec)\(\s*(?:input\(|request\.|sys\.argv)", PY, "parse the input instead of executing it"),
    _r("cors-allow-all-py", "code", "medium", "CORS open to every origin",
       r"(?:allow_origins\s*=\s*\[\s*[\"']\*[\"']|\bCORS\(\s*app\s*\))", PY,
       "list the origins that may call this API"),
    # ── javascript / typescript ─────────────────────────────────────────────
    _r("tls-reject-off", "code", "high", "TLS verification turned off",
       r"(?:NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*[\"']?0|rejectUnauthorized\s*:\s*false)", JS,
       "fix the certificate chain instead of disabling verification"),
    _r("jwt-alg-none", "code", "critical", "JWT accepts alg 'none'", r"algorithms\s*:\s*\[[^\]]*[\"']none[\"']", JS,
       "allow only the algorithm you sign with, e.g. ['HS256']"),
    _r("jwt-decode-unverified", "code", "medium", "jwt.decode() does not verify",
       r"\bjwt\.decode\(", JS, "use jwt.verify() before trusting any claim"),
    _r("exec-template", "code", "high", "shell command built from a template string",
       r"\bexec(?:Sync)?\(\s*`[^`]*\$\{", JS, "use execFile/spawn with an argument array"),
    _r("eval-js", "code", "medium", "eval()", r"(?<![.\w])eval\(", JS, "parse data with JSON.parse; never eval it"),
    _r("dangerously-set-html", "code", "medium", "dangerouslySetInnerHTML", r"dangerouslySetInnerHTML", JS,
       "sanitize with DOMPurify first, or render text instead"),
    _r("innerhtml-assign", "code", "medium", "innerHTML assigned from a variable",
       r"\.innerHTML\s*\+?=(?!\s*[\"'][^\"'`$]*[\"']\s*;?\s*$)\s*[^;\s]", JS,
       "use textContent, or sanitize the HTML first"),
    _r("cors-allow-all-js", "code", "medium", "CORS open to every origin",
       r"(?:\bcors\(\s*\)|origin\s*:\s*[\"']\*[\"']|Access-Control-Allow-Origin[\"']?\s*[,:]\s*[\"']\*)", JS,
       "list the origins that may call this API"),
    _r("token-in-localstorage", "code", "low", "auth token in localStorage",
       r"localStorage\.setItem\(\s*[\"'][^\"']*(?:token|jwt|auth)[^\"']*[\"']", JS,
       "any XSS can read localStorage; prefer an HttpOnly cookie", flags=re.I),
]

IGNORE_MARKER = re.compile(r"(?:#|//|/\*)\s*slopcheck:\s*ignore", re.I)


def mask(value: str) -> str:
    """Show just enough of a secret to recognise it, never enough to use it."""
    return value[:4] + "…" + ("*" * 4) if len(value) > 8 else "*" * 8


def scan_line(line: str, suffix: str) -> list[tuple[Rule, str]]:
    """(rule, subject) pairs for every rule that fires on this line."""
    if IGNORE_MARKER.search(line):
        return []
    hits = []
    for rule in RULES:
        if not rule.applies_to(suffix):
            continue
        m = rule.pattern.search(line)
        if not m:
            continue
        if rule.category == "secret":
            value = m.group(rule.secret_group)
            if rule.secret_group and PLACEHOLDER.match(value):
                continue
            if rule.id == "hardcoded-credential" and any(r.category == "secret" for r, _ in hits):
                continue  # already reported by a specific rule (e.g. api_key = "sk-…")
            hits.append((rule, mask(value)))
        else:
            snippet = line.strip()
            hits.append((rule, snippet if len(snippet) <= 70 else snippet[:69] + "…"))
    return hits
