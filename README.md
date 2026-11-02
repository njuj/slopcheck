# slopcheck

**Catch what AI coding assistants get wrong before it ships:** packages that don't exist, look-alikes of popular libraries, leaked API keys, and the security slips that appear in generated code again and again. One command. Zero dependencies.

[![ci](https://github.com/njuj/slopcheck/actions/workflows/ci.yml/badge.svg)](https://github.com/njuj/slopcheck/actions/workflows/ci.yml)
![python](https://img.shields.io/badge/python-3.11%2B-00ff9c?labelColor=0b0f17)
![deps](https://img.shields.io/badge/dependencies-0-00ff9c?labelColor=0b0f17)
![license](https://img.shields.io/badge/license-MIT-00ff9c?labelColor=0b0f17)

## The problem: slopsquatting

LLMs regularly recommend packages that **do not exist**. In [a study of 576,000 code samples from 16 models](https://arxiv.org/abs/2406.10279), almost 20% of the recommended packages were hallucinated, and the same fake names came back again and again. Repeated fake names are predictable, so an attacker can register them on PyPI or npm and wait for someone to paste `pip install` from a chat window. The attack is called **slopsquatting**.

Plain typos (`reqeusts`), import names used as package names (`pip install cv2`) and decorated look-alikes (`python-openai`) open the same door. None of these fail loudly: they install whatever happens to own the name.

## What it looks like

```text
$ slopcheck my-vibe-app/

 slopcheck v0.1.0  ·  14 dependencies  ·  5 files  ·  online  ·  2.3s

 DEPENDENCIES
  ✖ CRITICAL package.json:7      react-secure-auth-hooks  does not exist on npm
                                 the name is unregistered (or was removed), so an AI likely invented it: anyone can register it and ship malware to everyone who copies this file
                                 └ fix: remove it, or find the real package name in the library's own docs
  ✖ CRITICAL requirements.txt:4  reqeusts  does not exist on PyPI
                                 a look-alike of `requests` that nobody owns yet: anyone can register it and ship malware to everyone who copies this file
                                 └ fix: did you mean `requests`?
  ✖ CRITICAL requirements.txt:5  cv2  does not exist on PyPI
                                 `cv2` is the import name of `opencv-python`, and nobody owns it on PyPI yet: anyone can register it and ship malware to everyone who copies this file
                                 └ fix: did you mean `opencv-python`?
  ✖ HIGH     package.json:6      axois  impersonates 'axios'?
                                 one typo away from the popular `axios`, but little-known (1 release(s), first published 2019-08-29)
                                 └ fix: did you mean `axios`?
  …

 SECRETS
  ✖ CRITICAL .env:1  sk-p…****  OpenAI API key
                     └ fix: rotate it in the OpenAI dashboard and read it from an environment variable

 CODE
  ✖ HIGH     app.py:11     return db.execute(f"SELECT * FROM users WHERE id = {uid}").fetchone()  SQL built from strings
                           └ fix: use parameters: cursor.execute("... WHERE id = %s", (user_id,))
  ✖ HIGH     app.py:14     return requests.get(url, verify=False).json()  TLS verification turned off
                           └ fix: fix the certificate chain (or pass a CA bundle) instead of disabling verification
  ⚠ MEDIUM   src/api.ts:3  const claims = jwt.decode(token);  jwt.decode() does not verify
                           └ fix: use jwt.verify() before trusting any claim
  …

 CONFIG
  ✖ HIGH     .env:1  .env file not in .gitignore
                     one `git add .` away from publishing every secret in it
                     └ fix: add `.env` to .gitignore and commit a `.env.example` instead

 7 critical  ·  5 high  ·  3 medium  ·  1 low
```

This is real output against the live registries. `axois` is a real npm package: published once, in 2019, under a one-letter swap of a library with over 140 million weekly downloads.

## What it checks

**Dependencies** in `requirements*.txt`, `pyproject.toml` (PEP 621, PEP 735 groups, Poetry) and `package.json`:

| Finding | Severity |
|---|---|
| package does not exist on PyPI / npm (or was unpublished) | critical |
| registered in the last 30 days | high |
| one typo or a decorative affix (`-py`, `python-`, `-sdk`…) away from a popular package, and little-known | high |
| npm package runs `preinstall` / `install` / `postinstall` scripts | high if new or look-alike, else medium |
| import name used as package name (`sklearn`, `cv2`, `yaml`, `PIL`, `jwt`, `dotenv`…) | medium |
| established package that is still one typo away from a popular one | low |
| npm package with under 100 downloads a week | low |

**Secrets** in every text file: AWS, GitHub, OpenAI, Anthropic, Stripe live, Slack and Google API keys, private keys, and hard-coded passwords and tokens. Values are **masked** in the output (`sk-p…****`) so the report itself is safe to paste into a ticket.

**Code** (Python, JS/TS, notebooks): Flask/Django debug on, hard-coded `SECRET_KEY`, `verify=False`, `rejectUnauthorized: false`, `yaml.load` without a safe loader, `pickle.loads`, `shell=True`, SQL built with f-strings / `%` / `+`, `eval` on input, CORS open to `*`, JWT `alg: none`, `jwt.decode` used as if it verified, `exec` with template strings, `innerHTML` / `dangerouslySetInnerHTML`, tokens in `localStorage`.

**Config:** a `.env` file that `.gitignore` does not cover.

## Validated against the real registries

| Project | Result |
|---|---|
| AI-style demo app (invented packages, typos, import-name mix-ups, leaked key, classic slips) | every planted problem found, plus a real 2019 squat (`axois`) |
| Real Django + Next.js/shadcn stack, **48 legitimate dependencies** | 0 critical, 0 high, 0 medium · 1 low (`pyaml` vs `pyyaml`, which really is worth a second look) |

## Design decisions

- **Popular packages skip the network.** About 500 hand-curated well-known names are known to exist and to be what they claim, so only unfamiliar names are looked up. With npm's small *abbreviated* metadata instead of the full documents (which reach several MB for big packages), the 48-dependency scan went from 22 s to about 4 s.
- **Look-alike detection is deliberately conservative:** Damerau-Levenshtein distance 1 (a swapped pair counts as one typo), names under 5 characters skipped, scoped npm packages (`@org/x`) skipped because the scope owner controls them, and popular-vs-popular pairs such as `preact`/`react` never flagged.
- **Age and history decide the severity:** a look-alike with years of releases and real downloads is a *low* "double-check", but the same name registered last week is *high*.
- **An ignored `.env` is not scanned:** that file is exactly where secrets belong. One that `.gitignore` does not cover is flagged together with its contents.
- **Network errors are reported, never guessed:** an unreachable registry produces "could not verify", not a false *critical*.
- **Privacy:** only package **names** go to the public PyPI and npm APIs, never code or secrets. `--offline` sends nothing at all.

## Install

```bash
pip install git+https://github.com/njuj/slopcheck
```

## Usage

```bash
slopcheck                         # scan the current project
slopcheck path/to/app --json      # machine-readable
slopcheck --offline               # no network: name, secret and code checks only
slopcheck --fail-on medium        # stricter gate (default: high)
slopcheck --exclude "tests/*"     # skip paths (node_modules, venv, dist… are always skipped)
```

Silence a reviewed line with a trailing `# slopcheck: ignore` or `// slopcheck: ignore` comment.

**Exit codes:** `0` nothing at or above `--fail-on` · `1` findings at or above it · `2` error

### As a pre-commit hook

```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/njuj/slopcheck
    rev: v0.1.0
    hooks:
      - id: slopcheck
```

### In CI

```yaml
- run: pip install git+https://github.com/njuj/slopcheck
- run: slopcheck . --fail-on high
```

## Limitations

- Lockfiles (`package-lock.json`, `poetry.lock`, `uv.lock`) are not read yet, only direct dependencies.
- Code rules are line-based regexes. A call split over several lines can slip through. They are tripwires for the most common slips, not a replacement for a SAST tool.
- The popular-package list is curated by hand: good at catching imitations of famous names, blind to look-alikes of niche ones.

## Layout

```
slopcheck/
├── manifests.py   requirements / pyproject / package.json parsing
├── names.py       popular lists, Damerau-Levenshtein look-alikes, import-name mix-ups
├── registry.py    PyPI + npm lookups (threaded, abbreviated npm metadata)
├── deps.py        registry facts → findings and severities
├── rules.py       secret + code rules, masking, inline ignore
├── scanner.py     project walk, .env / .gitignore logic, notebooks
└── cli.py         argparse, renderer, exit codes
tests/             46 offline tests: registries are stubbed, secrets are assembled at runtime
```

```bash
python -m unittest discover -s tests -v
```

---

<sub>built by <a href="https://github.com/njuj">kira</a> · trust nothing, verify everything, including the code your AI wrote</sub>
