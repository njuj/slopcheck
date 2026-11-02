import io
import json
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock

from slopcheck import cli
from slopcheck.deps import assess
from slopcheck.model import Dependency, PackageInfo
from slopcheck.registry import npm_info, pypi_info
from slopcheck.rules import mask, scan_line
from slopcheck.scanner import scan

NOW = datetime(2026, 11, 2, tzinfo=timezone.utc)
OLD = NOW - timedelta(days=2000)

# Secret-shaped strings are assembled at runtime so this repository never contains a literal token.
GH_TOKEN = "gh" + "p_" + "a1B2c3D4" * 4 + "e5F6"
OPENAI_KEY = "sk-" + "proj-" + "Xy9" * 14
AWS_KEY = "AK" + "IA" + "Q3EGXZ7KLMN4P2RT"


def dep(name, ecosystem="pypi", **kw):
    return Dependency(name, ecosystem, "requirements.txt", 3, **kw)


def titles(findings):
    return [(f.severity, f.title) for f in findings]


class RegistryParsingTest(unittest.TestCase):
    def test_pypi_document(self):
        doc = {"releases": {
            "0.1": [{"upload_time_iso_8601": "2026-10-30T10:00:00.000000Z"}],
            "0.2": [{"upload_time_iso_8601": "2026-10-31T10:00:00.000000Z"}],
            "0.3": [],  # yanked / no files
        }}
        info = pypi_info(doc)
        self.assertEqual((info.exists, info.releases), (True, 2))
        self.assertEqual(info.created, datetime(2026, 10, 30, 10, tzinfo=timezone.utc))
        self.assertFalse(pypi_info({"releases": {}}).exists)

    def test_npm_document(self):
        doc = {"dist-tags": {"latest": "1.0.1"}, "time": {"created": "2026-10-29T08:00:00.000Z"},
               "versions": {"1.0.0": {}, "1.0.1": {"scripts": {"postinstall": "node x.js", "test": "jest"}}}}
        info = npm_info(doc, 12)
        self.assertEqual((info.releases, info.weekly_downloads, info.install_scripts), (2, 12, ["postinstall"]))
        self.assertFalse(npm_info({"time": {"unpublished": {}}}, None).exists)

    def test_npm_abbreviated_document(self):
        doc = {"dist-tags": {"latest": "2.0.0"}, "versions": {f"1.{i}.0": {} for i in range(30)} |
               {"2.0.0": {"hasInstallScript": True}}}
        info = npm_info(doc, 5000)
        self.assertEqual((info.created, info.releases, info.install_scripts), (None, 31, ["install"]))

    def test_many_versions_count_as_history(self):
        # abbreviated metadata has no creation date; 31 versions is history enough to not call it an impersonator
        f = assess(dep("axois", "npm"), PackageInfo(True, None, 31, 5000), NOW)
        self.assertEqual(titles(f), [("low", "similar to 'axios'")])


class AssessTest(unittest.TestCase):
    def test_missing_package_is_critical_with_suggestion(self):
        f = assess(dep("reqeusts"), PackageInfo(exists=False), NOW)
        self.assertEqual(titles(f), [("critical", "does not exist on PyPI")])
        self.assertIn("requests", f[0].fix)

    def test_missing_import_name(self):
        f = assess(dep("cv2"), PackageInfo(exists=False), NOW)
        self.assertEqual(titles(f), [("critical", "does not exist on PyPI")])  # one finding, not two
        self.assertIn("import name", f[0].detail)
        self.assertIn("opencv-python", f[0].fix)
        self.assertEqual(titles(assess(dep("cv2"), None, NOW)),
                         [("medium", "'cv2' is an import name, not the package")])

    def test_brand_new_package(self):
        f = assess(dep("flask-auth-magic"), PackageInfo(True, NOW - timedelta(days=3), 1), NOW)
        self.assertEqual(titles(f), [("high", "registered 3 day(s) ago")])

    def test_young_lookalike(self):
        f = assess(dep("axois", "npm"), PackageInfo(True, NOW - timedelta(days=60), 2, 40, ["postinstall"]), NOW)
        self.assertEqual(titles(f), [("high", "impersonates 'axios'?"), ("high", "runs code at install time")])

    def test_established_lookalike_is_low(self):
        f = assess(dep("pyaml"), PackageInfo(True, OLD, 40), NOW)
        self.assertEqual(titles(f), [("low", "similar to 'pyyaml'")])

    def test_popular_and_non_registry_skip_lookups(self):
        self.assertEqual(assess(dep("requests"), None, NOW), [])
        self.assertEqual(assess(dep("whatever-private", from_registry=False), PackageInfo(False), NOW), [])

    def test_install_script_on_established_package_is_medium(self):
        f = assess(dep("esbuild-wasm", "npm"), PackageInfo(True, OLD, 300, 900000, ["postinstall"]), NOW)
        self.assertEqual(titles(f), [("medium", "runs code at install time")])

    def test_barely_used(self):
        f = assess(dep("tiny-helper", "npm"), PackageInfo(True, OLD, 5, 7), NOW)
        self.assertEqual(titles(f), [("low", "barely used")])

    def test_offline_mode(self):
        self.assertEqual(titles(assess(dep("reqeusts"), None, NOW)), [("medium", "looks like 'requests'")])
        self.assertEqual(assess(dep("some-real-thing"), None, NOW), [])

    def test_network_error_is_reported_not_guessed(self):
        f = assess(dep("some-real-thing"), PackageInfo(True, error="timed out"), NOW)
        self.assertEqual(titles(f), [("low", "could not verify on PyPI")])


class RulesTest(unittest.TestCase):
    def ids(self, line, suffix=".py"):
        return [rule.id for rule, _ in scan_line(line, suffix)]

    def test_secrets_are_found_and_masked(self):
        hits = scan_line(f'GITHUB_TOKEN = "{GH_TOKEN}"', ".py")
        self.assertEqual([r.id for r, _ in hits], ["github-token"])
        self.assertEqual(hits[0][1], "ghp_…****")
        self.assertNotIn(GH_TOKEN[8:], hits[0][1])
        self.assertEqual(self.ids(f"aws_access_key_id={AWS_KEY}", ".env"), ["aws-access-key"])
        self.assertEqual(self.ids(f'api_key = "{OPENAI_KEY}"'), ["openai-key"])  # not double-reported

    def test_placeholders_are_not_secrets(self):
        for line in ('password = "your-password-here"', 'api_key: "<YOUR_API_KEY>"', 'password = "${DB_PASSWORD}"',
                     'token = os.environ["TOKEN"]', 'password = "short"'):
            with self.subTest(line=line):
                self.assertEqual(self.ids(line), [])
        self.assertEqual(self.ids('password = "Tr0ub4dor&3xyz"'), ["hardcoded-credential"])

    def test_python_slips(self):
        cases = {
            "app.run(host='0.0.0.0', debug=True)": "flask-debug",
            "DEBUG = True": "django-debug",
            "SECRET_KEY = 'django-insecure-abc'": "hardcoded-secret-key",
            "requests.get(url, verify=False)": "requests-verify-false",
            "cfg = yaml.load(f)": "yaml-unsafe-load",
            "obj = pickle.loads(blob)": "pickle-load",
            "subprocess.run(cmd, shell=True)": "subprocess-shell",
            'cur.execute(f"SELECT * FROM users WHERE id = {uid}")': "sql-string-building",
            "cur.execute(\"SELECT * FROM t WHERE a = '%s'\" % a)": "sql-string-building",
            "eval(input())": "eval-user-input",
            'app.add_middleware(CORSMiddleware, allow_origins=["*"])': "cors-allow-all-py",
            "CORS(app)": "cors-allow-all-py",
        }
        for line, rule_id in cases.items():
            with self.subTest(line=line):
                self.assertIn(rule_id, self.ids(line))

    def test_python_safe_forms(self):
        for line in ("cfg = yaml.load(f, Loader=yaml.SafeLoader)", "cfg = yaml.safe_load(f)",
                     'cur.execute("SELECT * FROM users WHERE id = %s", (uid,))', "app.run(debug=False)",
                     "requests.get(url, verify=True)", "CORS(app, origins=['https://example.org'])"):
            with self.subTest(line=line):
                self.assertEqual(self.ids(line), [])

    def test_js_slips(self):
        cases = {
            "process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0'": "tls-reject-off",
            "https.request({ rejectUnauthorized: false })": "tls-reject-off",
            "jwt.verify(t, key, { algorithms: ['HS256', 'none'] })": "jwt-alg-none",
            "const claims = jwt.decode(token)": "jwt-decode-unverified",
            "exec(`git clone ${repo}`)": "exec-template",
            "const v = eval(userInput)": "eval-js",
            "<div dangerouslySetInnerHTML={{ __html: html }} />": "dangerously-set-html",
            "el.innerHTML = comment.body": "innerhtml-assign",
            "app.use(cors())": "cors-allow-all-js",
            "localStorage.setItem('authToken', t)": "token-in-localstorage",
        }
        for line, rule_id in cases.items():
            with self.subTest(line=line):
                self.assertIn(rule_id, self.ids(line, ".ts"))

    def test_js_safe_forms(self):
        for line in ('el.innerHTML = "";', "el.textContent = comment.body", "app.use(cors({ origin: 'https://a.b' }))",
                     "JSON.parse(text)", "model.evaluate(x)"):
            with self.subTest(line=line):
                self.assertEqual(self.ids(line, ".js"), [])

    def test_rules_respect_language(self):
        self.assertEqual(self.ids("DEBUG = True", ".js"), [])
        self.assertEqual(self.ids("app.use(cors())", ".py"), [])

    def test_inline_ignore(self):
        self.assertEqual(self.ids("requests.get(url, verify=False)  # slopcheck: ignore"), [])
        self.assertEqual(self.ids("app.use(cors()) // slopcheck: ignore", ".js"), [])

    def test_mask(self):
        self.assertEqual(mask("abc"), "********")


class ProjectTest(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)

    def tearDown(self):
        self._tmp.cleanup()

    def write(self, rel, text):
        p = self.root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8")

    def test_env_file_must_be_ignored(self):
        self.write(".env", f"OPENAI_API_KEY={OPENAI_KEY}\n")
        report = scan(self.root, online=False)
        self.assertEqual(sorted(f.title for f in report.findings), [".env file not in .gitignore", "OpenAI API key"])
        self.write(".gitignore", "node_modules/\n.env\n")
        self.assertEqual(scan(self.root, online=False).findings, [])

    def test_env_example_is_fine(self):
        self.write(".env.example", "OPENAI_API_KEY=your-key-here\n")
        self.assertEqual(scan(self.root, online=False).findings, [])

    def test_skips_vendored_dirs_and_excludes(self):
        self.write("node_modules/x/index.js", "eval(x)")
        self.write("legacy/old.py", "DEBUG = True")
        self.write("app.py", "DEBUG = True")
        report = scan(self.root, online=False, exclude=["legacy"])
        self.assertEqual([f.file for f in report.findings], ["app.py"])

    def test_notebook_cells(self):
        nb = {"cells": [{"cell_type": "code", "source": ["import requests\n", "requests.get(u, verify=False)"]}]}
        self.write("analysis.ipynb", json.dumps(nb))
        findings = scan(self.root, online=False).findings
        self.assertEqual([(f.title, f.line) for f in findings], [("TLS verification turned off", 2)])

    def test_registry_results_flow_into_report(self):
        self.write("requirements.txt", "requests\nreqeusts\nflask-auth-magic\n")
        stub = mock.Mock()
        stub.lookup_all.return_value = {("pypi", "reqeusts"): PackageInfo(exists=False),
                                        ("pypi", "flask-auth-magic"): PackageInfo(True, NOW - timedelta(days=2), 1)}
        report = scan(self.root, online=True, registry=stub)
        looked_up = [d.name for d in stub.lookup_all.call_args.args[0]]
        self.assertEqual(looked_up, ["reqeusts", "flask-auth-magic"])  # popular `requests` needs no lookup
        self.assertEqual([(f.subject, f.severity) for f in report.findings],
                         [("reqeusts", "critical"), ("flask-auth-magic", "high")])


class CLITest(ProjectTest):
    def run_cli(self, *argv):
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            code = cli.main([str(a) for a in argv])
        return code, out.getvalue(), err.getvalue()

    def test_exit_codes_follow_fail_on(self):
        self.write("app.py", "obj = pickle.loads(blob)\n")  # medium
        self.assertEqual(self.run_cli(self.root, "--offline")[0], 0)
        self.assertEqual(self.run_cli(self.root, "--offline", "--fail-on", "medium")[0], 1)

    def test_json_and_text(self):
        self.write("app.py", "app.run(debug=True)\n")
        code, out, _ = self.run_cli(self.root, "--offline", "--json")
        doc = json.loads(out)
        self.assertEqual((code, doc["online"], doc["findings"][0]["title"]), (1, False, "Flask debug mode in code"))
        code, out, _ = self.run_cli(self.root, "--offline", "--no-color")
        self.assertIn("CODE", out)
        self.assertIn("fix:", out)

    def test_clean_project(self):
        self.write("app.py", "print('hello')\n")
        code, out, _ = self.run_cli(self.root, "--offline", "--no-color")
        self.assertEqual(code, 0)
        self.assertIn("nothing found", out)

    def test_bad_path(self):
        self.assertEqual(self.run_cli(self.root / "missing")[0], 2)


if __name__ == "__main__":
    unittest.main()
