"""Lockfiles and the OSV.dev checks. OSV is stubbed with documents shaped like its real answers."""

import json
import tempfile
import textwrap
import unittest
from pathlib import Path
from unittest import mock

from slopcheck import osv
from slopcheck.lockfiles import (parse_package_lock, parse_pipfile_lock, parse_pnpm_lock, parse_toml_lock,
                                 parse_yarn_lock)
from slopcheck.manifests import parse_package_json, parse_requirements
from slopcheck.model import Dependency
from slopcheck.scanner import scan


def pairs(deps):
    return [(d.name, d.version, d.from_registry) for d in deps]


class LockfileTest(unittest.TestCase):
    def test_package_lock_v3_and_v1(self):
        v3 = json.dumps({"lockfileVersion": 3, "packages": {
            "": {"name": "app", "dependencies": {"lodash": "^4.17.0"}},
            "node_modules/lodash": {"version": "4.17.15", "resolved": "https://registry.npmjs.org/lodash/-/lodash-4.17.15.tgz"},
            "node_modules/a/node_modules/@babel/core": {"version": "7.0.0"},
            "node_modules/local": {"version": "1.0.0", "resolved": "file:../local"},
            "node_modules/linked": {"link": True, "resolved": "packages/linked"},
        }}, indent=2)
        deps = parse_package_lock(v3, "package-lock.json")
        self.assertEqual(pairs(deps), [("lodash", "4.17.15", True), ("@babel/core", "7.0.0", True),
                                       ("local", "1.0.0", False)])
        self.assertEqual(deps[1].line, v3.splitlines().index('    "node_modules/a/node_modules/@babel/core": {') + 1)
        self.assertFalse(deps[0].direct)
        v1 = json.dumps({"lockfileVersion": 1, "dependencies": {
            "minimist": {"version": "0.0.8", "dependencies": {"left-pad": {"version": "1.1.3"}}}}})
        self.assertEqual(pairs(parse_package_lock(v1, "x")), [("minimist", "0.0.8", True), ("left-pad", "1.1.3", True)])

    def test_yarn_and_pnpm(self):
        yarn = textwrap.dedent('''\
            # yarn lockfile v1


            "@types/node@^20.0.0", "@types/node@^20.1.0":
              version "20.11.5"
              resolved "https://registry.yarnpkg.com/@types/node/-/node-20.11.5.tgz"

            lodash@^4.17.0:
              version "4.17.15"

            mylib@file:../mylib:
              version "0.0.1"
            ''')
        self.assertEqual(pairs(parse_yarn_lock(yarn, "yarn.lock")),
                         [("@types/node", "20.11.5", True), ("lodash", "4.17.15", True), ("mylib", "0.0.1", False)])
        berry = 'lodash@npm:^4.17.0:\n  version: 4.17.21\n  resolution: "lodash@npm:4.17.21"\n'
        self.assertEqual(pairs(parse_yarn_lock(berry, "yarn.lock")), [("lodash", "4.17.21", True)])
        pnpm = textwrap.dedent('''\
            lockfileVersion: '9.0'
            importers:
              .:
                dependencies:
                  lodash:
                    specifier: ^4.17.0
            packages:
              '@babel/core@7.24.0':
                resolution: {integrity: sha512-x}
              lodash@4.17.15:
                resolution: {integrity: sha512-y}
              /old-style/1.2.3:
                resolution: {integrity: sha512-z}
            snapshots:
              lodash@4.17.15: {}
            ''')
        self.assertEqual(pairs(parse_pnpm_lock(pnpm, "pnpm-lock.yaml")),
                         [("@babel/core", "7.24.0", True), ("lodash", "4.17.15", True), ("old-style", "1.2.3", True)])

    def test_poetry_uv_pipenv(self):
        poetry = textwrap.dedent('''\
            [[package]]
            name = "django"
            version = "3.2.0"

            [[package]]
            name = "mylib"
            version = "0.1.0"

            [package.source]
            type = "git"
            url = "https://example.invalid/mylib.git"
            ''')
        self.assertEqual(pairs(parse_toml_lock(poetry, "poetry.lock")), [("django", "3.2.0", True), ("mylib", "0.1.0", False)])
        uv = textwrap.dedent('''\
            version = 1
            [[package]]
            name = "app"
            version = "0.1.0"
            source = { editable = "." }

            [[package]]
            name = "jinja2"
            version = "2.10"
            source = { registry = "https://pypi.org/simple" }
            ''')
        self.assertEqual(pairs(parse_toml_lock(uv, "uv.lock")), [("app", "0.1.0", False), ("jinja2", "2.10", True)])
        pipenv = json.dumps({"default": {"requests": {"version": "==2.19.0"}}, "develop": {"pytest": {"version": "*"}}})
        self.assertEqual(pairs(parse_pipfile_lock(pipenv, "Pipfile.lock")), [("requests", "2.19.0", True)])

    def test_manifest_pins(self):
        reqs = parse_requirements("django==3.2.0\nflask>=2\nrequests == 2.19.0 ; python_version > '3'\nx==1.*\n", "r.txt")
        self.assertEqual([d.version for d in reqs], ["3.2.0", None, "2.19.0", None])
        pkg = parse_package_json('{"dependencies": {"lodash": "4.17.15", "react": "^18.2.0", "vue": "v3.4.0"}}', "p")
        self.assertEqual([d.version for d in pkg], ["4.17.15", None, "3.4.0"])


MALWARE = {"id": "GHSA-c2m4-w5hm-vqjw", "summary": "crossenv is malware", "aliases": ["CVE-2017-16074"],
           "database_specific": {"cwe_ids": ["CWE-506"], "severity": "HIGH"},
           "affected": [{"package": {"name": "crossenv", "ecosystem": "npm"}}]}
MAL_ID = {"id": "MAL-2025-1234", "summary": "Malicious code in reqeusts (PyPI)", "affected": []}


def vuln(id_, severity, fixed, cve, name="lodash", ecosystem="npm", aliases=()):
    return {"id": id_, "summary": f"problem {id_}", "aliases": [cve, *aliases],
            "database_specific": {"severity": severity} if severity else {},
            "affected": [{"package": {"name": name, "ecosystem": ecosystem},
                          "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": fixed}]}]}]}


class FakeOSV:
    def __init__(self, hits, docs):
        self.hits, self.docs, self.asked = hits, docs, None

    def query(self, deps):
        self.asked = [(d.name, d.version) for d in deps]
        return {(d.ecosystem, osv.canonical(d.name, d.ecosystem), d.version): self.hits.get((d.name, d.version), [])
                for d in deps}

    def details(self, ids):
        return {i: self.docs[i] for i in ids if i in self.docs}


class OSVTest(unittest.TestCase):
    DOCS = {d["id"]: d for d in [
        MALWARE, MAL_ID,
        vuln("GHSA-35jh-r3h4-6jhm", "HIGH", "4.17.21", "CVE-2021-23337"),
        vuln("GHSA-p6mc-m468-83gw", "HIGH", "4.17.19", "CVE-2020-8203"),
        vuln("GHSA-29mw-wpgm-hmr9", "MODERATE", "4.17.21", "CVE-2020-28500"),
        vuln("GHSA-aaaa-django", "CRITICAL", "3.2.25", "CVE-2024-0001", "Django", "PyPI"),
        vuln("PYSEC-2024-1", None, "3.2.25", "CVE-2024-0001", "django", "PyPI", aliases=("GHSA-aaaa-django",)),
    ]}

    def test_malware_vulnerabilities_and_fix_version(self):
        deps = [Dependency("crossenv", "npm", "package.json", 5),
                Dependency("lodash", "npm", "package.json", 6, version="4.17.15"),
                Dependency("Django", "pypi", "requirements.txt", 1, version="3.2.0"),
                Dependency("django", "pypi", "poetry.lock", 9, version="3.2.0", direct=False),   # same package: once
                Dependency("left-pad", "npm", "package-lock.json", 40, version="1.3.0", direct=False),
                Dependency("requests", "pypi", "requirements.txt", 2)]                        # unpinned, old CVEs: quiet
        fake = FakeOSV({("crossenv", None): ["GHSA-c2m4-w5hm-vqjw"],
                        ("lodash", "4.17.15"): ["GHSA-35jh-r3h4-6jhm", "GHSA-p6mc-m468-83gw", "GHSA-29mw-wpgm-hmr9"],
                        ("Django", "3.2.0"): ["GHSA-aaaa-django", "PYSEC-2024-1"],
                        ("django", "3.2.0"): ["GHSA-aaaa-django", "PYSEC-2024-1"],
                        ("requests", None): ["GHSA-j8r2-6x86-q33q"]}, self.DOCS)
        got = osv.check(deps, fake)
        self.assertEqual([(f.subject, f.severity, f.title, f.file) for f in got], [
            ("crossenv", "critical", "known malicious package", "package.json"),
            ("lodash", "high", "3 known vulnerabilities in 4.17.15", "package.json"),
            ("Django", "critical", "1 known vulnerability in 3.2.0", "requirements.txt"),
        ])
        self.assertIn("crossenv is malware (CVE-2017-16074)", got[0].detail)
        self.assertEqual(got[1].fix, "upgrade to 4.17.21 or later")
        self.assertIn("CVE-2021-23337, CVE-2020-8203, CVE-2020-28500", got[1].detail)

    def test_mal_ids_and_lockfile_wording(self):
        dep = Dependency("reqeusts", "pypi", "uv.lock", 12, version="0.0.1", direct=False)
        got = osv.check([dep], FakeOSV({("reqeusts", "0.0.1"): ["MAL-2025-1234"]}, self.DOCS))
        self.assertEqual((got[0].severity, got[0].title), ("critical", "known malicious package"))
        self.assertIn("installed through the lockfile", got[0].detail)

    def test_network_failure_is_reported_not_guessed(self):
        broken = mock.Mock(query=mock.Mock(side_effect=osv.OSVError("timed out")))
        got = osv.check([Dependency("lodash", "npm", "package.json", 1, version="4.17.15")], broken)
        self.assertEqual([(f.severity, f.title) for f in got],
                         [("low", "could not check OSV.dev for known malware and vulnerabilities")])

    def test_non_registry_packages_are_not_sent(self):
        fake = FakeOSV({}, {})
        osv.check([Dependency("mylib", "pypi", "x", 1, from_registry=False), Dependency("ok", "npm", "x", 1)], fake)
        self.assertEqual(fake.asked, [("ok", None)])

    def test_version_order(self):
        self.assertLess(osv._version_key("4.17.9"), osv._version_key("4.17.21"))
        self.assertLess(osv._version_key("2.0.0-rc1"), osv._version_key("2.0.0"))
        self.assertLess(osv._version_key("1.2"), osv._version_key("1.10.0"))


class ProjectWithLockfileTest(unittest.TestCase):
    def test_lockfile_versions_reach_osv_and_fill_direct_deps(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            (root / "package.json").write_text('{"dependencies": {"lodash": "^4.17.0"}}')
            (root / "package-lock.json").write_text(json.dumps({"lockfileVersion": 3, "packages": {
                "node_modules/lodash": {"version": "4.17.15"}, "node_modules/minimist": {"version": "0.0.8"}}}))
            fake = FakeOSV({("lodash", "4.17.15"): ["GHSA-35jh-r3h4-6jhm"]}, OSVTest.DOCS)
            registry = mock.Mock(lookup_all=mock.Mock(return_value={}))
            report = scan(root, online=True, registry=registry, osv_client=fake)
            self.assertEqual(fake.asked, [("lodash", "4.17.15"), ("lodash", "4.17.15"), ("minimist", "0.0.8")])
            self.assertEqual([(f.subject, f.file, f.line) for f in report.findings], [("lodash", "package.json", 1)])
            self.assertEqual(len(report.locked), 2)
            offline = scan(root, online=False)
            self.assertEqual(offline.findings, [])

    def test_editable_self_reference_and_malware_wins(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            (root / "pyproject.toml").write_text('[project]\nname = "app"\ndependencies = ["app[cli]", "crossenv"]\n')
            (root / "uv.lock").write_text('[[package]]\nname = "app"\nversion = "0.0.0"\nsource = { editable = "." }\n')
            fake = FakeOSV({("crossenv", None): ["GHSA-c2m4-w5hm-vqjw"]}, OSVTest.DOCS)
            registry = mock.Mock(lookup_all=mock.Mock(return_value={}))
            report = scan(root, online=True, registry=registry, osv_client=fake)
            self.assertEqual(fake.asked, [("crossenv", None)])              # the project itself is not looked up
            self.assertEqual([(f.subject, f.title) for f in report.findings], [("crossenv", "known malicious package")])

    def test_fix_is_the_nearest_on_each_advisory(self):
        multi = {"id": "GHSA-multi", "database_specific": {"severity": "HIGH"}, "aliases": [], "affected": [
            {"package": {"name": "undici", "ecosystem": "npm"}, "ranges": [{"type": "SEMVER", "events": [
                {"introduced": "0"}, {"fixed": "6.29.1"}, {"introduced": "7.0.0"}, {"fixed": "7.30.1"},
                {"introduced": "8.0.0"}, {"fixed": "8.12.2"}]}]}]}
        dep = Dependency("undici", "npm", "package-lock.json", 3, version="6.29.0", direct=False)
        got = osv.check([dep], FakeOSV({("undici", "6.29.0"): ["GHSA-multi"]}, {"GHSA-multi": multi}))
        self.assertEqual(got[0].fix, "upgrade to 6.29.1 or later")


if __name__ == "__main__":
    unittest.main()
