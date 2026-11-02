import unittest

from slopcheck.manifests import parse_package_json, parse_pyproject, parse_requirement, parse_requirements
from slopcheck.names import canonical, edit_distance, import_name_mixup, is_popular, lookalike


class RequirementsTest(unittest.TestCase):
    def test_names_specifiers_extras_markers(self):
        text = "\n".join([
            "# comment", "", "requests>=2.31", "Flask[async]==3.0.0 ; python_version >= '3.11'",
            "numpy~=1.26  # trailing comment", "-r other.txt", "-e .", "--index-url https://example.org/simple",
            "git+https://github.com/a/b.git", "https://example.org/pkg.whl", "./local/pkg",
            "mylib @ https://example.org/mylib-1.0.tar.gz", "zope.interface", "pyyaml",
        ])
        deps = parse_requirements(text, "requirements.txt")
        self.assertEqual([d.name for d in deps], ["requests", "Flask", "numpy", "mylib", "zope.interface", "pyyaml"])
        self.assertEqual([d.line for d in deps], [3, 4, 5, 12, 13, 14])
        self.assertFalse(next(d for d in deps if d.name == "mylib").from_registry)
        self.assertTrue(all(d.from_registry for d in deps if d.name != "mylib"))

    def test_direct_reference_with_extras(self):
        self.assertEqual(parse_requirement("pkg[cli] @ git+https://x/y.git"), ("pkg", False))
        self.assertEqual(parse_requirement("pkg>=1"), ("pkg", True))


class PyprojectTest(unittest.TestCase):
    def test_pep621_optional_groups_and_poetry(self):
        text = """
[project]
name = "demo"
dependencies = ["httpx>=0.27", "rich"]
[project.optional-dependencies]
dev = ["pytest"]
[dependency-groups]
lint = ["ruff", {include-group = "dev"}]
[tool.poetry.dependencies]
python = "^3.11"
fastapi = "^0.110"
internal = { path = "../internal" }
"""
        deps = parse_pyproject(text, "pyproject.toml")
        self.assertEqual([d.name for d in deps], ["httpx", "rich", "pytest", "ruff", "fastapi", "internal"])
        self.assertFalse(deps[-1].from_registry)
        self.assertEqual(deps[0].line, 4)


class PackageJsonTest(unittest.TestCase):
    def test_sections_and_non_registry_specs(self):
        text = """{
  "name": "app",
  "dependencies": {"express": "^4.19.2", "@scope/ui": "1.0.0", "local": "file:../local"},
  "devDependencies": {"vitest": "^1.6.0", "fork": "user/repo#main", "mono": "workspace:*"}
}"""
        deps = parse_package_json(text, "package.json")
        self.assertEqual([d.name for d in deps], ["express", "@scope/ui", "local", "vitest", "fork", "mono"])
        self.assertEqual([d.from_registry for d in deps], [True, True, False, True, False, False])
        self.assertTrue(all(d.ecosystem == "npm" for d in deps))
        self.assertEqual(deps[0].line, 3)


class NamesTest(unittest.TestCase):
    def test_canonical(self):
        self.assertEqual(canonical("Zope.Interface", "pypi"), "zope-interface")
        self.assertEqual(canonical("python_dateutil", "pypi"), "python-dateutil")
        self.assertTrue(is_popular("PyYAML", "pypi"))
        self.assertTrue(is_popular("discord.py", "pypi"))

    def test_edit_distance_counts_swaps_as_one(self):
        self.assertEqual(edit_distance("axios", "axois"), 1)
        self.assertEqual(edit_distance("requests", "reqeusts"), 1)
        self.assertEqual(edit_distance("lodash", "lodahs"), 1)
        self.assertEqual(edit_distance("flask", "django"), 5)

    def test_typos_and_affixes(self):
        self.assertEqual(lookalike("reqeusts", "pypi"), "requests")
        self.assertEqual(lookalike("requests-py", "pypi"), "requests")
        self.assertEqual(lookalike("python-openai", "pypi"), "openai")
        self.assertEqual(lookalike("axois", "npm"), "axios")
        self.assertEqual(lookalike("expresss", "npm"), "express")

    def test_not_lookalikes(self):
        self.assertIsNone(lookalike("requests", "pypi"))      # the real thing
        self.assertIsNone(lookalike("preact", "npm"))         # popular in its own right, one letter from react
        self.assertIsNone(lookalike("redux", "npm"))
        self.assertIsNone(lookalike("rq", "pypi"))            # too short to judge
        self.assertIsNone(lookalike("@acme/lodash", "npm"))   # scoped packages are owned by the scope
        self.assertIsNone(lookalike("my-internal-tool", "pypi"))

    def test_import_name_mixups(self):
        self.assertEqual(import_name_mixup("sklearn", "pypi"), "scikit-learn")
        self.assertEqual(import_name_mixup("cv2", "pypi"), "opencv-python")
        self.assertEqual(import_name_mixup("PIL", "pypi"), "pillow")
        self.assertIsNone(import_name_mixup("yaml", "npm"))


if __name__ == "__main__":
    unittest.main()
