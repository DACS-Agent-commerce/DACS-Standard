import contextlib
import copy
import hashlib
import importlib.util
import io
import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SCRIPT_PATH = ROOT / "scripts" / "check_vendored_vectors.py"
V04_COMMIT = "4bb9e48a1095ab32c06c25b7c0b52018d3ce4091"
BIG = 2**53


def load_checker():
    spec = importlib.util.spec_from_file_location("check_vendored_vectors", SCRIPT_PATH)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


CHECKER = load_checker()


def make_set(name, vectors, spec="DACS-4 §9.5.9"):
    try:
        digest = hashlib.sha256(CHECKER.canonical_json(vectors)).hexdigest()
    except ValueError:
        digest = hashlib.sha256(json.dumps(vectors, separators=(",", ":")).encode()).hexdigest()
    return {"set": name, "spec": spec, "count": len(vectors), "hash": digest, "vectors": vectors}


STANDARD_SETS = {
    "alpha-v0.1": make_set("alpha-v0.1", [{"name": "a1", "expected": "pass", "input": {"n": 1}}]),
    "beta-v0.1": make_set(
        "beta-v0.1",
        [{"name": "b1", "expected": "fail", "input": "x"}, {"name": "b2", "expected": "pass", "input": True}],
    ),
}


def write_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")


class VendoredVectorDriftTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)
        self.standard = self.tmp / "standard"
        vectors = self.standard / "conformance" / "vectors"
        for name, data in STANDARD_SETS.items():
            write_json(vectors / "security" / f"{name}.json", data)
        write_json(vectors / "golden.json", {"signing": {}})
        (vectors / "security" / "README.md").write_text("not a set\n", encoding="utf-8")
        self.vendored = self.tmp / "vendor" / "dacs-vectors"
        shutil.copytree(vectors, self.vendored)

    def tearDown(self):
        self._tmp.cleanup()

    def run_checker(self, *args, standard=None, vendored=None):
        argv = [str(vendored or self.vendored), "--standard", str(standard or self.standard), "--json", *args]
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = CHECKER.main(argv)
        return code, json.loads(out.getvalue())

    def vendored_set(self, name):
        return self.vendored / "security" / f"{name}.json"

    def edit_vendored(self, name, change):
        path = self.vendored_set(name)
        data = json.loads(path.read_text(encoding="utf-8"))
        change(data)
        write_json(path, data)

    def result_for(self, report, name):
        return next(result for result in report["sets"] if result["set"] == name)

    def test_no_drift_in_security_subdirectory(self):
        code, report = self.run_checker()
        self.assertEqual(code, 0)
        self.assertFalse(report["drift"])
        self.assertEqual(report["hashRule"], "sha256(canonical_json(vectors))")
        self.assertEqual(
            report["summary"],
            {"standard": 2, "vendored": 2, "match": 2, "drifted": 0, "missing": 0, "extra": 0,
             "uncheckable": 0, "ignoredJson": {"standard": 1, "vendored": 1}},
        )
        alpha = self.result_for(report, "alpha-v0.1")
        self.assertEqual(alpha["standardPath"], "security/alpha-v0.1.json")
        self.assertEqual(alpha["vendoredPath"], "security/alpha-v0.1.json")
        self.assertEqual(alpha["comparison"], "canonical-json-sha256+exact-json")
        self.assertEqual(alpha["contentHash"]["standard"], STANDARD_SETS["alpha-v0.1"]["hash"])

    def test_flat_vendored_layout_matches_by_set_name(self):
        flat = self.tmp / "flat"
        flat.mkdir()
        for path in (self.vendored / "security").glob("*.json"):
            shutil.copy(path, flat / path.name)
        code, report = self.run_checker(vendored=flat)
        self.assertEqual(code, 0)
        self.assertEqual(self.result_for(report, "beta-v0.1")["vendoredPath"], "beta-v0.1.json")

    def test_changed_vector_is_drift(self):
        self.edit_vendored("beta-v0.1", lambda data: data["vectors"][0].update(expected="pass"))
        code, report = self.run_checker()
        self.assertEqual(code, 1)
        beta = self.result_for(report, "beta-v0.1")
        self.assertEqual(beta["status"], "drifted")
        self.assertEqual(beta["changes"], ["vectors"])
        self.assertNotEqual(beta["contentHash"]["standard"], beta["contentHash"]["vendored"])
        self.assertEqual(report["summary"]["match"], 1)

    def test_missing_set(self):
        self.vendored_set("alpha-v0.1").unlink()
        code, report = self.run_checker()
        self.assertEqual(code, 1)
        alpha = self.result_for(report, "alpha-v0.1")
        self.assertEqual(alpha["status"], "missing")
        self.assertEqual(alpha["standardPath"], "security/alpha-v0.1.json")
        self.assertEqual(report["summary"]["missing"], 1)

    def test_extra_set(self):
        write_json(self.vendored / "security" / "gamma-v0.1.json", make_set("gamma-v0.1", [{"name": "g1"}]))
        code, report = self.run_checker()
        self.assertEqual(code, 1)
        gamma = self.result_for(report, "gamma-v0.1")
        self.assertEqual(gamma["status"], "extra")
        self.assertEqual(gamma["vendoredPath"], "security/gamma-v0.1.json")

    def test_stale_count(self):
        self.edit_vendored("beta-v0.1", lambda data: data.update(count=3))
        code, report = self.run_checker()
        self.assertEqual(code, 1)
        beta = self.result_for(report, "beta-v0.1")
        self.assertEqual(beta["changes"], ["count"])
        self.assertEqual(beta["count"], {"standard": 2, "vendored": 3, "vendoredVectors": 2})

    def test_changed_spec_or_declared_hash(self):
        self.edit_vendored("alpha-v0.1", lambda data: data.update(spec="DACS-4 v0.7 §9.5.9"))
        self.edit_vendored("beta-v0.1", lambda data: data.update(hash="0" * 64))
        code, report = self.run_checker()
        self.assertEqual(code, 1)
        self.assertEqual(self.result_for(report, "alpha-v0.1")["changes"], ["spec"])
        self.assertEqual(self.result_for(report, "beta-v0.1")["changes"], ["hash"])

    def test_refused_canonical_hash_uses_verified_declared_encoding(self):
        name = "wide-int-v0.1"
        data = make_set(name, [{"input": BIG}])
        path = self.standard / "conformance" / "vectors" / f"{name}.json"
        write_json(path, data)
        for replacement in (BIG, BIG + 1, str(BIG)):
            with self.subTest(replacement=replacement):
                write_json(self.vendored_set(name), make_set(name, [{"input": replacement}]))
                code, report = self.run_checker()
                result = self.result_for(report, name)
                self.assertEqual(code, 0 if replacement == BIG else 1)
                self.assertEqual(result["status"], "match" if replacement == BIG else "drifted")
                self.assertEqual(result["comparison"], "declared-encoding-sha256+parsed-json")
                self.assertIn("safe-integer", result["comparisonNote"])
                self.assertIsNone(result["contentHash"]["standard"])
                self.assertIsNotNone(result["comparisonHash"]["standard"])
                self.assertIn("declared-encoding", CHECKER.render_text(report))
                self.assertFalse(report["uncheckable"])

    def test_fallback_vector_edit_with_stale_declared_hash_is_drift(self):
        name = "wide-int-v0.1"
        data = make_set(name, [{"input": BIG, "name": "original"}])
        write_json(self.standard / "conformance" / "vectors" / f"{name}.json", data)
        write_json(self.vendored_set(name), data)
        self.edit_vendored(name, lambda value: value["vectors"][0].update(name="edited"))
        code, report = self.run_checker()
        result = self.result_for(report, name)
        self.assertEqual((code, result["status"], result["changes"]), (1, "drifted", ["vectors"]))
        self.assertEqual(result["comparison"], "declared-encoding-sha256+parsed-json")
        self.assertNotEqual(result["comparisonHash"]["standard"], result["comparisonHash"]["vendored"])
        self.assertTrue(all(result["comparisonHash"].values()))
        self.assertEqual(report["summary"]["uncheckable"], 0)

    def test_fallback_declared_hash_edit_with_identical_vectors_is_drift(self):
        name = "wide-int-v0.1"
        data = make_set(name, [{"input": BIG}])
        write_json(self.standard / "conformance" / "vectors" / f"{name}.json", data)
        write_json(self.vendored_set(name), dict(data, hash="0" * 64))
        code, report = self.run_checker()
        result = self.result_for(report, name)
        self.assertEqual((code, result["status"], result["changes"]), (1, "drifted", ["hash"]))
        self.assertEqual(result["comparison"], "declared-encoding-sha256+parsed-json")
        self.assertEqual(result["comparisonHash"]["standard"], result["comparisonHash"]["vendored"])
        self.assertEqual(result["comparisonHash"]["standard"], data["hash"])
        self.assertEqual(report["summary"]["uncheckable"], 0)

    def test_fallback_unencodable_vendored_copy_is_bad_input(self):
        name = "wide-int-v0.1"
        data = make_set(name, [{"input": BIG}])
        write_json(self.standard / "conformance" / "vectors" / f"{name}.json", data)
        write_json(self.vendored_set(name), data)
        self.edit_vendored(name, lambda value: value["vectors"][0].update(name="\ud800"))
        code, report = self.run_checker()
        self.assertEqual(code, 2)
        self.assertIn("cannot be hashed", report["error"])

    def test_neither_hash_available_is_uncheckable(self):
        name = "wide-int-v0.1"
        data = make_set(name, [{"input": BIG}])
        data["hash"] = "0" * 64
        write_json(self.standard / "conformance" / "vectors" / f"{name}.json", data)
        write_json(self.vendored_set(name), data)
        code, report = self.run_checker()
        result = self.result_for(report, name)
        self.assertEqual((code, result["status"]), (2, "uncheckable"))
        self.assertTrue(report["uncheckable"])
        self.assertIn("no canonical or verified declared-encoding hash", result["comparisonNote"])
        # A valid hash on the vendored side cannot choose the Standard's rule.
        write_json(self.vendored_set(name), make_set(name, [{"input": BIG}]))
        code, report = self.run_checker()
        self.assertEqual((code, self.result_for(report, name)["status"]), (2, "uncheckable"))

    def test_canonical_unicode_equality_does_not_hide_drift(self):
        name = "unicode-v0.1"
        data = make_set(name, [{"input": "e\u0301"}])
        write_json(self.standard / "conformance" / "vectors" / f"{name}.json", data)
        write_json(self.vendored_set(name), data)
        self.edit_vendored(name, lambda value: value["vectors"][0].update(input="\u00e9"))
        code, report = self.run_checker()
        result = self.result_for(report, name)
        self.assertEqual((code, result["status"], result["changes"]), (1, "drifted", ["vectors"]))
        self.assertEqual(result["contentHash"]["standard"], result["contentHash"]["vendored"])
        self.assertIn("differs as exact JSON", result["comparisonNote"])
        self.assertIn("differs as exact JSON", CHECKER.render_text(report))

    def test_missing_and_extra_status_is_independent_of_hash_availability(self):
        name = "wide-int-v0.1"
        for status, side, base in (
            ("missing", "standard", self.standard / "conformance" / "vectors"),
            ("extra", "vendored", self.vendored),
        ):
            for hash_available in (True, False):
                with self.subTest(status=status, hash_available=hash_available):
                    data = make_set(name, [{"input": BIG}])
                    if not hash_available:
                        data["hash"] = "0" * 64
                    path = base / f"{name}.json"
                    write_json(path, data)
                    code, report = self.run_checker()
                    result = self.result_for(report, name)
                    self.assertEqual((code, result["status"]), (1 if hash_available else 2, status))
                    self.assertEqual(report["summary"][status], 1)
                    self.assertEqual(report["summary"]["uncheckable"], 0 if hash_available else 1)
                    self.assertIn(status.upper(), CHECKER.render_text(report))
                    if not hash_available:
                        self.assertTrue(result["comparisonNote"].startswith(side + ":"))
                        self.assertIn("hash unavailable", CHECKER.render_text(report))
                    path.unlink()

    def test_symlinked_subdirectory_is_bad_input(self):
        storage = self.tmp / "storage"
        (self.vendored / "security").rename(storage)
        (self.vendored / "security").symlink_to(storage, target_is_directory=True)
        code, report = self.run_checker()
        self.assertEqual(code, 2)
        self.assertIn("symlinked directory", report["error"])
        (self.vendored / "security").unlink()
        (self.vendored / "loop").symlink_to(self.vendored, target_is_directory=True)
        code, report = self.run_checker()
        self.assertEqual(code, 2)
        self.assertIn("symlinked directory", report["error"])

    def test_float_zero_sign_is_preserved_but_spelling_is_not(self):
        self.assertFalse(CHECKER.same_json([0.0], [-0.0]))
        self.assertTrue(CHECKER.same_json([0.1], json.loads("[0.1000000000000000055511151231257827]")))

    def test_canonical_number_equality_does_not_hide_drift(self):
        name = "number-v0.1"
        data = make_set(name, [{"input": 1.0}])
        write_json(self.standard / "conformance" / "vectors" / f"{name}.json", data)
        write_json(self.vendored_set(name), data)
        self.edit_vendored(name, lambda value: value["vectors"][0].update(input=1))
        code, report = self.run_checker()
        result = self.result_for(report, name)
        self.assertEqual((code, result["status"], result["changes"]), (1, "drifted", ["vectors"]))
        self.assertEqual(result["contentHash"]["standard"], result["contentHash"]["vendored"])
        self.assertIn("differs as exact JSON", result["comparisonNote"])

    def test_ignored_json_counts_are_reported(self):
        write_json(self.vendored / "another-golden.json", {"signing": {}})
        code, report = self.run_checker()
        self.assertEqual(code, 0)
        self.assertEqual(report["summary"]["ignoredJson"], {"standard": 1, "vendored": 2})
        self.assertIn("Ignored JSON files: 1 standard, 2 vendored.", CHECKER.render_text(report))

    def test_text_report_names_each_problem(self):
        self.vendored_set("alpha-v0.1").unlink()
        write_json(self.vendored / "gamma-v0.1.json", make_set("gamma-v0.1", [{"name": "g1"}]))
        self.edit_vendored("beta-v0.1", lambda data: data.update(count=5))
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = CHECKER.main([str(self.vendored), "--standard", str(self.standard)])
        text = out.getvalue()
        self.assertEqual(code, 1)
        self.assertIn("MISSING  alpha-v0.1", text)
        self.assertIn("EXTRA    gamma-v0.1", text)
        self.assertIn("DRIFTED  beta-v0.1", text)
        self.assertIn("count: standard 2, vendored 5", text)
        self.assertIn("2 standard sets, 2 vendored: 0 match, 1 drifted, 1 missing, 1 extra, 0 uncheckable.", text)

    def test_bad_input_exits_2(self):
        valid = copy.deepcopy(STANDARD_SETS["alpha-v0.1"])
        cases = {
            "invalid JSON": "{not json",
            "duplicate member": '{"set": "alpha-v0.1", "set": "x", "vectors": []}',
            "NaN constant": '{"set": "alpha-v0.1", "spec": "s", "count": 1, "hash": "h", "vectors": [NaN]}',
            "missing hash": json.dumps({key: value for key, value in valid.items() if key != "hash"}),
            "missing vectors": json.dumps({key: value for key, value in valid.items() if key != "vectors"}),
            "set only": '{"set": "damaged-v0.1"}',
            "spec only": '{"spec": "DACS-4"}',
            "count only": '{"count": 0}',
            "hash only": '{"hash": "h"}',
            "vectors only": '{"vectors": []}',
            "deep JSON": "[" * 200000 + "]" * 200000,
            "boolean count": json.dumps(dict(valid, count=True)),
            "duplicate set name": json.dumps(dict(valid)),
        }
        for label, text in cases.items():
            with self.subTest(label=label):
                bad = self.tmp / "bad" / label.replace(" ", "-")
                shutil.copytree(self.vendored, bad)
                (bad / "extra-file.json").write_text(text, encoding="utf-8")
                code, report = self.run_checker(vendored=bad)
                self.assertEqual(code, 2)
                self.assertIn("error", report)
        # A damaged expected set must also be bad input, rather than missing.
        self.edit_vendored("alpha-v0.1", lambda data: data.pop("vectors"))
        code, report = self.run_checker()
        self.assertEqual(code, 2)
        self.assertIn("'vectors'", report["error"])
        write_json(self.vendored_set("alpha-v0.1"), valid)

        # Exercise os.walk's error callback even when run with elevated filesystem access.
        real_walk = CHECKER.os.walk
        def denied_walk(base, **kwargs):
            if base == self.vendored:
                kwargs["onerror"](PermissionError("unreadable security directory"))
            yield from real_walk(base, **kwargs)

        with mock.patch.object(CHECKER.os, "walk", side_effect=denied_walk):
            code, report = self.run_checker()
        self.assertEqual(code, 2)
        self.assertIn("unreadable security directory", report["error"])

        for target in ("canonical_json", "same_json"):
            with self.subTest(recursion=target), mock.patch.object(CHECKER, target, side_effect=RecursionError):
                code, report = self.run_checker()
                self.assertEqual(code, 2)
                self.assertIn("too deeply nested", report["error"])
        empty_standard = self.tmp / "empty-standard"
        (empty_standard / "conformance" / "vectors").mkdir(parents=True)
        for label, kwargs, args in (
            ("absent vendored dir", {"vendored": self.tmp / "absent"}, ()),
            ("standard without sets", {"standard": empty_standard}, ()),
            ("standard without vectors dir", {"standard": self.tmp / "vendor"}, ()),
            ("revision on a non-git standard", {}, ("--rev", "no-such-revision")),
            ("option-like revision", {"standard": ROOT}, ("--rev=--all",)),
            ("unknown revision", {"standard": ROOT}, ("--rev", "0" * 40)),
        ):
            with self.subTest(label=label):
                code, report = self.run_checker(*args, **kwargs)
                self.assertEqual(code, 2)
                self.assertIn("error", report)


class RepositoryVectorSetTests(unittest.TestCase):
    def run_checker(self, *argv):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = CHECKER.main([*map(str, argv), "--json"])
        return code, json.loads(out.getvalue())

    def test_repository_sets_have_computed_comparison_hashes(self):
        code, report = self.run_checker(ROOT / "conformance" / "vectors")
        security_sets = sorted((ROOT / "conformance" / "vectors" / "security").glob("*.json"))
        self.assertEqual(code, 0)
        self.assertEqual(report["summary"]["match"], len(security_sets))
        self.assertFalse(report["uncheckable"])
        for result in report["sets"]:
            self.assertEqual(result["status"], "match")
            self.assertTrue(all(result["comparisonHash"].values()))
            if result["contentHash"]["standard"] is None:
                self.assertEqual(result["comparison"], "declared-encoding-sha256+parsed-json")
                source = json.loads((ROOT / "conformance" / "vectors" / result["standardPath"]).read_text())
                digest = hashlib.sha256(CHECKER.canonical_encodings(source["vectors"])[result["hashEncoding"]]).hexdigest()
                self.assertEqual(digest, source["hash"])
                self.assertEqual(result["comparisonHash"]["standard"], digest)
            else:
                self.assertEqual(result["comparison"], "canonical-json-sha256+exact-json")
        self.assertTrue(all(r["standardPath"].startswith("security/") for r in report["sets"]))

    def test_revision_mode_reads_committed_sets(self):
        commit, files = CHECKER.read_revision(ROOT, V04_COMMIT)
        self.assertEqual(commit, V04_COMMIT)
        with tempfile.TemporaryDirectory() as tmp:
            vendored = Path(tmp)
            for relative, raw in files:
                (vendored / relative).parent.mkdir(parents=True, exist_ok=True)
                (vendored / relative).write_bytes(raw)
            code, report = self.run_checker(vendored, "--rev", V04_COMMIT)
            self.assertEqual(code, 0)
            self.assertFalse(report["uncheckable"])
            self.assertEqual(report["standard"]["commit"], V04_COMMIT)
            self.assertGreater(report["summary"]["match"], 0)
            first = next(r for r in report["sets"] if r["status"] == "match")
            path = vendored / first["vendoredPath"]
            data = json.loads(path.read_text(encoding="utf-8"))
            data["vectors"].pop()
            path.write_text(json.dumps(data), encoding="utf-8")
            code, report = self.run_checker(vendored, "--rev", V04_COMMIT)
            self.assertEqual(code, 1)
            self.assertFalse(report["uncheckable"])
            changed = next(r for r in report["sets"] if r["set"] == first["set"])
            self.assertEqual(changed["changes"], ["vectors", "count"])

    def test_conformance_readme_documents_the_checker(self):
        readme = (ROOT / "conformance" / "README.md").read_text(encoding="utf-8")
        self.assertTrue(
            "python3 scripts/check_vendored_vectors.py" in readme,
            "conformance/README.md does not show how to run the drift checker",
        )


if __name__ == "__main__":
    unittest.main()
