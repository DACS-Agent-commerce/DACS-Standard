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
NEXT_COMMIT = "df7bc202ebdc179a59d61a8221072f33f482b933"
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
             "uncheckable": 0, "ignoredJson": {"standard": 0, "vendored": 0},
             "files": {"standard": 1, "vendored": 1, "match": 1, "drifted": 0, "missing": 0, "extra": 0}},
        )
        self.assertEqual(report["files"], [{"path": "golden.json", "status": "match", "members": None}])
        alpha = self.result_for(report, "alpha-v0.1")
        self.assertEqual(alpha["standardPath"], "security/alpha-v0.1.json")
        self.assertEqual(alpha["vendoredPath"], "security/alpha-v0.1.json")
        self.assertEqual(alpha["comparison"], "canonical-json-sha256+exact-json")
        self.assertEqual(alpha["contentHash"]["standard"], STANDARD_SETS["alpha-v0.1"]["hash"])
        self.assertEqual(alpha["members"], [])

    def test_flat_vendored_layout_matches_by_set_name(self):
        flat = self.tmp / "flat"
        flat.mkdir()
        for path in (self.vendored / "security").glob("*.json"):
            shutil.copy(path, flat / path.name)
        # Sets match by name in any layout; other JSON files match by path.
        code, report = self.run_checker(vendored=flat)
        self.assertEqual(code, 1)
        self.assertEqual(report["summary"]["match"], 2)
        self.assertEqual(report["files"], [{"path": "golden.json", "status": "missing", "members": None}])
        code, report = self.run_checker("--sets-only", vendored=flat)
        self.assertEqual(code, 0)
        self.assertEqual(self.result_for(report, "beta-v0.1")["vendoredPath"], "beta-v0.1.json")
        shutil.copy(self.vendored / "golden.json", flat / "golden.json")
        code, report = self.run_checker(vendored=flat)
        self.assertEqual(code, 0)

    def test_top_level_member_edit_is_drift(self):
        # Vectors are evaluated against top-level members such as fixtures,
        # keys and status metadata, so each is compared and named.
        for name in STANDARD_SETS:
            data = copy.deepcopy(STANDARD_SETS[name])
            data.update(publicKeys={"seller": "AAAA"}, tier="historical",
                        conformanceProfile={"status": "superseded", "currentCollisionAuthority": False})
            write_json(self.standard / "conformance" / "vectors" / "security" / f"{name}.json", data)
            write_json(self.vendored_set(name), data)
        code, report = self.run_checker()
        self.assertEqual(code, 0)
        edits = {
            "alpha-v0.1": lambda data: (data["publicKeys"].update(seller="BBBB"),
                                        data.update(tier="current", agreement={"parties": []})),
            "beta-v0.1": lambda data: (data.pop("conformanceProfile"), data.update(publicKeys={"seller": 1})),
        }
        for name, change in edits.items():
            self.edit_vendored(name, change)
        code, report = self.run_checker()
        self.assertEqual(code, 1)
        alpha = self.result_for(report, "alpha-v0.1")
        self.assertEqual((alpha["status"], alpha["changes"]), ("drifted", ["members"]))
        self.assertEqual(alpha["members"], ["agreement", "publicKeys", "tier"])
        beta = self.result_for(report, "beta-v0.1")
        self.assertEqual((beta["status"], beta["changes"]), ("drifted", ["members"]))
        self.assertEqual(beta["members"], ["conformanceProfile", "publicKeys"])
        self.assertIn("  members: agreement, publicKeys, tier", CHECKER.render_text(report))
        # --sets-only narrows file comparison, never set members.
        code, report = self.run_checker("--sets-only")
        self.assertEqual((code, self.result_for(report, "alpha-v0.1")["status"]), (1, "drifted"))

        # A member that only gained or lost a list element, or gained a nested key, is drift too.
        beta = STANDARD_SETS["beta-v0.1"]
        write_json(self.standard / "conformance" / "vectors" / "security" / "beta-v0.1.json", beta)
        write_json(self.vendored_set("beta-v0.1"), beta)
        alpha = dict(STANDARD_SETS["alpha-v0.1"], agreement={"parties": ["a"]}, publicKeys={"seller": "AAAA"})
        for label, standard_member, vendored_member in (
            ("appended element", {"agreement": {"parties": ["a"]}}, {"agreement": {"parties": ["a", "b"]}}),
            ("dropped element", {"agreement": {"parties": ["a", "b"]}}, {"agreement": {"parties": ["a"]}}),
            ("vendored-only key", {"publicKeys": {"seller": "AAAA"}},
             {"publicKeys": {"seller": "AAAA", "buyer": "CCCC"}}),
        ):
            with self.subTest(label=label):
                write_json(self.standard / "conformance" / "vectors" / "security" / "alpha-v0.1.json",
                           dict(alpha, **standard_member))
                write_json(self.vendored_set("alpha-v0.1"), dict(alpha, **vendored_member))
                code, report = self.run_checker()
                result = self.result_for(report, "alpha-v0.1")
                self.assertEqual((code, result["status"], result["changes"], result["members"]),
                                 (1, "drifted", ["members"], list(standard_member)))

    def test_non_set_json_files_are_compared_by_path(self):
        standard_vectors = self.standard / "conformance" / "vectors"
        golden = {"negotiate": [{"id": "neg-ps3", "expect": "fail"}], "signing": {}}
        example = {"kind": "IdentityBundle", "artifact": {"claims": []}}
        for base in (standard_vectors, self.vendored):
            write_json(base / "golden.json", golden)
            write_json(base / "examples" / "identity-bundle.json", example)
        code, report = self.run_checker()
        self.assertEqual(code, 0)
        self.assertEqual([f["status"] for f in report["files"]], ["match", "match"])

        # Keeping every shared value does not hide an appended, dropped or added entry.
        two_cases = {"negotiate": golden["negotiate"] + [{"id": "neg-band", "expect": "pass"}], "signing": {}}
        noted = {"negotiate": [dict(golden["negotiate"][0], note="local")], "signing": {}}
        for label, standard_golden, vendored_golden in (
            ("appended case", golden, two_cases),
            ("dropped case", two_cases, golden),
            ("vendored-only key", golden, noted),
        ):
            with self.subTest(label=label):
                write_json(standard_vectors / "golden.json", standard_golden)
                write_json(self.vendored / "golden.json", vendored_golden)
                code, report = self.run_checker()
                self.assertEqual(code, 1)
                self.assertEqual(self.result_for_file(report, "golden.json"),
                                 {"path": "golden.json", "status": "drifted", "members": ["negotiate"]})
        write_json(standard_vectors / "golden.json", golden)

        edited = copy.deepcopy(golden)
        edited["negotiate"][0]["expect"] = "pass"
        write_json(self.vendored / "golden.json", edited)
        (self.vendored / "examples" / "identity-bundle.json").unlink()
        write_json(self.vendored / "golden-extra.json", {"signing": {}})
        code, report = self.run_checker()
        self.assertEqual(code, 1)
        self.assertTrue(report["drift"])
        self.assertEqual(report["summary"]["match"], 2)
        self.assertEqual(
            report["files"],
            [{"path": "examples/identity-bundle.json", "status": "missing", "members": None},
             {"path": "golden-extra.json", "status": "extra", "members": None},
             {"path": "golden.json", "status": "drifted", "members": ["negotiate"]}],
        )
        self.assertEqual(report["summary"]["files"],
                         {"standard": 2, "vendored": 2, "match": 0, "drifted": 1, "missing": 1, "extra": 1})
        text = CHECKER.render_text(report)
        self.assertIn("FILE DRIFTED  golden.json\n  members: negotiate", text)
        self.assertIn("FILE MISSING  examples/identity-bundle.json", text)
        self.assertIn("FILE EXTRA    golden-extra.json", text)
        self.assertIn("2 other standard JSON files, 2 vendored: 0 match, 1 drifted, 1 missing, 1 extra.", text)

        # A changed top-level type is drift without a member list.
        write_json(self.vendored / "golden.json", [golden])
        code, report = self.run_checker()
        self.assertEqual(self.result_for_file(report, "golden.json"),
                         {"path": "golden.json", "status": "drifted", "members": None})

    def result_for_file(self, report, path):
        return next(result for result in report["files"] if result["path"] == path)

    def test_vendored_vectors_refused_by_canonical_json_are_drift(self):
        # The Standard's vectors canonicalize, so a vendored value canonical_json
        # refuses is a known difference rather than an unknown one.
        for declared in ("verified", "stale"):
            with self.subTest(declared=declared):
                data = make_set("alpha-v0.1", [{"name": "a1", "expected": "pass", "input": {"n": BIG}}])
                if declared == "stale":
                    data["hash"] = STANDARD_SETS["alpha-v0.1"]["hash"]
                write_json(self.vendored_set("alpha-v0.1"), data)
                code, report = self.run_checker()
                alpha = self.result_for(report, "alpha-v0.1")
                self.assertEqual((code, alpha["status"]), (1, "drifted"))
                self.assertIn("vectors", alpha["changes"])
                self.assertFalse(alpha["uncheckable"])
                self.assertFalse(report["uncheckable"])
                self.assertIn("the Standard's vectors canonicalize", alpha["comparisonNote"])
                self.assertEqual(alpha["comparison"], "canonical-json-sha256+exact-json")
                self.assertIn("DRIFTED  alpha-v0.1", CHECKER.render_text(report))

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
        text = CHECKER.render_text(report)
        self.assertIn("  spec: standard 'DACS-4 §9.5.9'\n        vendored 'DACS-4 v0.7 §9.5.9'\n", text)
        self.assertIn(f"  hash: standard {STANDARD_SETS['beta-v0.1']['hash']}, vendored {'0' * 64}\n", text)

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

    def test_fallback_unencodable_vendored_copy_is_drift(self):
        # As in canonical mode, the Standard's vectors hash under the verified
        # encoding, so a vendored value that encoding refuses is a known difference.
        # Only the UTF-8 encodings refuse a lone surrogate.
        name = "wide-int-v0.1"
        ascii_encoding, utf8_encoding = "compact insertion-order (ascii)", "compact insertion-order (utf-8)"
        for encoding, vectors in ((ascii_encoding, [{"input": BIG}]),
                                  (utf8_encoding, [{"input": BIG, "name": "é"}])):
            with self.subTest(encoding=encoding):
                data = make_set(name, vectors)
                data["hash"] = hashlib.sha256(CHECKER.canonical_encoding(vectors, encoding)).hexdigest()
                write_json(self.standard / "conformance" / "vectors" / f"{name}.json", data)
                edited = [dict(vectors[0], name="\ud800")]
                write_json(self.vendored_set(name), dict(data, vectors=edited))
                code, report = self.run_checker()
                result = self.result_for(report, name)
                self.assertEqual((code, result["status"], result["changes"]), (1, "drifted", ["vectors"]))
                self.assertEqual(result["comparison"], "declared-encoding-sha256+parsed-json")
                self.assertEqual(result["hashEncoding"], encoding)
                self.assertEqual(result["comparisonHash"]["standard"], data["hash"])
                self.assertFalse(report["uncheckable"])
                self.assertIn(f"DRIFTED  {name}", CHECKER.render_text(report))
                if encoding == ascii_encoding:
                    vendored_hash = hashlib.sha256(CHECKER.canonical_encoding(edited, encoding)).hexdigest()
                    self.assertEqual(result["comparisonHash"]["vendored"], vendored_hash)
                    self.assertNotEqual(vendored_hash, data["hash"])
                    self.assertNotIn("cannot be hashed", result["comparisonNote"])
                else:
                    self.assertIsNone(result["comparisonHash"]["vendored"])
                    self.assertIn(f"vendored: cannot be hashed using {encoding} (", result["comparisonNote"])

    def test_fallback_reordered_members_under_insertion_order_encoding_are_drift(self):
        # Parsed values ignore member order, but an insertion-order encoding
        # hashes it, so reordered members no longer reproduce the declared hash.
        name = "wide-int-v0.1"
        encoding = "compact insertion-order (ascii)"
        data = make_set(name, [{"name": "w1", "input": BIG}])
        self.assertEqual(data["hash"], hashlib.sha256(CHECKER.canonical_encoding(data["vectors"], encoding)).hexdigest())
        write_json(self.standard / "conformance" / "vectors" / f"{name}.json", data)
        reordered = [{"input": BIG, "name": "w1"}]
        self.assertTrue(CHECKER.same_json(data["vectors"], reordered))
        write_json(self.vendored_set(name), dict(data, vectors=reordered))
        code, report = self.run_checker()
        result = self.result_for(report, name)
        self.assertEqual((code, result["status"], result["changes"]), (1, "drifted", ["vectors"]))
        self.assertEqual((result["comparison"], result["hashEncoding"]),
                         ("declared-encoding-sha256+parsed-json", encoding))
        self.assertEqual(result["comparisonHash"],
                         {"standard": data["hash"],
                          "vendored": hashlib.sha256(CHECKER.canonical_encoding(reordered, encoding)).hexdigest()})
        self.assertNotEqual(result["comparisonHash"]["standard"], result["comparisonHash"]["vendored"])
        self.assertIn(f"  comparison: declared-encoding-sha256+parsed-json ({encoding})\n", CHECKER.render_text(report))

    def test_fallback_uses_any_verified_encoding_the_copy_reproduces(self):
        # Sorted ASCII-only members verify under all four encodings. Reordered
        # members still reproduce the declared hash under the sorted-keys ones,
        # so the copy matches and the report names the encoding that matched.
        name = "wide-int-v0.1"
        data = make_set(name, [{"input": BIG, "name": "w1"}])
        verifying = [encoding for encoding in CHECKER.CANONICAL_ENCODINGS
                     if hashlib.sha256(CHECKER.canonical_encoding(data["vectors"], encoding)).hexdigest()
                     == data["hash"]]
        self.assertEqual(verifying, list(CHECKER.CANONICAL_ENCODINGS))
        write_json(self.standard / "conformance" / "vectors" / f"{name}.json", data)
        reordered = [{"name": "w1", "input": BIG}]
        write_json(self.vendored_set(name), dict(data, vectors=reordered))
        code, report = self.run_checker()
        result = self.result_for(report, name)
        self.assertEqual((code, result["status"], result["changes"]), (0, "match", []))
        self.assertEqual(result["hashEncoding"], "compact sorted-keys (ascii)")
        self.assertEqual(result["comparisonHash"], {"standard": data["hash"], "vendored": data["hash"]})
        self.assertIn(f"MATCH    {name}  (declared-encoding-sha256+parsed-json: compact sorted-keys (ascii))",
                      CHECKER.render_text(report))
        # Unchanged order still uses the first verified encoding.
        write_json(self.vendored_set(name), data)
        code, report = self.run_checker()
        self.assertEqual((code, self.result_for(report, name)["hashEncoding"]),
                         (0, "compact insertion-order (ascii)"))
        # A value edit reproduces the hash under no encoding: drift, under the first one.
        write_json(self.vendored_set(name), dict(data, vectors=[{"input": BIG, "name": "w2"}]))
        code, report = self.run_checker()
        result = self.result_for(report, name)
        self.assertEqual((code, result["changes"], result["hashEncoding"]),
                         (1, ["vectors"], "compact insertion-order (ascii)"))

    def test_fallback_encodings_are_the_validator_compact_forms(self):
        vectors = [{"b": "é", "a": BIG}]
        expected = {
            "compact insertion-order (ascii)": b'[{"b":"\\u00e9","a":9007199254740992}]',
            "compact insertion-order (utf-8)": '[{"b":"é","a":9007199254740992}]'.encode("utf-8"),
            "compact sorted-keys (ascii)": b'[{"a":9007199254740992,"b":"\\u00e9"}]',
            "compact sorted-keys (utf-8)": '[{"a":9007199254740992,"b":"é"}]'.encode("utf-8"),
        }
        encoded = {encoding: CHECKER.canonical_encoding(vectors, encoding) for encoding in CHECKER.CANONICAL_ENCODINGS}
        self.assertEqual(encoded, expected)
        self.assertEqual(sys.modules["validate_security_vectors"].canonical_encodings(vectors), expected)

    def test_fallback_standard_lone_surrogate_keeps_its_ascii_encoding(self):
        # A UTF-8 refusal does not hide the ASCII encoding that verifies the declared hash.
        name = "wide-int-v0.1"
        encoding = "compact insertion-order (ascii)"
        vectors = [{"input": BIG, "name": "\ud800"}]
        data = make_set(name, vectors)
        self.assertEqual(data["hash"], hashlib.sha256(CHECKER.canonical_encoding(vectors, encoding)).hexdigest())
        write_json(self.standard / "conformance" / "vectors" / f"{name}.json", data)
        write_json(self.vendored_set(name), data)
        code, report = self.run_checker()
        result = self.result_for(report, name)
        self.assertEqual((code, result["status"], result["hashEncoding"]), (0, "match", encoding))
        self.assertEqual(result["comparisonHash"], {"standard": data["hash"], "vendored": data["hash"]})
        self.assertFalse(report["uncheckable"])

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
        self.assertIn(f"UNCHECKABLE  {name}  (hash unavailable: ", CHECKER.render_text(report))
        self.assertNotIn("observed differences", CHECKER.render_text(report))
        # A valid hash on the vendored side cannot choose the Standard's rule.
        write_json(self.vendored_set(name), make_set(name, [{"input": BIG}]))
        code, report = self.run_checker()
        self.assertEqual((code, self.result_for(report, name)["status"]), (2, "uncheckable"))
        self.assertEqual(self.result_for(report, name)["changes"], ["hash"])
        self.assertIn("  observed differences: hash", CHECKER.render_text(report))

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

    def test_sets_only_reports_ignored_json_counts(self):
        write_json(self.vendored / "another-golden.json", {"signing": {}})
        write_json(self.vendored / "golden.json", {"signing": {"edited": True}})
        code, report = self.run_checker("--sets-only")
        self.assertEqual(code, 0)
        self.assertTrue(report["setsOnly"])
        self.assertEqual(report["files"], [])
        self.assertIsNone(report["summary"]["files"])
        self.assertEqual(report["summary"]["ignoredJson"], {"standard": 1, "vendored": 2})
        # Each ignored vendored file is named, so none is dropped silently.
        self.assertEqual(report["ignoredVendored"], ["another-golden.json", "golden.json"])
        self.assertIn("Ignored JSON files (--sets-only): 1 standard, 2 vendored.\n"
                      "  ignored vendored: another-golden.json\n"
                      "  ignored vendored: golden.json", CHECKER.render_text(report))
        code, report = self.run_checker()
        self.assertEqual(code, 1)
        self.assertFalse(report["setsOnly"])
        self.assertEqual(report["ignoredVendored"], [])
        self.assertNotIn("ignored vendored", CHECKER.render_text(report))

    def test_sets_only_ignores_json_without_a_set_member(self):
        # --sets-only counts other JSON as ignored, even when it uses a set
        # member name; without --sets-only such a file is still bad input.
        metadata = self.vendored / "metadata.json"
        for text in ('{"hash": "ordinary metadata"}', '{"count": 3}', '{"spec": "notes"}', '{"vectors": []}'):
            with self.subTest(text=text):
                metadata.write_text(text, encoding="utf-8")
                code, report = self.run_checker("--sets-only")
                self.assertEqual(code, 0, report)
                self.assertEqual((report["summary"]["match"], report["summary"]["ignoredJson"]),
                                 (2, {"standard": 1, "vendored": 2}))
                code, report = self.run_checker()
                self.assertEqual(code, 2)
                self.assertIn("metadata.json: vector set needs", report["error"])
        # An object with a set member must still be a complete set.
        metadata.write_text('{"set": "damaged-v0.1", "hash": "h"}', encoding="utf-8")
        code, report = self.run_checker("--sets-only")
        self.assertEqual(code, 2)
        self.assertIn("metadata.json: vector set needs a str 'spec' member", report["error"])
        metadata.unlink()
        # A vendored set that lost its set member keeps its file name, so it is
        # bad input rather than ignored (test_damaged_copy_named_after_a_standard_set_is_bad_input).
        self.edit_vendored("alpha-v0.1", lambda data: data.pop("set"))
        code, report = self.run_checker("--sets-only")
        self.assertEqual(code, 2)
        self.assertIn("security/alpha-v0.1.json: vector set needs a str 'set' member", report["error"])

    def test_damaged_copy_named_after_a_standard_set_is_bad_input(self):
        # Sets are named after their file stem, so a vendored file with a Standard
        # set's file name must hold a complete set in every mode, flat or not.
        flat = self.tmp / "flat"
        flat.mkdir()
        for path in (self.vendored / "security").glob("*.json"):
            shutil.copy(path, flat / path.name)
        alpha = STANDARD_SETS["alpha-v0.1"]
        damages = {
            "lost set member": ({key: value for key, value in alpha.items() if key != "set"},
                                "vector set needs a str 'set' member"),
            "lost set member and truncated": (
                dict({key: value for key, value in alpha.items() if key != "set"}, vectors=[]),
                "vector set needs a str 'set' member"),
            "wrapped in a list": ([alpha], "is not a vector set, but has the file name of the Standard's set "
                                           "'alpha-v0.1'"),
            "no set member at all": ({"notes": "emptied"}, "is not a vector set, but has the file name"),
        }
        modes = ((), ("--sets-only",), ("--subset",), ("--subset", "--sets-only"))
        for layout, base, relative in (("security", self.vendored, "security/alpha-v0.1.json"),
                                       ("flat", flat, "alpha-v0.1.json")):
            for label, (damaged, message) in damages.items():
                for args in modes:
                    with self.subTest(layout=layout, damage=label, args=args):
                        copy_dir = self.tmp / "damaged" / layout / label.replace(" ", "-") / "-".join(args)
                        shutil.copytree(base, copy_dir)
                        write_json(copy_dir / relative, damaged)
                        code, report = self.run_checker(*args, vendored=copy_dir)
                        self.assertEqual(code, 2, report)
                        self.assertIn(f"vendored {relative}: {message}", report["error"])
        # Any other name keeps the documented --sets-only behaviour: it is ignored.
        write_json(flat / "alpha-notes.json", [alpha])
        code, report = self.run_checker("--subset", "--sets-only", vendored=flat)
        self.assertEqual((code, report["ignoredVendored"]), (0, ["alpha-notes.json"]))

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

        for target, args, where in (
            ("canonical_json", (), "vectors"),
            ("same_json", (), "file golden.json"),
            ("same_json", ("--sets-only",), "vectors"),
        ):
            with self.subTest(recursion=target, args=args), \
                    mock.patch.object(CHECKER, target, side_effect=RecursionError):
                code, report = self.run_checker(*args)
                self.assertEqual(code, 2)
                self.assertIn("too deeply nested", report["error"])
                self.assertIn(where, report["error"])
        for base in (self.standard / "conformance" / "vectors", self.vendored):
            write_json(base / "security" / "alpha-v0.1.json", dict(valid, fixture={"deep": True}))
        real_same_json = CHECKER.same_json
        def deep_members(left, right):
            if left == {"deep": True}:
                raise RecursionError
            return real_same_json(left, right)
        with mock.patch.object(CHECKER, "same_json", side_effect=deep_members):
            code, report = self.run_checker("--sets-only")
        self.assertEqual(code, 2)
        self.assertIn("members are too deeply nested", report["error"])
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
        # Without --json the error goes to stderr alone.
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = CHECKER.main([str(self.tmp / "absent"), "--standard", str(self.standard)])
        self.assertEqual((code, out.getvalue()), (2, ""))
        self.assertTrue(err.getvalue().startswith("error: "), err.getvalue())
        self.assertIn("absent is not a directory", err.getvalue())
        # A git that cannot start is bad input, with its cause kept.
        with mock.patch.object(CHECKER.subprocess, "run", side_effect=OSError("no git executable")):
            code, report = self.run_checker("--rev", V04_COMMIT, standard=ROOT)
        self.assertEqual(code, 2)
        self.assertIn("cannot run git: no git executable", report["error"])

    def test_subset_reports_missing_entries_without_failing(self):
        # A copy of selected sets reports what it does not hold, without failing on it.
        self.vendored_set("alpha-v0.1").unlink()
        (self.vendored / "golden.json").unlink()
        for args in ((), ("--sets-only",)):
            with self.subTest(args=args):
                code, report = self.run_checker(*args)
                self.assertEqual((code, report["drift"], report["subset"]), (1, True, False))
                self.assertNotIn("(--subset)", CHECKER.render_text(report))
                code, report = self.run_checker("--subset", *args)
                self.assertEqual((code, report["drift"], report["subset"]), (0, False, True))
                self.assertEqual(self.result_for(report, "alpha-v0.1")["status"], "missing")
                self.assertEqual((report["summary"]["match"], report["summary"]["missing"]), (1, 1))
                text = CHECKER.render_text(report)
                self.assertIn("MISSING  alpha-v0.1", text)
                self.assertIn("\nMissing sets and files are reported but do not fail (--subset).", text)
        code, report = self.run_checker("--subset")
        self.assertEqual(report["files"], [{"path": "golden.json", "status": "missing", "members": None}])
        self.assertIn("FILE MISSING  golden.json", CHECKER.render_text(report))

    def test_subset_still_fails_on_drift_extra_and_uncheckable(self):
        self.vendored_set("alpha-v0.1").unlink()
        for label, args, change in (
            ("drifted set", (), lambda base: write_json(
                base / "security" / "beta-v0.1.json", dict(STANDARD_SETS["beta-v0.1"], count=3))),
            ("extra set", ("--sets-only",), lambda base: write_json(
                base / "gamma-v0.1.json", make_set("gamma-v0.1", [{"name": "g1"}]))),
            ("drifted file", (), lambda base: write_json(base / "golden.json", {"signing": {"edited": True}})),
            ("extra file", (), lambda base: write_json(base / "notes.json", ["local"])),
        ):
            with self.subTest(label=label):
                selection = self.tmp / "selection" / label.replace(" ", "-")
                shutil.copytree(self.vendored, selection)
                code, report = self.run_checker("--subset", *args, vendored=selection)
                self.assertEqual((code, report["drift"]), (0, False))
                change(selection)
                code, report = self.run_checker("--subset", *args, vendored=selection)
                self.assertEqual((code, report["drift"]), (1, True), report)
        # A Standard set with neither hash stays uncheckable even when it is not vendored.
        name = "wide-int-v0.1"
        write_json(self.standard / "conformance" / "vectors" / f"{name}.json",
                   dict(make_set(name, [{"input": BIG}]), hash="0" * 64))
        code, report = self.run_checker("--subset")
        self.assertEqual((code, self.result_for(report, name)["status"]), (2, "missing"))
        self.assertTrue(report["uncheckable"])

    def test_subset_with_nothing_to_compare_is_bad_input(self):
        # With missing entries not failing, an empty selection must not pass vacuously.
        selection = self.tmp / "selection"
        selection.mkdir()
        code, report = self.run_checker("--subset", vendored=selection)
        self.assertEqual(code, 2)
        self.assertIn("--subset: ", report["error"])
        self.assertIn("holds no vector sets or other JSON files to compare", report["error"])
        write_json(selection / "metadata.json", {"hash": "ordinary metadata"})
        code, report = self.run_checker("--subset", "--sets-only", vendored=selection)
        self.assertEqual(code, 2)
        self.assertIn("holds no vector sets to compare", report["error"])
        code, report = self.run_checker("--sets-only", vendored=selection)
        self.assertEqual((code, report["summary"]["missing"]), (1, 2))
        # A selection of other JSON files alone is still compared.
        (selection / "metadata.json").unlink()
        shutil.copy(self.vendored / "golden.json", selection / "golden.json")
        code, report = self.run_checker("--subset", vendored=selection)
        self.assertEqual((code, report["summary"]["missing"], report["summary"]["files"]["match"]), (0, 2, 1))


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
                digest = hashlib.sha256(CHECKER.canonical_encoding(source["vectors"], result["hashEncoding"])).hexdigest()
                self.assertEqual(digest, source["hash"])
                self.assertEqual(result["comparisonHash"]["standard"], digest)
            else:
                self.assertEqual(result["comparison"], "canonical-json-sha256+exact-json")
        self.assertTrue(all(r["standardPath"].startswith("security/") for r in report["sets"]))
        self.assertTrue(all(r["members"] == [] for r in report["sets"]))
        other_json = [p for p in (ROOT / "conformance" / "vectors").rglob("*.json")
                      if p.parent.name != "security"]
        self.assertEqual(report["summary"]["files"]["match"], len(other_json))
        self.assertIn("golden.json", {f["path"] for f in report["files"]})

    def test_sets_only_flat_copy_ignores_unrelated_metadata(self):
        security_sets = sorted((ROOT / "conformance" / "vectors" / "security").glob("*.json"))
        with tempfile.TemporaryDirectory() as tmp:
            vendored = Path(tmp)
            for path in security_sets:
                shutil.copy(path, vendored / path.name)
            (vendored / "metadata.json").write_text('{"hash": "ordinary metadata"}', encoding="utf-8")
            code, report = self.run_checker(vendored, "--sets-only")
        self.assertEqual(code, 0, report)
        self.assertEqual(report["summary"]["match"], len(security_sets))
        self.assertEqual(report["summary"]["ignoredJson"]["vendored"], 1)

    def test_subset_copy_passes_against_its_own_revision(self):
        # A flat copy of selected sets, as an SDK keeps, fails only on its own drift.
        security_sets = sorted((ROOT / "conformance" / "vectors" / "security").glob("*.json"))
        _commit, files = CHECKER.read_revision(ROOT, V04_COMMIT)
        with tempfile.TemporaryDirectory() as tmp:
            current, pinned = Path(tmp) / "current", Path(tmp) / "v0.4"
            current.mkdir()
            pinned.mkdir()
            for path in security_sets[:2]:
                shutil.copy(path, current / path.name)
            code, report = self.run_checker(current, "--sets-only")
            self.assertEqual(code, 1)
            code, report = self.run_checker(current, "--subset", "--sets-only")
            self.assertEqual(code, 0, report)
            self.assertEqual((report["summary"]["match"], report["summary"]["missing"]),
                             (2, len(security_sets) - 2))
            # A file pinned to another revision is checked against that revision.
            name = "commitment-anchor-authority-v0.3"
            (pinned / f"{name}.json").write_bytes(dict(files)[f"security/{name}.json"])
            code, report = self.run_checker(pinned, "--subset", "--sets-only", "--rev", V04_COMMIT)
            self.assertEqual((code, report["summary"]["match"]), (0, 1), report)
            code, report = self.run_checker(pinned, "--subset", "--sets-only", "--rev", NEXT_COMMIT)
        self.assertEqual(code, 1)
        self.assertEqual(next(r for r in report["sets"] if r["set"] == name)["status"], "drifted")

    def test_v04_copy_reports_top_level_and_golden_drift(self):
        # Between v0.4 and the base of this checker, commitment-anchor-authority-v0.3
        # changed only its top-level agreement fixtures, and golden.json changed.
        _commit, files = CHECKER.read_revision(ROOT, V04_COMMIT)
        with tempfile.TemporaryDirectory() as tmp:
            vendored = Path(tmp)
            for relative, raw in files:
                (vendored / relative).parent.mkdir(parents=True, exist_ok=True)
                (vendored / relative).write_bytes(raw)
            code, report = self.run_checker(vendored, "--rev", NEXT_COMMIT)
        self.assertEqual(code, 1)
        anchor = next(r for r in report["sets"] if r["set"] == "commitment-anchor-authority-v0.3")
        self.assertEqual((anchor["status"], anchor["changes"]), ("drifted", ["members"]))
        self.assertTrue({"agreement", "agreementHash", "commitmentRecord", "commitmentRecordHash",
                         "commitmentSignature"} <= set(anchor["members"]))
        drifted_files = {f["path"] for f in report["files"] if f["status"] == "drifted"}
        self.assertTrue({"golden.json", "dacs-v0.1-happy-path.json", "dacs-v0.1-negative-paths.json",
                         "examples/identity-bundle.json"} <= drifted_files)

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
        # A tag ref may be absent from a clone that has the commit, so the
        # example uses the v0.4 commit and says how to make the tag resolve.
        self.assertIn(f"--rev {V04_COMMIT}\n", readme)
        self.assertIn(f"--rev {V04_COMMIT}\n", SCRIPT_PATH.read_text(encoding="utf-8"))
        self.assertNotIn("--rev v0.4", readme)
        self.assertIn("(`git fetch --tags`)", readme)
        self.assertIn(" --subset --sets-only\n", readme)
        self.assertIn(" --subset --sets-only\n", SCRIPT_PATH.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
