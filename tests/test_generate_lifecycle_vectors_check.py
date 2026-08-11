"""Fail-closed proof for `scripts/generate_lifecycle_vectors.py --check`.

The gate is only worth wiring into CI if it can FAIL, and fails for the RIGHT
reason. A pristine tree exits 0 (test_control) — but so did the old
non-enforcing --check, so every other case here applies ONE targeted corruption
and asserts the SPECIFIC condition tag the gate must emit, never merely
"non-zero". A run in which every corruption collapsed into one generic error
would pass a non-zero-only test and still be a broken gate.

Method, mandatory for every case:
  1. copy the pristine repo (scripts/ conformance/ spec/ — everything the
     generator + validate_conformance_vectors + specsource read) into a tmp dir;
  2. apply exactly one corruption to the COPY;
  3. invoke the real --check code path against the copy;
  4. assert exit is non-zero AND the specific tag is present;
  5. the real committed fixtures are never touched — asserted byte-unchanged.

Two conditions are structurally reachable only from a GENERATOR regression, not
a fixture edit, because the gate compares a pristine `before` against the
regenerated `after` and the generator normalises fixture-side signature/opaque
edits away (see test_opaque_* and test_distribution_* docstrings). Those are
exercised by perturbing the generator/expectation copy — the real regression
class each guard exists to catch. One condition (nondeterminism) is not
exercised at all; see NondeterminismConditionUnproven for why.

--check does not cover everything: because it renders from the committed file
and echoes undrived fields, a corruption in a field that is both echoed verbatim
AND excluded from the signed hash cancels on both sides and passes (see the
generator module's "Scope of --check"). That residual class is backstopped here
by HashExcludedFieldTamperTripwire, which pins the committed corpus by exact
sha256 — not by the six-condition cases above.
"""
import json
import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from typing import List

ROOT = Path(__file__).resolve().parents[1]
HAPPY_REL = "conformance/vectors/dacs-v0.1-happy-path.json"
NEGATIVE_REL = "conformance/vectors/dacs-v0.1-negative-paths.json"
GENERATOR_REL = "scripts/generate_lifecycle_vectors.py"
VCV_REL = "scripts/validate_conformance_vectors.py"
COPY_DIRS = ("scripts", "conformance", "spec")

# Baseline hashes of the committed fixtures. The whole suite must leave these
# byte-identical; a moved hash is a silent corpus mutation, not a test pass.
BASELINE_SHA = {
    HAPPY_REL: "ebb618d5d19d632c3a872205a24a9345fbf89eff58d14305d4b7a3c25cab0912",
    NEGATIVE_REL: "0586a82c80fc11fc2c69bcb439671fd33ac32e3a51e50ad02e627f6ce5716a4e",
}

_TAG = re.compile(r"\[[A-Z-]+\]")


def _sha256(path: Path) -> str:
    import hashlib

    return hashlib.sha256(path.read_bytes()).hexdigest()


def _tags(text: str) -> List[str]:
    return sorted(set(_TAG.findall(text)))


def _stage() -> Path:
    """A throwaway copy of the repo subset the generator reads."""
    tmp = Path(tempfile.mkdtemp(prefix="lifecycle_check_"))
    for d in COPY_DIRS:
        shutil.copytree(ROOT / d, tmp / d)
    return tmp


def _run_check(repo: Path) -> subprocess.CompletedProcess:
    """Invoke the real CLI entrypoint (exactly what CI runs)."""
    return subprocess.run(
        ["python3", str(repo / GENERATOR_REL), "--check"],
        cwd=repo,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )


def _load(repo: Path, rel: str) -> dict:
    return json.loads((repo / rel).read_text(encoding="utf-8"))


def _dump(repo: Path, rel: str, data: dict) -> None:
    (repo / rel).write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def _flip_last_hex(value: str) -> str:
    """Change a 64-hex string's value while keeping it valid hex (and 64 long)."""
    return value[:-1] + ("0" if value[-1] != "0" else "1")


def _find(data: dict, artifact_id: str) -> dict:
    return next(a for a in data["artifacts"] if a["id"] == artifact_id)


class LifecycleCheckGateTests(unittest.TestCase):
    def setUp(self) -> None:
        self.repo = _stage()
        self.addCleanup(shutil.rmtree, self.repo, ignore_errors=True)

    # ---- A7 control: the heal-assertion. Without it every case below could be
    # green because the harness is broken. ----------------------------------
    def test_control_pristine_tree_passes(self) -> None:
        r = _run_check(self.repo)
        self.assertEqual(r.returncode, 0, r.stderr + r.stdout)
        self.assertEqual(_tags(r.stderr), [], "pristine tree must emit no failure tag")
        self.assertIn("all six gate conditions pass", r.stdout)

    # ---- A1: fixture drift, each chain independently -----------------------
    def test_fixture_drift_happy_flagged_DRIFT(self) -> None:
        # A DERIVED cross-reference: the generator recomputes it to the correct
        # value, so the render succeeds and the rendered bytes disagree with the
        # committed (corrupted) file — i.e. the comparison is what fails.
        data = _load(self.repo, HAPPY_REL)
        ref = _find(data, "agreement-fixed-price")["artifact"]["listingRef"]
        ref["contentHash"] = _flip_last_hex(ref["contentHash"])
        _dump(self.repo, HAPPY_REL, data)
        r = _run_check(self.repo)
        self.assertNotEqual(r.returncode, 0, r.stdout)
        self.assertIn("[DRIFT]", r.stderr)
        self.assertIn("dacs-v0.1-happy-path.json", r.stderr)

    def test_fixture_drift_negative_flagged_DRIFT(self) -> None:
        # The old --check never looked at the negative chain at all, so a
        # negative-only drift is the regression this case pins.
        data = _load(self.repo, NEGATIVE_REL)
        ref = _find(data, "neg-agreement-fixed-price")["artifact"]["listingRef"]
        ref["contentHash"] = _flip_last_hex(ref["contentHash"])
        _dump(self.repo, NEGATIVE_REL, data)
        r = _run_check(self.repo)
        self.assertNotEqual(r.returncode, 0, r.stdout)
        self.assertIn("[DRIFT]", r.stderr)
        self.assertIn("dacs-v0.1-negative-paths.json", r.stderr)

    # ---- A2: generator perturbation, fixtures pristine ---------------------
    def test_generator_render_perturbation_flagged_DRIFT(self) -> None:
        # Drift is caught from EITHER side: perturb the render (indent) with the
        # committed fixtures untouched, and the gate still fails as [DRIFT].
        gen = self.repo / GENERATOR_REL
        src = gen.read_text(encoding="utf-8")
        perturbed = src.replace(
            'json.dumps(after, indent=2, ensure_ascii=False) + "\\n"',
            'json.dumps(after, indent=4, ensure_ascii=False) + "\\n"',
            1,
        )
        self.assertNotEqual(perturbed, src, "expected render line to be present")
        gen.write_text(perturbed, encoding="utf-8")
        r = _run_check(self.repo)
        self.assertNotEqual(r.returncode, 0, r.stdout)
        self.assertIn("[DRIFT]", r.stderr)

    # ---- A3: cannot-run, distinguishable from drift ------------------------
    # The informational reproduction table reads the fixtures directly, so it
    # would crash on a missing/malformed fixture before the gate ran. The CLI now
    # isolates that table, so a cannot-run surfaces as the gate's clean
    # [CANNOT-RUN] message at the CLI itself — no traceback — and never as drift.
    def test_absent_fixture_cli_reports_CANNOT_RUN_not_drift_no_traceback(self) -> None:
        (self.repo / HAPPY_REL).unlink()
        r = _run_check(self.repo)
        self.assertNotEqual(r.returncode, 0, r.stdout)
        self.assertIn("[CANNOT-RUN]", r.stderr)
        self.assertIn("NOT a drift", r.stderr)
        self.assertNotIn("[DRIFT]", r.stderr)
        self.assertNotIn("Traceback", r.stderr)

    def test_malformed_fixture_cli_reports_CANNOT_RUN_not_drift_no_traceback(self) -> None:
        (self.repo / NEGATIVE_REL).write_text("{ this is not valid json", encoding="utf-8")
        r = _run_check(self.repo)
        self.assertNotEqual(r.returncode, 0, r.stdout)
        self.assertIn("[CANNOT-RUN]", r.stderr)
        self.assertIn("NOT a drift", r.stderr)
        self.assertNotIn("[DRIFT]", r.stderr)
        self.assertNotIn("Traceback", r.stderr)

    def test_absent_fixture_entrypoint_fails_and_never_passes(self) -> None:
        # Invariant guard, complementary to the case above: whatever the surface,
        # the CLI must never read as a pass on a missing fixture. Kept as a
        # standalone belt-and-suspenders check on the pass wording.
        (self.repo / HAPPY_REL).unlink()
        r = _run_check(self.repo)
        self.assertNotEqual(r.returncode, 0)
        self.assertNotIn("all six gate conditions pass", r.stdout)

    # ---- A4: unresolved reference ------------------------------------------
    def test_unresolved_reference_flagged_UNRESOLVED_not_cannot_run(self) -> None:
        # Every EXISTING 64-hex in the corpus is either generator-derived (a
        # corruption is corrected -> [DRIFT]) or a declared opaque input (a
        # corruption cascades -> [DRIFT]); none corrupts into "unresolved".
        # A dangling reference that resolves to nothing must therefore be a
        # 64-hex the generator does not rewrite: inject one and assert the tag is
        # [UNRESOLVED-REFERENCE], NOT [CANNOT-RUN]. (Condition 4 is classified by
        # exception TYPE — UnresolvedReferenceError, a ValueError subclass — since
        # Step-5b; test_unresolved_reference_classified_by_type_not_message pins
        # that the routing is message-independent.)
        data = _load(self.repo, HAPPY_REL)
        _find(data, "listing-analyze-csv")["artifact"]["strayRef"] = "0" * 64
        _dump(self.repo, HAPPY_REL, data)
        r = _run_check(self.repo)
        self.assertNotEqual(r.returncode, 0, r.stdout)
        self.assertIn("[UNRESOLVED-REFERENCE]", r.stderr)
        self.assertNotIn("[CANNOT-RUN]", r.stderr)

    def test_unresolved_reference_classified_by_type_not_message(self) -> None:
        # Structural classification (Step-5b): condition 4 is routed by exception
        # TYPE (UnresolvedReferenceError), never by matching the word "unresolved"
        # in the message. Reword ONLY the raise site's message (the type is kept)
        # and inject a dangling reference; the tag must stay [UNRESOLVED-REFERENCE].
        # This is a heal-assertion: it FAILS against the old substring impl (which
        # reclassified a reworded message as [CANNOT-RUN]) and PASSES against the
        # type-based one.
        gen = self.repo / GENERATOR_REL
        src = gen.read_text(encoding="utf-8")
        reworded = src.replace(
            "unresolved 64-hex value(s) after regeneration",
            "dangling 64-hex value(s) post-regen",
            1,
        )
        self.assertNotEqual(reworded, src, "expected the raise message fragment to be present")
        self.assertNotIn("unresolved 64-hex value(s) after regeneration", reworded)
        gen.write_text(reworded, encoding="utf-8")
        data = _load(self.repo, HAPPY_REL)
        _find(data, "listing-analyze-csv")["artifact"]["strayRef"] = "0" * 64
        _dump(self.repo, HAPPY_REL, data)
        r = _run_check(self.repo)
        self.assertNotEqual(r.returncode, 0, r.stdout)
        self.assertIn("[UNRESOLVED-REFERENCE]", r.stderr)
        self.assertNotIn("[CANNOT-RUN]", r.stderr)

    # ---- A5: opaque-input change (generator regression) --------------------
    def test_generator_mutating_opaque_input_flagged_OPAQUE_INPUT(self) -> None:
        # A fixture-side opaque edit is normalised away by the generator
        # (before == after), so this guard fires only when the GENERATOR mutates
        # an opaque input during regeneration — the real regression it exists to
        # catch. Simulate that: make regenerate_positive clobber an opaque digest.
        gen = self.repo / GENERATOR_REL
        src = gen.read_text(encoding="utf-8")
        anchor = '    composite = by_kind["CompositeVerificationRecord"]["artifact"]\n'
        injected = anchor + '    composite["bundleHash"] = "f" * 64  # regression: mutate opaque input\n'
        perturbed = src.replace(anchor, injected, 1)
        self.assertNotEqual(perturbed, src, "expected composite assignment to be present")
        gen.write_text(perturbed, encoding="utf-8")
        r = _run_check(self.repo)
        self.assertNotEqual(r.returncode, 0, r.stdout)
        self.assertIn("[OPAQUE-INPUT]", r.stderr)

    # ---- A6: signature distribution (expectation regression) ---------------
    def test_distribution_mismatch_flagged_SIGNATURE_DISTRIBUTION(self) -> None:
        # The generator always produces exactly the declared tamper distribution
        # (it re-signs then re-tampers), so a fixture-side signature edit cannot
        # change the observed distribution. This guard fires when the corpus-
        # derived EXPECTATION and the produced distribution disagree. Point the
        # expectation at the wrong artifact; the generator still produces the
        # real tamper, so the only failure is a real [SIGNATURE-DISTRIBUTION]
        # mismatch (no drift — the render is unchanged).
        vcv = self.repo / VCV_REL
        src = vcv.read_text(encoding="utf-8")
        perturbed = src.replace(
            '("signatures[0]", "neg-bundle-tampered-signature"),',
            '("signatures[0]", "neg-agreement-fixed-price"),',
            1,
        )
        self.assertNotEqual(perturbed, src, "expected INTENTIONAL_SIGNATURE_TAMPERS entry")
        vcv.write_text(perturbed, encoding="utf-8")
        r = _run_check(self.repo)
        self.assertNotEqual(r.returncode, 0, r.stdout)
        self.assertIn("[SIGNATURE-DISTRIBUTION]", r.stderr)
        self.assertIn("unexpected signature distribution", r.stderr)


class NondeterminismConditionUnproven(unittest.TestCase):
    """Condition 5 ([NONDETERMINISM]) is left unexercised, on purpose.

    The generator is deterministic by construction: fixed 0x41/0x42/0x43 seeds,
    a fixed structural tamper site, ed25519 (deterministic), and a stable JSON
    round-trip — two consecutive renders are always byte-identical. The only way
    to make them differ is to inject nondeterminism (a clock, a counter, RNG)
    INTO the generator, which does not correspond to any fixture/corpus
    corruption. Per the task's guidance, a guard that cannot be provoked without
    contriving a non-real failure mode is reported honestly rather than faked.

    The mechanism is not dead: it renders each chain twice and byte-compares
    (verified by reading Step 3's _check_determinism); it is simply not
    reachable by a corpus edit. This placeholder records that reasoning so the
    gap is disclosed, not silently omitted.
    """

    def test_condition_five_is_structurally_present(self) -> None:
        src = (ROOT / GENERATOR_REL).read_text(encoding="utf-8")
        self.assertIn("def _check_determinism", src)
        self.assertIn("[NONDETERMINISM]", src)


class HashExcludedFieldTamperTripwire(unittest.TestCase):
    """Backstop for the one class of corruption --check structurally cannot see.

    --check renders from `before = json.loads(committed)` and echoes every field
    it does not derive, so a corruption in a field that is BOTH echoed verbatim
    AND excluded from the signed §B.2 hash appears identically on both sides of
    its byte comparison and cancels — it passes. Confirmed examples of that class:
    the wrapper-level `id` (outside the signed artifact object) and `anchoredByRole`
    (hash-excluded per DACS-5 §10.4.1; see validate_conformance_vectors.HASH_EXCLUDED).
    These are examples, not the whole class — the class is every generator-echoed,
    hash-excluded field — so this pins the committed corpus by exact sha256 rather
    than asserting any one field, which catches ANY byte change to the fixtures.

    Requiring a hand update to these baselines after a legitimate `--write` is
    intentional, not brittleness: a conformance corpus SHOULD take a deliberate
    act to change, and this mirrors the repo's existing pinned-hash precedent —
    each security vector set JSON carries a declared `hash` that
    validate_security_vectors.py verifies, likewise requiring a deliberate
    regeneration to move."""

    def test_committed_fixtures_match_baseline(self) -> None:
        for rel, want in BASELINE_SHA.items():
            self.assertEqual(_sha256(ROOT / rel), want, f"{rel} drifted from baseline")


if __name__ == "__main__":
    unittest.main()
