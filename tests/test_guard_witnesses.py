"""Run every registered guard-removal witness and check witness claims in docs.

See ``guard_witness`` for the convention.  A corpus test module that declares
``GUARD_WITNESSES`` must be listed in ``WITNESS_MODULES``.
"""
from __future__ import annotations

import contextlib
import importlib
import json
import re
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
for path in (str(ROOT / "scripts"), str(ROOT / "tests")):
    if path not in sys.path:
        sys.path.insert(0, path)

import guard_witness  # noqa: E402


WITNESS_MODULES = (
    "test_current_use_replay_corpus",
    "test_phase_bound_delivery_vectors",
)
CLAIM_DOCUMENTS = (
    ROOT / "CHANGELOG.md",
    *sorted((ROOT / "conformance").rglob("README.md")),
)


def registry():
    declarations = [
        importlib.import_module(name).GUARD_WITNESSES for name in WITNESS_MODULES
    ]
    return {witnesses.corpus: witnesses for witnesses in declarations}


def claim_documents():
    return {
        path.relative_to(ROOT).as_posix(): path.read_text(encoding="utf-8")
        for path in CLAIM_DOCUMENTS
    }


class _Toy:
    """A two-guard toy reference: `shape` then `rule`."""

    shape = True
    rule = True

    @classmethod
    def evaluate(cls, case):
        if cls.shape and case.get("broken"):
            return "error"
        if cls.rule and case.get("violates"):
            return "fail"
        return "pass"


@contextlib.contextmanager
def _toy_off(attribute, value=False):
    old = getattr(_Toy, attribute)
    setattr(_Toy, attribute, value)
    try:
        yield
    finally:
        setattr(_Toy, attribute, old)


class GuardWitnessTests(unittest.TestCase):
    def test_registered_witnesses_flip(self):
        for corpus, witnesses in registry().items():
            with self.subTest(corpus=corpus):
                self.assertEqual([], guard_witness.witness_failures(witnesses))

    def test_every_declaration_is_registered(self):
        declared = {
            path.stem for path in (ROOT / "tests").glob("test_*.py")
            if re.search(r"^GUARD_WITNESSES\s*=", path.read_text(encoding="utf-8"), re.M)
        }
        self.assertEqual(set(WITNESS_MODULES), declared)

    def test_witness_claims_in_docs_are_backed(self):
        self.assertEqual(
            [], guard_witness.claim_problems(claim_documents(), registry())
        )

    def _toy_witnesses(self, directory, cases, guards, controls):
        path = Path(directory) / "toy-v1.json"
        path.write_text(json.dumps({"set": "toy-v1", "vectors": [
            {"name": "control", "expected": "pass"},
            {"name": "shape-broken", "expected": "error", "broken": True},
            {"name": "rule-violation", "expected": "fail", "violates": True},
            {"name": "shape-gated-rule-violation", "expected": "error",
             "broken": True, "violates": True},
        ]}), encoding="utf-8")
        return guard_witness.CorpusWitnesses(
            corpus="toy-v1", path=path, evaluate=_Toy.evaluate,
            guards=guards, cases=cases, controls=controls,
        )

    def test_harness_rejects_non_flipping_and_broad_removals(self):
        rule_off = lambda: _toy_off("rule")  # noqa: E731

        @contextlib.contextmanager
        def both_off():
            with _toy_off("shape"), _toy_off("rule"):
                yield

        with tempfile.TemporaryDirectory() as directory:
            good = self._toy_witnesses(
                directory, {"rule-violation": "rule"}, {"rule": rule_off},
                {"rule": ("control", "shape-broken")},
            )
            self.assertEqual([], guard_witness.witness_failures(good))

            # The shape gate decides this case first: removing the rule
            # guard does not change it, as with the PR #426 PDE-5 cases.
            shadowed = self._toy_witnesses(
                directory, {"shape-gated-rule-violation": "rule"}, {"rule": rule_off},
                {"rule": ("control",)},
            )
            [problem] = guard_witness.witness_failures(shadowed)
            self.assertIn("does not witness it", problem)

            # Removing both guards also flips the case, but the shape control
            # changes too, so it is not a single-guard witness.
            broad = self._toy_witnesses(
                directory, {"rule-violation": "rule"}, {"rule": both_off},
                {"rule": ("shape-broken", "control")},
            )
            [problem] = guard_witness.witness_failures(broad)
            self.assertIn("control 'shape-broken' changes", problem)

            uncontrolled = self._toy_witnesses(
                directory, {"rule-violation": "rule"}, {"rule": rule_off}, {},
            )
            self.assertEqual(
                ["toy-v1 / rule: guard has no control case"],
                guard_witness.witness_failures(uncontrolled),
            )
            missing = self._toy_witnesses(
                directory, {"no-such-case": "rule"}, {"rule": rule_off},
                {"rule": ("control",)},
            )
            self.assertEqual(
                ["toy-v1: case 'no-such-case' is not in the corpus"],
                guard_witness.witness_failures(missing),
            )

    def test_claim_check_on_constructed_text(self):
        reg = registry()
        lab = "corpus=current-use-reputation-v1"
        sentence = (
            "- adds `buyer-seller-role-rebinding` and `missing-era-proof`; each new "
            "case is one a verifier ignoring its rule gets wrong."
        )
        unmarked = guard_witness.claim_problems({"X.md": sentence}, reg)
        self.assertEqual(
            ["X.md:1: claims each case catches its rule but has no "
             "guard-witness-claim marker"], unmarked,
        )
        marked = sentence + (
            "\n  <!-- guard-witness-claim: %s "
            "cases=buyer-seller-role-rebinding,missing-era-proof -->" % lab
        )
        self.assertEqual([], guard_witness.claim_problems({"X.md": marked}, reg))

        # A listed case without a witness entry fails, as does a case the
        # paragraph names but the marker leaves out.
        unwitnessed = sentence.replace("missing-era-proof", "historical-original-pure-mapping") + (
            "\n<!-- guard-witness-claim: %s cases=buyer-seller-role-rebinding,"
            "historical-original-pure-mapping -->" % lab
        )
        self.assertEqual(
            ["X.md:1: historical-original-pure-mapping has no guard witness entry"],
            guard_witness.claim_problems({"X.md": unwitnessed}, reg),
        )
        omitted = sentence + (
            "\n<!-- guard-witness-claim: %s cases=buyer-seller-role-rebinding -->" % lab
        )
        self.assertEqual(
            ["X.md:1: names missing-era-proof, which the marker lists neither "
             "as witnessed nor as a control"],
            guard_witness.claim_problems({"X.md": omitted}, reg),
        )
        glob = (
            "Each `credential-*-signature-mutation` case fails, so a verifier "
            "skipping the delivery signature check gets it wrong.\n"
            "<!-- guard-witness-claim: corpus=phase-bound-delivery-evidence-v0.7 "
            "cases=credential-ref-signer-signature-mutation -->"
        )
        self.assertEqual(6, len(guard_witness.claim_problems({"X.md": glob}, reg)))
        for bad in ("corpus=nope cases=a", "cases=a", "corpus=x cases=a extra"):
            with self.subTest(marker=bad):
                self.assertEqual(1, len(guard_witness.claim_problems(
                    {"X.md": "text <!-- guard-witness-claim: %s -->" % bad}, reg
                )))

    def test_unwitnessed_cases_contradict_a_claim(self):
        # The PDE paragraph as reviewed: "each ... fails at the
        # delivery-signature guard" while the marker left the two
        # binding-only cases unwitnessed. Removing PDE-2 leaves them `fail`,
        # so the claim was false and the marker must not certify it.
        reg = registry()
        corpus = "corpus=phase-bound-delivery-evidence-v0.7"
        coherent = (
            "credential-ref-anchor-locator-signature-mutation,"
            "credential-ref-content-hash-signature-mutation,"
            "credential-ref-signer-signature-mutation,"
            "credential-access-model-signature-mutation,"
            "credential-cleartext-hash-signature-mutation"
        )
        binding_only = (
            "credential-ref-anchor-kind-signature-mutation,"
            "credential-renewal-seq-signature-mutation"
        )
        claim = (
            "- adds seven `credential-*-signature-mutation` cases. Each keeps a "
            "valid bundle and fails at the delivery-signature guard, so "
            "skipping the delivery signature turns them into `pass`.\n"
        )
        reviewed = claim + "  <!-- guard-witness-claim: %s cases=%s unwitnessed=%s -->" % (
            corpus, coherent, binding_only,
        )
        self.assertEqual(
            ["X.md:1: claims each case catches its rule but leaves %s unwitnessed; "
             "witness it, list it as a control, or narrow the claim" % name
             for name in binding_only.split(",")],
            guard_witness.claim_problems({"X.md": reviewed}, reg),
        )
        # Renaming the field does not make the claim true: the paragraph
        # still says each of the seven turns into `pass`, so listing the two
        # as controls without saying so is refused too.
        controlled = claim + "  <!-- guard-witness-claim: %s cases=%s controls=%s -->" % (
            corpus, coherent, binding_only,
        )
        self.assertEqual(
            ["X.md:1: claims each case catches its rule but lists controls %s without "
             "calling them controls; say which cases are controls, not witnesses, "
             "or narrow the claim" % binding_only],
            guard_witness.claim_problems({"X.md": controlled}, reg),
        )
        # The narrowed paragraph that says which cases are controls is backed:
        # the harness shows the PDE-2 removal leaves them `fail`.
        narrowed = (
            "- adds seven `credential-*-signature-mutation` cases. Each is rejected "
            "by the delivery-signature check. Only the locator, content-hash, "
            "signer, access-model and cleartext-hash cases witness that check: "
            "skipping the delivery signature turns them into `pass`. The anchor-kind "
            "and renewal cases stay `fail` without it; they are controls, not "
            "delivery-signature witnesses.\n"
            "  <!-- guard-witness-claim: %s cases=%s controls=%s -->"
            % (corpus, coherent, binding_only)
        )
        self.assertEqual([], guard_witness.claim_problems({"X.md": narrowed}, reg))
        # A control that is not declared as one is refused.
        undeclared = narrowed.replace(
            binding_only, binding_only + ",delivery-signature-mutation"
        )
        self.assertEqual(
            ["X.md:1: control delivery-signature-mutation is not a declared control"],
            guard_witness.claim_problems({"X.md": undeclared}, reg),
        )
        # Outside a claiming paragraph `unwitnessed=` still just covers a name.
        plain = (
            "The `credential-ref-anchor-kind-signature-mutation` case changes "
            "only the binding leaf.\n<!-- guard-witness-claim: %s cases=%s "
            "unwitnessed=credential-ref-anchor-kind-signature-mutation -->"
            % (corpus, "credential-ref-signer-signature-mutation")
        )
        self.assertEqual([], guard_witness.claim_problems({"X.md": plain}, reg))

    def test_controls_belong_to_the_witnessed_guard(self):
        # A control declared only for another guard says nothing about the
        # guard this marker's cases witness.
        with tempfile.TemporaryDirectory() as directory:
            witnesses = self._toy_witnesses(
                directory, {"rule-violation": "rule", "shape-broken": "shape"},
                {"rule": lambda: _toy_off("rule"), "shape": lambda: _toy_off("shape")},
                {"rule": ("control",), "shape": ("rule-violation",)},
            )
            reg = {"toy-v1": witnesses}
            text = ("Each case is rejected only by its guard; `%s` is a control.\n"
                    "<!-- guard-witness-claim: corpus=toy-v1 cases=%s controls=%s -->")
            self.assertEqual([], guard_witness.claim_problems(
                {"X.md": text % ("control", "rule-violation", "control")}, reg
            ))
            self.assertEqual(
                ["X.md:1: control control is declared only for rule, not for a "
                 "guard the listed cases witness"],
                guard_witness.claim_problems(
                    {"X.md": text % ("control", "shape-broken", "control")}, reg
                ),
            )

    def test_harness_compares_the_declared_set(self):
        with tempfile.TemporaryDirectory() as directory:
            witnesses = self._toy_witnesses(
                directory, {"rule-violation": "rule"},
                {"rule": lambda: _toy_off("rule")}, {"rule": ("control",)},
            )
            document = json.loads(witnesses.path.read_text(encoding="utf-8"))
            document["set"] = "toy-v2"
            witnesses.path.write_text(json.dumps(document), encoding="utf-8")
            [problem] = guard_witness.witness_failures(witnesses)
            self.assertIn("does not name", problem)
            self.assertIn("'toy-v2'", problem)

    def test_claim_detector_recognises_witness_phrasings(self):
        for text in (
            "Each new case is one a verifier ignoring its rule gets wrong.",
            "Each negative is rejected only by its named guard.",
            "Every added case pins its rule.",
            "Each case fails, and skipping the signature check turns them into `pass`.",
            "Each negative is replayed against a verifier missing only its named LAB guard.",
            # The two corpus README claims the reviewed head left unmarked.
            "Five named non-passing cases each isolate one LAB guard:",
            "Each negative carries otherwise valid signed bundles, bindings and "
            "finalized receipts: a verifier that omits only its named guard accepts it.",
            "Every new case fails only when its guard is removed.",
            "Each added case is rejected by exactly one guard; removing that "
            "guard makes it pass.",
            "All five negatives catch their rule.",
        ):
            with self.subTest(text=text):
                self.assertTrue(guard_witness.is_witness_claim(text))

    def test_claim_detector_ignores_ordinary_prose_and_code(self):
        for text in (
            "Each vector carries an `expected` disposition.",
            "A verifier without the key returns indeterminate.",
            "```\neach case is one a verifier ignoring its rule gets wrong\n```",
        ):
            with self.subTest(text=text):
                self.assertEqual([], guard_witness.claim_problems({"X.md": text}, {}))

    def test_contributing_documents_both_checks(self):
        text = (ROOT / "CONTRIBUTING.md").read_text(encoding="utf-8")
        for needle in (
            "tests/test_signature_vector_consistency.py",
            "tests/test_guard_witnesses.py",
            "GUARD_WITNESSES",
            "<!-- guard-witness-claim:",
            "ALLOWED_OFFENDERS",
        ):
            with self.subTest(needle=needle):
                self.assertTrue(needle in text, "CONTRIBUTING.md lacks %s" % needle)

    def test_workflow_runs_the_consistency_checks(self):
        workflow = (ROOT / ".github" / "workflows" / "validate.yml").read_text(encoding="utf-8")
        command = (
            "python3 -m unittest tests.test_signature_vector_consistency "
            "tests.test_guard_witnesses"
        )
        self.assertTrue(command in workflow, "validate.yml does not run %s" % command)


if __name__ == "__main__":
    unittest.main()
