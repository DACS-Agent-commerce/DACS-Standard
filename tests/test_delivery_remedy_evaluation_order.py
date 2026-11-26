"""Every delivery-or-remedy verdict is independent of evaluation order.

The whole-pack permutation test runs for several minutes, so it is kept apart
from tests/test_delivery_remedy_candidate_vectors.py, whose other tests stay
within the per-file test timeout.  It shares that file's pack helpers.
"""

import copy
import itertools
import json
import random
import unittest

import test_delivery_remedy_candidate_vectors as pack_tests
from scripts.verify_delivery_remedy_candidate_vectors import (
    DecisionLedger,
    evaluate_lifecycles,
    evaluate_protocol,
)
from test_delivery_remedy_candidate_vectors import VECTOR_PACK, verdict


class DeliveryRemedyEvaluationOrderTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.vector_pack = json.loads(VECTOR_PACK.read_text(encoding="utf-8"))
        cls.vectors = {item["name"]: item for item in cls.vector_pack["vectors"]}

    # The pack test class's helpers, borrowed without binding that class here:
    # a TestCase class named in this module would run all of its tests again.
    _vector = pack_tests.DeliveryRemedyCandidateVectorTests._vector
    _streamed = pack_tests.DeliveryRemedyCandidateVectorTests._streamed
    _assert_no_conflicting_pass = pack_tests.DeliveryRemedyCandidateVectorTests._assert_no_conflicting_pass

    def test_verdicts_do_not_depend_on_evaluation_order(self):
        vectors = self.vector_pack["vectors"]
        values = {vector["name"]: self._vector(vector["name"]) for vector in vectors}
        # Standalone positives; a vector with `evaluatedWith` is a replay scenario.
        positives = [
            vector["name"] for vector in vectors
            if vector["expected"] == "pass" and "evaluatedWith" not in vector
        ]
        for order in (positives, positives[::-1]):
            ledger = DecisionLedger()
            for _ in range(2):
                for name in order:
                    with self.subTest(order=order[0], vector=name):
                        observed = evaluate_protocol(copy.deepcopy(values[name]), ledger)
                        self.assertEqual(observed["result"], "pass")
                        self.assertNotIn("revises", observed)
        # Each vector set keeps its pinned verdict in every evaluation order.
        for vector in vectors:
            members = [*vector.get("evaluatedWith", []), vector["name"]]
            for order in itertools.permutations(members):
                with self.subTest(vector=vector["name"], order=order):
                    observed = evaluate_lifecycles(
                        [copy.deepcopy(values[name]) for name in order], DecisionLedger()
                    )[order.index(vector["name"])]
                    self.assertEqual(verdict(observed), (vector["expected"], vector["expectedRule"]))
        # The whole pack evaluated as one set: every verdict is the same in
        # any order, and no two conflicting terminals both pass.
        names = list(values)
        baseline = None
        for order in (names, names[::-1], random.Random(372).sample(names, len(names))):
            observed = evaluate_lifecycles([copy.deepcopy(values[name]) for name in order], DecisionLedger())
            verdicts = {name: tuple(item.values()) for name, item in zip(order, observed)}
            baseline = baseline or verdicts
            self.assertEqual(verdicts, baseline)
        self._assert_no_conflicting_pass(values, baseline)
        # One at a time through one ledger, in either order, no two
        # conflicting terminals both pass either, and the verdicts as revised
        # are the verdicts of the whole pack as one set.
        for order in (names, names[::-1]):
            ledger = DecisionLedger()
            streamed = {name: tuple(evaluate_protocol(copy.deepcopy(values[name]), ledger).values()) for name in order}
            self._assert_no_conflicting_pass(values, streamed)
            with self.subTest(streamed=order[0]):
                self.assertEqual(
                    self._streamed(values, order), {name: outcome[:2] for name, outcome in baseline.items()}
                )
        # With every standalone positive already known, each vector without
        # companions keeps its pinned verdict.
        shared = DecisionLedger()
        for name in positives:
            evaluate_protocol(copy.deepcopy(values[name]), shared)
        for vector in vectors:
            if "evaluatedWith" in vector:
                continue
            with self.subTest(shared=vector["name"]):
                observed = evaluate_protocol(copy.deepcopy(values[vector["name"]]), copy.deepcopy(shared))
                self.assertEqual(verdict(observed), (vector["expected"], vector["expectedRule"]))


if __name__ == "__main__":
    unittest.main()
