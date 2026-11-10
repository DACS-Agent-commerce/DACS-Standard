import decimal
import hashlib
import json
import re
import unicodedata
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
VECTORS = (
    ROOT / "conformance" / "vectors" / "security"
    / "cci-tlsn-stored-proof-check-v0.1.json"
)
SPEC = ROOT / "spec" / "DACS-2-VET.md"
HEX64 = re.compile(r"[0-9a-f]{64}")
PARSER_OUTCOMES = (
    "pass", "fail", "indeterminate", "error-executed", "error-pra5-preinvocation",
)
CHECK_RESULTS = (
    "pass-no-subject", "pass-subject-declared", "fail-stored-proof", "fail-subject",
)


class DuplicateMemberName(ValueError):
    pass


def is_identifier(value):
    """Exactly 64 lowercase hex characters, nothing before or after."""
    return isinstance(value, str) and HEX64.fullmatch(value) is not None


def reject_duplicate_members(pairs):
    names = [name for name, _ in pairs]
    if len(names) != len(set(names)):
        raise DuplicateMemberName(names)
    return dict(pairs)


def parse_exact(text, object_pairs_hook=None):
    """Parse JSON text with every number as an exact decimal (never a float)."""
    return json.loads(
        text,
        parse_float=decimal.Decimal,
        parse_int=decimal.Decimal,
        object_pairs_hook=object_pairs_hook,
    )


def parse_proof_text(text):
    return parse_exact(text, object_pairs_hook=reject_duplicate_members)


def supplied_proof(vector):
    """The supplied proof; `bodyRaw` is JSON text so duplicates and exact numbers survive."""
    proof = vector["proof"]
    if "bodyRaw" in proof:
        return parse_proof_text(proof["bodyRaw"])
    return proof["body"]


def stored_proof(entry):
    """The stored proof; `proofRaw` is JSON text so duplicates and exact numbers survive."""
    if "proofRaw" in entry:
        return parse_proof_text(entry["proofRaw"])
    return entry["proof"]


def json_equal(a, b):
    """Type-preserving structural equality of two parsed JSON values.

    Numbers must be `decimal.Decimal` (or `int`) and are compared exactly; a
    binary float is refused because it would round.
    """
    if isinstance(a, bool) or isinstance(b, bool):
        return isinstance(a, bool) and isinstance(b, bool) and a == b
    if isinstance(a, float) or isinstance(b, float):
        raise TypeError("numbers are compared as exact decimals, not floats")
    if a is None or b is None:
        return a is None and b is None
    if isinstance(a, str) or isinstance(b, str):
        return isinstance(a, str) and isinstance(b, str) and a == b
    numbers = (int, decimal.Decimal)
    if isinstance(a, numbers) or isinstance(b, numbers):
        return isinstance(a, numbers) and isinstance(b, numbers) and a == b
    if isinstance(a, list) or isinstance(b, list):
        return (
            isinstance(a, list) and isinstance(b, list) and len(a) == len(b)
            and all(json_equal(x, y) for x, y in zip(a, b))
        )
    if isinstance(a, dict) and isinstance(b, dict):
        return a.keys() == b.keys() and all(json_equal(a[k], b[k]) for k in a)
    return False


def stored_proof_ok(vector):
    """H resolves to a stored entry and the supplied proof equals its proof."""
    entry = vector["storedEntry"]
    if entry is None:
        return False
    try:
        return json_equal(supplied_proof(vector), stored_proof(entry))
    except DuplicateMemberName:
        return False


def subject_ok(vector):
    """A declared subject equals the stored userId as JSON strings only."""
    if "subject" not in vector["recipe"]["dataMap"]:
        return True
    subject = vector["proof"]["subject"]
    user_id = vector["storedEntry"]["userId"]
    if not isinstance(subject, str) or not isinstance(user_id, str):
        return False
    return unicodedata.normalize("NFC", subject) == unicodedata.normalize("NFC", user_id)


def evaluate(vector):
    """Return (expected, failedPart) for a cci-tlsn stored-proof check vector."""
    if not stored_proof_ok(vector):
        return "fail", "stored-proof"
    if not subject_ok(vector):
        return "fail", "subject"
    return "pass", None


def compose(check, parser):
    """Final outcome from the stored-proof check result and the parser outcome.

    Composes outcomes only; it does not run a parser. A PRA-5 `error` returned
    before the parser is invoked stands and the check is not evaluated. Otherwise
    part (2) stands over whatever an executed parser gives; part (3) applies only
    when the parser gives `pass`.
    """
    if check not in CHECK_RESULTS or parser not in PARSER_OUTCOMES:
        raise ValueError((check, parser))
    if parser == "error-pra5-preinvocation":
        return "error"
    if check == "fail-stored-proof":
        return "fail"
    if parser == "pass":
        return "fail" if check == "fail-subject" else "pass"
    if parser == "error-executed":
        return "error"
    return parser


def spec_section():
    text = SPEC.read_text(encoding="utf-8")
    start = text.index("#### 7.3.3 tlsnotary")
    return text[start:text.index("#### 7.3.4 zktls")]


def stored_proof_paragraph():
    section = spec_section()
    start = section.index("*Stored-proof check (`cci-tlsn` only).*")
    return section[start:].split("\n\n")[0]


class CciTlsnStoredProofCheckVectorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        text = VECTORS.read_text(encoding="utf-8")
        cls.document = parse_exact(text)
        cls.plain_document = json.loads(text)
        cls.vectors = {v["name"]: v for v in cls.document["vectors"]}

    def test_set_metadata_is_self_consistent(self):
        document = self.plain_document
        self.assertEqual(document["set"], VECTORS.stem)
        self.assertEqual(document["count"], len(document["vectors"]))
        self.assertEqual(len(self.vectors), len(document["vectors"]))
        digest = hashlib.sha256(
            json.dumps(
                document["vectors"], separators=(",", ":"), ensure_ascii=False
            ).encode("utf-8")
        ).hexdigest()
        self.assertEqual(document["hash"], digest)

    def test_every_vector_is_cci_tlsn_with_a_64_hex_lowercase_identifier(self):
        for vector in self.document["vectors"]:
            with self.subTest(vector=vector["name"]):
                self.assertEqual(vector["scheme"], "cci-tlsn")
                self.assertTrue(is_identifier(vector["identifier"]))

    def test_identifier_helper_rejects_anything_but_exactly_64_lowercase_hex(self):
        good = "0" * 62 + "ab"
        self.assertEqual(len(good), 64)
        self.assertTrue(is_identifier(good))
        too_long = good + "0"
        self.assertEqual(len(too_long), 65)
        for bad in (too_long, good + "g", good + "\n", " " + good, good[:63], good.upper(), None):
            with self.subTest(value=bad):
                self.assertFalse(is_identifier(bad))

    def test_every_vector_matches_the_check(self):
        for vector in self.document["vectors"]:
            with self.subTest(vector=vector["name"]):
                self.assertEqual(
                    evaluate(vector), (vector["expected"], vector["failedPart"])
                )

    def test_required_cases_are_present_with_their_results(self):
        required = {
            "stored-proof-and-string-subject-equal": ("pass", None),
            "string-subject-differs-from-user-id": ("fail", "subject"),
            "number-subject-with-string-user-id": ("fail", "subject"),
            "string-subject-with-number-user-id": ("fail", "subject"),
            "proof-stored-under-another-hash": ("fail", "stored-proof"),
            "hash-resolves-to-no-stored-entry": ("fail", "stored-proof"),
            "declared-subject-resolves-to-nothing": ("fail", "subject"),
            "no-subject-declared-stored-proof-supplied": ("pass", None),
        }
        for name, result in required.items():
            with self.subTest(vector=name):
                self.assertIn(name, self.vectors)
                vector = self.vectors[name]
                self.assertEqual((vector["expected"], vector["failedPart"]), result)

    def test_number_cases_use_json_numbers_on_the_non_string_side(self):
        number_subject = self.vectors["number-subject-with-string-user-id"]
        self.assertEqual(number_subject["proof"]["subject"], 12345)
        self.assertIsInstance(number_subject["storedEntry"]["userId"], str)
        number_user_id = self.vectors["string-subject-with-number-user-id"]
        self.assertEqual(number_user_id["storedEntry"]["userId"], 12345)
        self.assertEqual(number_user_id["proof"]["subject"], "12345")
        both_numbers = self.vectors["number-subject-with-equal-number-user-id"]
        self.assertEqual(both_numbers["proof"]["subject"], both_numbers["storedEntry"]["userId"])
        self.assertNotIsInstance(both_numbers["proof"]["subject"], str)

    def test_each_part_fails_on_its_own(self):
        for vector in self.document["vectors"]:
            if vector["failedPart"] == "stored-proof":
                with self.subTest(vector=vector["name"]):
                    self.assertFalse(stored_proof_ok(vector))
                    # the subject part would not fail here, so only stored-proof decides
                    entry = vector["storedEntry"] or {"userId": vector["proof"]["subject"]}
                    self.assertTrue(subject_ok(dict(vector, storedEntry=entry)))
            if vector["failedPart"] == "subject":
                with self.subTest(vector=vector["name"]):
                    self.assertTrue(stored_proof_ok(vector))
                    self.assertFalse(subject_ok(vector))

    def test_decomposed_subject_equals_precomposed_user_id_after_nfc(self):
        vector = self.vectors["subject-equal-after-nfc"]
        self.assertNotEqual(vector["proof"]["subject"], vector["storedEntry"]["userId"])
        self.assertEqual(evaluate(vector), ("pass", None))

    def test_no_subject_declared_adds_nothing_beyond_the_stored_proof_match(self):
        for vector in self.document["vectors"]:
            if "subject" not in vector["recipe"]["dataMap"]:
                with self.subTest(vector=vector["name"]):
                    self.assertEqual(
                        vector["expected"], "pass" if stored_proof_ok(vector) else "fail"
                    )

    def test_json_equal_is_type_preserving_structural_equality(self):
        d = decimal.Decimal
        equal = (
            ({"a": d(1), "b": {"c": [d(1), d(2)], "d": None}},
             {"b": {"d": None, "c": [d(1), d(2)]}, "a": d(1)}),
            (d(1), d("1.0")),
            (d("0.5"), d("0.50")),
            (True, True),
            (None, None),
            ("caf\u00e9", "caf\u00e9"),
        )
        for a, b in equal:
            with self.subTest(equal=(a, b)):
                self.assertTrue(json_equal(a, b))
                self.assertTrue(json_equal(b, a))
        unequal = (
            (True, d(1)), (False, d(0)), (d(1), True), (d(0), False), (None, d(0)),
            (None, False), (None, ""), (d(1), "1"), ("1", d(1)), (d(1), d(2)),
            (d("1.5"), d(1)),
            ([d(1), d(2)], [d(2), d(1)]), ([d(1)], [d(1), d(1)]), ([], {}),
            ({"a": d(1)}, {"a": d(1), "b": d(2)}), ({"a": d(1)}, {"b": d(1)}),
            ({"a": True}, {"a": d(1)}), ({"a": [True]}, {"a": [d(1)]}),
            ("cafe\u0301", "caf\u00e9"), ("a", "A"),
        )
        for a, b in unequal:
            with self.subTest(unequal=(a, b)):
                self.assertFalse(json_equal(a, b))
                self.assertFalse(json_equal(b, a))

    def test_number_equality_is_exact_decimal_equality_of_the_json_text(self):
        for left, right in (("1", "1.0"), ("1", "1e0"), ("1e2", "100"), ("0.5", "5e-1")):
            with self.subTest(equal=(left, right)):
                self.assertTrue(json_equal(parse_exact(left), parse_exact(right)))
        for left, right in (("1.00000000000000001", "1"), ("1e2", "101"), ("0.1", "0.10000000000000001")):
            with self.subTest(unequal=(left, right)):
                self.assertFalse(json_equal(parse_exact(left), parse_exact(right)))

    def test_oracle_does_not_equate_close_numbers_through_float(self):
        close, one = "1.00000000000000001", "1"
        # a binary float cannot tell these apart, so a float path would call them equal
        self.assertEqual(float(close), float(one))
        self.assertFalse(json_equal(parse_exact(close), parse_exact(one)))
        self.assertFalse(json_equal(parse_exact("[" + close + "]"), parse_exact("[" + one + "]")))
        with self.assertRaises(TypeError):
            json_equal(json.loads(close), json.loads(one))
        # booleans stay distinct from the numbers 1 and 0 on the exact path
        self.assertFalse(json_equal(parse_exact("true"), parse_exact("1")))
        self.assertFalse(json_equal(parse_exact("false"), parse_exact("0")))

    def test_duplicate_member_names_are_rejected_wherever_they_occur(self):
        for raw in (
            '{"valid":false,"valid":true}',
            '{"outer":{"a":1,"a":1}}',
            '[{"a":1,"a":2}]',
        ):
            with self.subTest(raw=raw):
                with self.assertRaises(DuplicateMemberName):
                    supplied_proof({"proof": {"bodyRaw": raw}})
                with self.assertRaises(DuplicateMemberName):
                    stored_proof({"proofRaw": raw})

    def test_structured_proof_cases_are_present_with_their_results(self):
        required = {
            "structured-proof-members-in-another-order": ("pass", None),
            "boolean-true-stored-number-one-supplied": ("fail", "stored-proof"),
            "number-one-stored-boolean-true-supplied": ("fail", "stored-proof"),
            "number-one-and-one-point-zero-are-equal": ("pass", None),
            "array-elements-in-another-order": ("fail", "stored-proof"),
            "supplied-proof-has-a-duplicate-member-name": ("fail", "stored-proof"),
            "string-one-stored-number-one-supplied": ("fail", "stored-proof"),
            "exponent-form-number-equals-integer": ("pass", None),
            "number-differs-beyond-binary-precision": ("fail", "stored-proof"),
            "stored-proof-has-a-duplicate-member-name": ("fail", "stored-proof"),
        }
        for name, result in required.items():
            with self.subTest(vector=name):
                self.assertIn(name, self.vectors)
                vector = self.vectors[name]
                self.assertEqual((vector["expected"], vector["failedPart"]), result)

    def test_duplicate_member_vector_would_pass_if_the_last_member_won(self):
        vector = self.vectors["supplied-proof-has-a-duplicate-member-name"]
        last_wins = parse_exact(vector["proof"]["bodyRaw"])
        self.assertTrue(json_equal(last_wins, vector["storedEntry"]["proof"]))
        self.assertFalse(stored_proof_ok(vector))

    def test_stored_duplicate_vector_would_pass_if_the_last_member_won(self):
        vector = self.vectors["stored-proof-has-a-duplicate-member-name"]
        last_wins = parse_exact(vector["storedEntry"]["proofRaw"])
        self.assertTrue(json_equal(vector["proof"]["body"], last_wins))
        self.assertFalse(stored_proof_ok(vector))

    def test_number_vectors_carry_their_numbers_as_json_text(self):
        close = self.vectors["number-differs-beyond-binary-precision"]
        self.assertIn("1.00000000000000001", close["proof"]["bodyRaw"])
        self.assertEqual(close["storedEntry"]["proof"], {"amount": 1})
        exponent = self.vectors["exponent-form-number-equals-integer"]
        self.assertIn("1e2", exponent["proof"]["bodyRaw"])
        self.assertEqual(exponent["storedEntry"]["proof"], {"amount": 100})

    def test_reordered_proof_vector_reorders_a_nested_object_too(self):
        vector = self.vectors["structured-proof-members-in-another-order"]
        stored, supplied = vector["storedEntry"]["proof"], vector["proof"]["body"]
        self.assertNotEqual(list(stored), list(supplied))
        nested = [k for k, v in stored.items() if isinstance(v, dict)]
        self.assertTrue(nested)
        for key in nested:
            self.assertNotEqual(list(stored[key]), list(supplied[key]))

    def test_composition_cases_cover_the_stated_combinations_with_their_results(self):
        cases = {(c["check"], c["parser"]): c["expected"] for c in self.document["compositionCases"]}
        pra5 = "error-pra5-preinvocation"
        required = {
            ("fail-stored-proof", "error-executed"): "fail",
            ("fail-stored-proof", pra5): "error",
            ("fail-stored-proof", "pass"): "fail",
            ("fail-subject", "error-executed"): "error",
            ("fail-subject", "indeterminate"): "indeterminate",
            ("fail-subject", "fail"): "fail",
            ("fail-subject", "pass"): "fail",
            ("pass-subject-declared", "pass"): "pass",
            ("pass-subject-declared", pra5): "error",
            ("pass-no-subject", "pass"): "pass",
            ("pass-no-subject", pra5): "error",
        }
        for key, outcome in required.items():
            with self.subTest(case=key):
                self.assertEqual(cases.get(key), outcome)

    def test_composition_cases_match_compose_and_are_complete(self):
        cases = self.document["compositionCases"]
        keys = [(c["check"], c["parser"]) for c in cases]
        self.assertEqual(len(keys), len(set(keys)))
        self.assertEqual(len({c["name"] for c in cases}), len(cases))
        # a wrong subject is only found by a parser that ran, so it never meets PRA-5
        reachable = {
            (check, parser)
            for check in CHECK_RESULTS for parser in PARSER_OUTCOMES
            if (check, parser) != ("fail-subject", "error-pra5-preinvocation")
        }
        self.assertEqual(set(keys), reachable)
        for case in cases:
            with self.subTest(case=case["name"]):
                self.assertEqual(compose(case["check"], case["parser"]), case["expected"])

    def test_compose_returns_the_pra5_error_before_any_check_result_is_used(self):
        for check in CHECK_RESULTS:
            with self.subTest(check=check):
                self.assertEqual(compose(check, "error-pra5-preinvocation"), "error")

    def test_compose_lets_part_two_stand_over_an_executed_parser_and_part_three_apply_only_on_parser_pass(self):
        for parser in PARSER_OUTCOMES:
            with self.subTest(parser=parser):
                executed = parser != "error-pra5-preinvocation"
                self.assertEqual(
                    compose("fail-stored-proof", parser), "fail" if executed else "error"
                )
                if parser != "pass":
                    self.assertEqual(
                        compose("fail-subject", parser), compose("pass-subject-declared", parser)
                    )
        with self.assertRaises(ValueError):
            compose("pass-no-subject", "unknown")

    def test_set_description_states_what_the_composition_model_is(self):
        description = self.document["description"]
        self.assertIn("composes outcomes only", description)
        self.assertIn("does not run a parser", description)
        self.assertIn("compositionCases", description)

    def test_spec_restores_the_base_procedure_paragraph(self):
        section = spec_section()
        self.assertIn(
            "**Procedure.** Validates the TLSNotary proof per the TLSNotary "
            "specification (current PSE rebuild); verifies the notary signature "
            "against a known notary public key registry; if sessionTemplate is set, "
            "verifies the proof targets that endpoint and protocol; anchors the "
            "proof commitment via SR-2; applies parser rules to any disclosed "
            "segments; returns VerifyResult per outcome. **Trust model:** TLS PKI; "
            "notary honesty; MPC computational assumptions. **Substrate:** SR-2.",
            section,
        )
        self.assertIsNone(re.search(r"^\d+\. \*\*", section, flags=re.MULTILINE))
        self.assertNotIn("tlsnotaryProofCommitment", section)
        self.assertNotIn("*Outcome.*", section)

    def test_spec_paragraph_pins_the_stored_proof_check(self):
        paragraph = stored_proof_paragraph()
        self.assertIn("applies only when the requirement is on a registered `cci-tlsn:H` claim", paragraph)
        self.assertIn("anchors via SR-2, is `H`", paragraph)
        self.assertIn("stored web2 entry whose proof hash is `H`", paragraph)
        self.assertIn("MUST equal the proof stored with that entry", paragraph)
        self.assertIn("MUST reject (`fail`) if `H` resolves to no stored entry or the proofs differ", paragraph)
        self.assertIn("type-preserving structural equality", paragraph)
        self.assertIn("in any member order", paragraph)
        self.assertIn(
            "numbers are equal when the decimal values written in their JSON text are "
            "mathematically equal (exact decimal comparison, no binary floating-point rounding)",
            paragraph,
        )
        self.assertIn("`1`, `1.0` and `1e0` are equal and `1.00000000000000001` and `1` are not", paragraph)
        self.assertIn("a number never equals a boolean, string or null", paragraph)
        self.assertIn(
            "Either proof, stored or supplied, that has a duplicate member name in any object "
            "fails the check (`fail`)",
            paragraph,
        )
        self.assertIn("does not define how `H` is derived from a proof and does not depend on it", paragraph)
        self.assertIn("How the node derives `H` is outside this check", paragraph)
        self.assertIn("declares a `subject` entry", paragraph)
        self.assertIn("MUST equal the stored entry's `userId`", paragraph)
        self.assertIn("compared as JSON strings only: exact equality after NFC", paragraph)
        self.assertIn("A non-string on either side", paragraph)
        self.assertIn("resolves to nothing", paragraph)
        self.assertIn("it never yields `pass` and adds no new outcome", paragraph)
        self.assertIn("are not yet supported by this check and fail closed", paragraph)
        self.assertIn("MUST NOT convert numbers to text here", paragraph)
        self.assertIn("adds nothing beyond (1) and (2)", paragraph)
        self.assertIn("The check applies to no other scheme", paragraph)
        self.assertIn("adds no session binding, signature, signature domain or nonce use", paragraph)
        self.assertIn("other outcomes follow the procedure above unchanged", paragraph)
        self.assertIn("its `fail` stands over whatever an executed parser gives", paragraph)
        self.assertIn("Part (3) applies only when the parser rules would otherwise give `pass`", paragraph)
        self.assertIn("`error` or `indeterminate`, that outcome stands", paragraph)
        self.assertIn(
            "When PRA-5 requires `error` before the parser is invoked, that `error` stands "
            "and this check is not evaluated.",
            paragraph,
        )
        self.assertTrue(
            paragraph.endswith("that `error` stands and this check is not evaluated.")
        )
        self.assertNotIn("whatever they give", paragraph)
        self.assertNotIn("evaluated even when PRA-5", paragraph)

    def test_spec_psp3_exception_is_only_the_unresolved_subject(self):
        text = SPEC.read_text(encoding="utf-8")
        psp3 = text[text.index("- (PSP-3)"):].split("\n")[0]
        self.assertIn(
            "MUST NOT by itself change the decision, except that a declared `subject` "
            "entry that resolves to nothing fails the §7.3.3 stored-proof check "
            "when the parser rules would otherwise give `pass`.",
            psp3,
        )
        self.assertNotIn("reserved", psp3)

    def test_spec_has_no_leftover_step_wording(self):
        # Only §7.3.3 is under test: other sections of DACS-2 number their own
        # steps, and "Session binding" is another method's own step name (§7.3.4).
        section = spec_section()
        for stale in ("step 6", "step 4", "tlsnotaryProofCommitment"):
            with self.subTest(stale=stale):
                self.assertNotIn(stale, section)
        self.assertNotIn("Session binding", section)


if __name__ == "__main__":
    unittest.main()
