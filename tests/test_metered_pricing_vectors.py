import hashlib
import json
import re
import unittest
from decimal import Decimal, ROUND_CEILING
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
VECTORS = ROOT / "conformance" / "vectors" / "security" / "metered-pricing-v0.3.json"
SPEC = ROOT / "spec" / "DACS-3-NEGOTIATE.md"

QUANTITY_RE = re.compile(r"(?:0|[1-9][0-9]*)\Z")
AMOUNT_RE = re.compile(r"(?:0|[1-9][0-9]*)(?:\.[0-9]*[1-9])?\Z")
KNOWN_PRICING_KINDS = {"fixed", "negotiable", "auction", "metered"}


def canonical_json(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def canonical_amount(value):
    rendered = format(value, "f")
    if "." in rendered:
        rendered = rendered.rstrip("0").rstrip(".")
    return rendered


def validate_agreement(pricing, terms):
    kind = pricing.get("kind")
    if kind not in KNOWN_PRICING_KINDS:
        return "reject", "unrecognized-pricing-kind", None

    if kind != "metered":
        if "meteredQuantity" in terms:
            return "reject", "unexpected-metered-quantity", None
        return "accept", None, None

    unit_price = pricing["unitPrice"]
    minimum = pricing.get("minTotal")
    if minimum is not None and minimum["currency"] != unit_price["currency"]:
        return "reject", "min-total-currency-mismatch", None
    if not pricing.get("unit"):
        return "reject", "empty-metered-unit", None
    if terms["price"]["currency"] != unit_price["currency"]:
        return "reject", "price-currency-mismatch", None

    measured = terms.get("meteredQuantity")
    if measured is None:
        return "reject", "missing-metered-quantity", None
    if measured.get("unit") != pricing["unit"]:
        return "reject", "metered-unit-mismatch", None
    quantity = measured.get("quantity")
    if not isinstance(quantity, str) or QUANTITY_RE.fullmatch(quantity) is None:
        return "reject", "non-canonical-metered-quantity", None

    amount = terms["price"]["amount"]
    if not isinstance(amount, str) or AMOUNT_RE.fullmatch(amount) is None or Decimal(amount) <= 0:
        product = Decimal(unit_price["amount"]) * int(quantity)
        floor = Decimal(minimum["amount"]) if minimum is not None else Decimal(0)
        return "reject", "non-canonical-price-amount", canonical_amount(max(product, floor))

    product = Decimal(unit_price["amount"]) * int(quantity)
    floor = Decimal(minimum["amount"]) if minimum is not None else Decimal(0)
    computed = canonical_amount(max(product, floor))
    if amount != computed:
        return "reject", "metered-total-mismatch", computed
    return "accept", None, computed


class MeteredPricingVectorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = json.loads(VECTORS.read_text(encoding="utf-8"))

    def test_vector_hash_and_count_are_byte_exact(self):
        self.assertEqual(self.data["count"], len(self.data["vectors"]))
        self.assertEqual(
            self.data["hash"],
            hashlib.sha256(canonical_json(self.data["vectors"])).hexdigest(),
        )

    def test_all_mtr_rules_have_executable_cases(self):
        covered = {rule for vector in self.data["vectors"] for rule in re.findall(r"MTR-[1-5]", vector["rule"])}
        self.assertEqual(covered, {"MTR-1", "MTR-2", "MTR-3", "MTR-4", "MTR-5"})

    def test_quantity_derivation_uses_decimal_ceil(self):
        cases = [v for v in self.data["vectors"] if v["surface"] == "quantity-derivation"]
        self.assertGreaterEqual(len(cases), 3)
        for vector in cases:
            with self.subTest(vector["name"]):
                raw = Decimal(vector["rawMeasurement"])
                derived = str(int(raw.to_integral_value(rounding=ROUND_CEILING)))
                self.assertEqual(vector["expected"], "accept")
                self.assertEqual(derived, vector["want"]["quantity"])
                self.assertRegex(derived, QUANTITY_RE)

    def test_agreement_vectors_execute_normative_predicate(self):
        cases = [v for v in self.data["vectors"] if v["surface"] == "agreement-validation"]
        self.assertGreaterEqual(len(cases), 15)
        for vector in cases:
            with self.subTest(vector["name"]):
                verdict, reason, computed = validate_agreement(vector["pricing"], vector["terms"])
                self.assertEqual(verdict, vector["expected"])
                self.assertEqual(reason, vector["want"].get("reason"))
                if "computedAmount" in vector["want"]:
                    self.assertEqual(computed, vector["want"]["computedAmount"])
                if reason == "unrecognized-pricing-kind":
                    self.assertFalse(vector["want"]["commitAgreement"])

    def test_spec_contains_the_executed_guards(self):
        spec = SPEC.read_text(encoding="utf-8")
        self.assertIn('"0"` or `[1-9][0-9]*`', spec)
        self.assertIn("rounded **up** (ceil)", spec)
        self.assertIn("unitPrice.amount × quantity", spec)
        self.assertIn("recorded `unrecognized-pricing-kind` reason", spec)


if __name__ == "__main__":
    unittest.main()
