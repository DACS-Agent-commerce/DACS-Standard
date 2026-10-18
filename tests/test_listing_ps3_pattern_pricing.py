"""PS-3 pattern/pricing compatibility in the reference Listing shape check.

DACS-3 §8.8 PS-3: negotiate-fixed-price runs over fixed, negotiable or metered
pricing; negotiate-rfq over negotiable or metered; the sealed-envelope
patterns only over auction pricing. No conformance vector exercises this
matrix, so the reference check in ``scripts/listing_artifact.py`` is pinned
here: each pattern passes over its compatible kinds and fails otherwise.
"""

import copy
import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import listing_artifact  # noqa: E402

IBH = ROOT / "conformance/vectors/security/identity-bundle-hash-binding-v0.1.json"
PRICE = {"amount": "1", "currency": "DEM"}
PRICING = {
    "fixed": {"kind": "fixed", "price": PRICE},
    "negotiable": {"kind": "negotiable", "bandCenter": PRICE, "minPct": 10, "maxPct": 10},
    "metered": {"kind": "metered", "unitPrice": PRICE, "unit": "call"},
    "auction": {"kind": "auction", "selectionRule": "lowest-price"},
}
SEALED = {"commitDeadline": 1, "revealWindow": 60, "selectionRule": "lowest-price"}
PATTERNS = {
    "negotiate-fixed-price": (None, {"fixed", "negotiable", "metered"}),
    "negotiate-rfq": ({"maxTurns": 2, "timeoutSec": 60}, {"negotiable", "metered"}),
    "negotiate-sealed-envelope": (SEALED, {"auction"}),
    "negotiate-sealed-envelope-procurement": (dict(SEALED, auctionMode="procurement"), {"auction"}),
}


def fixed_price_listing():
    raw = json.loads(IBH.read_text(encoding="utf-8"))
    return copy.deepcopy(raw["scenarios"]["identityBoundAgreement"]["listing"])


class Ps3PatternPricingTests(unittest.TestCase):
    def test_fixture_is_a_valid_fixed_price_listing(self):
        listing = fixed_price_listing()
        self.assertEqual([step["kind"] for step in listing["pipeline"]][1], "negotiate-fixed-price")
        self.assertEqual(listing["pricing"]["kind"], "fixed")
        self.assertEqual(listing_artifact.validate_listing_shape(listing)[:2], (True, None))

    def test_each_pattern_accepts_only_its_compatible_pricing_kinds(self):
        for pattern, (parameters, compatible) in PATTERNS.items():
            for kind, pricing in PRICING.items():
                with self.subTest(pattern=pattern, pricing=kind):
                    listing = fixed_price_listing()
                    step = {"kind": pattern}
                    if parameters is not None:
                        step["parameters"] = copy.deepcopy(parameters)
                    listing["pipeline"][1] = step
                    listing["pricing"] = copy.deepcopy(pricing)
                    ok, reason, _type, _domain = listing_artifact.validate_listing_shape(listing)
                    if kind in compatible:
                        self.assertEqual((ok, reason), (True, None))
                    else:
                        self.assertEqual((ok, reason), (False, "invalid or unsupported pipeline"))


if __name__ == "__main__":
    unittest.main()
