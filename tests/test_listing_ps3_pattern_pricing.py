"""PS-3 pattern/pricing compatibility in the reference Listing shape check.

DACS-3 §8.8 PS-3: negotiate-fixed-price runs over fixed, negotiable or metered
pricing; negotiate-rfq over negotiable or metered; the sealed-envelope
patterns, including both complete ones, only over auction pricing. No
conformance vector exercises this matrix, so the reference check in
``scripts/listing_artifact.py`` is pinned here: each negotiation pattern
passes over its compatible kinds and fails otherwise.

Each rejected row differs from an accepted row only in the pricing kind. The
sealed patterns also require the pricing's ``selectionRule`` to match their
own, which non-auction pricing lacks, so every pricing kind is also tried
carrying that rule. Only PS-3 can then reject a sealed pattern over it.
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
COMPLETE = dict(SEALED, candidateSetBinding={
    "bindingId": "fixture-candidate-set",
    "bindingVersion": "1",
    "definitionRef": {
        "anchor": {"kind": "storage-program", "locator": "storage-program:binding-1"},
        "contentHash": "ab" * 32,
    },
})
IDENTITY_BOUND = "commit-identity-bound-agreement"
SELECTION_BOUND = "commit-selection-bound-agreement"
# pattern: (negotiation parameters, the commitment it needs, compatible pricing kinds)
PATTERNS = {
    "negotiate-fixed-price": (None, IDENTITY_BOUND, {"fixed", "negotiable", "metered"}),
    "negotiate-rfq": ({"maxTurns": 2, "timeoutSec": 60}, IDENTITY_BOUND, {"negotiable", "metered"}),
    "negotiate-sealed-envelope": (SEALED, IDENTITY_BOUND, {"auction"}),
    "negotiate-sealed-envelope-procurement": (dict(SEALED, auctionMode="procurement"), IDENTITY_BOUND, {"auction"}),
    "negotiate-sealed-envelope-complete": (COMPLETE, SELECTION_BOUND, {"auction"}),
    "negotiate-sealed-envelope-procurement-complete": (
        dict(COMPLETE, auctionMode="procurement"), SELECTION_BOUND, {"auction"}),
}


def fixed_price_listing():
    raw = json.loads(IBH.read_text(encoding="utf-8"))
    return copy.deepcopy(raw["scenarios"]["identityBoundAgreement"]["listing"])


def listing_for(pattern, pricing):
    parameters, commitment, _compatible = PATTERNS[pattern]
    listing = fixed_price_listing()
    step = {"kind": pattern}
    if parameters is not None:
        step["parameters"] = copy.deepcopy(parameters)
    listing["pipeline"][1] = step
    listing["pipeline"][2] = {"kind": commitment}
    listing["pricing"] = copy.deepcopy(pricing)
    return listing


class Ps3PatternPricingTests(unittest.TestCase):
    def test_fixture_is_a_valid_fixed_price_listing(self):
        listing = fixed_price_listing()
        self.assertEqual([step["kind"] for step in listing["pipeline"]][1:3],
                         ["negotiate-fixed-price", IDENTITY_BOUND])
        self.assertEqual(listing["pricing"]["kind"], "fixed")
        self.assertEqual(listing_artifact.validate_listing_shape(listing)[:2], (True, None))

    def test_matrix_covers_every_negotiation_pattern(self):
        self.assertEqual(set(PATTERNS), set(listing_artifact.NEGOTIATION_PHASES))
        self.assertEqual({pattern for pattern, (_p, commitment, _c) in PATTERNS.items()
                          if commitment == SELECTION_BOUND},
                         set(listing_artifact.COMPLETE_SEALED_NEGOTIATIONS))

    def test_each_pattern_accepts_only_its_compatible_pricing_kinds(self):
        for pattern, (_parameters, _commitment, compatible) in PATTERNS.items():
            for kind, pricing in PRICING.items():
                # Every kind also carries the sealed patterns' selectionRule, so
                # the selectionRule check cannot be what rejects a row.
                for variant, priced in (("plain", pricing),
                                        ("with selectionRule", dict(pricing, selectionRule=SEALED["selectionRule"]))):
                    with self.subTest(pattern=pattern, pricing=kind, variant=variant):
                        listing = listing_for(pattern, priced)
                        ok, reason, _type, _domain = listing_artifact.validate_listing_shape(listing)
                        if kind in compatible:
                            self.assertEqual((ok, reason), (True, None))
                        else:
                            self.assertEqual((ok, reason), (False, "invalid or unsupported pipeline"))

    def test_sealed_patterns_reject_matching_selection_rules_over_non_auction_pricing(self):
        # The rows only PS-3's sealed clause decides: the same listing passes
        # over auction pricing and fails once the kind alone changes.
        sealed = [pattern for pattern in PATTERNS if pattern.startswith("negotiate-sealed-envelope")]
        self.assertEqual(len(sealed), 4)
        for pattern in sealed:
            accepted = listing_for(pattern, PRICING["auction"])
            self.assertEqual(listing_artifact.validate_listing_shape(accepted)[:2], (True, None), pattern)
            for kind in ("fixed", "negotiable", "metered"):
                with self.subTest(pattern=pattern, pricing=kind):
                    pricing = dict(PRICING[kind], selectionRule=PRICING["auction"]["selectionRule"])
                    rejected = listing_for(pattern, pricing)
                    self.assertEqual(rejected["pipeline"], accepted["pipeline"])
                    self.assertEqual(rejected["pricing"]["selectionRule"], accepted["pricing"]["selectionRule"])
                    self.assertEqual(listing_artifact.validate_listing_shape(rejected)[:2],
                                     (False, "invalid or unsupported pipeline"))


if __name__ == "__main__":
    unittest.main()
