# DACS implementation-manifest examples

These examples exercise the optional normative reporting contract in
[§14.10](../../spec/CONFORMANCE-PLAN.md#1410-implementation-conformance-claims).
They are illustrative implementation reports, not endorsements or declarations that
the named example software exists.

The examples show six deliberately scoped surfaces:

- `fixed-price-x402-seller.json` — fixed-price negotiation plus `pay-x402`;
- `fixed-price-pay-dem-seller.json` — the seller side of fixed-price negotiation,
  `pay-dem` settlement, and `deliver-storage-program` delivery;
- `fixed-price-pay-dem-buyer.json` — the buyer side of the same capability set;
- `pay-dem-rfq-buyer.json` — the buyer side of an RFQ settled with `pay-dem`;
- `pay-dem-rfq-seller.json` — the seller side of the same capability pairing; and
- `verifier-indexer.json` — bundle verification, reputation derivation, and directory indexing.

The two `fixed-price-pay-dem-*` examples are illustrative only. They are not
normative and are not a claim about any implementation. Their implementation
name, `example.invalid` repository, commit, and test commands are placeholders.
The §14.10 shape has no free-text description outside deviations, so the files
say this through those placeholder values.

Both pin the coordinated v0.4 release: the annotated tag `v0.4` named in
[PROFILE](../../spec/PROFILE.md), at commit `4bb9e48`, with the conformance
manifest at that commit. They scope each claim to what its cited cases
exercise, and no capability is exercised fully enough at that pin for a
passing claim:

- `fixed-price` cites every golden §8.5.x case that applies to it, but no case
  in the v0.4 suite exercises the §8.4.1 procedure (including its auto-accept
  checks) or PS-1 and PS-2. It is therefore `partial` and claimed only as
  `implemented`;
- PS-1..PS-3 appear only in the seller example, because DACS-3 §8.9 assigns
  them to the listing publisher;
- PB-1..PB-3 appear only in the buyer example, because DACS-4 §9.5.1 makes
  them checks the payer runs before submitting payment;
- `pay-dem`, with a single candidate case, is `partial` and claimed only as
  `implemented`. No v0.4 case exercises the §9.5.9 procedure, whose step 5
  returns success on the `included` state; a Demos node also reports
  `included` for a failed transfer. Open draft PR #432 proposes settling only
  on an executed transaction record, as the
  [FP-DEM map](../../docs/fp-dem-current-rules.md#known-gaps) records;
- the `demos-native:DEM` rail is claimed against its DACS-4 §9.4.2 registry
  entry with the `pay-dem` case, as `implemented`. No v0.4 case exercises a
  `demos-native` rail, and RD-1..RD-5 are rail-author duties (§9.4.3, §9.10);
- `deliver-storage-program` cites four of the six golden v0.4 settlement
  cases that check delivery evidence and its anchor; it does not cite the
  PC-6 and SIG-5 cases `settlement-delivery-with-finality-fail` and
  `settlement-delivery-extra-payment-field-pass`. None of the six exercises
  DV-1..DV-4 or the extended pointer that §9.6.1 requires above its 128 KB
  soft limit; the Demos node itself enforces 1 MiB, as the FP-DEM map
  records. The v0.4 `private-deliverables-v0.1` security set probes the DV
  rules, but its vectors are not cases in the pinned conformance manifest.
  Delivery is therefore `partial` and claimed only as `implemented`;
- the out-of-scope `rfq` pattern is listed as `unsupported`; and
- `availability` is omitted, as IM-2 allows for a non-operational library capability.

`fixed-price-x402-seller.json` makes no passing claim. A `capability` claim
that is `conformance-tested` reports the whole capability (§14.10), but none
of its three fixed-price cases exercises the §8.4.1 procedure, PS-1 or PS-2,
and its PS-3 golden case covers only PS-3's negotiable band-centre clause,
not the pattern/pricing compatibility. Its fixed-price claim, which names
PS-3, is therefore `partial` and claimed only as `implemented`, as in the
`fixed-price-pay-dem-*` examples. Its `pay-x402` evidence is
the single golden pass case `settlement-x402-pass`, which exercises none of
the X402-1..X402-4 rejection paths in DACS-4 §9.5.7 or the SB-1..SB-3 session
binding in §9.5.8, so `pay-x402` is `partial` and claimed only as
`implemented`.

This scoping is the examples' own choice. IM-4 requires only that cited case
ids exist in the pinned conformance manifest, and the validator does not check
whether a cited case is golden or candidate, or whether the cases exercise the
rules a claim names.

Run the dependency-free validator from the repository root:

```sh
python3 scripts/validate_implementation_manifests.py
```

The validator checks the normative shape, resolves profile documents and suite bytes
at their declared Standard commits, checks per-document versions and suite hashes,
and validates capability/evidence reference integrity, labelled-rule and document-section resolution, claim/status
compatibility, deterministic case IDs, experimental prefixes, and open deviations. It
does not certify that a self-asserted implementation actually ran the reported command.
Consumers still verify artifacts and perform normal runtime preflight.
