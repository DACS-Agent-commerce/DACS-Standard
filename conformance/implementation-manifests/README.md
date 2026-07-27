# DACS implementation-manifest examples

These examples exercise the optional normative reporting contract in
[§14.10](../../spec/CONFORMANCE-PLAN.md#1410-implementation-conformance-claims).
They are illustrative implementation reports, not endorsements or declarations that
the named example software exists.

The examples show four deliberately scoped surfaces:

- `fixed-price-x402-seller.json` — fixed-price negotiation plus `pay-x402`;
- `pay-dem-rfq-buyer.json` — the buyer side of an RFQ settled with `pay-dem`;
- `pay-dem-rfq-seller.json` — the seller side of the same capability pairing; and
- `verifier-indexer.json` — bundle verification, reputation derivation, and directory indexing.

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
