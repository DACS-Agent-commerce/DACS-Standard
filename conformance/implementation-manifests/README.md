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

Both pin the coordinated v0.4 release commit named in
[PROFILE](../../spec/PROFILE.md), with the conformance manifest at that commit.
They show the claim and evidence rules at work:

- capabilities backed by passing golden cases are `conformance-tested`;
- `pay-dem`, with a single candidate case, is `partial` and claimed only as
  `implemented`;
- the out-of-scope `rfq` pattern is listed as `unsupported`; and
- `availability` is omitted, as IM-2 allows for library capabilities.

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
