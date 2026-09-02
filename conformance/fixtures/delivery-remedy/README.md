# Delivery-or-remedy candidate fixtures

**Status:** non-normative review tooling for [issue
#356](https://github.com/DACS-Agent-commerce/DACS-Standard/issues/356). These
files do not change DACS conformance, register an ERC-8183 rail, or make any
deployment available.

The pack turns the pre-normative
[delivery-or-remedy candidate](../../../docs/delivery-or-remedy-candidate.md)
into executable review evidence:

- `candidate-vectors-v0.1.json` contains deterministic, signed synthetic
  lifecycle inputs for full release, evaluator rejection/refund,
  pre-submission expiry, and post-submission expiry. Its negative cases cover
  escrow-phase pairing, exact hash-to-`bytes32` mapping, role and account
  collisions, deadline divergence, cross-job and consumed-decision replay,
  release/refund direction, full-budget and zero-fee requirements, and the
  four-result verification boundary.
- `deployment-capabilities-v0.1.json` derives DRC-1 through DRC-12 outcomes
  from explicit capability evidence. It includes a synthetic all-pass control
  that is permanently marked `fixtureOnly`, individual rule regressions, and
  a pinned assessment of
  [`erc-8183/base-contracts@142e669`](https://github.com/erc-8183/base-contracts/blob/142e669c1fd318486a4628395b629f033654dd06/contracts/ERC8183.sol).
  The pinned reference is `rejected`, remains unregistered, and is never
  reported as available.

The synthetic control proves only that the checker can observe all twelve
positive capability predicates. Its `registrationStatus` is
`not-a-deployment`; a verified control therefore still has
`registrationEligible: false`.

## Reproduce

From the repository root:

```sh
python3 scripts/generate_delivery_remedy_candidate_vectors.py --check
python3 scripts/verify_delivery_remedy_candidate_vectors.py
python3 -m unittest tests.test_delivery_remedy_candidate_vectors -v
```

Regenerate after an intentional fixture change with:

```sh
python3 scripts/generate_delivery_remedy_candidate_vectors.py --write
```

The generator uses fixed Ed25519 seeds only for public test fixtures. They are
not operational keys.

## Promotion boundary

These fixtures stay under `conformance/fixtures/`, not the canonical
`conformance/vectors/` tier. Promotion still requires steward acceptance of
the artifact shapes, an independently reproduced implementation, complete
authenticated deployment evidence, and a separately registered rail
revision.
