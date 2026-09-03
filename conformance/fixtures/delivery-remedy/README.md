# Delivery-or-remedy candidate fixtures

**Status:** non-normative review tooling for [issue
#356](https://github.com/DACS-Agent-commerce/DACS-Standard/issues/356). These
files do not change DACS conformance, register an ERC-8183 rail, or make any
deployment available.

The pack turns the pre-normative
[delivery-or-remedy candidate](../../../docs/delivery-or-remedy-candidate.md)
into executable review evidence:

- `candidate-vectors-v0.1.json` contains deterministic, signed synthetic
  lifecycle inputs for full release, evaluator rejection/refund before or
  after submission, pre-submission expiry, and post-submission expiry. Its
  cases cover non-circular delivery binding and relayed evaluator execution.
  Negative cases cover escrow-phase pairing, exact hash-to-`bytes32` mapping,
  role and account
  collisions, deadline divergence, cross-job and consumed-decision replay,
  release/refund direction, full-budget and zero-fee requirements, and the
  four-result verification boundary.
- `deployment-capabilities-v0.1.json` derives DRC-1 through DRC-13 outcomes
  from explicit capability evidence. It includes a synthetic all-pass control
  that is permanently marked `fixtureOnly`, individual rule regressions, and
  a pinned assessment of
  [`erc-8183/base-contracts@142e669`](https://github.com/erc-8183/base-contracts/blob/142e669c1fd318486a4628395b629f033654dd06/contracts/ERC8183.sol).
  The pinned reference is `rejected`, remains unregistered, and is never
  reported as available.

The synthetic control proves only that the checker can observe all thirteen
positive capability predicates. Its `registrationStatus` is
`not-a-deployment`; a verified control therefore still has
`registrationEligible: false`.

The protocol verifier requires the finality records embedded in signed funding
and terminal artifacts to use the exact DACS-4 `SettlementFinalityRecord`
`block-depth` shape. It checks those records against non-empty canonical event
references plus resolver observations of block identity, timestamp, and
confirmation depth. A caller-supplied status or timestamp cannot make an
under-confirmed event final, classify submission timing, or establish Vet
freshness.

Each lifecycle fixture also carries `reproductionInputs`: the public test-key
seeds, role-bundle and Vet-record bodies, evaluation rule, delivered artifact or
dispute case, runtime-bytecode preimage, and native event/log observations with
their transaction and block-hash preimages. The verifier independently
recomputes their keys, hashes, references, event identities, chain binding,
ordering, and positive bindings. It also derives policy from the authenticated
rail definition and checks accountability projections against authenticated
findings. These are synthetic inputs, not a live chain resolver, production
identity registry, or eligible deployment.

The `externalEvidence` object is an explicit fixture boundary for authenticated
resolver outcomes such as registry availability and cross-substrate ordering.
The pack exercises unavailable and contradictory outcomes but does not claim to
implement those external resolvers. Promotion still requires real authenticated
resolver evidence and a second implementation; the status labels in this pack
cannot register a rail or authorize a transaction.

Every candidate rule ID is accounted for mechanically. Each executable vector
lists the rules its positive or negative path exercises. The pack's
`promotionBlockedRules` ledger names the remaining rules and the concrete
capability needed before they can be promoted. Those entries are intentionally
not marked as executed: they cover SR-2 logical addressing and anchoring, live
proxy/authority resolution, explicit-party evidence proof, retry orchestration,
and the future transcript and post-terminal dispute-revision profiles. The test
suite fails if a spec rule is absent from both sets or appears in both.

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
