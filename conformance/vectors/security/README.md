# DACS Security Conformance Vectors

Language-neutral conformance vectors for the **security / anti-abuse requirements**
of DACS — across settlement (SB-family, §9.5.8), negotiation/agreement (§8.5.2),
and identity/vetting (§7.3.2). These complement the lifecycle vectors in the
parent directory: where those assert that a well-formed five-stage session
validates, these are intended to assert that the **anti-abuse rules** behave
identically across independent implementations (SB-2's EVM row is cross-run-
converged; the others await a second impl). Derived from the §12.4 threat-to-test matrix
(published in `pathos-dacs-ref`; tracked in #158).

> **Shape note (why this is a subdirectory).** Each set is *verifier-input/output
> pairs* (a case's input fields → an `expected` §7.5.1 verdict), not five-stage
> lifecycle bundles, and **each carries its own schema** (described per-set below).
> The canonical `scripts/validate_conformance_vectors.py` run globs
> `conformance/vectors/*.json` non-recursively, so files here (like `../examples/`)
> are intentionally excluded from the lifecycle shape-check.

## Included sets

### `sb2-settlement-uniqueness-v0.1.json` — §9.5.8 SB-2 (settlement-tx uniqueness)

20 vectors for the cross-session / cross-phase double-count defence: a single
on-chain settlement MUST be counted **at most once** per `(jobId, phaseIndex)`,
keyed on the canonical `settlement-tx-id` pinned in **SB-1** (#161, commit
`072dc33`):

- **evm / x402:** `evm:{chainId}:{txHash}:{logIndex}`
- **solana:** `solana:{cluster}:{signature}:{instructionIndex}`

with SB-1's canonicalisation enforced: `chainId`/`logIndex`/`instructionIndex`
decimal with no leading zeros; `txHash` lower-case hex with no `0x` (so a `0x` or
upper-case re-spelling **collapses to one key** and cannot dodge the consumed
set); `signature` base58 decoding to **exactly 64 bytes**; and a malformed ref
(wrong-length / odd hex / non-64-byte base58 sig / missing coordinates) →
`error`, **never minting a distinct key**.

This set is built off the SN-4 single-use template, scope-inverted to settlement
(cX3po, #159 / #161). It is the `pathos-dacs-ref` independent implementation of
the §9.5.8 row; `mj-deving/dacs-verify` carries the second. On EVM the two impls
were cross-run case-for-case and agreed on **6/6** decisions (#159,
`issuecomment-4797534308`).

#### Vector schema

Each entry in `vectors[]`:

| field      | meaning |
|------------|---------|
| `name`     | stable case id |
| `decision` | expected §7.5.1 4-value verdict: `pass` \| `fail` \| `indeterminate` \| `error` (never collapsed) |
| `effect`   | settlement-counting effect: `count` \| `already-counted` \| `reject` \| `no-decision` \| `verifier-error` |
| `consumed` | prior consumed-set state, mapping canonical `settlement-tx-id` → the `{jobId, phaseIndex}` that already counted it (`{}` = empty ledger; `null` = ledger unreadable) |
| `record`   | the settlement record under test (`settlementRef`, `jobId`, `phaseIndex`) |
| `note`     | human-readable rationale |

The `decision`/`effect` split is deliberate: an idempotent re-presentation is a
`pass` whose `effect` is `already-counted`, so a consumer can never read
idempotent success as licence to count the settlement again.

#### Deterministic Solana fixture (cross-impl convergence)

So the Solana row converges byte-identically across impls, the valid Solana
signature used here is deterministic — base58 of 64 bytes each `0x05`:

```
6pc4LiB8KHAPvbUbkozrTcPL5zXspYBdATv5raNDyVbhiKjrKokLb9o111kxTD5KkPVd7UBSCcFcnWFkrJ82Hu6
```

(87 base58 chars decoding to exactly 64 bytes). Any conforming implementation
keying on the SB-1 form and reusing this signature should derive the same Solana
key; Solana cross-run convergence between impls remains pending (only the EVM row
has been cross-run to date — see Status).

#### Running

The vectors are language-neutral data: feed each `record` + `consumed` to your
SB-2 verifier and assert `(decision, effect)`. The reference run lives in
`pathos-dacs-ref`:

```
npx tsx conformance/security-vectors/sb2-settlement-uniqueness/run.mts
# → 20/20 vectors pass
```

### `agreement-listing-v0.1.json` — §8.5.2 (agreement ↔ listing validation)

30 vectors for the §8.5.2 check that a signed `AgreementDocument`'s terms are
permitted by the listing it cites — **7 ordered checks**: currency, price-band,
rail, deliverable, deadline, expiry, and cancellation/pattern. Price-band math is
**exact-decimal (BigInt)** — no float drift — so a price one minor-unit outside
the band fails deterministically across impls.

#### Vector schema
Each entry in `vectors[]`:

| field         | meaning |
|---------------|---------|
| `name`        | stable case id |
| `expected`    | §7.5.1 verdict: `pass` \| `fail` \| `indeterminate` \| `error` (never collapsed) |
| `committedAt` | commit timestamp (for deadline/expiry checks) |
| `agreement`   | the `AgreementDocument` under test |
| `listing`     | the cited listing whose terms bound the agreement |

Run (reference): `npx tsx conformance/security-vectors/agreement-listing/run.mts` → 30/30.

### `vp-replay-v0.1.json` — §7.3.2 (verifiable-presentation holder-binding / anti-replay)

13 vectors for VP holder-binding: a presentation is accepted only if a **holder
proof** (the key controlling the credential subject) verifies over a **challenge
that includes the session nonce**. Rejects both replay modes — a non-holder
presenter, and a valid presentation re-played across a different session (nonce
mismatch). Models the VC Data-Integrity `challenge` discipline, not a generic jti.

#### Vector schema
| field          | meaning |
|----------------|---------|
| `name`         | stable case id |
| `expected`     | §7.5.1 verdict (4-value, never collapsed) |
| `sessionNonce` | the verifier's fresh per-session nonce the holder proof must bind |
| `presentation` | the VP under test (holder proof + subject) |

Plus a top-level `keys` map (public keys) so verification is self-contained.
Run (reference): `npx tsx conformance/security-vectors/vp-replay/run.mts` → 13/13.

## Status

**Proposed / candidate** — independent reference-impl security vectors, derived
from the §12.4 threat matrix (#158), offered for the shared suite; pending
maintainer disposition of normative status and of whether they fold into the
generated `conformance/MANIFEST.json` surface alongside `dacs-verify`'s. SB-2's
EVM row is cross-run-converged with `dacs-verify` (#159); agreement-listing and
vp-replay await a second independent impl to cross-run against.
