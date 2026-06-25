# DACS Security Conformance Vectors

Language-neutral conformance vectors for the **security requirements (SB-family)**
of the DACS Settlement standard. These complement the lifecycle vectors in the
parent directory: where those assert that a well-formed five-stage session
validates, these assert that the **anti-abuse rules** behave identically across
independent implementations.

> **Shape note (why this is a subdirectory).** These vectors are
> *verifier-input/output pairs* (`record` + prior `consumed` state → expected
> `decision` + `effect`), not five-stage lifecycle bundles. The canonical
> `scripts/validate_conformance_vectors.py` run globs `conformance/vectors/*.json`
> non-recursively, so files here (like `../examples/`) are intentionally excluded
> from the lifecycle shape-check and carry their own schema, described below.

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

## Status

**Proposed / candidate** — two independently-converging implementations agree on
the EVM row; pending maintainer disposition of normative status and of whether
these fold into the generated `conformance/MANIFEST.json` surface alongside
`dacs-verify`'s.
