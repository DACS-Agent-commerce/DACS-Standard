# DACS Security Conformance Vectors

Language-neutral conformance vectors for the **security / anti-abuse requirements**
of DACS — across settlement (SB-family, §9.5.8), negotiation/agreement (§8.5.2),
identity/vetting (§7.3.2), VerifyResult acceptance (§7.12), rail-availability selection (§9.4.4), sealed-envelope bid admission (§8.4.3), channel-message replay (§8.3.3 + CH-6), fee disclosure + disclosed-fee reconciliation (§8.5.3 FS-1..FS-5, §9.7.2 FR-1..FR-4), and private-deliverable / entitlement-credential delivery (§9.6.1 / §9.6.2, DV-1..DV-6). These complement the lifecycle vectors in the
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

### `channel-message-replay-v0.1.json` — §8.3.3 + CH-6 (channel-message replay / channelId reuse)

15 vectors for the cross-session / in-channel offer-replay defence (threat-matrix
row #14 — the DACS-normative replay analog of the SR-4/L2PS nonce-reuse case, which
was correctly **declined** as a DACS vector because the crypto envelope is left to
implementations). A `ChannelMessage` is admitted only if **all** hold, as the
§7.5.1 4-value decision (never collapsed):

- **CH-6** — the session's `channelId` MUST NOT be one reused from a prior session
  (`priorChannelIds`); a reused session channel → `fail` (the whole session is rejected).
- **channel binding** — `message.channelId == sessionChannelId`; a foreign-channel
  message (a genuine message from another session presented here) → `fail`.
- **signature** — over `"dacs-channelmsg:v1:" || sha256(JCS(envelope − signature))`
  by the sender's self-describing `cci:<hex>` key. An unresolvable sender key →
  `indeterminate` (NOT `fail`); an invalid signature → `fail`.
- **monotonic sequence** — strictly greater than the highest already seen in the
  channel (starts at 1, §8.3.3); a duplicate or decreasing `sequence` → `fail`.

A cross-session replay fails **both** ways: keep the old `channelId` → channel-binding
`fail`; rewrite it → the signature (computed over the original `channelId`) breaks.
Malformed artifacts — a non-canonicalisable `body`, a non-integer/negative
`ctx.lastSequence`, or a non-string `priorChannelIds` element — return `error`,
never collapsing to `fail` (so bad context cannot bypass the replay gate).

#### Vector schema
| field      | meaning |
|------------|---------|
| `name`     | stable case id |
| `expected` | §7.5.1 verdict (4-value, never collapsed) |
| `message`  | the `ChannelMessage` under test (channelId, sequence, sender, signature, body…) |
| `ctx`      | per-case `{ sessionChannelId, lastSequence, priorChannelIds }` |

Self-contained (sender keys are self-describing `cci:<hex>`; signatures are real
ed25519 over the §8.3.3 signed scope). Run (reference):
`npx tsx conformance/security-vectors/channel-message-replay/run.mts` → 20/20
(15 persisted vectors + 5 non-serialisable robustness assertions).

### `verifyresult-acceptance-v0.1.json` — §7.12 (VerifyResult acceptance)

13 vectors for the §7.12 consumer-side acceptance checks — three threat rows from the §12.4 matrix (#158) in one set:

- **method substitution (#6):** `VerifyResult.method` MUST be in the recipe's `defaultMethod` ∪ `alternatives`; an unaccepted method is rejected.
- **recipe poisoning (#7):** the recipe's steward signature MUST verify and `recipeVersion` MUST equal the version pinned for the session.
- **VerifyResult replay (#17):** `identifier` MUST match the claim under verification per the CF-3 canonical identity; `bundleHash` binds the result to a bundle. **Cross-session reuse within `validUntil` is explicitly permitted** (and tested) — a conformant impl MUST NOT over-reject it.

Decision is the §7.5.1 four-value verdict, never collapsed: a steward key that cannot be resolved → `indeterminate` (not `fail`); malformed input → `error`. The set deliberately includes the SAFE cases (permitted cross-session reuse; CF-3 `cci:0x`/case canonicalisation) so existence of the rule can't be satisfied by blanket rejection.

#### Vector schema
Each entry in `vectors[]`:

| field | meaning |
|-------|---------|
| `name` | stable case id |
| `expected` | §7.5.1 verdict: `pass` \| `fail` \| `indeterminate` \| `error` (never collapsed) |
| `note` | human-readable rationale |
| `verifyResult` | the VerifyResult under test (`identifier`, `method`, `bundleHash?`, `validUntil?`) |
| `recipe` | the cited recipe (`method`, `alternatives?`, `recipeVersion`, `stewardSig`) |
| `ctx` | consumer context (`claimUnderVerification`, `pinnedRecipeVersion`, `expectedBundleHash?`, `stewardPub`, `now?`) |

Run (reference): `npx tsx conformance/security-vectors/verifyresult-acceptance/run.mts` → 13/13.

### `rail-availability-selection-v0.1.json` — §9.4.4 (rail-availability selection + poisoning)

15 vectors for the §9.4.4 rail-availability rules and the availability-field poisoning defence (#158 gap #13):

- **RAV-R2** — an orchestrator MUST NOT select a rail whose `availability` is `disabled` or `failed`.
- **RAV-R1** — a non-`live` availability (e.g. `mocked`) MUST NOT be treated as `live`.
- **RAV-R3** — `operator_gated` / `closed_data` / `bilateral` are selectable ONLY when the operator-side preflight is satisfied (a runtime check).
- **RAV-R5 (poisoning)** — `availability` MUST be read from the steward-signed **and pinned/anchored** `dacs-rail:v1:` definition. A valid signature alone is insufficient: an unsigned/counterparty copy, or a validly-signed-but-**stale/cached** copy that is not the pinned definition, MUST NOT steer selection.

Decision is the §7.5.1 four-value verdict, never collapsed: a steward key that cannot be resolved, or no pinned reference to compare against, → `indeterminate` (not a silent pass); malformed def / unknown availability value → `error`.

#### Vector schema
Each entry in `vectors[]`: `name`, `expected` (§7.5.1 4-value), `note`, `rail` (`railId`, `availability`, `railVersion?`, `stewardSig`), `ctx` (`stewardPub`, `operatorPreflightOk`, `pinnedRailDigest`).

Run (reference): `npx tsx conformance/security-vectors/rail-availability-selection/run.mts` → 15/15.

### `sealed-envelope-deadline-v0.1.json` — §8.4.3 (sealed-envelope bid admission)

15 vectors for whether a sealed bid is admitted to the auction candidate set (#158 gap #27):

- **SE-2 deadline gate** — the authoritative time is the **SR-2 anchor timestamp**; the self-reported `commitTimestamp` MUST NOT gate. A commit anchored after `commitDeadline` is late → excluded, and an on-time self-report does not save it (both directions tested).
- **SE-3 reveal window** — the reveal MUST be anchored within `[commitDeadline, commitDeadline + revealWindow]`; out-of-window (early or late) → excluded.
- **SE-4** — a committed bidder MUST reveal; a missing reveal → excluded.
- **CH-3** — the commit's `bidderClaim` MUST equal the authenticated sender → else excluded.
- **Commitment binding** — the revealed `{bid, salt}` MUST reproduce `bidHash = sha256("dacs-sealed-bid:v1:" || sha256(JCS(bid)) || salt)` (exact lowercase hex); a different bid/salt, or a non-lowercase-hex committed hash, → excluded / error.

§7.5.1 four-value, never collapsed: an unresolvable SR-2 anchor timestamp → `indeterminate`; malformed commit / non-hex salt / non-lowercase-hex bidHash → `error`. Boundary instants are deliberately not asserted.

#### Vector schema
A top-level `ctx` (`commitDeadline`, `revealWindowSec`, `authenticatedSender`); each entry in `vectors[]`: `name`, `expected`, `note`, `commit` (`bidHash`, `bidderClaim`, `commitTimestamp`, `anchorTimestamp`), `reveal` (`bid`, `salt`, `anchorTimestamp`) or `null`.

Run (reference): `npx tsx conformance/security-vectors/sealed-envelope-deadline/run.mts` → 15/15.

### `private-deliverables-v0.1.json` — §9.3 / §9.6.1 / §9.6.2 (DV-1..DV-6, private delivery + entitlement credentials)

16 vectors for the private-delivery (`accessModel`) and `credentialRef`-entitlement
rules — the six DV rows defined at §9.6.1 and §9.6.2. They assert that access mode,
buyer binding, audit trail, and the delivered/valid/readable gates behave identically
across implementations, and that the DV-6 readability verdict is **never collapsed**:

- **DV-1 content-hash invariant (§9.6.1)** — `deliverableContentHash` MUST be the
  sha256 of the **cleartext** canonical payload, byte-identical across `public` /
  `buyer-only` / `encrypt-to-buyer`, never the ciphertext. A pass case shows the same
  digest across all three modes; a fail case takes the hash over the ciphertext.
- **DV-2 access-mode fidelity (§9.6.1)** — a declared non-`public` deliverable resolved
  as delivered `public` ⇒ `indeterminate` (a provenanced `confidentiality-downgrade`
  flag), never `pass`; over-provision (declared `public`, delivered private) is NOT a
  violation (`pass`).
- **DV-3 buyer binding (§9.6.1)** — under `buyer-only` the ACL `allowed` entry MUST be
  the agreement-bound buyer `AgreementParty` (§8.5) address (a foreign, separately-
  presented address ⇒ `fail`); under `encrypt-to-buyer` the payload MUST be sealed to
  that party's `AgreementParty.encryptionKey` (a different key ⇒ `fail`).
- **DV-4 ACL-mutation auditability (§9.6.1)** — a deliverable ACL mutation SHOULD be an
  anchored+signed record, and MUST be for a `credentialRef` entitlement (§9.6.2); an
  unanchored `credentialRef` ACL mutation ⇒ `fail`.
- **DV-5 three gates never collapsed (§9.6.2)** — for a `credentialRef` entitlement,
  `SettlementEvidence` asserts ONLY **delivered** (binds the `credentialRef` + credential
  cleartext digest at the settled `renewalSeq`), never **valid** or **readable**; evidence
  that over-asserts `readable` ⇒ `fail`.
- **DV-6 readability verdict, do-not-collapse (§9.6.2)** — in `allowed` & not blacklisted
  ⇒ **readable** (`pass`); entitlement window lapsed ⇒ **clean-negative** (`fail`,
  lifecycle); buyer dropped from `allowed` / blacklisted ⇒ **ACL-dropped
  (channel-unreadable)** (`fail`); ACL/storage unresolvable ⇒ **indeterminate** — a
  transient outage MUST NOT be read as channel-unreadable. One vector per arm.

Decision is the §7.5.1 four-value verdict, never collapsed. Because DV-6's four
readability outcomes do not map one-to-one onto the four verdicts (both `clean-negative`
and `ACL-dropped` are negatives), the four-way readability label is carried in a
**companion `readability` field** alongside the top `expected` verdict (mirroring how
`sb2-settlement-uniqueness` splits `decision`/`effect`). DV-2's downgrade case likewise
carries a companion `flag`, and DV-5 an `assertedGates` list.

#### Vector schema
Each entry in `vectors[]`:

| field | meaning |
|-------|---------|
| `name` | stable case id |
| `expected` | §7.5.1 verdict: `pass` \| `fail` \| `indeterminate` \| `error` (never collapsed) |
| `rule` | the DV rule exercised (`DV-1`..`DV-6`) |
| `note` | human-readable rationale |
| `readability` | *(DV-6 only)* four-way readability label: `readable` \| `clean-negative` \| `ACL-dropped` \| `indeterminate` |
| `flag` | *(DV-2 downgrade only)* `confidentiality-downgrade` |
| `assertedGates` | *(DV-5 only)* the gates the `SettlementEvidence` asserts |
| `agreementBuyer` | the agreement-bound buyer `AgreementParty` (§8.5): `role`, `primaryClaim`, resolved `address`, `encryptionKey` |
| `delivery` / `deliveries` | the delivery under test (`accessModel`, `deliverableContentHash`, `hashedOver`, `acl`, `sealedTo`, declared/delivered mode…) |
| `entitlement` | *(DV-4..6)* the EntitlementRecord binding (`jobId`, `renewalSeq`, `credentialRef`, `startsAt`, `endsAt`) |
| `aclMutation` / `settlementEvidence` / `acl` / `now` | per-rule context for DV-4 (audit record), DV-5 (evidence gates), DV-6 (ACL + evaluation instant) |

Fixtures are deterministic: addresses/keys are fixed hex; `deliverableContentHash` values
are the real `sha256` of the canonical (JCS) cleartext payload (`hashedOver: "cleartext"`),
and the DV-1 fail case's hash is `sha256` over a distinct ciphertext byte-string; timestamps
are integer unix-ms. Entitlement window is `[1750000000000, 1750003600000]`.

#### Running
Language-neutral data: feed each vector's inputs to a §9.6 verifier and assert `expected`
(plus `readability` for DV-6). The set-level `hash` is
`sha256(JSON.stringify(vectors))` with sorted keys and ASCII-escaped output (the
`verifyresult-acceptance` convention); `count` MUST equal `vectors.length` (16). This set
awaits a reference `run.mts` and a second independent impl to cross-run against.

### `feeschedule-reconciliation-v0.1.json` — §8.5.3 FS-1..FS-5 + §9.7.2 FR-1..FR-4 (fee disclosure + disclosed-fee reconciliation)

17 vectors for the optional DACS-3 `feeSchedule` cost-disclosure (§8.5.3) and the informational DACS-4 disclosed-fee reconciliation (§9.7.2), requested by RB on #186. Two distinct operations are exercised, so each vector carries an `op` discriminator and its `expected` verdict is read in that op's vocabulary:

- **`validate-feeschedule`** — is the `feeSchedule` shape conformant? `expected` ∈ the §7.5.1 4-value `pass` \| `fail` \| `indeterminate` \| `error`. Covers **FS-1** (priceBasis REQUIRED + `oneOffTotal.currency == terms.price.currency`), **FS-2** (each `FeeItem` exactly one of `fixed`\|`rateBps`), **FS-5** (`earlyTerminationFee` is a disclosure shape only, semantics per §10.3.1).
- **`reconcile`** — does the disclosure reconcile against actual settlement? `expected` ∈ the **FR-4 trichotomy** `reconciles` \| `diverged` \| `indeterminate` (+`error` for malformed), *never collapsed* — a transient/absent resolution is `indeterminate`, never silently `diverged`. Covers **FR-1** (only `kind=="network"` reconciles vs `SettlementEvidence.paymentFee`; platform/processing/spread/subscription stay disclosure-only), **FR-2** (`rateBps → amount = price.amount × rateBps ÷ 10000`, canonical decimal, **half-up to the settlement asset's decimals**), **FR-3** (expected payer-total via `priceBasis` inclusive vs exclusive), **FR-4** (the reconciles/diverged/indeterminate trichotomy), and **FS-4** (a `recurrence` item is an ongoing disclosed cost, reconciled on the one-off only — never a charge trigger / never in a gating path).
- **`settle-gate`** — proves **FS-3**: a disclosed fee that mismatches actual settlement MUST NOT gate settlement; the settlement verdict stays `pass`. A `reconcile` op on the same data would return `diverged`, but that is informational and never blocks/reverts/retries settlement.

Fee math is exact-decimal (no float): the FR-2 boundary case `50 × 25 ÷ 10000 = 0.125` rounds **half-up** to `0.13` at 2-decimal precision (half-even would wrongly give `0.12`).

#### Vector schema

Each entry in `vectors[]`:

| field                | meaning |
|----------------------|---------|
| `name`               | stable case id |
| `rule`               | the normative rule exercised: `FS-1`..`FS-5` (§8.5.3) or `FR-1`..`FR-4` (§9.7.2) |
| `op`                 | operation under test: `validate-feeschedule` \| `reconcile` \| `settle-gate` |
| `expected`           | verdict in `op`'s vocabulary (see above) |
| `note`               | human-readable rationale (with the arithmetic where it applies) |
| `agreement`          | the `AgreementDocument` slice under test (`terms.price` + `terms.feeSchedule`) |
| `settlement`         | `SettlementEvidence` slice (`paymentAmount`, `paymentFee?`, `outcome`…) — present for `reconcile`/`settle-gate`; absent for pure validation |
| `rail`               | settlement `AssetSpec` (carries `decimals` for FR-2 rounding) — present where decimals matter |
| `expectedPayerTotal` | expected payer-total for the FR-3 `priceBasis` cases (distinguishes inclusive vs exclusive) |
| `reconciliation`     | provenanced divergence detail on the FR-4 `diverged` case (`signedDelta`, `breachedToleranceBps`, `direction`) |

#### Hash / count convention

`count` is the number of `vectors[]`. `hash` is `sha256(canonical_json(vectors))` where `canonical_json` is exactly `scripts/validate_conformance_vectors.py::canonical_json` (`json.dumps(..., sort_keys=True, separators=(",",":"), ensure_ascii=False)`) applied to the `vectors` array. Regenerate with the set's builder; the security subdirectory is excluded from the lifecycle shape-check glob (see the shape note above), so the §-references (validated by `scripts/validate_spec_refs.py`) are the CI-enforced surface here.

#### Running

Language-neutral data: feed each `agreement` (+ `settlement`/`rail` where present) to your §8.5.3 / §9.7.2 implementation and assert `expected` for the given `op`. Reference run (pending) lives in `pathos-dacs-ref`:

```
npx tsx conformance/security-vectors/feeschedule-reconciliation/run.mts
# → 17/17 vectors pass
```

## Status

**Proposed / candidate** — independent reference-impl security vectors, derived
from the §12.4 threat matrix (#158), offered for the shared suite; pending
maintainer disposition of normative status and of whether they fold into the
generated `conformance/MANIFEST.json` surface alongside `dacs-verify`'s. SB-2's
EVM row is cross-run-converged with `dacs-verify` (#159); agreement-listing and
vp-replay await a second independent impl to cross-run against.
`feeschedule-reconciliation` was authored on RB's request (#186) covering §8.5.3
FS-1..FS-5 + §9.7.2 FR-1..FR-4; awaiting a second independent impl to cross-run against.
