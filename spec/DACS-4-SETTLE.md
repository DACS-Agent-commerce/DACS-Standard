# DACS-4: Settle — Settle

*Normative module of DACS v0.1. Read the [Primer](../PRIMER.md) first; shared types, signatures, canonical form, the session model, and substrate requirements live in [CORE](CORE.md). Section numbers are retained from the unified specification; per the §→document map in [CORE](CORE.md), cross-references of the form §6–§10 point to sibling module documents, and §A / §12–§14 to the companion references (Demos mapping, threat model, glossary, conformance plan). The [conformance vectors](../conformance/) exercise this module's rules.*

## Chapter 9 — DACS-4: Settle

**Stage:** Settle (4th of 5). **Status:** Draft — **DACS-4 v0.2** (on the common DACS v0.1 baseline; adds SB-1..SB-3 session-bound settlement evidence, §9.5.8). **Depends on:** SR-2 (required), SR-5 (required for cross-chain rails only); composes with AP2, x402, ERC-20, SPL, HTLC contracts, and substrate-native bridges (Liquidity Tanks on Demos). **Used by:** DACS-5 (settlement evidence in session bundle).

### 9.1 Abstract

DACS-4 specifies how value is exchanged and the deliverable provided once a DACS-3 agreement is committed. It defines:

- A **payment rail registry** — a versioned, anchored set of payment rails. Each rail is a typed envelope identifying the chain or network, the asset, the settlement contract or protocol, and any rail-specific parameters.
- A **closed set of payment phases** (DACS-4 phase types) — pay-evm-erc20, pay-solana-spl, pay-cross-chain-htlc, pay-cross-chain-liquidity-tank, pay-ap2, pay-x402. Each is a phase with a uniform PhaseHandlerResult shape.
- A **closed set of delivery phases** — deliver-storage-program, deliver-entitlement, deliver-attested-payload. Each produces SettlementEvidence the rest of the stack consumes.
- A **uniform SettlementEvidence shape** — the record produced by every payment and delivery phase; the substrate-anchored audit unit referenced by DACS-5.
- A **cross-chain coordination layer** — atomic settlement primitives (HTLC, Liquidity Tank) so a payment on chain A and a delivery on chain B succeed together or not at all.

Payment and delivery are decoupled: a listing’s pipeline composes one or more payment phases with one or more delivery phases, in any order the seller deems safe. The DACS-3 agreement document carries the chosen rail and deliverable references; DACS-4 phases consume them and produce evidence DACS-5 anchors.

### 9.2 Motivation

Settlement is the stage where the most working open standards exist. Stablecoin transfers, ERC-20 / SPL token movements, HTLC swaps, AP2 payment mandates, and x402-style HTTP micropayments all ship in production today. None of them, individually, is sufficient for the agent commerce lifecycle, because each addresses a single slice:

- **AP2** (FIDO Alliance, April 2026) mandates *who is authorised to pay how much for what* — not how payment is routed, how delivery binds to payment, or what audit record results.
- **x402** (Coinbase / Cloudflare / Anthropic) specifies HTTP 402 micropayments — not agent-to-agent settlement off HTTP.
- **ERC-20 / SPL** specify on-chain token transfer — not cross-chain coordination, delivery binding, or evidence.
- **HTLC contracts** specify atomic cross-chain swaps — coordination only, not the rest of the lifecycle.

DACS-4 composes these standards into a uniform settlement layer. The payment rail registry routes each rail to its appropriate phase handler. The SettlementEvidence shape lets DACS-5 anchor the result regardless of which rail was used. The cross-chain coordination layer extends to settlements that span chains.

A second motivation is **scope discipline**: DACS-4 does not specify new payment cryptography. It composes existing protocols, adds the registry and evidence schema, and provides cross-chain coordination via substrate primitives (SR-5). The new bytes-on-the-wire are limited to the rail registry, the SettlementEvidence shape, and the phase-handler contracts.

### 9.3 Shared types

These types are referenced by DACS-1 (listings), DACS-3 (agreements), DACS-4 (this chapter), and DACS-5 (session record).

```
type PaymentRailRef = {

  railId: string                       // e.g. "evm-erc20:1:USDC" or "demos:cross-chain-tank:USDC"

  railVersion?: number                 // pinned at session start if set

  parameters?: Record<string, unknown>

}

type PricingSpec =

  | { kind: "fixed"; price: PriceTerm }

  | { kind: "negotiable"; bandCenter: PriceTerm; minPct: number; maxPct: number }   // price band around bandCenter; minPct/maxPct non-negative %, 0 ≤ minPct < 100; band + half-up rounding + inclusive bounds per §8.5.2. See the "Negotiable pricing band" note below.

  | { kind: "auction"; reservePrice?: PriceTerm; selectionRule: "lowest-price" | "highest-price" | "first-acceptable" | "rule-ref:<contentHash>:<uri>" }   // selectionRule MUST be drawn from the SAME enum as the phase-step parameter (§8.4.3) so the §8.4.3 step-5 "MUST equal" rule is type-expressible; reservePrice.currency MUST equal the listing currency; enforced as a floor (highest-price / first-acceptable / rule-ref) or ceiling (lowest-price), inclusive, per §8.4.3 step 5

type PriceTerm = {

  amount: string                       // canonical decimal string (rule CD-1, CORE §B.2): minimal-digit, no leading/trailing zeros, no exponent; MUST be positive (see normative rule below)

  currency: string                     // ISO 4217 fiat OR asset id (e.g. "usd-stablecoin", "USDC", "SOL")

  unit?: string                        // optional unit qualifier (e.g. "per-call")

}

type DeliverableSpec =

  | { kind: "storage-program"; schemaUrl?: string; expectedSizeBytes?: number }

  | { kind: "entitlement"; durationSec: number; renewable: boolean }

  | { kind: "attested-payload"; payloadFormat: string; verificationMethod?: VerificationMethod; expectedSizeBytes?: number }

  | { kind: "external"; description: string; verificationMethod?: VerificationMethod }

type DeliverableRef = {

  deliverableType: DeliverableSpec["kind"]

  hash: string                         // sha256 of the RFC 8785 JCS canonical form of the DeliverableSpec (see below)

  schemaUrl?: string

}

// On-chain transaction reference; discriminated union.

type TxRef = ChainTxRef

type ChainTxRef =

  | { kind: "evm"; chainId: number; txHash: string }

  | { kind: "solana"; cluster: "mainnet" | "devnet" | "testnet"; signature: string }

  | { kind: "demos"; txHash: string }

  | { kind: "storage-program"; address: string; writeTxHash: string }

  | { kind: "ap2"; mandateId: string; providerRef: string; protocolVersion: string }

  | { kind: "x402"; httpResource: string; paymentReceiptHash: string; settlementTxHash?: string; chainId?: number; protocolVersion: string }

  | { kind: "htlc-lock"; chainId: number; contractAddress: string; lockTxHash: string }

  | { kind: "htlc-reveal"; chainId: number; contractAddress: string; revealTxHash: string }   // the payer's destination claim, which reveals the preimage on-chain

  | { kind: "htlc-claim"; chainId: number; contractAddress: string; claimTxHash: string }   // the payee's source-side claim against the revealed preimage (the decisive success tx)

  | { kind: "htlc-refund"; chainId: number; contractAddress: string; refundTxHash: string }

  | { kind: "liquidity-tank"; bridgeId: string; sourceChainId: number; destChainId: number; lockTxHash: string; releaseTxHash?: string }
```

**Negotiable pricing band (`negotiable`).** `minPct` / `maxPct` are non-negative percentages with `0 ≤ minPct < 100`. The admissible band, its half-up rounding, and its inclusive bounds are defined by §8.5.2 (the listing-conformance check). A verifier MUST reject a listing whose computed lower bound is ≤ 0. The band is **asymmetric by design**: `minPct < 100` keeps the lower bound positive, but `maxPct` is **intentionally unbounded**. So the band gives **no upper price protection** — a buyer-side orchestrator SHOULD enforce its own acceptance ceiling rather than rely on the band to cap an overcharge.

> **Note (non-normative).** The unbounded `maxPct` is deliberate: open-ended upside is a legitimate market form.

**DeliverableRef canonical hash.** `DeliverableRef.hash` is `sha256(canonical_form)`, hex, where `canonical_form` is the RFC 8785 JCS serialisation of the `DeliverableSpec` — the same rule as every hashed DACS artifact. The load-bearing rule: **both parties MUST compute it over the listing's `offering.deliverable` *as anchored*, not a re-derived copy**. Otherwise a trivial formatting / optional-field difference changes the hash and the §8.5.2 check is no longer byte-deterministic.

> **Note (non-normative).** JCS's lexicographic keys + consistent omitted-vs-present handling are what make a discriminated-union-with-optional-fields hash reproducible.

**PriceTerm.amount positivity (normative).**

- `PriceTerm.amount` MUST parse to a finite value **strictly greater than zero** — never NaN, infinite, or negative.
- Implementations MUST reject any bid, listing price, or agreed price whose `amount` is non-positive **before applying `selectionRule` and before commit-agreement**.
- A violating revealed bid MUST be excluded from the candidate set, not selected.

> **Note (non-normative).** This is load-bearing because `amount` feeds three adversarial consumers — winner-selection (§8.4.3), band validation (§8.5.2), and on-chain amount construction (§9.5.2) — and a zero/negative bid would otherwise **win a `lowest-price` auction**.

### 9.4 Payment rail registry

A versioned, anchored set of payment rails. Each rail entry describes one settlement path.

#### 9.4.1 Rail schema

```
type RailDefinition = {
  railVersion: number
  railId: string                       // canonical id; lowercase ASCII; max 64 chars
  railType: "evm-erc20" | "solana-spl" | "cross-chain-htlc" | "cross-chain-liquidity-tank" | "ap2" | "x402"
  asset: AssetSpec                     // what is being transferred
  network: NetworkSpec                 // where it lives
  phaseHandler: PhaseType              // which pay-* phase handles it
  parameters: Record<string, unknown>  // rail-type-specific
  availability: RailAvailability       // operational status (see §9.4.4)
  governance: {
    proposedBy: ClaimReference;
    acceptedAt: number;
    supersedes?: number;
    anchoring: "in-code" | "single-signer" | "multisig";   // progressive-anchoring phase (PA-1/PA-2/PA-3); see §9.4.3 and §7.4.4
    emergency?: { isEmergency: true; failureObservation: string };   // present iff this is an emergency revision
    deprecated?: boolean;
    deprecationReason?: string                              // required when deprecated is true
  }
  signature: RailSignature             // steward's signature (see §9.4.3)
}
type RailAvailability =
  | "live"            // settlement path runs end-to-end against the network today
  | "operator_gated"  // requires per-operator credential, key, registration, or licensed-agent setup
  | "closed_data"     // network or asset access not publicly available (e.g., permissioned chain)
  | "bilateral"       // requires per-relationship agreement between counterparties
  | "mocked"          // settlement path stubbed; not a production rail
  | "disabled"        // rail present but the steward has marked it not-for-use
  | "failed"          // rail's underlying network or asset path is currently broken
type AssetSpec =
  | { kind: "erc20"; chainId: number; contract: string; symbol: string; decimals: number }
  | { kind: "spl"; cluster: "mainnet" | "devnet" | "testnet"; mint: string; symbol: string; decimals: number }
  | { kind: "native-evm"; chainId: number; symbol: string; decimals: number }
  | { kind: "native-solana"; cluster: "mainnet" | "devnet" | "testnet"; symbol: "SOL"; decimals: 9 }
  | { kind: "fiat-via-ap2"; isoCurrency: string; provider: string }
  | { kind: "stablecoin-cross-chain"; canonicalSymbol: string; routes: CrossChainRoute[] }
type NetworkSpec =
  | { kind: "evm"; chainId: number; rpcAttestation: "consensus-backed-proxy" | "evm-rpc" }
  | { kind: "solana"; cluster: "mainnet" | "devnet" | "testnet" }
  | { kind: "ap2-provider"; providerEndpoint: string }
  | { kind: "x402-resource"; resourceBaseUrl: string }
  | { kind: "cross-chain"; mechanism: "htlc" | "liquidity-tank" | "substrate-native" }
type CrossChainRoute = {
  sourceChainId: number | string
  destChainId: number | string
  htlcContracts?: { source: string; dest: string }
  liquidityTankIds?: string[]
}
```

#### 9.4.2 v0.1 registry contents

The v0.1 registry contains rail entries for the most-used settlement paths in production. Implementations MUST resolve rails from the canonical addresses listed in the rail-registry index document (dacs4:registry:v0.1).

| Rail ID | Phase handler | Notes |
| --- | --- | --- |
| evm-erc20:1:USDC | pay-evm-erc20 | Ethereum mainnet USDC |
| evm-erc20:8453:USDC | pay-evm-erc20 | Base mainnet USDC |
| evm-erc20:42161:USDC | pay-evm-erc20 | Arbitrum One USDC |
| evm-erc20:137:USDC | pay-evm-erc20 | Polygon mainnet USDC |
| solana-spl:mainnet:USDC | pay-solana-spl | Solana mainnet USDC |
| solana-spl:mainnet:USDT | pay-solana-spl | Solana mainnet USDT |
| cross-chain-htlc:USDC | pay-cross-chain-htlc | Atomic swap across EVM ↔ Solana for USDC |
| cross-chain-liquidity-tank:USDC | pay-cross-chain-liquidity-tank | Substrate-coordinated atomic settlement; on Demos: Liquidity Tanks. v0.1 supported routes: ETH Sepolia → Polygon Amoy unidirectional only |
| ap2:visa-direct | pay-ap2 | AP2 mandate to Visa Direct |
| ap2:mastercard-send | pay-ap2 | AP2 mandate to Mastercard Send |
| ap2:stripe-paymentintents | pay-ap2 | AP2 mandate to Stripe PaymentIntents |
| x402:default | pay-x402 | Generic x402 HTTP 402 micropayment |

**v0.1 cross-chain settlement scope.** `pay-cross-chain-liquidity-tank` is supported **only** for the live tank routes: ETH Sepolia ↔ Polygon Amoy testnet, USDC, EVM-source unidirectional. All other tank rails are 🟡 to-add. v0.1 keeps both `pay-cross-chain-liquidity-tank` and `pay-cross-chain-htlc` first-class.

> **Note (non-normative).** Further tank routes unlock as Native Bridges Phase 2–4 ship: Solana tanks, bidirectional routes, additional EVM rails, mainnet deployments, non-USDC stablecoins. HTLC is the path the reference implementation runs today — a ~929-LOC reference (Solana Anchor program + Base Sepolia EVM HTLC contract) with lock/reveal/refund implemented end-to-end.

**v0.1 rail reference-backing status (honest disclosure).** A rail is *reference-backed* when a live settlement path exists **and** a reference implementation exercises it. The registered rails differ in maturity. An orchestrator MUST consult each rail's pinned `availability` (§9.4.4) rather than assume `live`. In particular, `pay-ap2` registry entries declare a non-`live` `availability` (`operator_gated` or `mocked`) in v0.1, and orchestrators MUST NOT treat them as `live` (RAV-R1).

Maturity by rail:

| Rail(s) | v0.1 status |
| --- | --- |
| `pay-evm-erc20`, `pay-solana-spl`, `pay-cross-chain-htlc` | Reference-backed: exercised by the reference implementation, with §14 conformance vectors |
| `pay-cross-chain-liquidity-tank` | Partially live: only the Phase-1 testnet route (ETH Sepolia → Polygon Amoy, USDC, unidirectional); other routes to-add |
| `pay-x402` | Exercised by the reference implementation; §14 conformance vector present (`settlement-x402-pass`); **not** `operator_gated` (see note) |
| `pay-ap2` | Specified, not yet reference-backed: no live settlement path, no §14 conformance vector; `operator_gated` (see note) |

> **Note (non-normative).** *pay-x402* (§9.5.7) — x402 settles a gasless USDC transfer **on its settlement chain** (e.g. Base), so a `pay-x402` `SettlementEvidence` record is chain-verifiable against the settlement chain via `settlementTxHash`/`chainId`, exactly like the `evm` rail. The reference implementation runs x402 end-to-end as a primary rail: a buyer-side x402 client signing an EIP-3009/Permit2 authorisation and settling USDC on Base. It therefore meets the live-path + reference-implementation bar, and now has parity with the rails above, including a §14 conformance vector (`settlement-x402-pass`).
>
> *pay-ap2* (§9.5.6) — the handler procedure, registry entries, and evidence shape are defined, but there is no live path. `pay-ap2` settles **off-chain** (a provider receipt, not chain-verifiable) and requires AP2 provider onboarding (Visa Direct / Mastercard Send / Stripe PaymentIntents); AP2 itself was donated to the FIDO Alliance only in April 2026. Bringing it to reference-backed status — a live path plus conformance vectors — is roadmap work.

#### 9.4.3 Rail authoring and resolution

A conforming rail author MUST:

- (RD-1) sign the rail with the registry steward’s signing key over the domain-separated payload "dacs-rail:v1:" || rail_hash per §B.7;
- (RD-2) anchor the rail via SR-2 at the canonical address;
- (RD-3) specify railVersion as monotonically increasing per railId;
- (RD-4) specify supersedes when replacing a prior rail with the same railId;
- (RD-5) ensure the railType matches the asset and network kinds (an evm-erc20 rail with a Solana asset MUST be rejected).

A consumer MUST resolve a rail by:

1. reading the rail-registry index from dacs4:registry:v0.1;
2. looking up the entry for the agreement’s terms.rail.railId;
3. fetching the rail at the indicated anchor and verifying its content hash and signature;
4. if the agreement pins a specific railVersion, MUST use that version; otherwise MUST use the latest at session start, pinned into the session.

**Progressive anchoring for early deployments.** The rail registry follows the same progressive anchoring pattern as the DACS-2 recipe registry (§7.4.4):

- **PA-1 (bootstrap)** — rails shipped as in-code constants.
- **PA-2 (current)** — rails anchored by the steward, currently KyneSys Labs, under a single signature.
- **PA-3 (future)** — rails anchored under multi-signature governance, if and when a constituted body is established.

Implementations MUST disclose which phase they operate in. Consumers MUST verify the rail’s anchoring phase against their own trust requirements.

#### 9.4.4 Rail availability (normative)

Every RailDefinition MUST declare an availability value, with the same value set and semantics as recipe availability (§7.4.5). The value names the rail’s current operational status — what an orchestrator should actually expect when it tries to settle through this rail. Mapping is direct:

- **live** — settlement path runs end-to-end on the named network today. Typical for the major stablecoin-on-major-chain rails.
- **operator_gated** — rail technically functions but requires per-operator setup: pre-funded liquidity, licensed-agent registration (regulated fiat rails), API credentials with the payment processor, IP allow-listing.
- **closed_data** — rail targets a permissioned or non-public network. Rail shape is defined for forward compatibility but the path cannot run from an open operator.
- **bilateral** — rail runs only between counterparties with a pre-existing bilateral agreement (custom settlement contract, dedicated escrow agent, contracted clearing service).
- **mocked** — settlement path is stubbed for development or testing. MUST NOT be presented as a production rail.
- **disabled** — rail exists in the registry but the steward has marked it not-for-use. Orchestrators MUST NOT initiate new sessions selecting disabled rails; in-flight sessions continue.
- **failed** — rail’s underlying network or asset path is currently broken (chain congestion preventing settlement, asset contract paused, bridge offline).

**Orchestrator obligations.**

- (RAV-R1) An orchestrator MUST inspect rail availability before selecting a rail for a session.
- (RAV-R2) An orchestrator MUST NOT select rails with availability values disabled or failed.
- (RAV-R3) An orchestrator MAY select rails with availability values operator_gated, closed_data, or bilateral only if the relevant operator-side configuration is in place; this is a runtime preflight check, not a static property of the rail.
- (RAV-R4) A rail's `availability` is pinned at session start (§9.13), so a mid-session availability *flip* is not observable from the pinned definition; RAV-R4 therefore binds at the point of use. If a settlement attempt on the pinned rail fails because the rail is non-operational, the orchestrator MUST classify the failure `errorClass: "substrate"`, not `counterparty`. Rail-non-operational means a rail-down / substrate failure, as distinct from a transient RPC hiccup or a counterparty error.
- (RAV-R5) **Authoritative availability read.** An orchestrator MUST read `availability` from the authoritative rail definition: the signed, anchored `dacs-rail:v1:` record pinned at session start. It MUST NOT read `availability` from an unauthenticated cache, discovery mirror, or counterparty-supplied copy.

> **Note (non-normative).** RAV-R4: a proactive out-of-band rail-liveness probe, mirroring the §8.12 CH-4 channel-liveness probe, would let an orchestrator detect failure *before* attempting settlement. That probe is a roadmap item; v0.1 detects rail failure at the settlement attempt.
> RAV-R5 closes availability-field poisoning: a tampered pre-pin read could steer an orchestrator onto a disabled/failed rail, or away from a live one. The pinned, signed definition is the only trusted source.

**Steward obligations.** Same as recipe availability (RAV-5, RAV-6, RAV-7 in §7.4.5) applied to rails. The steward maintains availability values current; transitions are signed and anchored revisions; availability is per-rail-version.

### 9.5 Payment phases

The v0.1 closed set. Each is a PhaseType from chapter 6’s closed enumeration, with a phase-handler contract conforming to §B.5’s SessionContext / PhaseHandlerResult.

#### 9.5.1 Common contract

Every pay-* phase handler MUST:

**(PC-1)** accept a PaymentPhaseInput conforming to the shape below.

**(PC-2)** produce SettlementEvidence anchored via SR-2 at `dacs4:payment:{jobId}:{railId}:{phaseIndex}[:resolved]` (or substrate equivalent). Segment rules:

- `phaseIndex` is the bare-integer pipeline phase index of this pay-* invocation (`BundlePhaseEntry.index`). It is REQUIRED so repeated pay-* phases (PIPE-5) do not collide at one address.
- An ST-8 resolution anchors its superseding success record at the same address with a trailing `:resolved` segment.
- `railId` is a CF-4 variable segment and MUST be percent-encoded before assembly (internal colons → `%3A`, CORE §B.1). `jobId` (a ULID), `phaseIndex`, and `resolved` need no encoding.

Worked example — `jobId` `01J8ME0SXKQ4T9V2RC5HJ6WX7D`, rail `evm-erc20:8453:USDC`, phase index 3, after an ST-8 resolution:

```
dacs4:payment:01J8ME0SXKQ4T9V2RC5HJ6WX7D:evm-erc20%3A8453%3AUSDC:3:resolved
```

> **Note (non-normative).** The `phaseIndex` discriminator mirrors the entitlement `renewalSeq` and amendment `amendmentIndex` discipline.

**(PC-3)** return a PhaseHandlerResult with `attestationRef` pointing to the evidence (except as deferred by PC-7 for the cross-chain anchor-pending case).

**(PC-4)** classify the outcome as exactly one of `ok: true` (payment confirmed at the chain's finality semantics) or `ok: false` with an `errorClass`:

| errorClass | trigger |
| --- | --- |
| `permanent` | refused by chain, insufficient balance, invalid signature |
| `transient` | RPC failure, mempool congestion |
| `counterparty` | AP2 mandate revoked, x402 server refused |
| `substrate` | SR-2 unavailable, and no irreversible on-chain value movement has occurred (see PC-7) |
| `settlement-atomicity` | cross-chain only; one leg reached a terminal or asymmetric state the other did not match — a timeout, or the HTLC-9 preimage-revealed-but-counterpart-unclaimed state |

For the HTLC-9 asymmetric-open sub-case, the handler signals the open state and the orchestrator routes the session to the non-terminal `settle-asymmetric` state (§10.3.1, ST-8). A terminal `settlement-atomicity` outcome — the `settle-failed` state — is reached only after the ST-8 recovery window expires unresolved.

**(PC-5)** before settling, `amount.currency` MUST resolve to `rail.asset` (reject a mismatch as `ok: false` / `errorClass: "permanent"`), per AssetSpec kind:

| AssetSpec kind | `amount.currency` must equal |
| --- | --- |
| erc20 / spl / native-evm / native-solana | `rail.asset.symbol` |
| fiat-via-ap2 | `rail.asset.isoCurrency` |
| stablecoin-cross-chain | `rail.asset.canonicalSymbol` |

Handlers MUST NOT settle a payment whose `amount.currency` does not resolve under this mapping.

**(PC-6)** when outcome is `success`, populate `settlementFinality` (the finality model and parameters actually applied) in the produced SettlementEvidence — REQUIRED on any `success`-outcome payment evidence record, and absent on delivery evidence records.

**(PC-7) Cross-chain anchor/settlement decoupling.** On cross-chain rails the value moves on two foreign chains independent of the SR-2 substrate, so evidence anchoring is decoupled from settlement success. **Principle: once value has irreversibly moved on the foreign chains, anchoring is bookkeeping that must catch up — never a reason to fail or pause the payment.**

*Irreversible movement* means: an HTLC fully settled on BOTH legs — the payee's `htlc-claim` reaching source-chain finality (§9.5.4), not the HTLC-9 asymmetric state — or a liquidity-tank op reaching `completed`.

Once irreversible movement is confirmed, the handler:

- (a) MUST return `ok: true` with the confirmed foreign-chain `txRefs` even if SR-2 anchoring is unavailable or pending;
- (b) MUST queue a durable anchor-retry idempotent on the `dacs4:payment:{jobId}:{railId}:{phaseIndex}` address — write-once by the PC-2 discriminator, so a re-anchor cannot duplicate the record;
- (c) MAY omit `attestationRef` until the retry confirms the anchor, then attach it. `PhaseHandlerResult.attestationRef` is OPTIONAL in §5 precisely to permit this; the PC-2/PC-3 obligations are satisfied by the retry rather than at return time;
- (d) MUST NOT classify this as `errorClass: "substrate"` — that class is reserved for SR-2 unavailability *before* any irreversible movement, per PC-4.

PC-7 is the one carve-out from the ST-7 substrate-failure-pause (§10.3.1): because value has already moved irreversibly, the handler commits `ok: true` and anchors via the retry rather than pausing.

Two guards:

- PC-7 **EXCLUDES the HTLC-9** dest-revealed / source-claim-failed asymmetric state. That state is half-settled: it routes to `settle-asymmetric` (ST-8) and is surfaced as §9.5.4 asymmetric-settlement evidence, never as PC-7 `ok: true`.
- Any retry of a cross-chain payment phase MUST first check foreign-chain settlement state — the HTLC lock/reveal/claim txRefs, or the tank `bridge_id` status — before re-submitting, to avoid double-settlement.

```
type PaymentPhaseInput = {
  jobId: string
  agreement: AgreementDocument         // pinned at commit-agreement
  rail: RailDefinition                 // pinned at session start
  payer: {
    bundleHash: string
    primaryClaim: ClaimReference
    payingKey: ClaimReference          // MUST appear in payer's bundle.claims
  }
  payee: {
    bundleHash: string
    primaryClaim: ClaimReference
    payeeAddress: string               // rail-specific destination
  }
  amount: PriceTerm                    // from agreement.terms.price; rail-validated
  sessionContext: SessionContext
}
```

#### 9.5.2 pay-evm-erc20

Single-chain ERC-20 token transfer.

**Procedure.**

1. Resolve rail; verify `asset.kind == "erc20"` and `network.kind == "evm"`.
2. Verify `amount.currency` matches `rail.asset.symbol`.
3. Compute on-chain `amount = amount.amount × 10^rail.asset.decimals` (string-decimal multiplication, no float).
4. Construct an ERC-20 transfer transaction: `contract.transfer(payee.payeeAddress, amount)`.
5. Submit via the payer’s wallet (or via SR-3 proxy attestation when the payer’s wallet runs server-side).
6. Wait for chain finality per `rail.parameters.finalityBlocks` (default 1 for L2s, 12 for Ethereum mainnet).
7. Construct SettlementEvidence with `txRef` of kind `evm`; anchor via SR-2; return success.

**Failure modes.**

- payer balance insufficient → `permanent`
- transfer reverts (contract restrictions, paused token) → `permanent`
- chain unavailable → `transient`
- payer-side wallet rejects → `counterparty`

#### 9.5.3 pay-solana-spl

SPL token transfer on Solana.

**Procedure.**

1. Resolve rail; verify `asset.kind == "spl"`.
2. Construct an SPL Transfer instruction, or TransferChecked for decimal safety; the payee’s token account is the destination (must exist or be created).
3. Submit via the payer’s wallet.
4. Wait for confirmation per `rail.parameters.commitmentLevel` (default `"confirmed"`).
5. Construct SettlementEvidence with `txRef` of kind `solana`; anchor via SR-2; return success.

**Failure modes.**

- insufficient balance → `permanent`
- token account does not exist and create-if-missing not allowed → `counterparty` (payee setup issue)
- cluster congestion / timeout → `transient`

#### 9.5.4 pay-cross-chain-htlc

Atomic cross-chain settlement using HTLC contracts on source and destination chains.

**Procedure.**

*Setup:* resolve the rail (`asset.kind == "stablecoin-cross-chain"`, `network.kind == "cross-chain"`, mechanism `"htlc"`); select the route matching `(sourceChainId, destChainId)`; derive the preimage (HTLC-5) and per-chain hashlocks (HTLC-6):

    preimage        = HKDF(IKM=buyerSalt, salt=jobId, info=agreementHash)   (RFC 5869, sha256)
    hashlock_source = H_source(preimage)
    hashlock_dest   = H_dest(preimage)

*Swap order:*

1. the **payer** (preimage holder) locks the **source** — `source.lock(payeeAddr, amount, hashlock_source, timelock_source)`, refund → payer;
2. after source-lock finality (HTLC-8) the **payee** locks the **destination** — `dest.lock(payerAddr, amount, hashlock_dest, timelock_dest)`, refund → payee, with `timelock_source > timelock_dest` (HTLC-7);
3. the **payer claims the destination** (`dest.claim(preimage)`), which pays the payer and reveals the preimage. The payer SHOULD have enough margin to reach destination finality before `expiry_dest`; otherwise it SHOULD decline to reveal and let both legs refund (HTLC-10);
4. the **payee claims the source** against the now-public preimage.

*txRefs:*

| txRef | What it is |
| --- | --- |
| `htlc-lock` | source lock |
| `htlc-reveal` | payer's destination claim (reveals the preimage) |
| `htlc-claim` | payee's source claim — the decisive success tx |

- `outcome: "success"` is set ONLY once the payee's source claim reaches **source-chain finality**, not mere inclusion. Before that, the state is the HTLC-9 asymmetric `dest-revealed-source-unclaimed` failure.
- Construct SettlementEvidence and anchor via SR-2. If SR-2 is unavailable once the source claim is final, return `ok: true` with the foreign-chain txRefs plus a durable idempotent anchor-retry (PC-7; never `errorClass: "substrate"`).

> **Note (non-normative).** This is the canonical atomic-swap order: the secret-holding payer claims the shorter-timelock destination first, so the payee keeps a guaranteed window on the longer-timelock source (HTLC-7). The payer never *claims* the source — it is the payee's to claim, and the payer recovers its source position only via refund if the swap does not complete.

**buyerSalt entropy & lifecycle (normative).**

- (HTLC-1) buyerSalt MUST be generated from a cryptographically-secure random source with ≥128 bits of entropy.
- (HTLC-2) buyerSalt MUST NOT be disclosed to any party but the payer while either leg is live (until both legs are claimed or refunded). It is never revealed on-chain — the destination claim reveals the *preimage*, not the salt.
- (HTLC-3) buyerSalt MUST NOT be reused across sessions; each jobId uses a freshly-generated salt.
- (HTLC-4) The payer MUST retain buyerSalt until the destination-side claim reaches finality (loss makes the preimage unrecoverable — a fund-safety requirement, not merely operational).
- (HTLC-5) **Preimage derivation** MUST use HKDF (RFC 5869, sha256): IKM=buyerSalt, salt=jobId, info=agreementHash. Weaker derivations MUST NOT be used. jobId MUST be globally unique per swap and agreementHash MUST be collision-resistant; both hold in DACS, where jobId is per-session and agreementHash is the sha256 of the canonical agreement.
- (HTLC-6) **Hashlock** is the chain-native hash of the preimage. Source and destination chains MAY use different hash functions (keccak256 EVM, sha256 Solana/BTC, blake2b Cosmos) and MUST NOT be required to share one. The preimage is the only cross-chain-shared value; the preimage revealed on the destination is bit-identical to the one producing `hashlock_source`.
- (HTLC-7) **Timelock asymmetry.** Implementations MUST reject a route unless `expiry_source > expiry_dest + source_finality + safety`, evaluated on absolute expiry instants. The margin is sized to **source** finality, not destination latency: the binding constraint is the payee *finalising* its source claim after the reveal. `source_finality` and `safety` are the pinned rail parameters `rail.parameters.sourceFinalitySec` and `rail.parameters.safetyWindowSec`; both are REQUIRED, and `safetyWindowSec` defaults to 600s. The inequality MUST be evaluated against the pinned values, not runtime-estimated latency.
- (HTLC-8) **Timelock epoch.** Timelocks are durations measured from when each lock is mined. The destination lock MUST NOT be mined before source-lock finality; implementations MUST reject any schedule that could. With this anchoring, the HTLC-7 duration inequality implies the absolute-expiry inequality.
- (HTLC-10) **Free-option disclosure.** The asymmetry guarantees liveness but not freedom from the inherent HTLC free option. The payer MAY decline to reveal after observing market movement, at zero cost, while the payee's destination capital stays locked to the destination timelock. v0.1 does NOT standardise an anti-option mechanism. Listings sensitive to option abuse SHOULD prefer pay-cross-chain-liquidity-tank or require a payer stake.

> **Note (non-normative).**
> - HTLC-2 — disclosing the salt mid-swap lets an adversary recompute the preimage and claim whichever leg pays the submitter (the HTLC-7 race); there is no safe mid-swap disclosure point.
> - HTLC-5 — the derivation is deterministic, so a disputing party can re-derive and prove the preimage from buyerSalt (serving the DACS-X correction path). A repeated (salt, jobId, agreementHash) tuple would reproduce a preimage and let an observer of the first reveal claim the second swap.
> - HTLC-7 — a slow-source/fast-destination route is the failure case. "≥2× source-chain P99 latency" is how a rail author SHOULD *size* `sourceFinalitySec`, not a runtime input.
> - HTLC-10 — the free option is inherent to HTLC atomic swaps; a payee MAY record payer-abandoned-leg patterns via DACS-5.

> **Note (non-normative) — reference-implementation status.** The reference (agent-commerce-demo, ~929 LOC) runs HTLC for fx-rfq cross-chain settlement (a real Solana Anchor program + Base Sepolia EVM HTLC contract; lock/reveal/refund end-to-end) and will migrate to pay-cross-chain-liquidity-tank as Native Bridges Phase 1 stabilises. Two app-layer conformance items remain, with no on-chain contract or SDK change: (i) **reveal order** — it has the seller claim the source first rather than the canonical payer-claims-destination-first order, which removes a payer-loss risk if the payer goes offline after handover; (ii) **preimage generation** uses a plain CSPRNG rather than the HTLC-5 HKDF derivation.

**Failure modes.**

- source lock fails → `permanent` (no funds at risk)
- destination lock never placed → payer refunds the source after `timelock_source`; no value moved
- destination timeout (payer never claims, preimage never revealed) → both legs refund; `settlement-atomicity`, benign
- preimage revealed but payee's source claim not landed → `settlement-atomicity`, **non-refundable asymmetric state** (refunding the source would double-dip at the payee's expense; the source MUST NOT be refunded — see HTLC-9)

**Asymmetric-settlement evidence (normative). (HTLC-9)** The "preimage revealed but the payee's source-side claim has not landed" branch differs materially from a destination-timeout. Here the **payer** has already received value on the destination — its claim succeeded and the preimage is public — while the **payee's** source claim has not landed. Refunding the source would return funds to the already-paid payer, double-dipping at the payee's expense. **This state MUST NOT be modelled as a `refund` / `partial-refund` amendment.**

*Entering the state.* The asymmetric state MUST NOT be entered until the `htlc-reveal` reaches **destination-chain finality**. Before that, the case is the refund-eligible benign-timeout branch, and entering early would wrongly block a legitimate source refund.

*Representing it* (machine-distinguishable from a benign timeout):

- (a) the SettlementEvidence MUST set `outcome: "failure"` with a structured `reason` marker (RECOMMENDED `dest-revealed-source-unclaimed`);
- (b) `paymentTxRefs` MUST include the `htlc-reveal` txRef proving the preimage was revealed on the destination chain.

*Resolution.* The open state is the non-terminal `settle-asymmetric` session state (§10.3.1, ST-8), not a terminal failure. The orchestrator watches for the payee's source claim until `expiry_source` (HTLC-7/HTLC-8):

- **Resolved** — `htlc-claim` reaches **source-chain finality** within that window. Mere inclusion is not enough: a not-yet-final claim that later reorgs MUST NOT be read as success. The phase returns `ok: true` and anchors a superseding `outcome: "success"` record carrying `settlementFinality`, `paymentAmount` (§9.7), the full `htlc-lock` + `htlc-reveal` + `htlc-claim` set, and `supersedesEvidenceRef` → the interim failure record. The orchestrator then resumes remaining settle-stage phases (PIPE-3/PIPE-4) to `settle-completed` → terminal `completed`.
- **Expired** — `expiry_source` passes with no final source claim. The interim failure record stands and the session goes terminal `settle-failed` → `failed-counterparty`: the genuine unresolved loss, which DACS-X dispute may later address.

No `correction` amendment is used — the ST-8 forward resolution produces a normal `completed` bundle DACS-5 reads directly. DACS-5 weights a window-expired asymmetric loss strictly worse than a clean destination-timeout refund.

#### 9.5.5 pay-cross-chain-liquidity-tank

Substrate-coordinated atomic settlement using pre-funded liquidity primitives. On Demos: Liquidity Tanks.

**Procedure.**

1. Resolve rail; verify `asset.kind == "stablecoin-cross-chain"` and `network.kind == "cross-chain"` with `mechanism: "liquidity-tank"`.
2. Select `liquidityTankIds` matching `(sourceChainId, destChainId)`; validate the route is in v0.1 supported scope (today: ETH Sepolia → Polygon Amoy, USDC, unidirectional).
3. Call the substrate’s native bridge API — on Demos, construct a BridgeOperation conforming to `kynesyslabs/sdks/src/bridge/nativeBridgeTypes.ts` (originChainType, destinationChainType, originAddress, destinationAddress, originAmount, originAsset, destinationAsset); submit via `demos.bridge.submitBridgeOperation(…)`.
4. The substrate’s validator shard executes lock-on-source and release-on-dest atomically, within the substrate’s consensus epoch. Record the `bridge_id` — the 16-char hash that is the canonical end-to-end tracking handle.
5. Wait for `BridgeOperation.status` to transition `"empty"` → `"pending"` → `"completed"`.
6. Construct SettlementEvidence with `txRef` of kind `liquidity-tank` including bridgeId + both lock and release tx hashes; anchor via SR-2; return success. If the bridge has reached `completed` but SR-2 is unavailable, return `ok: true` with the bridge txRefs plus a durable idempotent anchor-retry, per PC-7 — never `errorClass: "substrate"`.

**Trust model.** Recipes referencing this rail MUST be evaluated against the relevant substrate’s security profile. On Demos, Liquidity Tanks are operated by a rotating Demos validator shard under 2/3 BFT multisig with a 15-day deployer emergency-recovery path. This is "the operator is the substrate itself", not "no operator". Other substrates implementing SR-5 via different mechanisms inherit their own substrate trust model.

> **Note (non-normative).** The tank contracts (LiquidityTank.sol, 600+ lines, audited) are deployed to ETH Sepolia (`0x7AE3A8B899BE0D9E9de51b81a9912C0CEE128d88`) and Polygon Amoy (`0x57cA16EeE7fbeC69BFD46E4806B5d91e173dd600`).

**Failure modes.**

- tank insufficiency on dest → `transient` (retry after re-balancing)
- source-lock succeeds but substrate epoch interruption prevents dest-release → **`substrate`**. The dest-release is blocked by a substrate condition, not a counterparty fault; substrate-native recovery applies per the SR-5 implementation (on Demos, the 15-day emergency recovery is the backstop). It resolves via ST-7 pause/resume, mapping to reputation-neutral `failed-substrate` on pause-timeout — NEVER `failed-counterparty`, since neither party is at fault for a substrate-recoverable lock.
- `BridgeOperation.status == "failed"` → `permanent` (deterministic rejection by tank shard)

**No mechanism substitution (normative).** The pinned rail's mechanism is binding:

- On tank insufficiency or capacity exhaustion, the orchestrator MUST retry the pinned tank rail (transient) or fail the phase. It MUST NOT silently fall through to a different mechanism (e.g. `pay-cross-chain-htlc`).
- The produced `txRef.kind` MUST match the pinned rail (§9.14). A phase whose executed mechanism differs from the pinned rail MUST fail with errorClass: permanent.
- An implementation wanting HTLC fallback MUST express it as a distinct pinned rail / phase, not an implicit fallthrough.

> **Note (non-normative).** Silent substitution would violate the §9.13 pinned-rail rule and break the one-to-one phase↔txRef-kind correspondence.

**Evidence scope (v0.1).** Tank SettlementEvidence is **success-only**: both `lockTxHash` and `releaseTxHash` are present when the bridge reaches `completed`. A locked-but-not-yet-released state inside the recovery window is surfaced via the settlement-atomicity failure mode above and resolved by the substrate's native recovery path. v0.1 does **not** define a distinct *recovery-pending* evidence marker or state to machine-distinguish a recoverable lock from a terminal loss.

> **Note (non-normative).** A recovery-pending marker — a `recoveryDeadline` field and/or a settle-recovery-pending state, analogous to HTLC-9's open-state handling — is a roadmap item.

#### 9.5.6 pay-ap2

Payment via an AP2 mandate to a card network or banking provider.

**Procedure.**

1. Resolve rail; verify `asset.kind == "fiat-via-ap2"`.
2. Construct an AP2 PaymentMandate conforming to the FIDO Alliance AP2 spec (April 2026 onwards).
3. The payer’s AP2-compatible wallet authorises the mandate.
4. Submit the mandate to `rail.network.providerEndpoint`; receive a payment receipt and provider-side reference (e.g. Visa Direct payment id, Stripe PaymentIntent id).
5. Construct SettlementEvidence with `txRef` of kind `ap2` carrying mandateId, providerRef, and the AP2 `protocolVersion` — the wire version that produced the mandate/receipt, so historical evidence is re-validatable against the rules of its era (#27). Anchor via SR-2; return success.

**Failure modes.**

- payer’s mandate authorisation refused → `counterparty`
- provider declines the underlying payment (insufficient funds, fraud check, regulatory hold) → `permanent`
- provider endpoint unavailable → `transient`
- mandate revoked between authorisation and submission → `counterparty`

#### 9.5.7 pay-x402

Payment via x402 HTTP 402 micropayment to an HTTP resource.

**Procedure.**

1. Resolve rail; verify `network.kind == "x402-resource"`.
2. Construct an x402 payment payload (signed authorisation per x402 spec); the authorisation MUST include the session `jobId` (SB-3, §9.5.8) so the verifier can bind the settlement to this session. Submit the GET request to the resource with x402 headers.
3. Receive the resource response and an x402 receipt; read the on-chain settlement transaction hash from the x402 `PAYMENT-RESPONSE` header (x402 settles a gasless USDC transfer on its settlement chain, e.g. Base).
4. Construct SettlementEvidence with `txRef` of kind `x402` carrying httpResource, paymentReceiptHash (sha256 of the receipt), and the x402 `protocolVersion` (#27). The handler MUST populate `settlementTxHash` + `chainId` whenever the facilitator returns them — the normal case. A record carrying `settlementTxHash`/`chainId` is **chain-verifiable directly against the settlement chain, exactly like the `evm` rail**: the primary audit path, with the receipt hash supplementary.
5. Anchor via SR-2; return success.

> **Note (non-normative) — what pay-x402 adds beyond bare x402.** A direct x402 transaction produces a receipt the client and server hold off-chain; there is no anchored audit trail and the transaction is not bound to a DACS session. pay-x402 binds the x402 transaction into a DACS session by:
>
> - (a) producing a SettlementEvidence record carrying the on-chain `settlementTxHash` (chain-verifiable against the settlement chain, like the `evm` rail) plus the x402 receipt hash, anchored via SR-2 — the receipt itself remains off-chain, but its hash, the settlement tx, and the protocol version become part of the on-chain bundle;
> - (b) tying the x402 transaction to a specific DACS-3 AgreementDocument via the session’s jobId;
> - (c) making the x402 transaction available to DACS-5 reputation derivation and ERC-8004 publication.
>
> For pure HTTP-402 use cases that do not need a session bundle, bare x402 is appropriate; pay-x402 is the right wrapper when the x402 transaction participates in a multi-stage agent commerce lifecycle.

**Failure modes.**

- server-side x402 endpoint rejects (insufficient payment, unsupported scheme) → `counterparty`
- HTTP error after payment submitted → `transient` (retry with idempotency key)
- payment-receipt signature invalid → `permanent`

#### 9.5.8 Session-bound settlement evidence (SB-1..SB-3)

A cross-chain HTLC settlement is bound to its session by the jobId-derived preimage (HTLC-5), but the single-chain / provider rails (`pay-evm-erc20`, `pay-solana-spl`, `pay-ap2`, `pay-x402`) carry a `ChainTxRef` with no session binding — so a record could cite an unrelated transfer of the agreed amount to the payee (*coincidental-citation*), or reuse one settlement across sessions (*cross-session double-count*).

- **(SB-1) Binding key.** A `SettlementEvidence` record's `paymentTxRefs` are a claim that the referenced transaction(s) settled **this** `(jobId, phaseIndex)`, where `phaseIndex` is the phase's `BundlePhaseEntry.index` — required because a repeated phase type (PIPE-5) settles the same `phase` more than once. `phaseIndex` is **not a new evidence field**: it is recovered from the §9.5.2 payment-evidence anchor address the record is published at (`dacs4:payment:{jobId}:{railId}:{phaseIndex}`), so two consumers key a settlement identically. A consumer MUST key a settlement on the tuple `(settlement-tx-id, jobId, phaseIndex)`. `settlement-tx-id` is the rail's canonical **event/instruction-level** reference (not the envelope transaction), pinned as the exact string:
  - **evm / x402:** `evm:{chainId}:{txHash}:{logIndex}`
  - **solana:** `solana:{cluster}:{signature}:{instructionIndex}`

  The key is the uniqueness defence, so it MUST be byte-identical across implementations. Canonicalisation: `chainId`, `logIndex`, and `instructionIndex` are decimal integers with no leading zeros; `txHash` is **lower-case hex with no `0x` prefix** (a `0x`-prefixed or upper-case re-spelling MUST collapse to the same key); `signature` is base58 that MUST decode to exactly 64 bytes. A reference that fails canonicalisation — wrong-length/odd hex, a signature that is not 64-byte base58, or missing `chainId`/`logIndex` — is malformed and MUST yield `error`; it MUST NOT be normalised into, or mint, a distinct key. Event/instruction-level identity is required for batched transfers and for ERC-4337, where the settling `Transfer(from=payerAccount,…)` is one event among several in a bundler transaction.
- **(SB-2) Cross-session uniqueness.** A consumer that aggregates settlement evidence across sessions — including the DACS-5 reputation reconciliation (§10.5.1) — MUST NOT count one `settlement-tx-id` under more than one `(jobId, phaseIndex)`. A second binding of the same id is rejected for the later record (earlier `observedAt` wins; ties broken by lower evidence hash). The check is scoped to the consumer's own evidence set; a global cross-network uniqueness index is out of scope. This closes the double-count threat on every rail with no on-chain change.
- **(SB-3) On-chain session binding (optional, per rail).** A rail MAY bind `jobId` into its on-chain settlement, closing coincidental-citation as well. v0.2 defines one for `pay-x402`, where the binding surface differs by authorization type:
  - **Permit2** — the handler MUST place `jobId` in the signed `witness` field; the verifier MUST check it equals `evidence.jobId`.
  - **EIP-3009** (`transferWithAuthorization`) — there is no arbitrary signed field, so the handler MUST derive the authorization `nonce` as `nonce = H(jobId ‖ phaseIndex ‖ …)` and the verifier MUST recompute and match it.

  Either way the binding rides inside the payer-signed authorization (no new contract). For a smart-account (ERC-4337) payer the signature is an ERC-1271 contract signature (`isValidSignature`) rather than an EOA signature; a verifier MUST accept either, selecting by whether the payer address has on-chain code as of the settlement transaction's block.

  When a rail declares a binding, the verifier resolves it in three branches:
  - **present and matches** → the binding guarantee is satisfied;
  - **present and mismatches** → reject the evidence;
  - **absent or unverifiable** (the binding is missing, or the on-chain check cannot complete — RPC unavailable, pruned history, unresolvable `isValidSignature`) → the binding guarantee is **not established** for that record: fall back to the SB-1 + SB-2 + §9.5.1 amount/payee posture of an unbound rail. This is **never** an automatic accept and **never** a hard fail — mirroring the §7.5.1 unresolvable-signer → `indeterminate` rule and the ST-8 `settle-asymmetric` discipline, so a transient verification outage does not become a reputation event.

  Log-forwarder (evm) and Memo (solana) bindings are anticipated per-rail follow-ons. A rail with no declared binding relies on SB-1 + SB-2 with the §9.5.1 amount/payee match, and is weaker against coincidental-citation; a verifier SHOULD prefer a bound rail for high-value settlements.

> **Note (non-normative).** SB-2 is structurally the §B.8 SN-4 single-use marker with the scope inverted — a settlement-tx-id is single-use per session as a session nonce is.

### 9.6 Delivery phases

The v0.1 closed set. Each consumes the agreement’s DeliverableRef and produces SettlementEvidence.

#### 9.6.1 deliver-storage-program

Seller writes a Storage Program (SR-2) containing the deliverable payload. Address derived from jobId.

**Procedure.**

1. Validate `agreement.terms.deliverable.deliverableType == "storage-program"`.
2. Seller constructs the deliverable payload conforming to `deliverable.schemaUrl` (if specified).
3. Write a Storage Program at address `dacs4:deliverable:{jobId}` with the payload as value.
4. Compute `contentHash = sha256(canonical_payload)`.
5. Construct SettlementEvidence with `deliverableContentHash = contentHash`, `deliverableAnchor = {kind: "storage-program", locator: …}`; anchor via SR-2; return success.

**Soft limit.** Storage Programs have a 128 KB cap. Larger payloads MUST use the extended-pointer pattern: the Storage Program at the canonical address contains a pointer record { externalUrl, externalContentHash, segmentRefs[]? }; the actual payload is hosted externally; the externalContentHash binds it. The buyer fetches the pointer, then fetches the payload, then verifies the hash.

#### 9.6.2 deliver-entitlement

Seller issues an EntitlementRecord granting the buyer time-bound access to a service.

**Procedure.**

1. Validate `agreement.terms.deliverable.deliverableType == "entitlement"`.
2. Resolve the entitlement parameters (`durationSec`, `renewable`) from the **DeliverableSpec** — the listing's `offering.deliverable`, bound to the agreement by the §8.5.2 hash check. They MUST NOT be resolved from `agreement.terms.deliverable`: that is a `DeliverableRef` carrying only `deliverableType` / `hash` / `schemaUrl?` and none of these fields.
3. Seller constructs the EntitlementRecord:

```
type EntitlementRecord = {

  entitlementVersion: "1"

  jobId: string

  grantee: ClaimReference              // buyer primary claim

  grantor: ClaimReference               // seller primary claim

  startsAt: number                     // unix ms

  endsAt: number                       // unix ms; computed from the entitlement DeliverableSpec's durationSec (listing offering.deliverable, hash-bound per §8.5.2)

  scope: { service: string; tier?: string; quotas?: Record<string, number> }

  serviceEndpoint?: string             // URL where the grantee exercises the entitlement; SHOULD be present for callable services so the record is a self-contained receipt

  renewable: boolean

  renewalSeq: number                   // 0 for the original grant; incremented per renewal (address discriminator)

  signature: ComponentSignature

}
```

4. Seller signs the EntitlementRecord over the domain-separated payload "dacs-entitlement:v1:" || sha256(canonical_JCS(record_without_signature)) per §B.7.
5. Seller anchors the EntitlementRecord via SR-2 at dacs4:entitlement:{jobId}:{renewalSeq}, with renewalSeq = 0 for the original grant.
6. Seller constructs SettlementEvidence; returns success.

**Exercising the entitlement.** Buyer presents the EntitlementRecord (or its hash + anchor) at the record's `serviceEndpoint` to access the entitled service. The record is a self-contained receipt — it names the grantee, the scope, the validity window, and where to exercise it — so the buyer needs nothing beyond the record itself. The service endpoint verifies the signature and anchor, checks now is within [startsAt, endsAt], and serves accordingly.

> **Note (non-normative).** `serviceEndpoint` carries *where* to access. How an access **credential / token** is delivered (vs. presenting the record itself as the bearer proof) is an out-of-band auth concern not specified in v0.1 — see roadmap.

**Renewal.** If renewable: true and the buyer re-pays before endsAt, the seller MAY issue a new EntitlementRecord with extended endsAt, the same jobId, and an **incremented renewalSeq**, anchored at dacs4:entitlement:{jobId}:{renewalSeq}. The renewalSeq discriminator gives each renewal a distinct SR-2 address so it does not collide with or overwrite the original grant (the address is otherwise fully determined by jobId on immutable content-addressed storage). A consumer resolves the current grant by reading the highest renewalSeq present for the jobId.

#### 9.6.3 deliver-attested-payload

Seller delivers a payload whose authenticity is attested via DACS-2 (e.g., the payload is a TLS-attested data fetch).

**Procedure.**

1. Validate `agreement.terms.deliverable.deliverableType == "attested-payload"`.
2. Seller performs the underlying fetch / computation.
3. Produce a DACS-2 attestation over the result (using the recipe in the attested-payload DeliverableSpec's `verificationMethod`, resolved from the listing's `offering.deliverable` per §8.5.2 — not from the `DeliverableRef` in `agreement.terms.deliverable`).
4. Write the payload + attestation reference into a Storage Program at `dacs4:deliverable:{jobId}`.
5. Construct SettlementEvidence carrying `deliverableContentHash`, `deliverableAnchor`, and `attestationRef` pointing at the DACS-2 attestation; anchor via SR-2; return success.

### 9.7 Settlement evidence

The uniform record produced by every payment and delivery phase. Anchored on the substrate; referenced by DACS-5.

```
type SettlementEvidence = {

  evidenceVersion: "1"

  jobId: string

  phase: PaymentPhaseType | DeliveryPhaseType

  outcome: "success" | "failure"

  reason?: string                              // when outcome == "failure"

  // Payment evidence

  paymentTxRefs?: ChainTxRef[]

  paymentAmount?: PriceTerm                    // actual settled amount; REQUIRED on any success-outcome evidence record (AMEND-3 is evaluated against it); MAY be absent only on failure-outcome records

  paymentFee?: PriceTerm                       // chain or provider fee

  // Delivery evidence

  deliverableContentHash?: string

  deliverableAnchor?: { kind: string; locator: string }

  attestationRef?: AttestationRef              // for deliver-attested-payload

  // Finality model for this settlement: REQUIRED on a success-outcome payment evidence record (PC-6); absent on delivery evidence and on failure-outcome payment evidence

  settlementFinality?: SettlementFinalityRecord

  // Optional cross-references

  amendmentRefs?: AttestationRef[]             // refunds / partial refunds linked here (see §9.7.1 AMEND-*)

  supersedesEvidenceRef?: AttestationRef       // present on an ST-8 `:resolved` success record; points to the interim dest-revealed-source-unclaimed failure record it supersedes (a same-phase supersession, NOT a refund amendment — distinct from amendsEvidenceRef)

  observedAt: number                           // unix ms

  signature: ComponentSignature                // signer is the phase orchestrator

}

// Records the finality model applied when the phase handler declared the payment confirmed.
// Populated by payment phases only (pay-evm-erc20, pay-solana-spl, pay-cross-chain-htlc,
// pay-cross-chain-liquidity-tank, pay-ap2, pay-x402); delivery phases MUST omit it.
type SettlementFinalityRecord = {

  model: "block-depth"          // EVM / UTXO: wait for N blocks (finalityBlocks from rail.parameters)
       | "commitment-level"     // Solana: wait for a named commitment (commitmentLevel from rail.parameters)
       | "provider-receipt"     // Fiat (AP2); also x402 ONLY in the fallback case where the facilitator returns no settlement tx — normally x402 uses "block-depth" on its settlement chain (the settlementTxHash, #28)
       | "htlc-reveal"          // Cross-chain HTLC: the payee's source-side claim (htlc-claim) landed against the revealed preimage — the decisive success tx; the payer's destination claim revealed the preimage earlier. (Model token retained as "htlc-reveal" for back-compat.)
       | "liquidity-tank"       // Native bridge liquidity-tank: bridge status transitions to "completed"

  // For model == "block-depth": the number of blocks waited before declaring confirmation.
  // Sourced from rail.parameters.finalityBlocks; echoed here so the evidence record is self-describing.
  finalityBlocks?: number

  // For model == "commitment-level": the Solana commitment level accepted.
  // Sourced from rail.parameters.commitmentLevel; echoed here so the evidence record is self-describing.
  finalityCommitmentLevel?: "processed" | "confirmed" | "finalized"

  // Wall-clock unix ms at which the finality condition was observed to be met.
  // For block-depth: block timestamp of the Nth confirmation block.
  // For commitment-level: timestamp at which the commitment level was reached.
  // For provider-receipt / htlc-reveal / liquidity-tank: timestamp of the decisive event
  // (for htlc-reveal: the payee's source-side htlc-claim confirmation — the same event that flips outcome to success).
  finalityObservedAt: number

}

type PaymentPhaseType = "pay-evm-erc20" | "pay-solana-spl"

                      | "pay-cross-chain-htlc" | "pay-cross-chain-liquidity-tank"

                      | "pay-ap2" | "pay-x402"

type DeliveryPhaseType = "deliver-storage-program" | "deliver-entitlement" | "deliver-attested-payload"

type ComponentSignature = {

  algorithm: "ed25519" | "ecdsa-secp256k1" | "sr1-aggregate"

  signer: ClaimReference                       // primary claim of the signing party; per-artifact role is given in each record's inline comment (e.g. phase orchestrator, refunding party, grantor)

  value: string                                // signature over the domain-separated payload defined for the artifact (§B.7)

}
```

Every anchored record that carries a `signature: ComponentSignature` field MUST populate it with this shape:

- `signer` MUST be a ClaimReference whose role is fixed by the artifact's inline comment;
- `value` MUST be the signature over that artifact's domain-separated payload as defined in its section.

Per the §B.2 canonical-form template, omitting the `signature` field. `supersedesEvidenceRef`, when present, is part of the hashed canonical form (only `signature` is omitted), so an ST-8 `:resolved` record's hash binds the interim record it supersedes. The signature is computed over:
signed_bytes := "dacs-evidence:v1:" || evidence_hash

#### 9.7.1 Refunds and partial refunds

Refunds are not a separate phase type in v0.1. A refund is modelled as a SettlementAmendment record anchored after the original SettlementEvidence:

```
type SettlementAmendment = {
  amendmentVersion: "1"
  jobId: string
  amendsEvidenceRef: AttestationRef    // points to the SettlementEvidence being amended
  amendmentType: "refund" | "partial-refund" | "correction"
  refundAmount?: PriceTerm
  refundTxRefs?: ChainTxRef[]
  reason: string
  observedAt: number
  signature: ComponentSignature        // signed by the refunding party (typically seller)
}
```

SettlementAmendment is anchored via SR-2 at dacs4:amendment:{jobId}:{evidenceHash}:{amendmentIndex}. The amendment signature is computed over the domain-separated payload "dacs-amendment:v1:" || sha256(canonical_JCS(amendment_without_signature)) per §B.7. The DACS-5 session record includes amendments in the bundle if they arrive before bundle finalisation.

**Amendment validity.** There are three amendment types: **refund** / **partial-refund** (financial — carry `refundAmount`) and **correction** (non-financial — carries no `refundAmount`). An amendment is valid only if it satisfies the constraints below; a refund must bind to a **real, successful** settlement.

> **Note (non-normative).** Without these constraints a refund could anchor against a non-existent or failure-outcome record, or over-refund, feeding DACS-5 reputation records it cannot trust.

- (AMEND-1) `amendsEvidenceRef` MUST resolve to an anchored SettlementEvidence whose `jobId` equals the amendment’s `jobId`.
- (AMEND-2) a `refund` or `partial-refund` MUST reference an evidence record whose `outcome == "success"`. A settlement-atomicity failure (no funds moved) is unwound on the rail’s refund path (e.g. the HTLC timelock-refund per §9.5.4), NEVER via a refund amendment. A `correction` MUST NOT carry `refundAmount`.
- (AMEND-3) the sum of `refundAmount` across all amendments referencing a single evidence record MUST NOT exceed that record’s `paymentAmount`, compared currency-matched per the PriceTerm. v0.1 REQUIRES refunds in the settled currency. A `refundAmount.currency` differing from the amended evidence's `paymentAmount.currency` makes the AMEND-3 bound non-evaluable and MUST be flagged per AMEND-4; cross-currency refunds are out of scope for v0.1 — a roadmap candidate.
- (AMEND-4) bundle assembly MUST reject — or, where a complete audit trail is preferred, flag — any amendment violating AMEND-1..AMEND-3 rather than silently including it. A flagged amendment MUST NOT be treated as a valid unwind by DACS-5 reputation derivation.

*Not an amendment: ST-8 supersession.* The ST-8 cross-chain asymmetric resolution does NOT use an amendment at all. It is a same-phase supersession recorded via the success record's `supersedesEvidenceRef` (§10.3.1 ST-8); `supersedesEvidenceRef` is not an `amendsEvidenceRef` and is not subject to AMEND-1..4. A post-resolution refund MUST reference the `:resolved` success record — whose `outcome == "success"` — not the superseded interim `failure` record, which is AMEND-2-ineligible.

### 9.8 Cross-chain atomic settlement (SR-5)

Atomic settlement across chains requires SR-5: either substrate-native cross-chain transactions, HTLC contracts on participating chains, or pre-funded liquidity primitives (Liquidity Tanks on Demos).

**Atomicity guarantee.** SR-5 implementations MUST ensure payment on chain A and value-receipt on chain B succeed together, or both refund / never-take-effect within a bounded time — per mechanism:

- **HTLC** — the timelock;
- **Liquidity Tank** — the substrate consensus epoch (Demos seconds, 15-day emergency backstop);
- **substrate-native** — atomically within the tx.

The one branch **outside the refund arm** is the HTLC-9 reveal-succeeded / source-claim-pending state (§9.5.4). SR-5 implementations MUST surface it as asymmetric-settlement evidence, not a refund, and resolve it via the non-terminal `settle-asymmetric`/ST-8: `htlc-claim` at source finality within `expiry_source` → `completed`; window expiry → terminal `failed-counterparty`. This is the bounded exception to the refund arm, not a hole in atomicity.

**Cross-chain messaging vs settlement.** Messaging protocols (Wormhole, LayerZero, Hyperlane, CCIP, Axelar, IBC) carry payloads between chains; SR-5 is *settlement*-atomicity (value on A and receipt on B happen together or not at all). A messaging protocol MAY be composed inside an SR-5 implementation but is not itself SR-5 — “message delivered” ≠ “value settled” — so DACS-4 does not register messaging protocols as first-class rails. A substrate whose SR-5 depends on a specific messaging protocol MUST disclose this in the rail definition; the trust model then inherits both.

**Choosing a rail.**

| | HTLC | Liquidity Tank |
| --- | --- | --- |
| **Cost** | gas on two chains | typically gas only on dest (source-side lock is operator-paid in tank schemes that subsidise gas, incl. Demos’s current model) |
| **Latency** | source finality + dest finality + claim round-trip (minutes typically) | substrate epoch (seconds on Demos) |
| **Trust** | cryptographic / chain consensus only | substrate operator |

Listings selecting cross-chain rails SHOULD declare the trust expectations in `terms.additionalTerms`.

### 9.9 Pipeline composition

A listing’s pipeline declares the order of payment and delivery phases. Common patterns:

- **Pay-then-deliver** (default for trusted seller; AP2 mandate, x402 micropayment): [pay-*, deliver-*].
- **Deliver-then-pay** (for cheap delivery / expensive verification; e.g. a free data preview + paid full fetch): [deliver-*, pay-*]. Risk shifts to seller.
- **Escrow with delivery-gate** (lock → deliver → release): the v0.1 `pay-cross-chain-htlc` handler is an **atomic swap** (§9.5.4) — it has no mid-lock suspension point, so it cannot run a `deliver-*` phase *between* lock and reveal. An escrow that gates release on delivery is therefore **not expressible in v0.1** and is reserved for a future job-escrow rail (ERC-8183 is the natural home — see roadmap). v0.1 listings needing escrow-like risk shifting use deliver-then-pay or pay-then-deliver with the counterparty risk that implies.
- **Streamed entitlement / subscription**: a multi-tranche subscription is conceptually a **sequence of independent sessions** — a fresh jobId is a *new session*, not a loop within one pipeline (§B.5/§10.3: one pipeline = one jobId). Continuous-flow / subscription settlement, including any cross-session correlation identifier, is **out of scope for v0.1** (§11.2.4; see roadmap). A v0.1 listing models each tranche as its own session.

**Conformance.**

- (PIPE-1) A pipeline MUST contain at least one deliver-* phase. A pipeline MAY contain **zero** pay-* phases — the **intake-only / settled-out-of-band** pattern that §6.3.4(8) names (RFP intake, reverse auctions where the bid is the commitment, free services gated by reputation, sealed-bid procurements settled out-of-band). If a pipeline contains any pay-* phase, the acceptedRails rule of §6.3.4(8) applies.
- (PIPE-2) Phase ordering MUST be deterministic; the listing’s declared order is normative.
- (PIPE-3) If a pay-* phase is followed by a deliver-* phase, the deliver-* phase MUST NOT execute until the pay-* phase returns ok: true.
- (PIPE-4) If a deliver-* phase is followed by a pay-* phase, the pay-* phase MUST NOT execute until the deliver-* phase returns ok: true.
- (PIPE-5) Pipelines MAY repeat a phase; each invocation produces independent SettlementEvidence. In v0.1 each repeated pay-* invocation settles the **same** agreement price (`PaymentPhaseInput.amount` = `agreement.terms.price`). The payment contract carries no per-phase amount override, fee, or split, so a **fee-split** (distinct amounts to distinct payees, e.g. buyer + platform fee) is NOT representable in v0.1 and is a roadmap item (fee-split / multi-payee settlement model). Repetition is for genuinely identical settlements, not for splitting one price across payees.

> **Note (non-normative).** PIPE-1 is deliberately aligned with §6.3.4(8): a reader of either chapter reaches the same accept decision for a pay-less pipeline.

### 9.10 Conformance summary

| Role | Requirements |
| --- | --- |
| Rail author | RD-1 through RD-5 |
| Orchestrator (rail selection) | RAV-R1 through RAV-R5 |
| Payment phase handler | PC-1 through PC-7; phase-specific procedure |
| Delivery phase handler | §9.6 per-kind procedure; SettlementEvidence emission |
| Pipeline executor | PIPE-1 through PIPE-5 |
| SettlementEvidence consumer | Canonical hash recomputation; signature validation; AMEND-1 through AMEND-4 (amendment chain following) |

### 9.11 Rationale

**Closed rail registry vs open.** Open registries make conformance untestable (a listing could name a rail no orchestrator implements). The closed v0.1 set covers the dominant production paths; new rails ship via the DACS-4 version process under the registry steward.

**Uniform SettlementEvidence vs rail-specific evidence shapes.** Rail-specific shapes would force every downstream consumer (DACS-5, auditors, analytics) to handle N shapes. The uniform shape with a discriminated txRefs union keeps consumption simple while preserving per-rail detail.

**Payment and delivery as separate phases vs combined.** Decoupling lets listings compose risk however the seller deems safe: pay-then-deliver for trusted sellers, deliver-then-pay where risk shifts to the seller. A combined phase would force every listing into one risk model. (Escrow-with-delivery-gate and streamed subscriptions are named in §9.9 as roadmap, not v0.1 patterns.)

**HTLC and Liquidity Tank as parallel first-class rails.** HTLC is the only fully trust-minimised cross-chain primitive shipping today across heterogeneous chains (the reference runs on it). Liquidity Tanks are faster and cheaper but trust the substrate operator. Both have legitimate uses; v0.1 ships both rather than picking a winner.

**AP2 and x402 as rails vs separate stages.** AP2 and x402 are payment protocols; they fit naturally as rails with their own phase handlers. Modelling them as separate stages would duplicate everything DACS-4 already does (evidence, conformance, error classification) for no gain.

**Refunds as amendments vs separate phases.** Refunds happen post-settlement and may arrive long after the original phase has completed. Modelling them as out-of-band amendments anchored after the original evidence lets sessions close normally even when refunds straggle in. The amendment is included in the bundle if present at bundle time.

**Native bridge / Liquidity Tank trust model disclosure.** Honest disclosure of "operated by a rotating Demos validator shard under 2/3 BFT multisig with 15-day emergency recovery" is the right default. Users picking this rail are choosing speed + cost over trust-minimisation, and the recipe makes that trade-off explicit. Substrates with different SR-5 realisations inherit their own trust models and MUST disclose them similarly.

### 9.12 Backwards compatibility

**ERC-20.** pay-evm-erc20 uses the standard ERC-20 transfer interface; any compliant ERC-20 token works. The rail registry pins specific tokens (e.g. USDC) per chain to avoid scam-token substitution.

**SPL.** pay-solana-spl uses the standard SPL TransferChecked instruction; any compliant SPL token works. The rail registry pins specific mints per cluster.

**HTLC contracts.** Generic HTLC pattern; reference HTLC contracts in the DACS reference implementation are deployed on Base Sepolia and Solana devnet. Other deployments are compatible if they implement lock/claim/refund with the same hashlock-and-timelock semantics.

**AP2.** Compatible with AP2 spec as donated to the FIDO Alliance in April 2026 and subsequent FIDO Alliance versions. Per-provider rail entries (ap2:visa-direct, ap2:mastercard-send, ap2:stripe-paymentintents) pin provider-specific parameters.

**x402.** Compatible with x402 spec as published by Coinbase / Cloudflare / Anthropic. The pay-x402 rail handler is provider-agnostic; specific x402 servers may add parameters via the generic parameters field.

**ERC-8183 escrow (future).** ERC-8183 introduces an EVM-native escrow primitive for job-style transactions. A future v0.2 rail (pay-evm-erc8183) will compose ERC-8183 escrow with DACS-4 evidence; v0.1 does not include it.

**Substrate-native bridges (Demos Liquidity Tanks).** pay-cross-chain-liquidity-tank on Demos uses Liquidity Tanks per the SDK shape at kynesyslabs/sdks/src/bridge/nativeBridgeTypes.ts. Other substrates implementing SR-5 via native cross-chain transactions (e.g. Polkadot XCM) MAY add their own rails under the cross-chain-liquidity-tank rail type with substrate-specific parameters.

### 9.13 Security considerations

**Re-entrancy on EVM rails.** *Threat:* a malicious ERC-20 hook re-enters the orchestrator during pay-evm-erc20 settlement. *Mitigation:* phase handlers MUST be re-entrancy-safe; the SettlementEvidence MUST be anchored only after the chain transaction is confirmed at finality.

**MEV / front-running on payment txs.** *Threat:* a public-mempool payment can be front-run by MEV bots. *Mitigation:* rail.parameters MAY specify Flashbots-style private mempools or rate-limited public submission. Payment phases SHOULD support submitting via private mempools when available. For high-stakes settlements, cross-chain-liquidity-tank avoids public-mempool exposure entirely.

**Cross-chain settlement-atomicity failure.** *Threat:* HTLC source-lock succeeds but dest-claim never happens; payer’s funds are locked. *Mitigation:* HTLC timelocks let payer reclaim after expiry. Phase handlers MUST track lock expiry and invoke refund automatically. settlement-atomicity error class flags this for DACS-5 reputation logic.

**Liquidity Tank operator compromise.** *Threat:* the substrate validator shard operating Liquidity Tanks is compromised. *Mitigation:* the substrate’s security model (2/3 BFT multisig on Demos, 15-day emergency-recovery on Demos) is the floor. Listings handling high-stakes flows over Liquidity Tanks SHOULD evaluate the substrate’s validator-shard security; for the highest stakes, HTLC is recommended.

**AP2 mandate replay.** *Threat:* an old AP2 mandate is replayed against the provider. *Mitigation:* AP2 mandates include a nonce and an expiry; the provider rejects replays. DACS-4 inherits AP2’s anti-replay properties.

**x402 payment-receipt forgery.** *Threat:* a server claims payment it did not receive. *Mitigation:* x402 settles on-chain, so the primary audit is verifying the anchored `settlementTxHash` against the settlement chain — like the `evm` rail, not server- or facilitator-forgeable (§9.5.7). Where no settlement tx is returned, verification falls back to the facilitator-signed receipt (processor-attested, not chain-verified). Buyer-side x402 wallets SHOULD keep a local record of submitted payments.

**Delivery non-delivery.** *Threat:* seller signals payment received, never delivers. *Mitigation:* outside DACS-4’s remit; this is a DACS-3 / DACS-5 issue (the deliver-* phase MUST return ok: false on missing deliverable; DACS-5 records the failure; reputation impact accrues). Listings handling expensive non-recoverable deliveries SHOULD order the pipeline to shift the risk they care about — deliver-then-pay or pay-then-deliver (§9.9) — accepting the residual counterparty risk each implies. A true escrow that gates release on demonstrable delivery (lock → deliver → release) is **not expressible in v0.1** (§9.9): `pay-cross-chain-htlc` is an atomic swap with no mid-lock suspension point, and delivery-gated escrow is roadmapped to the ERC-8183 job-escrow rail.

**Refund laundering.** *Threat:* a seller refunds to quietly unwind a failed delivery without recording failure. *Mitigation:* SettlementAmendments are anchored, signed, and included in DACS-5 bundles, so the trail shows both the original payment and the later refund; reputation derivation MUST treat refunded sessions appropriately. The inverse — a refund against a non-existent/failure-outcome record, or an over-refund — is guarded by AMEND-1..4 (§9.7.1).

**Decimal-overflow in cross-decimal pay paths.** *Threat:* converting `amount.amount` to on-chain integer units overflows or mis-rounds. *Mitigation:* the §9.5.2/§9.5.3 procedures mandate string-decimal arithmetic with no float, and `PriceTerm.amount` is canonical per CD-1 (CORE §B.2). Rail authors MUST specify `decimals` exactly, and phase handlers MUST validate `amount.amount` precision against `rail.asset.decimals` (excess precision is an error).

**Pinned-rail vs latest-rail at settle time.** *Threat:* the rail registry changes between agreement commit and settle execution. *Mitigation:* the rail is pinned at session start (per railRegistryVersion in SessionContext). Settle MUST use the pinned rail definition, even if the registry has since superseded it.

### 9.14 Phase parameters reference card

A single-table summary of phase types, their parameters (from listing PhaseStep), and the SettlementEvidence they produce, for implementers.

| Phase type | Parameters (PhaseStep) | Evidence txRef kind |
| --- | --- | --- |
| pay-evm-erc20 | {rail: railId}; rail.parameters.finalityBlocks optional | evm |
| pay-solana-spl | {rail: railId}; rail.parameters.commitmentLevel optional | solana |
| pay-cross-chain-htlc | {rail: railId}; rail.parameters.timelockSourceSec, timelockDestSec, sourceFinalitySec, and safetyWindowSec required, with timelockSourceSec > timelockDestSec + sourceFinalitySec + safetyWindowSec (HTLC-7 — the margin covers the payee reaching SOURCE-chain finality after the reveal; evaluated against the pinned params, not runtime latency), under the source-lock-finality epoch (HTLC-8) | htlc-lock + htlc-reveal + htlc-claim (source) |
| pay-cross-chain-liquidity-tank | {rail: railId} | liquidity-tank |
| pay-ap2 | {rail: railId}; rail.parameters.providerEndpoint required | ap2 (txRef carries `protocolVersion`, required) |
| pay-x402 | {rail: railId} | x402 (txRef carries `protocolVersion` required; + `settlementTxHash`/`chainId` when the facilitator returns them, §9.5.7) |
| deliver-storage-program | none (driven by listing.offering.deliverable) | n/a (deliverableContentHash + deliverableAnchor instead) |
| deliver-entitlement | none (driven by listing.offering.deliverable) | n/a |
| deliver-attested-payload | none (driven by listing.offering.deliverable) | n/a + attestationRef |
