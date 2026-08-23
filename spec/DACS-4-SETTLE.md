# DACS-4: Settle — Settle

*Normative module of DACS v0.1. Read the [Primer](../PRIMER.md) first; shared types, signatures, canonical form, the session model, and substrate requirements live in [CORE](CORE.md). Section numbers are retained from the unified specification; per the §→document map in [CORE](CORE.md), cross-references of the form §6–§10 point to sibling module documents, and §A / §12–§14 to the companion references (Demos mapping, threat model, glossary, conformance plan). The [conformance vectors](../conformance/) exercise this module's rules.*

## Chapter 9 — DACS-4: Settle

**Stage:** Settle (4th of 5). **Status:** Draft — **DACS-4 v0.7** (on the common DACS v0.1 baseline; v0.7 adds the provider-neutral negotiated `x402:protocol` rail, complete agreement-signed request/selection binding, numeric-version generic settlement evidence, local capability separation, and an independent-verification success floor while preserving `x402:default` bytes for replay; v0.6 adds signed event-level `evm-event`, `solana-instruction`, and `x402-event` transaction-reference arms plus the deterministic SB-1 projection and legacy-replay rules, and hardens `pay-ap2` with the registered byte-exact AP2-6 idempotency key, AP2-7 session-phase replay binding, separate-chain checkout admission, explicit transaction-ID derivation, a DACS-profiled checkout-JWT signature policy, and the split-credential registration gate; v0.5 adds the minor-safe `PayloadAttestationRecord` and DPA-1..DPA-9 so `deliver-attested-payload` evidence binds the exact job, agreement, DeliverableSpec, payload bytes, and verification method, and makes PB-2 EVM chain applicability byte-exact through the DACS-1 EIP-155 `cci-xm` profile; v0.4 requires finalized DACS-3 commitment before irreversible effects and generalizes post-final-payment SR-2 evidence catch-up to every rail; v0.2 additions: SB-1..SB-3 session-bound settlement evidence §9.5.8, `pay-solana-spl` payer-funded ATA-rent §9.5.3, the native-DEM `pay-dem` rail §9.5.9, and liquidity-tank recovery-pending evidence via ST-8 §9.5.5; v0.3 additions: PB-1..PB-3 payee-destination binding through the minor-safe `PayeeBoundAgreementDocument` §9.5.1, AP2-1..AP2-6 attested provider-receipt verification / provider-metadata session binding / capture-not-irreversibility semantics for `pay-ap2` §9.5.6/§9.5.8, byte-exact SB-3 EIP-3009 nonce derivation for `pay-x402` §9.5.8, and the `metered` usage-based `PricingSpec` variant, validated per DACS-3 §8.5.2 MTR-1..5). **Depends on:** SR-2 (required), SR-3 for `consensus-backed-proxy` payload verification, and any substrate capability required by the selected DACS-2 verification method; SR-5 is required for cross-chain rails only. Composes with AP2, x402, ERC-20, SPL, HTLC contracts, DACS-2 verification methods, and substrate-native bridges (Liquidity Tanks on Demos). **Used by:** DACS-5 (settlement evidence in session bundle).

### 9.1 Abstract

DACS-4 specifies how value is exchanged and the deliverable provided once a DACS-3 agreement is committed. It defines:

- A **payment rail registry** — a versioned, anchored set of payment rails. A static rail identifies its network, asset, settlement contract/protocol, and parameters; a negotiated-protocol rail fixes provider-neutral resolution and verification behaviour while the signed agreement selects the exact request and requirement.
- A **closed set of payment phases** (DACS-4 phase types) — pay-evm-erc20, pay-solana-spl, pay-cross-chain-htlc, pay-cross-chain-liquidity-tank, pay-ap2, pay-x402, pay-dem. Each is a phase with a uniform PhaseHandlerResult shape.
- A **closed set of delivery phases** — deliver-storage-program, deliver-entitlement, deliver-attested-payload. Each produces SettlementEvidence the rest of the stack consumes.
- A **payload-attestation record** — a signed, addressable binding from exact delivered bytes and method-native proof to the job, committed agreement, DeliverableSpec, verification method, and immutable attempt number.
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
type PaymentRailRef = StaticPaymentRailRef | X402ProtocolPaymentRailRef

type StaticPaymentRailRef = {

  railId: string                       // e.g. "evm-erc20:1:USDC" or "demos:cross-chain-tank:USDC"; MUST NOT equal "x402:protocol"

  railVersion?: number                 // pinned at session start if set

  parameters?: Record<string, unknown>

}

type X402ProtocolPaymentRailRef = {

  railId: "x402:protocol"

  railVersion: number                  // REQUIRED: exact provider-neutral definition pinned for the session

  parameters: X402ProtocolRailParameters

}

type X402ProtocolRailParameters = {

  request: {
    method: string                     // canonical upper-case HTTP method
    url: string                        // exact absolute HTTPS target; no userinfo or fragment
    bodyHash?: string                  // sha256 lowerhex of exact request-body bytes; required iff a body is sent
  }

  selection: {
    x402Version: number                // positive safe integer; copied from PaymentRequired.x402Version
    scheme: string                     // x402 scheme token; "exact" is the v0.7 success profile
    network: string                    // CAIP-2 namespace:reference
    asset: string                      // exact PaymentRequirements.asset value
    assetDecimals: number              // independently established by the selected scheme/network adapter
    currency: string                   // MUST equal agreement.terms.price.currency
    maxTimeoutSeconds: number
    extra: Record<string, unknown>     // complete PaymentRequirements.extra object
  }

  paymentRequiredExtensions?: Record<string, unknown>   // complete top-level PaymentRequired.extensions object; presence is significant

}

type PricingSpec =

  | { kind: "fixed"; price: PriceTerm }

  | { kind: "negotiable"; bandCenter: PriceTerm; minPct: number; maxPct: number }   // price band around bandCenter; minPct/maxPct non-negative %, 0 ≤ minPct < 100; band + half-up rounding + inclusive bounds per §8.5.2. See the "Negotiable pricing band" note below.

  | { kind: "auction"; reservePrice?: PriceTerm; selectionRule: "lowest-price" | "highest-price" | "first-acceptable" | "rule-ref:<contentHash>:<uri>" }   // selectionRule MUST be drawn from the SAME enum as the phase-step parameter (§8.4.3) so the §8.4.3 step-5 "MUST equal" rule is type-expressible; reservePrice.currency MUST equal the listing currency; enforced as a floor (highest-price / first-acceptable / rule-ref) or ceiling (lowest-price), inclusive, per §8.4.3 step 5

  | { kind: "metered"; unitPrice: PriceTerm; unit: string; minTotal?: PriceTerm }   // usage-based: authoritative terms.price = max(minTotal ?? 0, unitPrice.amount × quantity), computed at commit from terms.meteredQuantity (rules MTR-1..4, §8.5.2). Pairs with negotiate-fixed-price (deterministic total) or negotiate-rfq per PS-3.

type PriceTerm = {

  amount: string                       // canonical decimal string (rule CD-1, CORE §B.2): minimal-digit, no leading/trailing zeros, no exponent; MUST be positive (see normative rule below)

  currency: string                     // ISO 4217 fiat OR asset id (e.g. "usd-stablecoin", "USDC", "SOL")

  unit?: string                        // optional unit qualifier (e.g. "per-call")

}

type DeliverableSpec =

  | { kind: "storage-program"; schemaUrl?: string; expectedSizeBytes?: number; accessModel?: "public" | "buyer-only" | "encrypt-to-buyer" }   // default "public"; non-public ⇒ private delivery (§9.6.1)

  | { kind: "entitlement"; durationSec: number; renewable: boolean }

  | { kind: "attested-payload"; payloadFormat: string; verificationMethod?: VerificationMethod; expectedSizeBytes?: number }   // verificationMethod remains optional in the legacy wire shape; it is conditionally REQUIRED when the pipeline selects deliver-attested-payload (DPA-1)

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

  | { kind: "evm-event"; chainId: number; txHash: string; logIndex: number }   // current success-outcome pay-evm-erc20 evidence; event identity is inside the signed SettlementEvidence scope (SB-1)

  | { kind: "solana"; cluster: "mainnet" | "devnet" | "testnet"; signature: string }

  | { kind: "solana-instruction"; cluster: "mainnet" | "devnet" | "testnet"; signature: string; instructionIndex: number }   // current success-outcome pay-solana-spl evidence (SB-1)

  | { kind: "demos"; txHash: string; blockNumber?: number }   // blockNumber set on a pay-dem settlement (bft-final inclusion, §9.5.9)

  | { kind: "storage-program"; address: string; writeTxHash: string }

  | { kind: "ap2"; mandateId: string; providerRef: string; protocolVersion: string; receiptAttestation?: AttestationRef }   // receiptAttestation REQUIRED on a success-outcome record (AP2-2, §9.5.6): the SR-3 attestation of the provider payment-status response, contentHash = attested response hash; MAY be absent only on failure-outcome records

  | { kind: "x402"; httpResource: string; paymentReceiptHash: string; settlementTxHash?: string; chainId?: number; protocolVersion: string }   // paymentReceiptHash and protocolVersion follow X402-1..X402-4 (§9.5.7)

  | { kind: "x402-event"; httpResource: string; paymentReceiptHash: string; settlementTxHash: string; chainId: number; logIndex: number; protocolVersion: string }   // current on-chain pay-x402 evidence; receipt and settling Transfer event share one signed arm (SB-1)

  | { kind: "x402-protocol"; httpResource: string; paymentRequiredHash: string; paymentReceiptHash: string; x402Version: number; settlementNetwork: string; settlementTransaction: string; settlementEvent: string }   // negotiated x402:protocol success evidence; adapter-canonical transaction/event identity is independently verified (XN-7..XN-9)

  | { kind: "htlc-lock"; chainId: number; contractAddress: string; lockTxHash: string }

  | { kind: "htlc-reveal"; chainId: number; contractAddress: string; revealTxHash: string }   // the payer's destination claim, which reveals the preimage on-chain

  | { kind: "htlc-claim"; chainId: number; contractAddress: string; claimTxHash: string }   // the payee's source-side claim against the revealed preimage (the decisive success tx)

  | { kind: "htlc-refund"; chainId: number; contractAddress: string; refundTxHash: string }

  | { kind: "liquidity-tank"; bridgeId: string; sourceChainId: number; destChainId: number; lockTxHash: string; releaseTxHash?: string; recoveryDeadline?: number }   // recoveryDeadline (unix ms): on a locked-but-unreleased interim record (ST-8 tank case, §9.5.5), the substrate recovery-window bound; releaseTxHash is absent until/unless the release lands
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
type RailDefinition = StaticRailDefinition | X402ProtocolRailDefinition

type RailDefinitionBase = {
  railVersion: number
  railId: string                       // canonical id; lowercase ASCII; max 64 chars
  phaseHandler: PhaseType              // which pay-* phase handles it
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
type StaticRailDefinition = RailDefinitionBase & {
  railType: "evm-erc20" | "solana-spl" | "cross-chain-htlc" | "cross-chain-liquidity-tank" | "ap2" | "x402" | "demos-native"
  asset: AssetSpec                     // what is being transferred
  network: NetworkSpec                 // where it lives
  parameters: Record<string, unknown>  // rail-type-specific
}
type X402ProtocolRailDefinition = RailDefinitionBase & {
  railId: "x402:protocol"
  railType: "x402"
  phaseHandler: "pay-x402"
  resolution: { kind: "x402-payment-required" }
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
  | { kind: "native-dem"; symbol: "DEM"; decimals: 9 }                  // native Demos token; 1 DEM = 10^9 OS base units (§9.5.9)
  | { kind: "fiat-via-ap2"; isoCurrency: string; provider: string }
  | { kind: "stablecoin-cross-chain"; canonicalSymbol: string; routes: CrossChainRoute[] }
type NetworkSpec =
  | { kind: "evm"; chainId: number; rpcAttestation: "consensus-backed-proxy" | "evm-rpc" }
  | { kind: "solana"; cluster: "mainnet" | "devnet" | "testnet" }
  | { kind: "demos" }                                                   // the Demos substrate itself (native-DEM rail, §9.5.9); BFT inclusion is final, operator is the substrate
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
| demos-native:DEM | pay-dem | Native-DEM transfer on the Demos substrate (§9.5.9); single payee. |
| ap2:visa-direct | pay-ap2 | AP2 mandate to Visa Direct |
| ap2:mastercard-send | pay-ap2 | AP2 mandate to Mastercard Send |
| ap2:stripe-paymentintents | pay-ap2 | AP2 mandate to Stripe PaymentIntents |
| x402:protocol | pay-x402 | Provider-neutral negotiated x402 protocol; the exact request and requirement are agreement-signed (§9.5.7). |
| x402:default | pay-x402 | Legacy static x402 entry; retained only for pinned historical replay and disabled for new sessions (XN-10). |

**v0.1 cross-chain settlement scope.** `pay-cross-chain-liquidity-tank` is supported **only** for the live tank routes: ETH Sepolia ↔ Polygon Amoy testnet, USDC, EVM-source unidirectional. All other tank rails are 🟡 to-add. v0.1 keeps both `pay-cross-chain-liquidity-tank` and `pay-cross-chain-htlc` first-class.

> **Note (non-normative).** Further tank routes unlock as Native Bridges Phase 2–4 ship: Solana tanks, bidirectional routes, additional EVM rails, mainnet deployments, non-USDC stablecoins. HTLC is the path the reference implementation runs today — a ~929-LOC reference (Solana Anchor program + Base Sepolia EVM HTLC contract) with lock/reveal/refund implemented end-to-end.

**v0.1 rail reference-backing status (honest disclosure).** A rail is *reference-backed* when a live settlement path exists **and** a reference implementation exercises it. The registered rails differ in maturity. An orchestrator MUST consult each rail's pinned `availability` (§9.4.4) rather than assume `live`. In particular, `pay-ap2` registry entries declare a non-`live` `availability` (`operator_gated` or `mocked`) in v0.1, and orchestrators MUST NOT treat them as `live` (RAV-R1).

Maturity by rail:

| Rail(s) | v0.1 status |
| --- | --- |
| `pay-evm-erc20`, `pay-solana-spl`, `pay-cross-chain-htlc` | Reference-backed: exercised by the reference implementation, with §14 conformance vectors |
| `pay-cross-chain-liquidity-tank` | Partially live: only the Phase-1 testnet route (ETH Sepolia → Polygon Amoy, USDC, unidirectional); other routes to-add |
| `pay-x402` / `x402:protocol` | Provider-neutral protocol profile specified in v0.7; implementation support is declared locally per `(x402Version, scheme, network)` and exercised by §14 negotiated-rail vectors. |
| `pay-x402` / legacy `x402:default` | Historical path exercised by the reference implementation and `settlement-x402-pass`; disabled for new sessions and retained for byte-stable replay only. |
| `pay-ap2` | Specified, not yet reference-backed: no live settlement path, no §14 conformance vector; `operator_gated` (see note) |

> **Note (non-normative).** *pay-x402* (§9.5.7) — `x402:protocol` does not imply one settlement chain or asset. An independently verified EVM exact settlement remains chain-verifiable, but another locally supported CAIP-2 network uses that scheme/network adapter's authenticated event and finality rules. The historical Base/USDC implementation and `settlement-x402-pass` vector exercise the frozen static `x402:default` shape; they do not establish conformance to the negotiated v0.7 profile.
>
> *pay-ap2* (§9.5.6) — the handler procedure, registry entries, and evidence shape are defined, but there is no live path. `pay-ap2` settles **off-chain** (a provider receipt, not chain-verifiable) and requires AP2 provider onboarding (Visa Direct / Mastercard Send / Stripe PaymentIntents); AP2 itself was donated to the FIDO Alliance only in April 2026. Bringing it to reference-backed status — a live path plus conformance vectors — is roadmap work.

#### 9.4.3 Rail authoring and resolution

A conforming rail author MUST:

- (RD-1) sign the rail with the registry steward’s signing key over the domain-separated payload "dacs-rail:v1:" || rail_hash per §B.7;
- (RD-2) anchor the rail via SR-2 at the canonical address;
- (RD-3) specify railVersion as monotonically increasing per railId;
- (RD-4) specify supersedes when replacing a prior rail with the same railId;
- (RD-5) for a `StaticRailDefinition`, ensure the railType matches the asset and network kinds (an evm-erc20 rail with a Solana asset MUST be rejected). For an `erc20` or `native-evm` asset on an `evm` network, `asset.chainId` and `network.chainId` MUST be the same positive integer; a mismatch MUST be rejected before the rail can participate in PB-2. An `X402ProtocolRailDefinition` instead MUST match its complete discriminated arm exactly; it has no static asset or network to compare.
- (RD-6) keep `phaseHandler` invariant across every version sharing a `railId`.
  A registry update that would change that handler MUST use a new `railId`;
  the steward and registry-index publisher MUST reject a same-`railId` handler
  change.

- (XN-1) **Provider-neutral protocol definition.** The canonical
  `x402:protocol` entry MUST be an `X402ProtocolRailDefinition` and MUST NOT
  carry `asset`, `network`, static rail `parameters`, a resource or facilitator
  URL, a provider name, credentials, a wallet, an RPC endpoint, or an asset,
  network, provider, facilitator, or scheme allowlist. Its signed global scope
  fixes only `pay-x402` dispatch, `x402-payment-required` resolution, registry
  availability/governance, and the XN verification contract below. A
  definition that combines either discriminated arm's fields with the other
  arm is malformed and MUST be rejected; a consumer MUST NOT coerce it into a
  static rail by inventing placeholder asset or network values.

A consumer MUST resolve a rail by:

1. reading the rail-registry index from dacs4:registry:v0.1;
2. looking up the entry for the agreement’s terms.rail.railId;
3. fetching the rail at the indicated anchor and verifying its content hash and signature;
4. if the agreement pins a specific railVersion, MUST use that version; otherwise MUST use the latest at session start, pinned into the session.

For DACS-1 listing validation, every advertised `PaymentRailRef` is resolved
before session creation under §6.3.4 LRR-1..LRR-6, including references not
used by a particular pay phase. That listing-time check uses the same canonical
index, definition hash/signature, per-reference version selection, and
governance authority described above. For a railId-only pay-phase field it
checks that every matching reference-resolved definition uses the RD-6 handler
and that the handler equals the phase kind; it does not select one complete
reference. It returns `verified` / `rejected` / `indeterminate` for the listing
as a whole. It establishes discovery eligibility only; the orchestrator still
selects one complete reference, repeats resolution, pins the exact definition
at session start, and applies RAV-R1..RAV-R5.

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
- **mocked** — settlement path is stubbed for development or testing. It MUST NOT be presented or selected as a production rail.
- **disabled** — rail exists in the registry but the steward has marked it not-for-use. Orchestrators MUST NOT initiate new sessions selecting disabled rails; in-flight sessions continue.
- **failed** — rail’s underlying network or asset path is currently broken (chain congestion preventing settlement, asset contract paused, bridge offline).

**Orchestrator obligations.**

- (RAV-R1) An orchestrator MUST inspect rail availability before selecting a rail for a session.
- (RAV-R2) For any new session, an orchestrator MUST NOT select a rail with availability `disabled` or `failed`. For a new production session, it additionally MUST NOT select a rail with availability `mocked`. Production/non-production mode for this decision MUST come from trusted local implementation or operator execution policy established before rail selection. It is not a `RailDefinition` or session-artifact field and MUST NOT be supplied or overridden by a listing, rail definition, discovery/catalog record, counterparty, or other evaluated protocol input. Non-production mode MUST be explicitly configured for development or testing; missing, malformed, or unauthenticated mode is not authority to select `mocked`, and the orchestrator MUST fail closed. A session that already pinned a rail MAY continue under that pinned definition when a later registry revision marks the rail `disabled`; the orchestrator MUST NOT reinterpret that permission as authority to create a replacement or additional session. `failed` settlement attempts remain subject to RAV-R4.
- (RAV-R3) An orchestrator MAY select rails with availability values operator_gated, closed_data, or bilateral only if the relevant operator-side configuration is in place; this is a runtime preflight check, not a static property of the rail.
- (RAV-R4) A rail's `availability` is pinned at session start (§9.13), so a mid-session availability *flip* is not observable from the pinned definition; RAV-R4 therefore binds at the point of use. If a settlement attempt on the pinned rail fails because the rail is non-operational, the orchestrator MUST classify the failure `errorClass: "substrate"`, not `counterparty`. Rail-non-operational means a rail-down / substrate failure, as distinct from a transient RPC hiccup or a counterparty error.
- (RAV-R5) **Authoritative availability read.** An orchestrator MUST read `availability` from the authoritative rail definition: the signed, anchored `dacs-rail:v1:` record pinned at session start. It MUST NOT read `availability` from an unauthenticated cache, discovery mirror, or counterparty-supplied copy. A discovery or catalog availability value MAY be used only as a non-authoritative prefilter or user-interface hint; it MUST NOT establish, contradict, or override the result of RAV-R1..RAV-R4.

> **Note (non-normative).** RAV-R4: a proactive out-of-band rail-liveness probe, mirroring the §8.12 CH-4 channel-liveness probe, would let an orchestrator detect failure *before* attempting settlement. That probe is a roadmap item; v0.1 detects rail failure at the settlement attempt.
> RAV-R5 closes availability-field poisoning: a tampered pre-pin read could steer an orchestrator onto a disabled/failed rail, or away from a live one. The pinned, signed definition is the only trusted source.

**Steward obligations.** Same as recipe availability (RAV-5, RAV-6, RAV-7 in §7.4.5) applied to rails. The steward maintains availability values current; transitions are signed and anchored revisions; availability is per-rail-version.

### 9.5 Payment phases

The closed v0.x set at this revision. Each is a PhaseType from chapter 6’s closed enumeration, with a phase-handler contract conforming to §B.5’s SessionContext / PhaseHandlerResult.

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

**(PC-3)** return a PhaseHandlerResult with `attestationRef` pointing to the evidence and `anchorReceipt` carrying its latest verified SR-2 lifecycle snapshot, except that both MAY be attached asynchronously under PC-7 after rail-final payment.

**(PC-4)** classify the outcome as exactly one of `ok: true` (payment confirmed at the chain's finality semantics) or `ok: false` with an `errorClass`:

| errorClass | trigger |
| --- | --- |
| `permanent` | refused by chain, insufficient balance, invalid signature |
| `transient` | RPC failure, mempool congestion |
| `counterparty` | AP2 mandate revoked, x402 server refused |
| `substrate` | SR-2 unavailable, and the payment has not yet reached its rail-defined finality (see PC-7) |
| `settlement-atomicity` | cross-chain only; one leg reached a terminal or asymmetric state the other did not match — a timeout, or the HTLC-9 preimage-revealed-but-counterpart-unclaimed state |

For the HTLC-9 asymmetric-open sub-case, the handler signals the open state and the orchestrator routes the session to the non-terminal `settle-asymmetric` state (§10.3.1, ST-8). A terminal `settlement-atomicity` outcome — the `settle-failed` state — is reached only after the ST-8 recovery window expires unresolved.

**(PC-5)** before settling, `amount.currency` MUST resolve to the pinned payment asset (reject a mismatch as `ok: false` / `errorClass: "permanent"`). For a `StaticRailDefinition`, resolve through `rail.asset` per AssetSpec kind:

| AssetSpec kind | `amount.currency` must equal |
| --- | --- |
| erc20 / spl / native-evm / native-solana / native-dem | `rail.asset.symbol` |
| fiat-via-ap2 | `rail.asset.isoCurrency` |
| stablecoin-cross-chain | `rail.asset.canonicalSymbol` |

For an `X402ProtocolRailDefinition`, the selected
`agreement.terms.rail.parameters.selection.currency` MUST equal
`amount.currency`; asset precision and the exact wire amount are then verified
under XN-5. Handlers MUST NOT settle a payment whose `amount.currency` does not
resolve under the applicable arm.

**(PC-6)** when outcome is `success`, populate `settlementFinality` (the finality model and parameters actually applied) in the produced SettlementEvidence — REQUIRED on any `success`-outcome payment evidence record, and absent on delivery evidence records.

**(PC-7) Rail-final payment / evidence-anchor decoupling.** Payment finality and SR-2 evidence finality are separate gates on **every** rail. **Principle: once payment reaches the rail's declared finality, anchoring `SettlementEvidence` is bookkeeping that must catch up — never a reason to fail the payment, submit it again, or classify the finalized payment as unpaid.**

*Rail finality* is the condition encoded by `SettlementFinalityRecord`: block depth, commitment level, verified provider receipt with the rail-defined capture semantics, completed HTLC or liquidity-tank settlement, or Demos BFT finality. For an HTLC it means BOTH legs are fully settled — the payee's `htlc-claim` reaching source-chain finality (§9.5.4), not the HTLC-9 asymmetric state.

Once rail finality is confirmed, the handler:

- (a) MUST return `ok: true` with the confirmed rail `txRefs` or provider evidence even if SR-2 anchoring is unavailable or pending;
- (b) MUST queue a durable anchor-retry idempotent on the `dacs4:payment:{jobId}:{railId}:{phaseIndex}` address — write-once by the PC-2 discriminator, so a re-anchor cannot duplicate the record;
- (c) MAY omit `attestationRef` and `anchorReceipt` until the retry confirms the anchor, then attach them. The PC-2/PC-3 obligations are satisfied by the retry rather than at payment-return time;
- (d) MUST NOT classify this as `errorClass: "substrate"` — that class is reserved for SR-2 unavailability *before* payment reaches rail finality, per PC-4; and
- (e) MUST keep the session non-terminal until the evidence has a verified `finalized` receipt and is independently resolvable, as required by DACS-5 §10.4.3. This catch-up gate delays terminal audit publication; it does not delay or reverse the already-final payment result.

PC-7 is the one carve-out from the ST-7 substrate-failure-pause (§10.3.1): because payment is already final, the handler commits `ok: true` and anchors via the retry rather than pausing or manufacturing a failed payment.

Two guards:

- PC-7 **EXCLUDES the HTLC-9** dest-revealed / source-claim-failed asymmetric state. That state is half-settled: it routes to `settle-asymmetric` (ST-8) and is surfaced as §9.5.4 asymmetric-settlement evidence, never as PC-7 `ok: true`.
- Any retry or recovery of a payment phase MUST first check the rail's settlement state using the original `(jobId, phaseIndex)` / idempotency binding and transaction/provider references. If the payment is final, it MUST resume only the evidence-anchor catch-up and MUST NOT resubmit settlement. If the transaction's established state is `submitted`, `accepted`, `dropped`, or `replaced`, or its current observation disposition is `indeterminate`, the handler MUST follow the rail's declared reconciliation semantics and MUST NOT infer a second payment is safe from non-observation alone.

```
type PaymentPhaseInput = {
  jobId: string
  agreement: AgreementArtifact         // pinned by the listing's agreement commitment phase
  rail: RailDefinition                 // pinned provider-neutral/static definition; exact PaymentRailRef remains in agreement.terms.rail
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

**Artifact gate and legacy behaviour.** Before interpreting agreement terms, a payer MUST select the DACS-3 artifact schema from its required version discriminator (§8.5). A payer that does not implement `PayeeBoundAgreementDocument` MUST reject that artifact as unsupported before invoking any pay handler; it MUST NOT discard `payeeBoundAgreementVersion` or `terms.payoutBindings` and retry it as an `AgreementDocument`. In particular, a DACS-4 v0.2 payer expects the required `agreementVersion` field, so the new artifact fails its legacy schema gate and no payment is submitted.

The legacy `AgreementDocument` remains valid with its pre-PB behaviour: PB-1 through PB-3 do not apply, and the pay handler uses `PaymentPhaseInput.payee.payeeAddress` after the other §9.5.1 checks. A later implementation MAY refuse legacy agreements by local risk policy, but it MUST NOT report their destination as PB-bound. This preserves earlier-minor semantics instead of retroactively making an optional field action-bearing.

**Payee-destination binding (PB-1..PB-3).** The rules below apply only when `agreement` is a `PayeeBoundAgreementDocument`. `payingKey` already binds the payer side to the bundle (`MUST appear in payer's bundle.claims`); PB restores the missing symmetry on the destination.

- (PB-1) **Agreement carriage.** The pinned agreement MUST carry exactly one `terms.payoutBindings` entry (§8.5) for this phase's `(railId, phaseIndex)`. `PaymentPhaseInput.payee.payeeAddress` MUST equal that entry's `payeeAddress`, and the handler MUST NOT submit payment to any other destination. A missing entry, duplicate key, wrong railId, or extra entry makes the payee-bound artifact invalid and MUST fail before payment. The lookup key is the same anchor tuple PC-2 already derives (`dacs4:payment:{jobId}:{railId}:{phaseIndex}`), so the equality check is a direct anchor-tuple lookup.
- (PB-2) **Destination-identity binding.** Before submitting, the payer MUST verify the destination is bound to `payee.primaryClaim` by the strongest **applicable** tier. Tier *applicability* is decided by the pinned payee bundle (`payee.bundleHash`) together with the pinned `RailDefinition`, not by whether pay-time linkage resolution succeeds:
  - **Tier 1 — intrinsic.** The rail's destination is definitionally the primary claim's address (e.g. `pay-dem`, §9.5.9): the binding holds by construction.
  - **Tier 2 — controlled linked claim.** Applicable iff the pinned bundle carries a `cci-xm:<chain>:<subchain>:…` claim whose SR-1 anchored linkage resolves control-proven per §6.3.2 step (6) for the pay rail's chain — the same gate, applied settle-side. Applicable and resolving to the phase's `payeeAddress` → bound. Applicable but unresolvable → `substrate` (ST-7 pause); the payer MUST NOT fall through to tier 3 and MUST NOT pay. The pause record MUST carry (or reference) the gate's VerifyResult `decision` and `reason`, so a consumer can distinguish a could-not-verify-the-stronger-binding pause from any other substrate pause; a resolver `error` stays `error` (§7.3.2), never a silent downgrade.
  - **Tier 3 — agreement-signed destination assertion.** Legal only when no stronger tier is applicable (the pinned bundle establishes no intrinsic or controlled binding for the rail's chain). The payee's co-signature over `terms.payoutBindings` is the binding — an assertion, not a control proof; the residual (a payee asserting an address it does not control) is a payee-side risk, not a substitution surface. A tier-3 settlement SHOULD record the binding tier used in its evidence, so downstream consumers can see the destination was bound by assertion.

  For an EVM rail, implementations MUST derive tier-2 chain applicability as
  follows:

  1. The pinned settlement selection has an EIP-155 settlement chain iff
     either (a) its `StaticRailDefinition.network` is
     `{ kind: "evm", chainId }` and the definition has passed RD-5, or (b) it
     is the `x402:protocol` definition and the complete agreement-signed
     `X402ProtocolPaymentRailRef.parameters.selection.network` is exactly
     `eip155:<chainId>`, where `<chainId>` is a positive minimal-decimal safe
     integer. Its canonical chain identifier is `eip155:` followed by that
     minimal decimal spelling. The negotiated arm is eligible only after the
     complete selected reference passes XN-2; a rail/selection exposing no
     single EIP-155 chain has no EVM tier-2 claim applicable under this
     predicate. A chain learned only from a later challenge, receipt, provider
     response, redirect, or ledger lookup MUST NOT retroactively change the
     bundle-derived tier.
  2. A pinned-bundle `cci-xm` claim has an EIP-155 settlement chain iff it
     conforms to the DACS-1 EVM settlement-chain profile. Its scheme is
     `cci-xm`, its family component is byte-equal to the lowercase ASCII
     literal `evm`, its `<chainId>` is a bare positive minimal-decimal integer,
     and the address component after `cci-xm:evm:<chainId>:` and before any
     optional `?` parameters is non-empty. The address component is otherwise
     opaque and does not determine the settlement chain; parameters likewise
     do not determine it. The claim's canonical chain identifier is the
     corresponding `eip155:<chainId>`. An empty address or a non-lowercase
     family spelling does not establish tier-2 applicability.
  3. That claim is applicable to the rail iff the two canonical chain
     identifiers are byte-for-byte equal. A different numeric chain ID is not
     applicable. A name-style or otherwise non-profile subchain — including
     `mainnet`, `testnet`, or `sepolia` — is also not applicable and MUST NOT be
     guessed through a local alias.
  4. If no pinned claim matches, tier 2 is not applicable and tier 3 remains
     legal. If a claim matches, tier 2 is applicable before its SR-1 linkage is
     resolved; a linkage `indeterminate` or `error` therefore follows the
     existing pause/error arms above and MUST NOT fall through to tier 3.
- (PB-3) **No downgrade.** SB-3 (§9.5.8) grades what a past, recoverable record proves and resolves absent-or-unverifiable by falling back to the unbound posture. PB-2 gates an irreversible pre-pay decision, and the pinned `bundleHash` makes *absent* (tier 3 legal) and *applicable-but-unresolvable* (pause) distinct, replayable states. An implementation MUST NOT apply SB-3's fallback arm to the PB-2 decision.

Where no tier is satisfiable for a payee-bound phase, the payer MUST refuse to pay. A missing `payoutBindings` entry is an invalid `PayeeBoundAgreementDocument`, not a legacy agreement and not permission to infer a destination.

**PB failure modes (all pay rails).**

- PB-1 malformed or incomplete payee-bound artifact → abort before submitting payment, `permanent`
- PB-1 destination mismatch, or PB-2 tier-2 resolving to a different address → abort before submitting payment, `counterparty`
- PB-2 applicable-but-unresolvable → `substrate` (ST-7 pause; the recorded VerifyResult reason distinguishes it)

#### 9.5.2 pay-evm-erc20

Single-chain ERC-20 token transfer.

**Procedure.**

1. Resolve rail; verify `asset.kind == "erc20"` and `network.kind == "evm"`.
2. Verify `amount.currency` matches `rail.asset.symbol`.
3. Compute on-chain `amount = amount.amount × 10^rail.asset.decimals` (string-decimal multiplication, no float).
4. Construct an ERC-20 transfer transaction: `contract.transfer(payee.payeeAddress, amount)`.
5. Submit via the payer’s wallet (or via SR-3 proxy attestation when the payer’s wallet runs server-side).
6. Wait for chain finality per `rail.parameters.finalityBlocks` (default 1 for L2s, 12 for Ethereum mainnet).
7. Identify the exact settling ERC-20 `Transfer` log and construct SettlementEvidence with a `txRef` of kind `evm-event`, including its `logIndex`; anchor via SR-2; return success.

**Failure modes.**

- payer balance insufficient → `permanent`
- transfer reverts (contract restrictions, paused token) → `permanent`
- chain unavailable → `transient`
- payer-side wallet rejects → `counterparty`

#### 9.5.3 pay-solana-spl

SPL token transfer on Solana.

**Procedure.**

1. Resolve rail; verify `asset.kind == "spl"`.
2. Construct an SPL Transfer instruction, or TransferChecked for decimal safety; the payee’s associated token account (ATA) is the destination. If the ATA does not exist, the handler MUST create it only when the rail parameter `createPayeeAtaIfMissing` is `true` (default `false`); the **rent-exempt reserve for ATA creation is funded by the payer** and MUST be included in the payer’s required-balance preflight.
3. Submit via the payer’s wallet.
4. Wait for confirmation per `rail.parameters.commitmentLevel` (default `"confirmed"`).
5. Identify the exact settling SPL transfer instruction and construct SettlementEvidence with a `txRef` of kind `solana-instruction`, including its `instructionIndex`; anchor via SR-2; return success.

**Failure modes.**

- insufficient balance → `permanent`
- token account does not exist and `createPayeeAtaIfMissing` is `false` → `counterparty` (payee setup issue)
- `createPayeeAtaIfMissing` is `true` but the payer cannot cover the ATA rent-exempt reserve → `permanent`
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
- source-lock succeeds but the destination release has not landed and the substrate's native recovery path is still open → the orchestrator anchors the interim locked-unreleased record and routes to the non-terminal `settle-asymmetric` state bounded by `recoveryDeadline` (ST-8, §10.3.1; see Evidence scope below). Substrate-native recovery applies per the SR-5 implementation (on Demos, the 15-day emergency recovery is the backstop). The release landing within the window resolves to success; the window expiring resolves to reputation-neutral `failed-substrate` — NEVER `failed-counterparty`, since neither party is at fault for a substrate-recoverable lock. (A *transient* substrate unavailability with no committed lock is the ordinary `substrate` / ST-7 pause, not this asymmetric-open state.)
- `BridgeOperation.status == "failed"` → `permanent` (deterministic rejection by tank shard)

**No mechanism substitution (normative).** The pinned rail's mechanism is binding:

- On tank insufficiency or capacity exhaustion, the orchestrator MUST retry the pinned tank rail (transient) or fail the phase. It MUST NOT silently fall through to a different mechanism (e.g. `pay-cross-chain-htlc`).
- The produced `txRef.kind` MUST match the pinned rail (§9.14). A phase whose executed mechanism differs from the pinned rail MUST fail with errorClass: permanent.
- An implementation wanting HTLC fallback MUST express it as a distinct pinned rail / phase, not an implicit fallthrough.

> **Note (non-normative).** Silent substitution would violate the §9.13 pinned-rail rule and break the one-to-one phase↔txRef-kind correspondence.

**Evidence scope.** A successful tank settlement carries both `lockTxHash` and `releaseTxHash` (bridge `completed`). A **locked-but-not-yet-released** lock whose substrate recovery path is still open is **recovery-pending**, machine-distinguishable from a terminal loss: the orchestrator anchors an interim `outcome: "failure"`, `reason: "tank-locked-unreleased"` SettlementEvidence whose `liquidity-tank` txRef carries `lockTxHash` (no `releaseTxHash`) and the `recoveryDeadline`, and routes the session to the non-terminal `settle-asymmetric` state (ST-8, §10.3.1). Resolution follows ST-8: the release landing within `recoveryDeadline` supersedes the interim record with a success record (both tx hashes); the deadline expiring transitions to `settle-failed` recorded as reputation-neutral `failed-substrate`. This reuses the same asymmetric-open machinery as the HTLC-9 `dest-revealed-source-unclaimed` case, differing only in the window bound (`recoveryDeadline` vs `expiry_source`) and the expired verdict (`failed-substrate` vs `failed-counterparty`).

#### 9.5.6 pay-ap2

Payment via an AP2 mandate to a card network or banking provider.

**Procedure.**

1. Resolve rail; verify `asset.kind == "fiat-via-ap2"`.
2. Construct the AP2 mandate chain conforming to the FIDO Alliance AP2 spec (April 2026 onwards), binding the session into the provider-side payment object per AP2-1. The handler MUST possess and verify the complete **CheckoutMandate + PaymentMandate** chain as separate artifacts: the CheckoutMandate carries `checkout_jwt` and `checkout_hash`, while the PaymentMandate carries `transaction_id`, payee, amount, and payment instrument. A PaymentMandate MUST NOT be interpreted as carrying the CheckoutMandate or checkout JWT. Before reserving any AP2-7 binding or submitting anything to the provider, the handler MUST verify both mandate artifacts and the merchant signature, then compute `transaction_id = base64url_nopad( H( UTF8( J ) ) )`, where `J` is the exact RFC 7515 JWS Compact Serialization stored in `CheckoutMandate.checkout_jwt` (`BASE64URL(header) "." BASE64URL(payload) "." BASE64URL(signature)`). `H` MUST be the hash algorithm named by the `_sd_alg` claim in the base payload of the SD-JWT carrying the CheckoutMandate when that claim is present; when it is absent, `H` MUST be SHA-256. This DACS rule follows AP2 v0.2's CheckoutMandate algorithm selector and resolves the PaymentMandate schema's ambiguous reference to the algorithm "used by the `sd_hash` field": `sd_hash` is a digest, not an algorithm identifier. A malformed, unknown, or locally unsupported `_sd_alg` yields verifier result `error` and handler `errorClass: "permanent"`; it MUST NOT fall back to another algorithm. The recomputed value MUST equal the PaymentMandate's `transaction_id`; a mismatch MUST fail before the handler reserves the AP2-7 binding, creates provider metadata, or submits a payment. Because the preimage includes the merchant signature, `transaction_id` is derived **once** from the exact signed JWT bytes and is **not** recomputable from checkout fields; the handler MUST persist those exact bytes so AP2-7 and later verification use the same value. The merchant checkout JWT's signature generation MUST be non-deterministic. **DACS profiles the stricter** of AP2 v0.2's two formulations: `specification.md` excludes deterministic schemes, while the security-and-privacy text permits them when the Checkout carries sufficient-entropy salt. DACS selects the stricter branch because a verifier cannot portably establish the entropy of a checkout-provided salt. This profile applies only to the merchant checkout JWT and does not change the algorithm rules for DACS-owned records.
3. The payer’s AP2-compatible wallet authorises the mandate.
4. Submit the mandate to `rail.network.providerEndpoint`; receive a payment receipt and provider-side reference (e.g. Visa Direct payment id, Stripe PaymentIntent id).
5. Verify the receipt per AP2-2: an SR-3 attested fetch of the provider’s payment-status endpoint for `providerRef`, using an AP2-3-conformant credential.
6. Construct SettlementEvidence with `txRef` of kind `ap2` carrying mandateId, providerRef, the AP2 `protocolVersion` — the wire version that produced the mandate/receipt, so historical evidence is re-validatable against the rules of its era (#27) — and the AP2-2 `receiptAttestation`. Anchor via SR-2; return success.

- (AP2-1) **Provider-metadata session binding.** The handler MUST bind the session into the provider-side payment object at creation: metadata key `dacs_job_id` set to the session `jobId`, and SHOULD additionally set `dacs_agreement_hash` to the agreement content hash (§8.5.2). The key names are pinned so two implementations produce and check the same binding. This is the §9.5.8 SB-3 binding for `pay-ap2`: it rides the provider’s own payment record, so the AP2-2 attested status response returns it and a single attestation binds payment → session (→ agreed terms when the agreement hash is present). A verifier resolves the binding per the SB-3 three branches (matches / mismatches-reject / absent-or-unverifiable-fallback). A provider whose payment object cannot carry the AP2-1 metadata, **or whose payment-status endpoint does not return it**, cannot satisfy AP2-1/AP2-2 and MUST NOT be registered as a `pay-ap2` rail — a registration-time gate, not a per-settlement silent degradation to the SB-3 absent branch.
- (AP2-2) **SR-3-bounded provider-receipt verification.** A success-outcome `pay-ap2` record MUST verify the provider receipt through the selected SR-3 binding's authenticated fetch of the provider’s payment-status endpoint for `providerRef`. Universally, a verifier MAY claim only the response-authentication property that the selected SR-3 binding establishes and MUST NOT infer a stronger observation, signature, or quorum property. In the **current Demos DAHR binding** (DEMOS-MAPPING §A.3), the authenticated on-chain `web2Request` transaction and response hash establish a consensus-anchored hash commitment: the response body is checked against that commitment, but is not itself multi-validator-observed or consensus-set-signed. A Demos verifier therefore MUST NOT read `receiptAttestation` as quorum-observed unless a later binding explicitly supplies and authenticates validator body-signatures. A stronger conforming SR-3 binding MAY establish stronger response authentication, and its verifier MAY report only those authenticated properties. Under the selected binding, the fetch checks that: the provider-reported status is the provider’s settled/captured value; the amount and currency match the agreement; and the AP2-1 binding resolves (per its three-branch rule). The attestation MUST be recorded in `txRef.receiptAttestation` (an AttestationRef whose `contentHash` is the authenticated response hash). A bare provider reference with no attestation MUST NOT be presented as verified settlement evidence.
- (AP2-3) **Least-privilege provider credentials and registration gate.** The provider credential disclosed for the AP2-2 attested fetch MUST be scoped read-only to payment status; a credential capable of moving funds (charge, refund, payout, transfer) MUST NOT be disclosed to the attestation layer. The credential necessarily transits the SR-3 relay — scope containment is the defence (§9.13). The credential the handler uses to **create** the provider payment object and write the AP2-1 metadata (step 2 / AP2-1) is a distinct, more-privileged credential: it MUST NOT be the read-only status credential and MUST NOT transit the SR-3 relay. Both least-privilege scopes are normative — the create/metadata-write credential (never relayed) and the read-only status credential (relayed, scope-contained). An integration that cannot provision a distinct payment-status-only credential MUST NOT be registered as a `pay-ap2` rail; lack of portable runtime scope introspection does not weaken this registration-time eligibility gate.
- (AP2-4) **Capture, not irreversibility.** A `pay-ap2` success record with `provider-receipt` finality (§9.7) asserts that funds were **captured at the provider** as of `finalityObservedAt`. It MUST NOT be read as asserting irreversibility: card-network rules permit post-capture reversal. Post-capture reversals are recorded through the settlement-amendment machinery (§9.7.1), not by re-opening the phase.
- (AP2-5) **Retry safety — no double-charge.** Because the mandate is submitted (step 4) before the receipt is verified (step 5), a `transient` failure can occur after funds are already captured at the provider. On any retry of a `transient` `pay-ap2` failure the handler MUST first perform the AP2-2 attested status fetch for the **existing** `providerRef` and, if it reports captured, resume from step 6 (construct evidence) rather than constructing a new mandate — the same value-moved-verification-pending discipline the §9.5 rule already mandates for cross-chain retries. Only a status fetch confirming no capture permits a fresh mandate.
- (AP2-6) **Idempotent submission.** The handler MUST attach a **provider idempotency key** to the mandate submission (step 4), derived deterministically from `(jobId, phaseIndex)` as `idempotencyKey = lowercase-hex( SHA-256( UTF8("dacs-ap2-idem:v1:") || UTF8(NFC(jobId)) || 0x3a || ASCII(decimal(phaseIndex)) ) )` — the same preimage shape the pay-x402 SB-3 EIP-3009 nonce uses (§9.5.8) under a distinct non-signature hash-domain tag registered in CORE §B.7, where `decimal(phaseIndex)` is minimal base-10 ASCII with no leading zeros and no sign (matching the merged `decimal()` definition). Pinned byte-for-byte so two implementations derive the same key. An idempotency key is a token the provider remembers: on a submission carrying a key it has already processed, the provider returns the **existing** charge rather than creating a new one, so a re-submitted mandate settles the same payment, never a second. This is required because step 4 can fail `transient` *after* the provider has charged but *before* its `providerRef` reaches the handler (a dropped response, a relay partition); on that retry there is no `providerRef` for the AP2-5 status-check to look up, so without the key the retry would charge twice. Deriving the key from `(jobId, phaseIndex)` makes the retry reproduce the same key automatically — the same session binding SB-3 applies to the `pay-x402` EIP-3009 `nonce`. A provider whose submission endpoint does not support idempotency keys cannot satisfy AP2-6 and MUST NOT be registered as a `pay-ap2` rail (the same registration-time gate as AP2-1).
- (AP2-7) **`transaction_id` session-phase binding and replay defence.** A `pay-ap2` handler MUST treat `transaction_id` as opaque after deriving and matching it under step 2, and atomically bind its first valid presentation to exactly one `(jobId, phaseIndex)`. A valid presentation is one whose separate CheckoutMandate and PaymentMandate artifacts, merchant signature policy, digest selection, exact-JWS derivation, and `transaction_id` comparison have all passed. The handler **MUST NOT reserve the AP2-7 binding** or permit any provider side effect for an invalid, mismatched, or unsupported presentation. A later presentation of the same `transaction_id` under a different `jobId` or `phaseIndex` MUST be rejected as cross-session or cross-phase replay. A later presentation under the same tuple is not a second purchase: it is an idempotent retry or reconciliation of the existing phase and MUST reuse the AP2-6 idempotency key, resume the existing provider operation or settlement when one is recoverable, and MUST NOT create or count another payment. Conflicting or multiply established stored bindings fail closed as `error`; a handler MUST NOT select one arbitrarily. Replay defence lives here, at the verifier — no content inside the checkout JWT can prevent replay of the JWT itself. Where the implementer also mints the checkout JWT (closed-loop or test deployments, not a live AP2 provider), the JWT payload SHOULD carry standard single-use claims (e.g. `jti`, `exp`) so distinct sessions yield distinct JWTs; against a live AP2 provider the checkout JWT is outside DACS's jurisdiction and this is not required.

**Failure modes.**

- CheckoutMandate or PaymentMandate absent/unverifiable, merchant signature violates the DACS profile, malformed/unsupported `_sd_alg`, malformed compact checkout JWS, or `transaction_id` mismatch → `permanent` before AP2-7 reservation or any provider side effect
- payer’s mandate authorisation refused → `counterparty`
- provider declines the underlying payment (insufficient funds, fraud check, regulatory hold) → `permanent`
- provider endpoint unavailable → `transient`
- mandate revoked between authorisation and submission → `counterparty`
- AP2-2 attested fetch unreachable (SR-3 or the provider status endpoint unavailable) → `transient`
- AP2-2 attested status reports a terminal non-captured state, or an amount/currency mismatch against the agreement → `permanent`

#### 9.5.7 pay-x402

Payment via an x402 HTTP 402 challenge. Current sessions use the negotiated,
provider-neutral `x402:protocol` rail. The frozen static `x402:default` path is
retained only for already-pinned sessions and historical evidence replay under
XN-10.

**Negotiated protocol procedure.**

1. Resolve and pin the `x402:protocol` definition and the exact complete
   `X402ProtocolPaymentRailRef` selected by the agreement. Apply XN-2 and XN-3
   before contacting the resource.
2. Issue the agreement-bound request with no payment authorization. Require a
   version-shaped HTTP 402 `PaymentRequired`, retain the complete object as
   received, and apply XN-4 through XN-6. No wallet or signing operation may occur before all of those gates pass.
3. Construct the x402 `PaymentPayload` from the one matched requirement. For an
   EIP-3009 or Permit2 authorization, apply the applicable SB-3 binding. Submit
   the paid request with the same method, URL, and body bytes as the unpaid
   request.
4. Decode the version-selected settlement-response header, retain the complete
   response object, compute both XN-7 hashes, and reconcile its version,
   network, transaction, payer, and exact-scheme amount with the selected
   requirement and agreement.
5. Independently verify the adapter-canonical settlement transaction/event and
   finality under XN-8/XN-9. Only then construct success-outcome
   `SettlementEvidence` with one `x402-protocol` reference and
   `settlementFinality.model == "scheme-network-finality"`; anchor via SR-2 and
   return success. If payment may have been submitted but verification is
   unavailable, retain a reconciliation-pending state and apply XN-11; do not
   infer that another authorization is safe.

- **(XN-2) Signed selection identity and shape.** A listing MAY contain
  multiple canonically distinct `X402ProtocolPaymentRailRef` values. It MUST
  reject duplicate full-reference CORE §B.2 JCS bytes under DACS-1 LRR-1. The
  committed agreement MUST select exactly one listing member by equality of the
  complete canonical `PaymentRailRef`, including `railVersion` and every
  `parameters` member; `railId` is only the handler dispatch key. Selection of
  the first matching `railId`, parameter merging, defaults supplied after
  signature, or a resolution-relevant value outside the enclosing agreement's
  signed scope is non-conforming. A `StaticPaymentRailRef` whose `railId` is
  `x402:protocol` is malformed; a consumer MUST NOT use the static arm's
  optional fields to bypass the negotiated shape. A current `x402:protocol`
  session MUST use a `PayeeBoundAgreementDocument`; the agreement buyer and
  seller MUST each occur exactly once in `parties`, and the applicable
  `(railId, phaseIndex)` payout binding MUST satisfy PB-1. The request method
  MUST be a non-empty upper-case HTTP token. The URL MUST be an absolute HTTPS
  URL with a non-empty host and no userinfo or fragment and is compared as the
  exact signed string. A present `bodyHash` MUST be exactly 64 lower-case
  hexadecimal digits. The selection's
  `x402Version` and `maxTimeoutSeconds` MUST be positive safe integers;
  `assetDecimals` MUST be a non-negative safe integer; `scheme`, `network`,
  `asset`, and `currency` MUST be non-empty strings; `network` MUST have the
  CAIP-2 `namespace:reference` form; and `extra` plus any
  `paymentRequiredExtensions` MUST be JSON objects valid under CORE §B.2.

- **(XN-3) Capability and operator separation.** Before the unpaid request, the
  executing implementation MUST establish local support for the exact
  `(x402Version, scheme, network)` and for a DACS scheme-binding profile capable
  of independently verifying that network. Unsupported local capability is
  `ok: false` / `errorClass: "permanent"` with reason
  `x402-capability-unsupported`; it is not proof that the signed offer or
  provider is globally invalid. Facilitator endpoints and credentials, wallet
  selection, RPC endpoints, API keys, and routing preferences MUST remain
  trusted local configuration. They MUST NOT be read from the global protocol
  definition, the selected rail reference, a PaymentRequired extension, a
  catalog, or another counterparty-controlled input, and changing them MUST NOT
  change `railId`, `railVersion`, or the agreement's selected requirement.

- **(XN-4) Exact challenge match.** The unpaid response MUST be an HTTP 402 with
  a well-formed `PaymentRequired` for the signed `x402Version`. The version
  adapter preserves the complete raw object for hashing, and exposes one
  comparison surface: v2 uses top-level `resource.url` and
  `PaymentRequirements.amount`; v1 maps the selected member's `resource` to the
  URL and `maxAmountRequired` to `amount` without rewriting the retained object.
  `PaymentRequired.x402Version` and the effective resource URL MUST equal the
  signed selection. Exactly one `accepts` member MUST match the signed
  `scheme`, CAIP-2 `network`, `asset`, `maxTimeoutSeconds`, and complete
  CORE §B.2 JCS `extra` object, plus the amount and destination derived by XN-5.
  Zero or multiple matches, a non-parseable/non-version-shaped 402 body, a bare
  network label, or any mismatch MUST reject before authorization. For v2, the
  presence and complete JCS value of top-level `PaymentRequired.extensions`
  MUST equal `paymentRequiredExtensions`; omitted and `{}` are distinct. A v1
  selection MUST omit `paymentRequiredExtensions`.

- **(XN-5) Exact amount and signed parties.** v0.7 defines DACS settlement
  success only for `selection.scheme == "exact"`. The handler MUST require
  `selection.currency == agreement.terms.price.currency`, independently
  establish that `selection.assetDecimals` is correct for the selected asset
  through its scheme/network adapter, and convert the CD-1 agreement amount to
  atomic units by exact decimal shifting. Excess fractional precision,
  rounding, floating-point conversion, overflow, a non-canonical unsigned
  atomic amount, or inequality with the matched requirement's `amount` MUST
  reject before authorization. The matched requirement's `payTo` MUST equal the
  PB-1 payout binding for this `(x402:protocol, phaseIndex)`. The
  `PaymentPhaseInput` payer and payee MUST equal the signed agreement buyer and
  seller respectively. Before signing, the adapter MUST establish that the
  authorization payer is controlled by the buyer's pinned bundle/paying key;
  after settlement, it MUST independently establish that the authenticated
  event debits that payer and credits the signed `payTo` in the selected asset
  for exactly the selected atomic amount. An unsigned legacy
  `PaymentPhaseInput.payee.payeeAddress`, server-returned payer/payee, or local
  wallet default cannot substitute for these signed bindings.

- **(XN-6) Complete extension and request binding.** The handler MUST preserve
  and compare the complete `PaymentRequirements.extra` and top-level
  `PaymentRequired.extensions` objects under XN-4. It MUST validate every
  extension or `extra` member that can influence authorization, request
  execution, settlement, destination, fees, or follow-on actions; an
  action-bearing member unsupported by the selected adapter MUST reject before
  signing. Descriptive members MAY be ignored semantically but remain bound by
  whole-object equality and the XN-7 challenge hash. If `request.bodyHash` is
  present, both unpaid and paid requests MUST carry identical body bytes whose
  SHA-256 equals it; if absent, both requests MUST have no body. Redirects MUST
  NOT be followed, and an effective method, URL, or body change requires a new
  listing/agreement rather than an override. The paid request MUST differ from
  the validated unpaid request only by x402 authorization transport fields and
  other version-defined payment headers.

- **(XN-7) Numeric-version evidence and canonical commitments.** Before
  hashing either received object, apply CORE §B.2 CF-1 recursively to every
  JSON string value, then compute:

  ```text
  paymentRequiredHash = lowerhex(SHA-256(UTF8(JCS(nfcPaymentRequired))))
  paymentReceiptHash  = lowerhex(SHA-256(UTF8(JCS(nfcSettlementResponse))))
  ```

  Both values MUST be exactly 64 lower-case hexadecimal digits without `0x`.
  The preimages are the complete version-shaped decoded objects, including
  extensions and unrecognised members—not base64/header text, a normalized
  cross-version projection, a subset of fields, a transaction receipt, or the
  transaction identifier alone. Numeric `x402Version` in the
  `x402-protocol` reference MUST equal the signed selection and the received
  `PaymentRequired.x402Version`; the settlement response is selected by that
  version's exact header/schema and does not acquire a synthetic version
  member. `httpResource` MUST equal the exact signed URL;
  `settlementNetwork` and `settlementTransaction` MUST equal the successful
  response and the selected network. Version 1 selects
  `X-PAYMENT-RESPONSE`; version 2 selects `PAYMENT-RESPONSE`; an unsupported
  version/header/schema, invalid base64/JSON, non-success response, missing
  complete object, non-canonical stored hash, or recomputed mismatch MUST NOT
  produce success evidence.

- **(XN-8) Independent success floor.** A success-outcome `pay-x402` record
  using `x402:protocol` MUST carry exactly one `x402-protocol` reference and a
  `scheme-network-finality` record whose network and scheme equal the signed
  selection. The verifier MUST resolve independently authenticated
  scheme/network data for `settlementTransaction`, require the signed
  adapter-canonical `settlementEvent` to identify exactly one finalized payment
  event, and re-establish the XN-5 payer, payee, asset, amount, authorization,
  and finality predicates. Missing authenticated data or a locally unsupported
  network/profile is `indeterminate`; a resolved contradiction is `fail`; a
  malformed coordinate is `error`. A server/facilitator response, its hash, an
  ordinary HTTP acknowledgement, or a server-signed receipt extension alone
  MUST NOT produce `SettlementEvidence.outcome: "success"`, authorize delivery,
  satisfy a terminal bundle, or contribute payment volume/reputation. Such an
  acknowledgement MAY be retained outside successful SettlementEvidence as
  explicitly lower-assurance diagnostic material; it is not independent
  settlement proof.

- **(XN-9) Open protocol, defined scheme bindings.** DACS does not register or
  approve providers, facilitators, assets, or networks for `x402:protocol`.
  The `exact` scheme binding is defined by XN-4..XN-8 for any network whose
  local adapter can independently establish asset metadata, authorization,
  transfer semantics, an adapter-canonical event coordinate, and finality.
  `upto`, `batch-settlement`, and every other scheme remain protocol-valid but
  MUST NOT produce DACS settlement success until a DACS binding profile defines
  price/maximum versus actual charge, authorization, event identity, and
  eventual finality. `batch-settlement` commitment acceptance is never eventual
  financial settlement. When Permit2 or EIP-3009 is the selected authorization
  form, its SB-3 profile remains mandatory. Another authorization form uses its
  defined binding when one exists; otherwise the evidence MUST NOT claim SB-3,
  though independently verified SB-1/SB-2 baseline evidence may still satisfy
  the `exact` profile.

- **(XN-10) Legacy boundary and disabled default.** The registry steward MUST
  publish a superseding `x402:default` revision with
  `availability: "disabled"`, `governance.deprecated: true`, and a
  `deprecationReason` directing new sessions to `x402:protocol`. Regardless of
  a requested legacy `railVersion` or that version's historical `availability`,
  a v0.7 orchestrator MUST NOT start a new or replacement session with
  `railId == "x402:default"`; pinning the earlier live revision is not a bypass.
  RAV-R2 enforces the same result for the superseding disabled revision. An
  already pinned in-flight session MAY finish under its pinned definition, and
  historical evidence remains verified over its original signed bytes.
  `x402:default` evidence uses the frozen `x402`/`x402-event` arms and string
  `protocolVersion` under X402-1..X402-4; `x402:protocol` evidence MUST use the
  distinct `x402-protocol` arm and numeric `x402Version` and MUST NOT emit
  `protocolVersion`. The semantic versions `"2"` and `2` may identify the same
  upstream version only for version selection; a verifier MUST NOT rewrite,
  re-canonicalise, re-hash, or re-sign committed legacy evidence.

- **(XN-11) Retry and reconciliation safety.** After an authorization may have
  been submitted, timeout, response loss, unavailable ledger data, or an
  indeterminate adapter result MUST NOT authorize another payment. The handler
  MUST reconcile using the original `(jobId, phaseIndex)`, selected complete
  requirement, scheme-defined authorization identity, and any known
  transaction/event reference. A proven finalized match resumes evidence
  construction and PC-7 catch-up; a proven terminal non-settlement follows the
  scheme profile; an indeterminate result stays pending. The handler MUST NOT
  switch provider, facilitator, scheme, network, asset, resource, destination,
  or authorization identity inside the session and MUST NOT manufacture a new
  requirement or nonce to escape reconciliation.

**Legacy static procedure and receipt rules.** The following frozen rules apply
only to an already-pinned `x402:default` session or historical evidence. They do
not authorize a new session under XN-10.

1. Resolve the pinned static rail and verify `network.kind == "x402-resource"`.
2. Construct the x402 payment payload and apply the applicable SB-3 binding;
   submit the request to the pinned resource.
3. Receive the paid resource response and apply X402-1..X402-4.
4. Identify the exact settling transfer event and construct an `x402-event`
   reference; anchor via SR-2 and return success.

- **(X402-1) Versioned receipt selection.** For a success-outcome legacy record, `protocolVersion` MUST be the negotiated x402 version as a minimal unsigned-decimal string. Version `"1"` selects `X-PAYMENT-RESPONSE`; version `"2"` selects `PAYMENT-RESPONSE`. The handler MUST base64-decode the selected header, parse its JSON as that version's `SettlementResponse`, require `success == true`, and retain every received member, including `extensions` and unrecognised members. A handler MUST refuse a protocol version whose settlement-response header or schema it does not implement.
- **(X402-2) Canonical receipt hash.** Before hashing, the handler MUST apply CORE §B.2 CF-1 to the complete X402-1 object. It MUST recursively NFC-normalise every JSON string value. It MUST then set `paymentReceiptHash = lowerhex(SHA-256(UTF8(JCS(nfcSettlementResponse))))`, where `nfcSettlementResponse` is that normalised object and JCS is RFC 8785. The value MUST be exactly 64 lower-case hexadecimal digits without `0x`. The base64 header text, decoded non-canonical JSON bytes, an on-chain transaction receipt, and `settlementTxHash` alone are not conforming preimages.
- **(X402-3) Receipt/evidence consistency.** A successful response's `transaction` MUST equal `settlementTxHash` when that field is recorded. Its `network` MUST map to `chainId` when that field is recorded: directly from v2 `eip155:{chainId}`, or through the registered v1 legacy-network mapping. A mismatch MUST reject the evidence; it MUST NOT be repaired by hashing a different receipt interpretation.
- **(X402-4) Verification and invalid input.** A verifier presented with the response header MUST independently apply X402-1 and X402-2 and compare the resulting 32 bytes. Invalid base64, invalid JSON/schema, a non-success response, a non-canonical stored hash, or a hash mismatch MUST be rejected. A handler without the complete successful response object MUST NOT emit success-outcome legacy `pay-x402` evidence.

> **Note (non-normative) — what pay-x402 adds beyond bare x402.** A direct x402 transaction produces a receipt the client and server hold off-chain; there is no anchored audit trail and the transaction is not bound to a DACS session. pay-x402 binds the x402 transaction into a DACS session by:
>
> - (a) producing a SettlementEvidence record carrying the on-chain `settlementTxHash` (chain-verifiable against the settlement chain, like the `evm` rail) plus the x402 receipt hash, anchored via SR-2 — the receipt itself remains off-chain, but its hash, the settlement tx, and the protocol version become part of the on-chain bundle;
> - (b) tying the x402 transaction to a specific DACS-3 AgreementArtifact via the session’s jobId;
> - (c) making the x402 transaction available to DACS-5 reputation derivation and ERC-8004 publication.
>
> For pure HTTP-402 use cases that do not need a session bundle, bare x402 is appropriate; pay-x402 is the right wrapper when the x402 transaction participates in a multi-stage agent commerce lifecycle.

> **Note (non-normative) — why JCS.** x402 transports a JSON object in base64 but does not make one language's emitted property order, whitespace, escaping, or base64 spelling authoritative. X402-2 makes those transport differences hash-identical while preserving every semantic receipt member. The off-chain receipt remains the material disclosed to a receipt verifier; the on-chain DACS field is its commitment.

**Failure modes.**

- challenge is malformed or differs from the signed selection before authorization → `counterparty`
- local version/scheme/network capability is unsupported before authorization → `permanent` with `x402-capability-unsupported`, not `counterparty`
- server-side x402 endpoint rejects a conforming submitted payment → `counterparty`
- HTTP error after payment submitted → `transient` (retry only through the rail's idempotency/reconciliation path; for EIP-3009, use the derived-nonce rule below)
- malformed, non-success, hash-mismatched, or transaction/network-inconsistent settlement response → `permanent`
- signed receipt extension present but its signature invalid → `permanent`
- independent settlement verification unavailable after possible submission → reconciliation-pending / `indeterminate`; never a second authorization and never success
- EIP-3009 nonce already used or cancelled and not reconcilable to this phase's completed transfer → `permanent`

#### 9.5.8 Session-bound settlement evidence (SB-1..SB-3)

A cross-chain HTLC settlement is bound to its session by the jobId-derived preimage (HTLC-5), but the single-chain / provider rails (`pay-evm-erc20`, `pay-solana-spl`, `pay-ap2`, `pay-x402`) carry a `ChainTxRef` with no session binding — so a record could cite an unrelated transfer of the agreed amount to the payee (*coincidental-citation*), or reuse one settlement across sessions (*cross-session double-count*).

- **(SB-1) Signed event identity and binding key.** A `SettlementEvidence` record's `paymentTxRefs` claim that the referenced transaction event(s) settled **this** `(jobId, phaseIndex)`, where `phaseIndex` is the phase's `BundlePhaseEntry.index` — required because a repeated phase type (PIPE-5) settles the same `phase` more than once. `phaseIndex` is **not a new evidence field**: it is recovered from the §9.5.2 payment-evidence anchor address the record is published at (`dacs4:payment:{jobId}:{railId}:{phaseIndex}`), so two consumers key a settlement identically.

  Before projecting any SB-1 identity, a consumer MUST compare the complete PC-2 logical-address tuple, not only its terminal phase-index segment. The address `jobId` MUST equal the signed `SettlementEvidence.jobId`; the CF-4-decoded `railId` MUST equal the rail selected by the authenticated agreement and phase context; and `phaseIndex` MUST equal that pay phase's authenticated `BundlePhaseEntry.index`. The optional `:resolved` segment does not change this tuple and is valid only for an ST-8 superseding record. A well-formed tuple mismatch is `fail` and the evidence MUST be rejected before projection. A malformed or non-canonical address, including a non-CF-4 rail segment, is `error`. The evidence signature, a matching transaction event, an outer SR-2 receipt, or a caller/indexer annotation MUST NOT substitute for this address-binding check.

  For a success-outcome `pay-evm-erc20`, `pay-solana-spl`, or legacy-static
  on-chain `pay-x402` record produced under DACS-4 v0.6 or later, the applicable
  event/instruction index MUST be inside the signed `SettlementEvidence` scope.
  The producer MUST use `evm-event`, `solana-instruction`, or `x402-event`,
  respectively. It MUST NOT emit the legacy `evm`, `solana`, or `x402` arm for
  new success evidence on those paths. A DACS-4 v0.7 `x402:protocol` producer
  instead MUST use `x402-protocol`; its signed `settlementEvent` is the complete
  adapter-canonical native SB-1 event identifier required by XN-8/XN-9. The
  distinct `kind` values are additive type boundaries: a reader that does not
  implement one rejects it as unsupported before acting, and a current reader
  MUST NOT strip or substitute the discriminator and retry verification as
  another arm.

  Before accepting the evidence, a verifier MUST resolve independently authenticated ledger data at the referenced transaction and establish that the signed `logIndex` or `instructionIndex` selects the transfer committed by the evidence and agreement: the selected asset/program or token contract, payer, agreement-authorized payee destination (PB-1 when applicable), and exact `paymentAmount` MUST match. For legacy static x402, X402-1..X402-4 MUST additionally bind the same transaction and network to the signed receipt. For `x402:protocol`, XN-2..XN-9 MUST bind the signed selection, challenge, response, complete `settlementEvent`, and independently verified finality. A missing ledger result is `indeterminate`; a resolved index/event whose transfer does not match is `fail`; a missing or malformed signed coordinate/event identifier is `error`. An event index or identifier supplied outside the signed evidence is never authority and MUST NOT repair a current arm.

  After signature, shape, anchor-address, and ledger-event verification, the consumer deterministically projects the verified signed arm to `settlement-tx-id`:

  - **`evm-event` / `x402-event`:** `evm:{chainId}:{txHash}:{logIndex}` (for `x402-event`, `txHash` is `settlementTxHash`)
  - **`solana-instruction`:** `solana:{cluster}:{signature}:{instructionIndex}`
  - **`x402-protocol`:** the verified signed `settlementEvent` string. The
    applicable scheme/network adapter MUST emit the same native DACS event key
    as a direct rail over that ledger: EIP-155 exact uses the `evm:` form above;
    Solana exact uses the `solana:` form above. A future ledger profile MUST
    define a canonical collision-resistant native namespace and MUST define
    cross-rail alias collapse before it can produce success.
  - **demos (`pay-dem`):** `demos:{txHash}` — a single native transfer is one settlement, so no event/instruction index is needed (§9.5.9)

  The key is the uniqueness defence, so it MUST be byte-identical across implementations. `chainId`, `logIndex`, and `instructionIndex` MUST be non-negative safe integers and are rendered as minimal base-10 ASCII (`chainId` MUST additionally be greater than zero). EVM hashes are rendered as exactly 64 lower-case hexadecimal digits without `0x`; a verified legacy spelling with `0x` or upper-case characters collapses to that form. A current producer MUST emit the canonical spelling. A Solana signature is base58 that MUST decode to exactly 64 bytes. An `x402-protocol.settlementEvent` MUST already be in the adapter's canonical producer form; a spelling that normalizes to another native key is non-canonical and yields `error`, not a second identity. A reference that cannot produce its applicable canonical form is malformed and yields `error`; it MUST NOT mint a distinct key. Event/instruction-level identity is required for batched transfers and for ERC-4337, where the settling `Transfer(from=payerAccount,…)` is one event among several in a bundler transaction.

  **Legacy read/replay.** The `evm`, `solana`, and `x402` arms are frozen historical shapes; current consumers continue to verify their original `dacs-evidence:v1:` signed bytes and MUST NOT rewrite or re-sign them. Because those arms do not sign an event coordinate, a consumer may derive an event-level key only by resolving independently authenticated ledger data and applying the same asset, payer, payee, amount, and x402 receipt checks above. Exactly one matching event permits that event's authenticated index to be projected. No matching event is `fail`; unavailable ledger data or more than one matching event is `indeterminate`. A caller-supplied index, cache annotation, or indexer field that is not itself authenticated ledger evidence MUST be ignored and cannot disambiguate the record. Legacy evidence that remains `indeterminate` is replayable as history but is not countable under SB-2 and cannot satisfy a final verification gate.
- **(SB-2) Cross-session uniqueness.** A consumer that aggregates settlement evidence across sessions — including the DACS-5 reputation reconciliation (§10.5.1) — MUST NOT count one `settlement-tx-id` under more than one `(jobId, phaseIndex)`. A second binding of the same id is rejected for the later record (earlier `observedAt` wins; ties broken by lower evidence hash). The check is scoped to the consumer's own evidence set; a global cross-network uniqueness index is out of scope. This closes the double-count threat on every rail with no on-chain change.
- **(SB-3) On-chain session binding (optional, per rail).** A rail MAY bind `jobId` into its settlement-side record, closing coincidental-citation as well. v0.2 defines one for `pay-x402`; v0.3 adds the `pay-ap2` provider-metadata binding (AP2-1, §9.5.6: `dacs_job_id` in the provider-side payment metadata, checked in the AP2-2 attested status response). For `pay-x402` the binding surface differs by authorization type:
  - **Permit2** — the handler MUST place `jobId` in the signed `witness` field; the verifier MUST check it equals `evidence.jobId`.
  - **EIP-3009** (`transferWithAuthorization`) — there is no arbitrary signed field, so the handler MUST derive the authorization's `bytes32 nonce` exactly as follows:

    ```text
    preimage = UTF8("dacs-sb3:v1:")
               || UTF8(NFC(jobId))
               || 0x3a
               || ASCII(decimal(phaseIndex))
    nonceBytes = SHA-256(preimage)
    ```

    `UTF8` is UTF-8 without a byte-order mark. `0x3a` is the single ASCII colon byte. `decimal(phaseIndex)` is the non-negative integer's minimal base-10 ASCII representation (`0` for zero; no sign and no leading zeroes). `nonceBytes` is used directly as the 32-byte EIP-3009 value; when a DACS implementation serialises that value as text it MUST use `0x` followed by exactly 64 lower-case hexadecimal digits. The handler MUST use this derived value and MUST NOT substitute a random or provider-generated nonce. The verifier MUST recover `phaseIndex` from the SB-1 payment-evidence anchor, independently recompute `nonceBytes` from `evidence.jobId`, and compare the decoded 32 bytes. A well-formed nonce that differs is a **present-and-mismatches** rejection under the branch rule below; a malformed nonce encoding is `error`.

    The derived nonce is also the retry identity. After an indeterminate submission, the handler MUST reconcile the token contract's authorization state before submitting again. If chain evidence proves that the same authorization and transfer parameters already settled this `(jobId, phaseIndex)`, the handler MUST resume with that existing settlement reference rather than charge again. A nonce that is used or cancelled but cannot be reconciled to that completed transfer MUST fail closed; the handler MUST NOT generate a fresh nonce for the same `(jobId, phaseIndex)`.

  Either way the binding rides inside the payer-signed authorization (no new contract). For a smart-account (ERC-4337) payer the signature is an ERC-1271 contract signature (`isValidSignature`) rather than an EOA signature; a verifier MUST accept either, selecting by whether the payer address has on-chain code as of the settlement transaction's block.

  When a rail declares a binding, the verifier resolves it in three branches:
  - **present and matches** → the binding guarantee is satisfied;
  - **present and mismatches** → reject the evidence;
  - **absent or unverifiable** (the binding is missing, or the on-chain check cannot complete — RPC unavailable, pruned history, unresolvable `isValidSignature`) → the binding guarantee is **not established** for that record: fall back to the SB-1 + SB-2 + §9.5.1 amount/payee posture of an unbound rail. This is **never** an automatic accept and **never** a hard fail — mirroring the §7.5.1 unresolvable-signer → `indeterminate` rule and the ST-8 `settle-asymmetric` discipline, so a transient verification outage does not become a reputation event.

  Log-forwarder (evm) and Memo (solana) bindings are anticipated per-rail follow-ons. For a `PayeeBoundAgreementDocument`, a rail with no declared binding relies on SB-1 + SB-2 with the §9.5.1 amount/payee match — where the payee side of that match is the PB-1 agreement-bound destination, not a free-standing evidence field — and is weaker against coincidental-citation; a verifier SHOULD prefer a bound rail for high-value settlements. A legacy `AgreementDocument` provides no PB-1 destination guarantee.

> **Note (non-normative).** SB-2 is structurally the §B.8 SN-4 single-use marker with the scope inverted — a settlement-tx-id is single-use per session as a session nonce is.

> **Note (non-normative — x402 implementation boundary).** An EIP-3009 facilitator receives an already-signed opaque `bytes32` nonce; the derivation above does not require facilitator changes. Generic buyer clients that always generate their own random nonce need a DACS-specific payment-scheme adapter (or equivalent caller-controlled authorization construction) to satisfy SB-3.

#### 9.5.9 pay-dem

Native-DEM transfer on the Demos substrate: settle the agreed price in DEM directly, with no foreign chain, cross-chain primitive, or provider. A `pay-dem` settlement is to a **single payee**.

**Procedure.**

1. Resolve rail; verify `asset.kind == "native-dem"` and `network.kind == "demos"`.
2. Verify `amount.currency == "DEM"`; convert to OS base units (`1 DEM = 10^9 OS`, integer arithmetic, no float).
3. Construct a native transfer to `payee.payeeAddress` for the OS amount (the substrate's native `send`).
4. Submit via the payer's wallet (or via SR-3 proxy attestation when the wallet runs server-side); wait for inclusion.
5. On the transaction reaching the terminal **`included`** state (BFT finality, below), construct SettlementEvidence with `txRef` of kind `demos` (`txHash` + `blockNumber`) and `settlementFinality.model == "bft-final"`; anchor via SR-2; return success.

**Finality.** Demos has **deterministic BFT finality**: a transaction reaching `included` in a forged block is final — there is no reorg or confirmation-depth wait. The evidence cites `{ txHash, blockNumber }` against the `bft-final` model (§9.7); `block-depth` / `commitment-level` do not apply (no meaningful depth or commitment tier exists). A transaction reaching the terminal `failed` state did not settle.

**Failure modes.**

- payer DEM balance insufficient → `permanent`
- transaction reaches terminal `failed` on-chain → `permanent`
- Demos node / RPC unreachable → `substrate` (ST-7 pause; `failed-substrate` if unrecovered)
- payer-side wallet rejects / declines to sign → `counterparty`

**Trust model.** Settlement is secured by **Demos consensus itself** — a rotating validator shard under 2/3 BFT — i.e. "the operator is the substrate," not an external bridge, facilitator, or provider. Unlike every other v0.2 rail, `pay-dem` introduces no foreign-chain or third-party trust.

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

**Private delivery (`accessModel`).** A `storage-program` deliverable MAY be delivered privately when `deliverable.accessModel` (declared in the agreement, hash-bound per §8.5.2) is non-`public`:
- `buyer-only` — the Storage Program is written with a `restricted` ACL listing the buyer's address in `allowed`; reads are node-enforced.
- `encrypt-to-buyer` — the payload is sealed to the buyer's encryption key and the ciphertext anchored (which MAY itself be public, since only the holder can open it).

- (DV-1) **Content-hash invariant.** `deliverableContentHash` MUST be the sha256 of the **cleartext** canonical payload — byte-identical across all `accessModel` values, never the ciphertext — so settlement evidence (§9.7) binds the same digest regardless of access mode.
- (DV-2) **Access-mode fidelity.** The delivered access mode MUST match the agreement's declared `accessModel`. A consumer resolving a declared non-`public` deliverable as delivered `public` MUST emit `indeterminate` (a provenanced confidentiality-downgrade flag), never `pass`; over-provision (declared `public`, delivered private) is NOT a violation.
- (DV-3) **Buyer binding.** Under `buyer-only`, the ACL `allowed` entry MUST be the buyer address resolved from the agreement-bound buyer `AgreementParty` (§8.5), not a separately-presented address. Under `encrypt-to-buyer`, the payload MUST be sealed to that party's `AgreementParty.encryptionKey`.
- (DV-4) **ACL-mutation auditability.** Under `buyer-only` the owner CAN later mutate the ACL (add/remove readers). Each mutation SHOULD be recorded as an anchored, signed record so the buyer can detect a post-delivery reader addition — and MUST be recorded for a `credentialRef`-backed entitlement (§9.6.2).

> **Note (non-normative — confidentiality tiers).** `buyer-only` is node-enforced: confidential against the public and other users, but the owner can re-open the ACL and node operators can see the bytes ("private until the owner changes the ACL"). `encrypt-to-buyer` is a cryptographic one-shot seal (operator-blind, non-revocable). The normative envelope is the native post-quantum `UnifiedCrypto` (`ml-kem-aes`); an external envelope (HPKE/age) MAY be used only as a cross-substrate profile and is classical-not-PQC.

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

  credentialRef?: { ref: AttestationRef; accessModel: "buyer-only" | "encrypt-to-buyer" }   // optional access credential delivered via §9.6.1 private delivery; default buyer-only (the only revocable mode)

  signature: ComponentSignature

}
```

4. Seller signs the EntitlementRecord over the domain-separated payload "dacs-entitlement:v1:" || sha256(canonical_JCS(record_without_signature)) per §B.7.
5. Seller anchors the EntitlementRecord via SR-2 at dacs4:entitlement:{jobId}:{renewalSeq}, with renewalSeq = 0 for the original grant.
6. Seller constructs SettlementEvidence; returns success.

**Exercising the entitlement.** Buyer presents the EntitlementRecord (or its hash + anchor) at the record's `serviceEndpoint` to access the entitled service. The record is a self-contained receipt — it names the grantee, the scope, the validity window, and where to exercise it — so the buyer needs nothing beyond the record itself. The service endpoint verifies the signature and anchor, checks now is within [startsAt, endsAt], and serves accordingly.

> **Note (non-normative).** `serviceEndpoint` carries *where* to access. *How* an access **credential / token** is delivered (vs. presenting the record itself as the bearer proof) is the optional `credentialRef` defined below — delivered via §9.6.1 private delivery (DV-5 / DV-6).

**Renewal.** If renewable: true and the buyer re-pays before endsAt, the seller MAY issue a new EntitlementRecord with extended endsAt, the same jobId, and an **incremented renewalSeq**, anchored at dacs4:entitlement:{jobId}:{renewalSeq}. The renewalSeq discriminator gives each renewal a distinct SR-2 address so it does not collide with or overwrite the original grant (the address is otherwise fully determined by jobId on immutable content-addressed storage). A consumer resolves the current grant by reading the highest renewalSeq present for the jobId.

**Access-credential handover (`credentialRef`).** An EntitlementRecord MAY carry a `credentialRef` — an access credential (e.g. an API key / token) delivered to the grantee via §9.6.1 private delivery, default `buyer-only` (the only mode that can be revoked when the entitlement ends). It is private content, so it follows DV-1..DV-4. Because the credential lives behind a mutable ACL while the entitlement's validity is its signed window, the two can diverge — so the verification questions MUST be kept separate:

- (DV-5) **Three gates, never collapsed.** For a `credentialRef` entitlement:
  - **delivered** — `SettlementEvidence` binds the `credentialRef` and the credential's cleartext digest (DV-1) at the settled `renewalSeq`. Settlement evidence asserts ONLY this.
  - **valid** — the signed `[startsAt, endsAt]` window at the highest `renewalSeq`. Read from the record, NOT from the ACL.
  - **readable** — the ACL read at access time.
  `SettlementEvidence` MUST NOT assert `valid` or `readable`: a credential being *delivered* is neither the entitlement being *valid* nor the credential being *currently readable*.
- (DV-6) **Readability verdict (do-not-collapse).** A consumer checking whether the buyer can currently read the credential MUST distinguish: in `allowed` and not blacklisted → **readable**; entitlement window lapsed → **clean negative** (lifecycle); buyer dropped from `allowed` / blacklisted → **ACL-dropped (channel-unreadable)**; ACL or storage unresolvable → **`indeterminate`** — a transient outage MUST NOT be read as channel-unreadable. An ACL-drop is **channel-provable** (the anchored ACL mutation, DV-4) and proves the credential is unreadable **via storage** — it is NOT by itself credential **invalidation**: a bearer credential the grantee already fetched keeps authenticating at the `serviceEndpoint` until rotated. Full revocation therefore requires **endpoint-side credential rotation** (endpoint-attested, off-DACS-scope) in addition to the ACL-drop; the anchored trail proves only the channel half.

#### 9.6.3 deliver-attested-payload

Seller delivers a payload whose authenticity is attested via DACS-2 (e.g., the payload is a TLS-attested data fetch).

The verification method supplies the native proof; DACS supplies the commerce
binding. A DACS-2 claim `VerifyResult` is not that binding: it attests a
`(scheme, identifier)` claim and does not carry the delivered payload digest,
agreement hash, or DeliverableSpec hash. `deliver-attested-payload` therefore
uses the distinct `PayloadAttestationRecord` below. The record composes the
selected DACS-2 `VerificationMethod` without reinterpreting a claim
`VerifyResult`.

```
type PayloadAttestationRecord = {

  payloadAttestationVersion: "1"              // structural discriminator; never resultVersion or evidenceVersion

  jobId: string

  agreementHash: string                       // exact committed AgreementArtifact hash

  deliverableSpecHash: string                 // hash of the signed listing's complete DeliverableSpec; equals agreement.terms.deliverable.hash

  payloadFormat: string                       // equals the signed attested-payload DeliverableSpec.payloadFormat

  payloadContentHash: string                  // sha256 hex of the exact cleartext payload bytes delivered to the buyer

  verificationMethod: VerificationMethod["kind"]

  verificationMethodHash: string              // sha256 hex of RFC 8785 JCS over the complete signed-listing verificationMethod object

  attempt: number                             // non-negative integer; starts at 0 and increments for a new method invocation

  decision: "pass" | "fail" | "indeterminate" | "error"

  reason: string

  methodEvidenceRef?: AttestationRef           // REQUIRED for pass; MAY carry partial/native evidence for fail, indeterminate, or error

  methodTransactionRef?: { kind: string; value: string }   // REQUIRED when the method binding identifies an authoritative native transaction (DAHR profile: demos web2Request txHash)

  verifiedAt: number

  signature: ComponentSignature               // verifier that executed/re-derived the selected method; it MAY be the seller, but the method proof remains independently checked

}
```

The record follows the CORE §B.2 canonical-form template, omitting only
`signature`. Its content hash is `payload_attestation_hash`; the signature is:

```
signed_bytes := "dacs-payload-attestation:v1:" || payload_attestation_hash
```

It is anchored via SR-2 at the logical address
`dacs4:payload-attestation:{jobId}:{verificationMethodHash}:{attempt}`. The
method's native evidence remains separately addressable through
`methodEvidenceRef`; the payload itself is stored at
`dacs4:deliverable:{jobId}` and is bound by `payloadContentHash`.

**Payload-attestation rules.**

- (DPA-1) **Listing/phase coherence.** Before a session starts, a listing whose
  pipeline contains `deliver-attested-payload` MUST resolve its signed
  `offering.deliverable` and verify that it has `kind == "attested-payload"` and
  a present, well-formed `verificationMethod`. The complete method object MUST
  describe a supported method capable of binding the exact delivered payload
  bytes. Missing, malformed, or locally unsupported configuration makes the
  listing unfulfillable and the reader MUST reject it before any payment or
  irreversible effect. A temporary failure while resolving a method dependency
  is `indeterminate`/`error` under the method rules, never permission to omit
  attestation.
- (DPA-2) **Exact-byte digest.** `payloadContentHash` is sha256 over the exact
  cleartext bytes the buyer receives and MUST equal
  `SettlementEvidence.deliverableContentHash`. `payloadFormat` labels those
  bytes; it does not silently transform them. In particular,
  `application/json` is not automatically reserialised as JCS. A profile that
  canonicalises or transforms a payload MUST do so before verification and
  delivery, then hash and deliver those same final bytes.
- (DPA-3) **Method proof.** A verifier MUST resolve `methodEvidenceRef`, verify
  its content hash and every method-/binding-specific signature, commitment,
  transaction, request, public input, or authority rule, and independently
  establish that the proof commits to `payloadContentHash`. A `pass` record
  MUST carry `methodEvidenceRef`. When the binding defines an authoritative
  transaction reference, the record MUST also carry `methodTransactionRef` and
  the verifier MUST authenticate that transaction at `included` or stronger.
  An ordinary HTTP/RPC acknowledgement is not method evidence.
- (DPA-4) **Commerce binding.** A consumer MUST resolve the signed listing and
  committed agreement, recompute the complete DeliverableSpec hash and
  verification-method hash, and require exact equality for `jobId`,
  `agreementHash`, `deliverableSpecHash`, `payloadFormat`,
  `verificationMethod`, and `verificationMethodHash`. It MUST verify the
  record signature against `signature.signer`; the signature identifies who
  performed or re-derived the verification, while trust in the payload still
  comes from the selected method evidence.
- (DPA-5) **Decision gate.** Only `decision == "pass"` can support successful
  `deliver-attested-payload` evidence. `fail`, `indeterminate`, and `error`
  MUST NOT be collapsed to pass. Retry behaviour follows the selected method's
  DACS-2 semantics; a retry increments `attempt` and emits a new immutable
  record rather than mutating an anchored result.
- (DPA-6) **Settlement-evidence closure.** A success-outcome
  `SettlementEvidence` whose phase is `deliver-attested-payload` MUST carry all
  three of `deliverableContentHash`, `deliverableAnchor`, and
  `attestationRef`. The `attestationRef` MUST resolve to a valid
  `PayloadAttestationRecord` with `decision == "pass"` and matching
  `jobId`/`payloadContentHash`; it points to that DACS record, not directly to
  a raw DAHR/TLSNotary/zkTLS response.
- (DPA-7) **Resolution outcomes.** A resolved contradiction (bad signature,
  wrong hash, wrong job/agreement/spec/method, missing required proof or
  transaction, or a conclusive non-pass decision) is `fail`. Inability to
  resolve an otherwise well-formed candidate or authenticate a newer native
  observation is `indeterminate` or `error` according to the selected method;
  it MUST NOT produce success evidence. A producer MAY anchor failure evidence
  for audit, but MUST classify the phase as failed.
- (DPA-8) **No self-assertion shortcut or replay.** The phase-orchestrator
  signature on `SettlementEvidence` is not payload-authenticity evidence and
  MUST NOT substitute for the DPA-3 method proof. A `self-signed`
  verification method remains permitted as its explicitly disclosed
  minimal-trust tier, but it still requires a real method proof and the complete
  payload-bound record. Binding `jobId`, `agreementHash`, and
  `deliverableSpecHash` makes a valid record for one session invalid in every
  other session.
- (DPA-9) **Minor-safe type distinction.** A consumer MUST classify a payload
  attestation by `payloadAttestationVersion` before interpreting any other
  field. A `PayloadAttestationRecord` MUST NOT carry `resultVersion` or
  `evidenceVersion`, and a DACS-2 `VerifyResult` or `SettlementEvidence` MUST
  NOT be coerced into this type. Unsupported payload-attestation versions are
  rejected as unsupported under CORE §11.1.2. The legacy optional spelling of
  `DeliverableSpec.verificationMethod` is retained for wire readability. The
  new artifact type is additive at the wire boundary, but DPA-1 is a behavioural
  compatibility and reject-timing change: a current reader rejects an
  attested-payload delivery phase with no method before session start and before
  payment, whereas a pre-DPA reader could accept it and discover the missing
  method only when delivery was attempted.

**Procedure.**

1. Apply DPA-1 and validate
   `agreement.terms.deliverable.deliverableType == "attested-payload"`.
2. Resolve the signed listing's complete DeliverableSpec and verify its hash
   equals `agreement.terms.deliverable.hash`.
3. Perform the underlying fetch/computation and obtain the final cleartext
   payload bytes.
4. Execute the declared verification method, retain its native evidence, and
   create, sign, and anchor a `PayloadAttestationRecord` satisfying DPA-2..DPA-5.
5. Write the exact payload bytes to `dacs4:deliverable:{jobId}`.
6. Construct `SettlementEvidence` satisfying DPA-6, anchor it via SR-2, and
   return success only after both records and the deliverable are independently
   resolvable. CORE §5.1 finalization remains required for terminal DACS-5
   bundle production.

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

  attestationRef?: AttestationRef              // for deliver-attested-payload success: REQUIRED and points to PayloadAttestationRecord (DPA-6)

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
       | "provider-receipt"     // Fiat (AP2). Historical pre-v0.6 x402 evidence may retain this model for replay; legacy-static on-chain x402 uses block-depth.
       | "scheme-network-finality"  // negotiated x402:protocol: finality independently verified by the selected DACS scheme/network adapter (XN-8/XN-9)
       | "htlc-reveal"          // Cross-chain HTLC: the payee's source-side claim (htlc-claim) landed against the revealed preimage — the decisive success tx; the payer's destination claim revealed the preimage earlier. (Model token retained as "htlc-reveal" for back-compat.)
       | "liquidity-tank"       // Native bridge liquidity-tank: bridge status transitions to "completed"
       | "bft-final"            // Native Demos (pay-dem, §9.5.9): the tx reached the terminal "included" state. Demos has deterministic BFT finality — inclusion is final, no block-depth or commitment tier applies.

  // For model == "block-depth": the number of blocks waited before declaring confirmation.
  // Sourced from rail.parameters.finalityBlocks; echoed here so the evidence record is self-describing.
  finalityBlocks?: number

  // For model == "commitment-level": the Solana commitment level accepted.
  // Sourced from rail.parameters.commitmentLevel; echoed here so the evidence record is self-describing.
  finalityCommitmentLevel?: "processed" | "confirmed" | "finalized"

  // REQUIRED iff model == "scheme-network-finality"; absent otherwise.
  // `bindingProfile` names DACS price/authorization/event/finality semantics,
  // not a provider or facilitator. v0.7 success uses dacs-x402-exact:v1.
  schemeNetworkFinality?: {
    scheme: string
    network: string
    bindingProfile: string
  }

  // Wall-clock unix ms at which the finality condition was observed to be met.
  // For block-depth: block timestamp of the Nth confirmation block.
  // For commitment-level: timestamp at which the commitment level was reached.
  // For provider-receipt / scheme-network-finality / htlc-reveal / liquidity-tank: timestamp of the decisive event
  // (for htlc-reveal: the payee's source-side htlc-claim confirmation — the same event that flips outcome to success).
  finalityObservedAt: number

}

type PaymentPhaseType = "pay-evm-erc20" | "pay-solana-spl"

                      | "pay-cross-chain-htlc" | "pay-cross-chain-liquidity-tank"

                      | "pay-ap2" | "pay-x402"

                      | "pay-dem"

type DeliveryPhaseType = "deliver-storage-program" | "deliver-entitlement" | "deliver-attested-payload"

type ComponentSignature = {

  algorithm: "ed25519" | "ecdsa-secp256k1" | "sr1-aggregate"

  signer: ClaimReference                       // primary claim of the signing party; per-artifact role is given in each record's inline comment (e.g. phase orchestrator, refunding party, grantor)

  value: string                                // unpadded Base64URL signature over the artifact payload (CORE §B.7 SIG-6)

}
```

Every anchored record that carries a `signature: ComponentSignature` field MUST populate it with this shape:

- `signer` MUST be a ClaimReference whose role is fixed by the artifact's inline comment;
- `value` MUST be the unpadded Base64URL signature over that artifact's domain-separated payload, validated per CORE §B.7 SIG-6.

`RailSignature.value` and every other DACS-4 signature-envelope `value` use the
same SIG-6 encoding. Protocol-specific transaction references retain their own
encodings, including the base58 Solana `ChainTxRef.signature`.

Per the §B.2 canonical-form template, omitting the `signature` field. `supersedesEvidenceRef`, when present, is part of the hashed canonical form (only `signature` is omitted), so an ST-8 `:resolved` record's hash binds the interim record it supersedes. The signature is computed over:
signed_bytes := "dacs-evidence:v1:" || evidence_hash

#### Final settlement data and propagation

An implementation may prepare an in-memory evidence draft before a payment rail returns its final transaction or receipt data. That draft is not a `SettlementEvidence` record and is outside the protocol until finalised as follows:

- (FP-1) A placeholder, predicted, or otherwise unconfirmed transaction or receipt value MUST NOT appear in a signed or SR-2-anchored success-outcome `SettlementEvidence`. A terminal `AttestationBundle` MUST NOT reference such a draft.
- (FP-2) After the rail returns its authoritative final values, the producer MUST construct a fresh `SettlementEvidence`, recompute every rail-defined derived field, recompute `evidence_hash`, sign the new `dacs-evidence:v1:` payload, and anchor that exact signed record. An already anchored record is immutable; replacement is a new record or a spec-defined supersession, never an in-place mutation.
- (FP-3) A bundle produced from the final evidence MUST carry its final `AttestationRef` in `settlementEvidence[]` and in the corresponding `phaseSummary[].attestationRef` when that optional pointer is present. Any duplicated `phaseSummary[].txRefs` MUST be regenerated from the final phase result and MUST NOT retain a placeholder. The producer MUST then recompute the attestation-bundle hash and every required `dacs-bundle:v1:` signature. This propagation does not authorize a change to any unrelated listing, agreement, party, vet, delivery, amendment, rating, or registry field.
- (FP-4) A checker comparing an in-memory draft artifact set with the same-outcome final set MUST accept the transitive integrity closure. The closure contains authoritative settlement-source fields and fields derived from those sources by the rail. It also contains the evidence hash/signature/anchor, downstream evidence or transaction references, and bundle hash/signatures/anchor. The checker MUST still perform ordinary artifact, reference, and signature verification. It MUST reject a stale propagated value or a semantic change outside that closure. It MUST NOT require that only the bytes of `SettlementEvidence` differ. A changed phase outcome follows the ordinary lifecycle and evidence rules instead of this propagation-only comparison.

> **Note (non-normative).** `BundleParty.bundleHash` hashes that party's DACS-1 `IdentityBundle`; it is not the DACS-5 attestation-bundle hash and does not change during settlement finalisation.

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

#### 9.7.2 Disclosed-fee reconciliation (informational)

A consumer MAY reconcile a DACS-3 `feeSchedule` disclosure (§8.5.3) against actual settlement. The reconciliation is **informational and non-gating**: it MUST NOT block, revert, or retry settlement, MUST NOT alter any `outcome`, and MUST NOT book a fault. It **observes** the disclosed-vs-actual gap; it does NOT reallocate funds — who effectively bears a gap is determined by `priceBasis` and the rail's fund flow, not by this rule.

- (FR-1) **Scope.** Only a `kind == "network"` item is reconcilable — against `SettlementEvidence.paymentFee` (the chain/provider fee). `platform` / `processing` / `spread` / `subscription` items are off-chain and remain disclosure-only (the signed pre-commit record is the artifact).
- (FR-2) **`rateBps → amount` (canonical).** A `rateBps` item resolves to `amount = price.amount × rateBps ÷ 10000`, computed as a canonical decimal (rule CD-1, CORE §B.2) **rounded half-up to the settlement asset's decimal precision** (`StaticRailDefinition.asset.decimals`, or the independently verified agreement-signed `selection.assetDecimals` for `x402:protocol`). Two implementations MUST derive an identical amount.
- (FR-3) **Expected total via `priceBasis`.** The expected payer-total MUST be computed according to the disclosure's `priceBasis` (inclusive vs exclusive); two consumers MUST NOT disagree on whether a schedule reconciles because they assumed different bases.
- (FR-4) **Verdict — do-not-collapse** (mirroring the §7.5.1 decision semantics):
  - *reconciles* — the actual `network` fee is within the item's `toleranceBps` of the disclosed estimate (absent `toleranceBps` ⇒ exact), and any `fixed` / `rateBps`-derived amount matches **exactly** after FR-2 rounding (these are deterministic — no tolerance applies to them).
  - *diverged* — resolves but beyond tolerance. The consumer records a **provenanced informational flag** carrying the **signed delta** (`paymentFee − disclosed`) and the breached tolerance, so under-disclosure (payer charged more than disclosed) is distinguishable from over-disclosure.
  - *indeterminate* — the actual fee or the agreement cannot be resolved. This MUST NOT be reported as `diverged`: a transient resolution failure is not a divergence.

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
- (PIPE-6) Before executing any pay-* phase or any delivery whose disclosure, access grant, or external side effect is irreversible, the orchestrator MUST verify the DACS-3 commitment's CORE §5.1 receipt is `finalized` and matches the session's `jobId`, agreement hash, listing reference, and logical address. `submitted`, `accepted`, index-visible, or an unverified `included` state is insufficient. A binding whose declared finality profile makes inclusion final MAY satisfy both states with one receipt.

> **Note (non-normative).** PIPE-1 is deliberately aligned with §6.3.4(8): a reader of either chapter reaches the same accept decision for a pay-less pipeline.

### 9.10 Conformance summary

| Role | Requirements |
| --- | --- |
| Rail author | RD-1 through RD-6; XN-1 for `x402:protocol` |
| Listing publisher / reader | DACS-1 §6.3.4 LRR-1 through LRR-6 |
| Orchestrator (rail selection) | RAV-R1 through RAV-R5 |
| Payment phase handler | PC-1 through PC-7; PB-1 through PB-3 for payee-bound agreements; XN-2 through XN-11 for `x402:protocol`; phase-specific procedure |
| Delivery phase handler | §9.6 per-kind procedure; DPA-1 through DPA-9 for attested payloads; SettlementEvidence emission |
| Pipeline executor | PIPE-1 through PIPE-5 |
| SettlementEvidence consumer | Canonical hash recomputation; signature validation; XN-7 through XN-10 for negotiated x402; DPA-3 through DPA-9 when phase is `deliver-attested-payload`; AMEND-1 through AMEND-4 (amendment chain following) |

### 9.11 Rationale

**Closed rail handlers, open negotiated protocol.** The registry remains closed
over behaviour/handler definitions so a listing cannot invent semantics. The
`x402:protocol` handler is one registered definition whose agreement-signed
selection is deliberately open over providers, facilitators, assets, networks,
and upstream scheme tokens. Local capability plus the DACS scheme-binding
contract determines executability; the global registry is not a provider or
asset allowlist.

**Uniform SettlementEvidence vs rail-specific evidence shapes.** Rail-specific shapes would force every downstream consumer (DACS-5, auditors, analytics) to handle N shapes. The uniform shape with a discriminated txRefs union keeps consumption simple while preserving per-rail detail.

**PayloadAttestationRecord vs a DACS-2 VerifyResult.** A VerifyResult answers
whether an identity/credential claim identified by `(scheme, identifier)` is
valid. A delivery attestation must instead bind exact payload bytes to a
specific job, agreement, DeliverableSpec, and verification method. Reusing
VerifyResult would either leave those bindings absent or change the meaning of
its existing fields. A distinct DACS-4 artifact preserves the DACS-2 claim type,
lets an unsupported older reader refuse by discriminator, and still composes
the same method-native DAHR/TLSNotary/zkTLS evidence.

**Payment and delivery as separate phases vs combined.** Decoupling lets listings compose risk however the seller deems safe: pay-then-deliver for trusted sellers, deliver-then-pay where risk shifts to the seller. A combined phase would force every listing into one risk model. (Escrow-with-delivery-gate and streamed subscriptions are named in §9.9 as roadmap, not v0.1 patterns.)

**HTLC and Liquidity Tank as parallel first-class rails.** HTLC is the only fully trust-minimised cross-chain primitive shipping today across heterogeneous chains (the reference runs on it). Liquidity Tanks are faster and cheaper but trust the substrate operator. Both have legitimate uses; v0.1 ships both rather than picking a winner.

**AP2 and x402 as rails vs separate stages.** AP2 and x402 are payment protocols; they fit naturally as rails with their own phase handlers. Modelling them as separate stages would duplicate everything DACS-4 already does (evidence, conformance, error classification) for no gain.

**Refunds as amendments vs separate phases.** Refunds happen post-settlement and may arrive long after the original phase has completed. Modelling them as out-of-band amendments anchored after the original evidence lets sessions close normally even when refunds straggle in. The amendment is included in the bundle if present at bundle time.

**Native bridge / Liquidity Tank trust model disclosure.** Honest disclosure of "operated by a rotating Demos validator shard under 2/3 BFT multisig with 15-day emergency recovery" is the right default. Users picking this rail are choosing speed + cost over trust-minimisation, and the recipe makes that trade-off explicit. Substrates with different SR-5 realisations inherit their own trust models and MUST disclose them similarly.

### 9.12 Backwards compatibility

**Agreement artifacts across minor versions.** A legacy DACS-4 v0.2 payer continues to accept `AgreementDocument` and use the runtime `payeeAddress` under its existing semantics. It rejects `PayeeBoundAgreementDocument` at the required `agreementVersion` schema gate and therefore cannot ignore PB and pay anyway. A DACS-4 v0.3 payer recognises both artifacts, applies PB-1 through PB-3 only to the payee-bound type, and does not attribute a PB guarantee to the legacy type. This is additive new-type refusal under CORE §11.1.2, not a semantic change to the legacy artifact.

**Payload attestations across minor versions.** `PayloadAttestationRecord` is a
new DACS-4 v0.5 artifact with its own `payloadAttestationVersion` discriminator
and `dacs-payload-attestation:v1:` domain. It does not add a required field to
`SettlementEvidence` or rewrite DACS-2 `VerifyResult`. The
`DeliverableSpec.verificationMethod?` spelling remains byte-for-byte unchanged.
DPA-1 nevertheless changes behaviour and reject timing for a listing that
selects `deliver-attested-payload` but supplies no method. A current reader
rejects that listing before session start and before payment; an older reader
could accept the same wire-valid listing and fail only when the delivery handler
attempted the already-required attestation. This is not a signed-shape break,
but it is a deliberate fail-earlier compatibility change. An older reader that
does not support the new record rejects its unknown discriminator; it MUST NOT
reinterpret it as a VerifyResult or accept the enclosing delivery without
validating the target of `attestationRef`.

**Settlement event references across minor versions.** DACS-4 v0.6 does not
add a required field to the frozen legacy `evm`, `solana`, or `x402`
`ChainTxRef` arms. It adds three distinct arms for newly produced success
evidence. An older reader rejects those unknown action-bearing discriminators
before counting or settlement verification; it MUST NOT erase the discriminator
and reinterpret the record as a legacy arm. A current reader continues to
verify historical `dacs-evidence:v1:` bytes unchanged and applies SB-1's
exactly-one-authenticated-match rule without rewriting the signed artifact.

**Negotiated x402 across minor versions.** DACS-4 v0.7 adds the distinct
`X402ProtocolRailDefinition`, `X402ProtocolPaymentRailRef`, `x402-protocol`
transaction-reference arm, and `scheme-network-finality` model. A pre-v0.7
reader rejects those unknown action-bearing types before authorization or
settlement admission; it MUST NOT remove `resolution`, `parameters`,
`x402Version`, or the new discriminator and retry as `x402:default`. Historical
`x402:default` rail/evidence bytes retain their static asset/network,
`protocolVersion: string`, and X402-1..X402-4 replay semantics. XN-10 prohibits
cross-shape rewriting.

**ERC-20.** pay-evm-erc20 uses the standard ERC-20 transfer interface; any compliant ERC-20 token works. The rail registry pins specific tokens (e.g. USDC) per chain to avoid scam-token substitution.

**SPL.** pay-solana-spl uses the standard SPL TransferChecked instruction; any compliant SPL token works. The rail registry pins specific mints per cluster.

**HTLC contracts.** Generic HTLC pattern; reference HTLC contracts in the DACS reference implementation are deployed on Base Sepolia and Solana devnet. Other deployments are compatible if they implement lock/claim/refund with the same hashlock-and-timelock semantics.

**AP2.** Compatible with AP2 spec as donated to the FIDO Alliance in April 2026 and subsequent FIDO Alliance versions. Per-provider rail entries (ap2:visa-direct, ap2:mastercard-send, ap2:stripe-paymentintents) pin provider-specific parameters.

**x402.** Compatible with the version-shaped x402 `PaymentRequired`,
`PaymentRequirements`, `PaymentPayload`, and settlement-response contracts.
`x402:protocol` keeps provider/facilitator/network/asset selection outside the
global definition: the exact request and semantic selection are carried in the
signed `PaymentRailRef`, and operator secrets/routing remain local. The generic
`PaymentRailRef.parameters` behavior applies only to static rails; it is not a
post-signature override surface for the negotiated arm.

**ERC-8183 escrow (future).** ERC-8183 introduces an EVM-native escrow primitive for job-style transactions. A future v0.2 rail (pay-evm-erc8183) will compose ERC-8183 escrow with DACS-4 evidence; v0.1 does not include it.

**Substrate-native bridges (Demos Liquidity Tanks).** pay-cross-chain-liquidity-tank on Demos uses Liquidity Tanks per the SDK shape at kynesyslabs/sdks/src/bridge/nativeBridgeTypes.ts. Other substrates implementing SR-5 via native cross-chain transactions (e.g. Polkadot XCM) MAY add their own rails under the cross-chain-liquidity-tank rail type with substrate-specific parameters.

### 9.13 Security considerations

**Unsigned event-index substitution.** *Threat:* one EVM transaction or Solana
transaction contains multiple transfers, while a caller supplies an unsigned
`logIndex`/`instructionIndex` after `SettlementEvidence` was signed, allowing
the same signed envelope reference to project to different SB-1 keys or select
a different payee transfer. *Mitigation:* v0.6 producers sign an event-level
reference with a distinct discriminator; verifiers independently match that
coordinate to ledger data and the agreement. Frozen legacy shapes are
projectable only when exactly one event matches, so an unsigned annotation
cannot resolve ambiguity. *Residual:* unavailable authenticated ledger history
leaves the record `indeterminate` and uncountable rather than manufacturing an
identity or attributing counterparty fault.

**Re-entrancy on EVM rails.** *Threat:* a malicious ERC-20 hook re-enters the orchestrator during pay-evm-erc20 settlement. *Mitigation:* phase handlers MUST be re-entrancy-safe; the SettlementEvidence MUST be anchored only after the chain transaction is confirmed at finality.

**MEV / front-running on payment txs.** *Threat:* a public-mempool payment can be front-run by MEV bots. *Mitigation:* rail.parameters MAY specify Flashbots-style private mempools or rate-limited public submission. Payment phases SHOULD support submitting via private mempools when available. For high-stakes settlements, cross-chain-liquidity-tank avoids public-mempool exposure entirely.

**Cross-chain settlement-atomicity failure.** *Threat:* HTLC source-lock succeeds but dest-claim never happens; payer’s funds are locked. *Mitigation:* HTLC timelocks let payer reclaim after expiry. Phase handlers MUST track lock expiry and invoke refund automatically. settlement-atomicity error class flags this for DACS-5 reputation logic.

**Liquidity Tank operator compromise.** *Threat:* the substrate validator shard operating Liquidity Tanks is compromised. *Mitigation:* the substrate’s security model (2/3 BFT multisig on Demos, 15-day emergency-recovery on Demos) is the floor. Listings handling high-stakes flows over Liquidity Tanks SHOULD evaluate the substrate’s validator-shard security; for the highest stakes, HTLC is recommended.

**AP2 mandate replay.** *Threat:* an old AP2 mandate is replayed against the provider. *Mitigation:* AP2 mandates carry a nonce and an expiry, which are **upstream AP2 evidence** — DACS-4 records the `ap2` txRef (mandateId, providerRef, protocolVersion) and anchors it via SR-2, rather than inheriting AP2’s anti-replay guarantee. The DACS-side binding of the cited payment to *this* session is AP2-1 (`dacs_job_id` / `dacs_agreement_hash` in the provider-side metadata, checked in the AP2-2 attested status response), resolved per the SB-3 three branches; SB-1/SB-2 uniqueness keying applies on top.

**Provider-credential disclosure to the attestation layer (AP2-2/AP2-3).** *Threat:* the AP2-2 attested status fetch necessarily carries a provider API credential through the SR-3 relay; a compromised relay or validator observes it. *Mitigation:* AP2-3 confines the disclosed credential to read-only payment-status scope, so observation yields the ability to read payment statuses on that account — never to charge, refund, or move funds. Operators SHOULD rotate the disclosed credential periodically and MAY scope it per-integration. The residual read exposure (payment metadata on the merchant account) is bounded by the same SR-3 trust floor as every consensus-backed-proxy fetch (§7.3.5) — and includes, specifically, the session↔fiat-payment linkage this rail's own AP2-1 binding creates: a compromised read credential exposes the `dacs_job_id` correlation for every DACS deal on that account until rotation. AP2-3 is an operational MUST that no conformance vector can exercise (it constrains the credential an operator discloses, not an artifact); this threat row is its enforcement surface. *Second residual (disclosure-completeness, not a defence gap):* the AP2-2 status body carries the settlement **amount and currency**, which the SR-3 relay and validators observe; where the agreement is otherwise confidential (an encrypted-anchored mode, roadmap), this discloses amount/currency in cleartext at the same SR-3 floor (§7.3.5), which an operator pricing a private deal should weigh.

**Payee-destination substitution.** *Threat:* a tampered listing, compromised negotiation channel, or malicious orchestrator substitutes `payeeAddress` so funds go to an attacker while every identity check passes. *Mitigation:* for `PayeeBoundAgreementDocument`, PB-1 carries the destination inside the co-signed artifact (a substituted address breaks the agreement hash; an honest payee never co-signs an attacker's address), and PB-2 binds it to the vetted identity by the strongest applicable tier — intrinsic, control-proven `cci-xm:` linkage (§6.3.2 step (6)), or the payee's own agreement signature; applicable-but-unresolvable pauses rather than paying (§9.5.1). The distinct artifact and phase make older readers reject before settlement rather than ignore PB. *Residual:* a legacy `AgreementDocument` has no PB guarantee; a payee asserting a tier-3 address it does not control bears the payee-side risk, visible via the recorded binding tier.

**x402 payment-receipt forgery.** *Threat:* a server claims payment it did not receive. *Mitigation:* negotiated success evidence signs `x402-protocol` challenge/receipt commitments plus the native `settlementEvent` and independently verifies the selected transfer/finality under XN-7..XN-9. The legacy static path signs `x402-event` and applies X402-1..X402-4. In either path a facilitator receipt is supplementary, not server- or facilitator-forgeable proof of settlement. Historical receipt-only evidence remains replayable under its signed bytes but cannot establish an event-level SB-1 identity without a uniquely matching authenticated event. Buyer-side x402 wallets SHOULD keep a local record of submitted payments.

**x402 global-endpoint and challenge substitution.** *Threat:* a supposedly
generic registry entry pins one seller endpoint, or a resource changes the
method, URL, body, version, scheme, network, asset, amount, destination,
timeout, `extra`, or extensions after agreement and before authorization.
*Mitigation:* XN-1 keeps the global arm provider-neutral; XN-2 places every
resolution input inside the co-signed agreement; XN-4..XN-6 require one exact
challenge match and prohibit redirect/effective-request changes before wallet
use. *Residual:* endpoint availability remains a seller operational concern; a
dead signed endpoint fails or stays transient and cannot be silently replaced
inside the session.

**x402 acknowledgement downgrade.** *Threat:* a server/facilitator response or
signed extension is presented as finalized payment without independent
settlement proof. *Mitigation:* XN-7 commits to both complete received objects,
XN-8 requires independently authenticated event/finality verification before
success, and XN-9 keeps non-final batch commitment distinct. Diagnostic
acknowledgements never authorize delivery, bundles, volume, or reputation.

**Delivery non-delivery.** *Threat:* seller signals payment received, never delivers. *Mitigation:* outside DACS-4’s remit; this is a DACS-3 / DACS-5 issue (the deliver-* phase MUST return ok: false on missing deliverable; DACS-5 records the failure; reputation impact accrues). Listings handling expensive non-recoverable deliveries SHOULD order the pipeline to shift the risk they care about — deliver-then-pay or pay-then-deliver (§9.9) — accepting the residual counterparty risk each implies. A true escrow that gates release on demonstrable delivery (lock → deliver → release) is **not expressible in v0.1** (§9.9): `pay-cross-chain-htlc` is an atomic swap with no mid-lock suspension point, and delivery-gated escrow is roadmapped to the ERC-8183 job-escrow rail.

**Payload self-attestation and proof replay.** *Threat:* a seller signs ordinary
SettlementEvidence, omits the declared method proof, or reuses a real proof from
another job and calls the payload “attested.” *Mitigation:* DPA-3 independently
verifies the method evidence against the exact payload digest; DPA-4 binds that
digest to the job, committed agreement, DeliverableSpec, and selected method;
DPA-6 makes the payload record mandatory for a success outcome; and DPA-8 states
that the orchestrator's evidence signature is not a substitute. A deliberately
selected `self-signed` method remains a transparent minimal-trust tier rather
than being silently upgraded to independent authority evidence.

**Refund laundering.** *Threat:* a seller refunds to quietly unwind a failed delivery without recording failure. *Mitigation:* SettlementAmendments are anchored, signed, and included in DACS-5 bundles, so the trail shows both the original payment and the later refund; reputation derivation MUST treat refunded sessions appropriately. The inverse — a refund against a non-existent/failure-outcome record, or an over-refund — is guarded by AMEND-1..4 (§9.7.1).

**Decimal-overflow in cross-decimal pay paths.** *Threat:* converting `amount.amount` to on-chain integer units overflows or mis-rounds. *Mitigation:* the §9.5.2/§9.5.3 procedures mandate string-decimal arithmetic with no float, and `PriceTerm.amount` is canonical per CD-1 (CORE §B.2). Static rail authors MUST specify `asset.decimals` exactly; an x402 adapter independently verifies the agreement-signed `selection.assetDecimals` under XN-5. Phase handlers validate precision against the applicable value, and excess precision is an error rather than a rounded payment.

**Pinned-rail vs latest-rail at settle time.** *Threat:* the rail registry changes between agreement commit and settle execution. *Mitigation:* the rail is pinned at session start (per railRegistryVersion in SessionContext). Settle MUST use the pinned rail definition, even if the registry has since superseded it.

### 9.14 Phase parameters reference card

A single-table summary of phase types, their parameters (from listing PhaseStep), and the SettlementEvidence they produce, for implementers.

| Phase type | Parameters (PhaseStep) | Evidence txRef kind |
| --- | --- | --- |
| pay-evm-erc20 | {rail: railId}; rail.parameters.finalityBlocks optional | evm-event (legacy read: evm) |
| pay-solana-spl | {rail: railId}; rail.parameters.commitmentLevel optional | solana-instruction (legacy read: solana) |
| pay-cross-chain-htlc | {rail: railId}; rail.parameters.timelockSourceSec, timelockDestSec, sourceFinalitySec, and safetyWindowSec required, with timelockSourceSec > timelockDestSec + sourceFinalitySec + safetyWindowSec (HTLC-7 — the margin covers the payee reaching SOURCE-chain finality after the reveal; evaluated against the pinned params, not runtime latency), under the source-lock-finality epoch (HTLC-8) | htlc-lock + htlc-reveal + htlc-claim (source) |
| pay-cross-chain-liquidity-tank | {rail: railId} | liquidity-tank |
| pay-ap2 | {rail: railId}; rail.parameters.providerEndpoint required | ap2 (txRef carries `protocolVersion`, required) |
| pay-x402 | {rail: railId}; `x402:protocol` takes the exact request/selection from agreement.terms.rail.parameters | x402-protocol (numeric `x402Version`, challenge + receipt hashes, CAIP-2 network, transaction, adapter-canonical native event); pinned legacy-static read/continuation: x402-event / x402 |
| deliver-storage-program | none (driven by listing.offering.deliverable) | n/a (deliverableContentHash + deliverableAnchor instead) |
| deliver-entitlement | none (driven by listing.offering.deliverable) | n/a |
| deliver-attested-payload | none (driven by listing.offering.deliverable; verificationMethod conditionally required by DPA-1) | deliverableContentHash + deliverableAnchor + attestationRef → PayloadAttestationRecord (DPA-6) |
