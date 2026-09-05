# DACS-1: Identify — Identify

*Normative module of DACS v0.1. Read the [Primer](../PRIMER.md) first; shared types, signatures, canonical form, the session model, and substrate requirements live in [CORE](CORE.md). Section numbers are retained from the unified specification; per the §→document map in [CORE](CORE.md), cross-references of the form §6–§10 point to sibling module documents, and §A / §12–§14 to the companion references (Demos mapping, threat model, glossary, conformance plan). The [conformance vectors](../conformance/) exercise this module's rules.*

## Chapter 6 — DACS-1: Identify

**Stage:** Identify (1st of 5). **Status:** Draft — **DACS-1 v0.8** on the common DACS v0.1 baseline. v0.8 adds the structurally distinct complete sealed-envelope negotiation and selection-bound agreement-commitment phase kinds from DACS-3 v0.6; their signed `candidateSetBinding` parameter makes older listing readers reject before acting rather than ignore candidate-set completeness. v0.7 defines presence-only `ClaimRequirement` matching under PCR-1..PCR-6 without manufacturing verification evidence or weakening the identity-control boundary, and adds the signed, listing-only `pay-alternative` phase whose complete-reference validation routes through DACS-4 APR-1/APR-2 without making it an executable handler. v0.6 makes `domain:<lowercase-IDNA-hostname>` the sole producer form and defines permanent, signature-preserving read compatibility for historical Demos `web2:domain:` aliases under DCR-1..DCR-8. v0.5 defines the EIP-155 chain profile used when an EVM `cci-xm` claim participates in DACS-4 payee-destination binding and makes accepted-rail resolvability an executed canonical-registry check under LRR-1..LRR-6 rather than a self-referential listing assertion. v0.4 requires a listing anchor to reach the CORE §5.1 finalized and independently resolvable gate before active discovery. v0.3 adds the §6.3.2 step (6) control gate, `pre-commit` `cancellationPolicy` handling §6, the sealed-envelope procurement listing-role clarification, the minor-safe `commit-payee-bound-agreement` phase, the §6.3.5/§6.3.6 DACS-5 bundle-binding discovery surfaces, and independently resolvable `RevocationBinding` revocation markers. **Depends on:** SR-1 (optional), SR-2 (required); composes with ERC-8004, W3C DIDs, A2A. **Used by:** DACS-2..5.

### 6.1 Abstract

DACS-1 specifies how an agent is identified, what it offers, and how it is found. It defines three primary artifacts, a revocation record, and a discovery extension:

- An **identity claim reference scheme** — a way to name an identity that already exists somewhere else (a domain, DID, company LEI, platform account, signing key), written as `type:value` (e.g. `lei:5493…`), optionally carrying proof it was checked against that source (a DACS-2 verification).
- An **identity bundle schema** — an ordered set of independently-verifiable claims a party presents, plus a listing-side requirement schema declaring which bundles a listing accepts.
- A **service listing schema** — a signed, anchored JSON document declaring the bundle requirement, offering, deliverable, pipeline, accepted rails, and terms. The listing is the publisher's signed, pinned statement of terms — the single source of truth every deal with that publisher is checked against.
- A **revocation marker and binding** — a signed withdrawal record plus the discovery metadata needed to resolve its native anchor.
- A **discovery extension** — a `.well-known/agent.json` listings-index URL plus an off-chain catalog API for indexed search and revocation resolution.

Identity is a bundle of independently-verified claims, not a single rooted identifier — so the same structure covers micropayments (a signing key) and regulated trades (LEI + KYB + FINRA + OFAC). The substrate MUST provide anchored storage (SR-2); single-signature bundle convenience (SR-1) is OPTIONAL and supplements, never replaces, per-claim verification.

### 6.2 Motivation

The Identify stage answers three questions a buyer resolves before transacting: *who is the counterparty?* (cryptographically, at stakes-appropriate confidence); *what do they offer, on what terms?*; *how are they found when only the offering is known?*

Existing standards address fragments — ERC-8004 (an EVM-native agent-identity NFT), W3C DIDs (self-sovereign identifiers), A2A's `.well-known/agent.json` (capability advertisement), and authority/platform identifiers (LEI, FINRA CRD, SAM UEI; verified domains, OAuth accounts). None, alone or combined, let a transaction *declare* which claims it requires, *present* a matching set with per-claim verification references, bind a signed anchored *listing* as the contract, and offer a *commercial discovery* surface distinct from capability advertising.

DACS-1 fills these gaps with minimal additions. The unifying mechanism is **claims, not roots**: a listing requires a bundle of claims; a counterparty presents one (signed by a single SR-1 root, per-claim signatures, or a session key), and the rest of the stack consumes it uniformly. This is why a single-rooted model fails — identity for a sub-cent call is a signing key; for a $500 SaaS purchase, a key plus platform claims plus reputation; for a $50k trade, an LEI of record with FINRA/OFAC/KYB. One structure spans all three.

### 6.3 Specification

#### 6.3.1 Identity claim reference scheme

A claim reference identifies a fact about a party that can in principle be verified against an external system.

**Grammar**
A claim reference MUST conform to:

```
ClaimReference   := Scheme ":" Identifier [ "?" Parameters ]

Scheme           := scheme-start ( scheme-cont )*

scheme-start     := lowercase-ascii

scheme-cont      := lowercase-ascii | digit | "-"

Identifier       := scheme-specific, non-empty, NFC-normalized Unicode (printable ASCII recommended)

Parameters       := key1=value1 [ "&" key2=value2 ]*
```

- A Scheme MUST start with a lowercase ASCII letter and MAY include lowercase ASCII letters, digits, and hyphens thereafter. Underscores are reserved for future use and MUST NOT appear in v0.1 scheme names.
- Parsers MUST treat Scheme case-insensitively on read and SHOULD emit lowercase on write.
- Identifier is treated per-scheme; the per-scheme rules below specify canonicalisation.
- The ?<parameters> suffix carries scheme-specific qualifiers (e.g. cci-xm:evm:8453:0x…?jurisdiction=US). Unknown parameters MUST be ignored by readers, MUST NOT cause rejection, and MUST NOT be silently stripped when forwarding the reference.

**Canonical form and identity (rules CF-2, CF-3).** A ClaimReference has a *canonical byte form* (the bytes embedded whenever it appears inside a hashed or signed document) and a *canonical identity* (the `(Scheme, Identifier)` pair used for matching, reputation keying, and the §7.3.2 replay defence). Both rules are defined in **CORE §B.1**; CF-2's identifier normalisation uses the per-scheme identifier rules below.

**Registered schemes (v0.1) — two-axis registry**
The v0.1 scheme registry is organised along two axes: (a) **CCI-native** schemes — one per Demos CCI context, with the identifier directly addressing the relevant slot in GCRMain.identities; (b) **Stor-backed credential** schemes — schemes whose verification result is anchored as a Storage Program written by a DACS-2 attestation.

**CCI-native schemes** — map to Demos CCI contexts (8 in production today + 6 to-add for DACS-1 v0.1):

| Scheme | CCI context | Identifier shape | Status |
| --- | --- | --- | --- |
| cci-xm:<chain>:<subchain>:<address> | xm | per chain (EVM PB-2 profile: `evm:<eip155-chainId>:<address>`; Solana base58, …) | Done |
| cci-web2:<platform>:<username> | web2 | twitter / github / discord / telegram | Done |
| cci-pqc:<algorithm>:<pubkey> | pqc | falcon / ml-dsa | Done |
| cci-ud:<domain> | ud | Unstoppable Domain | Done |
| cci-nomis:<address> | nomis | Nomis wallet score subject | Done |
| cci-humanpassport:<id> | humanpassport | humanity proof id | Done |
| cci-ethos:<id> | ethos | Ethos profile id | Done |
| cci-tlsn:<proof-hash> | tlsn | TLSNotary proof commitment | Done — DACS-2 MUST treat as a CCI claim, NOT as an external tlsnotary method |
| cci-lei:<20-char> | lei (NEW) | uppercase LEI | Deferred — later version, not v0.1 |
| cci-finra-crd:<digits> | finra-crd (NEW) | digits only, no leading zeros | Deferred — later version, not v0.1 |
| cci-sam-uei:<12-char> | sam-uei (NEW) | uppercase UEI | Deferred — later version, not v0.1 |
| cci-fedramp:<id> | fedramp (NEW) | as-issued | Deferred — later version, not v0.1 |
| cci-naics:<6-digit> | naics (NEW) | digits only | Deferred — later version, not v0.1 |
| cci-cmmc:<cert-id> | cmmc (NEW) | as-issued | Deferred — later version, not v0.1 |

**EVM `cci-xm` settlement-chain profile.** The general `cci-xm` identifier
continues to mirror the substrate's `<chain>:<subchain>:<address>` storage
coordinates. When a claim is intended to establish the DACS-4 PB-2
chain-specific payee binding for an EVM rail, producers MUST emit
`cci-xm:evm:<chainId>:<address>`, where `<chainId>` is the EIP-155 chain ID as
a bare positive decimal integer with no leading zeros and `<address>` is
non-empty. The family component is the lowercase ASCII literal `evm`; any
other spelling does not conform to this profile.

For PB-2 chain applicability, a reader treats the bytes after
`cci-xm:evm:<chainId>:` and before any optional `?` parameters as the address
component. The address component MUST be non-empty but is otherwise opaque to the
chain-applicability predicate: its syntax, case, and normalization do not
determine the settlement chain, and unknown ClaimReference parameters remain
ignored as required above. An empty address, including an address represented
only by parameters, does not conform to this profile. The pair
`evm:<chainId>` maps one-to-one to the CAIP-2 network identifier
`eip155:<chainId>`; for example, Ethereum mainnet is `evm:1`, Ethereum Sepolia
is `evm:11155111`, Base mainnet is `evm:8453`, and Base Sepolia is
`evm:84532`.

Human-readable subchain labels such as `mainnet`, `testnet`, and `sepolia` are
not globally unique network identifiers. Readers MUST NOT infer an EIP-155
chain ID from such a label, from the address shape, or from a local
provider/SDK convention. This version registers no legacy name-to-chain-ID
aliases. A future alias can affect PB-2 only if a later Standard revision adds
it to an explicit closed, versioned table; an implementation-specific alias
MUST NOT affect a conforming PB-2 result. Existing name-style `cci-xm` values
remain readable as their original generic claim references, but do not by
themselves establish an EVM settlement-chain match. These rules do not rewrite
or re-hash an existing ClaimReference; they define only its eligibility for
the DACS-4 chain-applicability predicate.

The six new contexts (lei, finra-crd, sam-uei, fedramp, naics, cmmc) extend the existing 8-context CCI model with regulatory identity claims. **They are deferred to a later version and are not part of v0.1.** The native CCI contexts are deferred, not the schemes — `lei`, `finra-crd`, `sam-uei`, `fedramp`, `naics`, and `cmmc` remain live DACS-2-verifiable scheme names (verified via `consensus-backed-proxy` recipes against their respective authorities, e.g. `api.gleif.org` for `lei`), so the `institutional` identity tier (§6.3.2.1) stays reachable in v0.1. Each deferred context will follow the same pattern as the existing 8 contexts: per-context GCR routine for validation; verified payload stored in GCRMain.identities; readable via the existing wallet/SDK identity surface. Until they ship, regulatory credentials are carried via the stor-cred extensibility surface below (the scheme grammar, claim tiers, and DACS-2 verification recipes are substrate-independent and unchanged).

**The DACS-1 / DACS-2 boundary for these claims.** DACS-1 is **registered identity** (what the party stably holds — LEI, FINRA registration, etc., kept in CCI). DACS-2 is **freshness check** (per-session re-verification that the registered claim is still valid right now). The DACS-2 DAHR call against the authority produces the verified result; that result is written into the relevant CCI context (DACS-1 surface) AND referenced from the DACS-2 CompositeVerificationRecord for that session.

**Stor-backed credential schemes (extensibility surface)**
For credentials Demos has not yet promoted to a native CCI context — future regulatory regimes, jurisdiction-specific identifiers, industry-specific certifications, ad-hoc one-off attestations — DACS-1 allows a Stor-backed scheme of the form:
stor-cred:<credential-type>:<identifier>
The Storage Program at stor-{sha256(subject_cci + ":" + credential-type + ":" + identifier)} holds the latest DACS-2 VerifyResult for that (subject, credential) tuple. This is the extensibility mechanism: when a new credential type is needed and there is no native CCI context for it, listings can require a stor-cred:*scheme without waiting for Demos to add a context. When a stor-cred:* scheme sees broad enough use, it SHOULD graduate to a native CCI context per the v2 scheme-addition process.

**Composition and low-stakes schemes**

| Scheme | Identifier shape | Use |
| --- | --- | --- |
| did:… | per W3C DID method | external decentralised identifier; resolution per method |
| erc8004:<chainId>:<contract>:<tokenId> | <chainId> is an eip155 chain id as a bare decimal integer (no leading zeros), canonically the CAIP-2 chain id eip155:<chainId>; lowercase 0x-prefixed contract; tokenId is the uint256 token id in decimal, no leading zeros | external EVM agent identity NFT; verified via DACS-2 evm-rpc |
| domain:<dns> | lowercase IDNA A-label hostname | fresh DNS / TLS control via DACS-2 `domain-tls-control`, or persistent Demos host/account binding via `demos-gcr-domain` |
| key:<hex-pubkey> | lowercase, no 0x | self-signed; lowest tier; signing-key only |
| substrate-validator-set:<substrateId>:<epochOrSetId> | registered substrateId + epoch/set id | not a party identity — the signer of a consensus-backed-proxy / evm-rpc DACS-2 attestation; resolution + roster verification per §7.5 |

**Canonical DNS-domain profile and Demos compatibility (DCR-1..DCR-8).**

- **(DCR-1) Canonical domain identity.** The only canonical DACS DNS-domain ClaimReference is `domain:<host>`. `<host>` MUST be the lower-case ASCII A-label result of IDNA2008 ToASCII with STD3 rules applied label-by-label to the NFC-normalized Unicode hostname. It MUST contain only non-empty labels, each at most 63 octets and the complete hostname at most 253 octets. A producer MUST emit that exact form before hashing or signing. A current `domain:` reference carrying a U-label, upper-case ASCII host, or any other spelling that merely maps to the canonical result is non-conforming and MUST be rejected rather than repaired during verification.
- **(DCR-2) Hostname-only boundary.** A conforming domain identifier MUST NOT contain a scheme, user information, port, path, query, fragment, IP literal, empty label, leading/trailing hyphen, underscore, wildcard, surrounding whitespace, or terminal root dot. Inputs such as `https://example.com`, `example.com:443`, `user@example.com`, `example.com/path`, `127.0.0.1`, `[::1]`, `*.example.com`, and `example.com.` are not ClaimReference hostnames and MUST be rejected rather than stripped or repaired.
- **(DCR-3) Producer transition.** DACS-1 v0.6 and later producers MUST emit only the canonical `domain:` form. Demos `web2.domain` is a substrate-native storage context, not a second DACS scheme. A Demos adapter maps a verified native record to `domain:<host>` and retains its source context under `BundleClaim.metadata.demosGcrDomain`; it MUST NOT emit `web2:domain:`. This is a producer-output requirement: conformance is tested at the producer/serializer boundary. The frozen `IdentityBundle.bundleVersion: "1"` shape carries no authenticated DACS-1 minor-version discriminator, so a reader MUST NOT infer production era from mutable deployment state, a caller sidecar, `presentedAt`, or a producer self-declaration.
- **(DCR-4) Permanent legacy read/replay.** A signature-valid `bundleVersion: "1"` artifact containing a `web2:domain:<host>` reference is handled through this permanent read/replay compatibility arm for semantic matching only. A reader MUST first verify the enclosing artifact's original bytes, hash, and signature. Only after that verification may it canonicalize `<host>` under DCR-1 and derive the semantic identity `domain:<host>`. ASCII letter case in an otherwise valid historical hostname is folded to lower case during that semantic derivation and is not, by itself, malformed. It MUST NOT rewrite, re-hash, re-sign, or represent the artifact as having originally contained the canonical spelling. A malformed legacy hostname is `error`, not a new identity. The reader MUST apply this rule from the signed artifact's registered `bundleVersion` and alias spelling alone; mutable current profile state cannot reclassify the same retained bytes. Current-producer conformance is enforced at emission under DCR-3, not by disabling permanent reads. This compatibility arm does not permit a current `domain:` producer to rely on reader-side repair under DCR-1.
- **(DCR-5) Semantic deduplication.** Before requirement matching, primary-claim resolution, tier derivation, `oneOf` evaluation, or reputation keying, a reader MUST collapse canonical and legacy aliases with the same DCR-1 host to one semantic domain claim. The aliases cannot count twice, improve identity tier, satisfy two alternatives, or split/merge reputation. A current producer emitting both aliases is non-conforming; a reader of historical bytes still verifies the original artifact and evaluates the deduplicated semantic set.
- **(DCR-6) Source metadata.** `BundleClaim.metadata.demosGcrDomain`, when present, MUST carry the native context literal `web2.domain`, canonical `hostname`, 64-character lower-case hexadecimal Demos Ed25519 `account`, exact HTTPS `proofUrl`, the Demos `sourceTransaction` (`txHash` and `blockNumber`), and `recordedAt`. The canonical proof URL is exactly `https://<host>/.well-known/demos-cci.txt`. The historical fetched proof body is not part of the GCR record and MUST NOT be invented or re-fetched as if it were persistent evidence. Metadata is inspectable provenance, not authority: consumers independently resolve and authenticate the GCR record under DACS-2 §7.3.10.
- **(DCR-7) Controlled use.** A passing and fresh `demos-gcr-domain` result establishes a persistent host-to-Demos-account binding. It qualifies the domain as controlled only when the bundle presentation also verifies under that same Ed25519 account (directly, or through an authenticated SR-1/session-key binding to it). A GCR record copied into another party's bundle is valid source data but does not give that party control, cannot serve as its `presentedBy`, and cannot receive its reputation.
- **(DCR-8) Persistent is not fresh control.** `demos-gcr-domain` and `domain-tls-control` are distinct verification families. The former proves the consensus-recorded persistent host/account link as of its GCR inclusion time; the latter proves a fresh ACME-style challenge. Neither MUST be reported as the other. A requirement that explicitly selects fresh domain control is not satisfied by a GCR record, even while that record remains within its ordinary effective window.

The metadata shape used by DCR-6 is:

```text
type DemosGCRDomainMetadata = {
  context: "web2.domain"
  hostname: string
  account: string
  proofUrl: string
  sourceTransaction: { txHash: string; blockNumber: number }
  recordedAt: number
}
```

**Demos self-certifying agent DID profile.** `did:demos:agent:<64hex>` is a
canonical ClaimReference under the already-registered `did` scheme: its
Scheme is `did` and its Identifier is `demos:agent:<64hex>`. The final component
is the lowercase, 32-byte Ed25519 public key used by the Demos agent account;
writers MUST emit exactly 64 lowercase hex characters with no `0x` prefix.
Readers resolve this profile by decoding that component as the raw verification
key and applying the signature envelope's algorithm and domain separator. The
Demos substrate mapping in §A.1 defines this profile; it does not register a
second top-level claim scheme.

On read, the general case-insensitive Scheme rule applies only to the leading
`did` scheme component: for example,
`DID:demos:agent:<64-lowercase-hex>` MUST resolve as this profile and MUST
canonicalise to the lowercase `did:` spelling before hashing, signing, or
comparison (CF-2). The `demos:agent:` Identifier profile and its key component
remain case-sensitive. A reader MUST reject an uppercase key component as
non-canonical rather than lowercase it.

`demos:0x<64hex>` is a substrate-address notation, not a registered v0.x
ClaimReference and not an alias of `did:demos:agent:<64hex>`. In ClaimReference
grammar its Scheme would be the unregistered value `demos`, so a conforming
reader MUST apply the unknown-scheme rule below. Implementations MUST NOT emit
`demos:0x<64hex>` in a ClaimReference field. A migration tool MAY establish an
out-of-band key/address relationship, but MUST NOT silently rewrite one form to
the other inside a signed artifact or merge their DACS-5 reputation keys.

**Unknown-scheme handling**
A reader encountering an unknown scheme MUST: preserve the reference verbatim when forwarding; treat the reference as **unverified** for evaluation purposes; NOT silently accept the reference as satisfying a bundle requirement; log or surface the unknown scheme to the calling agent. A reader MAY decline to engage with a bundle that contains an unknown scheme in a required position.

**Adding new schemes (v2 and beyond)**
The v0.1 scheme registry is closed. New schemes are added in subsequent versions of DACS-1 by: submitting a scheme definition (name, identifier grammar, canonical form, authority, default DACS-2 verification recipe); demonstrating a working DACS-2 recipe; acceptance by the registry steward per the process in chapter 11. Implementations MAY support pre-standard "experimental" schemes prefixed x- (e.g., x-myorg-internal-id); these MUST be treated as unknown by conforming readers unless out-of-band agreement exists.

#### 6.3.2 Identity bundle

An identity bundle is an ordered set of claims a party presents about itself, with verification metadata, plus a presentation signature.

**Schema**

```
type IdentityBundle = {

  bundleVersion: "1"

  presentedBy: ClaimReference          // primary identity claim within `claims`

  presentedAt: number                  // unix milliseconds (always present); informational/diagnostic only — session freshness/replay is bound by sessionNonce (§6.3.2), not by presentedAt; verifiers MUST NOT gate acceptance on presentedAt

  sessionNonce?: string                // session-binding nonce for per-claim / session-key presentations; top-level so it enters bundle_hash (§6.3.2). SIWD conveys the nonce in the SIWD message Nonce field instead.

  claims: BundleClaim[]                // non-empty; order is meaningful

  presentation: PresentationSignature

}

type BundleClaim = {

  ref: ClaimReference

  verifiedBy?: VerifyResultRef         // DACS-2 result reference

  issuedAt?: number                    // unix ms when the verification was performed

  expiresAt?: number                   // unix ms; presenter upper bound — narrows the authority window only (§6.3.2 Freshness window)

  metadata?: Record<string, unknown>   // scheme-specific

}

type PresentationSignature =

  | { kind: "siwd"; message: string; signature: string; address: string }

  | { kind: "per-claim"; signatures: { ref: ClaimReference; signature: string }[] }

  | { kind: "session-key"; key: string; signature: string; rootBinding?: string }

  | { kind: "sr1-root"; rootClaim: ClaimReference; aggregateSignature: string }
```

SIWD is the preferred presentation. The siwd shape matches the return of provider.request({ method: "wallet_signIn", params: […] }) on the Demos wallet — { message, signature, address } — and is the same EIP-4361-style envelope. The rules:

- Verifiers MUST validate the SIWD signature against the **Demos wallet's signing key** (the wallet that produced `wallet_signIn`).
- The bundle's primary claim MAY be on any chain (EVM, Solana, …). It is bound to that wallet through the wallet's verified **CCI / SR-1 cross-chain identity link**, NOT by requiring the primary claim itself to produce the EIP-4361 signature.
- A verifier MUST confirm the wallet controls the primary claim via that CCI/SR-1 link; the Demos wallet is the identity root that holds the per-chain claims.
- A primary claim with no CCI link to a SIWD-capable wallet MUST use the `per-claim` or `sr1-root` presentation instead.

**sr1-root presentation.** When SR-1 cross-substrate identity aggregation is available, a single root key may co-sign every claim in the bundle under an SR-1 aggregate signature, producing one signature that covers the whole bundle. rootClaim names the SR-1 root identity (a CCI primary claim on Demos); aggregateSignature is the SR-1 aggregate signature over the domain-separated payload (§6.3.2 below). Verifiers MUST resolve the root key via SR-1 and verify the aggregate signature against the domain-separated payload `signed_bytes` (§6.3.2).

> **Note (non-normative).** sr1-root is the natural presentation for a party self-binding a single document (a seller signing their own listing, an orchestrator binding multiple per-substrate addresses under one identity): it avoids the per-claim signature overhead and produces one cryptographic artifact the rest of the stack can reason about.

**Domain-separated payload.** All four presentation kinds bind to the same payload:

`signed_bytes := "dacs-bundle-presentation:v1:" || bundle_hash`

- **per-claim** — each per-claim signature signs `signed_bytes` (not the raw bundle hash).
- **session-key** — the session key signs `signed_bytes`; if `rootBinding` is set, the root key additionally signs `"dacs-session-binding:v1:" || session_key || bundle_hash`.
- **sr1-root** — the SR-1 aggregate signature signs `signed_bytes`; verifiers reconstruct the SR-1 aggregate from the `rootClaim`'s sub-identity set and verify against `signed_bytes`.
- **siwd** — the wallet signs the SIWD message, which MUST carry `signed_bytes` as an EIP-4361 `Resources` entry in the exact form `dacs:<hex>`:
  - `<hex>` is the lowercase-hex encoding of the full `signed_bytes` — i.e. `dacs:` followed by `hex("dacs-bundle-presentation:v1:" || bundle_hash)`. The `dacs-bundle-presentation:v1:` prefix is carried INSIDE the hashed-and-hex-encoded bytes, NOT in the URI scheme path.
  - A bare hex value MUST NOT be emitted on its own; it is not a valid RFC 3986 URI, and a strict EIP-4361 parser would reject the whole SIWD message. Only the `dacs:<hex>` form is conformant.
  - The SIWD signature thereby transitively binds to the same payload: the message is the SIWD envelope; the `Resources` entry carries the bundle binding.

  > **Note (non-normative).** This is the exact Resource string the reference `docs/flow-trace.md` emits and re-derives for its `bundle.presentation.message.includes(expectedResource)` SIWD check, so the normative text and the reference implementation produce byte-identical resources.

**Session nonce binding.** `presentedAt` is always present (a required schema field). A bundle presented in the context of a specific session SHOULD additionally carry a session-binding nonce:

- The nonce is conveyed via the SIWD message’s Nonce field (per EIP-4361) or, for per-claim and session-key presentations, via the top-level `sessionNonce` field on the IdentityBundle — which therefore enters `bundle_hash` and is covered by the presentation signature for those kinds.
- A verifier in a session context MUST check that the bundle’s `sessionNonce` (or SIWD Nonce) matches the session’s expected nonce, and MUST reject a session-context presentation that carries no session nonce. The nonce's provenance — verifier-generated, ≥128-bit, per-`jobId`, single-use — is governed by **CORE §B.8 (SN-1..SN-4)**; this bullet is the match check that consumes it.
- For SIWD the nonce lives in the omitted `presentation` field and so is not in `bundle_hash`; the verifier's nonce-match check above is the binding for that kind and is therefore a MUST, not advisory.
- Bundles presented without session-nonce binding are usable only outside session contexts (e.g., listing publication where the bundle is the seller’s own self-binding to the listing).

**Canonical serialisation**
The bundle follows the §B.2 canonical-form template, omitting the `presentation` field. The domain-separated `signed_bytes` (above) is what the presentation signature actually signs. Verifiers MUST recompute both the canonical form and the domain-separated payload when validating.

**SIWD bundle-binding check.** For the `siwd` kind specifically:

- The verifier MUST parse the SIWD `message` and confirm its `Resources` list contains the URI `dacs:<hex>`, where `<hex>` is the verifier's independently-recomputed lowercase-hex of `signed_bytes` (= `hex("dacs-bundle-presentation:v1:" || bundle_hash)`). A missing or mismatched binding URI MUST cause rejection.
- The comparison is exact string equality against the single `dacs:<hex>` form above. A bare hex string or any other wrapping MUST NOT be accepted, so two implementations cannot diverge on the encoding.
- If the message carries multiple `Resources` entries, at least one MUST equal it.

> **Note (non-normative).** Without this check, a captured SIWD `{message, signature, address}` whose wallet controls the same primary claim could be reattached to a different bundle — the SIWD signature alone proves the wallet signed *some* message, not that it committed to *this* bundle.

**Claim tiers.** Claims rank by how much real-world cost and accountability backs the identity (highest → lowest). A tier counts **only when the claim is verified-and-fresh** (a passing, in-window `verifiedBy`); an unverified or stale claim falls to the bottom tier.

| Tier | Schemes |
| --- | --- |
| 1 — authority-issued | `lei`, `finra-crd`, `sam-uei`, `fedramp`, `cmmc`, `naics` |
| 2 — DID / ERC-8004 with verifiable proof | `did`, `erc8004` (verified) |
| 3 — platform identifier | verified `domain`, OAuth / platform accounts |
| 4 — plain signing key | `key` (and any unverified or stale claim) |

This ranking governs the `presentedBy` selection below — which primary claim to present, by scheme strength. The §6.3.2.1 `identityTier` derivation uses it only for the top level (a verified **tier-1** claim → `institutional`) and otherwise keys on *verification status*, not scheme tier: any other **verified** claim → `verified`, and **no** verified claim → `self-declared`. So a verified `key:` is `verified`, despite being the lowest presentedBy tier. The two rankings answer different questions — scheme strength vs verification status.

**presentedBy selection rule**
- presentedBy MUST be one of the claim references appearing in `claims` (matching by canonical scheme and identifier).
- If the listing's `BundleRequirement.primaryClaimSelector` is set, the presenter SHOULD select the highest-tier claim of the matching scheme. If no selector is set, the presenter SHOULD select the highest-tier claim available, per the **Claim tiers** table above.
- Readers MUST accept any `presentedBy` value that resolves to a claim in `claims`. A reader MAY prefer a higher-tier alternative for display or reputation lookup but MUST NOT reject a bundle solely because `presentedBy` is not the highest-tier claim.

**Controlled `presentedBy` for reputation.** Reputation MUST NOT be keyed against an uncontrolled `presentedBy` claim, regardless of whether `primaryClaimSelector` is set. Ordinarily the resolved claim therefore needs a passing **and fresh** `verifiedBy` plus the applicable control proof from step (6). The narrow exception is an exact `key:` claim whose valid bundle presentation itself proves control: it MAY key reputation at the lowest (plain signing-key) tier without a `VerifyResult`. This exception proves control of that signing key only; it does not make the key verified, elevate `identityTier`, or transfer control to another presence-only claim. A presence-only authority identifier such as `lei:` remains existence-only and MUST NOT become `presentedBy` or a reputation key without an independent control proof. *Existence ≠ control:* a verification that only confirms the identifier is real, with no DACS-1 control proof binding it to the presenter, does not qualify the claim as a controlled reputation key.

> **Note (non-normative).** This stops an unverified-or-stale high-tier identifier (e.g. an `lei:` the presenter does not control, or one whose verification has gone stale) from laundering reputation onto itself while preserving the useful self-authenticating `key:` case. The MA-3/PCR-5 controlled-presentedBy check (§6.3.3) enforces this at match time when a selector is set; this rule extends the same protection to the no-selector case where reputation still keys on `presentedBy` (§6.6, §10.5.2).

**Verification reference resolution.** For a BundleClaim with `verifiedBy` present, the reader runs these checks in order; **any failure makes the claim unverified** for evaluation against bundle requirements:

1. **Fetch** the VerifyResult from `VerifyResultRef.anchor.locator` (the indicated kind).
2. **Hash-check** — canonicalise the fetched content to its RFC 8785 form and confirm `sha256(canonical_form) == VerifyResultRef.contentHash` (mismatch MUST cause rejection). A VerifyResult is always a canonical-JSON DACS document (§7.5), so only this canonical-form branch applies to a VerifyResultRef — raw-byte attestations are handled in §7.5.2.
3. **Parse + recipe-check** — parse the canonicalised content as a DACS-2 VerifyResult and verify it matches the recipe at `recipeVersion`.
4. **Identifier match** — `VerifyResult.identifier` matches the `BundleClaim.ref` identifier component canonically.
5. **Decision** — `VerifyResult.decision == "pass"`.
6. **Control (for controlled use only)** — for a claim to serve as a **controlled** claim (the bundle's `presentedBy`, and the claim reputation keys against), the presenter MUST have **proven control** of it — a **DACS-1** property, established by one of: the **bundle presentation signature** for a `key:` claim (§6.3.2 / §B.7); the **anchored address-key linkage** (SR-1) for a `cci-xm:` claim; a credential **holder-binding** proof (§7.3.2 — the presenter signs with the credential-subject key) for a VC / vLEI claim; or, for `domain:`, a passing-and-fresh `demos-gcr-domain` result plus a bundle presentation that verifies under the result's exact GCR-bound Ed25519 account (DCR-7). A claim established **only** by a DACS-2 existence/validity check (a `pass` confirming the identifier is real but binding no key — e.g. a bare-registry `lei` lookup) is **valid-but-uncontrolled**: it MAY satisfy a required claim and serve as supporting context (its verified `data`), but it MUST NOT be the `presentedBy` claim and reputation MUST NOT key against it. Control follows the **proof, not the storage** — materialising a claim from a DACS-1 / CCI context confers no control on its own. Steps 1–5 gate use as a *required* claim per the listing's `BundleRequirement`; step 6 additionally gates the *controlled* uses.

   Key rotation, revocation, and post-revocation validity after this control proof are governed by the §6.6 **Key lifecycle** rules; a historical proof does not make a rotated or revoked key current for a new session.

**Freshness window.** The claim's effective window is derived from the resolved VerifyResult, **not** the presenter-supplied wrapper:
- **Issuance** = `VerifyResult.verifiedAt`.
- **Expiry** = `min(BundleClaim.expiresAt ?? ∞, VerifyResult.validUntil ?? (verifiedAt + defaultMaxAgeSec × 1000))`, where `defaultMaxAgeSec` is read from the recipe at `VerifyResult.recipeVersion` (the exact recipe the result was validated under, §7.4.3 — NOT "latest", so a later recipe revision cannot retroactively widen an already-issued result's window).
- **Presenter narrows only** — a `BundleClaim.issuedAt` later than `verifiedAt`, or an `expiresAt` later than `VerifyResult.validUntil`, MUST be ignored (clamped to the authority window): a presenter cannot extend the authority's freshness window with a generous wrapper timestamp.
- **Fail-closed for verified use** — if `VerifyResult.validUntil < verifiedAt`, or `verifiedAt` is absent/non-numeric, the window is undeterminable and the claim MUST be treated as stale. When `verifiedBy` is absent there is no authority window: the claim cannot satisfy a verification-required use, but it MAY still satisfy an explicit presence-only requirement under PCR-1..PCR-3.
**Staleness**
A `verifiedBy` reference is **stale** when `now >` the effective expiry from the **Freshness window** above (`verifiedAt`/`validUntil` are unix ms; `defaultMaxAgeSec` is seconds → ×1000). This is the same `validUntil`-aware window VP-C1 uses for reuse (§7.6.1), so the freshness and reuse rules agree. When `verifiedBy` is absent or its window is undeterminable, the reference MUST be treated as stale (fail-closed) for verification-required use — an unknown age MUST NOT pass the freshness gate. A stale verification MUST be refreshed during the Vet stage (DACS-2) only when the applicable `ClaimRequirement.verificationRequired` is `true`; a presence-only match MUST NOT trigger or depend on that refresh.

**Conformance — bundles**
A conforming bundle **producer** MUST:
- (BP-1) produce JCS-canonical serialisation for hashing and signing;
- (BP-2) include at least one claim;
- (BP-3) provide `presentedBy` that resolves to a claim;
- (BP-4) provide a presentation signature that verifies against the domain-separated payload `signed_bytes` (`"dacs-bundle-presentation:v1:" || bundle_hash`, §6.3.2) — not the raw bundle hash.
A conforming bundle **reader** MUST:
- (BR-1) recompute the bundle hash from canonical form before the signature check;
- (BR-2) reject a bundle whose presentation signature does not verify;
- (BR-3) reject a bundle in which a required (per listing) claim has a missing or invalid `verifiedBy` when `verificationRequired = true`;
- (BR-4) treat claims with unknown schemes as unverified;
- (BR-5) when the listing sets `primaryClaimSelector`, apply MA-3/PCR-5 to the exact `presentedBy` claim. It MUST be controlled and either verified-and-fresh or explicitly authorized by a satisfied presence-only selector requirement. The latter path is usable for a self-authenticating `key:` presentation but does not make an existence-only identifier controlled. A separately verified claim of the same scheme MUST NOT launder the selected claim.
**Selective disclosure (scope note).** v0.1 provides no per-claim selective-disclosure mechanism at the bundle layer: there is no per-claim blinding, no commitment-with-open-on-demand, and no proof-of-possession-without-disclosure for a claim a listing did not require. Concretely:

- A verifier that receives a bundle sees every claim in `claims[]`; the `presentedBy` primary claim is always disclosed and is the cross-session correlator used for reputation and audit (§6.4 Rationale, §6.3.4).
- The DACS-2 zkTLS / TLSNotary methods (§7.3.3 tlsnotary, §7.3.4 zktls) protect the secret *inside* a claim's verification; they do NOT conceal *which* claims a party holds from a counterparty.
- The only minimisation available in v0.1 is presenter-side: a presenter MAY publish a bundle containing only the claims a given listing requires, accepting that the primary claim remains linkable across presentations.
- Implementers MUST NOT treat DACS-1 + a privacy-preserving DACS-2 method as an end-to-end selective-disclosure guarantee.

Blinded / minimised-claim presentation is a named follow-on item (§11.2.7).

#### 6.3.2.1 Identity tier derivation (optional, deterministic)

An optional `identityTier` signal MAY be computed from an `IdentityBundle` to give downstream systems a single-word summary of identity quality. It is a derived convenience over the claim set, not a new trust primitive; the load-bearing facts remain the individual `BundleClaim.verifiedBy` references.

**The tier is never trusted as self-reported.** A conformant reader MUST derive it deterministically from the bundle's claims and MUST ignore (and recompute over) any self-asserted `identityTier` value a presenter places in the bundle or its metadata. Only a **verified** claim — a `BundleClaim` whose `verifiedBy` resolves to a `decision == "pass"` VerifyResult that is **fresh** per the §6.3.2 effective-window gate — counts toward tier elevation; a missing, failing, or stale `verifiedBy` does not.

**Derivation rule (normative).** A conformant reader MUST compute `identityTier` in this priority order:

1. If `claims[]` contains at least one **verified** claim whose `ref.scheme` is an authority-issued regulatory scheme (`lei`, `finra-crd`, `sam-uei`, `fedramp`, `cmmc`, `naics` — tier 1 in the §6.3.2 Claim tiers table), the tier is `"institutional"`.
2. Else if `claims[]` contains at least one **verified** claim of any other scheme (an ERC-8004 / W3C DID / platform identifier / signing key carrying a passing-and-fresh `verifiedBy`), the tier is `"verified"`.
3. Otherwise (no verified claim — only self-asserted or stale claims), the tier is `"self-declared"`.

Institutional precedence is strict: a bundle holding both a verified `lei:` and a verified `did:` derives `"institutional"`. The three values key on **verification status**, not scheme tier alone: a verified **tier-1** (authority-issued) claim → `"institutional"`; any other **verified** claim (DID / ERC-8004 / platform / signing key) → `"verified"`; **no** verified claim → `"self-declared"`. A verified `key:` is therefore `"verified"` even though it is the lowest §6.3.2 presentedBy tier — the presentedBy ranking (scheme strength) and this derivation (verification status) answer different questions, so neither overrides the other.

| Value | Meaning | Example |
|-------|---------|---------|
| `institutional` | Backed by a regulated / high-assurance entity identifier with real-world cost | verified `lei:`, `finra-crd:`, `sam-uei:` |
| `verified` | A non-authority identity carrying a passing-and-fresh DACS-2 verification | `did:` or `key:` with a verified `verifiedBy` |
| `self-declared` | Raw cryptographic identity, no passing-and-fresh verification | plain `key:` / `did:` with no (or stale) `verifiedBy` |

**Relationship to DACS-5.** `identityTier` is a creation-time signal about identity *quality*; a behavioural-reputation signal about conduct *after* transactions begin (e.g. a `suspiciousPatternFlags` field, a roadmap candidate) is an orthogonal dimension and SHOULD remain a separate field, not be blended into a single score.

**Conformance — identity tier derivation (IT-1..IT-3).** A reader that computes `identityTier` MUST: (IT-1) derive the tier from verified-and-fresh claims only, using the priority rule above; (IT-2) ignore any self-asserted `identityTier` value and recompute; (IT-3) produce the same tier as any other conforming reader for the same `IdentityBundle`.

#### 6.3.3 Bundle requirement schema

A listing declares which bundles it will accept.

```
type BundleRequirement = {
  requirementVersion: "1"
  required: ClaimRequirement[]         // all MUST be satisfied; MAY be empty
  oneOf?: ClaimRequirement[][]         // omitted/empty adds no constraint; each present inner group MUST be non-empty and satisfied (AND across groups); a group is satisfied when ≥1 of its members is satisfied (OR within a group)
  preferredPresentation?: "siwd" | "sr1-root" | "per-claim" | "session-key" | "any"
  primaryClaimSelector?: string        // scheme whose identifier MUST be `presentedBy`
}
type ClaimRequirement = {
  scheme: string                       // e.g. "lei"
  verificationRequired: boolean
  maxAge?: number                      // verificationRequired=true only; seconds; tightens (never widens) the effective freshness window
  recipeVersion?: number               // verificationRequired=true only; pin a specific DACS-2 recipe version (§7.4.1); else latest-at-session-start
  parameters?: Record<string, unknown> // scheme-specific
}
```

**Presence-only claim requirements (PCR-1..PCR-6).** `verificationRequired` selects one of two closed evaluation modes; it is not a hint to a verifier.

- **(PCR-1) Configuration boundary.** `verificationRequired` MUST be the JSON boolean `true` or `false`; another type or absence is a requirement error. When `verificationRequired = false`, the requirement is **presence-only**. `maxAge` and `recipeVersion` MUST be absent because no authority result or authority time window is selected. Their presence is a requirement error, not an instruction to manufacture or resolve a `VerifyResult`. When `verificationRequired = true`, the existing verification and freshness rules apply unchanged. An empty `required` array and an omitted or empty `oneOf` array impose no member constraint; an empty inner `oneOf` group is a requirement error rather than an unsatisfiable or silently satisfied group.
- **(PCR-2) Presence predicate.** A presence-only member passes only when the signed `IdentityBundle` contains a claim of the required known scheme whose reference is canonical, whose unexpired `expiresAt` (when present) contains `now`, and whose signed `BundleClaim` data satisfies `parameters` (when present). A match establishes only that the presenter signed those claim values; it does not authenticate them against an external authority. A missing claim, an expired `expiresAt`, or a parameter mismatch is a non-match. `issuedAt` is informational in this mode: it MAY be absent and, when present, MUST NOT be treated as an authority issuance time or proof of verification.
- **(PCR-3) Optional verification reference.** A presence-matched claim MAY carry `verifiedBy`, but its decision, freshness, resolution availability, and reuse status MUST NOT elevate or defeat the presence decision. Readers MUST NOT dereference it solely to decide presence. The reference still MUST have the `VerifyResultRef` wire shape; a malformed reference makes the bundle evaluation an error. This rule does not erase the reference or permit its use as passing verification elsewhere.
- **(PCR-4) Verified predicate.** A member with `verificationRequired = true` passes only through the §6.3.2 resolution, passing-decision, freshness, `maxAge`, recipe, and parameter checks. Presence of a matching claim is insufficient.
- **(PCR-5) Control and tier boundary.** Presence is not control and is not verification. It MUST NOT elevate `identityTier`, establish a controlled `presentedBy`, or key reputation. MA-3 permits an exact presence-only selector only when the requirement explicitly authorizes that presence path **and** the presenter independently proves control under §6.3.2 step (6). A valid bundle presentation proves this for its exact `key:` claim; an existence-only authority identifier such as `lei:` does not. A different verified claim of the same scheme MUST NOT supply control or verification to the selected claim.
- **(PCR-6) DACS-2 bridge.** Vet evaluates presence-only members directly against the exact signed bundle bound by `CompositeVerificationRecord.bundleHash`; it MUST NOT emit a synthetic `VerifyResult` or `VerifyResultRef` for presence. DACS-2 §7.7.1 defines mixed required/`oneOf` aggregation and strict replay.

**Matching algorithm**
A reader MUST evaluate a candidate IdentityBundle against a BundleRequirement using the following deterministic algorithm:

```
match(bundle, requirement):

  0. Verify the original bundle bytes, hash, and presentation signature.

     Then derive a semantic claim set: canonicalize domain hosts under DCR-1,

     map readable web2:domain aliases to domain:, and collapse equal aliases

     under DCR-5. All following steps operate on that set; the original bytes

     remain unchanged and current dual-alias producers are still non-conforming.

     Validate every ClaimRequirement before matching. An unknown/non-canonical

     scheme, a non-boolean/missing verificationRequired, a malformed parameters

     value, or an empty inner oneOf group returns ERROR. Empty required and

     omitted/empty oneOf collections are valid and add no member constraint.

     If a presence-only member

     carries maxAge or recipeVersion, return ERROR (PCR-1). Validate every

     present BundleClaim.verifiedBy as a VerifyResultRef wire value; a malformed

     reference returns ERROR even though a presence-only decision does not resolve it (PCR-3).

  1. (MA-1) For each cr in requirement.required:

       result := find_claim(bundle, cr)

       if result == error: return ERROR("invalid claim or requirement: <cr.scheme>")

       if result != pass: return REJECT("missing or unsatisfied required: <cr.scheme>")

  2. (MA-1) For each group in (requirement.oneOf or []):

       any_satisfied := false

       for each cr in group:

         result := find_claim(bundle, cr)

         if result == error: return ERROR("invalid oneOf member: <cr.scheme>")

         if result == pass: any_satisfied := true; break

       if NOT any_satisfied: return REJECT("oneOf group unsatisfied")

  3. (MA-2) If requirement.primaryClaimSelector is set:

       if bundle.presentedBy.scheme != requirement.primaryClaimSelector: return REJECT

  3b. (MA-3) If requirement.primaryClaimSelector is set:

       // The exact claim presentedBy resolves to MUST itself be controlled — not merely some claim of the selector scheme.

       // Otherwise a presenter could launder reputation by pairing an unverified (or third-party) presentedBy identifier with a *different*, already-verified claim of the same scheme.

       presented := the claim c in bundle.claims whose c.ref matches bundle.presentedBy by canonical scheme AND identifier (the §6.3.2 presentedBy resolution rule)

       if presented is null: return REJECT   // presentedBy does not resolve to a claim in the bundle

       verified_selector := presented has a passing-and-fresh verifiedBy under the §6.3.2 verified-claim gate

       presence_selector := exact_presented_satisfies_presence_member(requirement, presented)

                            AND no required verificationRequired=true member has the selector scheme

                            AND every oneOf group containing a verificationRequired=true member of

                                the selector scheme is satisfied either by an exact presence-only

                                member for presented or by a passing member of another scheme

       controlled := presenter proves control of the exact presented claim under §6.3.2 step (6)

       if NOT controlled OR NOT (verified_selector OR presence_selector): return REJECT

       // A valid key: bundle presentation can satisfy controlled+presence_selector.

       // An existence-only lei: cannot. A different verified same-scheme claim cannot launder either predicate.

  4. If requirement.preferredPresentation is set AND != "any":

       if bundle.presentation.kind != requirement.preferredPresentation: return WARN, accept

  5. return ACCEPT

exact_presented_satisfies_presence_member(requirement, presented):

  selector := canonical_scheme(presented.ref)

  return any cr in requirement.required ++ flatten(requirement.oneOf) where

         cr.scheme == selector

         AND cr.verificationRequired == false

         AND presented.ref is canonical

         AND (presented.expiresAt is absent OR now <= presented.expiresAt)

         AND (cr.parameters is absent OR scheme_specific_match(presented, cr.parameters))

find_claim(bundle, cr):

  if cr.verificationRequired == false AND (cr.maxAge present OR cr.recipeVersion present): return error

  for each c in bundle.claims:

    if c.ref.scheme != cr.scheme: continue

    if c.ref is non-canonical OR c.verifiedBy is present but malformed: return error

    if c.expiresAt is present AND now > c.expiresAt: continue

    if cr.parameters AND NOT scheme_specific_match(c, cr.parameters): continue

    if cr.verificationRequired == false:

      // issuedAt and any well-shaped verifiedBy are non-authoritative for this decision.

      // Do not resolve verifiedBy and do not run a verification freshness gate (PCR-2/PCR-3).

      return pass

    if c.verifiedBy missing OR resolution fails OR (the VerifyResult resolved from c.verifiedBy).decision != "pass": continue

    // Verification-required freshness gate (PCR-4). It does not run for presence-only members.
    // Freshness is keyed on the EFFECTIVE window from the resolved VerifyResult (§6.3.2 clamp):
    //   vr := the VerifyResult resolved from c.verifiedBy
    //   eff_verifiedAt := vr.verifiedAt
    //   eff_expiry := min(c.expiresAt ?? ∞, vr.validUntil ?? (eff_verifiedAt + recipe(c.ref.scheme, vr.method, vr.recipeVersion).defaultMaxAgeSec * 1000))
    //     (defaultMaxAgeSec from the recipe family at (scheme, method, recipeVersion) — the exact recipe vr was validated under, not "latest")
    // Presenter-supplied c.issuedAt/c.expiresAt cannot extend this window (clamped, §6.3.2).
    // Window undeterminable (verifiedBy missing, verifiedAt absent, or vr.validUntil < eff_verifiedAt) → fail closed.
    if c.verifiedBy missing OR vr window undeterminable OR now > eff_expiry: continue
    if cr.maxAge AND (now - eff_verifiedAt) > cr.maxAge * 1000: continue   // listing-tightened bound (overrides the recipe default downward); ms vs seconds → ×1000

    return pass

  return fail
```

scheme_specific_match is defined per scheme in DACS-2 recipes. Where parameters are unrecognised, readers MUST treat the requirement as unmatched (not silently passed).

**Failure mode and selector semantics**
A BundleRequirement that does not match MUST cause the buyer or seller to refuse to advance the transaction past the Vet stage. v0.1 specifies no downgrade or renegotiation path. The primaryClaimSelector controls which claim’s identifier is used as the reputation key in DACS-5 and the counterparty identifier of record for audit purposes. Listings that handle regulated flows SHOULD set primaryClaimSelector to an authority-issued scheme (e.g., lei) to ensure reputation accumulates against a stable, externally-verifiable identifier rather than a session key.

#### 6.3.4 Service listing

The listing is the canonical contract for a transaction.

**Schema**

```
type Listing = {
  // Versioning
  dacsVersion: "1"
  listingVersion: number               // monotonic per listingId, starts at 1
  listingId: string                    // unique per listing publisher; URL-safe ASCII; max 128 chars
  requiredCapabilities?: SubstrateRequirement[]
  // Listing publisher (named seller for wire compatibility; role interpretation below)
  seller: {
    identity: IdentityBundle           // listing publisher's own bundle
    displayName: string                // max 200 chars
    publicEndpoint?: string            // optional HTTPS endpoint
  }
  // Offering
  offering: {
    title: string                      // max 200 chars
    description: string                // max 2000 chars
    category: string                   // dot-delimited (e.g. "data.finance.fx")
    tags: string[]                     // max 16 tags, max 32 chars each
    deliverable: DeliverableSpec       // per DACS-4
    extendedDescriptionUrl?: string
    extendedDescriptionHash?: string
  }
  // Counterparty requirement (field name preserved for wire compatibility; role interpretation below)
  buyerRequirement: BundleRequirement
  // Pipeline of phases to execute, per DACS-3/4/5
  pipeline: PhaseStep[]                // non-empty, ordered
  // Pricing and accepted rails, per DACS-4
  pricing: PricingSpec
  acceptedRails?: PaymentRailRef[]      // OPTIONAL: required and non-empty IF pipeline contains a concrete pay-* or pay-alternative phase
  // Terms
  terms: ListingTerms
  // Validity window
  validity: {
    notBefore: number                  // unix ms
    notAfter?: number                  // unix ms; absent => no expiry
  }
  // Listing-level signature
  signature: ListingSignature
}
type SubstrateRequirement =
  | "SR-1" | "SR-2" | "SR-3" | "SR-4" | "SR-5"
type ListingTerms = {
  termsOfServiceUrl?: string
  termsOfServiceHash?: string
  jurisdictions?: string[]             // ISO 3166-1 alpha-2 codes
  conflictOfLawsRule?: "buyer-jurisdiction" | "seller-jurisdiction" | "rule-ref:<uri>"
  deadlineSecAfterCommit?: number
  acceptanceModel?: "auto-accept"      // §8.4.1; when set, the seller pre-issues an AutoAcceptCommitment instead of a per-session signature
  cancellationPolicy?: "none" | "pre-commit" | "with-fee"   // "pre-commit" is honoured as a reputation-neutral cancellation; "none" and "with-fee" are not — see note below
  retentionYears?: number
  transcriptDisclosurePolicy?: "none" | "encrypted-anchored-recommended" | "encrypted-anchored-required"
}
```

**Listing publisher and counterparty roles.** The `seller` field is the **listing publisher and listing signer** for all listing kinds; the field name is retained for wire compatibility with v0.1 listings. For ordinary listings — fixed-price, RFQ, and sealed-envelope demand (`negotiate-sealed-envelope` or `negotiate-sealed-envelope-complete`, absent or `"demand"` `auctionMode`) — the listing publisher is also the agreement `seller`, and `buyerRequirement` gates the buyer / bidders. For sealed-envelope procurement (`negotiate-sealed-envelope-procurement` or `negotiate-sealed-envelope-procurement-complete`, DACS-3 §8.4.3 SE-8 / §8.4.4 SAC-9), the listing publisher is the prospective agreement `buyer`, the winning bidder is the agreement `seller`, and `buyerRequirement` gates the bidders / suppliers eligible to submit bids. Implementations MUST NOT infer final AgreementArtifact roles from the DACS-1 field names alone; DACS-3 assigns agreement roles from the negotiation pattern and pinned mode. Logical-address variables named `sellerPrimaryClaim` and revocation markers continue to use the listing publisher's primary claim.

**`cancellationPolicy` semantics.** The field MAY be advertised. A signed listing advertising **`pre-commit`** grants a reputation-neutral cancellation right: a party that withdraws while the session is still pre-commit (a `vet-pending` / `negotiate-pending` state, before `commit-completed`) MAY mark the resulting `aborted-by-self` as a policy-permitted cancellation, which a verifier honours as reputation-neutral after resolving this **signed** listing and confirming the policy and the pre-commit timing (DACS-5 §10.3.1 ST-10). The neutrality derives from the *signed, advertised* policy — the mutual notice is what earns it; an unannounced withdrawal (no advertised policy, or a `none` policy) remains an ordinary `aborted-by-self` per §10.3.1 ST-3, and a withdrawal whose listing cannot be resolved is treated as indeterminate, never as a free neutral exit (ST-10 trichotomy).

**`none`** permits no neutral cancellation. **`with-fee`** — a cancellation owing a fee after `commit-completed` — is **reserved and not defined**: it confers no neutrality, and a session ending after commit records its ordinary §10.3.1 outcome regardless of a `with-fee` advertisement.

```
type ListingSignature = {
  algorithm: "ed25519" | "ecdsa-secp256k1" | "sr1-aggregate"
  signer: ClaimReference               // MUST appear in seller.identity.claims
  value: string                        // unpadded Base64URL (CORE §B.7 SIG-6) over "dacs-listing:v1:" || listing_hash
}
```

DeliverableSpec, PricingSpec, and PaymentRailRef are normatively defined in chapter 9 (DACS-4). PhaseStep is defined below. A listing MUST use types that conform to the cited specs.

**PhaseStep schema**

```
type PhaseStep = {
  kind: PhaseType                           // closed v0.x set at this revision, below
  parameters?: Record<string, unknown>      // per-`kind` shape defined in the owning spec
}
type PhaseType =
  // DACS-2
  | "vet-credentials"
  // DACS-3
  | "negotiate-fixed-price" | "negotiate-rfq" | "negotiate-sealed-envelope" | "negotiate-sealed-envelope-procurement"
  | "negotiate-sealed-envelope-complete" | "negotiate-sealed-envelope-procurement-complete"
  | "commit-agreement" | "commit-payee-bound-agreement" | "commit-selection-bound-agreement"
  // DACS-4
  | "pay-evm-erc20" | "pay-solana-spl"
  | "pay-cross-chain-htlc" | "pay-cross-chain-liquidity-tank"
  | "pay-ap2" | "pay-x402" | "pay-dem" | "pay-alternative"
  | "deliver-storage-program" | "deliver-entitlement" | "deliver-attested-payload"
  // DACS-5
  | "rate"
```

Per-kind parameter shapes are normative in the owning chapter:

| Phase kind | Parameters | Owning chapter |
| --- | --- | --- |
| vet-credentials | none | 7 |
| negotiate-fixed-price | none | 8 |
| negotiate-rfq | {maxTurns, timeoutSec, channelSubnet?, rfqInitiator?} | 8 |
| negotiate-sealed-envelope | {commitDeadline, revealWindow, selectionRule, auctionMode?, channelSubnet?}; `auctionMode`, when present, MUST be `"demand"` | 8 |
| negotiate-sealed-envelope-procurement | {commitDeadline, revealWindow, selectionRule, auctionMode, channelSubnet?}; `auctionMode` MUST be `"procurement"` and is defined in §8.4.3 | 8 |
| negotiate-sealed-envelope-complete | {commitDeadline, revealWindow, selectionRule, candidateSetBinding, auctionMode?, channelSubnet?}; `selectionRule` is `"lowest-price"` or `"highest-price"`; `auctionMode`, when present, MUST be `"demand"`; DACS-3 §8.4.4 | 8 |
| negotiate-sealed-envelope-procurement-complete | {commitDeadline, revealWindow, selectionRule, candidateSetBinding, auctionMode, channelSubnet?}; `selectionRule` is `"lowest-price"` or `"highest-price"`; `auctionMode` MUST be `"procurement"`; DACS-3 §8.4.4 | 8 |
| commit-agreement | none | 8 |
| commit-payee-bound-agreement | none | 8 |
| commit-selection-bound-agreement | none; consumes only `SealedSelectionAgreementDocument` | 8 |
| pay-alternative | {alternatives: PaymentRailRef[]} (DACS-4 APR-1; listing projection only, never executable) | 9 |
| pay-* | {rail: string} (railId) | 9 |
| deliver-* | none (details come from the listing’s DeliverableSpec) | 9 |
| rate | optional {required?: boolean} | 10 |

For a new session under the current DACS-1 v0.8 / DACS-3 v0.6 profile, a sealed-envelope listing MUST use one of the two `*-complete` negotiation phases and `commit-selection-bound-agreement`. The two earlier sealed phase kinds remain valid signed historical inputs and may complete an already pinned session, but they cannot establish candidate-set completeness and MUST NOT be selected for a new current-profile session. This is paired with the structurally distinct new phase and agreement types so an older reader rejects a current complete-profile listing rather than silently ignoring its security requirements.

**Canonical serialisation and signature**
The listing follows the §B.2 canonical-form template, omitting the `signature` field. The signature.value is computed over:
signed_bytes := "dacs-listing:v1:" || listing_hash
Verifiers MUST:

- recompute the canonical form, listing hash, and domain-separated signed bytes;
- resolve signature.signer to the corresponding key (via seller.identity.claims, then via DACS-2 verification if a verifiable identifier);
- verify the signature against signed_bytes.

If signature.algorithm is sr1-aggregate, the signer’s IdentityBundle.presentation MUST be of kind sr1-root and the signature is the SR-1 root signature over signed_bytes — the SR-1 aggregate signature scheme applies to the same domain-separated payload, not directly to the listing hash.

**Anchoring and size limits**
A listing MUST be anchored using SR-2.

**Logical address vs native address.** DACS specifies a *logical* address pattern for each artifact kind. The logical pattern for a listing is dacs1:{sellerPrimaryClaim}:{listingId}:v{listingVersion}. The logical pattern is a stable, substrate-independent identifier the protocol reasons about; it is not necessarily the literal string the substrate accepts as an address. Each substrate-binding section specifies how the logical pattern maps to the substrate’s native addressing.

**Demos binding.** On Demos, the substrate’s StorageProgram addressing requires colon-free names and resolves writes to a sha256-derived handle of the form stor-<hex>. The Demos binding for a DACS listing therefore is:

```
logical_address    := "dacs1:" + sellerPrimaryClaim + ":" + listingId + ":v" + listingVersion   // CF-4-encoded segments
storageProgramName := implementation-defined colon-free StorageProgram name   // opaque write input; Demos rejects ":" in names

// Actual StorageProgram address derivation (SDK: storage/StorageProgram.ts):
native_address     := "stor-" + first40hex( sha256( deployerAddress + ":" + storageProgramName + ":" + nonce + ":" + salt ) )
```

`storageProgramName` is implementation-defined: DACS does not define a reversible `logical_address → storageProgramName` encoding. A producer MUST choose a colon-free name accepted by Demos and MUST treat that name as an opaque write input, not as a canonical identifier or a consumer resolution key. Different conforming producers MAY choose different names for the same logical address; interoperability is provided by the published logical→native binding below.

Because the native derivation folds in that implementation-defined name, the **deployer address**, and the **per-write transaction nonce** (and truncates to 40 hex / 160 bits), the native address is **not** recomputable from the logical address alone — this is the write-input-mapping case of the front-matter universal rule. Implementations on Demos MUST therefore:

- (a) anchor at native_address;
- (b) carry logical_address (in CF-4-encoded form) as descriptive metadata on the anchored record;
- (c) publish the logical→native binding via the listings index (§6.3.5) and catalog (§6.3.6).

Consumers resolve a listing by looking up native_address for the logical_address through the published binding, then reading the StorageProgram at native_address and verifying the content hash. The anchor transaction (the on-chain write) is the canonical pointer; the substrate’s native address is the addressable handle.

*Forward note.* A future SDK capability to anchor a StorageProgram at a caller-chosen address — or a Demos-native deterministic `logical → native` function that hashes only the logical address — would restore direct recomputation (the pure-mapping case) and let consumers resolve without the published binding. Until then the binding-publication requirement above governs.

**Logical-address delimiter encoding (rule CF-4).** A listing's logical address `dacs1:{sellerPrimaryClaim}:{listingId}:v{listingVersion}` has a colon-bearing variable segment — `sellerPrimaryClaim`, a ClaimReference (e.g. `cci-xm:evm:8453:0x1234`) — that is percent-encoded before assembly per **rule CF-4 (CORE §B.1)**; `listingId` is URL-safe ASCII, so it carries no reserved delimiters. CF-4 governs only the address *string*'s reversible parseability. How it maps to a substrate's *native* address is governed by the §"Logical vs native addresses" universal rule and, for Demos, the Demos-binding block above. The CF-4 table in CORE §B.1 enumerates the variable vs fixed segments for every `dacsN:` address kind across the stack.

Substrates MAY use equivalent addressing schemes; the requirement is that any party with substrate access can dereference an anchor reference to the canonical content and verify the content hash.

**Size cap.** The canonical JSON form of a listing MUST NOT exceed 16,384 bytes (16 KB). Listings exceeding the cap MUST use the extendedDescriptionUrl + extendedDescriptionHash pattern to host verbose offering descriptions externally with content-hash binding. The cap applies after canonicalisation; the actual on-chain payload size may differ slightly due to substrate encoding. On substrates whose SR-2 implementation has a smaller per-record cap, the substrate cap governs (the lesser of 16 KB and the substrate cap). Implementations MUST reject listings exceeding the applicable cap at the validation step (LR-2).

**Operational engagement and reachability.** Cryptographic validity answers
"who signed these terms?"; it does not establish that a buyer can contact the
seller now. A publisher advertising an active listing through a well-known
index or catalog SHOULD expose at least one currently actionable,
machine-readable engagement surface. This MAY be the listing's HTTPS
`seller.publicEndpoint`, a surface defined by an accepted rail, or a
negotiation-transport coordinate defined by the owning registry. A
`publicEndpoint`, when present, SHOULD answer an unauthenticated discovery
request with enough information for an agent to start or negotiate the listed
service; execution itself MAY require authentication, payment, or a private
channel.

Intent-scoped payment resources need not quote before an agreement exists. In
particular, an x402 `resourceBase` MAY expose discovery metadata at its base and
issue HTTP 402 only at a job-specific resource created from a signed agreement.
The discovery response SHOULD explain how to create that intent and provide the
resource template. A dead base URL and a dead `publicEndpoint` do not combine
into an actionable surface.

- (LP-5) Before publishing or refreshing an active discovery record, the
  publisher SHOULD probe its advertised engagement surface and SHOULD withdraw,
  revoke, or clearly mark the record unavailable when no actionable surface
  remains.
- Reachability is time-varying operational evidence. A failed or successful
  network probe MUST NOT change the listing's content hash, signature validity,
  historical conformance, or revocation result, and MUST NOT be inserted into
  the reader validation order below.
- A consumer MAY decline to start a session with a currently unreachable
  listing. It SHOULD distinguish `unreachable` from `invalid` and retain the
  verified listing for audit/history.

**Versioning, immutability, revocation**
Versioning rules:

- Each listingVersion is independently anchored. Prior versions MUST remain readable.
- A new version supersedes prior versions for new sessions; sessions already past their DACS-3 agreement commitment phase MUST continue against their pinned version.
- listingVersion MUST be monotonically increasing per listingId. Versions MUST NOT be skipped.

**Revocation marker and binding.** A `RevocationMarker` is the seller's signed withdrawal of one listing version. A `RevocationBinding` locates that marker without relying on its StorageProgram name.

```
type RevocationSignature = {
  algorithm: "ed25519" | "ecdsa-secp256k1" | "sr1-aggregate"
  signer: ClaimReference
  value: string                        // unpadded Base64URL, CORE §B.7 SIG-6
}

type RevocationMarker = {
  listingId: string
  listingVersion: number
  listingContentHash: string
  revokedAt: number
  reason?: string
  signature: RevocationSignature
}

type RevocationBinding = {
  sellerPrimaryClaim: ClaimReference
  listingId: string
  listingVersion: number
  listingContentHash: string
  logicalAddress: string
  markerAnchor: { kind: string; locator: string }
  markerContentHash: string
}

type RevocationCheck = "absent" | "revoked" | "indeterminate"
```

A seller MAY revoke one listing version by completing RB-1..RB-3.

- (RB-1) A seller revoking a listing version MUST anchor one `RevocationMarker` via SR-2. Its logical address is `dacs1-revoked:{sellerPrimaryClaim}:{listingId}:v{listingVersion}`, encoded per CF-4.
- The anchored record MUST carry the RB-1 logical address as descriptive metadata. Its native address follows the applicable substrate's §A.2 mapping.
- The marker's `signature` MUST cover `"dacs-revocation:v1:" || markerContentHash` per §B.7. `markerContentHash` is `sha256` of the §B.2 canonical marker with `signature` omitted.
- The marker's signer MUST equal the signer of the listing version. Its three listing fields MUST equal the listing's `(listingId, listingVersion, contentHash)` tuple.
- (RB-2) The seller MUST publish a `RevocationBinding` through every discovery surface on which it publishes that listing version.
- The binding's seller and listing fields MUST equal the revoked listing's publisher and tuple. Its `logicalAddress` MUST equal the RB-1 derivation.
- The binding's `markerContentHash` MUST equal the marker hash signed under RB-1. Its `markerAnchor` MUST locate the anchored marker's native content.
- (RB-3) A discovery record for a revoked listing version MUST be retained with `status: "revoked"` and its `RevocationBinding`. An active record MUST NOT carry a `RevocationBinding`.
- (RB-4) A reader checking revocation MUST validate each discovered binding before returning `revoked`:
  1. match the binding's publisher and listing tuple to the listing under evaluation;
  2. derive the CF-4 logical address and match `logicalAddress`;
  3. fetch `markerAnchor` and recompute `markerContentHash`;
  4. verify the marker signature and signer under RB-1; and
  5. match the marker's three listing fields to the listing under evaluation.
- A binding supplies discovery only. A reader MUST NOT honour revocation from the binding without completing every RB-4 post-fetch check.
- (RB-5) A missing required binding or an incomplete RB-4 check MUST produce `indeterminate`. A reader MUST refuse a new session when the result is `revoked` or `indeterminate`.
- (RB-6) Across the discovery records consulted for one check, result precedence is `revoked`, then `indeterminate`, then `absent`. A reader MAY return `absent` only when every successfully consulted record is integrity-consistent, active, and has no binding.
- A well-known read is integrity-consistent only when `listings.json` matches `indexHash`. A catalog-only record whose `catalogObservedAt` is older than 24 hours MUST NOT establish `absent`.
- A transport failure, stale record, or integrity mismatch is `indeterminate`, not `absent`.
- Sessions already past their agreement commitment phase MUST NOT be invalidated by revocation.

> **Note (non-normative).** The binding is not a new trust root. A false pointer, tuple, or hash fails RB-4; only the listing key's existing marker signature establishes revocation.

> **Note (non-normative).** RB-6 distinguishes a completed discovery read from a resolution failure. It does not claim that one transport's successful “not found” response proves global absence across censored views.

**Validation order for readers**
Readers MUST validate listings in the following order, **halting on the first
failure**, except that the `indeterminate` result described in step 8 is
retained while the reader completes step 9:

```
type ListingValidationDisposition =
  | "verified"
  | "rejected"
  | "revoked"
  | "indeterminate"
```

1. schema conformance;
2. `dacsVersion` supported — a **major**-version gate: reject a listing whose `dacsVersion` major the reader does not implement. Minor skew is **not** checked here (and needs no per-artifact minor field), because the §11.1.2 additivity contract + SIG-5 make a newer-minor listing forward-readable by an older reader (§11.2.5);
3. `validity.notBefore ≤ now ≤ validity.notAfter` (if set);
4. canonical form well-formed and signature verifies;
5. revocation check per RB-4..RB-6 returns `absent`;
6. `seller.identity` bundle conformant per §6.3.2;
7. pipeline references valid phase types per DACS-3/4/5;
8. if pipeline contains any concrete pay-* phase or `pay-alternative`,
   `acceptedRails` MUST be present and
   non-empty and the reader MUST run listing-time rail resolution under
   LRR-1..LRR-6. A `rejected` result is a validation failure and halts. An
   `indeterminate` result is retained, MUST NOT be relabelled as `rejected`,
   and MUST NOT suppress step 9; after step 9 succeeds the listing remains
   discovery-ineligible and session-ineligible until re-resolution returns
   `verified`. If pipeline contains no pay-* phase, `acceptedRails` MAY be
   absent (the intake-only listing pattern — RFP intake, reverse auctions where
   the bid is the commitment, free services gated by reputation, sealed-bid
   procurements settled out-of-band);
9. signer resolves to a key controllable by the listing publisher (`seller.identity`).

The reader MUST compose those results into exactly one
`ListingValidationDisposition`:

- a failure at step 1–4, 6–7, or 9, and an LRR `rejected` result at step 8,
  produce `rejected`;
- the RB-4..RB-6 result at step 5 produces `revoked` or `indeterminate` when
  it is not `absent`; those revocation dispositions are not relabelled as
  `rejected`;
- an LRR `indeterminate` at step 8 is retained while step 9 runs. If step 9
  then fails, the terminal signer-control failure produces `rejected`; if step
  9 succeeds, the overall result is `indeterminate`; and
- `verified` is returned only when every ordinary validation step succeeds,
  revocation is `absent`, and listing-time rail resolution is `verified` or is
  not applicable to a pay-less pipeline.

**Listing-time rail resolution (normative).** `acceptedRails` is the publisher's signed claim about rails it is willing to use; it is not evidence that any named rail exists. A reader evaluates step 8 with a three-way `ListingRailResolution` disposition:

```
type ListingRailResolution = "verified" | "rejected" | "indeterminate"
```

- (LRR-1) **Unambiguous listing binding.** Every concrete DACS-4 `PaymentPhaseType` phase MUST carry a string `parameters.rail`, and every such value MUST equal the `railId` of at least one `acceptedRails` entry. `pay-alternative` is the sole exception: it MUST carry complete references under APR-1 and MUST NOT carry or be coerced to a single `parameters.rail`. The raw `acceptedRails` array MUST NOT contain duplicate full-canonical `PaymentRailRef` values, where equality is over the CORE §B.2 RFC 8785 canonical bytes. Canonically distinct references MAY share a `railId`: at listing time the `railId` dispatches to the one handler fixed by DACS-4 RD-6, while the complete reference carries a selectable version/parameter requirement for agreement and session start. No one complete reference is selected merely by a concrete listing phase's `parameters.rail`, and array order never selects an APR alternative. Every reference is validated independently, and every entry in `acceptedRails`, including an entry whose `railId` is not used by a particular concrete phase or alternative, is subject to LRR-2 through LRR-5. Mere membership in the listing's own array never establishes resolution.
- (LRR-2) **Authoritative source.** The reader MUST resolve one internally consistent rail-registry snapshot through DACS-4 §9.4.3. Under PA-2 or PA-3 this means reading `dacs4:registry:v0.1`, verifying the applicable steward/governance authority, and obtaining verified CORE §5.1 `finalized` receipts plus independent content resolution for the index and the definition resolved for every advertised `PaymentRailRef`. The reader MUST NOT use a catalog row, listing field, counterparty copy, or unauthenticated cache as registry authority.
- (LRR-3) **Reference-to-definition match.** For every `PaymentRailRef`, the authenticated index MUST contain that exact `railId`. If `railVersion` is present, the indexed and resolved definition MUST carry that exact version; otherwise the reader uses the index's latest version in the snapshot for this validation attempt. That result is the reference-resolved definition. It MUST match the index's anchor/content hash, verify under `dacs-rail:v1:`, repeat the reference's `railId` and the selected `railVersion`, and satisfy its schema plus RD-1..RD-6.
- (LRR-4) **Phase-handler binding.** For every concrete DACS-4 `PaymentPhaseType` phase, every reference-resolved definition whose `railId` equals the phase's `parameters.rail` MUST carry the same `phaseHandler`, as required across versions by DACS-4 RD-6, and that handler MUST equal the phase's `kind`. Two concrete phases with different kinds therefore cannot dispatch through the same `railId`. For `pay-alternative`, apply APR-2 instead: each complete alternative resolves to its own concrete handler and that handler MUST NOT be `pay-alternative`; no handler is required to equal the listing-only projection kind. Selection of one complete `PaymentRailRef` and its parameters is deferred to the agreement and session-start pin; it is not inferred from a concrete listing phase's railId-only field or from alternative array order. A listing cannot route `pay-x402`, for example, through a definition registered for `pay-evm-erc20`.
- (LRR-5) **Disposition and precedence.** Failure to authenticate the registry authority under LRR-2 returns `indeterminate`; an unauthenticated snapshot MUST NOT establish a contradiction. Once registry authority is authenticated, aggregate the checks over every advertised reference with flat precedence `rejected`, then `indeterminate`, then `verified`. Return `rejected` when the listing binding is malformed or ambiguous under LRR-1, when the authenticated snapshot conclusively lacks a named rail/version, or when an otherwise valid resolved definition contradicts the listing or phase handler under LRR-3/LRR-4. Return `indeterminate` when a required definition, finality receipt, independent content, or steward/governance key is absent, unavailable, internally inconsistent, not yet finalized, or cannot be authenticated. Return `verified` only after every applicable check succeeds. Consequently, an unavailable definition for an advertised but currently unused rail makes the whole signed listing `indeterminate` and LR-3 blocks every new session from that listing until all advertised claims resolve; a publisher can remove the unavailable claim only by issuing a new signed listing version.
- (LRR-6) **Progressive-anchoring and session boundary.** PA-1, PA-2, and PA-3 name the authority basis a reader accepts for this check, not a lifecycle state of the listing. A reader explicitly operating and disclosing PA-1 MAY resolve against its disclosed, signed in-code registry snapshot only when its trust policy accepts `governance.anchoring: "in-code"`; it MUST retain and surface `pa1-in-code` as the authority basis and MUST NOT describe that result as canonically anchored. For an unpinned PA-1 reference, the unique highest `railVersion` for that `railId` in the signed snapshot is used; duplicate definitions at that version or handler drift under RD-6 are `rejected`. A PA-2 or PA-3 reader MUST NOT fall back to in-code constants when the canonical index or a definition is unavailable. Listing-time `verified` establishes discovery eligibility only: at session start the orchestrator MUST select one complete `PaymentRailRef`, resolve and pin its exact definition under DACS-4 §9.4.3, and apply RAV-R1..RAV-R5. A discovery mirror MAY surface availability only as a non-authoritative prefilter or user-interface hint. That hint cannot satisfy the authoritative read, change `ListingValidationDisposition`, establish or refute a RAV result, or override a missing or contradictory authoritative value.

**Conformance — listing publishers and readers**
A conforming publisher MUST: (LP-1) obtain and verify a CORE §5.1 `finalized` `AnchorReceipt` for each listingVersion, and verify that its native address independently resolves to the expected content hash, before publishing the listing as `active` or referencing it from a listing index; (LP-2) sign the listing with a key referenced by a claim in seller.identity.claims; (LP-3) use monotonic listingVersion values per listingId; and (LP-4) publish and retain revocation markers and bindings per RB-1..RB-3. A submitted, broadcast-acknowledged, merely accepted, or merely index-visible listing does not satisfy LP-1. A deterministic-BFT binding may establish `included` and `finalized` in the same receipt per CORE §5.1. It SHOULD: (LP-5) probe and maintain an actionable engagement surface for every actively published record. For a pay-bearing listing it MUST: (LP-6) obtain `verified` under LRR-1..LRR-6 at publication time rather than treating its own `acceptedRails` array as proof.
A conforming reader MUST: (LR-1) pin the (listingId, listingVersion, contentHash) tuple into any session record derived from the listing; (LR-2) reject listings whose overall `ListingValidationDisposition` is `rejected`; (LR-3) refuse new sessions unless the overall `ListingValidationDisposition` is `verified`, including when it is `revoked` or `indeterminate`.

#### 6.3.5 Discovery — .well-known/agent.json extension

The .well-known/agent.json document published at the agent’s domain is extended with a dacs block:

```
{
  // ... existing A2A agent-card fields ...
  "dacs": {
    "dacsVersion": "1",
    "listings": {
      "indexUrl": "https://example.com/.well-known/dacs/listings.json",
      "indexHash": "sha256-...",
      "anchor": {
        "kind": "storage-program",
        "address": "dacs1-index:..."
      }
    },
    "identityClaims": [
      "lei:984500ABCDEF12345678",
      "domain:example.com",
      "erc8004:1:0x...:42"
    ]
  }
}
```

**Listing index file (listings.json)**

```
type ListingIndex = {
  indexVersion: "1"
  generatedAt: number
  seller: ClaimReference
  listings: ListingIndexEntry[]
}
type ListingIndexEntry = {
  listingId: string
  version: number
  contentHash: string
  anchor: { kind: string; locator: string }
  summary: {
    title: string
    category: string
    tags: string[]
    priceHint?: string
  }
  status: "active" | "revoked"
  revocation?: RevocationBinding       // REQUIRED iff status == "revoked"; forbidden when active (RB-3)
}
```

**Bundle-binding index (optional).** The `dacs` block MAY additionally carry a `bundleBindings` entry — `{ "indexUrl": …, "indexHash": "sha256-…" }` — pointing to a JSON document `{ "bindings": BundleBinding[] }` of signed DACS-5 `BundleBinding` records (§10.4.2) for sessions the agent participated in. Because a `BundleBinding` is self-authenticating (§10.4.2 BB-3), the index MAY carry either side's records, including a counterparty's. Consumers MUST verify each record per §10.4.2 BB-4; the index is discovery convenience, not a source of truth.

The index MAY itself be anchored via SR-2; if so, the well-known block’s anchor field MUST point to it. The indexHash field in the well-known block enables clients to detect stale caches. Clients MUST cross-check each ListingIndexEntry.anchor independently before engaging with a listing; the index is for discovery convenience, not a source of truth.

**Interoperability with A2A; update and revocation**
The dacs block is additive. A2A-only clients ignore the dacs field. DACS-aware clients use the dacs field for listing discovery; absence of the field MUST be interpreted as "this agent does not publish DACS listings via well-known" (the agent MAY still have listings discoverable via a catalog API). Sellers update by re-publishing listings.json with new entries and updated generatedAt; the well-known indexHash MUST be updated to match. Revocation retains the listing entry, changes its status to `revoked`, and adds the required `RevocationBinding` per RB-3.

#### 6.3.6 Discovery — catalog API

A DACS catalog is an off-chain index aggregating listings across many sellers, providing search, filtering, and discovery.

**Endpoints**

```
GET /api/dacs/listings
  Query parameters:
    category=<dot-delimited prefix>
    tag=<repeatable>
    credential=<scheme>                # listings whose buyerRequirement requires this scheme
    primaryClaim=<scheme>              # listings whose seller.identity.presentedBy uses this scheme
    rail=<railId>                      # listings accepting this rail
    priceMax=<decimal>                 # advisory; uses summary.priceHint
    minCompletionRate=<float>          # advisory; filters on reputationHint.completionRate when present
    minRating=<float>                  # advisory; filters on reputationHint.averageSellerRating when present
    cursor=<opaque>                    # pagination
    limit=<int, default 50, max 200>
  Response:
    { "listings": ListingSummary[], "cursor": <opaque>?, "total"?: <int> }
GET /api/dacs/listings/{listingId}/{version}
  Response: Listing (canonical JSON)
GET /api/dacs/bundles/{jobId}
  Response: { "bindings": BundleBinding[] }   # signed DACS-5 BundleBinding records (§10.4.2) known to this catalog for the jobId
GET /api/dacs/sellers/{primaryClaimRef}
  Response: {
    "listings": ListingSummary[],
    "identity": IdentityBundle (catalog-cached, last-seen),
    "reputation": ReputationSummary (per DACS-5)
  }
```

primaryClaimRef is URL-encoded canonical form (e.g., lei%3A984500ABCDEF12345678).

**ListingSummary, caching, authentication, cross-reference**

```
type ListingSummary = {

  listingId: string

  version: number

  contentHash: string

  anchor: { kind: string; locator: string }

  seller: { primaryClaim: ClaimReference; displayName: string }

  offering: { title: string; category: string; tags: string[] }

  pricing: { priceHint?: string; currency?: string }

  status: "active" | "revoked"

  revocation?: RevocationBinding       // REQUIRED iff status == "revoked"; forbidden when active (RB-3)

  catalogObservedAt: number

  // Optional, time-stamped catalog observation. This is operational metadata,
  // never part of the signed Listing and never a validity or trust signal.
  reachabilityHint?: {
    status: "reachable" | "unreachable" | "unknown"
    checkedAt: number
    surface?: string
  }

  // Optional: catalog-computed reputation snapshot for this seller in the listing's category.
  // Derived from the seller's DACS-5 bundles scoped to offering.category using the
  // category-scoped derivation algorithm in §10.5.4. When present, consumers MAY use this
  // as a lightweight pre-filter; they MUST NOT treat it as authoritative without deriving
  // reputation themselves from the underlying bundles (§10.5.3 computation surfaces).
  reputationHint?: ReputationHint

}

// Lightweight reputation snapshot attached to a ListingSummary.
// Scoped to the listing's offering.category prefix (e.g. "data.finance")
// so buyers see reputation for relevant transaction types, not overall lifetime metrics.

type ReputationHint = {

  // The category scope used to filter the bundles for this derivation
  // (MUST equal or be a prefix of the listing's offering.category).
  categoryScope: string

  // Completion rate in [0, 1] across bundles scoped to categoryScope;
  // null when no qualifying bundles exist (same semantics as ReputationDerivation.metrics.completionRate).
  completionRate: number | null

  // Average seller rating across bundles scoped to categoryScope; null when none.
  averageSellerRating: number | null

  // Number of bundles in the derivation window that contributed to this hint.
  bundleCount: number

  // The DACS-5 derivation window applied (unix ms).
  windowStart: number
  windowEnd: number

  // When the catalog last computed this hint. Consumers SHOULD treat hints older
  // than 24 hours as stale and fall back to deriving reputation themselves.
  computedAt: number

}
```

Catalogs MAY return cached ListingSummary records. Clients MUST dereference the anchor to obtain the canonical Listing before engaging. The catalog provides discovery; the chain provides binding. Catalogs SHOULD verify each indexed listing’s anchor at least every 24 hours; the catalogObservedAt timestamp surfaces the catalog’s confidence.

Catalogs MAY probe an advertised engagement surface and publish the result as
`reachabilityHint`. They MUST timestamp the observation, MUST treat
counterparty-supplied status as untrusted, and MUST NOT use a probe result to
rewrite listing validity, revocation, identity tier, or reputation.

Any catalog or consumer that performs a server-side network probe of a
listing- or counterparty-supplied URL MUST treat the target as untrusted and
enforce all of the following for the initial request and every subsequent
request:

- allow only explicitly supported network schemes (normally HTTPS), and reject
  loopback, private, link-local, shared-address, unspecified, multicast,
  reserved, and cloud-provider metadata destinations, including equivalent
  IPv4-mapped IPv6 spellings; an operator MAY permit a non-public target only
  through an explicit out-of-band allowlist that listing content cannot modify;
- resolve the hostname before connecting, validate every returned address,
  bind the connection to a validated address, and repeat resolution and
  validation for each new connection so DNS rebinding cannot switch the request
  to a forbidden destination after validation;
- disable redirects or re-run the complete scheme, hostname, DNS, and address
  validation at every redirect hop, with a finite redirect limit;
- enforce finite connection and whole-request timeouts plus a finite response
  byte limit, including after content decoding/decompression; and
- avoid forwarding ambient credentials, cookies, or internal authorization
  headers to the probed target.

URL syntax validation or safe link rendering alone does not satisfy these
server-fetch requirements. Renderers MUST separately safety-validate any URL
before making `surface` clickable. Consumers SHOULD regard a stale hint as
`unknown` and MAY perform their own probe only under the same bounded-fetch
requirements.

A **catalog or rendering** consumer MAY skip or partially render a listing whose `PricingSpec.kind` (DACS-4) it does not recognize, rather than reject it — a directory should not hide a listing merely because it cannot price-render it. This tolerance is scoped to rendering only; a **transacting** reader MUST still reject an unrecognized pricing kind at commit-agreement (DACS-3 MTR-5). One value, two consumer classes, opposite verdicts: the directory shows what it cannot price, the settler refuses to pay what it cannot price.
A catalog MAY carry DACS-5 `BundleBinding` records (§10.4.2); how records reach a catalog is out of scope for v0.1, exactly as for listings. A catalog that carries them MUST serve every record passing §10.4.2 BB-4 regardless of which party authored it, and consumers MUST verify each record per BB-4 before use. Read endpoints MUST NOT require authentication. Write/registration semantics are out of scope for v0.1; the canonical source of truth is always the substrate-anchored listing, not the catalog entry. For every ListingSummary returned, a DACS-aware client MUST resolve the anchor to the on-chain content and validate the contentHash. The catalog’s role is to surface candidates; binding decisions MUST follow the substrate.

#### 6.3.7 Conformance summary

| Role | Requirements |
| --- | --- |
| Listing publisher | LP-1 anchor; LP-2 sign; LP-3 monotonic versions; LP-4 publish and retain revocation markers and bindings; LP-5 maintain an actionable engagement surface (SHOULD); LP-6 resolve every advertised pay rail before publication |
| Listing reader | LR-1 pin tuple; LR-2 reject `rejected`; LR-3 refuse new sessions for revocation- or rail-resolution `indeterminate`; LRR-1..LRR-6 resolve every advertised rail |
| Revocation publisher | RB-1 anchor and sign marker; RB-2 publish binding; RB-3 retain tombstone |
| Revocation reader | RB-4 post-fetch verification; RB-5 fail closed; RB-6 distinguish successful absence from resolution failure |
| Bundle producer | BP-1 JCS canonical; BP-2 non-empty claims; BP-3 valid presentedBy; BP-4 valid presentation signature |
| Bundle reader | BR-1 recompute hash; BR-2 reject invalid signature; BR-3 reject missing required verifiedBy; BR-4 treat unknown schemes as unverified; BR-5 reject unverified presentedBy when primaryClaimSelector set |
| Well-known publisher | Publish dacs block; keep indexHash current; optional bundleBindings index per §10.4.2 BB-2 |
| Catalog operator | Open read endpoints; honour caching constraint; decline write endpoints by spec discretion; if carrying bundle bindings, serve every §10.4.2 BB-4-valid record regardless of authoring party |
| Catalog client | Dereference anchors before binding |

### 6.4 Rationale

**Identity-as-bundle vs single-rooted identifier.** A single-root model forces every listing onto one primitive — either too weak for institutional flows (a signing key) or infeasible for micropayments (an LEI). The bundle model lets each listing declare its own minimum and each counterparty present what it holds. Reputation keys against the bundle's *primary* claim so a party accumulates separate reputation per tier — preventing a strong signing-key reputation from laundering into a fresh LEI presentation.

**Closed scheme registry in v0.1 vs open.** An open registry fragments: parsers can't validate bundles without runtime-loaded recipes and conformance becomes untestable. v0.1 ships a fixed high-volume set (LEI, FINRA-CRD, SAM-UEI, FedRAMP, NAICS, CMMC, plus self-sovereign and platform identifiers); new schemes ship via subsequent minor versions under the steward, and `x-` experimental prefixes are the out-of-band escape valve.

**Listing as full JSON vs hash-only.** Full anchoring lets any party with substrate access retrieve and verify the binding contract without off-chain dependency. The cost is on-chain size; the 16 KB cap (§6.3.4) keeps anchoring cheap while the `extendedDescriptionUrl` + hash pattern carries verbose content. Listings whose essential terms exceed 16 KB are a v2 concern; v0.1 treats the cap as a forcing function toward simplicity.

**Discovery via `.well-known/agent.json` extension.** An additive `dacs` block preserves A2A interoperability and reuses a deployed pattern; a separate surface would duplicate publishing and create ambiguity.

**Catalog API off-chain vs on-chain.** The chain holds listings (source of truth); off-chain catalogs index for performance. An on-chain catalog would centralise discovery while being slower and costlier. Competing catalogs may coexist; clients always dereference to chain for the binding artifact.

**SR-1 optional vs required.** Requiring SR-1 would block DACS-1 on substrates without cross-substrate identity aggregation (most EVM chains). Optional SR-1 lets DACS-1 ship anywhere with anchored storage, adding single-signature convenience where supported.

**Per-claim verification references (`verifiedBy`).** A claim without one is a self-assertion — fine for low stakes, not load-bearing for high. The rest of the stack references *verifications*, not raw claims, when stakes matter.

**Cost model.** DACS-1 assumes SR-2 anchored storage is economically viable up to the soft size limit (trivially true on Demos / L2s / IPFS+L1-anchored-hash; not on Ethereum L1). High-cost substrates SHOULD use the `extendedDescriptionUrl` + hash pattern aggressively and anchor only essential fields.

### 6.5 Backwards compatibility

**ERC-8004.** A listing's claims MAY include an `erc8004` claim referencing an Ethereum identity-registry token, verified via the chapter-7 `evm-rpc` recipe (a proxy-attested call confirming the token owner). Its reputation-registry entries MAY additionally surface DACS-5 derivations for EVM consumers, but DACS-1 does not require this.

**W3C DIDs.** `did` claims resolve per the relevant W3C DID method; the recipe varies by method (key material in the DID document → self-signed verification; VC-bound methods → `verifiable-credential`).

**A2A `.well-known/agent.json`.** The `dacs` extension is additive; A2A-only clients ignore it. A DACS-aware client finding no `dacs` block MUST NOT infer the agent has no listings — it MAY fall back to a catalog search.

**W3C Verifiable Credentials.** A claim's `verifiedBy` MAY back to the `verifiable-credential` method; the verifier checks VC signature, issuer, and freshness per the DACS-2 recipe.

**Future identity standards.** New schemes are added via the DACS-1 version process; adding one requires only registry updates, not changes to the bundle, listing, or discovery schemas.

### 6.6 Security considerations

**Forged listings.** *Threat:* an attacker publishes a listing impersonating a known seller. *Mitigation:* listings are signed; the signer MUST be a key referenced in seller.identity.claims, and the bundle itself MUST verify. A reader following the validation order detects the impersonation at the signature step or the bundle-conformance step.

**Bundle replay across sessions.** *Threat:* an attacker captures a bundle from one session and replays it in another. *Mitigation:* the presentation signature is over the domain-separated payload "dacs-bundle-presentation:v1:" || bundle_hash, which the presenter generates fresh per session and which is bound to the session-binding nonce when presented in a session context. The binding is direct for the per-claim and session-key kinds (the top-level `sessionNonce` field enters `bundle_hash`), and runs via the verifier's mandatory SIWD Nonce-match plus Resource-line check for the SIWD kind, whose nonce lives in the omitted `presentation` field (§6.3.2). Verifiers in a session context MUST validate the nonce; bundles missing the nonce in a session context MUST be rejected. Replay of an unverified bundle outside a session context is the equivalent of an unverified self-assertion and offers no advantage to the attacker.

**Catalog poisoning.** *Threat:* a catalog returns false listings or omits real ones. *Mitigation:* ListingSummary includes the anchor and contentHash; clients dereference and verify. A poisoned catalog causes UX confusion (a listing that does not exist on chain, or a missing listing) but cannot produce a verifiable false transaction.

**Self-declared or unregistered payment rail.** *Threat:* a signed listing names a rail in `acceptedRails` and its pipeline, but the rail is absent from the canonical registry, changes handler across versions, has a different registered phase handler, or is available only through an undisclosed local fallback. *Mitigation:* LRR-1..LRR-6 treat the listing fields only as claims, resolve every accepted rail independently through the authenticated registry, enforce the RD-6 same-`railId` handler invariant, bind each pay phase to that handler, and keep unavailable authority `indeterminate`. PA-2/PA-3 readers never fall back silently to in-code constants.

**Claim-scheme spoofing.** *Threat:* a bundle includes a claim with a scheme the reader does not understand. *Mitigation:* unknown schemes MUST be treated as unverified. The reader cannot accept the claim as satisfying a required-and-verified bundle requirement.

**Identity-claim substitution between bundle presentation and Vet.** *Threat:* a counterparty presents bundle A in negotiation and bundle B at Vet time. *Mitigation:* the bundle hash is pinned into the session record at presentation time; DACS-2’s Vet stage operates on the pinned bundle. Substitution is detected by hash mismatch.

**Reading a listing after revocation.** *Threat:* a reader has cached a listing and cannot locate its write-input-addressed revocation marker. *Mitigation:* RB-1..RB-6 retain a discoverable binding, verify the fetched marker, and fail closed when resolution is indeterminate. Sessions already past their agreement commitment phase are not invalidated by revocation, preserving in-flight obligations.

**Stale bundles in active sessions.** *Threat:* a session runs long enough that a verifiedBy reference becomes stale. *Mitigation:* DACS-2 specifies refresh semantics for required claims. For long-running entitlement sessions, listings SHOULD declare a refresh interval; v0.1 does not standardise this, deferring to DACS-2’s per-recipe defaults.

**Index integrity in .well-known.** *Threat:* a compromised web server publishes a falsified listings.json. *Mitigation:* the indexHash in the well-known block is signed only by the TLS certificate, not by the seller’s identity. Clients SHOULD prefer the index’s anchor (substrate-anchored copy) when available; in any case, individual listings MUST be dereferenced and validated independently.

**Private endpoints and impersonation.** *Threat:* seller.publicEndpoint claims a URL the seller does not control. *Mitigation:* this is a self-claim; readers MUST NOT treat the endpoint as authoritative for any cryptographic purpose. Endpoints are conveniences for off-chain reads, not trust anchors. A successful reachability probe proves only that a surface responded at `checkedAt`; it does not prove seller control, listing validity, or correct execution.

**Key lifecycle.** Every spec assumes a primary key exists per ClaimReference. Implementations MUST:

- hold primary keys in a key-management system that does not retain plaintext at rest (HSM, TEE-backed enclave, or equivalent);
- support rotation — the relationship between a ClaimReference and its current key may change over time; the DACS-2 recipe for a scheme defines how key-current-ness is resolved;
- propagate revocation — publish a revocation marker for any listings the key signed, and update bundle presentations to use a new key going forward;
- treat signatures produced by a key after its revocation timestamp as invalid for new sessions; sessions already past their agreement commitment phase using the prior key remain bound (the obligation already exists).
