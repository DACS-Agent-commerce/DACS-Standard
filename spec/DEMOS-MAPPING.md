# DACS — Demos production mapping (§A)

> Part of **DACS v0.1**. Companion reference to [CORE](CORE.md) — moved out of the Core document to keep the normative reading surface compact. Original section numbering is retained, so existing citations (e.g. §A.x) remain stable.

Which Demos substrate primitives are live today, what the Demos team adds for v0.1, and which dependencies are third-party — for each substrate capability SR-1..SR-5.

---

## A. Demos production mapping

A mapping of which substrate primitives are live today, what extensions are needed for v0.1, and which dependencies are third-party. The mapping applies to every per-stage standard — DACS-1 through DACS-5 — in this paper.

**Legend.** 🟢 in production today; 🟡 Demos team to add for v0.1; ⚪ deferred — planned for a later version, not v0.1; 🔵 third-party (composed, not built by Demos). This legend describes the substrate-primitive status — what the chain ships. Per-recipe and per-rail operational status uses the normative availability field defined in §7.4.5 (recipes) and §9.4.4 (rails). The legend here is informative about substrate features; availability there is normative about specific attestation paths and settlement rails. Earlier drafts conflated the two surfaces by extending this legend to recipes and rails; that conflation has been corrected in v0.1.

### A.1 SR-1 — Cross-Context Identities (CCI)

- 🟢 8 native contexts in production: xm, web2, pqc, ud, nomis, humanpassport, ethos, tlsn. Stored in GCRMain.identities. SDK methods getXmIdentities, getWeb2Identities, addXmIdentity, addTwitterIdentity, etc. SIWD (wallet_signIn, EIP-4361-style) for presentation.
- ⚪ 6 new CCI contexts for regulatory identity: lei, finra-crd, sam-uei, fedramp, naics, cmmc. **Deferred to a later version — not part of v0.1.** Each needs a GCR routine following the pattern of the existing 8 reference implementations. Until they ship, regulatory credentials on Demos are carried via the stor-cred extensibility surface below and verified through DACS-2.
- 🔵 ERC-8004 token references; W3C DIDs (carried via claim references; verified through DACS-2).

**Stor-backed credentials.** The stor-cred:<type>:<id> scheme convention is the extensibility surface for future credentials not yet promoted to native CCI contexts. **OFAC-clear is not a CCI context** — it is a per-session freshness check that lives only in DACS-2’s CompositeVerificationRecord (it is a check, not a stable identity claim).

**Transaction sequencing note.** Demos account nonces are monotonic replay-protection counters in GCR_Main. Same-signer DACS flows that depend on multiple Demos transactions in order — including settlement followed by an SR-2 evidence anchor — should serialize signing on observed nonce advancement / inclusion, not merely on HTTP broadcast acceptance.

### A.2 SR-2 — Storage Programs

- 🟢 StorageProgramData per SDK at kynesyslabs/sdks/src/storage/StorageProgram.ts. Content-addressed at stor-{sha256(…)}. 128 KB cap. JSONB-backed in GCR_Main.data. ACL modes (private/public/restricted). Provenance via createdByTx, lastModifiedByTx, interactionTxs.
- 🟡 Native multi-party Storage Program signature helper so buyer + seller co-signature of a closed AttestationBundle is a single transaction — current SDK supports owner-signed writes only.

**Logical vs native addresses (applies universally).** Throughout this document, addresses of the form dacs1:…, dacs2:…, dacs3:…, dacs4:…, dacs5:… are *logical* addresses: substrate-independent, human-readable, stable identifiers the protocol reasons about. Variable segments embedded in a logical address (e.g. the seller's primary claim, which itself contains colons) are delimiter-encoded per rule CF-4 (§B.1) so the logical string is unambiguously parseable back into its components on any substrate. Each substrate maps the logical address to its native addressing in one of two ways:

- **Pure mapping.** Where a substrate's native address is a pure function of the logical address, the mapping MUST be deterministic, one-to-one, and reversible, and consumers compute the native address directly from the logical pattern before reading.
- **Write-input mapping.** Where a substrate folds write-time inputs (deployer address, transaction nonce, salt) into its native address — as Demos's StorageProgram derivation does (§6.3.4) — the native address is **not** recomputable from the logical address alone. The implementation MUST then publish the logical→native binding: as descriptive metadata on the anchored record AND via the discovery surfaces (§6.3.5 well-known index, §6.3.6 catalog). Consumers resolve the native address through that published binding before reading.

In both cases implementations MUST anchor at the native address, the anchor transaction is the canonical pointer, and consumers MUST verify the content hash after dereferencing.

**Operational write notes (informative).** Storage Program writes have two observable completion points: broadcast acceptance and later read visibility. A DACS implementer should not publish a new SR-2 anchor to counterparties until the native address can be read back and its content hash matches the written artifact. Updates and granular writes can be stale-visible from a lagging node, so read-back checks should compare parsed canonical content (RFC 8785 / JCS for DACS JSON artifacts), not raw JSON text or byte-for-byte serialization. Because native address derivation includes the signer nonce, same-signer dependent writes should wait for nonce advancement / inclusion before deriving and signing the next native address. Re-broadcasting an idempotent write to the same derived native address is a safe recovery path only when the payload and logical→native binding are unchanged; consumers still verify the content hash plus createdByTx / lastModifiedByTx provenance.

### A.3 SR-3 — DAHR (Data Agnostic HTTPS Relay)

- 🟢 Live via demos.web2.createDahr() → dahr.startProxy(…). Returns IWeb2Result with responseHash, responseHeadersHash, txHash. One on-chain web2Request tx per call. GCR routines per CCI context handle native-claim validation (including tlsn).
- 🟡 DAHR signing-model clarification — current docs show **hash commitments only**, with no validator signature over the response body. v0.1 treats this as a **consensus-anchored hash commitment** model. If Kynesys upgrades DAHR to validator-sign the response body itself, DACS-2 v0.2 may strengthen the claim.
- 🟡 CompositeVerificationRecord Storage Program schema.
- 🟡 oauth-attested method depends on a Demos-side OAuth attester. If not built, the method is 🔵 third-party.
- 🔵 W3C Verifiable Credentials, TLSNotary (external proof library — distinct from the 🟢 cci-tlsn:* native context), zkTLS (Reclaim, Pluto), ACME challenges for domain-tls-control.

### A.4 SR-4 — L2PS (Layer-2 Privacy Subnets)

- 🟢 new l2ps.L2PS() / new l2ps.L2PS(rsaPrivateKey). DemosWork orchestration with WorkStep (id, context, content, output, depends_on, critical), BaseOperation, ConditionalOperation (SDK module @kynesyslabs/demosdk/demoswork). Storage Programs for agreement-hash anchoring and sealed-envelope commitments.
- 🟡 CCI-keyed L2PS membership — bind subnet membership to CCI primary claim so channel signatures map to the same identity that holds value on-chain. Current API is RSA-key-based.
- 🟡 L2PS channel message envelope API — sequence numbering, signature export, transcript export.
- 🟡 Encrypted transcript anchoring helper (for terms.transcriptDisclosurePolicy: "encrypted-anchored-required").
- 🔵 ERC-8183 escrow primitive (Ethereum, draft); institutional RFQ desks’ off-chain systems composed as L2PS-equivalent transport.

**DACS-3 phase types are realised as DemosWork WorkSteps.** Each negotiation pattern compiles to a sequence of WorkSteps with context: "xm" | "web2" | "native" and DACS-defined content shapes.

### A.5 SR-5 — Native Bridges / Liquidity Tanks

- 🟢 LiquidityTank.sol (audited; 600+ lines; rotating 2/3 multisig + 15-day emergency recovery) deployed on **ETH Sepolia** (0x7AE3A8B899BE0D9E9de51b81a9912C0CEE128d88) and **Polygon Amoy** (0x57cA16EeE7fbeC69BFD46E4806B5d91e173dd600).
- 🟢 SDK type BridgeOperation at kynesyslabs/sdks/src/bridge/nativeBridgeTypes.ts. RPC handler at kynesyslabs/node/src/libs/network/manageNativeBridge.ts. Tank addresses config at kynesyslabs/node/config/tankAddresses.json. **bridge_id** (16-char hash) is the canonical end-to-end tracking handle.
- 🟢 Trust model: **operated by a rotating Demos validator shard under 2/3 BFT multisig with 15-day deployer emergency recovery.** Not "no operator" — the operator is the substrate itself.
- 🟢 MVP scope: USDC only; EVM-source; unidirectional. Gasless bridge operations (contract reimburses user gas from subsidy pool). BridgeOperation.status lifecycle: "empty" → "pending" → "completed" | "failed". XM SDK single-chain transfers (preparePay, prepareTransfer, prepareTransfers) for non-bridge rails. Storage Programs for deliver-storage-program and entitlement records.
- 🟡 Phase 2: Solana tank programs (treasury Phases 3.3–3.4, SolanaAddressManagement class, vault management).
- 🟡 Phase 3: Bidirectional + cross-chain shard rotation.
- 🟡 Phase 4: Production polish + executeBridgeOperations consensus logic + cross-chain bridge message verification + emergency recovery mechanisms. Additional EVM tank deployments (currently 4 placeholder entries in tankAddresses.json). Mainnet deployments. Non-USDC stablecoin support. Native EntitlementRecord registry (optional; Stor-backed is fine for v0.1).
- 🔵 AP2 (Google → FIDO Alliance, April 2026) — DACS-4 carries as a rail envelope. x402 (Coinbase + Cloudflare + Anthropic) — DACS-4 carries as a rail envelope. Rubic Bridge (third-party DEX aggregator, wrapped by SDK at @kynesyslabs/demosdk/bridge) — alternative cross-chain rail with explicit third-party trust disclosure.
- 🔵 **HTLC contracts (generic atomic-swap pattern)** — pay-cross-chain-htlc is a first-class supported rail in DACS-4 v0.1. **The reference implementation in agent-commerce-demo uses HTLCs today for the fx-rfq cross-chain settlement** (929 LOC: real Solana Anchor program + Base Sepolia EVM HTLC contract; lock/reveal/refund implemented end-to-end). This predates Native Bridges Phase 1 deployment. The reference implementation will migrate to pay-cross-chain-liquidity-tank as Phase 1 stabilises; until then both rails are documented honestly. ERC-20, SPL (standard token interfaces). ERC-8183 escrow (proposed; future rail).

**v0.1 cross-chain settlement scope.** pay-cross-chain-liquidity-tank is supported **only** for the rails currently live in tankAddresses.json (ETH Sepolia, Polygon Amoy; USDC; unidirectional EVM source). All other tank rails in the registry are 🟡 to-add and will unlock as Native Bridges Phase 2–4 ship. pay-cross-chain-htlc is the path the reference implementation runs today; v0.1 keeps both first-class.
