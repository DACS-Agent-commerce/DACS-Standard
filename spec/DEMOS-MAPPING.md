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

**Demos agent DID profile.** DACS implementations use the self-certifying
`did:demos:agent:<64-lowercase-hex>` ClaimReference for a Demos agent account
whose 32-byte Ed25519 public key is carried in the final component. This is the
`did` scheme with the `demos:agent:<hex>` identifier profile defined in DACS-1
§6.3.1. `demos:0x<64hex>` remains a substrate-address notation; it is not a
registered ClaimReference or a canonical alias, and it MUST NOT be emitted in
identity, signer, catalog-key, or reputation-key fields.

**Demos domain-GCR profile (normative).** The native CCI context remains
`web2.domain`; it is not a DACS ClaimReference scheme. A conforming adapter
resolves the consensus-recorded GCR identity entry and emits
`domain:<DCR-1-canonical-host>` while preserving the native context, host,
Demos Ed25519 account, proof URL, source transaction hash and block number,
and inclusion timestamp as DACS-1 DCR-6 metadata. The adapter
MUST authenticate those values against the carrying Demos transaction and
finalized GCR state; an Indexer projection alone is insufficient.

The historical Demos proof payload is the UTF-8 string
`demos:dw2p:ed25519:<128-lowercase-hex-signature>`. At registration time the
decoded Ed25519 signature verifies over the exact UTF-8 message
`dacs-domain:v1:<DCR-1-canonical-host>:<64-lowercase-hex-account>`, and the
proof URL is exactly `https://<host>/.well-known/demos-cci.txt`. Demos records
the consensus-validated identity and proof URL, not the fetched response body;
the DACS adapter therefore preserves the authenticated GCR record and source
transaction and never re-fetches or invents the historical body. The legacy
`web2:domain:<host>` reference is normalized to `domain:<host>` only after
original-artifact verification for semantic matching.
Resolution, outcome, timestamp, and control semantics are DACS-2
DGCR-1..DGCR-6 and DACS-1 DCR-4..DCR-8. This is persistent GCR evidence; it
does not invoke DAHR and does not claim a fresh ACME challenge.

**Stor-backed credentials.** The stor-cred:<type>:<id> scheme convention is the extensibility surface for future credentials not yet promoted to native CCI contexts. **OFAC-clear is not a CCI context** — it is a per-session freshness check that lives only in DACS-2’s CompositeVerificationRecord (it is a check, not a stable identity claim).

**Transaction sequencing note.** Demos account nonces are monotonic replay-protection counters in GCR_Main. Nodes enforce strict sequential nonces: a transaction with a stale or skipped nonce fails loudly. Same-signer DACS flows that depend on multiple Demos transactions in order — including settlement followed by an SR-2 evidence anchor — should not derive or sign the follow-on transaction from HTTP broadcast acceptance alone. Same-wallet batches MUST construct with explicit sequential nonces (`getAddressNonce(address)` plus `options.nonce`, demosdk ≥4.0.14) or maintain a local counter across the batch and resume read-derived nonce selection only after the on-chain account nonce catches up.

### A.2 SR-2 — Storage Programs

- 🟢 StorageProgramData per SDK at kynesyslabs/sdks/src/storage/StorageProgram.ts. Content-addressed at stor-{sha256(…)}. 128 KB cap. JSONB-backed in GCR_Main.data. ACL modes (private/public/restricted). Provenance via createdByTx, lastModifiedByTx, interactionTxs.
- ⚪ Optional native multi-party Storage Program transaction-signature helper — not a DACS v0.1 dependency. DACS co-signing occurs on the bundle artifact under §10.4.1: for `completed`, `failed-perm`, `failed-counterparty`, and `failed-substrate`, the bundle carries every required buyer, seller, and distinct-orchestrator `BundleSignature`, and under §10.4.2 each required signing party anchors its fully co-signed role-specific copy through its own owner-signed SR-2 write and independently authenticated receipt. The abort outcomes are the normative exception: an `aborted-by-self` or `aborted-by-other` bundle MAY be single-signed, a withdrawing party need not anchor, and the §10.11 bundle-suppression rules apply; every party that actually signs and anchors publishes its own role-specific copy. A future one-transaction multi-party helper is an optimization only; a transaction co-signature MUST NOT substitute for an artifact signature, create a signature or publication duty that DACS-5 suppresses, or remove another role's applicable publication duty.

**Logical vs native addresses (applies universally).** Throughout this document, addresses of the form dacs1:…, dacs2:…, dacs3:…, dacs4:…, dacs5:… are *logical* addresses: substrate-independent, human-readable, stable identifiers the protocol reasons about. The DACS-5 role-specific bundle address `stor-{sha256(jobId + "-bundle-" + role)}` (§10.4.2) is likewise a logical address in scope for the two mapping cases below; being hash-formed it carries no delimiter-encoding concern, and on the write-input case its published binding object is the §10.4.2 `BundleBinding`. Variable segments embedded in a logical address (e.g. the seller's primary claim, which itself contains colons) are delimiter-encoded per rule CF-4 (§B.1) so the logical string is unambiguously parseable back into its components on any substrate. Each substrate maps the logical address to its native addressing in one of two ways:

- **Pure mapping.** Where a substrate's native address is a pure function of the logical address, the mapping MUST be deterministic, one-to-one, and reversible, and consumers compute the native address directly from the logical pattern before reading.
- **Write-input mapping.** Where a substrate folds write-time inputs (deployer address, storage-program name, transaction nonce, salt) into its native address — as Demos's StorageProgram derivation does (§6.3.4) — the native address is **not** recomputable from the logical address alone. The implementation MUST then publish the artifact's logical→native binding. For listings, publication is per DACS-1 §6.3.4(b)/(c): descriptive metadata on the anchored record AND the discovery surfaces (§6.3.5 well-known index, §6.3.6 catalog). Listing revocations use `RevocationBinding` and RB-1..RB-6. For DACS-5 bundles, publication is per the §10.4.2 `BundleBinding` rules (BB-1..BB-2). Consumers resolve the native address through the applicable published binding before reading.

In both cases implementations MUST anchor at the native address, the anchor transaction is the canonical pointer, and consumers MUST verify the content hash after dereferencing.

**Operational write notes (informative).** Storage Program writes have two observable completion points: broadcast acceptance and later read visibility. A DACS implementer should not publish a new SR-2 anchor to counterparties until the native address can be read back and its content hash matches the written artifact. Updates and granular writes can be stale-visible from a lagging node, so read-back checks should compare parsed canonical content (RFC 8785 / JCS for DACS JSON artifacts), not raw JSON text or byte-for-byte serialization. Because native address derivation includes the signer nonce, same-signer dependent writes and batches MUST use explicit sequential nonces or wait for observed nonce advancement before deriving and signing the next native address. An account-nonce read can lag inclusion, so deriving `nonce + 1` from a stale read can fail even after the previous transaction was accepted. Re-broadcasting an idempotent write to the same derived native address remains a safe recovery path when the failure is observable, but only when the payload and logical→native binding are unchanged; consumers still verify the content hash plus createdByTx / lastModifiedByTx provenance.

**SR-2 lifecycle binding (normative).** Demos applies CORE §5.1 as follows:

- SDK/HTTP broadcast acknowledgement establishes only `submitted`. It does not establish CORE `accepted`, because the current Demos binding exposes no independently verifiable durable-admission receipt before consensus.
- A Storage Program write is `included` when an authenticated consensus result identifies the transaction in a Demos block and the resulting record binds the expected `createdByTx` / `lastModifiedByTx`, native address, writer, nonce, and content hash.
- Demos uses deterministic BFT finality for this profile: a valid `included` write is also `finalized`. The receipt MAY be emitted directly with `state: "finalized"` and `observationDisposition: "established"`, with `finalityProfile: "demos-bft-final"`, the Demos transaction hash as `transactionRef`, and the consensus block number/timestamp in `blockRef`.
- Storage API or indexer read-back is the independent CORE visibility observation. A matching positive read is useful for resolution checking but does not establish inclusion by itself; delayed read visibility does not undo a consensus-authenticated final receipt.

Because this binding has no qualifying pre-consensus `accepted` evidence, a DACS stage that permits reversible progression at `accepted` still waits for Demos BFT inclusion/finality.

**Authoritative absence.** The current Demos Storage Program mapping specifies positive record retrieval and content-integrity verification, but it does not declare an authenticated finalized non-membership proof or an independent read-quorum policy. An ordinary Demos RPC or storage API `not found` response therefore has the CORE SR-2 disposition `indeterminate`, not `absent`, for a DACS rule whose outcome depends on authoritative absence. Positive reads and their hash/provenance checks are unaffected. A later Demos binding revision MAY declare an absence-evidence policy without changing any DACS artifact shape; until then, reputation-bearing one-copy DACS-5 lookups fail closed under §10.4.3.

### A.3 SR-3 — DAHR (Data Agnostic HTTPS Relay)

- 🟢 Live via demos.web2.createDahr() → dahr.startProxy(…). Returns IWeb2Result with responseHash, responseHeadersHash, txHash. One on-chain web2Request tx per call. GCR routines per CCI context handle native-claim validation (including tlsn).
- 🟡 DAHR signing-model clarification — current docs show **hash commitments only**, with no validator signature over the response body. v0.1 treats this as a **consensus-anchored hash commitment** model. If Kynesys upgrades DAHR to validator-sign the response body itself, DACS-2 v0.2 may strengthen the claim.
- 🟡 CompositeVerificationRecord Storage Program schema.
- 🟡 oauth-attested method depends on a Demos-side OAuth attester. If not built, the method is 🔵 third-party.
- 🔵 W3C Verifiable Credentials, TLSNotary (external proof library — distinct from the 🟢 cci-tlsn:* native context), zkTLS (Reclaim, Pluto), ACME challenges for domain-tls-control.

**DAHR-backed payload attestation (normative Demos binding).** DAHR supplies
the method-native evidence for a DACS-4 §9.6.3
`PayloadAttestationRecord`; it does not itself supply the DACS commerce
binding. For
`verificationMethod.kind == "consensus-backed-proxy"` on Demos:

- (a) the verifier MUST require the `IWeb2Result.txHash` even though the SDK
  interface types it as optional for generic callers, carry it as
  `methodTransactionRef = { kind: "demos-web2-request", value: txHash }`, and
  resolve the corresponding on-chain `web2Request` transaction;
- (b) it MUST authenticate Demos consensus inclusion at `included` or stronger,
  with finalization required before terminal DACS-5 bundle production, verify that the
  transaction commits to the requested canonical URL, HTTP method, request
  body hash when present, response status, `responseHash`, and
  `responseHeadersHash`, and require those request inputs to equal the signed
  listing's complete `verificationMethod` configuration;
- (c) it MUST obtain the returned `data` string, encode it as UTF-8 without
  reserialisation, require `sha256(UTF8(data)) == responseHash`, and deliver
  those exact bytes so
  `PayloadAttestationRecord.payloadContentHash == responseHash ==
  SettlementEvidence.deliverableContentHash`; and
- (d) it MUST retain a resolvable canonical evidence envelope through
  `methodEvidenceRef`, containing or resolving the authenticated transaction
  and response commitment needed to repeat checks (a)–(c).

A missing `txHash`, an unresolvable transaction, an unauthenticated
broadcast/RPC acknowledgement, or a response/request/hash mismatch MUST NOT
produce `decision: "pass"`. The current DAHR implementation converts the HTTP
body to a string and hashes its UTF-8 bytes; this profile therefore supports
UTF-8 textual payloads only. An arbitrary binary response is unsupported until
DAHR exposes a byte-preserving result, and an implementation MUST fail or
surface that case as unsupported rather than claim a byte-exact attestation.
DAHR's v0.1 trust statement remains a consensus-anchored hash commitment — the
body is verified against the committed hash, not represented as directly
validator-body-signed.

### A.4 SR-4 — L2PS (Layer-2 Privacy Subnets)

- 🟢 new l2ps.L2PS() / new l2ps.L2PS(rsaPrivateKey). DemosWork orchestration with WorkStep (id, context, content, output, depends_on, critical), BaseOperation, ConditionalOperation (SDK module @kynesyslabs/demosdk/demoswork). Storage Programs for agreement-hash anchoring and sealed-envelope commitments.
- 🟡 CCI-keyed L2PS membership — bind subnet membership to CCI primary claim so channel signatures map to the same identity that holds value on-chain. The interim §8.3.2 binding-proof path is shipped as l2ps.binding: createMembershipBinding (attestation signed by the CCI primary key), anchorMembershipBinding (Storage Program at a deterministic collision-safe name), resolveMember (signature check + SP-owner check against impostor programs). Native CCI-keyed subnet membership (node-side enforcement) remains pending; the current native subnet API is RSA-key-based.
- 🟢 L2PS channel message envelope API shipped as l2ps.channel.ChannelSession — implements the §8.3.3 envelope: closed message-type union, CCI-keyed ed25519 signing over the dacs-channelmsg:v1: domain tag, monotonic per-channel sequence with anti-replay validation, CH-6 channelId-reuse registry, and transcript accumulation (ChannelTranscript, §8.7 shape).
- 🟢 Encrypted transcript anchoring helper shipped as l2ps.anchor.anchorEncryptedTranscript — encrypts a ChannelTranscript to the subnet member set (AES-GCM via the L2PS key), anchors ciphertext + public content hash via SR-2 under a deterministic per-channel SP name, signs the plaintext hash with the Demos key, and implements all three terms.transcriptDisclosurePolicy behaviours (none → throw, recommended → consent-gated, required → propagate failure). decryptAnchoredTranscript / verifyAnchorIntegrity included.
- 🔵 ERC-8183 escrow primitive (Ethereum, draft); institutional RFQ desks’ off-chain systems composed as L2PS-equivalent transport.

**DACS-3 phase types are realised as DemosWork WorkSteps.** Each negotiation pattern compiles to a sequence of WorkSteps with context: "xm" | "web2" | "native" and DACS-defined content shapes.

**Complete sealed-envelope candidate sets (not currently available).** Demos Storage Programs can anchor each positive commit/reveal record, but the current node/SDK mapping does not expose an authenticated current-finalized prefix enumeration or non-omission proof over bidder-owned writes. It therefore does not yet supply a `CandidateSetBindingRef` satisfying DACS-3 SAC-3/SAC-4. On Demos, `negotiate-sealed-envelope-complete` and `negotiate-sealed-envelope-procurement-complete` MUST currently fail with a capability-missing/`indeterminate` result; an SDK MUST NOT treat an Indexer query, L2PS inbox, or several successful Storage Program reads as a complete candidate set.

A Demos candidate-set binding can become registrable only when the node/binding supplies all of the following for the session-derived `dacs3:auction:{jobId}` collection:

- permissionless or policy-authorized bidder writes whose signed record bytes and unique logical address are preserved;
- authenticated enumeration of every matching commit/reveal write at one exact finalized state, with a canonical native order key and proof bound to the exact record-set hash and count;
- evidence that the referenced state is the latest acceptable finalized tip under a declared maximum-lag rule, not merely a valid older block;
- deterministic fork/reorg reconciliation and authenticated independent-observer thresholds; and
- independent later resolution of every included record and receipt, with conflicting writes or views surfaced rather than first-seen-selected.

This is a node/binding requirement, not something the DACS SDK can manufacture from cached positive records. Historical §8.4.3 sealed-envelope flows remain available under their disclosed non-completeness semantics.

**Operational transport notes (informative).** L2PS exposes two message-transport servers, and public-node availability differs between them. The L2PS messaging server (rollup-backed persistence, per-subnet isolation via l2psUid) is opt-in node configuration — a messaging-enabled flag, a dedicated messaging port, and subnet creation — and, as probed on the public testnet nodes 2026-07-09, is not exposed on either; the Kynesys documentation assumes a self-hosted node for it. A legacy signaling server is live on at least one public node and was verified end-to-end on the same probe (two peers registered with an ML-DSA proof, peer discovery, and an ML-KEM+AES-encrypted message relayed and decrypted); it is relay-only — no offline queue, no rollup persistence, no network isolation. Client gotcha: the messaging peer's advertised public key MUST be the ML-KEM (encapsulation) identity key, not the ML-DSA (signing) key the registration proof is signed with — peers fetch the advertised key for ML-KEM encapsulation, so advertising the signing key breaks message send. Practical consequence: DACS-3 private patterns can run today by composing ChannelSession over the legacy relay (client-side end-to-end encryption preserves CH-2), with a transport-adapter swap to the L2PS messaging server once a node exposes it; the SDK anticipates this seam via l2ps.channel.L2PSMessagingPeerLike.

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
