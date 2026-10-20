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

**Logical vs native addresses (applies universally).** Throughout this document, addresses of the form dacs1:…, dacs2:…, dacs3:…, dacs4:…, dacs5:… are *logical* addresses: substrate-independent, human-readable, stable identifiers the protocol reasons about. Every `{jobId}` segment first satisfies CORE JID-1 and is inserted as its exact ASCII bytes. The DACS-5 role-specific bundle address `stor-{sha256(ASCII(jobId) || ASCII("-bundle-") || ASCII(role))}` (§10.4.2) is likewise a logical address in scope for the two mapping cases below; being hash-formed it carries no delimiter-encoding concern, and on the write-input case its published binding object is the §10.4.2 `BundleBinding`. Variable segments embedded in a logical address (e.g. the seller's primary claim, which itself contains colons) are delimiter-encoded per rule CF-4 (§B.1) so the logical string is unambiguously parseable back into its components on any substrate. Each substrate maps the logical address to its native addressing in one of two ways:

- **Pure mapping.** Where a substrate's native address is a pure function of the logical address, the mapping MUST be deterministic, one-to-one, and reversible, and consumers compute the native address directly from the logical pattern before reading.
- **Write-input mapping.** Where a substrate folds write-time inputs (deployer address, storage-program name, transaction nonce, salt) into its native address — as Demos's StorageProgram derivation does (§6.3.4) — the native address is **not** recomputable from the logical address alone. The implementation MUST then publish the artifact's logical→native binding. For listings, publication is per DACS-1 §6.3.4(b)/(c): descriptive metadata on the anchored record AND the discovery surfaces (§6.3.5 well-known index, §6.3.6 catalog). Historical listing revocations use `RevocationBinding` and RB-1..RB-6; the current RSC state line instead binds its stable native locator inside the signed Listing before any later revocation exists. For DACS-5 bundles, publication is per the §10.4.2 `BundleBinding` rules (BB-1..BB-2). Consumers resolve the native address through the applicable signed or published binding before reading.

For a session artifact with no class-specific public surface, the default
pre-bundle path on Demos is direct delivery of a verified `AnchorReceipt` to
every entitled participant under CORE §5.1 SR2-10..SR2-12. After terminal
bundle publication, consumers use its authenticated native content references
under SR2-13. Listings, revocations, and bundles retain their existing public
surfaces; Demos conformance does not require a public per-job payment-evidence
index. The recipe and rail index roots use the release-pinned, non-recursive
`RegistryBootstrapDescriptor`; authenticated entries in the verified immutable
index snapshot are content references for their separately signed definitions.
The opaque `storageProgramName` is never a consumer resolution input.

In both cases implementations MUST anchor at the native address, the anchor transaction is the canonical pointer, and consumers MUST verify the content hash after dereferencing.

**DACS-5 legacy-checkpoint mapping.** The unallocated current-use candidate's
`dacs5:legacy-bundle-checkpoint:v1:{CF-4(substrate)}` address follows the same
two mapping cases. On Demos it is a write-input mapping, so checkpoint discovery
MUST resolve the signed `LegacyBundleCheckpointBinding`, then authenticate the
exact Demos transaction, writer, nonce, native address, checkpoint hash and BFT-
final receipt under CORE §5.1. The checkpoint producer's timestamp, a storage API
read, an Indexer row, or a candidate-supplied steward list cannot establish the
activation position. Historical bundle eligibility likewise requires the
original signed `BundleBinding`, original BB-6 selection context and original
finalized Demos write receipt; a current read or writer label cannot reconstruct
that authority. The repository's current-use corpus uses independently pinned
signed synthetic native proofs solely to execute this offline boundary. It does
not specify a production Demos proof wire codec; until an adapter supplies the
authenticated Demos evidence above, the production mapping is unavailable and
the stronger consumer returns `indeterminate`.

**Operational write notes (informative).** Storage Program writes have two observable completion points: broadcast acceptance and later read visibility. A DACS implementer should not publish a new SR-2 anchor to counterparties until the native address can be read back and its content hash matches the written artifact. Updates and granular writes can be stale-visible from a lagging node, so read-back checks should compare parsed canonical content (RFC 8785 / JCS for DACS JSON artifacts), not raw JSON text or byte-for-byte serialization. Because native address derivation includes the signer nonce, same-signer dependent writes and batches MUST use explicit sequential nonces or wait for observed nonce advancement before deriving and signing the next native address. An account-nonce read can lag inclusion, so deriving `nonce + 1` from a stale read can fail even after the previous transaction was accepted. Re-broadcasting an idempotent write to the same derived native address remains a safe recovery path when the failure is observable, but only when the payload and logical→native binding are unchanged; consumers still verify the content hash plus createdByTx / lastModifiedByTx provenance.

**SR-2 lifecycle binding (normative).** Demos applies CORE §5.1 as follows:

- SDK/HTTP broadcast acknowledgement establishes only `submitted`. It does not establish CORE `accepted`, because the current Demos binding exposes no independently verifiable durable-admission receipt before consensus.
- A Storage Program write is `included` when an authenticated consensus result identifies the transaction in a Demos block and the resulting record binds the expected `createdByTx` / `lastModifiedByTx`, native address, writer, nonce, and content hash.
- Demos uses deterministic BFT finality for this profile: a valid `included` write is also `finalized`. The receipt MAY be emitted directly with `state: "finalized"` and `observationDisposition: "established"`, with `finalityProfile: "demos-bft-final"`, the Demos transaction hash as `transactionRef`, and the consensus block number/timestamp in `blockRef`.
- Storage API or indexer read-back is the independent CORE visibility observation. A matching positive read is useful for resolution checking but does not establish inclusion by itself; delayed read visibility does not undo a consensus-authenticated final receipt.

Because this binding has no qualifying pre-consensus `accepted` evidence, a DACS stage that permits reversible progression at `accepted` still waits for Demos BFT inclusion/finality.

**Native DEM transfer outcome.** This SR-2 profile does not define payment success. Like a Storage Program write, a DACS-4 §9.5.9 `pay-dem` transfer needs its resulting record. BFT inclusion makes the transfer final, but DEM-2 and DEM-3 require a bound `confirmed` transaction record and independently authenticated applied-payment authority to establish payment. The node's status index can label a transaction `included` while its record is `failed`; that failure is final too. Recovery re-reads the retained hash and never re-broadcasts the payment (DEM-6), unlike the idempotent Storage Program re-broadcast described above.

**Native-send record profile (normative).** DACS-4 §9.5.9 DEM-1, DEM-2 and DEM-7 compare a Demos native transfer only through this projection.

*Node semantics.* The profile's execution-record semantics are those of `kynesyslabs/node` commit `61b8e75aa8db5e408c49e1c3a89db4d673f45578` (`stabilisation` branch). Consensus stores each included transaction's record with status `confirmed` or `failed` (`src/libs/consensus/v2/PoRBFT.ts`), and a failed apply restores the pre-transaction state (`src/libs/blockchain/gcr/handleGCR.ts`). `getTxByHash` serves that record and returns an error result for an unknown hash. `getTransactionStatus` reports `included` for any stored record, including a `failed` one, `pending` for a mempool entry and `unknown` otherwise; it never reports `failed`. Nodes built from the `testnet` branch at `ac8f45f02fc9c25082ce9b83595c2e3916b49c5a` have no `getTransactionStatus` and store every block transaction they held as `confirmed`, so they do not implement this profile. A handler or consumer MUST pin, in its Demos binding configuration, the nodes it reads as running a build of exactly that commit from an unmodified tree. The pin is the binding configuration's own build attestation for each node, naming that commit and a clean tree; the handler or consumer compares it with this profile's commit before relying on a record. No other node release is within the pin until a revision of this profile lists its commit and the behaviour re-checked at it. A node's self-reported version or commit, an attested build of another commit, and a build from a modified tree are each not that pin. A record from a node that is not pinned is unbound under DEM-2 and DEM-7, so the outcome stays `indeterminate`. The node regenerates edits at RPC admission (`confirmTx`, `src/libs/network/endpointValidation.ts`), at mempool admission and, with the `nonceEnforcement` fork active, at apply time. Both admission paths use the `GCRGeneration` of the `@kynesyslabs/demosdk` 4.0.12 that the node bundles (`bun.lock`), whose edit generation and serializer modules are byte-identical to 4.0.16; a revision of the pin re-checks that. The profile describes a network on which the `osDenomination` fork is active and the `gasFeeSeparation` fork is unscheduled: the network's sealed genesis sets `forks.gasFeeSeparation.activationHeight` to `null`, as the pinned `data/genesis.json` does. With `gasFeeSeparation` active, apply prepends fee-distribution edits to the transaction's `content.gcr_edits` and the node stores them (`src/libs/blockchain/gcr/handleGCR.ts`, `gcr_routines/feeDistribution.ts`), so no record of a fee-paying send carries only the four edits below and DEM-3 success is unreachable. A clean build of the pinned commit does not exclude this: its default fork configuration activates `gasFeeSeparation` at height 0 for a genesis without that entry (`src/forks/forkConfig.ts`), its devnet genesis activates it, and no RPC reports it (`getNetworkInfo` reports only `osDenomination`). A handler's Demos binding configuration MUST therefore attest, for each network, from that network's sealed genesis, that `gasFeeSeparation` is unscheduled. An activation height, including a future one, a genesis without the entry and a missing attestation are each not that attestation, and DEM-1 refuses to sign or send under them. A record whose edits carry fee-distribution edits is outside this profile and never establishes payment: the handler's DEM-3 result is `indeterminate`, and so is a consumer's DEM-7 result unless an independently authenticated applied-payment authority contradicts the bound values, which DEM-7 decides `fail` whatever the record's edits (*Applied payment authority* below). A network that replaces its genesis after a transfer is signed leaves the attestation stale until the binding is reconfigured. Its records never establish success: the handler's result stays `indeterminate`, and a consumer whose authenticated applied-payment authority binds another genesis than the phase's pinned network decides `fail` under DEM-7. Independently of forks, `handleGCR.ts` returns success before the apply-time edit check for missing, non-array or empty `gcr_edits`. A `confirmed` record therefore does not by itself establish that a native payment changed state. The edit list is necessary but never proof of application: a handler or consumer MUST NOT treat a `confirmed` record as payment unless its `content.gcr_edits`, with each `txhash` replaced by the empty string, equal the four edits of its send listed under *Signed transaction*. A `confirmed` record without them is a no-op apply and stays `indeterminate` even if an authority reports payment; the applied-payment authority below still decides for one that has them. The SDK reference is `@kynesyslabs/demosdk` 4.0.16 (npm integrity `sha512-nVhp1uC+tFGzhew9c8XIajTMmELopx7gd0joqqzDd2XyUuFDcqrda51NYqvX5C8+L3Xgnie/mRf7JRqZ7r3tHA==`), which signs the native `send` in the post-`osDenomination` form below.

*Decoding.* A `getTxByHash` record, or a signed transaction for DEM-1, decodes only when every member below has the stated form. A record's other members are ignored; a signed transaction has the further requirements under *Signed transaction*. JSON numbers are compared by value after a CORE §B.2 parse, so a JSON number is accepted only when its value is an integer from 0 to 2^53 − 1. A *canonical decimal string* is `0` or a non-zero digit followed by digits, with no sign, space, exponent or fraction. A *Demos key* is an optional `0x` followed by exactly 64 lower-case hexadecimal digits; it projects to the 64 digits, which is the DACS-1 key form. A *pay-dem party address* is the authority side of that comparison: for `pay-dem`, the Agreement's payout binding and `payee.payeeAddress` (DACS-4 §9.5.1 PB-1), and the key that `payer.payingKey` names, MUST each be a Demos key or a DACS-1 `did:demos:agent:` DID whose key component is exactly 64 lower-case hexadecimal digits, and each projects to those 64 digits. DACS-4 §9.5.9 DEM-1, DEM-7 and FV-5 compare only that projection, so the bare, `0x` and DID spellings of one key bind alike. Any other value, such as upper-case hexadecimal, a DID key component with `0x`, or a 20-byte address, projects to nothing: the handler sends nothing for the phase and a consumer's DEM-7 result is `error`.

| Member | Required form | Projects to |
| --- | --- | --- |
| `hash` | exactly 64 lower-case hexadecimal digits without `0x` | transaction hash (also the canonical `ChainTxRef` `demos` `txHash` and the SB-1 `demos:{txHash}` spelling) |
| `blockNumber` (record only) | JSON integer | block number |
| `status` (record only) | string, compared exactly | record status |
| `content.type` | exactly `"native"` | — |
| `content.nonce` | JSON integer or canonical decimal string | nonce |
| `content.from` | Demos key; `content.from_ed25519_address`, when present, MUST project to the same key | sender |
| `content.to` | Demos key | recipient |
| `content.amount` | JSON integer or canonical decimal string, in OS | OS amount |
| `content.data` | exactly `["native", {"nativeOperation": "send", "args": [to, amount]}]`, where `to` is a Demos key projecting to the recipient and `amount` is a canonical decimal string equal to the OS amount | — |

The node serves `nonce` as a decimal string, `amount` as a number up to 2^53 − 1 and a string above it, `from` and `to` with `0x`, and the `send` recipient argument with whatever optional `0x` prefix the client supplied. The SDK signs a numeric nonce and a string amount. All of these project to the same values. A record whose amount is in the earlier DEM-denominated (pre-`osDenomination`) form does not decode under this profile.

*Signed transaction.* The DEM-1 signed transaction is the demosdk 4.0.16 `sign()` result; this profile uses its `content`, `hash` and `signature` members and ignores its other envelope members. It decodes only when it is authentic as well as in the form above. Unlike served records, signed `content.amount` and all three `transaction_fee` amount members (`network_fee`, `rpc_fee`, `additional_fee`) MUST be canonical OS decimal strings. The fee object and those three members MUST be present; JSON numbers are not valid signed OS amounts because the post-fork serializer interprets numeric amounts as DEM. Signed `content.nonce` MUST be a JSON integer from 0 to 2^53 − 1. The upper bound is this profile's own; demosdk 4.0.16 signs a JSON number nonce. A decimal string is not a valid signed nonce, because the pinned node admits it but its consensus filter compares the nonce with `===` and never applies the transaction (`src/libs/consensus/v2/routines/mempoolFilters.ts`). The fee object MUST have exactly the members `network_fee`, `rpc_fee`, `additional_fee` and `rpc_address`, in that order, with `rpc_address` `null` or a string. The pinned node's RPC ingress rebuilds the fee object in that order before it re-derives `hash`: it defaults `rpc_address` to `null` and drops other members (`src/forks/serializerGate.ts`). The content MUST also carry the members that `pay()` and `sign()` add before hashing and that the node checks at admission:

- `timestamp` MUST be a positive JSON integer, which the node converts with `BigInt` (`src/libs/blockchain/mempool.ts`).
- `content.from_ed25519_address` MUST be present.
- `gcr_edits` MUST equal the four edits the SDK generates for the send, member for member and in order, once each `txhash` value is replaced by the empty string:
  - `{"type":"balance","operation":"remove","isRollback":false,"account":F,"txhash":"","amount":A}`
  - `{"type":"balance","operation":"add","isRollback":false,"account":T,"txhash":"","amount":A}`
  - `{"type":"balance","account":F,"operation":"remove","amount":"1000000000","txhash":"","isRollback":false}`
  - `{"type":"nonce","operation":"add","account":F,"amount":1,"txhash":"","isRollback":false}`

  Here F is `content.from_ed25519_address`, T is the `send` recipient argument with `0x` prefixed when absent, and A is the `send` amount argument. The node regenerates these edits at admission and refuses a native transaction whose edits differ (`src/libs/blockchain/validation/verifyGcrEdits.ts`).

`hash` MUST be the lower-case hexadecimal SHA-256 of the UTF-8 `JSON.stringify(content)`, with members in their signed order. `signature` MUST be `{"type": "ed25519", "data": "0x" + 128 lower-case hexadecimal digits}`, an Ed25519 signature over the pinned node's transaction signature preimage (the bare UTF-8 bytes of `hash` at `61b8e75`) that verifies under the key `content.from` projects to. A transaction signed with another algorithm, such as a post-quantum wallet whose `from` is not an Ed25519 key, is not authentic under this profile. Later demosdk releases add a domain-separated `signatureDomain` preimage (`demos-tx:v1:<chainId>:<hash>`) that the node at `61b8e75` does not activate; a node release that activates it changes the preimage and requires a revision of this profile. Without it, the signed bytes name no network or genesis, so a signed transfer is also valid on another Demos network on which the same key holds the funds and the nonce; a binding keeps a paying key and its pinned nodes to one network. A node record is not re-hashed. The node serves `content` with other JSON types than the SDK signed, such as a string nonce, so consumers authenticate the full record through the independent execution-result source required by FV-5 instead. The block's transaction-hash commitment does not commit the later `status`; the node semantics pin does not authenticate an RPC response.

*Applied payment authority.* For DEM-3 and DEM-7, the handler or consumer MUST additionally authenticate the committed native-send state transition independently of the RPC record. The authority MUST bind the same network, inclusion block identity, transaction hash and block number, sender and recipient, and establish that this transaction's committed payment debit and payee credit both equal the projected OS amount (excluding fees). It establishes them from committed state: it authenticates the payer's and payee's balances immediately before and after this transaction's apply and the fee the apply charged, and the debit is the payer's balance decrease less that fee and the credit the payee's balance increase. A debit or credit that is not that change of the committed balances the authority authenticates establishes nothing and is `indeterminate`, as is an authority that does not carry them. A configured verified replay, state-transition commitment, or independent result policy that verifies the actual applied transition MAY supply this authority. A result policy MUST attest the committed balances and the applied debit and credit as well as the full record; copying `confirmed`, the record's `amount` or `content.gcr_edits` does not establish application, because the record and its edits are the claim being checked. Missing or unavailable applied-payment authority is `indeterminate`, even for a bound `confirmed` record. For a bound `confirmed` record, an independently authenticated transition that contradicts the bound values is `fail` for a consumer, whether the record came from an FV-5-authenticated or an ordinary read. That covers another transaction, block, network or party, or a debit or credit other than the OS amount, including the unchanged balances of a no-op apply or of a `confirmed` record carrying all four edits whose apply committed nothing. For the payer's handler that transition is DEM-5 `indeterminate`. A bound `failed` record stays under DEM-4 for the handler and under DEM-7's `failed` rules for a consumer, whatever the authority reports. This profile defines no production proof wire codec; a binding without this authority cannot establish payment success, so DEM-1 refuses to sign or send a transfer under it.

*Validity response.* demosdk 4.0.16 `confirm()` sends the signed transaction to the node's `confirmTx` and returns its validity response, an `RPCResponseWithValidityData` `{"result", "response": {"data": {"valid", "reference_block", "message", "gas_operation", "transaction"}, "signature", "rpc_public_key"}, "require_reply", "extra"}`. At `61b8e75`, on a network where `gasFeeSeparation` is unscheduled as DEM-1 requires, `confirmTx` embeds the transaction it received, unchanged, as `response.data.transaction`, signs the SHA-256 of `JSON.stringify(response.data)` with the node key, and answers `result` 200 even when `response.data.valid` is `false`. When validation itself throws, for example on a GCR-edit mismatch or a fee-balance shortfall, the node answers `result` 200 with `valid: false` and no embedded transaction (`transaction: null`). demosdk `confirm()` and `broadcast()` throw on `valid: false`, so neither branch yields a response that DEM-1 lets a broadcast carry. `broadcast(validationData)` sends that whole object to `broadcastTx`, and the node executes the embedded transaction once it has checked its own signature (`src/libs/network/endpointExecution.ts`). The broadcast therefore egresses the embedded transaction, not the transaction the handler retained, and DEM-1 binds the two.

> **Note (non-normative).** The demosdk 4.0.16 helpers `payAndWait` and `transferAndWait` run `pay()`, `confirm()` and `broadcastAndWait()` in one call and resolve on inclusion. They leave no point to retain the signed transfer before its first egress (DEM-1) and report inclusion rather than the record status (DEM-3), so a conformant handler does not use them. It calls `pay()`, durably retains the result, then calls `confirm()` and `broadcast()` once each, passing `broadcast()` the validity response that `confirm()` returned, and reads `getTxByHash` for the retained hash. The SDK transport retransmits the same request inside one call on a connection error or an HTTP 502, 503 or 504; DEM-6 treats that as the same call, because the pinned node deduplicates the identical hash at `confirmTx`, in each validator's mempool and at storage, and at apply only with the `nonceEnforcement` fork active (a non-validator node relays a retransmitted `broadcastTx` again, and the receiving validators deduplicate it). The handler itself never repeats a call that returned an error or timed out.

> **Note (non-normative).** On 2026-10-17, read-only calls to `node2.demos.sh`, which reported commit `61b8e75` with a dirty tree, returned status index `included` and record status `failed` (`TX_NONCE_INVALID_LOW`) for transaction `85b8fcdc…7744cbd`. The `pay-dem-execution-v0.1` corpus copies that record and a `confirmed` one. These are observations of the profile, not its normative pin: a dirty-tree build is not the pin, so the corpus replays the record bytes as if a pinned node had served them. A source comment at that commit says the index's `failed` state is reserved and that failed transactions surface as `unknown`. The same commit's code, and these observations, show that a stored `failed` record is reported as `included`.

**Authoritative absence and current state.** The current Demos Storage Program mapping specifies positive record retrieval and content-integrity verification, but it does not declare an authenticated finalized non-membership proof, an independent read-quorum policy, or a current-value proof that establishes one returned program value against the latest acceptable finalized Demos state. An ordinary Demos RPC or storage API `not found` response therefore has the CORE SR-2 disposition `indeterminate`, not `absent`, for a DACS rule whose outcome depends on authoritative absence. Likewise, a valid old program update cannot satisfy DACS-1 RSC-3 merely because its containing block finalized. Positive reads and their hash/provenance checks are unaffected. A later Demos binding revision MAY declare these policies without changing any signed DACS artifact shape; until then, reputation-bearing one-copy DACS-5 lookups fail closed under §10.4.3 and a current DACS-1 revocation non-membership check is `indeterminate` under RSC-3.

### A.3 SR-3 — DAHR (Data Agnostic HTTPS Relay)

- 🟢 Live via demos.web2.createDahr() → dahr.startProxy(…). Returns IWeb2Result with responseHash, responseHeadersHash, txHash. One on-chain web2Request tx per call. GCR routines per CCI context handle native-claim validation (including tlsn).
- 🟡 DAHR signing-model clarification — current docs show **hash commitments only**, with no validator signature over the response body. v0.1 treats this as a **consensus-anchored hash commitment** model. If Kynesys upgrades DAHR to validator-sign the response body itself, DACS-2 v0.2 may strengthen the claim.
- 🟡 CompositeVerificationRecord Storage Program schema.
- 🟡 oauth-attested method depends on a Demos-side OAuth attester. If not built, the method is 🔵 third-party.
- 🔵 W3C Verifiable Credentials, TLSNotary (external proof library — distinct from the 🟢 cci-tlsn:* native context), zkTLS (Reclaim, Pluto), ACME challenges for domain-tls-control.

**DAHR-backed AP2 receipt binding (normative Demos binding).** For DACS-4
§9.5.6 AP2-2, the transaction reference MUST use the distinct `ap2-sr3` arm.
Its `receiptAttestation` identifies the fetched provider status resource and
commits to the exact returned bytes; the DAHR `txHash` is carried separately as
`receiptTransactionRef = { kind: "demos-web2-request", value: txHash }`.
Implementations MUST NOT label that transaction hash as a `storage-program`
AttestationRef locator: a `web2Request` transaction is not a Storage Program
record and cannot satisfy the DACS-2 §7.5.2 fetch-and-hash algorithm as one.
Consumers authenticate the referenced transaction and response commitment by
the same inclusion checks in (a)–(c) below. The AP2 verifier MUST obtain the
exact returned UTF-8 body, require its SHA-256 hash to equal the authenticated
`responseHash`, and derive the provider status, `providerRef`, amount, currency,
and AP2-1 metadata from that body. A detached or caller-supplied projection of
those fields cannot establish settlement, even when another response hash is
authentic.

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
  listing's complete `verificationMethod` configuration. The consensus verifier
  MUST obtain the authorized validator roster from an independently authenticated
  network profile, validator-set epoch, or equivalent trust anchor; a `peerlist`
  or signer roster carried only inside the candidate block MUST NOT authenticate
  itself;
- (c) it MUST obtain the returned `data` string, encode it as UTF-8 without
  reserialisation, require `sha256(UTF8(data)) == responseHash`, and deliver
  those exact bytes so
  `PayloadAttestationRecord.payloadContentHash == responseHash ==
  DeliveryEvidence.deliverableContentHash` for current evidence (or the frozen
  legacy `SettlementEvidence.deliverableContentHash`); and
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
- 🟡 L2PS channel message envelope API shipped as
  `l2ps.channel.ChannelSession` in `@kynesyslabs/demosdk@4.0.16`, with
  monotonic sequence and CH-6 channel reuse handling. Its shipped message wire
  is **not** evidence for the frozen §8.3.3 `LegacyDemosChannelMessage`
  historical read/import arm.

  `signChannelMessage` signs UTF-8 bytes of `"dacs-channelmsg:v1:"` followed by
  the lowercase-hex SHA-256 digest of the canonical unsigned message. It emits
  a `{ sigVersion: "1", signature: "0x…" }` object. The frozen `legacy-import`
  arm instead requires a bare lowercase-hex signature over the domain prefix
  followed by the **raw** 32-byte digest. The shipped wire also lacks CH-7's
  discriminator and signature envelope. Its ASCII-hex digest framing is
  CH-8-style, but it signs under the historical domain rather than CH-8's
  `"dacs-canonical-channel-message:v1:"`. Its signed bytes are therefore
  neither arm's, and `current-read` rejects it. Neither operation may silently
  fall back to another wire; this mapping does not change the frozen historical
  arm.

  Separately, the shipped API does not establish verifier-owned durable
  replay-state continuity across issuer reconstruction or restart. Adapters
  must verify that requirement independently and keep historical audit state
  separate from live state. No Demos SDK version is recorded as a conforming
  `CanonicalChannelMessage` producer. Recording one requires a released version
  that emits only the CH-7/CH-8 wire and passes the mixed-wire corpus. Adapters
  MUST NOT claim current SR-4 message conformance in advance.
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

### RSC v2 capability requirement

A Demos adapter for current RSC admission must authenticate both locator values at one finalized evaluation state under a registered compatible policy and separately provide the complete native-record encoding and trusted size limit. Ordinary address reads and transaction-history pagination alone do not establish that contract. Until an identified binding supplies both capabilities, new current-profile Listing eligibility remains indeterminate. The offline conformance policy is not a claim of deployed Demos support.
