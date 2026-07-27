# DACS — Logical Flow Trace (SDK-mapped pseudocode)

**Spec version.** Aligned to **DACS v0.1**. Trace updates with each minor version of the spec; see CHANGELOG for material changes since earlier drafts.

**Purpose.** Trace one end-to-end DACS happy path against the Demos SDK (`@kynesyslabs/demosdk`), so the logical flow can be sanity-checked against the technical flow that production code executes. Where the protocol needs something the SDK doesn't yet expose, that's called out inline and consolidated in the gap list at the end.

> **Read this as protocol-level pseudocode, not copy-paste-runnable SDK code.** The
> calls below name the *capability* the SDK provides; the exact import path and
> method name track the SDK and have drifted across versions. The mapping below was
> verified against **`@kynesyslabs/demosdk` 4.0.5** (the current published version at
> the time of writing) — always cross-check method names against the published SDK
> reference before implementing.
>
> | Capability (as written below) | SDK 4.0.5 surface |
> |---|---|
> | `demos.storage.read / write` | `demos.storagePrograms.read(...)`; writes via `demos.store(...)` / `demos.tx.store(...)` |
> | `demos.cci.resolve(claimRef)` | `Identities` class from `@kynesyslabs/demosdk/abstraction` (`getIdentities(...)`); see also `demos.crypto.getIdentity` |
> | `demos.wallet.signIn(...)` (SIWD) | `DemosWebAuth` from `@kynesyslabs/demosdk/websdk` (`.create / .login / .sign / .verify`) |
> | `demos.work.run(work)` | `@kynesyslabs/demosdk/demoswork` — build with `DemosWork` / `WorkStep` / `prepareXMStep`, submit via the prepared payload |
> | `demos.web2.createDahr()` → `dahr.startProxy(...)` | matches verbatim ✓ |
> | `demos.sign / connect / connectWallet / getAddress / tx.*` | match verbatim ✓ |
> | `l2ps.L2PS()` | matches (`@kynesyslabs/demosdk/l2ps`); anonymous-key today (see §9.2) |
> | `demos.crypto.encryptForRecipients`, `demos.dacs.sign` | not yet in the SDK (see gap list §9.4, §9.8) |

For a copy/paste-runnable, SDK-independent starting point, run the
[`conformance/walkthrough/`](../conformance/walkthrough/) minimum-conformant
lifecycle. It uses the pinned profile and conformance manifest, links to the
repository vectors, and publishes through a fake substrate adapter;
this document remains the separate live-Demos capability mapping.

**Scenario.** A buyer agent commissions a content-moderation service from a seller agent. The seller posts a listing requiring buyer LEI + jurisdiction proof. Negotiation runs as an RFQ over an L2PS subnet (multi-turn, private). Settlement is cross-chain: buyer pays USDC on Base, seller receives USDC on Solana, routed via Demos's Liquidity Tank infrastructure (which the SDK accesses through `WorkStep`s of context `"xm"`). The seller delivers an entitlement record granting API access. Both parties co-sign the session bundle and anchor it as a Storage Program.

**Substrate primitives exercised.** SR-1 (CCI) · SR-2 (Storage Programs) · SR-3 (DAHR) · SR-4 (L2PS) · SR-5 (Liquidity Tank, accessed via `DemosWork` + `WorkStep` of context `"xm"`).

---

## 1. Sequence diagram

> **The end-to-end sequence diagram** is rendered from the Mermaid source in [Appendix A](#appendix-a--mermaid-source) below — GitHub renders the `mermaid` block inline.

---

## 2. Shared types and helpers

```typescript
// DACS-specific helpers (not part of the SDK; protocol-level)
function domainSep(kind: string, version: "v1"): string {
  return `dacs-${kind}:${version}:`;
}
function signedBytes(kind: string, artifactHash: string): Uint8Array {
  // CORE §B.7: artifactHash is the 64-character lowercase hex string, not raw digest bytes.
  return concat(utf8(domainSep(kind, "v1")), utf8(artifactHash));
}
function jcs(obj: any): string { /* RFC 8785 canonical JSON */ }
function sha256Hex(bytes: Uint8Array | string): string { /* sha256, hex-encoded */ }

// SDK imports used throughout
import { Demos } from "@kynesyslabs/demosdk/websdk";
import { EVM, SOLANA } from "@kynesyslabs/demosdk/xm-websdk";
import { DemosWork, BaseOperation, WorkStep } from "@kynesyslabs/demosdk/demoswork";
import { l2ps } from "@kynesyslabs/demosdk";
```

---

## 3. Stage 1 — Identify

The buyer connects to a Demos node, assembles an IdentityBundle, and presents it under a SIWD signature. The orchestrator validates against the seller's listing.

```typescript
// === Orchestrator-side: issue the session challenge (CORE §B.8 SN-1/SN-3) ===
// The VERIFIER generates the nonce — never the presenter — and binds it to the
// session jobId. ≥128-bit CSPRNG per SN-2. Held in verifier-side state until the
// session reaches a terminal state, with a bounded challenge lifetime (SN-4).
const nonceStore = new Map<string, { sessionNonce: string; consumed: boolean; issuedAt: number }>();

function issueChallenge(jobId: string): { jobId: string; sessionNonce: string } {
  const sessionNonce = randomBytes(16).toString("hex");           // 128 bits, lowercase hex (SN-2)
  nonceStore.set(jobId, { sessionNonce, consumed: false, issuedAt: Date.now() });
  return { jobId, sessionNonce };                                  // delivered to the buyer out of band (SN-3)
}

// === Buyer-side: connect + present, using the verifier-issued challenge ===
async function buyerPresentsIdentity(
  privateKey: string,
  listing: Listing,
  challenge: { jobId: string; sessionNonce: string },   // received from the orchestrator (SN-1)
) {
  const demos = new Demos();
  await demos.connect("https://node.demos.network");
  await demos.connectWallet(privateKey);

  const claims = [
    { ref: "lei:529900T8BM49AURSDO55",    context: "freshness" },
    { ref: "cci-xm:evm:base:0xBuyerEOA",  context: "settlement" },
    { ref: "cci-xm:solana:9xBuyerSOL",    context: "settlement" },
    { ref: "iso3166:GB",                  context: "jurisdiction" },
  ];

  // For the siwd kind the nonce lives in the SIWD message, NOT in a top-level
  // bundle.sessionNonce field (§6.3.2). The presenter does not invent a nonce —
  // it copies the verifier's challenge into the SIWD `nonce` (SN-1).
  const bundle = {
    id: "bundle:" + ulid(),
    primaryClaim: "lei:529900T8BM49AURSDO55",
    claims,
    presentedAt: Date.now(),
  };

  const bundleHash = sha256Hex(jcs(omitField(bundle, "presentation")));

  // SIWD via the Demos wallet — same shape as the standard wallet_signIn call.
  // The SIWD message includes the domain-separated payload as a Resource line so
  // the signature transitively binds to the bundle hash.
  const siwd = await demos.wallet.signIn({
    domain: "buyer-agent.example",
    address: demos.getAddress(),
    statement: "Sign DACS bundle presentation",
    uri: "https://buyer-agent.example",
    nonce: challenge.sessionNonce,                                 // verifier-issued challenge, copied in (SN-1)
    issuedAt: new Date(bundle.presentedAt).toISOString(),
    resources: [`dacs:${hexEncode(signedBytes("bundle-presentation", bundleHash))}`],
  });

  bundle.presentation = {
    kind: "siwd",
    message: siwd.message,
    signature: siwd.signature,
    address: siwd.address,
  };

  await demos.disconnect();
  return bundle;
}

// === Orchestrator-side: validate ===
async function orchestratorValidatesBundle(bundle: Bundle, listing: Listing, jobId: string) {
  const demos = new Demos();
  await demos.connect("https://node.demos.network");

  // 1. Reconstruct the domain-separated payload and verify SIWD.
  const bundleHash = sha256Hex(jcs(omitField(bundle, "presentation")));
  const expectedResource = `dacs:${hexEncode(signedBytes("bundle-presentation", bundleHash))}`;
  assert(bundle.presentation.message.includes(expectedResource), "SIWD resource binding mismatch");
  verifySiwdSignature(bundle.presentation);

  // 1b. Session-nonce match + single-use (CORE §B.8 SN-3 / SN-4). The SIWD Nonce
  //     MUST equal the nonce THIS verifier issued for jobId, and MUST be unconsumed
  //     and within its challenge lifetime. Consume on attempt (not only on success).
  const issued = nonceStore.get(jobId);
  const presentedNonce = parseSiwdNonce(bundle.presentation.message);
  assert(issued && !issued.consumed, "no live challenge issued for this session (SN-4)");
  assert(Date.now() - issued.issuedAt <= CHALLENGE_LIFETIME_MS, "challenge expired (SN-4 bounded lifetime)");
  assert(presentedNonce === issued.sessionNonce, "session-nonce mismatch — not the issued challenge (SN-3)");
  issued.consumed = true;                                          // single-use, consumed on attempt (SN-4)

  // 2. Resolve every claim via CCI to confirm they share a root identity.
  for (const c of bundle.claims) {
    const resolved = await demos.cci.resolve(c.ref);                       // SR-1
    assert(
      resolved.boundTo === bundle.primaryClaim ||
      resolved.boundUnder === bundle.primaryClaim,
      `claim ${c.ref} not bound to primary ${bundle.primaryClaim}`
    );
  }

  // 3. Match against listing.buyerRequirement (required + oneOf).
  matchRequirement(bundle, listing.buyerRequirement);

  await demos.disconnect();
  return { ok: true, bundleHash };
}
```

Notes:
- **`demos.wallet.signIn(...)` is the SIWD entry point** — same shape as `provider.request({ method: "wallet_signIn", params: [...] })`. The bundle's domain-separated hash is carried in the `resources` field so the SIWD signature transitively binds to it.
- **`demos.cci.resolve(ref)`** — for sub-identity binding. The check confirms one root key controls the LEI + the Base address + the Solana address + the jurisdiction claim. Without this, the four claims would be four loose strings.
- **Connection lifecycle.** Every SDK consumer follows `new Demos() → connect → connectWallet → ... → disconnect`. The trace shows it once per stage; production code typically scopes a single `Demos` instance over a session.

---

## 4. Stage 2 — Vet

The orchestrator verifies the buyer's LEI via DAHR. The recipe (signed, anchored) tells it which method to use and which endpoint to hit.

```typescript
async function vet(bundle: Bundle, listing: Listing, jobId: string) {
  const demos = new Demos();
  await demos.connect("https://node.demos.network");
  await demos.connectWallet(ORCHESTRATOR_KEY);

  const results: VerifyResult[] = [];

  for (const claim of bundle.claims) {
    // 1. Fetch the recipe from its anchored Storage Program.
    const recipeAddr = `stor-${sha256Hex("dacs2:recipe:" + claim.scheme)}`;
    const recipeBlob = await demos.storage.read(recipeAddr);               // SR-2
    const recipe = JSON.parse(recipeBlob.value);
    verifyRecipeSignature(recipe);                                          // steward's signature
    assert(matchedClaimRequirement.recipeVersion === undefined
           || recipe.recipeVersion === matchedClaimRequirement.recipeVersion);   // §7.4.1: exact recipe pin per ClaimRequirement (§6.3.3), else latest-at-session-start

    if (recipe.method === "consensus-backed-proxy") {
      results.push(await vetViaDAHR(demos, claim, recipe, jobId));
    } else if (recipe.method === "self-signed") {
      results.push(await vetViaSelfSig(demos, claim, recipe, bundle, jobId));
    } else if (recipe.method === "cci-native") {
      results.push(await vetViaCCI(demos, claim, recipe, jobId));
    }
    // ... other methods omitted for this trace
  }

  // Aggregate per §7.7.1
  const overall = aggregate(results, listing.buyerRequirement);

  const record = {
    jobId,
    evaluatedParty: bundle.primaryClaim,
    freshness: results.map(r => r.attestation),
    overallDecision: overall.decision,
    failureReasons: overall.reasons,
  };
  const recordHash = sha256Hex(jcs(omitField(record, "signature")));
  record.signature = await demos.sign(signedBytes("composite", recordHash));

  // Anchor the composite verification record.
  await demos.storage.write({                                              // SR-2
    address: `stor-${sha256Hex("dacs2:composite:" + jobId + ":" + bundle.primaryClaim)}`,
    value: JSON.stringify(record),
  });

  await demos.disconnect();
  return record;
}

async function vetViaDAHR(demos: Demos, claim: Claim, recipe: Recipe, jobId: string) {
  // ↓ The key question this call answers: "how does the on-chain hash trigger an
  //   operation, and how, without private info?"
  //
  // demos.web2.createDahr() instantiates a DAHR session. dahr.startProxy(...)
  // submits the fetch spec to the validator set. Validators perform the HTTPS
  // GET, then co-sign a Demos transaction that asserts: "URL=X, time=T,
  // body_sha256=H." The body is returned to the caller inline. The on-chain
  // artifact is the *hash*, not the body. No private info crosses chain
  // because the request is a public-API GET — DAHR is explicitly never used
  // for endpoints that require buyer-side secrets.
  const dahr = await demos.web2.createDahr();
  let response;
  try {
    const url = renderTemplate(recipe.endpoint.urlTemplate, { identifier: claim.identifier });
    response = await dahr.startProxy({
      url,
      method: "GET",
      headers: recipe.endpoint.headers,
    });
    // response shape (as observed in production):
    //   { body, status, responseHash, responseHeadersHash, anchorTxRef, validatorSig, fetchedAt }
    assert(sha256Hex(response.body) === response.responseHash, "body/hash mismatch");
  } finally {
    await dahr.stopProxy();
  }

  // Parse with recipe's rules
  const parsed = applyParser(recipe.parser, response.body);
  const decision = recipe.negativeMatch
    ? (parsed.matched ? "fail" : "pass")    // OFAC-style: match-found means listed
    : (parsed.matched ? "pass" : "fail");   // GLEIF-style: match-found means valid

  const vr: VerifyResult = {
    jobId,
    method: "consensus-backed-proxy",
    claim: claim.ref,
    decision,
    attestation: {
      anchor: { kind: "demos-tx", locator: response.anchorTxRef },
      contentHash: response.responseHash,
      // §7.5 of the spec: this identifies which validator set signed the attestation.
      // Today the SDK exposes anchorTxRef; the validator-set claim ref is reconstructed
      // from the tx by looking up the consensus epoch at fetchedAt.
      signer: `substrate-validator-set:demos-mainnet:${response.epochAtFetch ?? "unknown"}`,
    },
    validFrom: response.fetchedAt,
    validUntil: response.fetchedAt + (recipe.defaultMaxAgeSec ?? 86_400) * 1000,
  };
  const vrHash = sha256Hex(jcs(omitField(vr, "signature")));
  vr.signature = await demos.sign(signedBytes("verifyresult", vrHash));

  await demos.storage.write({                                              // SR-2
    address: `stor-${sha256Hex("dacs2:vr:" + jobId + ":" + claim.ref)}`,
    value: JSON.stringify(vr),
  });
  return vr;
}
```

Notes:
- **The "hash triggers an operation" answer is in `dahr.startProxy(...)`.** Validators fetch, validators co-sign the anchoring tx asserting `(url, time, bodyHash)`. The body is delivered to the caller inline; the anchoring tx is what survives. A later consumer holding the VerifyResult can either trust the anchored hash or re-fetch and re-verify against the hash.
- **"How, without private info?"** Public-API endpoint. DAHR is for attesting *public* data fetches. Anything credential-bound goes through other DACS-2 methods (`verifiable-credential` for VC issuance flows, `oauth-attested` for OAuth-scoped fetches handled by buyer-side code without validator involvement, `zktls` when underlying data is private and a TLSNotary proof is appropriate).
- **Recipe pinning.** A `ClaimRequirement.recipeVersion` (§6.3.3, §7.4.1) pins an exact DACS-2 recipe version per claim at session start. If the steward ships a new recipe mid-session (e.g., GLEIF moved their endpoint), the session continues against the pinned version. New sessions start against the latest (when no pin is set).

---

## 5. Stage 3 — Negotiate (RFQ on L2PS)

The buyer and seller exchange offers and counters through an L2PS subnet. Each channel message is signed under the channel-msg domain separator. The final terms become a signed AgreementArtifact (legacy or payee-bound as selected by the listing); the AgreementHash is what's anchored on-chain via a CommitmentRecord.

```typescript
async function negotiateRFQ(
  buyerDemos: Demos,
  sellerDemos: Demos,
  orchestratorDemos: Demos,
  listing: Listing,
  jobId: string
) {
  // 1. Create the L2PS subnet.
  //
  // ⚠ Today the SDK exposes only `new l2ps.L2PS()` with anonymous RSA-key
  // membership. The protocol wants CCI-keyed membership (the subnet's
  // membership predicate is "primary claim must be in {buyer, seller}").
  // CCI-keyed membership is on the DACS-3 build backlog (Tier 1).
  // For this trace we show the production-API call shape; the membership
  // restriction is enforced by the orchestrator at the application layer
  // today, and will move into the SR-4 substrate when CCI-keyed L2PS ships.
  const subnet = new l2ps.L2PS();                                          // SR-4 (substrate exists)
  const subnetId = await subnet.register(orchestratorDemos);               // ⚠ Build: API surface

  // Distribute RSA membership keys to buyer + seller out-of-band (e.g., via SIWD).

  // 2. Multi-turn exchange. Each message signed under "dacs-channelmsg:v1:".
  const transcript: SignedChannelMsg[] = [];

  // Turn 1: buyer offers 85 USDC
  transcript.push(await sendChannelMsg(subnet, buyerDemos, {
    channelId: subnetId,
    sequence: 1,
    type: "counter",
    body: { price: { amount: "85", currency: "USDC" }, deliverable: listing.offering.deliverable },
  }));

  // Turn 2: seller counters 95 USDC
  transcript.push(await sendChannelMsg(subnet, sellerDemos, {
    channelId: subnetId,
    sequence: 2,
    type: "counter",
    body: { price: { amount: "95", currency: "USDC" }, refs: { repliesTo: 1 } },
  }));

  // Turn 3: buyer counters 90 USDC
  transcript.push(await sendChannelMsg(subnet, buyerDemos, {
    channelId: subnetId,
    sequence: 3,
    type: "counter",
    body: { price: { amount: "90", currency: "USDC" }, refs: { repliesTo: 2 } },
  }));

  // Turn 4: seller accepts
  const acceptMsg = await sendChannelMsg(subnet, sellerDemos, {
    channelId: subnetId,
    sequence: 4,
    type: "accept",
    body: { acceptedTerms: transcript[2].body, refs: { repliesTo: 3 } },
  });
  transcript.push(acceptMsg);

  // 3. Construct the AgreementDocument from accepted terms.
  const agreement = {
    jobId,
    derivedFromPattern: "rfq",  // AgreementDocument enum value (the DACS-3 phase kind is "negotiate-rfq"; the agreement records the bare pattern "rfq" per §8.5)
    listingRef: listing.anchor,
    listingContentHash: listing.contentHash,
    parties: {
      buyer: { primaryClaim: "lei:529900T8BM49AURSDO55", address: buyerDemos.getAddress() },
      seller: { primaryClaim: "lei:213800SELLER12345LEI",  address: sellerDemos.getAddress() },
    },
    terms: {
      price: acceptMsg.body.acceptedTerms.price,
      rail: "demos-tank:base-usdc-to-solana-usdc",
      deliverable: listing.offering.deliverable,
      deadline: Date.now() + listing.terms.deadlineSecAfterCommit * 1000,
    },
    signatures: [] as AgreementSignature[],
  };
  const agreementHash = sha256Hex(jcs(omitField(agreement, "signatures")));

  agreement.signatures = [
    { party: "buyer",  value: await buyerDemos.sign(signedBytes("agreement", agreementHash)) },
    { party: "seller", value: await sellerDemos.sign(signedBytes("agreement", agreementHash)) },
  ];

  // 4. commit-agreement: anchor the CommitmentRecord.
  const commitment = {
    jobId,
    agreementHash,
    parties: agreement.parties,
    orchestratorClaim: "lei:OOORCH123ORCH4567OR",
    committedAt: Date.now(),
  };
  const crHash = sha256Hex(jcs(omitField(commitment, "signature")));
  commitment.signature = await orchestratorDemos.sign(signedBytes("commitment", crHash));

  await orchestratorDemos.storage.write({                                  // SR-2
    address: `stor-${sha256Hex("dacs3:commit:" + jobId)}`,
    value: JSON.stringify(commitment),
  });

  // 5. Optional: anchor the encrypted transcript if listing requires it.
  if (listing.terms.transcriptDisclosurePolicy === "encrypted-anchored-required") {
    const enc = encryptForRecipients(transcript, [
      agreement.parties.buyer.primaryClaim,
      agreement.parties.seller.primaryClaim,
    ]);
    await orchestratorDemos.storage.write({
      address: `stor-${sha256Hex("dacs3:transcript:" + jobId)}`,
      value: enc,
    });
  }

  return { agreement, agreementHash, commitment };
}

async function sendChannelMsg(subnet: any, sender: Demos, msg: Partial<ChannelMessage>) {
  const envelope = {
    channelId: msg.channelId,
    sequence: msg.sequence,
    sender: { primaryClaim: lookupPrimaryClaim(sender), address: sender.getAddress() },
    sentAt: Date.now(),
    type: msg.type,
    body: msg.body,
    refs: msg.refs,
  };
  const envHash = sha256Hex(jcs(envelope));
  const signed = {
    ...envelope,
    signature: await sender.sign(signedBytes("channelmsg", envHash)),
  };

  // ⚠ Today: subnet.sendMessage({ recipient, content }) is the SDK call.
  // The protocol wants the envelope (with sequence + signature) to be the
  // first-class type the subnet stores and exposes via a transcript-export
  // API. Today the caller manages that envelope structure in-app.
  await subnet.sendMessage({ recipient: subnet.id, content: signed });     // SR-4
  return signed;
}
```

Notes:
- **L2PS today vs L2PS the protocol wants.** Today: anonymous RSA-key subnet, opaque message bag, no first-class envelope. Wanted: CCI-keyed membership, signed envelopes with monotonic sequence + replies-to refs, encrypted-transcript-anchor export. All three are on the build backlog (DACS-3 Tier 1 substrate work). The trace shows the protocol's view; production code today carries the envelope shape in application code.
- **What the chain sees.** Only the CommitmentRecord (with `agreementHash`, not the transcript) is anchored by default. The transcript stays in the L2PS subnet (private to members). If the listing's `transcriptDisclosurePolicy` is `encrypted-anchored-required`, an encrypted copy is anchored — readable only by the parties' keys.
- **The agreementHash is what binds the rest.** Stage 4 (Settle) and Stage 5 (Verify) both reference `agreementHash`. The negotiation transcript shapes the agreement but doesn't have to be visible to anyone reading the bundle later.

---

## 6. Stage 4 — Settle (Liquidity Tank via DemosWork)

Settlement runs as a `DemosWork` script with two sequential `WorkStep`s:
1. an `xm` step that the Demos node auto-routes through the Liquidity Tank infrastructure (buyer pays USDC on Base; tank releases USDC on Solana to the seller),
2. a follow-up step where the seller mints + anchors the EntitlementRecord and the orchestrator anchors `SettlementEvidence` for both phases.

This is the most important point of alignment: **there is no `tank.transfer()` SDK call**. Liquidity Tanks are an internal optimisation that the substrate applies to cross-chain `xm` steps that meet certain conditions (route exists, amount within tank capacity, source+dest assets both supported). The SDK surface is just `WorkStep` with `context: "xm"`.

```typescript
async function settle(
  agreement: Agreement,
  agreementHash: string,
  buyerKey: string,
  sellerKey: string,
  orchestratorDemos: Demos,
  jobId: string
) {
  // === Payment phase: pay-cross-chain-liquidity-tank ===
  //
  // The buyer constructs a cross-chain payment payload. The Demos node, when
  // executing the xm WorkStep, sees the source/dest combination and routes
  // it through the appropriate Liquidity Tank if one exists for that pair.
  // Lifecycle: empty → pending → completed | failed, all internal to the tank.

  const buyerBase = await EVM.create("https://sepolia.base.org");
  try {
    await buyerBase.connectWallet(buyerKey);

    // Prepare the cross-chain payment payload. preparePay returns a signed
    // payload ready for Demos to broadcast; for cross-chain via tank, the
    // payload also carries the destination chain/address as metadata that
    // the tank reads.
    const payload = await buyerBase.preparePay(
      agreement.parties.seller.address,    // ← destination on Solana, resolved by CCI
      agreement.terms.price.amount,
      {
        asset: "usdc",
        destChain: "solana",
        destAsset: "usdc",
        sessionRef: { jobId, agreementHash },
      }
    );

    const buyerDemos = new Demos();
    await buyerDemos.connect("https://node.demos.network");
    await buyerDemos.connectWallet(buyerKey);

    // Wrap as a WorkStep + DemosWork.
    const paymentStep = new WorkStep({
      context: "xm",
      content: payload,
      critical: true,
      description: "pay-cross-chain-liquidity-tank: Base USDC → Solana USDC",
    });

    const work = new DemosWork();
    work.push(new BaseOperation(paymentStep));

    // Execute. The node:
    //   (a) routes the xm step into the tank,
    //   (b) the tank locks source-side and releases destination-side
    //       atomically within a substrate epoch,
    //   (c) returns the resulting tx refs (sourceTx on Base, destTx on Solana).
    const result = await buyerDemos.work.run(work);                        // SR-5
    assert(result.steps[paymentStep.id].status === "completed");
    const txRefs = result.steps[paymentStep.id].output;

    // Anchor the SettlementEvidence for the payment phase.
    const paymentEvidence: SettlementEvidence = {
      jobId,
      agreementHash,
      phaseType: "pay-cross-chain-liquidity-tank",
      phaseIndex: 0,
      actor: agreement.parties.buyer.primaryClaim,
      completedAt: Date.now(),
      txRef: {
        kind: "liquidity-tank",
        sourceTx: txRefs.sourceTx,
        destTx: txRefs.destTx,
        bridgeOperationId: txRefs.bridgeOperationId,
      },
      errorClass: null,
    };
    const peHash = sha256Hex(jcs(omitField(paymentEvidence, "signature")));
    paymentEvidence.signature = await buyerDemos.sign(signedBytes("evidence", peHash));

    await buyerDemos.storage.write({                                       // SR-2
      address: `stor-${sha256Hex("dacs4:evidence:" + jobId + ":0")}`,
      value: JSON.stringify(paymentEvidence),
    });

    await buyerDemos.disconnect();
  } finally {
    await buyerBase.disconnect();
  }

  // === Delivery phase: deliver-entitlement ===
  const sellerDemos = new Demos();
  await sellerDemos.connect("https://node.demos.network");
  await sellerDemos.connectWallet(sellerKey);

  const entitlement = {
    jobId,
    agreementHash,
    grantedTo: agreement.parties.buyer.primaryClaim,
    serviceEndpoint: "https://api.seller.example/moderate",
    scope: ["content-moderation:v1"],
    apiKeyHash: sha256Hex(generateApiKey()),     // raw key sent off-chain to buyer
    startsAt: Date.now(),
    endsAt:   Date.now() + 30 * 86400 * 1000,
  };
  const entHash = sha256Hex(jcs(omitField(entitlement, "signature")));
  entitlement.signature = await sellerDemos.sign(signedBytes("entitlement", entHash));

  const entAnchor = await sellerDemos.storage.write({                      // SR-2
    address: `stor-${sha256Hex("dacs4:entitlement:" + jobId)}`,
    value: JSON.stringify(entitlement),
  });

  const deliveryEvidence: SettlementEvidence = {
    jobId,
    agreementHash,
    phaseType: "deliver-entitlement",
    phaseIndex: 1,
    actor: agreement.parties.seller.primaryClaim,
    completedAt: Date.now(),
    deliverableContentHash: entHash,
    deliverableAnchor: entAnchor,
    errorClass: null,
  };
  const deHash = sha256Hex(jcs(omitField(deliveryEvidence, "signature")));
  deliveryEvidence.signature = await sellerDemos.sign(signedBytes("evidence", deHash));

  await sellerDemos.storage.write({                                        // SR-2
    address: `stor-${sha256Hex("dacs4:evidence:" + jobId + ":1")}`,
    value: JSON.stringify(deliveryEvidence),
  });

  await sellerDemos.disconnect();
  return { paymentEvidence, deliveryEvidence, entitlement };
}
```

Notes:
- **Liquidity Tank access is implicit, not explicit.** The SDK has no `demos.tank.*` namespace. A cross-chain `xm` WorkStep with a supported source/dest pair routes through a tank. At the SDK level the same call *could* be served by HTLC if tank capacity were exhausted — but the **DACS-4 rail model forbids silent mechanism substitution** (§9.5.5): a pinned `pay-cross-chain-liquidity-tank` rail MUST NOT fall through to HTLC. The produced `txRef.kind` MUST match the pinned rail; a phase whose executed mechanism differs MUST fail (errorClass: permanent). An implementation wanting HTLC fallback expresses it as a distinct pinned rail / phase, not an implicit fallthrough.
- **The entitlement key is off-chain.** Only the hash of the API key is on-chain. The raw key is delivered to the buyer via encrypted message to the buyer's primary key (typically as a payload in an L2PS message, or directly to the buyer's wallet inbox).
- **One DemosWork per phase, or one per session?** The trace shows one `DemosWork` for the payment phase; the entitlement is anchored as a separate write. Production code can compose them into a single `DemosWork` if atomic execution is required, but the protocol allows independent anchoring (each phase produces its own evidence record).

---

## 7. Stage 5 — Verify

The session ends. The orchestrator assembles the AttestationBundle; buyer and seller co-sign; each role anchors their copy at a role-specific address.

```typescript
async function verify(session: SessionState, jobId: string) {
  const orchestrator = new Demos();
  await orchestrator.connect("https://node.demos.network");
  await orchestrator.connectWallet(ORCHESTRATOR_KEY);

  const bundle: AttestationBundle = {
    id: "bundle:" + ulid(),
    bundleVersion: "1",
    jobId,
    finalisedAt: Date.now(),
    parties: [
      { primaryClaim: session.buyer.primaryClaim,        role: "buyer",
        bundleRef: session.buyerIdentityBundleAnchor },
      { primaryClaim: session.seller.primaryClaim,       role: "seller",
        bundleRef: session.sellerIdentityBundleAnchor },
      { primaryClaim: session.orchestrator.primaryClaim, role: "orchestrator" },
    ],
    listing: {
      ref: session.listing.anchor,
      contentHash: session.listing.contentHash,
    },
    agreement: {
      ref: session.commitment.anchor,
      hash: session.agreementHash,
    },
    verificationRecord: { ref: session.vetRecord.anchor },
    phaseSummary: session.evidence.map(e => ({
      phaseType: e.phaseType,
      phaseIndex: e.phaseIndex,
      evidenceRef: e.anchor,
      errorClass: e.errorClass,
      completedAt: e.completedAt,
    })),
    outcome: "completed",
    ratingRefs: [],
  };
  const bundleHash = sha256Hex(jcs(omitField(bundle, "signatures")));

  // Each role co-signs the same bundle hash under the dacs-bundle domain separator.
  bundle.signatures = [
    {
      party: session.buyer.primaryClaim, role: "buyer",
      value: await session.buyerDemos.sign(signedBytes("bundle", bundleHash)),
    },
    {
      party: session.seller.primaryClaim, role: "seller",
      value: await session.sellerDemos.sign(signedBytes("bundle", bundleHash)),
    },
    {
      party: session.orchestrator.primaryClaim, role: "orchestrator",
      value: await orchestrator.sign(signedBytes("bundle", bundleHash)),
    },
  ];

  // Two-sided anchoring: each role anchors its own copy. In the happy case all
  // three copies are canonically equal. Divergence is detectable by reading
  // both role-addressed Storage Programs and comparing.
  for (const party of bundle.parties) {
    await orchestrator.storage.write({                                     // SR-2
      address: `stor-${sha256Hex(jobId + "-bundle-" + party.role)}`,
      value: JSON.stringify(bundle),
    });
  }

  await orchestrator.disconnect();
  return bundle;
}
```

Notes:
- **The bundle is the audit unit that survives.** A consumer reading just the bundle can dereference every ref (listing, agreement, verifyresults, evidence, entitlement) and verify content hashes + signatures end-to-end.
- **Reputation derivation reads bundles.** Keyed against the bundle's `primaryClaim` — `lei:529900T8BM49AURSDO55` — not the EVM or Solana address. This is what makes reputation portable across substrates and rotations.
- **Bundle anchoring is the orchestrator's responsibility in this trace**, but the protocol allows each party to anchor their own copy at their own role address. In production code the writes would typically be wrapped in a single `DemosWork` for atomicity (all three or none).

---

## 8. Substrate primitive call-out

SDK surface column verified against `@kynesyslabs/demosdk` **4.0.5**. Names track the SDK across versions — cross-check the published SDK reference before implementing.

| Primitive | SDK surface (4.0.5) | Production status |
|---|---|---|
| **SR-1** Cross-substrate identity | `Identities` (`@kynesyslabs/demosdk/abstraction`, `getIdentities(...)`); SIWD via `DemosWebAuth` (`@kynesyslabs/demosdk/websdk`) | ✅ Live (8 CCI contexts in production) |
| **SR-2** Anchored storage | `demos.storagePrograms.read(addr)`; writes via `demos.store(...)` / `demos.tx.store(...)` | ✅ Live (Storage Programs, 128 KB cap) |
| **SR-3** Consensus-backed proxy | `demos.web2.createDahr()` → `dahr.startProxy({url, method})` → `dahr.stopProxy()` | ✅ Live (hash-commitment mode); ⚠ validator-body-signed mode pending |
| **SR-4** Private channel | `new l2ps.L2PS()` (`@kynesyslabs/demosdk/l2ps`) → `subnet.sendMessage({recipient, content})` | ⚠ Substrate live; CCI-keyed membership + envelope API + transcript export on backlog |
| **SR-5** Atomic cross-chain settlement | `WorkStep` / `prepareXMStep` (context `"xm"`) inside `DemosWork` (`@kynesyslabs/demosdk/demoswork`), auto-routed through Liquidity Tank | ⚠ Phase 1 live (EVM-USDC unidirectional, 2 testnet tanks); Phase 2-4 (Solana, bidirectional, consensus execute, emergency recovery) on roadmap |

---

## 9. Gap list: what the trace assumes the SDK provides but doesn't yet

The trace is an honest forward projection of what production DACS-on-Demos code looks like when the build backlog is closed. Below is the audit of *exactly* what calls in this trace are forward-looking vs live today.

### 9.1 SR-3 (DAHR) — `dahr.startProxy(...)` response shape

**Trace assumption.** The response carries `{ body, responseHash, responseHeadersHash, anchorTxRef, validatorSig, fetchedAt, epochAtFetch }`.

**Reality today.** Production DAHR returns `body`, `responseHash`, `responseHeadersHash`, and an `anchorTxRef`. The `validatorSig` and `epochAtFetch` fields are not first-class on the response object — they're derivable from the anchor tx by looking up the consensus epoch, but the SDK doesn't surface them as a structured field.

**Gap.** Add `validatorSig` and `epochAtFetch` to the `startProxy` return shape so the VerifyResult can populate `attestation.signer = "substrate-validator-set:demos-mainnet:{epoch}"` without an extra round-trip.

**Spec impact.** None — the VerifyResult shape doesn't care how the signer field is populated, as long as it can be.

### 9.2 SR-4 (L2PS) — CCI-keyed membership

**Trace assumption.** `new l2ps.L2PS()` then `subnet.register(orchestratorDemos)` produces a subnet whose membership predicate is "primary claim must be in {buyer, seller}".

**Reality today.** `new l2ps.L2PS()` produces an anonymous RSA-keyed subnet. Membership is "holder of the RSA private key." There is no concept of "primary claim must match X" enforced at the substrate.

**Gap.** Add CCI-keyed L2PS subnet creation: the subnet's registration accepts a list of CCI primary claims, and the substrate's L2PS membership-check resolves an incoming message's signer against the registered claim list. This is the **Tier 1 substrate work** for DACS-3 (already on the backlog).

**Spec impact.** None on protocol; the trace's CCI-keyed assumption matches DACS-3 §8.3 as written. The build work unlocks the spec.

### 9.3 SR-4 (L2PS) — channel-message envelope API

**Trace assumption.** `sendChannelMsg(...)` sends a fully-structured envelope (sequence, signature, refs) and the SDK preserves the structure on the receive side.

**Reality today.** `subnet.sendMessage({ recipient, content })` accepts arbitrary `content`. The structure is whatever the caller puts in. There is no SDK-level type for `ChannelMessage`, no sequence enforcement, no transcript-export.

**Gap.** First-class `ChannelMessage` type in the SDK with sequence validation on receive, transcript export, and helper for the `dacs-channelmsg:v1:` signing. Also on DACS-3 Tier 1.

**Spec impact.** None — the envelope shape in this trace matches DACS-3 §8.3.3.

### 9.4 SR-4 (L2PS) — encrypted-transcript anchoring

**Trace assumption.** `encryptForRecipients(transcript, [...])` + `demos.storage.write(...)` anchors an encrypted transcript that the listed parties can later decrypt.

**Reality today.** Storage write is straightforward; encryption-to-recipients-by-primary-claim is not an SDK helper.

**Gap.** Add `demos.crypto.encryptForRecipients(claims, payload)` that resolves each primary claim to its current encryption key via CCI and produces a multi-recipient envelope. Required for `transcriptDisclosurePolicy: "encrypted-anchored-required"`.

**Spec impact.** None.

### 9.5 SR-5 (Liquidity Tank) — destination-chain resolution on `preparePay`

**Trace assumption.** `EVM.preparePay(destinationAddress, amount, { destChain, destAsset, sessionRef })` produces a cross-chain payload with destination metadata that the tank reads.

**Reality today.** `preparePay(recipient, amount)` produces a single-chain payment payload. Cross-chain via tank is currently constructed by hand (the buyer constructs a tank-deposit transaction on the source chain, the tank operator handles the dest-side release).

**Gap.** Either:
- (a) Extend `preparePay` (or add `prepareCrossChainPay`) to take destination metadata and emit a tank-aware payload, OR
- (b) Document the manual construction pattern and provide a helper.

This is on the DACS-4 build backlog ("WorkStep wrapper for `pay-cross-chain-liquidity-tank`").

**Spec impact.** None — the protocol says nothing about the SDK shape, only the resulting txRef shape (`{ kind: "liquidity-tank", sourceTx, destTx, bridgeOperationId }`).

### 9.6 SR-5 (Liquidity Tank) — Solana destination

**Trace assumption.** Tank routes Base USDC → Solana USDC.

**Reality today.** Phase 1 tanks are EVM-only (ETH Sepolia + Polygon Amoy, both EVM, USDC unidirectional). Solana destination is Phase 2-4 work.

**Gap.** Phase 2-4 Liquidity Tank work: Solana destination support, bidirectional flow, consensus `executeBridgeOperations` (validator-set co-signing of tank ops), emergency recovery path.

**Spec impact.** None on protocol; the SR-5 capability statement is satisfied by any atomic cross-chain settlement primitive. Today the protocol can fall through to `pay-cross-chain-htlc` for Solana destinations (the reference implementation uses HTLC for fx-rfq Solana ↔ EVM today).

### 9.7 Protocol-level: validator-set claim resolution

**Trace assumption.** `substrate-validator-set:demos-mainnet:{epochId}` is a resolvable ClaimReference.

**Reality today.** Demos publishes validator-set rosters by epoch; the SDK doesn't yet expose a `cci.resolveValidatorSet(substrateId, epoch)` helper.

**Gap.** Add the resolver helper so VerifyResult signer fields can be programmatically validated. Useful for cross-substrate consumers verifying Demos-produced VerifyResults.

**Spec impact.** None; the resolver is a convenience.

### 9.8 Protocol-level: domain-separated signing convenience

**Trace assumption.** `demos.sign(signedBytes("kind", hash))` is the universal signing path.

**Reality today.** `demos.sign(bytes)` exists; the caller constructs the domain-separated payload.

**Gap.** Optional: a `demos.dacs.sign("kind", hash)` helper to enforce the registry of domain separators from §7.7 of the spec. Reduces the surface area where a sloppy caller could sign the raw hash by mistake.

**Spec impact.** None; it's a convenience helper to make protocol violations harder.

---

## 10. Summary — what this trace shows

**Protocol composes with the SDK where the SDK is complete** (SR-1, SR-2, SR-3). The Identify and Vet stages map onto existing SDK capabilities — identity resolution (`Identities` / `getIdentities`), SIWD auth (`DemosWebAuth`), storage programs (`demos.storagePrograms.read` / `demos.store`), and DAHR (`demos.web2.createDahr` + `startProxy`, which matches the pseudocode verbatim). The exact method names differ from the illustrative calls in the stages above; see the SDK-compatibility note at the top of this document for the verified mapping against SDK 4.0.5.

**The two stages with real SDK gaps are Negotiate (SR-4) and Settle (SR-5).** Both have substrate primitives that exist today (L2PS subnet, Liquidity Tank Phase 1) but lack the SDK-surface ergonomics the protocol assumes. None of the gaps require new protocol design — they're all build-backlog items already tracked (Tier 1 for SR-4 L2PS-CCI work; Phase 2-4 for SR-5 tank expansion).

**The protocol does not ask the substrate for anything it isn't already on track to provide.** Every gap above is either a documented backlog item or a convenience helper. There is no "the protocol assumes a primitive that doesn't exist and isn't planned" gap.

**Open questions surfaced by writing this SDK-mapped trace** (different from the protocol-only trace's open questions):

1. The `xm`-step routing decision (tank vs HTLC) happens at the node, not in caller code. **Resolved (§9.5.5, normative, issue #60):** the rail-registry distinction is enforced — the produced `txRef.kind` MUST match the pinned rail, and a phase that executed a different mechanism than pinned MUST fail (errorClass: permanent). No silent tank→HTLC fallthrough; HTLC fallback must be a distinct pinned rail.

2. SR-3 today produces a hash-commitment. The protocol's v0.2+ strengthening adds a validator-body-signed mode. **What's the migration trigger?** Schemes that require it (lei, finra-crd, ofac-clear) would need to be flagged in their recipes when the new mode ships, and old recipes would need to be re-anchored. *Suggests: spec should explicitly require new recipe versions, not in-place upgrades, when the trust model changes.*

3. The L2PS CCI-keyed membership work — does the substrate enforce the predicate or does the orchestrator? *Today: orchestrator (application layer). After Tier 1: substrate. Worth being explicit in DACS-3 about which layer enforces, because consumers reading bundles want to know.*

---

## Appendix A — Mermaid source

If you want to re-render the diagram, edit it, or paste it into a tool like https://mermaid.live, here is the source. The rendered version at the top of this document is produced from this exact code.

```mermaid
sequenceDiagram
    autonumber
    participant B as Buyer Agent
    participant O as Orchestrator
    participant S as Seller Agent
    participant D as Demos Node<br/>(RPC + validators)
    participant Ext as GLEIF API

    Note over S,D: Pre-session: seller publishes listing
    S->>D: new Demos() + connectWallet
    S->>D: anchor listing as Storage Program
    D-->>S: stor-{hash}, listingHash

    Note over B,O: Stage 1 — Identify
    B->>B: new Demos() + connectWallet
    B->>O: IdentityBundle + SIWD presentation
    O->>D: CCI sub-identity resolution
    D-->>O: claim->key mappings
    O->>O: validate vs listing.buyerRequirement

    Note over O,Ext: Stage 2 — Vet
    O->>D: read recipe from Storage Program
    D-->>O: signed recipe
    O->>D: demos.web2.createDahr() + startProxy
    D->>Ext: HTTPS GET api.gleif.org/lei-records/{lei}
    Ext-->>D: response body
    D-->>O: body + validator-signed (URL, time, bodyHash)
    O->>D: anchor VerifyResult + CompositeRecord
    O->>D: dahr.stopProxy()

    Note over B,S: Stage 3 — Negotiate (RFQ on L2PS)
    O->>D: new l2ps.L2PS() (subnet substrate)
    Note over O: ⚠ Today: anonymous RSA; CCI-keyed membership on backlog
    B->>S: offer (turn 1, signed channel msg)
    S->>B: counter (turn 2)
    B->>S: counter (turn 3)
    S->>B: accept (turn 4)
    O->>O: construct AgreementDocument
    B->>O: sign agreementHash
    S->>O: sign agreementHash
    O->>D: anchor CommitmentRecord

    Note over B,S: Stage 4 — Settle (Liquidity Tank via DemosWork)
    B->>B: new DemosWork()
    B->>B: WorkStep(context="xm", evmInstance.preparePay(...))
    B->>D: demos.work.run(work)
    D->>D: tank auto-leverages: lock Base / release Solana
    D-->>B: tx confirmations both chains
    S->>S: mint EntitlementRecord (signed, anchored)
    S->>D: anchor SettlementEvidence
    B->>D: anchor SettlementEvidence

    Note over B,O: Stage 5 — Verify
    O->>O: assemble AttestationBundle
    B->>O: sign bundleHash
    S->>O: sign bundleHash
    O->>D: anchor bundle at two role-specific addresses
    D-->>O: bundleRefs
```
