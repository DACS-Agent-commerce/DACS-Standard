# DACS-2: Vet — Vet

*Normative module of DACS v0.1. Read the [Primer](../PRIMER.md) first; shared types, signatures, canonical form, the session model, and substrate requirements live in [CORE](CORE.md). Section numbers are retained from the unified specification; per the §→document map in [CORE](CORE.md), cross-references of the form §6–§10 point to sibling module documents, and §A / §12–§14 to the companion references (Demos mapping, threat model, glossary, conformance plan). The [conformance vectors](../conformance/) exercise this module's rules.*

## Chapter 7 — DACS-2: Vet

**Stage:** Vet (2nd of 5). **Status:** Draft — **DACS-2 v0.6** (on the common DACS v0.1 baseline; v0.6 evaluates presence-only `ClaimRequirement` members against the exact signed `IdentityBundle` under PCR-1..PCR-6 and excludes them from `VerifyResult` evidence; v0.5 makes `parserRules` conditional on the selected method's declared evaluation mode and rejects parser/method confusion before invocation; v0.4 registers the persistent Demos `demos-gcr-domain` method and permits distinct recipe families for one claim scheme; v0.3 adds complete `ClaimRequirement` qualification before §7.7.1 decision classification and binds Vet progression and terminal verification to the CORE §5.1 SR-2 lifecycle; v0.2 pins that a `VerifyResult` establishes **existence/validity, never control** — §7.3.2 area; and the `lei` **registration-status → decision** mapping, §7.4.1). **Depends on:** SR-2 (required), SR-3 (required for consensus-backed-proxy and evm-rpc methods); composes with W3C VC, TLSNotary, zkTLS / Reclaim. **Used by:** DACS-1 (claim verification), DACS-3 (pre-negotiation gate), DACS-5 (audit references).

### 7.1 Abstract

DACS-2 specifies how a party's claimed credentials are verified against authoritative sources during the Vet stage. It defines:

- A **verification method registry** — a closed set (`verifiable-credential`, `tlsnotary`, `zktls`, `consensus-backed-proxy`, `oauth-attested`, `evm-rpc`, `domain-tls-control`, `self-signed`, `demos-gcr-domain`), each with input/output shape, trust model, and substrate requirements.
- A **recipe registry** — a versioned, anchored lookup binding a DACS-1 claim scheme (`lei`, `finra-crd`, `domain`, …) to the method and parsing rules used to verify it.
- A **uniform VerifyResult** — the method-agnostic, anchored record the rest of the stack consumes (decision, attestation reference, extracted data).
- A **composite verification record** — the anchored artifact Vet produces, aggregating freshness checks, supplementary signals, and deal-specific claims; referenced by DACS-5.
- A **vet-credentials phase** — the phase the orchestrator invokes over the counterparty's bundle and the listing's requirement, emitting the composite record.

Vet does three jobs and produces one output (the composite verification record) that the rest of the transaction — and a future auditor, regulator, or arbitrator — references.

### 7.2 Motivation

The Vet stage answers two questions before progressing past vet-credentials:

- *Is the counterparty's bundle valid right now?* Claims assembled months ago may have lapsed registrations, updated sanctions lists, or expired certifications.
- *Is it sufficient for this specific deal?* The listing may require deal-specific claims the bundle was never pre-attested for.

A one-shot check at session start fails for three reasons:

- **Freshness** — existing standards attest at issuance; Vet must re-check against current authority state and produce a current attestation superseding the stale one.
- **Supplementary signals** — reputation, completion history, dispute rates, and prior ratings inform the decision without being formal credentials.
- **Deal-specific claims** — some claims exist only for this transaction (insurance binding, project clearance) and aren't reused.

Two further design failures DACS-2 avoids:

- Treating each method as its own protocol. The uniform `VerifyResult` is the lingua franca — methods produce it, the stack consumes it.
- Forcing one method onto all credentials. Public-registry credentials fit consensus-backed proxy/SR-3; private-data fit TLSNotary/zkTLS; cooperative-issuer fit W3C VC. The recipe registry routes each scheme; the stack stays method-agnostic.

### 7.3 Verification methods (v0.5 closed registry)

The v0.5 method set is closed. New methods are added in subsequent versions of DACS-2 by the governance process in chapter 11.

#### 7.3.1 Common contract

Every method MUST:

- **(CM-1)** accept inputs as specified in its sub-section;
- **(CM-2)** anchor its attestation via SR-2 at an address derived from the session id, claim scheme, and identifier:

  `dacs2:{jobId}:{scheme}:{identifier}:v{recipeVersion}`

  (or substrate-equivalent) — `{identifier}` is a CF-4 variable segment and MUST be percent-encoded before assembly (CORE §B.1). Recipe versions remain unique and monotonic across the scheme, including when the scheme has multiple families, so two families cannot collide at this address;
- **(CM-3)** produce a VerifyResult conforming to §7.5;
- **(CM-4)** classify its outcome as exactly one of `pass`, `fail`, `indeterminate`, or `error` per the semantics in §7.5.1;
- **(CM-5)** set `VerifyResult.method` to its own kind.

#### 7.3.2 verifiable-credential

```
type VCMethodInput = {
  recipe: Recipe
  identifier: string                   // claim identifier (must match VC subject)
  presentation: VerifiablePresentation
  issuerAllowList?: ClaimReference[]
}
```

**Procedure.** The verifier runs these steps:

1. **Parse** the presentation.
2. **Verify the VC signature** against the issuer key (resolved per the VC method).
3. **Issuer allow-list** — if `issuerAllowList` is set, MUST reject if the VC issuer is not in the list.
4. **Validity** — verify the VC has not expired and is not revoked (via status list, if present).
5. **Subject match** — verify the VC’s subject identifier matches the claim’s identifier canonically.
6. **Holder-binding proof** — verify the VerifiablePresentation's holder-binding proof: the presentation MUST be signed by the key controlling the credential subject (the holder), over a challenge that includes the bundle's session nonce (see *Session-nonce binding* below). MUST reject if the holder proof is absent or does not verify.
7. **Anchor** the VC (or its hash, if the VC is private) via SR-2.
8. **Extract** structured data per `recipe.parserRules`.
9. **Return** a VerifyResult (see *Outcome* below).

*Session-nonce binding.* The challenge nonce is, per the §6.3.2 disjunction, the SIWD message `Nonce` for a `siwd`-presented bundle, else the top-level `bundleToVet.sessionNonce` (a SIWD-presented bundle does NOT populate the top-level field, so a VC claim inside one binds to the SIWD Nonce); its provenance is CORE §B.8 (SN-1..4) — the verifier generates it, so the same party runs this binding check. This is the same session nonce the presentation check validated (Vet runs before DACS-3, so the bundle nonce is the comparison target). Without it, a verified VC captured from one party could be replayed by a non-holder, or re-presented across sessions — verifying the VC's issuer signature alone proves the credential is genuine, not that the presenter holds it.

*Outcome.* `pass` if all steps succeed; `fail` on signature/expiry/revocation/holder-binding failures; `error` on parser failures (a verifier-side failure to consume the presentation — never `fail`; consistent with PSP-2 and the §7.5.1 decision semantics, so it is retryable per VP-R1 rather than treated as a terminal authority answer); a parseable-but-inconclusive presentation is `indeterminate`.

**Trust model:** issuer; W3C VC spec; key resolution method (e.g. did:web). **Substrate:** SR-2.

#### 7.3.3 tlsnotary

```
type TLSNotaryMethodInput = {
  recipe: Recipe
  identifier: string
  proof: TLSNotaryProof                // MPC-derived TLS session commitment + notary signature
  sessionTemplate?: string
}
```

**Procedure.** Validates the TLSNotary proof per the TLSNotary specification (current PSE rebuild); verifies the notary signature against a known notary public key registry; if sessionTemplate is set, verifies the proof targets that endpoint and protocol; anchors the proof commitment via SR-2; applies parser rules to any disclosed segments; returns VerifyResult per outcome. **Trust model:** TLS PKI; notary honesty; MPC computational assumptions. **Substrate:** SR-2.

#### 7.3.4 zktls

```
type ZKTLSMethodInput = {
  recipe: Recipe
  identifier: string
  provider: "reclaim" | "pluto" | string
  programId: string
  proof: ZKTLSProof
}
```

**Procedure.** Loads the verifier circuit for provider:programId; verifies the zk proof per the circuit’s verification algorithm; verifies any public inputs match expected values; anchors the proof + public-input hash via SR-2; applies parser rules to public-input disclosed data; returns VerifyResult per outcome. **Trust model:** zk soundness; provider’s circuit correctness; TLS PKI; proxy honesty (provider-dependent). **Substrate:** SR-2.

#### 7.3.5 consensus-backed-proxy

```
type ConsensusProxyMethodInput = {
  recipe: Recipe
  identifier: string
  endpoint: {
    method: "GET" | "POST"
    urlTemplate: string                // e.g. "https://api.gleif.org/api/v1/lei-records/{identifier}"
    headers?: Record<string, string>
    body?: string
  }
}
```

**Procedure.** Renders the URL by substituting {identifier} and other recipe parameters into urlTemplate; submits the fetch specification to the substrate’s SR-3 primitive (on Demos: dahr.startProxy({url, method, options})); the substrate returns the response body inline plus chain-anchored commitment hashes (responseHash, responseHeadersHash) via a one-tx web2Request. Anchors the commitment record via SR-2; applies parser rules to the response body; if recipe.negativeMatch is true (OFAC pattern): decision = "pass" when the parser finds no match, "fail" when a match is found; otherwise pass when the parser matches expected success criteria.

**Trust model in v0.1 — consensus-anchored hash commitment.** The substrate validator set collectively signs the on-chain transaction that asserts "we fetched URL X at time T and obtained a response with hash H." The full response body is **not** independently signed by the validator set in v0.1; the chain-level guarantee is "this hash came from this URL at this time," not "this body content is validator-attested." Verifiers consuming the body MUST verify the body’s hash matches the on-chain commitment.

**Trust caveats v0.1 implementations MUST surface to consumers.**

- (a) A validator-set majority that colludes can sign a commitment to a forged response; the body the consumer reads will hash to the committed value, so consumers cannot detect this from the commitment alone.
- (b) A single validator fetching the response and the rest signing the resulting hash is operationally indistinguishable from a full-fanout fetch under current SR-3 specs; recipes used for high-stakes verification SHOULD set multi-method alternatives (see §7.12).
- (c) The TLS connection between substrate validators and the authority is the trust floor for response authenticity at fetch time; an attacker who can MITM the authority’s TLS endpoint can cause all validators to commit to forged content.

**v0.2 strengthening (planned).** A future minor version is expected to specify a "validator-body-signed" mode in which each validator independently signs the response body bytes and the aggregate signature is anchored. When this mode ships, recipes for high-stakes schemes (lei, finra-crd, ofac-clear, sam-uei) SHOULD migrate to require it. v0.1 recipes that already declare alternatives are forward-compatible.

**Substrate:** SR-3 (proxy attestation primitive); SR-2 (anchoring).

**Note on the tlsn CCI context.** TLSNotary proofs are a native CCI context on Demos (cci-tlsn:<proof-hash>), validated by Demos’s GCR routines. When the proof is already registered as a cci-tlsn claim in the counterparty’s bundle, Vet treats it as a CCI-native verification (the tlsn GCR routine has already validated it) and does NOT re-run the external tlsnotary method. The external tlsnotary method applies only when an *unregistered* proof is presented at session time.

#### 7.3.6 oauth-attested

```
type OAuthAttestedMethodInput = {
  recipe: Recipe
  identifier: string
  provider: string                     // e.g. "google", "github"
  scopes: string[]
  maxTokenAgeSec: number               // recipe-required
  attestation: OAuthAttestationEnvelope
}
```

**Procedure.** The verifier runs these steps:

1. **Validate** the attestation envelope’s signature.
2. **Identifier match** — verify the attestation references an OAuth flow that resolved to the claimed identifier (e.g. the `sub` claim from a Google ID token matches).
3. **Scopes** — verify the granted scopes include those required by the recipe.
4. **Session binding** — verify the attestation is bound to this session: the attestation challenge/nonce MUST include the bundle's session nonce (the §6.3.2 disjunction, as defined under *Session-nonce binding* in §7.3.2), and the verifier MUST reject an envelope whose nonce does not match it. This is the same anti-replay requirement as the §7.3.2 holder-binding rule — a captured envelope cannot be replayed by a non-holder or across sessions within `maxTokenAgeSec`. If the attestation service cannot carry a nonce, the recipe MUST document the residual replay risk.
5. **Anchor** the attestation via SR-2.
6. **Return** a VerifyResult.

**Trust model:** OAuth provider; attestation service honesty; TLS PKI. **Substrate:** SR-2 (SR-3 if the attestation service is the substrate’s API Verification primitive).

#### 7.3.7 evm-rpc

```
type EVMRPCMethodInput = {
  recipe: Recipe
  identifier: string
  chainId: number
  contract: string                     // 0x address
  method: string                       // contract method name or selector
  args?: unknown[]                     // ABI-encoded arguments
}
```

**Procedure.** Submits a proxy-attested EVM call via SR-3 (typically wrapped as a JSON-RPC fetch); substrate validator set executes the call and signs the result; anchors the signed result via SR-2; decodes the return value per recipe parser rules; compares the decoded value to the claim’s identifier (e.g., owner address of an ERC-8004 token); returns VerifyResult. **Trust model:** substrate consensus; EVM chain finality. **Substrate:** SR-3; SR-2.

#### 7.3.8 domain-tls-control

```
type DomainTLSControlMethodInput = {
  recipe: Recipe
  identifier: string                   // the domain
  challengeType: "http-01" | "dns-01" | "tls-alpn-01"
  challenge: Challenge
  response: ChallengeResponse
}
```

**Procedure.** Validates the challenge/response per the ACME-style challenge specification; confirms response was retrievable from the claimed domain at the time of the challenge; anchors the challenge/response transcript via SR-2; returns VerifyResult (pass on valid response, fail on invalid, indeterminate on retrieval failure). **Trust model:** DNS / TLS PKI; ACME challenge integrity. **Substrate:** SR-2.

#### 7.3.9 self-signed

```
type SelfSignedMethodInput = {
  recipe: Recipe
  identifier: string                   // hex public key
  signature: string                    // signature over the claim assertion
  assertion: string                    // canonical bytes signed
}
```

**Procedure.** Validates the signature against the key in identifier; anchors the signed assertion via SR-2; returns VerifyResult with pass on valid signature, fail on invalid. This method provides minimal trust — it proves possession of the key, nothing more. Recipes targeting authority-issued schemes MUST NOT use self-signed. **Trust model:** cryptographic signature. **Substrate:** SR-2.

#### 7.3.10 demos-gcr-domain

```
type DemosGCRDomainMethodInput = {
  recipe: Recipe
  identifier: string                   // canonical DCR-1 A-label hostname
  metadata: DemosGCRDomainMetadata     // DACS-1 §6.3.1 DCR-6 provenance
}
```

This method verifies a persistent domain-to-Demos-account binding already recorded by Demos consensus. It MUST NOT fetch, or treat a prior fetch of, `/.well-known/demos-cci.txt` as fresh session proof.

- **(DGCR-1) Authenticated resolution.** Resolve `metadata.sourceTransaction` through the Demos binding and authenticate the carrying transaction, its finalized block, and the GCR `web2.domain` record. An Indexer response is discovery data only. If the authenticated record or finality evidence is temporarily unavailable or cannot be resolved, return `indeterminate`; do not convert absence or transport failure to `fail`.
- **(DGCR-2) Exact record match.** Require native context `web2.domain`; the DCR-1 canonical hostname; the 64-character lower-case hexadecimal Ed25519 account; exact `proofUrl`; source transaction hash and block number; and inclusion time to match the authenticated record. The account MUST be the authenticated writer/account bound by the carrying GCR transition. A passing VerifyResult MUST copy those authenticated values, and only those values, to `data.demosGcrDomain`; DACS-1 control checks consume that result data rather than trusting the bundle's metadata copy. A resolved mismatch returns `fail`; malformed input returns `error`.
- **(DGCR-3) Consensus validation profile.** Authenticate that the carrying GCR transition was accepted under the Demos domain-proof rule: the node fetched the exact URL `https://<host>/.well-known/demos-cci.txt`, required a body of the exact form `demos:dw2p:ed25519:<128-lowercase-hex-signature>`, and verified the decoded Ed25519 signature with `account` over the UTF-8 bytes of `dacs-domain:v1:<host>:<account>` before recording `web2.domain`. The fetched body is not persisted in the GCR and the DACS verifier MUST NOT re-fetch it. A binding that cannot authenticate that this validation profile governed the state transition returns `indeterminate`; a resolved transition that proves a different host, account, URL, or validation profile returns `fail`.
- **(DGCR-4) Persistent evidence time.** Set `verifiedAt` to the authenticated GCR inclusion timestamp (`metadata.recordedAt`), not query time; set `fetchedAt` to query time. `validUntil`, when emitted, MUST NOT exceed `verifiedAt + recipe.defaultMaxAgeSec * 1000`. Re-reading an old GCR record cannot refresh its effective window.
- **(DGCR-5) Control boundary.** A passing result establishes that the persistent record bound the host to the Demos account at inclusion. DACS-1 DCR-7 separately requires the bundle presentation to verify under that same account before the domain is treated as controlled. This method alone does not prove who is presenting it.
- **(DGCR-6) Proof-family separation.** The result method MUST be `demos-gcr-domain`. It does not satisfy a `domain-tls-control` requirement and MUST NOT be relabelled as fresh ACME-style control. Conversely, a `domain-tls-control` result does not authenticate a Demos GCR record.

On successful checks the method anchors the VerifyResult under CM-2 and returns `pass`. **Trust model:** Demos validator consensus and Ed25519; the historical TLS fetch is preserved as provenance, not re-performed. **Substrate:** Demos SR-2 resolution/finality.

### 7.4 Recipe registry

A recipe binds a DACS-1 claim scheme to one verification-method family plus method-applicable evaluation rules and defaults. A scheme MAY have multiple recipe families when the methods prove materially different properties; the family identity is `(scheme, defaultMethod.kind)`.

#### 7.4.1 Recipe schema

```
type Recipe = {

  recipeVersion: number                       // unique and monotonic per scheme; starts at 1

  scheme: string

  defaultMethod: VerificationMethod

  alternatives?: VerificationMethod[]

  defaultMaxAgeSec: number                    // when a verifiedBy reference becomes stale

  parserRules?: ParserSpec                    // presence and execution governed by PRA-1..PRA-5

  negativeMatch?: boolean                     // true => presence in source means fail

  retryClass: "transient" | "permanent"

  retryOnIndeterminate?: boolean              // default false; see §7.6.1 VP-R4

  retryBudget?: number                        // recipe-defined retry budget for transient error; default 3 (see §7.6.1 VP-R1)

  backoff?: { strategy: "exponential" | "fixed"; baseMs?: number }  // default exponential (see §7.6.1 VP-R1)

  availability: RecipeAvailability            // operational status (see §7.4.5)

  governance: {

    proposedBy: ClaimReference

    acceptedAt: number

    supersedes?: number

    anchoring: "in-code" | "single-signer" | "multisig"   // progressive-anchoring phase (PA-1/PA-2/PA-3); see §7.4.4

    emergency?: {                              // present iff this is an emergency revision; see §7.4.4

      isEmergency: true

      failureObservation: string               // URL of authority change / observed response-format diff

    }

    deprecated?: boolean                       // true => MUST NOT start new sessions for required claims; see §7.4.4

    deprecationReason?: string                 // required when deprecated is true

  }

  signature: RecipeSignature                  // steward's signature (see §7.4.4)

}

type RecipeAvailability =

  | "live"            // authority endpoint reachable, attestation path runs end-to-end

  | "operator_gated"  // requires per-operator credential, key, or whitelisting

  | "closed_data"     // authority data not publicly accessible (e.g., paid feed, internal source)

  | "bilateral"       // requires per-relationship agreement between parties

  | "mocked"          // attestation path stubbed; not a production verification

  | "disabled"        // recipe present but the steward has marked it not-for-use

  | "failed"          // recipe's underlying authority is currently broken or unreachable

type VerificationMethod =

  | { kind: "verifiable-credential"; issuerAllowList?: ClaimReference[]; schemaUrl?: string }

  | { kind: "tlsnotary"; endpoint: string; sessionTemplate?: string }

  | { kind: "zktls"; provider: "reclaim" | "pluto" | string; programId: string }

  | { kind: "consensus-backed-proxy"; endpoint: { method: "GET" | "POST"; urlTemplate: string; headers?: Record<string, string>; body?: string } }

  | { kind: "oauth-attested"; provider: string; scopes: string[]; maxTokenAgeSec: number }

  | { kind: "evm-rpc"; chainId: number; contract: string; method: string; args?: unknown[] }

  | { kind: "domain-tls-control"; challengeType: "http-01" | "dns-01" | "tls-alpn-01" }

  | { kind: "self-signed" }

  | { kind: "demos-gcr-domain" }

type IndeterminatePredicate =

  | { jsonPath: string } | { selector: string } | { xPath: string } | { matcher: string }

type ParserSpec =

  | { format: "json"; successJsonPath: string; indeterminateOn?: IndeterminatePredicate[]; dataMap?: Record<string, string> }

  | { format: "html"; successSelector: string; indeterminateOn?: IndeterminatePredicate[]; dataMap?: Record<string, string> }

  | { format: "xml"; successXPath: string; indeterminateOn?: IndeterminatePredicate[]; dataMap?: Record<string, string> }

  | { format: "raw"; matcher: string; indeterminateOn?: IndeterminatePredicate[] }
```

**Parser applicability (normative).** `ParserSpec` consumes structured or raw
content disclosed by a verification method. It is not a generic second verdict
layer and MUST NOT be applied to a method whose own authenticated procedure
already produces the decision and output data.

- **(PRA-1) Closed method classification.** In DACS-2 v0.5 the
  parser-consuming methods are `verifiable-credential`, `tlsnotary`, `zktls`,
  `consensus-backed-proxy`, and `evm-rpc`. The method-native methods are
  `oauth-attested`, `domain-tls-control`, `self-signed`, and
  `demos-gcr-domain`. A later method registration MUST declare exactly one of
  these evaluation modes as part of that method's normative definition.
- **(PRA-2) Recipe-shape validity and compatibility.** If `defaultMethod` or
  any member of `alternatives` is parser-consuming, `parserRules` is REQUIRED
  and MUST be a valid `ParserSpec`; `null` is not absence and is not a valid
  `ParserSpec`. The single `parserRules` member is shared unchanged by every
  parser-consuming method declared by the recipe. A recipe author MUST ensure
  that each such method discloses authenticated content compatible with that
  same parser format, match predicate, and `dataMap`; the registry steward MUST
  reject a combination that requires method-specific parser interpretation or
  rewriting. Methods that require different ParserSpecs MUST be published in
  distinct recipe families. A verifier MUST NOT select, synthesize, or rewrite
  a ParserSpec based on the selected method. A recipe author producing a
  native-only recipe MUST omit `parserRules`, and the registry steward MUST NOT
  activate a newly submitted native-only recipe that carries it. For
  read/replay compatibility, however,
  a verifier that encounters a signed native-only recipe carrying
  `parserRules` MUST ignore that member regardless of its value and MUST NOT
  reject the recipe solely because the member is present. This is a reader
  compatibility rule, not permission for current producers to emit the field.
- **(PRA-3) Selected-method execution.** The verifier first selects the exact
  method from `defaultMethod` or `alternatives`. It applies `parserRules` only
  when that selected method is parser-consuming. In a mixed recipe, selecting
  a method-native alternative MUST skip parser execution even though the
  recipe necessarily carries `parserRules` for its parser-consuming member.
- **(PRA-4) Method-native authority.** A method-native path derives its
  `decision` and any `VerifyResult.data` only from that method's authenticated
  procedure and inputs. Parser output, an inert matcher, or a parser-produced
  value MUST NOT override, supplement, or relabel the method-native result.
- **(PRA-5) Fail before invocation.** A recipe that violates PRA-1 or the
  applicable PRA-2 production/shape rule is invalid and MUST NOT be activated
  by the registry steward. A verifier that encounters a missing or invalid
  required ParserSpec or an unclassified method MUST return `error` before
  invoking the method, fetching an authority, anchoring an attestation, or
  producing any external side effect. A native-only recipe carrying
  `parserRules` follows PRA-2's read rule and PRA-3/PRA-4: the member is inert
  and never becomes a verifier input.

**Existence/validity, never control (normative).** A DACS-2 `VerifyResult` establishes that the identifier is **real and currently valid at its authority** — it does **not**, and a `decision: "pass"` MUST NOT be read to, establish that the presenter *controls* the identifier. Control is a **DACS-1** property (DACS-1 §6.3.2 step (6)): proven by the bundle presentation signature (`key:`), the anchored address-key linkage (`cci-xm:`), or a credential **holder-binding** proof (§7.3.2) for VC/vLEI claims. A bare-registry method (`consensus-backed-proxy`, e.g. `lei` at GLEIF) resolves a *public* identifier with no key-binding, so it can only ever establish existence — never control — whatever it resolves and wherever the result is stored.

**ParserSpec semantics (normative).** When PRA-3 selects a parser-consuming method, the verifier applies the recipe's ParserSpec to that method's authenticated disclosed content to produce a decision and an optional extracted-data map:

- (PSP-1) **successJsonPath / successSelector / successXPath / matcher** is the *match predicate*. For `json`, it is a JSONPath that MUST select at least one node for a match; for `html`, a CSS selector that MUST select at least one element; for `xml`, an XPath that MUST select at least one node; for `raw`, `matcher` is a regular expression (RE2 syntax, no backreferences) that MUST find at least one match in the body.
- (PSP-2) **Decision mapping.** Schemes have a *match polarity*: for a **positive-match** scheme (e.g. `lei`) a match means the claim holds; for a **negative-match** scheme (e.g. `ofac-clear`, where a match means "listed") the recipe’s `negativeMatch: true` flag inverts the outcome. The `indeterminateOn` predicates, when present, are evaluated against the parsed body BEFORE the match predicate; if any matches, the decision is `indeterminate` and the match predicate is not applied. Otherwise:

  | Body parses? | Match predicate | positive-match scheme | negative-match scheme |
  | --- | --- | --- | --- |
  | yes | matches | `pass` | `fail` (match = "listed") |
  | yes | no match | `fail` | `pass` |
  | no — malformed JSON/HTML/XML, parser exception | — | `error` (verifier-side failure to obtain a decision, never `fail`) | `error` |
  | authority signals "no conclusive answer" (a pending/partial-record marker listed in `indeterminateOn`) | — | `indeterminate` | `indeterminate` |

  Each predicate uses the expression kind appropriate to the declared `format` (`jsonPath` for `json`, `selector` for `html`, `xPath` for `xml`, `matcher` for `raw`).
- (PSP-3) **dataMap** maps output field names to JSONPath/selector/XPath expressions evaluated against the same body; each resolved value is recorded in the VerifyResult’s extracted data for audit. A `dataMap` expression that resolves to nothing is recorded as null and MUST NOT by itself change the decision.
- (PSP-4) Parser evaluation MUST be deterministic and MUST NOT execute scripts, fetch sub-resources, or follow redirects embedded in the body.
- (PSP-5) **Negative-match completeness floor.** For a negative-match scheme whose decision rests on the *absence* of the identifier in a full-list download (e.g. `ofac-clear` over SDN.XML), the verifier MUST confirm the response is **complete** before returning the negative (`pass` = "not listed") outcome. It MUST check the received response against a completeness signal — the authority's declared record-count / list-size field, a documented end-of-list sentinel, or the HTTP `Content-Length` matching the received byte count — and MUST NOT return `pass` on a response that is truncated, partial, or whose completeness cannot be confirmed (→ `indeterminate`). *Why:* a truncated-but-parseable SDN download in which the searched entity merely fell outside the received bytes would otherwise clear a sanctioned party; absence MUST be trusted only over a provably-complete response. PSP-5 applies to any `negativeMatch: true` recipe whose match predicate is "identifier not found in a downloaded list".

*Worked example (`lei`, positive-match, GLEIF JSON-API):*

```
recipe.parserRules = {
  format: "json",
  // PRIMARY signal is registration.status, NOT entity.status. Match selects iff the
  // registration is current (ISSUED); the data array is filtered by the nested status.
  successJsonPath: "$.data[?(@.attributes.registration.status=='ISSUED')]",
  // Real-but-not-current registrations are inconclusive, not false (do-not-collapse):
  indeterminateOn: [
    { jsonPath: "$.data[?(@.attributes.registration.status=='LAPSED' || @.attributes.registration.status=='RETIRED' || @.attributes.registration.status=='PENDING_TRANSFER' || @.attributes.registration.status=='PENDING_ARCHIVAL')]" }
  ],
  dataMap: {
    legalName:          "$.data[0].attributes.entity.legalName.name",  // NFC-normalized; this IS the resolvedEntity
    registrationStatus: "$.data[0].attributes.registration.status",    // PRIMARY for the verdict
    entityStatus:       "$.data[0].attributes.entity.status",          // diagnostic only — MUST NOT override registration.status
    jurisdiction:       "$.data[0].attributes.entity.jurisdiction"
  }
}
// registration.status == ISSUED                                  -> decision = pass
// registration.status in {LAPSED, RETIRED, PENDING_TRANSFER,
//   PENDING_ARCHIVAL} (indeterminateOn, eval'd before the match)  -> decision = indeterminate
// registration.status in {ANNULLED, DUPLICATE, MERGED, CANCELLED},
//   or no `data` record (404)                                     -> decision = fail
// non-404 transport / 5xx / `errors[]` body (not valid JSON, or
//   a reachable-but-error authority response)                     -> decision = error
// (extracted legalName/status/jurisdiction recorded in the VerifyResult — these are public GLEIF registry fields, exempt from §7.5 public-anchor minimisation; a privacy-sensitive recipe MUST instead reduce private fields to predicate outcomes)
```

**`lei` status → decision mapping (normative).** The `lei` recipe decides on GLEIF **`registration.status`** — the authority's lifecycle field — **not** `entity.status` (which is diagnostic and MUST NOT override it). The §7.5.1 decision values map as:

| `registration.status` | decision | rationale |
|---|---|---|
| `ISSUED` | `pass` | validly issued **and current** |
| `LAPSED`, `RETIRED`, `PENDING_TRANSFER`, `PENDING_ARCHIVAL` | `indeterminate` | a real, validly-issued registration that is **not current** — inconclusive, not false (do-not-collapse; the same discipline as an unresolvable signer → `indeterminate`) |
| `ANNULLED`, `DUPLICATE`, `MERGED`, `CANCELLED` | `fail` | the identifier is invalid or superseded — the claim is false |
| no `data` record (404) | `fail` | not found |
| reachable-but-error (non-404 / 5xx / `errors[]` body) | `error` | undecidable; retryable per VP-R1 |

A consumer requiring a *current* LEI applies its own risk policy to `indeterminate` (DACS-3 retry-vs-proceed-vs-block); the recipe MUST NOT pre-collapse it to `fail`. **`RETIRED → indeterminate` is a steward decision:** a wound-down entity *was* validly registered, so it reads as "validly-issued, not-current" rather than a false claim — `fail` is the documented alternate under a strict "valid-today" reading. `resolvedEntity` is the NFC-normalized `entity.legalName.name` (the `dataMap.legalName` above). The mapping was source-grounded against **LEI-CDF 3.1** and confirmed by independent implementations converging on the ISSUED / LAPSED / RETIRED rows.

#### 7.4.2 v0.4 recipe registry contents

The registry contains one or more recipe families per scheme registered in chapter 6. Each recipe is anchored via SR-2 at a steward-controlled address. Implementations MUST resolve recipes from the canonical addresses listed in the recipe-registry index document (`dacs2:registry:v0.1` until the steward publishes its signed successor). Default methods per family:

| Scheme | Default method | Notes |
| --- | --- | --- |
| key | self-signed | Lowest trust; session continuity only |
| did | verifiable-credential (DID-bound) or self-signed (key-bound) | Per DID method |
| erc8004 | evm-rpc | Reads token owner |
| lei | consensus-backed-proxy against api.gleif.org/api/v1/lei-records/{identifier} | JSON parser; GLEIF JSON-API |
| finra-crd | consensus-backed-proxy against api.brokercheck.finra.org/search/individual/{identifier} | JSON; FINRA BrokerCheck JSON API (not the HTML site) |
| sam-uei | consensus-backed-proxy against api.sam.gov/entity-information/v3/entities?ueiSAM={identifier} | JSON; SAM.gov Entity API |
| ofac-clear | consensus-backed-proxy against sanctionslistservice.ofac.treas.gov/api/PublicationPreview/exports/SDN.XML | XML; full SDN List download; negativeMatch: true; parser searches for {identifier} entity |
| fedramp | consensus-backed-proxy against marketplace.fedramp.gov/api/v1/products/{identifier} | JSON; FedRAMP Marketplace API |
| naics | consensus-backed-proxy against api.census.gov/data/2017/cbp?get=NAICS2017&NAICS2017={identifier} | JSON; US Census API for NAICS validation |
| cmmc | verifiable-credential preferred; consensus-backed-proxy fallback against cmmcab.org public registry endpoint | CMMC AB publishes both VC issuance and a registry |
| domain | domain-tls-control | Fresh ACME-style challenge |
| domain | demos-gcr-domain | Persistent Demos `web2.domain` GCR binding; does not imply fresh control |
| platform:<provider> | oauth-attested | Provider-specific |
| stripe-connect | oauth-attested (provider="stripe") | Stripe-specific scopes |

**Authority API stability.** The endpoints above are the canonical structured-data endpoints offered by each authority as of v0.1 publication. Authority APIs change; recipes MUST be re-anchored when endpoint URLs or response formats change materially. See §7.4.4 for the recipe-track governance that makes this operational.

#### 7.4.3 Recipe authoring and resolution

A conforming recipe author MUST:

- (RA-1) sign the recipe with the registry steward’s signing key over the domain-separated payload "dacs-recipe:v1:" || recipe_hash per §B.7;
- (RA-2) anchor the recipe via SR-2 at the canonical address;
- (RA-3) specify recipeVersion as unique and monotonically increasing per scheme, including across distinct recipe families for that scheme;
- (RA-4) specify supersedes when replacing a prior recipe in the same family;
- (RA-5) provide at least one alternative method only if the scheme’s underlying authority supports multiple equivalent attestation paths; when more than one declared path is parser-consuming, all of them MUST satisfy PRA-2's single shared-ParserSpec contract.
- (RA-6) ensure that no two active families for one scheme claim the same method kind as either default or alternative. Materially different proof properties (including persistent versus fresh domain control) MUST be separate families, never alternatives.

A verifier MUST resolve a recipe by:

1. reading the recipe-registry index from dacs2:registry:v0.1;
2. looking up the entries for the claim’s scheme, then selecting the exact recipe family required by the listing or supplied evidence; a listing selects a method with `ClaimRequirement.parameters.verificationMethod`, and Demos GCR metadata selects `demos-gcr-domain` only when no method was required;
3. if the matched `ClaimRequirement` pins a specific `recipeVersion` (§6.3.3), resolving that exact version within the selected family; otherwise selecting that family's exact latest version in the authenticated recipe-registry snapshot identified by `SessionContext.recipeRegistryVersion` at session start. The selected family and version MUST resolve before verification or aggregation; a missing family, an absent explicit version, or an implicit latest entry that cannot be resolved returns `error`, not a counterparty `fail`. For an implicit pin, the selected latest entry MUST be `live`; any other availability returns `error`, and the verifier MUST NOT scan backward to an older live version. An explicit pin remains subject to RAV-1 through RAV-4, including the required `error` for `mocked`, `disabled`, or `failed`;
4. fetching that exact recipe at its indicated anchor and verifying its content hash and domain-separated signature;
5. retain that registry snapshot pin in both `VetCredentialsInput.recipeRegistryVersion` and `VetCredentialsInput.sessionContext.recipeRegistryVersion`, require byte-for-byte numeric equality before live aggregation, and carry it into the signed `AttestationBundle` or `FaultAttestationBundle` for later replay. A `SessionRecord` MAY retain the pin operationally, but because it is off-chain, mutable, and unsigned (§10.3.2), it is not replay authority.

A consumer of an existing VerifyResult selects its recipe by the exact triple `(scheme, method, recipeVersion)`. It MUST reject an ambiguous or missing family and MUST NOT silently substitute a different method. For `domain`, a requirement whose `parameters.verificationMethod` is `domain-tls-control` is therefore not satisfied by `demos-gcr-domain`, and vice versa.

This mirrors the rail-side `railVersion` pin (§9.3) and is the mechanism that protects an in-flight session from a steward shipping a recipe revision mid-session.

#### 7.4.4 Recipe-track lifecycle and current steward

**Recipes are operational artifacts on a different lifecycle than the DACS-2 standard itself.** Authority API endpoints change, response formats evolve, sanctions lists update, OAuth provider scopes shift. Treating every recipe revision as a DACS-2 minor version would force the standard onto an impractical release cadence. v0.1 separates the two tracks:

- **DACS-2 standard releases** (this chapter) version on a multi-year cadence. They define the method registry, the VerifyResult shape, the recipe schema, the aggregation algorithm, the phase contract.
- **DACS-2 recipe releases** (the recipe registry) allocate versions per scheme on whatever cadence the underlying authority demands. A scheme's family revisions share that monotonic sequence; recipe revisions ship under the steward’s signing key and do not block on DACS-2 standard releases.

**Current steward (v0.1).** The DACS-2 recipe registry is currently maintained by **KyneSys Labs** as the v0.1 steward. This is a single-signer arrangement (phase PA-2 per the progressive-anchoring scheme below). Wider governance — working-group constitution, multi-signature schemes, sub-authority delegation by domain (sanctions lists, financial regulation, etc.) — is open work for v0.2+ and depends on the eventual constitution of a multi-party body. v0.1 implementations and consumers reason about the registry under single-steward semantics: one signing key, one anchoring authority, full transparency about both.

**Emergency recipe updates.** When an authority endpoint becomes unavailable or returns materially-incompatible data, the steward MAY publish an emergency recipe revision. Emergency revisions MUST: be signed normally; include an emergency: true field in the governance block; cite the failure observation (URL of authority change announcement, observed response format diff). Emergency revisions take effect at next session start; in-flight sessions continue against pinned recipeVersion.

**Recipe deprecation.** A recipe MAY be marked deprecated by publishing a new revision with deprecated: true and a deprecationReason. Verifiers MUST NOT initiate new sessions using deprecated recipes for required claims; in-flight sessions continue. A deprecated recipe with no replacement leaves the scheme un-verifiable; this is a v0.2 strengthening target for any scheme that hits this condition.

**Progressive anchoring phases.** Recipe anchoring proceeds through three phases, recorded in the recipe's `governance.anchoring` field (§7.4.1):

| Phase | `anchoring` value | What it means |
| --- | --- | --- |
| (PA-1) Bootstrap | `in-code` | Implementations MAY ship recipes as in-code constants or static configuration. Recipes in this phase MUST be marked `anchoring: "in-code"` and MUST NOT be presented as canonically anchored. |
| (PA-2) Single-steward | `single-signer` | The steward (currently KyneSys Labs) anchors recipes at the canonical address under a single signature, marked `anchoring: "single-signer"` and disclosing the steward’s identity. **This is the current operating phase for v0.1.** |
| (PA-3) Constituted | `multisig` | If and when a multi-party governance body is constituted, recipes anchor under that body’s multi-signature scheme. |

**Append-only re-anchoring.** Re-anchoring is append-only: prior single-signer recipeVersions MUST remain anchored, immutable, and independently re-verifiable under the steward key and content hash recorded during the single-signer phase (PA-2). The constituted body re-anchors prior recipes only as NEW recipeVersions under its multi-signature scheme; it MUST NOT mutate the signer or content hash of an already-published recipeVersion. This preserves the monotonic recipe-version pinning that §7.12 and §12.4 depend on: a VerifyResult pinned to a recipeVersion during PA-2 MUST continue to validate against the anchoring phase and signing key in force at pin time, not the current registry state.

**Phase disclosure.** (GOV-2) Implementations MUST clearly disclose which phase they operate in. (GOV-3) Consumers reading a VerifyResult MUST verify the recipe’s anchoring phase against their own trust requirements, evaluating each pinned recipeVersion against the phase recorded at the time it was anchored. GOV-3 is satisfiable from the data the protocol exposes: the consumer already resolves the recipe to verify a VerifyResult (§7.4.3), and the resolved Recipe carries `governance.anchoring` (`in-code` / `single-signer` / `multisig`, §7.4.1) — that field is the machine-readable anchoring phase GOV-3 checks.

#### 7.4.5 Recipe availability (normative)

Every Recipe MUST declare an availability value. The value names the recipe’s current operational status — what a verifier should actually expect when it tries to run this attestation path. The values are deliberately discrete and disjoint so consumers can compose them programmatically without flattening operational reality into a single boolean.

| Value | Meaning |
| --- | --- |
| live | Authority endpoint reachable today; the attestation path runs end-to-end against a public or near-public source. The normal operating state for a recipe consumers expect to "just work". |
| operator_gated | Recipe technically functions but requires per-operator setup before it can run: API credentials, IP whitelisting, paid subscription, registered relationship with the authority. Consumers can’t rely on it working without operator-side configuration. |
| closed_data | Authority data not publicly accessible — paid feed, proprietary database, regulator-only API. Recipe shape is defined for forward compatibility but the path cannot run from an open verifier. |
| bilateral | Recipe runs only between parties with a pre-existing bilateral agreement (custom trust anchor, shared secret, contracted attestation service). The shape exists so DACS-2 can describe such verifications uniformly; the recipe doesn’t function for general open-network use. |
| mocked | Attestation path is stubbed for development, testing, or honest-scope visibility. MUST NOT be presented as a production verification path. Implementations MUST surface this state to consumers (e.g., via the "dahr-stub:" prefix marker on attestations). |
| disabled | Recipe exists but the steward has marked it not-for-use, typically because a successor recipe exists or the underlying scheme is being retired. Verifiers MUST NOT initiate new sessions using disabled recipes; in-flight sessions continue. |
| failed | Recipe’s underlying authority is currently broken (endpoint down, response format changed in a way the parser cannot consume, certificate expired). Operationally indistinguishable from "live but unreachable" until the steward publishes an emergency revision or marks the recipe disabled. |

**Consumer obligations.** Verifiers MUST inspect availability before running the recipe.

- (RAV-1) A verifier MUST NOT silently treat operator_gated, closed_data, bilateral, mocked, disabled, or failed as live.
- (RAV-2) A verifier presented with a VerifyResult produced under a non-live availability MUST surface the availability value to the verifier’s consumer; a UI flattening seven states into "verified" / "not verified" without disclosing availability is non-conformant.
- (RAV-3) Aggregation under §7.7.1 treats VerifyResults from disabled, failed, or **mocked** recipes as decision = "error" regardless of the underlying authority response (the recipe is non-operational or a stub; any output is unreliable). In particular a `mocked` recipe MUST NOT satisfy a required claim — its `pass` is a test fixture, not a verification. (`operator_gated` / `closed_data` / `bilateral` differ: they can run validly once the relevant operator-side configuration is in place, so they are not forced to `error`.)
- (RAV-4) The availability of an alternative method does not override the availability of the default; consumers selecting an alternative MUST honour that alternative’s own availability.

**Steward obligations.** The current steward (§7.4.4 and §11.1.1) MUST keep availability values current.

- (RAV-5) Discovery that an authority endpoint has gone down requires either an emergency revision (§7.4.4) or a recipe revision setting availability to failed within a reasonable window.
- (RAV-6) Transitions from live → failed and failed → live are themselves recipe revisions and MUST be signed and anchored normally.
- (RAV-7) Availability is per-recipe-version, not per-scheme; a v3 recipe MAY be live while a v2 recipe is disabled for the same scheme.
**Why this is normative, not informative.** Earlier drafts carried this distinction in the front-matter production-mapping legend as informative iconography (🟢 / 🟡 / 🔵). That framing flattened distinct operational states (live, operator-gated, closed-data, mocked, etc.) into a single "wired" status and pushed disambiguation onto every implementer’s UI surface. Promoting availability to a normative field on the recipe itself moves the disambiguation into the protocol layer, where verifiers can reason about it programmatically and consumers can rely on conformant disclosure. This change was proposed by PATH-OS Labs (third-party reviewer; §11.3) and accepted into v0.1.

### 7.5 VerifyResult

The uniform record every method produces.

```
type VerifyResult = {

  resultVersion: "1"

  scheme: string                              // DACS-1 claim scheme

  identifier: string                          // canonical identifier verified

  recipeVersion: number

  method: VerificationMethod["kind"]

  decision: "pass" | "fail" | "indeterminate" | "error"

  reason: string                              // brief

  attestation: AttestationRef

  data?: Record<string, unknown>              // authenticated method-native output or ParserSpec extraction

  fetchedAt: number                           // unix ms when the authority was queried

  verifiedAt: number                          // unix ms when the result was finalised

  validUntil?: number

  signature: VerifyResultSignature

}

type AttestationRef = {

  anchor: { kind: "storage-program" | "ipfs" | "https"; locator: string }

  contentHash: string

  signer?: ClaimReference                     // for VC: issuer; for proxy: substrate validator-set claim (see below)

}
```

The VerifyResult follows the §B.2 canonical-form template, omitting the `signature` field; the signature is computed over:
signed_bytes := "dacs-verifyresult:v1:" || verifyresult_hash

`VerifyResultSignature.value`, `RecipeSignature.value`, and every DACS-2
`ComponentSignature.value` MUST use the unpadded Base64URL encoding and strict
verification rules in CORE §B.7 (SIG-6).

**Validator-set claim references.** When AttestationRef.signer designates the producer of a consensus-backed-proxy or evm-rpc attestation, the ClaimReference MUST use the substrate-validator-set scheme: substrate-validator-set:<substrateId>:<epochOrSetId>.

- <substrateId> is a registered substrate identifier (v0.1 registry: "demos-mainnet", "demos-testnet"; future substrates added by the registry steward).
- <epochOrSetId> identifies the specific validator set that signed the attestation. Demos uses epoch numbers; substrates using rotating sets use whatever identifier the substrate exposes.
- Consumers MUST resolve the validator-set reference to the substrate’s published validator-set roster for that epoch and verify the attestation signature against the aggregate of those validators’ keys per the substrate’s consensus protocol.
- Substrates whose validator-set rosters are not publicly resolvable MUST NOT be used as the signer of a VerifyResult intended for cross-substrate consumption.

**Public-anchor data minimisation (normative).** A VerifyResult is anchored at a publicly-derivable address (§7.3.1 CM-2) in cleartext, so its `data` field is world-readable. The rules:

- `data` in a publicly-anchored VerifyResult MUST carry **only predicate outcomes** — the booleans / derived facts the recipe's match needs (e.g. `{ overEighteen: true }`, `{ sanctioned: false }`, `{ kycTier: "enhanced" }`).
- `data` in a publicly-anchored VerifyResult MUST NOT carry raw extracted **private** personal or financial fields (date of birth, account balance, document/government-ID numbers) or any value a privacy-preserving method was used specifically to avoid disclosing. Carrying the raw fields is only permissible under the encrypted-to-parties anchoring mode that is roadmap work (§12.1).
- A recipe whose `parserRules`, when present, would extract such sensitive raw fields MUST reduce them to predicate outcomes before they enter an unencrypted anchored `data`.
- Fields that are **already public at the authority** — e.g. a public registry's published company name / jurisdiction, such as GLEIF LEI data — are NOT subject to this minimisation, since anchoring already-public registry data leaks nothing.

> **Note (non-normative).** This is load-bearing for privacy-preserving methods: a `tlsnotary` or `zktls` recipe exists precisely to prove a fact without revealing the underlying value, and copying that value into a cleartext public anchor would defeat the method. The exposure of `scheme`, `identifier`, and `decision` themselves is accepted by design per §12.1.

#### 7.5.1 Decision values and semantics

The four decision values are not interchangeable. Each has distinct semantics that govern retry behaviour, aggregation, and consumer interpretation:

- **pass** — verification ran cleanly and the authority confirmed the claim. The claim is verified.
- **fail** — verification ran cleanly and the authority’s response conclusively contradicts the claim (authority returned "no record found", returned a record that contradicts the asserted identifier, or returned an explicit denial). The claim is verified-false. fail is the authority’s decision; the verifier ran to completion.
- **indeterminate** — verification ran cleanly and the authority’s response was parseable but neither confirms nor contradicts the claim. Examples: authority returned a partial-match record; authority returned a status code that signals "result pending"; authority returned a record whose fields are insufficient to make the comparison the recipe requires. The authority gave its answer; the answer just wasn’t conclusive. indeterminate is the authority’s decision being non-binary.
- **error** — verification could not complete. Transport failure, SR-3 fetch timeout, malformed authority response that the parser cannot consume at all, parser exception, unexpected authority API change. The verifier never received a decision. error is the verifier’s failure to obtain an authority decision, not the authority’s decision to be ambiguous.

**Retry semantics.** (a) error MUST be handled per the recipe's retryClass (§7.6.1): the verifier MAY retry within the VP-R1 budget only when retryClass is `transient`; VP-R3 forbids in-session retry for `permanent`. (b) indeterminate MUST NOT be retried unless the recipe explicitly marks the method as retry-on-indeterminate (rare; reserved for authorities whose "pending" responses become conclusive on re-fetch). The authority’s indeterminate answer is the answer; re-asking does not change it. (c) pass and fail are terminal; no retry.

**Aggregation semantics.** A required claim with overall result error or indeterminate after retry budget exhaustion MUST cause vet-credentials to fail the phase. Consumers MUST NOT treat any of indeterminate, error, or fail as pass under any circumstances. Aggregation logic (§7.7.1) distinguishes the three non-pass outcomes in its failure reasons so downstream consumers (dispute, audit, debugging) can determine whether verification reached the authority at all.

**Why distinguish indeterminate from error.** Both produce non-pass outcomes, but the diagnostic value differs significantly. error means "we should try again or change verification path." indeterminate means "the authority answered, and the answer is not yes or no — escalate to a different authority or accept the ambiguity." Collapsing them loses information that consumers need.

#### 7.5.2 Attestation resolution algorithm

A consumer of a VerifyResult MUST validate the attestation by:

1. fetching the anchor at AttestationRef.anchor.locator;
2. checking integrity against AttestationRef.contentHash by the same procedure that produced it at anchor time (contentHash is the sha256 of the anchored content's canonical form, per the Content-hash definition):
   - for attestations that are canonical-JSON DACS documents — parsing the fetched content, recomputing the RFC 8785 canonical form, and comparing sha256(canonical_form) to AttestationRef.contentHash;
   - for raw-byte attestations (e.g. a consensus-backed-proxy response body per §7.3.5, a tlsnotary proof, or an oauth-attested envelope) — hashing the fetched bytes and comparing sha256(bytes) to AttestationRef.contentHash;
   - mismatch MUST cause rejection in either case;
3. for methods with signer, validating the attestation signature against the signer’s known key (mismatch MUST cause rejection);
4. optionally parsing the attestation to independently re-derive the structured data (for high-stakes verifications).

### 7.6 Verification procedure

The verifier MUST execute each claim verification by:

1. resolving the recipe, validating its PRA-1/PRA-2 parser applicability, and pinning recipeVersion to the session record;
2. rendering method inputs by substituting the claim’s identifier into the method’s template;
3. invoking the method (calling the appropriate substrate primitive for SR-3 methods, or external service);
4. receiving the attestation (raw bytes or a reference if too large for inline transport);
5. anchoring the attestation via SR-2 at the derived address;
6. when the selected method is parser-consuming under PRA-1, applying the required `recipe.parserRules` to the method's authenticated disclosed content and extracting structured data into `VerifyResult.data`; when the selected method is method-native, skipping parser execution and accepting only the decision/data produced by that method's normative procedure (PRA-3/PRA-4);
7. applying parameters — checking the listing’s ClaimRequirement.parameters against authenticated method-native or parser-extracted data (failure to match MUST set decision = "fail");
8. signing and emitting the VerifyResult.

#### 7.6.1 Retry and caching semantics

**Retry policy.** The verifier retries only its own *transient* failures; an authority's substantive answer is final.

- (VP-R1) On `decision = "error"` with `recipe.retryClass == "transient"`, the verifier MAY retry up to a recipe-defined retry budget (default: 3 attempts, exponential backoff).
- (VP-R2) A retry MUST produce a new attestation; reusing the prior attestation is not a retry.
- (VP-R3) On `recipe.retryClass == "permanent"`, the verifier MUST NOT retry within the same session; the failure is final for that session.
- (VP-R4) On `decision = "indeterminate"`, the verifier MUST NOT retry unless `recipe.retryOnIndeterminate` is explicitly true (default false). The authority’s indeterminate answer is itself the answer; re-asking does not change it. The `retryOnIndeterminate` flag is reserved for authorities whose "pending" or "queued" responses become conclusive on re-fetch.
**Reuse / caching.** (VP-C1) A VerifyResult for `(scheme, identifier, recipeVersion)` is cache-eligible while it is still fresh:

    now ≤ VerifyResult.validUntil ?? (verifiedAt + defaultMaxAgeSec × 1000)

`validUntil` governs when present; `defaultMaxAgeSec` (read from the recipe at *that* `recipeVersion`) is the fallback only when `validUntil` is absent. This is the SAME `validUntil ?? default` window the §6.3.2 freshness gate uses (the `min` with `BundleClaim.expiresAt` in §6.3.2 is the bundle-presentation clamp, which has no analogue at reuse time), so the reuse and freshness rules agree. Cache eligibility is not aggregation applicability: every reused result still passes CRQ-1 through CRQ-4 under the consuming requirement.

A cross-session `pass` MAY participate only after the consuming family, version, age, and parameter checks qualify its authenticated data. A cross-session non-pass (`fail`, `error`, or `indeterminate`) MAY be reused only when authenticated cache provenance establishes CORE-canonical equality between the complete originating `ClaimRequirement.parameters` predicate and the consuming predicate. `VerifyResult` v1 does not carry that provenance, so the artifact alone is insufficient. Without proven exact predicate equality, the verifier MUST execute the recipe again under the consuming predicate and use the new result; if no current result can be obtained, aggregation returns `error` and MUST NOT act on the cached non-pass. This new-session execution is not a same-session retry under VP-R1 through VP-R4.

- (VP-C2) Reuse MUST update the consuming session’s record to reference the cached VerifyResult.
- (VP-C3) Reuse MUST NOT bypass the consuming requirement's exact method family, recipe version, parameter predicate, or listing-declared `ClaimRequirement.maxAge` (the listing can demand fresher than the cache window). VP-C1 establishes only cache eligibility; §7.7.1 establishes applicability.

### 7.7 Composite verification record

The document the vet-credentials phase produces.

```
type CompositeVerificationRecord = {
  recordVersion: "1"
  jobId: string                               // DACS-5 session id
  evaluatedParty: ClaimReference              // counterparty's primary identity claim
  bundleHash: string                          // sha256 of the IdentityBundle this Vet ran against
  requirementHash: string                     // sha256 of the exact BundleRequirement evaluated; not proof of its authorship/provenance
  freshness: VerifyResultRef[]                // re-verifications of pre-attested claims
  supplementary: SupplementarySignal[]
  dealSpecific: VerifyResultRef[]
  overallDecision: "pass" | "fail" | "indeterminate" | "error"
  warnings?: VerificationWarning[]            // advisory only; MUST NOT affect overallDecision (WN-1)
  generatedAt: number
  signature: ComponentSignature               // signed by the verifier
}
type VerifyResultRef = {
  anchor: { kind: "storage-program" | "ipfs" | "https"; locator: string }
  contentHash: string
  recipeVersion: number
}
type SupplementarySignal = {
  source: "dacs-5" | "cci-nomis" | "cci-ethos" | "cci-humanpassport" | "external" | string
  signalType: string                          // e.g. "completion-rate", "dispute-rate", "rating-avg"
  value: number | string
  observedAt: number
  attestation?: AttestationRef                // required for "external" sources
}
type VerificationWarning = {
  claimRef: ClaimReference                     // the claim (canonical scheme+identifier) that produced the warning
  code: WarningCode                            // enumerated; see below
  retryable: boolean                           // whether the condition is expected to be transient
  suggestedRetryAfterMs?: number               // advisory per-authority hint; does NOT override recipe-level backoff/retryBudget (WN-4)
}
type WarningCode =
  | "AUTHORITY_UNAVAILABLE"                     // 5xx, timeout, connection failure (maps to a VP-R1 transient error)
  | "AUTHORITY_RATE_LIMITED"                    // 429 or equivalent (VP-R1 transient)
  | "DNS_RESOLUTION_FAILED"                     // transient DNS failure (VP-R1 transient)
  | "TLS_HANDSHAKE_FAILED"                      // transient TLS/certificate issue (VP-R1 transient)
  | "RESPONSE_MALFORMED"                        // unexpected response format (VP-R1 transient, or permanent per recipe retryClass)
  | "RETRY_EXHAUSTED"                           // all VP-R1 retry attempts spent (terminal)
```

**Presence evidence is the signed bundle, not a verification artifact.** Under DACS-1 PCR-6, the producer evaluates every `verificationRequired = false` member directly against the exact `IdentityBundle` supplied as `bundleToVet`. It MUST NOT call a verification recipe, create a `VerifyResult`, or add a `VerifyResultRef` to `freshness` or `dealSpecific` solely to represent that member. A reference needed by a separate `verificationRequired = true` member remains valid evidence for that verified member; it does not turn the presence decision into a verification decision. A genuinely passing-and-fresh pre-attested reference on the claim may still count independently under the ordinary DACS-1 verified-claim and tier rules.

The wire shape of `CompositeVerificationRecord` is unchanged. Its existing `bundleHash` is the binding: a strict consumer replays aggregation with the original signed `IdentityBundle` as companion input, recomputes its DACS-1 bundle hash, and requires exact equality with `record.bundleHash`. The consumer likewise recomputes the RFC 8785 hash of the exact `BundleRequirement` and requires equality with `record.requirementHash`. If the exact bundle is unavailable, the record MUST NOT be accepted as proof that a presence-only member passed; the reliance decision is `indeterminate` until the bundle is available. An invalid bundle presentation, hash mismatch, malformed claim/reference, invalid composite signature, or aggregation mismatch MUST cause rejection.

**Verification warnings (rules WN-1..WN-6).** The optional `warnings` array surfaces transient/retryable verification conditions encountered while producing the record — without changing the verification decision. Warnings are strictly advisory and orthogonal to the §7.7.1 aggregation:

- (WN-1) the presence of one or more warnings MUST NOT change `overallDecision`;
- (WN-2) warnings MUST NOT be used to convert a `pass` into a `fail` or vice versa;
- (WN-3) warnings MUST be preserved in the record even when `overallDecision` is `pass` (they document conditions a consumer may act on operationally, e.g. an authority that was rate-limited but answered on retry);
- (WN-4) `suggestedRetryAfterMs` is an advisory per-authority hint and does NOT override the recipe-level `backoff` (§7.4.1) or `retryBudget` (§7.6.1 VP-R1) — the recipe remains the governing retry policy and the warning only adds per-authority context;
- (WN-5) consumers SHOULD surface warnings to human operators when `overallDecision` is `indeterminate` (the warnings often explain *why* the answer was inconclusive);
- (WN-6) implementations MAY add implementation-specific `code` values but SHOULD prefer the enumerated v0.1 codes when applicable, and a consumer encountering an unknown code MUST treat it conservatively (as advisory, never as grounds to elevate or downgrade the decision — consistent with WN-1/WN-2).

The codes align with the §7.6.1 retry taxonomy: the five transient codes correspond to a VP-R1 retryable `error`, and `RETRY_EXHAUSTED` records that the VP-R1 budget was spent.

CCI-native reputation signals (cci-nomis, cci-ethos, cci-humanpassport) are first-class supplementary signal sources: they are read from the counterparty’s CCI without needing a separate attestation, because the underlying CCI context’s GCR routine has already validated them.

#### 7.7.1 Aggregation algorithm

A verifier MUST compute `overallDecision` per the following algorithm. A member's classifier is selected by `verificationRequired`: presence-only members are evaluated against the signed bundle under PCR-1..PCR-3, while verified members use the existing `VerifyResult` path under PCR-4. Mixed `required` and `oneOf` collections therefore compose the two modes without synthesising evidence. The algorithm distinguishes four cases for each member: passing, indeterminate (authority or required replay input unavailable), errored (malformed input or verifier failure), and failing/absent. Precedence among non-pass outcomes is failures > errors > indeterminates so that the strongest evidence dominates aggregation.

```
aggregate(record, recordRef, requirement, authority, recipeRegistryResolver):

  if authority.kind == "production":

    vetInput := authority.vetInput

    authenticatedSessionStart := authority.authenticatedSessionStart

    if authenticatedSessionStart is not the orchestrator-owned active `SessionContext` for record.jobId:

      return "error", ["authenticated session-start authority missing or mismatched"]

    if vetInput is missing or vetInput.jobId != record.jobId or vetInput.sessionContext is missing or vetInput.sessionContext.jobId != record.jobId:

      return "error", ["authenticated production context missing or mismatched"]

    if vetInput.sessionContext is not the authenticatedSessionStart context passed by the orchestrator:

      return "error", ["production session context is not authoritative"]

    if vetInput.recipeRegistryVersion != vetInput.sessionContext.recipeRegistryVersion:

      return "error", ["production recipe-registry pins disagree"]

    # The requirement is phase input, not an independently supplied aggregation argument.

    requirement := vetInput.requirement

    registryVersion := vetInput.sessionContext.recipeRegistryVersion

    exactBundle := vetInput.bundleToVet

  else if authority.kind == "replay":

    verifiedBundle := authority.bundle

    if verifiedBundle is not an `AttestationBundle` or `FaultAttestationBundle` whose canonical hash and required §10.4.1 signatures have been verified:

      return "error", ["authenticated replay bundle missing or invalid"]

    if verifiedBundle.jobId != record.jobId:

      return "error", ["replay bundle job mismatched"]

    if recordRef is missing or verifiedBundle.vetRecords does not contain recordRef:

      return "error", ["replay bundle does not bind this record"]

    if dereferencing recordRef does not yield record with a matching content hash and valid §7.7.2 signature:

      return "error", ["replay record reference invalid"]

    if sha256(CORE-canonical(requirement)) != record.requirementHash:

      return "error", ["replay claim requirement does not match record"]

    registryVersion := verifiedBundle.recipeRegistryVersion

    exactBundle := authority.resolvedIdentityBundle

  else:

    # In particular, the off-chain unsigned SessionRecord (§10.3.2) is not authority.

    return "error", ["aggregation authority missing or invalid"]

  # Strict bundle/requirement binding and presence-only evidence preflight
  # (PCR-1, PCR-3, PCR-6). Production uses vetInput.bundleToVet; replay must
  # independently resolve the same signed IdentityBundle bytes.

  if sha256(CORE-canonical(requirement)) != record.requirementHash: return REJECT_RECORD

  requiredMembers := requirement.required

  oneOfGroups := requirement.oneOf if present, otherwise []

  if requiredMembers is not an array OR oneOfGroups is not an array:

    return "error", ["malformed claim requirement collections"]

  if any group in oneOfGroups is not a non-empty array:

    return "error", ["malformed empty or non-array oneOf group"]

  claimRequirements := requiredMembers ++ flatten(oneOfGroups)

  if any cr in claimRequirements is not an object OR
     cr.verificationRequired is not exactly the JSON boolean true or false:

    return "error", ["invalid verificationRequired mode"]

  if any presence-only member carries maxAge or recipeVersion:

    return "error", ["invalid presence-only requirement"]

  if exactBundle unavailable: return "indeterminate", ["exact bundle unavailable"]

  if exactBundle presentation invalid: return REJECT_RECORD

  if sha256(dacs1_bundle_canonical_form(exactBundle)) != record.bundleHash: return REJECT_RECORD

  if any BundleClaim.verifiedBy is present but not a well-formed VerifyResultRef:

    return "error", ["malformed verification reference"]

  # Every CVR VerifyResultRef must be attributable to at least one verified
  # member. Presence-only members add no references and never invoke a recipe.

  if any record result reference is attributable only to presence-only members: return REJECT_RECORD

  verifiedMembers := [cr for cr in claimRequirements
                      if cr.verificationRequired == true]

  registry := recipeRegistryResolver.resolve_authenticated(registryVersion)

  if registry is unavailable or invalid:

    return "error", ["session-pinned recipe registry unavailable or invalid"]

  # Resolve every decision-bearing family/version and any required rerun before
  # classifying any member. A registry error therefore cannot fall through to
  # "constraints not satisfied" or be masked by a separately failing member.

  qualificationContexts := {}

  for cr in verifiedMembers:

    context := preflight_qualification(record, cr, registry)

    if context is error:

      return "error", [context.reason]

    qualificationContexts[cr] := context

  # Verified-member helpers below use this authenticated aggregation-scoped
  # registry and the requirement-scoped, preflighted result views.

  failures := []

  errors := []

  indeterminates := []

  # Every required member must pass in its selected mode.

  for cr in requiredMembers:

    outcome := classify_member(record, exactBundle, cr)

    if outcome == "fail": failures.append("required failing or absent: " + cr.scheme)

    else if outcome == "error": errors.append("required errored: " + cr.scheme)

    else if outcome == "indeterminate": indeterminates.append("required indeterminate: " + cr.scheme)

  # oneOf groups must each contain at least one passing

  for group in oneOfGroups:

    outcomes := [classify_member(record, exactBundle, cr) for cr in group]

    if not any(outcome == "pass" for outcome in outcomes):

      # A oneOf group is satisfied iff ≥1 member passes (OR within the group).
      # When none pass, classify the group by whether it could STILL be satisfied.
      # Precedence WITHIN a oneOf group is error > indeterminate > fail — deliberately
      # the OPPOSITE of the required-claim/global precedence (fail > error > indeterminate):
      # in an OR group an applicable retryable error or pending indeterminate alternative
      # means the group is NOT yet conclusively unsatisfiable, so it MUST NOT be reported
      # as a hard fail. A result outside the member's pinned version or age bound is not
      # current evidence for that member and does not participate. Only when every member
      # hard-fails or lacks a qualified current result is the group a conclusive fail.

      if any(outcome == "error" for outcome in outcomes):

        errors.append("oneOf group: at least one claim errored")

      else if any(outcome == "indeterminate" for outcome in outcomes):

        indeterminates.append("oneOf group: at least one claim indeterminate")

      else:

        failures.append("oneOf group: no claim satisfied")

  # The composite decision covers the complete BundleRequirement, not only its

  # member sets. Apply DACS-1 MA-2/MA-3 and PCR-5 to the exact presentedBy claim,

  # using exact-claim verified evidence in this record where verification is required.

  if requirement.primaryClaimSelector is set AND

     NOT exact_selector_authorized(record, exactBundle, requirement):

    failures.append("primaryClaimSelector is mismatched, uncontrolled, or unauthorized")

  # Cross-accumulator precedence (across ALL required claims and oneOf groups): failures > errors > indeterminates.
  # This is fail-first because a single hard-failed REQUIRED claim dooms the whole requirement (AND), regardless of
  # any retryable oneOf group. (It is distinct from the within-a-oneOf-group precedence above, which is error-first.)

  if failures: return "fail", failures

  if errors: return "error", errors

  if indeterminates: return "indeterminate", indeterminates

  return "pass", []

classify_member(record, exactBundle, cr):

  if cr.verificationRequired == false:

    # Apply DACS-1 PCR-1..PCR-3 to exactBundle. A matching canonical, unexpired,

    # parameter-conforming claim passes. Missing/expired/mismatched is fail.

    # Malformed configuration or ref is error. issuedAt and the decision,

    # freshness, or availability of a well-shaped verifiedBy do not affect this outcome.

    return classify_presence(exactBundle, cr)

  # Apply the existing result resolution, recipe/version, identifier, decision,

  # freshness/maxAge, parameter, disabled/mock method, and retry classifiers.

  return classify_verified_member(record, cr)

exact_selector_authorized(record, exactBundle, requirement):

  selector := requirement.primaryClaimSelector

  oneOfGroups := requirement.oneOf if present, otherwise []

  if selector is absent: return true

  if canonical_scheme(exactBundle.presentedBy) != selector: return false

  presented := the claim in exactBundle.claims whose canonical ClaimReference
               equals exactBundle.presentedBy

  if presented is absent: return false

  controlled := the exact presented claim passes DACS-1 §6.3.2 step (6)

  # `verifiedSelector` is exact-claim evidence only. It passes only when the
  # record commits presented.verifiedBy and the independently resolved result
  # passes hash, signature, identifier, recipe/version, decision, and freshness
  # checks for `presented`; another same-scheme claim cannot supply it.

  verifiedSelector := presented has a record-committed passing-and-fresh
                      verifiedBy under the DACS-1 §6.3.2 verified-claim gate

  exactPresenceMembers := [cr for cr in requirement.required ++ flatten(oneOfGroups)
                           if cr.scheme == selector
                           and cr.verificationRequired == false
                           and classify_presence(exactBundle, cr,
                                                 exactClaimRef := presented.ref) == "pass"]

  presenceSelector := exactPresenceMembers is not empty

  if any required member has scheme == selector and verificationRequired == true:

    presenceSelector := false

  for group in oneOfGroups where any member has
      scheme == selector and verificationRequired == true:

    exactPresenceInGroup := any cr in group where cr.scheme == selector
                            and cr.verificationRequired == false
                            and classify_presence(exactBundle, cr,
                                                  exactClaimRef := presented.ref) == "pass"

    passingOtherScheme := any cr in group where cr.scheme != selector
                          and classify_member(record, exactBundle, cr) == "pass"

    if NOT (exactPresenceInGroup OR passingOtherScheme):

      presenceSelector := false

  return controlled AND (verifiedSelector OR presenceSelector)

preflight_qualification(record, cr, registry):

  scopedResults := find_all_results(record, cr.scheme)

  selectedMethods := {cr.parameters.verificationMethod} when present, otherwise the distinct r.method values in scopedResults

  for selectedMethod in selectedMethods:

    if selectedMethod is missing or its exact `(cr.scheme, selectedMethod)` family cannot be resolved:

      return error("selected recipe family unavailable or invalid")

    expectedVersion := cr.recipeVersion when present, otherwise registry.latest_version(cr.scheme, selectedMethod)

    selectedRecipe := registry.resolve_exact(cr.scheme, selectedMethod, expectedVersion)

    if expectedVersion is missing or selectedRecipe cannot be resolved:

      return error("effective recipe version unavailable or invalid")

    if cr.recipeVersion is absent and selectedRecipe.availability != "live":

      # Do not fall back to an older live version: the latest exact-family entry
      # is the decision-bearing session pin.

      return error("implicit latest recipe version is not live")

    if cr.recipeVersion is present and selectedRecipe.availability in {"mocked", "disabled", "failed"}:

      return error("explicit recipe version is non-operational")

  for r in scopedResults:

    if r came from another session and r.decision != "pass":

      if authenticated cache provenance does not establish CORE-canonical equality of the complete originating and consuming cr.parameters predicates:

        replace r in scopedResults with a newly executed result from the selected recipe under the consuming predicate

        if no authenticated current result is obtained:

          return error("non-pass cache entry requires current-predicate execution")

  return {results: scopedResults, expectedVersionByMethod: the versions resolved above}

classify_verified_member(record, cr):

  same_scheme := qualificationContexts[cr].results   // authenticated, resolved freshness ++ dealSpecific results after VP-C1 reuse handling; supplementary signals NOT included

  if same_scheme is empty:

    return "fail"

  results := find_applicable_results(record, cr)

  if results is empty:

    return "fail"

  if any(r.decision == "pass" and parameters_match(r, cr) for r in results):

    return "pass"  // claim satisfied

  if any(r.decision == "pass" and not parameters_match(r, cr) for r in results):

    return "fail"

  if any(r.decision == "fail" for r in results):

    return "fail"

  if any(r.decision == "error" for r in results):

    return "error"

  // remaining results are "indeterminate"

  return "indeterminate"

find_qualified_pass(record, cr):

  return any(r.decision == "pass" and parameters_match(r, cr) for r in find_applicable_results(record, cr))

find_applicable(record, cr, decision):

  return any(r.decision == decision for r in find_applicable_results(record, cr))

find_applicable_results(record, cr):

  results := qualificationContexts[cr].results

  return [r for r in results if ALL applicable constraints hold]:

    1. selectedMethod := cr.parameters.verificationMethod when present, otherwise r.method; r.method MUST equal selectedMethod

    2. expectedVersion := qualificationContexts[cr].expectedVersionByMethod[selectedMethod]; r.recipeVersion MUST equal this already-resolved exact-family pin (§7.4.3)

    3. if cr.maxAge is present, record.generatedAt <= r.verifiedAt + cr.maxAge * 1000 (the additional listing-declared VP-C3 bound; seconds converted to milliseconds; it cannot widen the governing §6.3.2 / §7.6.1 freshness window)

parameters_match(r, cr):

  if cr.parameters is absent: return true

  require cr.parameters.verificationMethod, when present, to equal r.method

  return r.data contains every other own key in cr.parameters and each corresponding value is equal under CORE canonical JSON (§7.6 step 7); additional r.data keys do not disqualify the result
```

(CRQ-1) `find_all_results` and `find_applicable_results` operate only on `VerifyResult` objects whose references, hashes, signatures, recipe authority, attestations, and governing §6.3.2 / §7.6.1 freshness windows have already passed their checks. Before classification, the verifier MUST bind the composite record and registry pin to authenticated authority for the same `jobId`. During production the authority is the orchestrator-owned active `SessionContext` supplied at the CORE §B.5 phase-handler boundary, not a caller-deserialised assertion. The required `VetCredentialsInput.sessionContext` MUST be that context; `VetCredentialsInput.jobId` and `sessionContext.jobId` MUST equal `record.jobId`; and its separate `recipeRegistryVersion` MUST exactly equal `sessionContext.recipeRegistryVersion` before registry resolution. Production aggregation MUST use the exact `VetCredentialsInput.requirement` carried at that phase boundary; a separately supplied aggregation projection is not an input and cannot substitute for it. This execution binding fixes the bytes evaluated and later covered by `requirementHash`; it does not by itself authenticate who authored or accepted a complementary non-Listing requirement. A producer or ST-11 auditor MUST NOT treat the phase input, Composite signature, or `requirementHash` as proof of that requirement's cross-party provenance. During replay or later consumption the authority is a cryptographically verified, signed `AttestationBundle` or `FaultAttestationBundle`: its `jobId` MUST equal `record.jobId`, its `vetRecords` MUST contain the exact `AttestationRef` being aggregated, and that reference MUST dereference to the same hash- and signature-verified §7.7.2 record. The CORE-canonical hash of the `BundleRequirement` being aggregated MUST equal that signed record's `requirementHash`. Every projected result participating in aggregation MUST be obtained by dereferencing a `VerifyResultRef` committed by that record and validating its content hash and signature. The resolved set MUST correspond one-to-one with the complete ordered union of the record's `freshness` and `dealSpecific` references: no committed reference may be omitted, duplicated, or replaced, and no uncommitted result may be introduced. (`supplementary` contains `SupplementarySignal` values, not `VerifyResultRef` values, and remains outside this result-resolution set.) Caller-supplied requirements or result projections cannot substitute for authenticated bytes. Replay derives the registry pin only from the verified bundle's `recipeRegistryVersion`. An unsigned `SessionRecord` MUST NOT supply replay authority. A standalone record, a missing or mismatched production input, a production pin mismatch, a missing/invalid/substituted replay bundle, record reference, requirement, or result projection, or a missing, invalid, or unresolvable registry snapshot fails aggregation closed as `error`. A consumer MUST NOT infer the registry version from the record, an unsigned session record, or current registry state. The `ClaimRequirement.maxAge` predicate is an additional listing-declared bound and cannot widen that baseline window. A result-resolution failure retains its existing rejected or `indeterminate` disposition and MUST NOT be converted into an applicable result.

(CRQ-2) A verifier MUST derive one effective recipe family and expected version for every candidate result under a `ClaimRequirement`. The family is `(cr.scheme, cr.parameters.verificationMethod)` when the listing selects a method, otherwise `(cr.scheme, r.method)` from the authenticated evidence. If the listing selects a method, `r.method` MUST equal it. The expected version is the explicit `cr.recipeVersion` when present, otherwise the exact latest version for that family in the authenticated registry snapshot selected by CRQ-1's production or replay authority. Every selected family and explicit or implicit version MUST resolve before any requirement is classified. Missing family metadata, an absent explicit version, or an absent implicit latest version returns `error`; it MUST NOT become an empty applicable set or a counterparty `fail`. If the implicit latest entry is not `live`, aggregation returns `error` and MUST NOT fall back to an older live version. An explicit version is checked under RAV-1 through RAV-4. Once this preflight succeeds, the verifier applies method and exact-version equality plus age qualification before a result participates in decision classification. An omitted `ClaimRequirement.recipeVersion` therefore does not disable family-aware version qualification. A `pass` additionally satisfies its `ClaimRequirement` only when `parameters_match` is true; `verificationMethod` is matched against `r.method`, while every other required parameter is matched against authenticated `r.data`. A missing authenticated parameter value therefore makes that `pass` a constraint failure. An applicable current-session `error` or `indeterminate` retains its decision without requiring extracted data that the unsuccessful or inconclusive verification may not have produced; VP-C1 separately prevents an unbound cross-session non-pass from carrying a predicate-sensitive decision into this set. A result outside the selected method family, resolved effective recipe version, or age bound is not current evidence for that requirement and does not participate, regardless of its decision. `verificationRequired` remains the DACS-1 policy controlling whether verification is required; it does not create a field on `VerifyResult`.

(CRQ-3) Multiple requirements using the same scheme are evaluated independently. A passing result qualified for one requirement MUST NOT satisfy another requirement whose recipe-version, age, or parameter constraints it does not satisfy.

(CRQ-4) Required-claim and `oneOf` aggregation MUST use applicable results and qualified passes as defined above. Qualification does not change the decision of an applicable result. If only non-applicable results exist after successful family/version preflight, aggregation reports the requirement or group as unsatisfied; this is not a reclassification of those excluded results. An unresolved family/version or non-live implicit latest fails that preflight as `error` before either precedence ladder runs. Within the applicable set, the existing four-value semantics and both precedence orders are unchanged.

Supplementary signals MUST NOT change overallDecision from pass to fail automatically; they are informational. A listing MAY declare in terms that specific signals are gating (e.g. minimum reputation score); when so declared, the gating check is treated as a deal-specific claim and runs through the same aggregation. Five required-claim diagnostic reasons carry distinct value: "required not present" (no same-scheme VerifyResult exists), "required constraints not satisfied" (same-scheme results exist but none meets the pinned version and age constraints, or a current `pass` fails parameter matching), "required failing" (an applicable authority result said no), "required indeterminate" (an applicable authority result answered ambiguously), and "required errored" (an applicable verifier result could not reach authority). Consumers debugging or auditing a failed session can read the failure reasons to determine which class the failure belongs to.

A producer MUST set `record.overallDecision` to the algorithm's result. A strict consumer MUST independently run the same algorithm, dereference and content-hash-check every `VerifyResultRef` used by a verified member, and reject the record if the recomputed result differs from the signed `overallDecision`. An optional failing, stale, or unavailable `verifiedBy` on a presence-matched claim is not dereferenced for that member and cannot turn its presence pass into another decision. Conversely, a presence pass cannot satisfy a `verificationRequired = true` member, establish control, or elevate DACS-1 `identityTier`.

#### 7.7.2 Anchoring and signature

- **Anchor.** The composite record MUST be anchored via SR-2 at address `dacs2:composite:{jobId}:{evaluatedParty}` (or substrate equivalent). `{evaluatedParty}` is a ClaimReference and a CF-4 variable segment, so it MUST be percent-encoded before assembly (CORE §B.1).
- **Record.** The anchor reference is recorded in the DACS-5 session record.
- **Sign.** The composite record’s signature MUST be produced by the verifier (the party running Vet on the counterparty) over the domain-separated payload per §B.7:

signed_bytes := "dacs-composite:v1:" || composite_hash
In v0.1, the composite record carries a single verifier signature. Multi-party composition (e.g., two-sided independent Vet records cross-referenced into one) is deferred to v2.

### 7.8 The vet-credentials phase

```
type VetCredentialsInput = {
  jobId: string
  actor: "buyer" | "seller"
  bundleToVet: IdentityBundle
  requirement: BundleRequirement
  verifierIdentity: IdentityBundle
  sessionContext: SessionContext
  recipeRegistryVersion: number
  attempt: number
}
type VetCredentialsOutput = PhaseHandlerResult & {
  contextDelta: {
    "vet-credentials": {
      compositeRecord: AttestationRef
      overallDecision: "pass" | "fail" | "indeterminate" | "error"
    }
  }
}
```

#### 7.8.1 Phase contract

The orchestrator MUST:

- (VPC-1) invoke vet-credentials after a successful Identify stage and before any Negotiate phase requiring a verified bundle;
- (VPC-2) invoke vet-credentials **once per party** — each party's bundle is vetted against the *counterparty's* requirements:
  - the buyer’s bundle against listing-side requirements on buyers, and
  - the seller’s bundle against buyer-side requirements on sellers —

  each invocation producing its own CompositeVerificationRecord (the input carries a single `bundleToVet` + `actor`), before Negotiate;
- (VPC-3) submit the composite record for anchoring and, before returning `ok: true`, obtain a verified CORE §5.1 receipt at `accepted` or later and return that receipt as `anchorReceipt`. The phase MAY therefore permit reversible progression into Negotiate on binding-defined durable admission. A submission or ordinary RPC/broadcast acknowledgement is insufficient. If the substrate binding exposes no verifiable durable `accepted` state, the handler MUST wait for `included` or `finalized`;
- (VPC-4) on `overallDecision != "pass"` (after permitted retries), MUST fail the phase with `errorClass` derived from the overall decision:

  | overall decision | `errorClass` (fault attribution) |
  | --- | --- |
  | `fail` | counterparty |
  | `indeterminate` / `error` | permanent |
  | *except* an `error`/`indeterminate` whose sole proximate cause is a presentation the counterparty supplied that the verifier could not parse in its declared format | counterparty (§7.8.2) |

- (VPC-5) when VPC-3 returns before `finalized`, retain a durable idempotent reconciliation keyed by the record's logical address and content hash. It MUST resume observation of the same transaction (or a binding-valid replacement), MUST NOT create a second logical record, and MUST surface an established `dropped`, `replaced`, `expired`, or `reorged` state—or an `indeterminate` observation disposition over the preserved state—rather than treating the record as final. After authenticated `dropped`, `expired`, or `reorged`, the handler MAY resubmit the **identical canonical record bytes** under the same logical address and content hash when the binding supports readmission; the new transaction/native binding MUST be published and verified through a new receipt. It MUST NOT resubmit merely because observation is `indeterminate`, and MUST follow a `replaced` receipt only by independently verifying the named replacement. Reconciliation never repeats credential verification or changes the composite decision. DACS-5 §10.4.3 forbids terminal bundle production until the composite record has a verified `finalized` receipt and is independently resolvable.

This affects fault attribution only; the overall decision is unchanged. By the point VPC-4 is evaluated the retry budget is already exhausted (`indeterminate` MUST NOT be retried at all per VP-R4; `error` is retried only while budget remains), so the *phase-overall* outcome is terminal: the `transient` class applies to in-flight retries, never to the phase-fail result. This matches the §7.8.2 cause table (`indeterminate`/`error` after retry-budget exhaustion → permanent).

#### 7.8.2 Error classification and idempotency

| Error class | Cause | Retry? |
| --- | --- | --- |
| transient | Substrate temporarily unavailable; authority HTTP 5xx | Yes (per VP-R1) |
| permanent | Bundle malformed/unparseable; or `indeterminate`/`error` after retry-budget exhaustion (per recipe.retryClass) | No |
| counterparty | Counterparty fails to present a required claim, OR a required claim returns `decision=fail` (the authority conclusively rejected the counterparty's claim) | No (Vet fails; counterparty marked at-fault) |
| substrate | SR-2 or SR-3 unavailable for sustained period | Pause session per DACS-5 |

**VPC-4 is the authoritative cause→class mapping; this table enumerates causes consistent with it, not an independent rule.**

- A required claim returning `decision=fail` maps to **counterparty** (per VPC-4: `"fail" → counterparty`) — it is the counterparty's claim that the authority rejected, so it is never `permanent`.
- `permanent` is reserved for self-caused or structural failures (a malformed/unparseable bundle on the verifier/local side) and for `indeterminate`/`error` outcomes that exhaust their retry budget for non-counterparty reasons.
- **However, when the error/indeterminate is solely caused by a presentation the COUNTERPARTY supplied that the verifier could not parse in its declared format — an observable provenance (counterparty-supplied bytes that fail to parse) — the class is `counterparty`, not `permanent`**: the counterparty malformed its own claim, mirroring `decision=fail → counterparty`. This notably covers a `oneOf` group classified `error`/`indeterminate` only because the counterparty malformed one alternative while another conclusively failed (a credential-less counterparty must not escape the counterparty fault by malforming an alternative).
- This carve-out affects **fault attribution only** — the overall decision and the within-a-oneOf-group decision precedence (error > indeterminate > fail, §7.7.1) are unchanged.
- Because the class is fully determined by the decision/cause, an orchestrator has no discretion to steer a self-caused `fail` away from the counterparty fault bucket, nor to steer a counterparty-malformed `error` into the self/`permanent` bucket (§10.5.1).

Re-running vet-credentials with the same inputs MUST produce the same composite-record content modulo the volatile fields refreshed against current state — `generatedAt`, each VerifyResult's `fetchedAt`/`verifiedAt`, and supplementary signals' `observedAt`/`value`. The orchestrator MUST NOT double-anchor; the reuse/no-change test is over the **stable** content (the freshness/deal-specific VerifyResultRefs + decisions, excluding those volatile timestamp/value fields), so an unchanged authority state reuses the existing anchor.

### 7.9 Conformance summary

| Role | Requirements |
| --- | --- |
| Method implementer | CM-1 through CM-5 |
| Recipe author | RA-1 through RA-6; PRA-1 through PRA-5; PSP field semantics (§7.4.1) when declaring a ParserSpec |
| Recipe-availability consumer | RAV-1 through RAV-4 |
| Recipe steward (availability & governance) | RAV-5 through RAV-7; GOV-2; PA-1 through PA-3 |
| Verifier (orchestrator) | VP-R1 through VP-R4; VP-C1 through VP-C3; VPC-1 through VPC-5; PCR-1 through PCR-6; PRA-3 through PRA-5; PSP-1 through PSP-5; WN-1 through WN-4 |
| VerifyResult consumer | §7.5.2 attestation resolution; recipe-version pinning; WN-5, WN-6; GOV-3 |
| Composite record reader | §7.7.1 mixed-mode aggregation; CRQ-1 through CRQ-4; exact bundle/requirement hash replay; signature validation; PCR-6 no-synthetic-result boundary |

### 7.10 Rationale

**Method-pluggable registry vs single method.** No single approach fits every credential (cooperative-issuer → W3C VC; private-data → zkTLS; public-registry → consensus-backed proxy). The registry routes by type; the stack consumes a uniform `VerifyResult`.

**Closed method set vs open.** An open registry makes conformance untestable (a verifier could declare an arbitrary method producing unvalidatable results). v0.5 ships nine methods covering the established attestation patterns; new ones come via the steward's acceptance process, as in DACS-1.

**Recipe-family-per-scheme vs general-purpose protocol.** A general-purpose fetch endpoint would lose the structured parser rules, success-criterion semantics, and negative-match pattern recipes encode. Recipes are small, family-scoped within a scheme, and capture each authority's messy response format.

**Composite record vs per-claim records.** The stack references *one* Vet artifact, not N. The composite record composes, signs, and anchors once instead of forcing every consumer to walk a list.

**SR-3 dependency for consensus-backed-proxy.** Substrate-agnostic alternatives (single proxy / MPC TLSNotary) exist as separate registry methods but cost more per verification. For high-volume public-registry verification — the bulk of institutional Vet — consensus-backed proxy at chain rate is the right tool; the dependency is explicit and opt-in per recipe.

**Single-verifier signature on the composite record.** Each side runs Vet on the other and produces its own record; v0.1 carries one signature per record. Mutual-Vet multi-party composition is deferred.

**Reputation as supplementary signal, not a hard gate.** Reputation has no authoritative source; as a hard gate it would lock new sellers out of the market. It is surfaced to the verifier (and optional listing gating) but does not by default block engagement.

### 7.11 Backwards compatibility

**W3C Verifiable Credentials.** A recipe MAY declare `verifiable-credential` as its method; the verifier accepts a W3C VP per VC data model 2.0. Recipe authors SHOULD set `issuerAllowList` where only specific issuers are trusted (e.g. a `kyc-tier` recipe allow-listing specific KYC providers).

**TLSNotary.** A recipe MAY declare `tlsnotary`; the notary signature anchors as part of `AttestationRef`. Compatible with the PSE 2024 rebuild and later.

**zkTLS / Reclaim / Pluto.** A recipe MAY declare `zktls` and select a provider whose circuit / verification-program id determines the check. Compatible with Reclaim's production verifier contracts and equivalent providers shipping a circuit description.

**ERC-8004.** `erc8004`-scheme recipes use `evm-rpc` to read token ownership via proxy-attested call. DACS-2 results MAY additionally be published to ERC-8004 reputation/validation registries via DACS-5; DACS-2 itself does not write there.

**ACME / Let's Encrypt.** The `domain-tls-control` method follows ACME's challenge/response (RFC 8555); implementations MAY reuse existing ACME libraries.

### 7.12 Security considerations

**Method substitution.** *Threat:* a verifier uses a weaker method than the recipe declares. *Mitigation:* the VerifyResult.method field MUST be the method actually executed; consumers compare to the recipe’s defaultMethod and alternatives and reject results that used an unaccepted method. Recipes SHOULD list only equivalent alternatives.

**Recipe poisoning.** *Threat:* a compromised recipe registry returns incorrect parsing rules, causing every verification using that recipe to mis-classify outcomes. *Mitigation:* recipes are signed by the registry steward (currently KyneSys Labs, per §7.4.4); consumers MUST verify the signature. Recipe recipeVersion is monotonic and pinned per session; an attacker compromising the registry tomorrow does not retroactively change recipes used in already-pinned sessions. Steward-key compromise is the principal residual risk under the current PA-2 single-signer phase; multi-signature governance (PA-3) is the v0.2+ mitigation pathway.

**Replay of VerifyResult across sessions.** *Threat:* a verifier reuses a stale or predicate-specific VerifyResult from a different session or counterparty. *Mitigation:* the VerifyResult.identifier MUST match the claim under verification canonically; consumers verify the match. The composite record’s bundleHash and evaluatedParty bind the current aggregation to a specific bundle. VP-C1 cache eligibility does not imply CRQ applicability: a cached `pass` is requalified under the consuming method, version, age, and parameters; a cached non-pass requires authenticated exact originating-parameter equivalence or a new execution under the consuming predicate. Because `VerifyResult` v1 carries no originating predicate, the artifact alone cannot authorize cross-session non-pass reuse.

**TOCTOU: authority state changes between fetch and use.** *Threat:* a counterparty’s authority status changes between Vet and the actual transaction execution. *Mitigation:* listings handling time-sensitive flows SHOULD set ClaimRequirement.maxAge aggressively (e.g., 60 seconds for OFAC clearance on a real-money trade). Sessions with long latency between Vet and Settle SHOULD re-run Vet at Settle time for the most stake-sensitive claims.

**Substrate validator capture (SR-3).** *Threat:* a majority-corrupt substrate validator set forges responses, causing consensus-backed-proxy and evm-rpc methods to attest to false facts. *Mitigation:* the substrate’s consensus model is the trust floor; DACS-2 inherits whatever security properties the substrate provides. For credentials where this risk is unacceptable, recipes SHOULD declare **alternative independent methods** (the recipe `alternatives` mechanism, §7.4) so a high-stakes claim can additionally be verified by an independent method (e.g. tlsnotary or zktls) rather than relying on consensus-backed-proxy alone. Note the scope of what v0.1 composes: **cross-claim AND** — a listing requiring several distinct verified claims, all of which MUST pass — is already enforced (§6.3.3 `BundleRequirement.required`, "all MUST be satisfied"), and is how a real vet stacks GLEIF + OFAC + reputation. What v0.1 does **not** define is a single-claim multi-method-**AND** combinator (verifying the *same* claim by two methods that MUST both pass): §7.7.1 aggregation composes multiple VerifyResults for one claim but has no `requireAll` semantics, and no such flag is defined on the Recipe. Single-claim multi-method-AND is a roadmap item; v0.1 high-stakes recipes use alternatives (additional independent methods) plus cross-claim required-set AND.

**W3C VC issuer compromise.** *Threat:* the signing key of a VC issuer is compromised, causing all VCs signed by that issuer to be untrustworthy. *Mitigation:* recipes SHOULD set issuerAllowList and check issuer revocation registries (where available, e.g., W3C VC Status List 2021). Issuers SHOULD rotate keys regularly. Consumers of historical VerifyResults SHOULD check whether the issuer was known-compromised at the time of verification.

**TLSNotary notary collusion.** *Threat:* the notary colludes with the prover to attest to false TLS sessions. *Mitigation:* TLSNotary’s MPC ensures the notary cannot see plaintext but does require honesty about the commitment. Recipes using tlsnotary SHOULD specify a known-good notary public key in the recipe; multi-notary patterns are a future extension.

**zkTLS proxy compromise.** *Threat:* the zkTLS provider’s proxy attests to false TLS responses. *Mitigation:* recipes select specific providers and program IDs. Compromise of a provider’s proxy invalidates all results from that provider; consumers SHOULD treat results from a known-compromised provider as invalid retroactively.

**Supplementary signal poisoning.** *Threat:* false reputation data is injected (e.g. a Sybil network creating fake successful completions). *Mitigation:* DACS-5 specifies the reputation derivation; supplementary signals from DACS-5 inherit DACS-5’s anti-Sybil properties. Supplementary signals from external sources MUST carry an AttestationRef; consumers MAY decline to weigh signals from sources they do not trust.

**Identifier canonicalisation gaps.** *Threat:* the same logical identifier in two different forms produces two different VerifyResult lookups or two different reputation keys, allowing an attacker to substitute or to split/launder reputation. *Mitigation:* the canonical-form rules CF-1 (NFC, §B.2), CF-2 (ClaimReference canonical byte form), and CF-3 (canonical identity = canonical scheme + identifier, parameters excluded), plus any per-scheme identifier rule, are normative. Verifiers MUST canonicalise per CF-1/CF-2 before issuing a VerifyResult, and consumers MUST compare per the CF-3 identity before lookup, reputation keying, or the §7.3.2 replay check.

**Composite record forgery.** *Threat:* an attacker constructs a composite record with overallDecision = "pass" and false VerifyResultRefs. *Mitigation:* the composite record is signed by the verifier; consumers verify the signature. The `bundleHash` and `requirementHash` fields bind the record to the exact inputs evaluated; consumers verify these against the inputs they actually used. Those hashes do not authenticate who authored or accepted a complementary requirement, and MUST NOT be presented as the separate cross-party provenance needed by a recursive audit. Each VerifyResultRef MUST be dereferenced and content-hash-validated before the composite record is accepted.

**Synthetic presence verification or bundle substitution.** *Threat:* an attacker fabricates a passing `VerifyResult` for a presence-only requirement, or replays a passing composite record beside a different bundle whose claim is missing or expired. *Mitigation:* PCR-6 forbids presence-only result references and requires strict consumers to verify the composite signature, the exact signed bundle presentation, `bundleHash`, `requirementHash`, and the independently recomputed mixed-mode decision. The residual availability risk is explicit: without the exact bundle, reliance remains `indeterminate` rather than failing open.

**Indeterminate-decision exploitation.** *Threat:* an attacker arranges for a required claim’s verification to fail in a way that returns indeterminate rather than fail, hoping consumers treat the result as pass. *Mitigation:* indeterminate is not pass. The aggregation algorithm treats indeterminate in a required position as overall indeterminate, which MUST fail the phase.
