# Glossary index

This non-normative index maps commonly referenced DACS terms to their canonical specification sections. The full glossary is [Chapter 13](../spec/GLOSSARY.md) (informative; per-chapter definitions are normative).

| Term | Primary spec section | Notes |
|------|----------------------|-------|
| Anchor / Anchored | [§5 / SR-2](../spec/CORE.md#5-substrate-capabilities), [§12.5](../spec/THREAT-MODEL.md#125-composite-trust-property) | Stored with content integrity via substrate anchoring. |
| AttestationBundle | [§10.4](../spec/DACS-5-VERIFY.md#104-attestation-bundle) | End-of-session DACS-5 audit artifact. |
| AttestationRef | [§B.5](../spec/CORE.md#b5-shared-phase-handler-types) | Reference to anchored evidence plus content hash. |
| BundleParty | [§10.4](../spec/DACS-5-VERIFY.md#104-attestation-bundle) | Party entry inside an AttestationBundle. |
| Canonical form | [§B.7](../spec/CORE.md#b7-universal-signature-scheme-domain-separated-signing) | RFC 8785 / JCS form used for hashes and signatures. |
| ClaimReference | [§B.1](../spec/CORE.md#b1-claim-references-and-identity) | Canonical identifier format for identity claims. |
| CompositeVerificationRecord | [§7.7](../spec/DACS-2-VET.md#77-composite-verification-record) | DACS-2 composite output for Vet. |
| IdentityBundle | [§6.3.2](../spec/DACS-1-IDENTIFY.md#632-identity-bundle) | Ordered self-presented claim set with presentation signature. |
| Listing | [§6.3](../spec/DACS-1-IDENTIFY.md#63-specification) | DACS-1 signed service advertisement. |
| Listing reachability | [§6.3.4](../spec/DACS-1-IDENTIFY.md#634-service-listing) | Time-stamped operational engagement status, not cryptographic validity. |
| Payment rail | [§9.4](../spec/DACS-4-SETTLE.md#94-payment-rail-registry) | Registry entry describing a supported payment path. |
| PayloadAttestationRecord | [§9.6.3](../spec/DACS-4-SETTLE.md#963-deliver-attested-payload) | DACS-4 exact-payload and commerce-binding wrapper around method-native evidence. |
| RatingRecord | [§10.6](../spec/DACS-5-VERIFY.md#106-the-rate-phase-optional) | Optional per-direction counterparty rating artifact. |
| SettlementEvidence | [§9.7](../spec/DACS-4-SETTLE.md#97-settlement-evidence) | Anchored DACS-4 evidence produced by settle/deliver phases. |
| VerifyResult | [§7.5](../spec/DACS-2-VET.md#75-verifyresult) | DACS-2 single-method verification result. |

## Maintenance notes

- Keep this file additive and non-normative.
- If a term definition changes, update the linked spec section rather than paraphrasing new semantics here.
- Run `python3 scripts/validate-docs.py` after editing anchors.
