TITLE: fix(DACS-1/DACS-2): canonical `domain:` claim ref + `demos-gcr-domain` recipe (#275)

References #275 — does NOT close it (see "Blocking follow-up" below).

## What this does (per steward ruling, issuecomment-5189615932)

DACS-2 → v0.4:
- New `VerificationMethod` union member `demos-gcr-domain` (§7.4.1) — config only
  (`gcrContext`, `proofPathTemplate`).
- New method subsection §7.3.10: `DemosGCRResultRef` + `DemosGCRDomainMethodInput`
  + procedure. Consumes the consensus-recorded GCR `web2.domain` result (no
  refetch), recomputes the host/account binding to `dacs-domain:v1:<host>:<ed25519Address>`.
- §7.4.2 `domain` default method → `demos-gcr-domain`, superseding the prior
  `domain-tls-control` recipeVersion (still pinnable). First in-document recipe
  supersession; mirrors the DACS-4 rail `supersedes` pattern.

DACS-1 → v0.6:
- `domain:<lowercase-IDNA-host>` is the sole canonical DNS-domain claim ref.
- `web2:domain:<host>` is a permanent read alias resolved to an effective
  `domain:` reference before matching (three-layer resolution; original signed
  bytes verified first, never rewritten/re-hashed).
- §6.3.2 step-4 identifier match runs against the effective ref.
- §6.3.3 semantic-claim dedup + ordered greedy `oneOf` consumption.

DEMOS-MAPPING §A.1: `web2.domain` source-representation paragraph. Fixture:
`identity-bundle.json` claim `web2:domain:alice.example` -> `domain:alice.example`.

## Executed (vectors), not just reported

Two CI-auto-discovered runners, fail-closed on skip:
- `tests/test_domain_claim_canonicalization_vectors.py` +
  `conformance/fixtures/identity/domain-claim-canonicalization.json` — V1/V2/V5,
  nine mutation-pinned hostname guards, and the identity-bundle example guard.
- `tests/test_domain_claim_bundle_semantics_vectors.py` +
  `conformance/fixtures/identity/domain-claim-bundle-semantics.json` — V3 (original-
  byte sig/hash preservation), V4 (dedup + `oneOf`), V6 (host/account mismatch),
  V7 (indeterminate vs error), V8 (proof metadata), V9 (persistent-not-fresh).

Mutation-pin map (guard -> the single vector it kills): C1 reject-oversize-label;
C3 reject-leading-hyphen; C4 reject-trailing-dot; C6 reject-underscore; C7
reject-uppercase; C8 reject-non-ascii; C10 reject-malformed-xn--; C11
reject-ipv4-literal; C12 reject-all-numeric-labels.

## Load-bearing arguments (stated, not left to review silence)

- Union-member minor-safety, scoped: a new `kind` is dispatched at the
  discriminator, so a conforming older reader applies CORE §11.1.2 new-type
  refusal; a reader without the unknown-`kind` arm is already non-conforming
  independent of this change. Not an absolute shield.
- The alias's OWN minor-safety (distinct from new-type refusal): a conforming
  older reader treats `web2:domain:` as unknown -> unverified -> requirement
  unsatisfied (fail-closed) — correct behaviour; the newer reader's acceptance
  is additive. The §11.1.2 additivity test met on its own fail-closed terms.
- `parserRules`: the `demos-gcr-domain` procedure does not consume it, matching
  `domain-tls-control` and `self-signed`. That `parserRules` is required of
  methods that never apply it, and that §7.5.2 step 6 assumes all methods parse,
  is a PRE-EXISTING DACS-2 inconsistency this method is the THIRD instance of; it
  is observed here, not resolved. Filed as a separate follow-up issue:
  <parserRules follow-up issue link>
- First in-document recipe supersession — no prior recipe sets `supersedes`; the
  DACS-4 rail supersession is the only structural precedent.
- Registry-publication boundary: this PR defines the method/recipe normatively
  and ships vectors; it does NOT sign or publish the anchored `dacs2:registry:v0.1`
  entry — the steward does that after merge review.
- The `oneOf` ordered-greedy consumption rule is our reading of ruling point 4
  for the steward to confirm.

## Blocking follow-up (why #275 stays open)

The issue's acceptance criterion "SDK requirement matching proves that a
Demos-verified domain satisfies the canonical DACS requirement exactly once"
requires the `dacs-sdk` emit site (`src/identity/cci.ts:168` and `:180`) to emit
the canonical `domain:` form. That is a SEPARATE SDK PR (the steward asked not to
combine SDK work into the Standard PR). #275 closes only after that SDK PR lands.

## Out of scope

`domain-tls-control` fourth challenge type (ruled out); DEM-767 fresh challenge;
refetch-model semantics; making `parserRules` conditional on method kind (the
follow-up above); publishing the anchored registry entry; the SDK change.
