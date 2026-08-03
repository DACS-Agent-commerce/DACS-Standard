# DACS Conformance Vectors

This directory contains machine-readable fixtures for implementers who want a
small, repeatable check against the DACS v0.1 artifact lifecycle.

> **✅ Regenerated to current v0.1 spec shapes (#133/D2 — quarantine lifted).**
> The two lifecycle vectors below were regenerated from the `pathos-dacs-ref`
> reference verifier with real ed25519 signatures and sha256 hashes, in current
> v0.1 artifact shapes. They pass **both** `scripts/validate_conformance_vectors.py`
> (wrapper) and `scripts/validate_artifact_shapes.py` (deep per-`type` shape check)
> — they are no longer quarantined. For the broader verifier-emitted conformance
> suite see [`golden.json`](./golden.json) + [`../MANIFEST.json`](../MANIFEST.json) (236 cases).

> **SIG-6 transition.** These two generated lifecycle chains predate the canonical
> signature-value ruling and retain padded standard-Base64 signature spellings.
> Each downstream artifact binds the complete serialized content hash of earlier
> artifacts, so changing a spelling requires generator-side chain regeneration
> and re-signing rather than an in-place edit. They are legacy migration inputs,
> not SIG-6 wire-encoding cases. Current encoding conformance is pinned by
> [`security/signature-value-encoding-v0.1.json`](./security/signature-value-encoding-v0.1.json).
> The validator accepts the padded spelling only when BOTH an explicit
> `"signatureValueSpelling": "legacy-padded-base64"` declaration AND a recognised
> lifecycle-vector basename are present. This is an explicit **compatibility
> routing**, not an authenticity boundary — it decides which decoder runs, not
> whether a file is trustworthy. Canonical SIG-6 decode is attempted first, so a
> future SIG-6 migration simply drops the declaration and the legacy path closes.

> **Internal-reference residual (#278 / #313).** Each artifact's `contentHash`
> envelope value is the §B.2 content hash — sha256 of the RFC 8785 canonical form
> with the signature field omitted (bundles also omit `anchoredByRole`, §10.4.1).
> The embedded ed25519 signatures already commit to that hash, so correcting the
> envelope values needed no re-signing. The signed **internal cross-references**,
> however — `agreement.listingRef.contentHash`,
> `agreement.parties[*].vetRecordRef.contentHash`, and
> `bundle.listingRef.contentHash` — still commit to the legacy *whole-artifact*
> envelope hashes: they sit inside the signed scope, so they cannot be corrected
> in place without invalidating the (externally-keyed) signatures. Until the chain
> is regenerated generator-side, **these fixtures MUST NOT be used as
> reference-resolution vectors** — a consumer resolving an internal ref against the
> corrected envelope hash will see a mismatch. Tracked in #313.

## Included vectors

- [`dacs-v0.1-happy-path.json`](./dacs-v0.1-happy-path.json) — one minimal
  positive session covering all five stages in order:
  `DACS-1 → DACS-2 → DACS-3 → DACS-4 → DACS-5`. *(current v0.1 shapes — regenerated)*
- [`dacs-v0.1-negative-paths.json`](./dacs-v0.1-negative-paths.json) — negative
  examples that conforming implementations are expected to reject or classify as
  failures, with rule references for the expected failures. Uniquely asserts a few
  negative rules not yet in `golden.json` (RAV-R2, RT-1/2, BP-3). *(current v0.1 shapes — regenerated)*

## Core artifact examples

- [`examples/identity-bundle.json`](./examples/identity-bundle.json) — a
  machine-readable IdentityBundle example for §6.3.2.
- [`examples/rating-record.json`](./examples/rating-record.json) — a
  machine-readable RatingRecord example for §10.6.
- [`examples/attestation-bundle.json`](./examples/attestation-bundle.json) — a
  machine-readable, **verifier-emitted** AttestationBundle example for §10.4,
  regenerated from the `pathos-dacs-ref` reference verifier (real ed25519
  signatures over the `dacs-bundle:v1:` scope; `verifyBundleV1` → accept). This is
  the DACS-5 portion of the #133/D2 regeneration: the bundle artifact matches the
  current spec `type AttestationBundle` shape. The full five-stage lifecycle
  vectors above are now likewise regenerated (#133/D2), so the shape-check
  quarantine is lifted.

## Shared fixture packs

The repository also includes small shared fixtures outside this vector directory.
They are excluded from the canonical `validate_conformance_vectors.py` default
vector run; check `conformance/MANIFEST.json` for each fixture's normative status
and validation command.

### v0.1 hardening fixtures

- `conformance/fixtures/identity/identity-tier-*.json` — deterministic
  `identityTier` cases for institutional, verified, and self-declared bundles
  (IT-1..IT-3).
- `conformance/fixtures/identity/demos-agent-claim-reference.json` —
  canonical lowercase output, case-insensitive `did` scheme parsing, strict
  lowercase key material, and unknown `demos:0x…` handling for the Demos agent
  DID profile (§6.3.1 / CF-2).

### Roadmap/prototype fixtures

These are non-normative prototype artifacts for roadmap items; they do not add new
v0.1 conformance requirements:

- `conformance/fixtures/reputation/reputation-suspicious-pattern-flags.json` —
  advisory `suspiciousPatternFlags` on a ReputationDerivation / derivation surface.
- `conformance/fixtures/settlement/htlc9-asymmetric.json` — the HTLC-9
  `dest-revealed-source-unclaimed` interim evidence state.
- `conformance/fixtures/dacsx/dispute-outcome-htlc9-correction.json` — the
  provisional DACS-X DisputeOutcome seam that emits a correction amendment.

## Validate locally

From the repository root:

```bash
python3 scripts/validate_conformance_vectors.py
python3 scripts/validate_domain_separators.py
python3 scripts/validate_rule_ids.py
python3 scripts/validate_spec_tables.py
python3 scripts/verify_dacsx_dispute_pack.py
```

The validators are stdlib-only. The vector validator checks:

- required top-level vector fields
- exactly ordered five-stage coverage
- per-artifact required fields
- `§`-style spec references
- registered §7.7 domain separators
- deterministic `sha256:` content hashes over the §B.2 canonical form (RFC 8785
  JCS with the signature field omitted; bundles also omit `anchoredByRole`)
- executed ed25519 verification of every embedded signature over the §B.7
  domain-separated payload, pinned two-way per artifact in `signatureChecks`
- exact nested §7.5.2 `AttestationRef` shapes in the reference-bearing shared
  fixtures, including every DACS-5 bundle ref position
- exact §9.3 `ChainTxRef` union arms, backed by all-discriminator positive
  cases and legacy-shape negative cases

## Scope

These vectors are non-normative tooling around the standard. The normative source
remains the [spec documents](../../spec/). When a vector and
the specification disagree, the specification wins and the vector should be fixed.
