# DACS Conformance Vectors

This directory contains machine-readable fixtures for implementers who want a
small, repeatable check against the DACS v0.1 artifact lifecycle.

> **✅ Regenerated to current v0.1 spec shapes (#133/D2 — quarantine lifted).**
> The two lifecycle vectors below were regenerated from the `pathos-dacs-ref`
> reference verifier with real ed25519 signatures and sha256 hashes, in current
> v0.1 artifact shapes. They pass **both** `scripts/validate_conformance_vectors.py`
> (wrapper) and `scripts/validate_artifact_shapes.py` (deep per-`type` shape check)
> — they are no longer quarantined. For the broader verifier-emitted conformance
> suite see [`golden.json`](./golden.json) + [`../MANIFEST.json`](../MANIFEST.json) (186 cases).

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
- deterministic `sha256:` content hashes over each artifact payload

## Scope

These vectors are non-normative tooling around the standard. The normative source
remains the [spec documents](../../spec/). When a vector and
the specification disagree, the specification wins and the vector should be fixed.
