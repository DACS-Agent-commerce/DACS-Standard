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

> **SIG-6 spelling (migrated).** Both lifecycle chains now carry canonical SIG-6
> signature values (unpadded Base64URL) and no longer declare
> `signatureValueSpelling`, matching every other SIG-6 vector (e.g.
> [`security/bundle-binding-v0.1.json`](./security/bundle-binding-v0.1.json)). The
> re-spelling changed only the wire encoding — the underlying signature bytes are
> byte-identical to the prior padded spelling. Because each downstream artifact binds
> the serialized content hash of earlier artifacts, the re-spelling was done
> generator-side (`scripts/generate_lifecycle_vectors.py`), never by hand. Encoding
> conformance itself is pinned by
> [`security/signature-value-encoding-v0.1.json`](./security/signature-value-encoding-v0.1.json).
>
> The validator still supports a legacy padded-Base64 **dual gate** — padded standard
> Base64 is accepted only when BOTH an explicit
> `"signatureValueSpelling": "legacy-padded-base64"` declaration AND an allowlisted
> basename are present — for any genuine legacy vector that might yet appear. Canonical
> SIG-6 is attempted first, so a SIG-6 file never requests that permit; these lifecycle
> files therefore no longer sit on the allowlist. The gate's load-bearing behaviour is
> exercised by a self-contained synthetic specimen in
> `tests/test_validate_conformance_vectors.py::test_legacy_base64_dual_gate`, not by any
> committed fixture. This is **compatibility routing**, not an authenticity boundary —
> it decides which decoder runs, not whether a file is trustworthy.

> **Internal-reference coherence (#278 / #313).** Each artifact's `contentHash`
> envelope value is the §B.2 content hash — sha256 of the RFC 8785 canonical form
> with the signature field omitted (bundles also omit `anchoredByRole`, §10.4.1).
> The embedded ed25519 signatures already commit to that hash, so correcting the
> envelope values needed no re-signing. The signed **internal cross-references** —
> `agreement.listingRef.contentHash`,
> `agreement.parties[*].vetRecordRef.contentHash`, and
> `bundle.listingRef.contentHash` — sit inside the signed scope, so they could not
> be corrected in place; the chains were instead regenerated generator-side
> (`scripts/generate_lifecycle_vectors.py`) and re-signed with the disclosed
> repeated-byte ed25519 keys. Those references now resolve to the referent's §B.2
> signature-omitted envelope hash in **both** lifecycle chains. The coherence
> relationship is executable and pinned by
> `tests/test_payload_attestation_vectors.py::test_happy_path_is_dpa1_coherent_and_transitively_resigned`
> (positive chain, including the Vet-record references) and
> `::test_negative_chain_is_internally_coherent` (negative chain). This is the
> generator-side regeneration #313 anticipated, carried out here for #278; #313
> remains its tracking issue.

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
  `dest-revealed-source-unclaimed` interim evidence state (signed).
- `conformance/fixtures/settlement/htlc9-asymmetric-resolved.json` — the ST-8
  `:resolved` success record that supersedes it (`supersedesEvidenceRef` binds the
  interim record's §B.2 content hash; no amendment — DACS-4 §9.5.4). Both are
  emitted by `scripts/generate_htlc9_st8_pack.py` from the public orchestrator seed
  and verified, signatures included, by `scripts/verify_htlc9_st8_pack.py`.

## Validate locally

From the repository root:

```bash
python3 scripts/validate_conformance_vectors.py
python3 scripts/validate_domain_separators.py
python3 scripts/validate_rule_ids.py
python3 scripts/validate_spec_tables.py
python3 scripts/generate_htlc9_st8_pack.py --check
python3 scripts/verify_htlc9_st8_pack.py
```

The validators are stdlib-only, except signature verification (the vector validator
and `verify_htlc9_st8_pack.py`), which needs `cryptography` and says so if it is missing.
The vector validator checks:

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
