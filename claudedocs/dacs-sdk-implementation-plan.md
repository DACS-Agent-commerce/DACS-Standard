# DACS SDK — Repo-Local Implementation Plan (v0.1)

**Audience:** implementers building the first TypeScript SDK for DACS v0.1.

**Goal:** add a DACS-owned SDK package inside this repository. The SDK wraps
`@kynesyslabs/demosdk` as the Demos rail/substrate layer, while DACS artifact
construction, validation, conformance behavior, and version targeting remain
owned by this repo.

This is a build plan, not normative specification text. The spec remains the
source of truth: `spec/CORE.md`, `spec/DACS-1..5-*.md`, `spec/PROFILE.md`, and
the conformance fixtures under `conformance/`.

---

## 0. Layering

Dependency direction:

```text
DACS-Standard repo
  spec/ + conformance/ + package source
        |
        v
packages/dacs-sdk
  DACS artifacts, validators, rails adapters, conformance utilities
        |
        v
@kynesyslabs/demosdk
  Demos substrate calls: identity, storage, DAHR, L2PS, DemosWork/XM
```

The SDK must not treat Demos as the normative source for DACS behavior. Demos is
the first rail/substrate adapter because it is the substrate used to prove the
v0.1 flow end-to-end. The DACS SDK owns DACS-shaped inputs, outputs, canonical
serialization, rule-aware validation, and conformance-vector compatibility.

---

## 1. Package Location And Scaffold

Create the first package at:

```text
packages/dacs-sdk/
```

Use Bun and TypeScript:

- root workspace metadata when the first package lands;
- package name candidate: `@dacs-standard/sdk` or `@kynesyslabs/dacs-sdk`;
- ESM-first TypeScript package;
- generated or checked-in type surfaces must version-stamp the DACS spec version
  they target;
- CI must run SDK tests plus the existing stdlib validators.

Why `packages/dacs-sdk/` instead of a standalone repo:

- conformance vectors and spec fixtures live here and should be the SDK's golden
  test source;
- DACS behavior stays colocated with DACS governance and versioning;
- Demos remains a dependency/adaptor layer, not the place where DACS semantics
  are defined.

---

## 2. Initial Export Surface

First public modules:

```text
artifacts/*
validators/*
rails/demos/*
conformance/*
```

### `artifacts/*`

Builders, parsers, canonical serializers, and content-hash helpers for the
v0.1 spine artifacts:

- `ClaimReference`
- `IdentityBundle`
- `CompositeVerificationRecord`
- `Listing`
- `AgreementDocument`
- `SettlementEvidence`
- `AttestationBundle`
- `ReputationDerivation`
- `RatingRecord`

### `validators/*`

Rule-aware validators for v0.1 artifact invariants. These should return
structured diagnostics with rule IDs where possible, not just booleans.

Initial targets:

- canonical decimal and string normalization helpers;
- signature payload/domain-separator checks;
- artifact required-field and phase-shape validation;
- PC-6 `settlementFinality` presence/absence checks;
- IT-1..IT-3 identity-tier recomputation helpers;
- WN-1..WN-6 advisory-warning preservation checks.

### `rails/demos/*`

Thin adapters over `@kynesyslabs/demosdk` for DACS-shaped operations:

- DACS logical address assembly for SR-2 anchoring;
- DAHR result mapping into DACS-2 evidence shapes;
- DACS-3 channel/session helper types where the live SDK surface exists;
- DACS-4 payment/delivery evidence helpers for rails already represented in
  v0.1;
- no silent substitution between DACS payment rails and Demos execution
  mechanisms.

The adapter should expose DACS concepts, not raw demosdk objects as the primary
API. Raw demosdk access can remain available for advanced callers, but DACS
validity must be checked at the SDK boundary.

### `conformance/*`

Utilities for consuming this repo's conformance corpus:

- load vectors from `conformance/vectors/`;
- load fixture packs from `conformance/fixtures/` via `conformance/MANIFEST.json`;
- run SDK validators against golden fixtures;
- snapshot expected diagnostics for negative cases.

---

## 3. First Deliverables

Keep the first SDK increment non-normative and helper-focused:

1. Artifact builders/parsers for the spine artifacts.
2. Canonicalization, hashing, and signing payload helpers.
3. Rule-aware validators with diagnostics.
4. Demos rail adapter interfaces for existing DACS v0.1 rails.
5. Conformance-vector consumption utilities and golden tests.

Do not put these in the first cut:

- new v0.2 artifact fields;
- new settlement semantics;
- new DACS-X behavior;
- generic phase hooks;
- speculative non-Demos adapters;
- silent rail fallback behavior not allowed by DACS-4.

---

## 4. MVP Path

Minimum useful path:

```text
self-declared IdentityBundle
  -> fixed-price Listing
  -> AgreementDocument
  -> one payment SettlementEvidence
  -> one delivery SettlementEvidence
  -> AttestationBundle
  -> basic RatingRecord / derivation helper
```

The SDK should be usable before it can run every roadmap rail. The first
acceptance bar is vector-backed artifact correctness, not full live-money
automation.

---

## 5. Test Plan

No SDK API should ship without a vector-backed usage test.

Required gates:

- unit tests for canonicalization, hash construction, and artifact builders;
- golden tests against `conformance/vectors/`;
- fixture-pack tests through `conformance/MANIFEST.json`;
- negative tests for required-field and rule violations;
- regression tests for every v0.1 hardening defect fixed during the health pass;
- existing validators:
  - `python3 scripts/validate_conformance_vectors.py`
  - `python3 scripts/validate_domain_separators.py`
  - `python3 scripts/validate_rule_ids.py`
  - `python3 scripts/validate_spec_tables.py`
  - `python3 scripts/validate-docs.py`

---

## 6. Open Decisions Before Scaffolding

Lock these before the package PR:

1. Public package name and npm scope.
2. Whether root workspace metadata should be introduced in the same PR as the
   package scaffold or one preparatory PR earlier.
3. Whether generated JSON Schemas are in scope for the first package increment
   or follow after handwritten TypeScript builders/validators.
4. Which live Demos-backed settlement rail is the first example path.
5. Whether examples live under `packages/dacs-sdk/examples/` or a future
   top-level `examples/` workspace.

---

## 7. Non-Goals

- This SDK does not evolve DACS governance or the v0.1 spec.
- This SDK does not make Demos the normative definition of DACS.
- This SDK does not create new settlement rails.
- This SDK does not absorb MCP server work.
- This SDK does not replace the existing conformance validators; it consumes the
  same source corpus and adds TypeScript-side tests.
