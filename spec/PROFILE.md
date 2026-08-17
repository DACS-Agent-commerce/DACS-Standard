# DACS Profile — v0.1

A DACS **profile** pins a coherent set of document versions that implement and conform together. Each document versions independently thereafter (per-stage minor versions per [CONTRIBUTING](../CONTRIBUTING.md)); a profile is the snapshot an implementer targets.

## DACS v0.1

| Document | Version | Status |
| --- | --- | --- |
| [CORE](CORE.md) | 0.1 | Draft |
| [DACS-1-IDENTIFY](DACS-1-IDENTIFY.md) | 0.1 | Draft |
| [DACS-2-VET](DACS-2-VET.md) | 0.1 | Draft |
| [DACS-3-NEGOTIATE](DACS-3-NEGOTIATE.md) | 0.1 | Draft |
| [DACS-4-SETTLE](DACS-4-SETTLE.md) | 0.1 | Draft |
| [DACS-5-VERIFY](DACS-5-VERIFY.md) | 0.1 | Draft |

**Conformance to "DACS v0.1"** means conformance to every document at the version pinned above, exercised by the [conformance vectors](../conformance/).

## DACS v0.4 coordinated release

The unqualified profile name remains **DACS v0.1**: it names the common full-profile
baseline and does not advance when one stage receives an additive minor release. A
claim against the coordinated v0.4 release pins the release tag or exact
specification commit together with the per-document versions. The v0.4
composition is:

| Document | Version | Status |
| --- | --- | --- |
| [CORE](CORE.md) | 0.1 | Draft |
| [DACS-1-IDENTIFY](DACS-1-IDENTIFY.md) | 0.3 | Draft |
| [DACS-2-VET](DACS-2-VET.md) | 0.2 | Draft |
| [DACS-3-NEGOTIATE](DACS-3-NEGOTIATE.md) | 0.3 | Draft |
| [DACS-4-SETTLE](DACS-4-SETTLE.md) | 0.3 | Draft |
| [DACS-5-VERIFY](DACS-5-VERIFY.md) | 0.3 | Draft |

The coordinated cut is identified by the annotated repository tag `v0.4`.

## Candidate Atomic amendment composition

The RFC #320 Atomic DACS Work amendment is a draft, capability-gated candidate,
not a released coordinated profile. Review and conformance artifacts for the
candidate pin the following document versions at one exact specification
commit:

| Document | Version | Status |
| --- | --- | --- |
| [CORE](CORE.md) | 0.3 | Draft / Demos DACS binding and evidence required |
| [DACS-1-IDENTIFY](DACS-1-IDENTIFY.md) | 0.6 | Draft |
| [DACS-2-VET](DACS-2-VET.md) | 0.5 | Draft |
| [DACS-3-NEGOTIATE](DACS-3-NEGOTIATE.md) | 0.5 | Draft / Atomic candidate |
| [DACS-4-SETTLE](DACS-4-SETTLE.md) | 0.7 | Draft / Atomic candidate |
| [DACS-5-VERIFY](DACS-5-VERIFY.md) | 0.5 | Draft / Atomic candidate |

No implementation may claim this composition merely from generic Atomic Work,
schema, or candidate-vector support. Demos's existing `DemosWork` orchestration
primitive does not by itself provide the consensus-atomic DACS binding. The
DACS-specific path is selectable only after the exact release/profile mapping,
authenticated capability, and evidence required by
[DEMOS-MAPPING §A.6](DEMOS-MAPPING.md#a6-atomic-dacs-work-capability-gate) are
pinned and demonstrated.

## Qualified implementation claims

The unqualified phrase **“DACS v0.1 conformant”** retains the full-profile meaning
above. Implementations with a narrower surface can make qualified module, role, or
capability claims without implying support for the complete profile.

Qualified claims use the optional `ImplementationManifest` reporting contract in
[§14.10](CONFORMANCE-PLAN.md#1410-implementation-conformance-claims). A manifest
separates implemented support, operational availability, and test evidence. Declaring
an optional capability `unsupported` is not itself a conformance failure, but the
capability cannot appear inside a passing claim.

The manifest is reporting metadata. It does not replace artifact verification,
registry availability checks, substrate preflight, or any normative transaction rule.

## Scope is a profile decision

Which stages, methods, and rails a release ships is decided here, not by deleting specification text. A future profile MAY:

- omit a module (e.g. ship without `DACS-3-NEGOTIATE` on a substrate lacking SR-4 — only `negotiate-fixed-price` is then available, which needs no private channel);
- pin a reduced module variant (e.g. a `DACS-2-VET` profile exposing a subset of the eight verification methods, or a `DACS-4-SETTLE` profile exposing a subset of rails);
- add a module (e.g. `DACS-X-DISPUTE`, or a `pay-evm-erc8183` escrow rail) once it reaches the shipped-path + reference-implementation bar (see [ROADMAP](../ROADMAP.md)).

This makes scope trimming and feature addition version events on the profile, not edits that churn the normative documents.
