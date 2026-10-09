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

## Unreleased corrective candidate

This candidate is a **breaking pre-v1 correction** under CORE §11.1.2, not an
ordinary additive minor. It replaces the existing `jobId` meaning and every
normalization-tolerant job-specific derivation. It also changes existing Vet
behaviour so session presentation admission uses verifier-issued, issuer-owned
nonce state and aggregation uses authenticated invocation, time, signer,
result-set, registry, and receipt authority rather than unsigned or
caller-projected substitutes. Every accepting IdentityBundle match and Vet
decision also requires control of the exact `presentedBy` claim whether or not
a selector is set. Without a selector, the exact presenter must additionally be
verified-and-fresh or satisfy the exact-key signature exception; selector
presence can combine only with an already-supported control proof, including an
independent mechanism where the selected profile permits it.
Production requalifies every load-bearing result-backed presenter proof at
trusted current time. `verifierIdentity` admission requires proof of control of
the exact independently expected identity. No signed artifact shape or signature domain
is changed.

On top of that boundary, the governed legacy-agreement activation boundary is
added as DACS-4 v0.8 (LAA-1..LAA-7), and DACS-3 v0.6 / DACS-5 v0.6 apply that
checkpoint to pay-bearing commitment and bundle/reputation admission, including
the exact pre-checkpoint commitment plus co-signed
`LegacyPaymentReservation`, the exclusive
`LegacyTransitionSettlementEvidence` transition, and its
current-profile-ineligible `transition-only` audit classification.

The complete coordinated tuple is:

| Document | Version | Status |
| --- | --- | --- |
| [CORE](CORE.md) | 0.3 | Draft corrective candidate; JID-1 and shared Vet admission behaviour affected |
| [DACS-1-IDENTIFY](DACS-1-IDENTIFY.md) | 0.8 | Draft corrective candidate; JID-1, session presentation, and current composed module behaviour affected; exact presenter control aligned |
| [DACS-2-VET](DACS-2-VET.md) | 0.6 | Draft corrective candidate; Vet aggregation and authority behaviour affected; current presenter-proof requalification and verifier-identity control aligned |
| [DACS-3-NEGOTIATE](DACS-3-NEGOTIATE.md) | 0.6 | Draft; current composed module |
| [DACS-4-SETTLE](DACS-4-SETTLE.md) | 0.8 | Draft corrective candidate; current composed module |
| [DACS-5-VERIFY](DACS-5-VERIFY.md) | 0.7 | Draft corrective candidate |

The exact-presenter and verifier-identity alignment above corrects the existing
unreleased DACS-1 v0.8 / DACS-2 v0.6 candidate; it does not create another
module-version bump. In particular, `primaryClaimSelector` adds exact-claim
authorization constraints but does not gate the mandatory control predicate.
Matching version labels from an implementation that accepts an uncontrolled
no-selector presenter or a verifier identity controlled only by another
included signer do not establish compatibility with this candidate.

The candidate is not an admissible live profile until a coordinated release
records an annotated tag or immutable merge commit here. At that point every
implementation claim MUST pin that identifier and this complete tuple. A
deployment that cannot authenticate the same exact pin for every participant
MUST refuse before producing, signing, resolving, comparing, or acting on a
JID-1 artifact or performing current Vet admission or aggregation. The existing
module labels do not assert same-version interoperability with implementations
of the pre-correction behaviour. A pre-JID-1 artifact, or a Vet decision,
composite, invocation record, or conformance result produced or interpreted
only under pre-correction execution semantics—including selector-conditional
presenter control or borrowed verifier-identity control—is historical input: it
remains readable under explicitly selected frozen semantics and cannot be
silently promoted into this profile or authorize a current protocol action. This does
not revoke VP-C1..VP-C3 reuse of a structurally unchanged `VerifyResult` v1.
After current-profile admission, the current verifier may qualify such a result
from authenticated recipe family/version, signed predicates, times, and trusted
context; the result itself neither carries nor proves the producing profile.

That authenticated authority MUST be verifier- or orchestrator-owned context
outside caller-controlled artifacts and phase input, bound to the exact session
and authenticated participant identity. Caller-supplied profile objects and
opaque labels are not authority. Missing, duplicate, unauthenticated,
identity-mismatched, or session-mismatched evidence fails closed before any
protocol action.

This draft does not yet name the coordinated release tag or immutable merge
commit required for live admission. Repository hashes such as the walkthrough
`profileSha256`, fixture hashes, and `MANIFEST.json` `inputBindings` establish
the integrity of their named source or test bytes; they are not a release pin,
participant profile-admission evidence, or permission to relabel earlier test
evidence as coverage of this correction. Evidence for the eventual corrective
profile MUST identify the future exact release/commit and this complete tuple.

This candidate tuple also carries the **DACS-3 v0.6 channel-message wire
replacement** declared under the same CORE §11.1.2 pre-v1 corrective boundary
(#349). The current channel message is the discriminated
`CanonicalChannelMessage` with the exclusive
`canonicalChannelMessageVersion: "1"` discriminator, the version-1 signature
envelope, and the byte-exact
`"dacs-canonical-channel-message:v1:" || ASCII(lowercase-hex sha256(JCS(unsigned_message)))`
signed-byte framing. The historical Demos wire is archival-only: accepted only
by the explicitly selected `legacy-import` operation, refused on
`current-read`, with no fallback between arms and no legacy fallback anywhere.
This tuple does not claim ordinary cross-minor compatibility with a pre-v0.6
channel-message profile, and mixed corrective/pre-corrective live operation
remains unsupported for channel messages exactly as for `jobId`.

This tuple also carries the **breaking pre-v1 current-delivery admission
correction**, affecting CORE v0.3, DACS-4 v0.8, and DACS-5 v0.7 under CORE
§11.1.2. The changed behaviour is current admission of historical
delivery-shaped `SettlementEvidence`: it is not current delivery authority,
including through the existing Boolean reference validator. Current delivery
uses `DeliveryEvidence` and PDE-8. Historical bytes remain readable only
through an explicitly selected, non-authorizing PDE-7 archival/audit operation;
there is no fallback through an archival result to current authorization.
This is not an ordinary additive-minor compatibility claim. All participants
must authenticate the same complete tuple above and the same exact coordinated
release tag or immutable specification commit before live use. The candidate
remains unreleased until that identifier is recorded here; a development branch
name or an older pin without this correction is insufficient. See the
[reference-validator migration guide](../docs/pr333-reference-validator-migration.md)
for the separate current and archival helper contracts and migration limits.

CORE v0.3 also specifies registry-bootstrap v1 as an independently testable
SR-2 registry-discovery and chain-validation capability. This candidate does
**not** activate its descriptor hash in the existing `SessionContext`, Vet or
Settle phase inputs, `SessionRecord`, or DACS-5 bundle types, and therefore does
not claim descriptor-authenticated session production or historical replay.
Those existing contracts retain their numeric registry-version fields and
semantics. A future coordinated profile must introduce distinct versioned
action-bearing contracts and pin their compatibility rules before descriptor
identity can govern a session; an unknown field, sidecar, or numeric-to-current
lookup cannot supply that authority.

## Candidate Atomic amendment composition

The RFC #320 Atomic DACS Work amendment is a draft, capability-gated candidate,
not a released coordinated profile. Review and conformance artifacts for the
candidate pin the following document versions at one exact specification
commit:

| Document | Version | Status |
| --- | --- | --- |
| [CORE](CORE.md) | 0.3 | Draft / Demos DACS binding and evidence required |
| [DACS-1-IDENTIFY](DACS-1-IDENTIFY.md) | 0.8 | Draft corrective candidate; current composed module |
| [DACS-2-VET](DACS-2-VET.md) | 0.6 | Draft; current composed module |
| [DACS-3-NEGOTIATE](DACS-3-NEGOTIATE.md) | 0.6 | Draft / Atomic candidate on current composed module |
| [DACS-4-SETTLE](DACS-4-SETTLE.md) | 0.8 | Draft / Atomic candidate on current composed module |
| [DACS-5-VERIFY](DACS-5-VERIFY.md) | 0.7 | Draft / Atomic candidate on current composed module |

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
