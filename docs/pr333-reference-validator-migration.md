# Reference-validator current and archival migration

This non-normative guide describes the Python conformance helpers in
[`tests/dacs5_reference.py`](../tests/dacs5_reference.py). They are repository
reference APIs, not a declaration of an SDK's public API or proof that a
downstream implementation has migrated. Normative authority remains with
[CORE §11.1.2](../spec/CORE.md#1112-versioning),
[DACS-4 PDE-7/PDE-8](../spec/DACS-4-SETTLE.md), and
[DACS-5 §10.4.3](../spec/DACS-5-VERIFY.md#1043-bundle-production-rules).

## Intentional compatibility change

The existing `validate_ebfab` Boolean entry point now means **current admission**.
It does not preserve a historical delivery-admission contract merely because
its name and three-item return shape remain unchanged. Current delivery uses
`DeliveryEvidence`; historical delivery-shaped `SettlementEvidence` is confined
to an explicitly selected, non-authorizing archival/audit operation. Historical
records are not rewritten or relabelled as current evidence.

This is a declared **breaking pre-v1 correction**, affecting CORE v0.3,
DACS-4 v0.8, and DACS-5 v0.7. The complete candidate tuple is CORE v0.3 /
DACS-1 v0.8 / DACS-2 v0.6 / DACS-3 v0.6 / DACS-4 v0.8 / DACS-5 v0.7.
[PROFILE](../spec/PROFILE.md) remains an unreleased candidate: before live
activation it must record an annotated coordinated release tag or immutable
specification commit containing this correction. Implementers must pin that
identifier and the complete tuple, and authenticate the same exact profile for
all participants under CORE §11.1.2. A mutable branch name, a major discriminator,
or a pin predating this correction does not establish compatibility.

## Choose the operation before validation

| Entry point | Meaning | Receipt contract | Return shape |
| --- | --- | --- | --- |
| `validate_ebfab` | Current EBFAB admission | Current CORE receipt | `(ok, reason, phase_keys)` |
| `validate_ebfab_disposition` | Current EBFAB admission with classified result | Current CORE receipt | `(disposition, reason, phase_keys)` |
| `validate_legacy_ebfab` | Frozen historical verification; audit only | Named historical receipt | `(ok, reason, phase_keys)` |
| `validate_legacy_ebfab_disposition` | Frozen historical verification; audit only | Named historical receipt | `(disposition, reason, phase_keys)` |
| `validate_archival_audit_ebfab_disposition` | Explicit pre-LAA audit; non-authorizing | Current CORE receipt envelope | `(disposition, reason, phase_keys)` |

The disposition vocabulary is `pass`, `fail`, `error`, and `indeterminate`.
Boolean callers do not retain that distinction: every non-passing disposition
is false. Callers that need to distinguish rejection, malformed input, and
unavailable authority should retain the classified result rather than infer a
category from a false Boolean. Success in an archival operation establishes
only that operation's audit result, not current bundle, delivery, payment,
metric, reputation, or volume authority. A current receipt envelope alone does
not turn the pre-LAA audit operation into current admission.

Choose current or archival use from verifier-owned operation context before
examining untrusted records. Do not select it from a record member or
unauthenticated caller label. Do not retry archival validation after a current
failure and treat the archival result as permission to continue current use.
The PDE-7 historical delivery arm remains limited to one unambiguous matching
invocation; it does not cover repeated delivery or establish DV-5 credential
delivery. Existing frozen archival semantics otherwise remain unchanged.

## Migration checklist

1. Inventory each direct and indirect reference-helper caller by intended use:
   current admission or historical audit. This guide does not assert that such
   a downstream inventory has already been completed.
2. Keep current callers on the current entry points and provide their required
   authenticated authority. Move only genuinely archival callers to the named
   archival operation and its corresponding receipt contract.
3. Preserve the distinction in the caller's result handling and storage. An
   archival `pass` must not populate current-authority decisions or metrics.
4. Record the exact candidate commit plus local patch digest for review. Before
   deployment, replace development identifiers with the coordinated release
   pin recorded in PROFILE and authenticate every participant's matching pin.
   Do not operate mixed corrective/pre-corrective live sessions.
5. Run the applicable current and frozen-archival conformance checks at that
   exact revision. Do not relabel earlier evidence as proof for the correction.

## Result classification and copy selection

For current consumers of released `AttestationBundle` and
`FaultAttestationBundle`, DACS-5 §10.4.3 specifies `fail` when rejection is
already certain but missing context leaves only `fail` versus `error`
undetermined. This is not a general preference for `fail`: independently
established malformed-input errors and explicit normative error rules still
apply. When availability can still change admissibility, the result is
`indeterminate`. The rule does not import EBFAB payment exact-set requirements
into released AB/FAB or change archival result meanings.

Apply no-weaker-fallback only within the applicable authenticated copy-selection
contract. A relevant authenticated selected stronger copy that fails its
required validation cannot be rescued by substituting a weaker copy. Unrelated,
unauthorized, or non-selected candidates are inert only where the governing
selection rule makes them so; callers cannot label a relevant failed copy
"unrelated" to discard it. This guide adds no new selection authority and does
not change type-specific reconciliation rules.

This documentation records the intended contracts. It is not a whole-candidate
review verdict, a claim that all consumers have been verified, or merge or
deployment approval.
