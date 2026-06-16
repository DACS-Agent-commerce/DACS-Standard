# Operational builder guide outline

This is a non-normative outline for operators preparing to implement DACS in production. It complements the existing [builders guide](./builders-guide.md) by focusing on operational, capital, and settlement-finality questions that the v0.1 specification deliberately leaves to implementers.

## 1. Scope and assumptions

- Identify which DACS stages your system will produce, consume, or both.
- Record substrate choices for SR-1 through SR-5 and note any operator-gated paths.
- Separate normative conformance requirements from local operational policy.

## 2. Capital and float planning

- Estimate per-rail working capital needs by asset, network, finality window, and refund policy.
- Track float reserved for pending sessions separately from treasury balances.
- Model worst-case concurrent settlement exposure, including retries and stuck transactions.
- Decide who funds gas, relay fees, bridge fees, and failed-settlement remediation.

## 3. Undercapitalised mid-session behavior

- Preflight balances before advertising or accepting payment rails.
- Fail fast when a selected rail cannot be funded; avoid partially committed settlement paths.
- Classify undercapitalised outcomes consistently with the relevant phase `errorClass`.
- Preserve evidence for failed attempts so reputation and dispute tooling can inspect the session.

## 4. Settlement finality integration

- Map each rail's confirmation rule to the application's finality threshold.
- Do not mark `ok: true` before the rail-specific finality semantics are satisfied.
- Surface chain reorganizations, bridge delays, and recovery windows in operator dashboards.
- Populate `settlementFinality` on success-outcome payment evidence with the finality model actually applied (PC-6).

## 5. Key custody and HSM practice

- Inventory signing keys by artifact type: bundle presentation, listing, agreement, settlement evidence, ratings, and bundle closeout.
- Prefer HSM or remote signer controls for steward, treasury, and production operator keys.
- Rotate session keys without breaking primary-claim reputation continuity.
- Log signature payload construction so domain-separation bugs are diagnosable.

## 6. Observability and incident response

- Monitor anchored write failures, availability transitions, verifier timeouts, and rail preflight failures.
- Alert when availability changes from `live` to a gated, disabled, or failed state.
- Keep runbooks for re-anchoring evidence, re-running verification, and explaining abort outcomes.

## 7. Implementation checklist

- Run documentation and conformance validators before release.
- Maintain local fixtures for happy-path and negative-path sessions.
- Record deviations from the reference vectors as implementation notes, not spec assumptions.
- Open implementation reports when production behavior reveals ambiguity in the standard.
