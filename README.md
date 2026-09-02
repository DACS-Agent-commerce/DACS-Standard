# DACS — Demos Agent Commerce Standards

**An open standard for verifiable agent-to-agent commerce.**

[![Status: v0.1](https://img.shields.io/badge/status-v0.1%20draft-2B36D9)](./CHANGELOG.md)
[![License: MIT](https://img.shields.io/badge/license-MIT-FF4808)](./LICENSE)
[![Spec](https://img.shields.io/badge/spec-v0.1-010109)](./spec/)

Autonomous agents are transacting with agents they have never met. Open standards
exist for *fragments* of what a transaction requires — identity registries, payment
authorisation, HTTP micropayments, capability discovery — but each addresses one
slice. Nothing in widespread use composes the fragments into a working commerce
**lifecycle**, which is why agents that need the full lifecycle today fall back to
closed operator marketplaces.

DACS specifies that lifecycle as one standard per stage, composing with the open
standards that already work and filling the gaps where they don't.

```
Identify  →  Vet  →  Negotiate  →  Settle  →  Verify
```

Each stage produces a signed, content-addressed artifact. The final stage produces
an **AttestationBundle** — a single signed document that references everything that
happened in the session. A consumer reading the bundle can dereference every
artifact, verify every signature, and confirm the audit trail end-to-end.

---

## The five stages

| Standard | Stage | Scope |
|----------|-------|-------|
| **DACS-1** | Identify | Agent identity, signed & anchored service listings, discovery |
| **DACS-2** | Vet | Method-pluggable credential attestation with signed requirement, role, and verifier provenance |
| **DACS-3** | Negotiate | Private negotiation phases (RFQ, sealed envelope, fixed price) + agreement commitment |
| **DACS-4** | Settle | Payment-rail registry, payment phases, delivery phases |
| **DACS-5** | Verify | Session record, attestation bundle, reputation derivation |

The stages are sequential within a transaction. v0.1 is a common baseline that
publishes all five per-stage standards together; from there each versions
independently.

## Substrate requirements (SR-1 … SR-5)

DACS is specified at the **substrate-capability level**. Any substrate that ships
these five primitives can host a conformant implementation:

| | Capability |
|------|------------|
| **SR-1** | Cross-substrate identity aggregation |
| **SR-2** | Anchored immutable storage with content hashes |
| **SR-3** | Consensus-backed proxy attestation of external HTTPS fetches |
| **SR-4** | Identity-keyed private coordination channels |
| **SR-5** | Multi-chain coordinated atomic settlement |

The audit format is the standard; the substrate is a deployment choice. DACS was
written and proven end-to-end against the [Demos Network](https://demos.sh), which
ships all five primitives today — see §4–6 of the specification for the
substrate-to-primitive mapping and production status. The unified SDK is [`@kynesyslabs/demosdk`](https://www.npmjs.com/package/@kynesyslabs/demosdk); substrate docs are at [demos.sh](https://demos.sh).

## Composes with, does not replace

| Standard | Role in DACS |
|----------|--------------|
| W3C Verifiable Credentials | DACS-2 credential-verification method |
| ERC-8004 (agent identity) | DACS-1 claim scheme + optional DACS-5 reputation target |
| AP2 (FIDO Alliance) | DACS-4 payment phase type |
| x402 (Coinbase) | DACS-4 HTTP-micropayment phase type |
| TLSNotary | DACS-1 claim context + DACS-2 method |
| ACME (RFC 8555) | DACS-2 domain-control method |
| A2A (Google) | DACS-1 listing discovery surface |
| RFC 8785 (JCS) | Canonical-form serialisation everywhere |
| EIP-4361 (SIWE/SIWD) | DACS-1 identity bundle presentation |

---

## Repository contents

| Path | What it is |
|------|------------|
| [`spec/CORE.md`](./spec/CORE.md) | **The standard.** Full normative specification, DACS-1 … DACS-5, with conformance rules, error classes, threat model, and conformance test plan. |
| [`docs/builders-guide.md`](./docs/builders-guide.md) | A technical case for builders — what problems DACS solves and how to evaluate it honestly. |
| [`docs/flow-trace.md`](./docs/flow-trace.md) | End-to-end happy path as SDK-mapped pseudocode, with a sequence diagram and a verified SDK-compatibility note. |
| [`docs/glossary-index.md`](./docs/glossary-index.md) | Non-normative index mapping key terms to their specification sections. |
| [`docs/rule-id-index.md`](./docs/rule-id-index.md) | Non-normative index mapping labelled conformance rule families to spec sections and §14 test-plan hooks. |
| [`docs/operational-builder-guide.md`](./docs/operational-builder-guide.md) | Outline for implementation operations, capital/float planning, key custody, and settlement-finality topics. |
| [`conformance/vectors/`](./conformance/vectors/) | Machine-readable happy-path, negative-path, and core artifact example JSON fixtures with a stdlib validator. |
| [`CHANGELOG.md`](./CHANGELOG.md) | Normative change history. Start here if you implemented against an earlier draft. |
| [`ROADMAP.md`](./ROADMAP.md) | Anticipated follow-on work (informative). What's deferred beyond v0.1 and why — no committed dates. |
| [`IMPLEMENTATION_READINESS.md`](./IMPLEMENTATION_READINESS.md) | Additive validation, example, and contributor-support improvements that strengthen implementation readiness without changing v0.1 conformance semantics. |

**New here?** Read the [builders guide](./docs/builders-guide.md) first, then the
[flow trace](./docs/flow-trace.md), then the [specification](./spec/CORE.md).

---

## Status

DACS **v0.1** is the first publicly released version. It is a draft standard under
active development and we are actively seeking implementation feedback.

**Live today** (on Demos): SR-1 cross-substrate identity (CCI), SR-2 anchored
storage, SR-3 consensus-backed proxy (DAHR). **Substrate-live, SDK ergonomics on
the backlog:** SR-4 private channels (L2PS), SR-5 atomic cross-chain settlement
(Liquidity Tanks / Native Bridges, Phase 1).

The honest list of what is **not** done lives in the specification and the
[builders guide](./docs/builders-guide.md): SR-4/SR-5 SDK surface work, SR-5
Phase 2–4 expansion, a cross-substrate test of the artifact-level portability claim
against a non-Demos substrate, and constitution of multi-party governance to replace
the current single-steward arrangement.

## Reference implementations

- **`agent-commerce-demo`** — KyneSys Labs' reference implementation; runs an
  end-to-end DACS-1 … DACS-5 session against Demos testnet.
- **`pathos-dacs-ref`** — PATH-OS Labs' independent third-party implementation
  (DACS-1 publisher, DACS-2 GLEIF verifier, DACS-5 envelope-receipt verifier CLI).

## Contributing & feedback

DACS is published openly so builders can implement against it and tell us where it's
wrong. The highest-signal feedback names a section (§), a file path, and an alternate
interpretation. See [CONTRIBUTING.md](./CONTRIBUTING.md), open an
[issue](https://github.com/DACS-Agent-commerce/DACS-Standard/issues), or start a
[discussion](https://github.com/DACS-Agent-commerce/DACS-Standard/discussions).

## Local validation

All repository tooling is dependency-free Python stdlib plus GitHub Actions for CI:

```sh
python3 scripts/validate_conformance_vectors.py
python3 scripts/validate_domain_separators.py
python3 scripts/validate_rule_ids.py
python3 scripts/validate_spec_tables.py
python3 scripts/validate-docs.py
python3 -m unittest discover tests -v
```

The pull-request workflow runs the same documentation, registry, rule-ID,
spec-table, conformance-vector, and unit-test checks.

## Community & ecosystem

Tools, reference implementations, integrations, and apps built on DACS live in
the **[Community repo](https://github.com/DACS-Agent-commerce/Community)** —
non-normative by construction, one-PR submissions, with an honest conformance
disclosure per project. The spec, conformance vectors, and CHANGELOG stay here.

## Governance

DACS v0.1 operates under progressive-anchoring phase **PA-2**: a single steward
(KyneSys Labs) signs the recipe and rail registries. The PA-2 → PA-3 transition to
multi-party governance is named follow-on work (§11.2.6 of the spec).

## License

Released under the [MIT License](./LICENSE). The specification text and any
reference code in this repository are free to read, implement, and build on.
