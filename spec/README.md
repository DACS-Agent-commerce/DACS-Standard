# DACS Specification — v0.1

This directory holds the authoritative DACS standard, published as a **Core document plus one module per stage**. Start with the [Primer](../PRIMER.md) for a ~5-page overview, then read the documents you need.

| File | Description |
|------|-------------|
| [`CORE.md`](./CORE.md) | **Foundation.** Framing (§1–5), Demos production mapping (§A), global terminology + shared types + the universal signature/canonical-form scheme (§B), composed open standards (§C), governance & versioning (§11), the unified threat model (§12), the glossary (§13), and the conformance frame (§14). Read this to implement the shared model. |
| [`DACS-1-IDENTIFY.md`](./DACS-1-IDENTIFY.md) | Identity claims, identity bundles, signed/anchored listings, discovery (chapter 6). |
| [`DACS-2-VET.md`](./DACS-2-VET.md) | Verification methods, recipe registry, the vet-credentials phase (chapter 7). |
| [`DACS-3-NEGOTIATE.md`](./DACS-3-NEGOTIATE.md) | Private negotiation patterns and agreement commitment (chapter 8). |
| [`DACS-4-SETTLE.md`](./DACS-4-SETTLE.md) | Payment rail registry, payment and delivery phases, settlement evidence (chapter 9). |
| [`DACS-5-VERIFY.md`](./DACS-5-VERIFY.md) | Session record, attestation bundle, reputation derivation (chapter 10). |
| [`PROFILE.md`](./PROFILE.md) | The v0.1 version set, and how scope is a profile decision. |

Machine-readable schemas for the optional Atomic DACS Work profile are under
[`schemas/`](./schemas/). They accompany the normative definitions in CORE
§5.2 and DACS-4 §9.7.3; the Markdown rules remain authoritative when a schema
cannot express a cross-artifact or proof-verification requirement.

Section numbers are retained across the split (a §9.x reference lives in `DACS-4-SETTLE.md`, etc.); the [document map in CORE](./CORE.md#document-map) gives the §→document index.

**Normative language.** The specification uses the RFC 2119 / RFC 8174 keywords
(MUST, SHOULD, MAY, …), normative only when uppercase.

**Version.** Published as DACS **v0.1** — the first publicly released version. From v0.1 onward each per-stage module versions independently; a [PROFILE](./PROFILE.md) pins the coherent set. See the [CHANGELOG](../CHANGELOG.md) for normative change history.

> Spotted a problem in the spec — an unclear rule, an inconsistency, a broken
> reference? Please [open an issue](https://github.com/DACS-Agent-commerce/DACS-Standard/issues)
> citing the section (§) and the passage. See [CONTRIBUTING](../CONTRIBUTING.md).
