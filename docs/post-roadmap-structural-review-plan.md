# Post-roadmap structural review plan

## Status

- Parked / post-roadmap.
- Non-normative planning artifact.
- Applies after the current roadmap wave settles.
- Does not change the specification, conformance vectors, schemas, validators, or version semantics.

## Decision

Target direction:

- thin `CORE`
- readable stage contracts for `DACS-1..5`
- provider, authority, rail, scoring, and publication integrations split into hooks
- use-case bundles split into profiles
- machine-readable enumerations split into registries
- substrate mappings, governance, and roadmap material kept outside the validity-reading path

Rule:

- structural extraction first
- semantic simplification second

Do not redesign semantics while moving paragraphs. First separate layers and preserve destinations for existing obligations. Simplify only after boundaries are explicit.

## Target Structure

- `CORE`: shared invariants only: canonicalization, hashes, signatures, references, session identity, base outcomes, and substrate capability trust properties.
- `DACS-1..5`: stage-local contracts: purpose, artifacts, validity rules, inputs, outputs, and phase contracts needed to read that stage with `CORE`.
- `HOOKS`: provider, authority, rail, negotiation, scoring, and publication integrations with input shape, output shape, trust assumptions, failure semantics, and conformance status.
- `PROFILES`: use-case bundles such as micropayments, bilateral RFQ, sealed procurement, regulated trade, and cross-chain settlement.
- `REGISTRIES`: machine-readable enumerations for claim schemes, vet methods, recipes, negotiation patterns, rails, ratings, and publication targets.
- `MAPPINGS` / `GOVERNANCE` / `ROADMAP`: companion docs outside the validity path for substrate mappings, steward process, deployment reality, roadmap items, and deferred topics.

## Work Packages

1. Baseline and section inventory
   - Pin the exact source snapshot.
   - Freeze section numbering or publish a crosswalk policy.
   - Tag every existing section as `core invariant`, `stage-local`, `hook`, `registry`, `profile`, `mapping`, `governance`, `roadmap`, or `reference`.

2. Companion-doc extraction
   - Move Demos production mapping, governance, stewardship, versioning process, threat-model support, glossary, conformance support, and roadmap/deferred material out of the main validity-reading path.

3. Registry extraction
   - Move claim schemes, vet methods, vet recipes, negotiation patterns, rails, availability states, and optional rating/publication registries into data-oriented registry docs.
   - Preserve current semantics during this pass.

4. `CORE` thinning pass
   - Keep only shared invariants required by every conforming implementation.
   - Move rollout reality, provider detail, and use-case-specific text to companion docs, hooks, registries, or profiles.

5. `DACS-1..5` local-readability pass
   - Make each stage readable with `CORE` plus that one stage doc.
   - Pull hidden stage-local obligations into the relevant stage.
   - Make inputs and outputs explicit.

6. Hook/profile boundary pass
   - Put authority-, provider-, rail-, scoring-, publication-, and market-pattern-specific behavior behind hook or profile boundaries.
   - Record trust assumptions and failure semantics for each hook.

7. Crosswalk and conformance regeneration
   - Publish an old-to-new crosswalk for every old section.
   - Regenerate references, indexes, fixtures, schemas, and validation tables where practical after the structure settles.

## Move Map

| Current file | Future home | First-pass action |
| --- | --- | --- |
| `CORE` | `CORE`, `PRIMER`, `MAPPINGS`, `GOVERNANCE`, `ROADMAP`, `THREAT-MODEL`, `CONFORMANCE`, `GLOSSARY` | Keep shared substrate/canonicalization/signature/reference/session invariants in `CORE`; move motivation, Demos mapping, governance, roadmap, threat model, glossary, and conformance support out of the validity path. |
| `DACS-1` | `DACS-1`, `REGISTRIES`, `HOOKS`, `MAPPINGS`, `PRIMER` | Keep identity bundle, `presentedBy`, control proof, listing, listing validity, and discovery contracts; move claim registries, authority notes, Demos write/address detail, and excess rationale. |
| `DACS-2` | `DACS-2`, `HOOKS`, `REGISTRIES`, `GOVERNANCE` | Keep `VerifyResult`, composite verification, freshness/sufficiency, and `vet-credentials`; move verification methods, recipe schemas, parser specs, availability states, governance, and authority caveats. |
| `DACS-3` | `DACS-3`, `PROFILES`, `REGISTRIES`, `ROADMAP`, `MAPPINGS` | Keep `AgreementDocument`, `commit-agreement`, and minimal channel trust properties; move RFQ/sealed-envelope detail, pattern ladders, transcript policy, rollout notes, and mapping material when not universal. |
| `DACS-4` | `DACS-4`, `CORE`, `REGISTRIES`, `HOOKS`, `GOVERNANCE`, `MAPPINGS`, `ROADMAP` | Keep `SettlementEvidence`, payment contracts, delivery contracts, and shared commercial contract where stage-local; move rail registry contents, rail authoring process, provider/bridge specifics, deployment maturity, streaming, and escrow roadmap text. |
| `DACS-5` | `DACS-5`, `HOOKS`, `PROFILES`, `MAPPINGS`, `ROADMAP` | Keep `SessionRecord`, attestation bundle, state machine, terminal outcomes, reconciliation, and minimal canonical reputation summary; move richer reputation math, ERC-8004 publication mapping, optional scoring, and policy-heavy cancellation/dispute behavior. |

## Acceptance Criteria

- Every old section has a destination.
- No normative rule is deleted silently.
- No semantic redesign happens during pass 1.
- Each stage can be read with `CORE` plus one stage doc.
- Cross-chapter obligations are represented as tables, schemas, fixtures, generated indexes, or crosswalks where practical.
- Moved material is labeled as kept, moved, split, demoted, duplicate, or intentionally retired.
- Validators and generated references are regenerated only after structure stabilizes.

## Non-Goals

- Not a new DACS version by itself.
- Not a normative rewrite PR.
- Not an interruption of active roadmap work.
- Not deleting recipes, rails, profiles, or reputation logic.
- Not publishing the raw review bundle as the review surface.

## Sources

- Matt Williams, [Engineering for Bounded Cognition](https://shapeofthesystem.com/posts/2026/02/03/bounded-cognition.html), reviewed 2026-06-29.
- Rich Sutton, [The Bitter Lesson](https://www.incompleteideas.net/IncIdeas/BitterLesson.html), reviewed 2026-06-29.
- Current DACS docs from `origin/main` at `7a3117e9e47607c7c3fec39254c7b16939245631`, especially `ROADMAP.md`, `CONTRIBUTING.md`, `PRIMER.md`, `spec/CORE.md`, and `spec/DACS-1-IDENTIFY.md` through `spec/DACS-5-VERIFY.md`.
