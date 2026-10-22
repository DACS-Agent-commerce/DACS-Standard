# Contributing to DACS

DACS is an open standard published so that builders can implement against it and
report where it doesn't hold up. Implementation feedback is the most valuable
contribution at this stage.

## What we're looking for

- **Spec defects** — rules that reference undefined values, internal
  inconsistencies, or addressing/serialisation patterns that don't work on a real
  substrate.
- **Composition gaps** — a corner where DACS fails to compose cleanly with one of
  the standards it builds on (W3C VC, ERC-8004, AP2, x402, TLSNotary, A2A, …).
- **Implementation reports** — "I built X against §Y and hit Z." These shape the
  next minor version.
- **Editorial fixes** — typos, broken links, formatting.

## How to file feedback

The highest-signal reports name three things:

1. The **section** (e.g. `§7.7.1`).
2. The **artifact / file path** the issue touches.
3. An **alternate interpretation** or proposed fix.

Open an [issue](https://github.com/DACS-Agent-commerce/DACS-Standard/issues) for
defects and concrete proposals, or a
[discussion](https://github.com/DACS-Agent-commerce/DACS-Standard/discussions) for
open-ended questions.

## Versioning

- Draft phase uses `v0.MINOR` (v0.1, v0.2, …); `vMAJOR.MINOR` from v1.0 onward.
  Each per-stage standard versions independently from the shared v0.1 baseline.
- Breaking changes bump the major version; additive non-breaking changes bump the
  minor version; editorial-only changes do not bump the version. The only exception
  is CORE §11.1.2's declared pre-v1 corrective boundary: while the affected document
  is Draft and below v1.0, the steward may publish a breaking v0.x repair only with
  an exact coordinated-profile pin, explicit migration limits, and refusal of mixed
  corrective/pre-corrective live operation.
- Every normative change is recorded in [CHANGELOG.md](./CHANGELOG.md) with the
  section numbers it affects, so implementers can scan against their own code.

## Governance

DACS v0.1 operates under progressive-anchoring phase **PA-2**: a single steward
(KyneSys Labs) signs the recipe and rail registries. Constitution of multi-party
governance (PA-3) is named follow-on work in §11.2.6 of the specification. Until
then, normative changes are merged by the steward after public discussion.

## Which branch to target

Open pull requests against the **`next`** branch, not `main`. `main` tracks the
latest tagged release and only advances on a version cut (a `next` → `main`
fast-forward + tag); `next` is the integration branch where spec, documentation,
and conformance-vector changes accumulate between releases. Targeting `main`
directly leaves it ahead of `next` and breaks the release fast-forward.

Maintainers cutting a version must follow the staged
[release checklist](./docs/release-checklist.md), including exact-revision pin
validation, a zero-skip test run, and CI on the final `next` head before the
fast-forward and annotated tag.

## Editing the specification

The canonical specification lives in [`spec/`](./spec/). When proposing normative
text changes, quote the affected passage and section number in your issue or PR
description so the change is reviewable inline.

## Validation

Use Python 3 and an isolated environment with the same cryptographic dependency
pins as [the validation workflow](./.github/workflows/validate.yml):

```sh
python3 -m venv .venv
. .venv/bin/activate
python3 -m pip install 'cryptography==46.0.5' 'idna==3.10'
python3 -c "import cryptography, idna; print(cryptography.__version__, idna.__version__)"
```

Run the documentation and conformance validators:

```sh
python3 scripts/validate_conformance_vectors.py
python3 scripts/validate_security_vectors.py
python3 scripts/validate_domain_separators.py
python3 scripts/validate_rule_ids.py
python3 scripts/validate_spec_tables.py
python3 scripts/validate-docs.py
```

Run the complete unit suite with CI's zero-skip requirement. Ordinary unittest
discovery alone can report success when a required cryptographic suite is skipped.

For a changed rule that distinguishes structural `error` from semantic `fail`,
derive the expected outcome from the spec before building the test. Assert that
the negative case passes every earlier gate it is meant to pass: valid shape,
included signer, authentic signature, nonce, authority and bound inputs. Keep a
separate malformed control. Cover the accepting case, zero/one/multiple-match
boundaries where relevant, and the actual direct, received-JSON and conformance
consumer paths. A negative that is already invalid at an earlier gate cannot
prove the later classifier. Add a bounded wrong-implementation witness to normal
CI for a material regression and pin the reviewer case in
`conformance/pre-review-invariants.json` and `scripts/pre_review_gate.py`.

Two corpus-wide checks run as their own workflow step and in the unit suite:

```sh
python3 -m unittest tests.test_signature_vector_consistency tests.test_guard_witnesses -v
```

**Signature consistency.** `tests/test_signature_vector_consistency.py` walks
every JSON file under `conformance/` and checks each signature object whose
`algorithm` is in the spec's registered enum with `tests/signature_encoding.py`,
which shares its SIG-6 decoder and ECDSA format check with the channel oracle.
A case is any object carrying `expected` or `verdict`, wherever it sits; an
entry of a top-level map that cases name instead of holding (declared in
`SHARED_REFERENCES`, e.g. `executionAuthorityRef` → `executionAuthorities`) is
judged under the verdict of every case naming it. The check compares each
defect with the verdict the case expects and never reads case wording:

- a SIG-6 wire defect (CORE §B.7) is found by every verifier, so the case must
  expect a rejection (`error`, `fail`, `reject` or `rejected`);
- a format defect is found only by a verifier that checks that format and
  answers `fail`, so the case must expect `fail` or `reject`. CORE §B.7 names
  no format, so one is checked only where it is pinned: a 64-byte Ed25519
  value everywhere; the canonical DER low-S `ecdsa-secp256k1` profile only in a
  corpus that pins `signatureEncoding: canonical-DER-low-S` on an
  `ecdsa-secp256k1` key fixture (an unknown pin fails). `sr1-aggregate`, and
  `ecdsa-secp256k1` without a pin, are checked at the wire stage only.
  A pin anywhere in the document, including inside one case, applies to every
  signature of that algorithm in the file; this is a corpus-wide fixture profile.

A corpus whose spec fixes the verdict of each stage declares exactly that in
`VERDICT_CONTRACTS`: the DACS-3 §8.3.3 channel corpus (`error` for a wire
defect, `fail` for a format defect), DACS-1 RSC-7 (`indeterminate` unless
independently authenticated revocation takes precedence, giving corpus verdict
`fail`) and the binary encoding corpus (`reject`). The RSC exception reruns the
corpus's recorded-policy evaluator on the exact input and public keys; it never
trusts the expected verdict or a saved `want` result. A corpus holding current
channel-message signatures must be listed under the DACS-3 contract, regardless
of how its `spec` citation is worded. A case where a `key:` claim signs under another
registered algorithm without expecting a rejection must be listed, with its
reason, in `KEY_CLAIM_RELABELS`. Each offender is reported with file, case,
path and reason. The rules do not model a verdict decided before the signature
check (an earlier structural defect, or an algorithm outside the envelope's
own set); such a case that also carries a defective value needs an allow-list
entry saying so. Fix offenders through their generator; only a value that
cannot decide its case, a released file or an agreed follow-up goes in the
commented `ALLOWED_OFFENDERS` list, scoped to its cases, JSON paths, rules,
algorithm and values, and a stale entry fails.

**Guard witnesses.** A corpus whose cases are said to catch a rule declares
`GUARD_WITNESSES` in its test module (case → guard, a context manager that
removes that guard from the reference, and control cases) and is listed in
`tests/test_guard_witnesses.py`. Each case must keep its committed verdict with
the guard and change without it, while the controls keep theirs.

The gate scans the root documentation files listed in `CLAIM_DOCUMENTS` in
`tests/test_guard_witnesses.py`, plus all Markdown under `docs/` and
`conformance/`. It recognizes the quantified phrases in `CLAIM_PHRASE`, including
passive wording such as "the signature check is disabled". A matching paragraph
must carry this marker inside the paragraph:

```html
<!-- guard-witness-claim: corpus=<set> cases=<a>,<b> [controls=<c>] -->
```

Every listed case needs a witness entry, every `controls`
case must be a declared control of a guard the listed cases witness, and every
case the paragraph names must be in one of the two. A claiming paragraph that
lists `controls` must declare them to be controls (for example, "they are
controls") in a separate sentence without a witness claim. "Access-control",
"version control", and "controls included" do not qualify. The phrase matching
is lexical; it does not establish arbitrary natural-language claims, and files
outside the documented scan scope are not checked. `unwitnessed=<d>` only covers a named
case in a paragraph that makes no such claim; in a claiming paragraph it is
refused, so either add the witness or narrow the claim.

```sh
python3 - <<'PYTEST'
import sys, unittest
result = unittest.TextTestRunner(verbosity=2).run(
    unittest.TestLoader().discover("tests"))
for test, reason in result.skipped:
    print("SKIPPED %s: %s" % (test, reason))
sys.exit(0 if result.wasSuccessful() and not result.skipped else 1)
PYTEST
```

The workflow also runs generator, lifecycle, manifest and other consistency checks;
use its current commands for complete workflow verification. The commands above
do not claim that the selected validators alone reproduce every CI step.

If you add or edit a security-vector set under `conformance/vectors/security/`,
also regenerate the README's set-index table (it is generated, not hand-edited):

```sh
python3 scripts/generate_security_vector_index.py --write
```

Generated payload-attestation vectors have an additional byte-determinism check:

```sh
python3 scripts/generate_payload_attestation_vectors.py --check
```

The vector validator checks machine-readable examples under
[`conformance/vectors/`](./conformance/vectors/), including happy-path,
negative-path, IdentityBundle, and RatingRecord fixtures. The domain-separator,
rule-ID, and spec-table validators catch registry drift, undefined labelled-rule
references, and malformed registry rows before review. The docs validator checks
relative Markdown links and section anchors across the repo. Additive validation,
example, and contributor-support work that does not change v0.1 conformance
semantics is tracked in
[`IMPLEMENTATION_READINESS.md`](./IMPLEMENTATION_READINESS.md).

## v0.1 hardening vs roadmap growth

Keep pull requests narrowly scoped:

- **Good v0.1 hardening:** broken links/anchors, malformed tables, undefined
  labelled-rule references, registry drift, incorrect fixture metadata, or
  dependency-free validators that preserve existing conformance semantics.
- **Roadmap work:** new artifact fields, new phase types, new payment rails,
  expanded privacy/dispute semantics, new conformance obligations, or anything
  that changes what a v0.1 implementation must accept or reject.
- **Prototype fixtures:** shared fixtures under `conformance/fixtures/` are
  non-normative unless a future steward explicitly promotes them to canonical
  vectors under `conformance/vectors/`.

Issue templates under [`.github/ISSUE_TEMPLATE/`](./.github/ISSUE_TEMPLATE/) mirror
the feedback format above for spec defects, implementation reports, and editorial
fixes.

## Built something with DACS?

Tools, reference implementations, integrations, and apps belong in the
[Community repo](https://github.com/DACS-Agent-commerce/Community) — a single PR
with an honest conformance declaration (`vector-tested` / `exercises-spec` /
`prototype`). This repo stays spec-only; building against the standard and
reporting where it breaks is the contribution we value most.
