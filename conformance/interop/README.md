# DACS adapter proposal for issue 270

This directory contains a non-normative, offline proposal for connecting the
Standard's existing deterministic primitives to the language-neutral
`dacs-adapter/1` JSON Lines subprocess boundary. The interface is pinned to
`cX3po/pathos-dacs-ref` commit
`1297dd5f79d2e1305bfd4e8e4b2fa6830bc72eda`; its exported protocol document has
SHA-256
`ce6fd9a13e385a0f41edc2ade231920a36c5960e5c3db9f43ab5a52e9d17e844`.
The interface remains non-normative and is not copied into the Standard.

[`dacs-adapter-release-proposal-v1.json`](dacs-adapter-release-proposal-v1.json)
pins the Standard revision, tree, implementation blobs, source corpora, selected
case identifiers, and expected values. The adapter verifies those local
committed blobs and the exact DACS-Standard Git origin before importing them.
Adapter source identity (`sha256` plus Git blob), wrapped Standard revision, and
wrapped primitive digests remain separate. Repository identity contains no
revision, so two wrappers around DACS-Standard still count as one codebase.
In particular, the contributor `standard-jcs-adapter` and this wrapper cannot be
used as two independent implementations.

The executable operations are:

- `canonicalize`, calling `scripts/jcs.py`;
- `signedScopeHash`, calling
  `scripts/validate_conformance_vectors.py::artifact_hash_hex` for unambiguous
  `SettlementEvidence` and `AttestationBundle` inputs;
- `signatureValueVerdict`, calling
  `scripts/validate_conformance_vectors.py::decode_signature_value` with legacy
  spelling disabled. This operation is encoding-only, as required by F3, and
  does not impose Ed25519's decoded-length rule;
- `domainSepSign` and `domainSepVerify`, calling the existing walkthrough
  Ed25519 primitives under the bounded `listing-single-hash-golden-v1` profile.
  These operation names are advertised, but the generic `domain-sep-sign`
  family is not.

`verifyBundle` and legacy import are not advertised. Unknown operations and
unrecognised artifact shapes return controlled errors. The input loop caps each
request at 1 MiB and five parameters, emits one response line per input line,
and writes bounded plain-text diagnostics only to stderr.

The protocol's BigInt tag cannot be converted to Python `int`: that would erase
the distinction between an ordinary JSON integer and a host-language BigInt.
The decoder returns `UNSUPPORTED_CASE` before JCS and the release descriptor
excludes `bigint-native-type` from executable canonicalization cases. Turning an
opaque Python object into an expected JCS rejection would manufacture coverage.
The current runner maps every operation error to `THROWN`, which would still
look like the expected rejection; it must recognize this explicit unsupported
result as `ABSTAIN` before the BigInt case can enter a shared cross-run.

## Bounded F5 profile

The pinned neutral source defines its bytes as UTF-8 separator, optional
intermediate hash, then `messageBytes`. The bounded profile selects the
Standard's existing Listing golden: the message is the 64 ASCII lowercase-hex
artifact hash, the separator is exactly `dacs-listing:v1:`, and no intermediate
hash is present. It pins signing output, successful verification, and the
in-profile negative control where one lowercase-hex message digit changes while
the signature stays fixed. An unknown non-DACS separator returns `false` on
verification.

The existing Standard test showing that the golden signature does not verify
over the 32 raw digest bytes remains pinned as a primitive-level control. Raw
digest bytes are outside the adapter profile: both signing and verification
return `UNSUPPORTED_CASE` before cryptography, including when a separately
generated raw-digest signature is cryptographically valid.

This is a primitive bridge. It does not parse an artifact, derive its hash,
establish signer authority, admit intermediate hashes, or claim the full CORE
B.7 separator registry. Emission under any separator other than the selected
Listing separator returns `UNSUPPORTED_CASE`; DACS-shaped non-Listing
verification separators and Listing messages outside the 64 lowercase-hex
grammar also return `UNSUPPORTED_CASE`. Those are unsupported inputs, not
failed conformance candidates.

The generic four-family milestone remains incomplete because the shared runner
maps every operation error to an observed `THROWN` outcome. The remaining exact
handoff question is:

> Will the shared runner classify the adapter's explicit `UNSUPPORTED_CASE`
> error as `ABSTAIN` rather than `THROWN`, so BigInt host-type inputs and F5
> cases outside `listing-single-hash-golden-v1` remain unscored?

## Run

From a committed checkout containing this proposal:

```sh
python3 scripts/validate_dacs_adapter_release.py
printf '%s\n' \
  '{"protocol":"dacs-adapter/1","id":"1","type":"metadata"}' \
  '{"protocol":"dacs-adapter/1","id":"2","type":"execute","operation":"canonicalize","params":[{"b":1,"a":2}]}' \
  | python3 scripts/dacs_adapter.py
python3 -m unittest tests.test_dacs_adapter
```

These commands are a Standard self-check. An `INTEROP-AGREE` result requires a
separate adapter from a distinct implementation codebase and a shared runner;
none is claimed by this proposal. The immutable neutral-source export supplied
for this work contains the interface and adapter sources but no self-contained
runner executable or config schema. The reproducible adapter handoff command is
`python3 scripts/dacs_adapter.py`; the neutral runner owner can pass that command
through its documented repeatable `--adapter` option once the runner is
published.
