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
  does not impose Ed25519's decoded-length rule.

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

## F5 blocker — first interoperability milestone incomplete

This is an unsupported mapping, not a failed conformance candidate. The exact
handoff question for the neutral runner owner is:

> For `dacs-adapter/1` F5, does `messageBytes` mean the complete bytes after the
> separator, with `intermediateHashBytes` absent for CORE B.7 single-hash cases,
> and will the runner classify an explicit unsupported-case result as `ABSTAIN`?
> If not, should F5 add an explicit Standard payload-grammar or artifact-kind
> parameter before DACS-Standard advertises `domainSepSign`/`domainSepVerify`?

CORE B.7 defines single-hash signed bytes as UTF-8 `domain_separator` followed
by the ASCII lowercase-hex SHA-256 artifact hash. It separately defines three
composite payload grammars. F5 accepts arbitrary `messageBytes`, a separator,
and an optional `intermediateHashBytes` value, but does not identify which
Standard grammar those bytes represent. The shared runner also treats an
operation error as an observed mismatch, rather than a case-level abstention.
Advertising `domainSepSign` or `domainSepVerify` would therefore overstate the
mapping or require inventing a new byte contract. The release descriptor pins
the Standard's existing domain-separated signing case and exact expected bytes,
records this family as blocked, and the validator reproduces it directly with
the existing Ed25519 helpers. The adapter does not advertise F5.

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
none is claimed by this proposal.
