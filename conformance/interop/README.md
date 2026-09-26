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
case identifiers, and expected values. The adapter fixes the wrapped revision,
tree, and the sha256 of each of the four repository modules it executes in its
own source, so the metadata `revision` (the adapter's sha256) covers the code
that runs; the descriptor must repeat exactly those pins. Before executing
anything it wraps, the adapter verifies the committed blobs, the wrapped
revision and tree, and the single `remote.origin.url` in this checkout's local
Git configuration. Each module runs from the bytes that were verified, never
from a re-read file or cached bytecode. On POSIX hosts the adapter re-executes
its interpreter with `-I -S`, so `PYTHONPATH`, the script directory, user and
site packages, and `.pth` hooks take no part in its imports; after
verification an import guard refuses every module that is not part of the
interpreter's standard library. The optional `cryptography` import in
`validate_conformance_vectors.py` is therefore refused and its existing
fallback applies; no advertised operation uses it. These are consistency
checks, not remote attestation or host confinement: the interpreter, its
standard library, `PATH`, and `git` are trusted host inputs.
Adapter source identity (`sha256` plus Git blob), wrapped Standard revision, and
wrapped primitive digests remain separate.

The adapter asserts the revision-free codebase identity
`github.com/DACS-Agent-commerce/DACS-Standard`. Every wrapper around
DACS-Standard is one codebase, so this wrapper and the contributor
`standard-jcs-adapter` cannot be two independent implementations. The pinned
shared runner does not enforce that yet: it compares asserted
`provenanceCodebase` strings after only trimming and lowercasing them, and
`standard-jcs-adapter` asserts
`https://github.com/DACS-Agent-commerce/DACS-Standard@<revision>#scripts/jcs.py`.
Running both adapters through that runner reports `INTEROP-AGREE` with two
independent implementations for the same `scripts/jcs.py`. Such rows are
invalid evidence. Until the runner folds asserted identities to one
revision-free codebase, any run that includes more than one Standard wrapper
must give each of them the same
`--adapter-provenance github.com/DACS-Agent-commerce/DACS-Standard` override.

The executable operations are:

- `canonicalize`, calling `scripts/jcs.py`;
- `signedScopeHash`, calling
  `scripts/validate_conformance_vectors.py::artifact_hash_hex` for unambiguous
  `SettlementEvidence` and `AttestationBundle` inputs. CORE §11.2.5 gives every
  artifact type its own `*Version` literal, and the spec shapes of these two
  kinds carry no other top-level `*Version` member except the bundle's
  `recipeRegistryVersion` and `railRegistryVersion`. A record with any other
  `*Version` member, or any other shape, returns `UNSUPPORTED_CASE` and is
  never hashed as the kind it resembles. The shared runner's seed vector
  `dr-d4-settlement-golden-match`, which has no `phase`, therefore abstains;
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
request at 1 MiB and five parameters, accepts only strict UTF-8 JSON (no `NaN`
or `Infinity` literals and no duplicate member names), reports every
request-decoding failure as `INVALID_JSON`, emits one response line per input
line, and writes one bounded line of printable ASCII per diagnostic, only to
stderr. A rejection by a wrapped primitive is `OPERATION_FAILED`; any other
fault is `INTERNAL_ERROR`, which a runner must never score as an expected
rejection. Requests are bounded in size, not time. CPython's NFC normalization
is quadratic in long runs of combining marks (a 200 KB string can take over
ten seconds), so callers must enforce a per-request timeout, as the shared
runner does by default; a timeout is never a result.

The canonicalization descriptor partitions all 25 source cases: six are
selected, `bigint-native-type` is unsupported, twelve are excluded because their
Standard-only `binary64` or `unicode-code-units` tagged inputs cannot be carried
by `dacs-adapter/1`, and six expressible cases stay outside the frozen
first-milestone selection. Selecting them needs a new release descriptor.

The protocol's BigInt tag cannot be converted to Python `int`: that would erase
the distinction between an ordinary JSON integer and a host-language BigInt.
The decoder returns `UNSUPPORTED_CASE` before JCS and the release descriptor
excludes `bigint-native-type` from executable canonicalization cases. Turning an
opaque Python object into an expected JCS rejection would manufacture coverage.
The current runner maps every operation error to `THROWN`, which would still
look like the expected rejection; it must recognize this explicit unsupported
result as `ABSTAIN` before the BigInt case can enter a shared cross-run.
A BigInt never masks a malformed request: the whole request is decoded first,
so a malformed tag elsewhere is `MALFORMED_TAG`, and each operation checks its
parameter count and types before abstaining on a BigInt.

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

The pinned neutral protocol lists the intermediate hash as an optional final
parameter, and the shared runner sends an omitted optional argument as a
trailing JSON `null`. The adapter treats that `null` as absent, so an in-profile
case keeps its `true`, `false`, or signature result; a supplied intermediate
hash, even an empty one, returns `UNSUPPORTED_CASE`. Parameters of the wrong
type (including a BigInt), or a private key that is not 32 bytes, return
`INVALID_PARAMS` before any profile decision, so a malformed request is never
reported as unsupported or as a `false` verdict. A signature or public key of
the wrong length is a well-formed request whose verification fails, so it
returns `false`, as the reference adapter does.

Ed25519 point-encoding strictness is not pinned by CORE or by this profile. The
wrapped helper accepts an `x = 0` point encoding with the sign bit set, which
RFC 8032 decoding rejects; OpenSSL rejects that encoding for `R`. No such case
is selected. A divergence there would be an open specification question, not
evidence against either implementation.

The generic four-family milestone remains incomplete because the shared runner
maps every operation error to an observed `THROWN` outcome. It dispatches by
operation name, so leaving `domain-sep-sign` out of `supportedFamilies` does
not stop it from sending every seed F5 vector to this adapter. On the pinned
runner an explicit `UNSUPPORTED_CASE` therefore matches any vector that
expects `THROWN`: paired with the reference adapter, the seed rows
`cr-bigint`, `ds-s3-unknown-separator-sign-throws`, and
`ds-s6-legacy-emission-refused` report `INTEROP-AGREE` although this adapter
abstained. No scored run may use that runner. The remaining exact handoff
questions are:

> Will the shared runner classify the adapter's explicit `UNSUPPORTED_CASE`
> error as `ABSTAIN` rather than `THROWN`, so BigInt host-type inputs and F5
> cases outside `listing-single-hash-golden-v1` remain unscored?

> Will the shared runner fold every asserted DACS-Standard codebase identity,
> with or without a revision or path qualifier, to one codebase before counting
> independent implementations?

## Run

From a committed checkout containing this proposal and the wrapped revision
object (for example, full history), with Python 3.10 or later:

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
none is claimed by this proposal. The exported companion inputs pinned in the
descriptor do not include the runner, but the pinned public revision does
(`conformance/shared-suite/cross-run.mjs`, with repeatable `--adapter` and
`--adapter-provenance` options). That runner still maps `UNSUPPORTED_CASE` to
`THROWN`, and its own seed-corpus lock (`PINNED-SOURCES.json`) no longer matches
the committed `partner-kit/vectors.json`, so its command line refuses to run
until that lock is corrected. The reproducible adapter handoff command is
`python3 scripts/dacs_adapter.py`.
