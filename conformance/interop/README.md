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
pins the Standard revision, tree, complete repository-local Python import
closure for its advertised operations, source corpora, selected case identifiers,
and expected values. The adapter derives that five-file closure before imports
and requires its path set and every committed blob to match the descriptor. The
closure is `scripts/jcs.py`, `scripts/run_lifecycle_walkthrough.py`,
`scripts/dacs_reference.py`, `scripts/validate_conformance_vectors.py`, and
`scripts/specsource.py`; adding or removing a reachable local import therefore
requires a descriptor update. The adapter also verifies the exact DACS-Standard
Git origin before importing those files.
Adapter source identity (`sha256` plus Git blob), wrapped Standard revision, and
wrapped primitive digests remain separate. `provenanceCodebase` identifies the
wrapped DACS-Standard codebase without a revision. Wrappers that retain the same
assertion can be compared as a one-codebase self-check, even when their wrapper
repository URLs differ. The pinned contributor runner has not established
equivalence between asserted provenance and repository-derived identity when an
adapter omits the optional assertion. Until that boundary is repaired and
regression-tested, an `INTEROP-AGREE` result involving this adapter must not be
accepted or cited as independent interoperability evidence. In particular,
the contributor `standard-jcs-adapter` and this wrapper are not two independent
implementations.

The current descriptor advances the wrapped Standard and selected source pins
without rewriting the recorded runner execution. The exact descriptor bytes
used by the accepted `c799a163` run remain under
[`frozen/`](frozen/dacs-adapter-release-proposal-c799-v1.json); the historical
packet validator checks that fixture's original SHA-256 digest before deriving
its expected operations and outcomes.

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
none is claimed by this proposal. The pinned acceptance run does not test mixed
asserted and repository-derived identity metadata. The immutable neutral-source
export supplied for this work contains the interface and adapter sources but no
self-contained runner executable or config schema. The reproducible adapter
handoff command is `python3 scripts/dacs_adapter.py`. The neutral runner owner
can pass that command through its documented repeatable `--adapter` option once
the runner is published.

## Pinned runner acceptance packet

[`runner-acceptance-v1.json`](runner-acceptance-v1.json) records a separate,
non-normative execution of the contributor's replacement runner patch against
the frozen Standard commit `c799a163e80bff867ba01bc9e08f15ab7916e139`.
It is not a `dacs-cross-run-evidence/1` envelope: that proposal deliberately
does not execute adapters or establish implementation independence.

Reproduce the packet from two disposable fixture checkouts. Setup applies the
contributor's exact public patch to the newly cloned runner fixture; after that,
the producer leaves pinned and tracked source bytes unchanged and verifies their
pins again after execution. It does not write to an existing contributor
checkout. Python imports may still create ignored interpreter cache files.

The committed packet and validator intentionally pin the executed runtimes:
Node v24.19.0 with OpenSSL 3.5.7, and Python 3.12.6 with
`cryptography==46.0.5` and `idna==3.10`. Set `DACS_NODE` and `DACS_PYTHON` to
absolute executables providing those versions. A different runtime produces a
packet that the offline validator rejects.

```sh
(
set -eu
: "${DACS_NODE:=$(realpath "$(command -v node)")}"
: "${DACS_PYTHON:=$(realpath "$(command -v python3)")}"
case "$DACS_NODE" in /*) ;; *) echo 'DACS_NODE must be absolute' >&2; exit 1;; esac
case "$DACS_PYTHON" in /*) ;; *) echo 'DACS_PYTHON must be absolute' >&2; exit 1;; esac
DACS_ACCEPTANCE_TMP="$(mktemp -d)"
DACS_RUNNER_DIR="$DACS_ACCEPTANCE_TMP/pathos-dacs-ref"
DACS_STANDARD_DIR="$DACS_ACCEPTANCE_TMP/dacs-standard-c799"
DACS_RUNNER_PATCH="$DACS_ACCEPTANCE_TMP/runner-replacement.patch"

"$DACS_NODE" -e 'if (process.version !== "v24.19.0" || process.versions.openssl !== "3.5.7") process.exit(1)'
"$DACS_PYTHON" -c 'import platform,cryptography,idna; assert (platform.python_version(),cryptography.__version__,idna.__version__)==("3.12.6","46.0.5","3.10")'

git clone --no-checkout https://github.com/cX3po/pathos-dacs-ref.git "$DACS_RUNNER_DIR"
git -C "$DACS_RUNNER_DIR" checkout --detach 1297dd5f79d2e1305bfd4e8e4b2fa6830bc72eda
curl -fsSL -H 'Accept: application/vnd.github+json' \
  https://api.github.com/repos/DACS-Agent-commerce/DACS-Standard/issues/comments/5696719263 \
  | "$DACS_PYTHON" -c 'import json,re,sys; body=json.load(sys.stdin)["body"]; match=re.search(r"```diff\n(.*?)\n```",body,re.S); assert match; sys.stdout.write(match.group(1)+"\n")' \
  > "$DACS_RUNNER_PATCH"
"$DACS_PYTHON" -c 'import hashlib,pathlib,sys; actual=hashlib.sha256(pathlib.Path(sys.argv[1]).read_bytes()).hexdigest(); assert actual=="178d58f2682a145810e6ec7611d3b348c502c2cd94917231e97360973bb6639d", actual' "$DACS_RUNNER_PATCH"
git -C "$DACS_RUNNER_DIR" apply "$DACS_RUNNER_PATCH"

git clone --no-checkout https://github.com/DACS-Agent-commerce/DACS-Standard.git "$DACS_STANDARD_DIR"
git -C "$DACS_STANDARD_DIR" checkout --detach c799a163e80bff867ba01bc9e08f15ab7916e139

"$DACS_NODE" scripts/run_adapter_runner_acceptance.mjs \
  --runner "$DACS_RUNNER_DIR" \
  --runner-patch "$DACS_RUNNER_PATCH" \
  --standard "$DACS_STANDARD_DIR" \
  --python "$DACS_PYTHON" > "$DACS_ACCEPTANCE_TMP/runner-acceptance-v1.json"
"$DACS_PYTHON" scripts/validate_adapter_runner_acceptance.py \
  "$DACS_ACCEPTANCE_TMP/runner-acceptance-v1.json"
"$DACS_PYTHON" scripts/validate_adapter_runner_acceptance.py
"$DACS_PYTHON" -m unittest tests.test_adapter_runner_acceptance
)
```

The producer verifies the runner origin, base commit, replacement patch and
every imported source byte before importing contributor code. It separately
pins the Standard origin, head, tree, descriptor, adapter, primitives and
corpora, then rechecks runner and Standard pins after execution. Missing or
mismatched inputs stop the run. Every expected row value is built from the
frozen descriptor and its pinned corpora. The expected bounded result
is 18 `SELF-CHECK` rows and two `ABSTAIN` rows, with no `INTEROP-AGREE`: two
runner processes wrap the same Standard implementation. The packet also checks
that `UNSUPPORTED_CASE` abstains before scoring, launch and protocol failures
are `ERROR`, and the in-profile cryptographic mismatch returns `false`.
It also reruns the contributor's 16 focused tests with zero skips. On macOS the
focused suite needs `TMPDIR` resolved to its physical path because its temporary
CLI copy compares a file URL with `argv[1]`; the producer sets that canonical
path and the packet records the fact that canonicalization occurred, without
recording the machine-local path. The packet labels its additional launch and
malformed-protocol checks as exported-function probes, distinct from the focused
suite's actual CLI exit-2 regression.

The offline Python validator checks the recorded coordinates, complete case
set, outcomes and internal consistency. It does not prove that the producer ran
or certify execution on a hostile host; the separately executed producer run is
the evidence source for the committed packet.

This recipe makes no claim about an independent implementation, the full
legacy/default corpus, a live system, or a generic domain-separation profile.
