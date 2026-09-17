# Cross-run evidence provenance proposal

Status: **non-normative design and reference validator for discussion**. This
proposal does not change the existing `diff_vector_runs.py` input, promote a
vector set, establish implementation independence, or adopt a WG runner format.

## Problem and boundary

The legacy cross-run file identifies a set by its filename stem and an
implementation by a free-form string. The comparison then loads expected cases
from the current checkout. A recorded result can therefore still compare after
the set's bytes change while its case names and expected verdicts remain the
same.

`dacs-cross-run-evidence/1` adds immutable coordinates around the unchanged
`set`, `impl`, and `results` fields. It is compatible with the field direction
in the PR #362 evaluation pilot: repository/revision identity stays separate
from environment, result, run-validity, and candidate-disposition claims. It is
also separate from issue #270's `dacs-adapter/1` subprocess protocol. Adapter
outcomes and implementation-independence decisions are outside this proposal.

## Envelope

```json
{
  "schema": "dacs-cross-run-evidence/1",
  "set": "vp-replay-v0.1",
  "impl": "pathos-dacs-ref@1.4.0",
  "corpus": {
    "repository": "https://github.com/DACS-Agent-commerce/DACS-Standard.git",
    "revision": "<40 lowercase hex commit>",
    "path": "conformance/vectors/security/vp-replay-v0.1.json",
    "sha256": "<sha256 of exact raw file bytes>",
    "gitBlob": "<Git blob id of the same bytes>"
  },
  "implementation": {
    "id": "pathos-dacs-ref@1.4.0",
    "repository": "https://github.com/example/pathos-dacs-ref.git",
    "revision": "<40 lowercase hex commit>"
  },
  "runner": {
    "repository": "https://github.com/example/dacs-conformance-runner.git",
    "revision": "<40 lowercase hex commit>",
    "path": "src/cross-run.mjs",
    "sha256": "<sha256 of exact raw file bytes>",
    "gitBlob": "<Git blob id of the same bytes>"
  },
  "results": []
}
```

SHA-256 is over the exact file bytes, without JSON reserialization or newline
normalization. `gitBlob` is the object id returned by `git hash-object` for the
same bytes. The corpus path must be the trusted path resolved by the set name.
The corpus commit must exist in the supplied Standard checkout, must contain
that path as a regular file blob with both recorded digests, and those bytes
must equal the current trusted checkout's bytes. Directories, symbolic links,
and submodules are not artifact files. Git replacement objects are disabled for
all revision and object lookups. The current-byte comparison is what makes an old run
historical after a same-name corpus edit.

Implementation and runner repository/revision fields are always required. They
are mechanically checked when their checkouts are supplied. The runner source
also carries byte and blob digests. Repository identity, revision existence,
and source bytes cannot be authenticated from an unavailable external checkout;
the validator reports only internal consistency in that case. Human review of
implementation independence remains required.

## Reference validation

```sh
python3 scripts/validate_cross_run_evidence.py \
  --runner-checkout /path/to/runner \
  --implementation-checkout /path/to/implementation \
  run-a.json run-b.json
python3 scripts/diff_vector_runs.py run-a.json run-b.json
```

The first command verifies the recorded coordinates and bytes against the
supplied checkouts; it does not prove which code actually executed. Its output
states whether runner and implementation checkouts were verified or their
coordinates remain unverified. The second command retains the existing verdict
and abstention comparison. A legacy file without `schema` remains
accepted by the existing diff tool for compatibility, but has not passed this
validator and must not be described as `dacs-cross-run-evidence/1` or as
mechanically current. Adoption could later integrate the validator into the
diff command; this proposal deliberately leaves that policy decision explicit.

The evidence parser rejects duplicate object keys at any nesting depth and
non-finite `NaN`/`Infinity` constants before it performs Git lookups. The set id
must be one safe filename stem; it cannot supply a path.

## Acceptance controls

The focused tests cover:

- a valid envelope whose corpus, runner, and implementation resolve in Git;
- a corpus input edit that preserves set and case identities but invalidates
  the earlier run as current evidence;
- missing provenance and mismatched digests;
- Git replacement-object substitution and non-file artifact paths;
- duplicate JSON keys, non-finite JSON constants, and unsafe set ids;
- a free-form `impl` label that disagrees with the implementation identity; and
- optional mechanical verification of runner and implementation checkouts.

This format does not claim that a run is valid, or that the recorded runner and
implementation actually executed, merely because the recorded coordinates and
bytes validate. Setup, dependency, adapter, sandbox, verifier, cleanup,
execution identity, and candidate disposition remain distinct evidence
dimensions, as proposed by the PR #362 pilot.
