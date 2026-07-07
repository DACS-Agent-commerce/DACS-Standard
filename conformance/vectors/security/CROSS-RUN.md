# Cross-run protocol — candidate → golden promotion

The sets in this directory are **candidate tier**: authored by one
implementation, not yet proven to produce identical verdicts across
independent implementations. A set is promoted toward the golden suite when
at least two independent impls **converge** on it. This page is the mechanical
protocol for that — replacing the hand-compared result tables in issue
threads (#146, #159, #170) with a diffable artifact.

## 1. Emit a run file

Run your implementation over a set and write one JSON file — any language,
any runner, only the output shape is fixed:

```json
{
  "set":  "vp-replay-v0.1",
  "impl": "pathos-dacs-ref@1.4.0",
  "results": [
    { "name": "valid-holder-binding", "verdict": "pass" },
    { "name": "cross-session-nonce-replay", "verdict": "fail" }
  ]
}
```

- `set` — the set's name (its filename stem in this directory).
- `impl` — free-form implementation id; include a version.
- `results` — one entry per vector, keyed by the vector's `name`, carrying
  the verdict your implementation actually produced (not the expected one).

## 2. Diff

```sh
python3 scripts/diff_vector_runs.py run-yourimpl.json [run-otherimpl.json ...]
```

The `set` resolves to either a security set (`conformance/vectors/security/<set>.json`,
`vectors[{name}]`) or a golden identity fixture (`conformance/fixtures/identity/<set>.json`,
`cases[{id}]`) — so a control-gate cross-run diffs directly, no hand-built mirror. A run entry's
case is keyed by `name` (a fixture `id` works too).

```sh
```

Every run is checked against the set's expected verdicts, and any two runs
over the same set are checked against each other, case by case. Full
agreement prints `cross-run CONVERGED` — attach that output (or the run
files) to the tracking issue as the convergence evidence. Any divergence is
listed per case and exits non-zero; a divergence is a finding about either an
implementation or the set itself, and belongs on the set's tracking issue.

## 3. Promotion

Convergence does not auto-promote. The steward reviews the evidence and
decides whether the set enters the canonical §14 surface
(`conformance/MANIFEST.json`); until then it stays candidate tier. The
promotion bar: at least **two independent implementations** converged on the
full set, and the set passes `scripts/validate_security_vectors.py`.

## Conventions for new sets

`scripts/validate_security_vectors.py` (CI-enforced) requires each set to
carry `set` (== filename stem), `spec`, `count` (== `vectors.length`),
`hash`, and a non-empty `vectors` array with unique per-vector `name`s and a
verdict field (`expected`) drawn from the documented vocabularies.

**Hash.** `hash` is sha256 over the JSON of the `vectors` array. Existing
sets used three slightly different canonical encodings (all accepted by the
validator); **new sets SHOULD use compact, sorted-keys, UTF-8** — in Python:

```python
hashlib.sha256(json.dumps(vectors, separators=(",", ":"),
               sort_keys=True, ensure_ascii=False).encode("utf-8")).hexdigest()
```

**README index.** Do not hand-edit the set table in the README — it is
generated. After adding a set, run:

```sh
python3 scripts/generate_security_vector_index.py --write
```
