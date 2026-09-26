# Finality resolution timing evidence

The #392 D2 reference benchmark measures local verification elapsed time separately
from response acquisition. Run it from the repository root with the pinned
test runtime:

```sh
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=tests:scripts \
  python3 scripts/benchmark_finality_resolution_context.py \
  --warmup 100 --samples 1000
```

The script loads the deterministic
`finality-resolution-context-v1.json` fixture and constructs verifier-owned
trust before timing. Each sample surrounds only `verify_finality` with
`time.perf_counter_ns`; JSON loading, fixture generation, signing and trust
setup are excluded. Its JSON output records Python and dependency versions,
the repository commit and dirty state, fixture hash, registered fixture
binding, fixed authority count, warm-up and sample counts, median, nearest-rank
p95, minimum and maximum. A result from a dirty worktree does not claim that
HEAD is the exact candidate; retained acceptance evidence must be rerun on the
clean reviewed commit.

The included acquisition numbers are a deterministic illustration, not a
network benchmark. For the registered two-seat all-authorities fixture, sample
response delays of 120 ms and 410 ms have a sequential sum of 530 ms. A
concurrent acquisition implementation cannot complete full coverage before
the slowest required seat, so the modeled lower bound is 410 ms plus scheduling
and verification overhead. The reference code does not implement or measure
parallel transport.

If a required response never arrives, the modeled wait reaches the query's
6,000 ms acquisition deadline and the result remains `indeterminate`. An
authenticated explicit-unavailable response may establish that same
non-authorizing disposition before the deadline when it arrives; the document
does not assign a fabricated arrival time. Partial coverage never passes, and
the timeout is taken from the issued query rather than selected to improve the
benchmark.

These clocks have separate meanings:

- `signedObservationTime` is produced and signed by an observation authority.
- The authenticated checkpoint fixes the native observation boundary.
- `acquiredAt` is verifier-local evidence that the exact response was
  obtained for the issued nonce.
- `issuedAt` and `expiresAt` bound verifier acquisition.
- `perf_counter_ns` measures monotonic host-local elapsed time around
  verification.

Instrumentation does not enter signed response bytes, canonical hashes,
queries, replay records or four-value verdicts. The Standard sets no latency
threshold or production SLA. Historical single-view timing would measure a
weaker evidence contract and must not be described as equivalent-work D2
overhead.

Production timing work remains deferred until native mappings are registered.
That work needs observed provider latency distributions, shared failure and
correlation, timeout rates, authority-set size, request concurrency, freshness
and replay-safe cache limits, retries, and clock-boundary behavior. The
fixture-only measurements do not imply production support.
