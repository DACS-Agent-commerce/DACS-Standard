# Independent review protocol

Security-sensitive changes require both human independent review and executable
pre-review evidence. These are complementary controls; a green gate does not
claim that a person performed an independent review or approved the change.

## Human review

Assign a cold, rationale-blind reviewer who was not the implementation owner.
Give the reviewer the exact candidate head, the applicable security properties,
and the affected trust boundary, but do not prime them with the author's repair
rationale or expected conclusion. The reviewer examines the whole boundary,
including unchanged callers, helpers, compatibility paths, and fail-open or
downgrade behavior. Their disposition records attempted counterexamples and the
exact head reviewed. Any head change requires a fresh disposition.

## Executable evidence

`conformance/pre-review-invariants.json` declares the mandatory independent
review lenses. Every lens names runnable counterexample evidence and a distinct
legitimate control. `python3 scripts/pre_review_gate.py` validates the registry
and executes every named test. Missing lenses, missing or duplicated roles,
dangling evidence, unclaimed evidence, invalid surface declarations, and failing
tests fail the gate.

The mandatory evidence IDs, unittest targets, prior-blocker regressions, lens
roles, and declared surfaces are also pinned in `scripts/pre_review_gate.py`.
Adding or replacing a trust-boundary assertion therefore requires a reviewed
update to both the executable registry contract and the manifest; changing
manifest labels alone cannot claim coverage. Each selected target must execute
exactly one successful test: skips, expected failures, unexpected successes,
loader errors, and zero-test selections fail the gate.

The mandatory lenses cover hostile JSON/type totality at public APIs, independent
binding-axis mutation for current FAB delivery, current-versus-archival downgrade
and fallback behavior, direct-helper versus composed-caller parity, and preservation
of legitimate compatibility behavior. Extend the registry when a change introduces
a new trust boundary; never replace a lens with a general-suite or coverage claim.

For the review handoff, report the exact commit, the gate output, and links to the
counterexample/control tests. CI establishes only that this executable evidence
passed on that commit. It does not establish reviewer independence, review scope,
or approval.
