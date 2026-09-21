# Offline pre-review gate

Run `python3 scripts/pre_review_gate.py` before requesting review. The gate
executes the invariant registry in `conformance/pre-review-invariants.json` and
fails when a required case disappears, a declared matrix loses a cell, a vector
no longer produces its complete pinned outcome (verdict and consumer effects),
a control no longer produces its own independently pinned outcome, a negative no
longer differs from its control, or a named prior-blocker unit regression stops
executing.

Current enforced coverage is deliberately narrow:

- RSC-7 same-sequence sibling target presence × artifact authenticity;
- RSC-2 genesis/transition closed-head shape × extra/missing/wrong-type member;
- selected existing round 10, 11, 12, and 14 named blocker regressions.

The registry lists reference reuse, selector exclusivity, and cross-module
composition as `planned`; those labels are extension points, not coverage
claims. Promote one only by adding a complete executable matrix (or named unit
regression), a discriminating control, and tests that make registry drift fail.

Pre-review checklist:

1. Regenerate affected deterministic corpora and indexes.
2. Add every repaired finding as a named, executable case with a positive or
   otherwise observably different control.
3. Complete every declared matrix rather than adding a single example row.
4. Run this gate, all workflow commands, and zero-skip unit-test discovery.
5. Record the exact head SHA and request review only for that immutable head.
