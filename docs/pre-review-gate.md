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
- RB-4/RB-5 and RSC non-membership composition across absent, revoked, and
  unavailable discovery results;
- the sequence-selected genesis/transition head union, including each valid
  arm and both arm/body mismatches;
- exact revocation-reference use across consumed, duplicated, shadowed,
  wrong-target, and unused references;
- CORE §B.2 normative primitive parity for RSC hashing and signing, including
  rejection of an artifact signed by the legacy sorted-JSON helper with an
  unsupported integer magnitude;
- selected existing round 10, 11, 12, and 14 named blocker regressions.

The registry records reference reuse, selector exclusivity, and cross-module
composition as covered only through the matrix IDs that execute them. A claim
whose matrix is missing or does not declare that invariant class fails manifest
validation. Each matrix pins the complete result independently from the corpus,
executes a discriminating control with its own pinned result, and rejects
missing cells or extra/missing consumer effects.

This is targeted RSC/RB coverage, not a claim that every selector, reference,
or module composition elsewhere in DACS is exhaustively enumerated. New protocol
arms and new cross-module joins still require their own complete matrices before
review.

The JCS regression exercises the decoded object-model boundary. CORE CF-5 raw
token admission (including duplicate member names and non-canonical numeric
spellings) remains a separate upstream responsibility: externally supplied JSON
bytes must pass the repository's strict raw-input profile before object-model
canonicalization.

Pre-review checklist:

1. Regenerate affected deterministic corpora and indexes.
2. Add every repaired finding as a named, executable case with a positive or
   otherwise observably different control.
3. Complete every declared matrix rather than adding a single example row.
4. Run this gate, all workflow commands, and zero-skip unit-test discovery.
5. Record the exact head SHA and request review only for that immutable head.
