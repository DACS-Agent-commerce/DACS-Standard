# Release checklist

DACS releases advance `main` to a validated `next` commit by fast-forward and
then annotate that exact commit with the release tag. Stage modules version
independently, so the tag's release note must list the versions that compose the
release rather than imply that every module has the tag's minor version.

## 1. Freeze the candidate

- [ ] All intended normative pull requests are merged to `next`; unresolved
      normative issues and review threads are either closed or explicitly
      deferred.
- [ ] Every normative change appears under `CHANGELOG.md` `[Unreleased]`, and
      each changed module's title/status line carries its intended version.
- [ ] `spec/PROFILE.md` lists the exact CORE and DACS-1..5 version composition.
- [ ] Record the candidate's full `next` commit SHA. Do not add or amend
      normative text or conformance vectors after this point; restart the freeze
      if either changes.

## 2. Pin and validate the frozen revision

- [ ] Update release-facing `ImplementationManifest` examples to a real frozen
      profile commit whose declared document versions match the files at that
      revision.
- [ ] Pin the conformance-suite commit and byte-exact `conformance/MANIFEST.json`
      SHA-256 from that revision. Confirm every declared case ID exists there.
- [ ] Replace `[Unreleased]` with the release tag and date, then restore a new,
      empty `[Unreleased]` section above it.
- [ ] Run every repository validator and the complete unit-test suite with its
      crypto dependency installed. Treat any test skip as a release failure.
- [ ] Push the final metadata commit to `next` and require the `next` push
      workflow to pass on that exact head SHA. A pull-request run for another
      merge commit is not a substitute.
- [ ] Confirm the worktree is clean and `git diff --check` reports no errors.

The metadata commit may follow the frozen content commit so that it can name a
real Git revision. It must not change the normative documents or conformance
corpus it pins.

## 3. Cut the release

- [ ] Fetch the remote and confirm `origin/main` is an ancestor of the final
      `origin/next`; the release must be a fast-forward, not a divergent merge.
- [ ] Fast-forward `main` to the exact validated `next` head and push `main`.
- [ ] Confirm the `main` push workflow passes on that same commit.
- [ ] Create an annotated tag on that commit. The annotation lists the exact
      CORE and DACS-1..5 versions from `spec/PROFILE.md`.
- [ ] Push the tag and verify that `main`, `next`, and the tag resolve to the
      intended commit.

## 4. Post-cut check

- [ ] Check rendered repository links and the tag's changelog on GitHub.
- [ ] Confirm no release-only commit left `main` ahead of `next`.
- [ ] Announce the release with the module-version composition and any explicitly
      deferred work; do not describe candidate vectors as golden unless their
      independent cross-run promotion is complete.
