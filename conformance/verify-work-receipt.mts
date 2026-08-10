/**
 * Executable reference verifier for the proposed Atomic-DACS Work-receipt and
 * absence-proof profile (RFC #320). It makes receipt acceptance independent of
 * Indexer hydration, as required by the receipt-without-Indexer work in #973.
 *
 * Run `node conformance/verify-work-receipt.mts` for the human-readable
 * conformance table, or append `--json` for a machine-readable summary.
 * `--expect-count <n>` additionally asserts the executed corpus size.
 *
 * Runtime: Node.js >= 22.18.0 (or >= 23.6.0), which strips TypeScript types
 * natively. The file uses erasable syntax only and imports nothing outside
 * `node:` builtins, so the gate needs no package manager, lockfile, or network
 * *package* install — pinning the Node version alone makes it reproducible. The
 * CI runner still downloads the Node runtime itself, so this is reproducible
 * rather than hermetic.
 *
 * TRUST BOUNDARY — read this before adopting.
 *
 * CALLERS MUST SUPPLY ALREADY-BOUND VERIFICATION RESULTS. Each `ProofStatus` is a
 * DETACHED enum that this file takes on trust as the output of an upstream cryptographic
 * verifier. This file performs NO cryptographic verification: it does not check a Merkle
 * path, a quorum certificate, or a signature, and it cannot detect a `valid` label
 * attached to a proof over some OTHER subject. Binding a proof result to the receipt,
 * header, and state identities it is claimed to cover is the CALLER's obligation.
 *
 * What this file does guarantee is narrower and purely structural: a `pass` is never
 * reachable on labels alone. A receipt must carry the workId -> txHash -> block ->
 * receiptRoot binding, a rollback must carry operation results consistent with its
 * outcome, and slot/settlement identity must be real material rather than empty strings.
 * Absent that structure the verdict degrades, so an adopter cannot receive `pass` for a
 * receipt that names no Work — but `pass` still means "these supplied proof results, if
 * honestly produced over the right subjects, are internally coherent", NOT "the receipt
 * was cryptographically verified".
 *
 * Verdict precedence, applied uniformly: CONTRADICTED material (an invalid proof, roots
 * that disagree, a receipt contradicting its own outcome) outranks MISSING material. A
 * contradiction rejects regardless of structure; only absent evidence degrades to
 * indeterminate. Missing evidence is not counter-evidence.
 *
 * Profile-hardening notes for the Standard profile (from adversarial review):
 *  (A) ENFORCED (was a SHOULD): slot-key / root / identity components must each be a
 *      non-empty string or a NON-NEGATIVE INTEGER. `undefined`/`null` are absent, and so now
 *      are `''`, negative numbers and non-integers — an empty identifier compares equal to another
 *      empty identifier, so admitting it let two sides "match" on nothing and reach
 *      `pass`. A SHOULD in a comment does not make an exported `pass` fail-closed.
 *  (B) Verdict chains are outcome-scoped: a `rolled-back` receipt is judged on
 *      its declared chain (inclusion/finality/validatorSet + businessRootEquality)
 *      and does NOT reject on a stray invalid proof outside that chain (e.g. a
 *      `winnerStateProof` that only applies to a `committed` outcome). Consumers
 *      MUST NOT assume any-invalid-proof-anywhere -> reject.
 *  (C) Slot-key comparison is TYPE-STRICT (`0 !== "0"`). Encoders MUST normalize
 *      phaseIndex to a number. A type mismatch fail-safes AWAY FROM `pass`, but the
 *      verdict is `indeterminate`, not `reject`: a wrongly-typed phaseIndex fails
 *      `isIndex`, so that side's proven slot is untrusted and the pair is UNKNOWN
 *      rather than contradicted. (This note previously said `reject`, which the
 *      payment-slot lane does not do — corrected to match the code, since a note
 *      describing a verdict the verifier never returns is worse than no note.)
 *  (D) Payment-slot identity is the structured canonical tuple attested by the
 *      verified slot-state proof, never a claimant-presented label. This closes
 *      encoding-drift evasions (alias, zero-padding, delimiter ambiguity) while
 *      refusing to reject on unbound labels alone.
 *  (E) ENFORCED (was a SHOULD): a valid slotStateProof must carry a proof-derived
 *      `slotTransition`. Valid-proof-with-absent-transition degrades the pair to
 *      indeterminate rather than a non-consuming `pass`, and per note (A) phaseIndex
 *      is trusted only as a non-negative integer.
 */

import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

export type Verdict = 'pass' | 'indeterminate' | 'reject' | 'fail';

// Profile-proposed; refine when the Standard profile lands.
type ProofStatus = 'valid' | 'invalid' | 'absent';

// Profile-proposed; refine when the Standard profile lands.
interface WorkReceiptProofObservation {
  kind: 'work-receipt-proof';
  receipt?: {
    outcome?: string;
    preBusinessStateRoot?: string;
    postBusinessStateRoot?: string;
    [field: string]: unknown;
  };
  receiptInclusionProof?: ProofStatus;
  finalityProof?: ProofStatus;
  validatorSetProof?: ProofStatus;
  winnerStateProof?: ProofStatus;
  paymentSlotStateProof?: ProofStatus;
  businessRootEqualityProof?: ProofStatus;
  /**
   * Discovery telemetry only. Proofs MUST be self-standing; Indexer hydration
   * does not contribute to any verification verdict (#973 posture).
   */
  usedIndexerHydration?: boolean;
}

// Profile-proposed; refine when the Standard profile lands.
interface AbsenceClaimObservation {
  kind: 'absence-claim';
  evidence?: {
    kind?: string;
    proof?: ProofStatus;
    /**
     * Verifiers MUST DERIVE this from the VERIFIED proof type (e.g.
     * consumed-nonce / non-replayable-rejection => terminal; height-scoped
     * point-in-time non-membership => NEVER terminal), not read a
     * claimant-supplied flag. Modeled here as an already-derived input.
     */
    verifiedCannotLaterInclude?: boolean;
    /**
     * The subject this absence evidence is bound to. An absence verdict authorises
     * resubmission, so the evidence must name the Work and attempt it covers; a proof
     * over a different subject must not license a replacement here.
     */
    subjectWorkId?: string;
    subjectAttempt?: number;
    [field: string]: unknown;
  };
  /** The Work actually under question. The evidence's subject must match it. */
  claimedWorkId?: string;
  claimedAttempt?: number;
  [field: string]: unknown;
}

// Profile-proposed; refine when the Standard profile lands.
interface SettlementEvidenceObservation {
  kind: 'settlement-evidence';
  /**
   * Already-derived input, same footing as a verified signatureProof; a real
   * consumer derives it from signature verification.
   */
  signatureValid?: boolean;
  signatureProof?: ProofStatus;
  evidenceJobId?: string | null;
  anchorJobId?: string | null;
  evidenceRailId?: string | null;
  anchorRailId?: string | null;
  evidencePhaseIndex?: number | null;
  anchorPhaseIndex?: number | null;
  [field: string]: unknown;
}

// Profile-proposed; refine when the Standard profile lands.
interface PaymentSlotIdentity {
  networkId?: string;
  railId?: string;
  jobId?: string;
  phaseIndex?: number;
}

interface PaymentSlotWork {
  slotStateProof?: ProofStatus;
  slotTransition?: string;
  /** Consensus-canonical tuple attested by slotStateProof. */
  provenSlot?: PaymentSlotIdentity;
  /** Optional claimant-presented/display label; never used for a verdict. */
  slot?: PaymentSlotIdentity;
  [field: string]: unknown;
}

// Profile-proposed; refine when the Standard profile lands.
interface PaymentSlotObservation {
  kind: 'payment-slot';
  firstWork?: PaymentSlotWork;
  secondWork?: PaymentSlotWork;
  ledgerLevelCAS?: boolean;
  [field: string]: unknown;
}

// Profile-proposed; refine when the Standard profile lands.
interface UnknownObservation {
  kind: string;
  [field: string]: unknown;
}

export type Observation =
  | WorkReceiptProofObservation
  | AbsenceClaimObservation
  | SettlementEvidenceObservation
  | PaymentSlotObservation
  | UnknownObservation;

const isAbsent = (value: unknown): boolean =>
  value === undefined || value === null;

/**
 * Identifier material must be a NON-EMPTY string. An empty string is not an identifier:
 * it carries no binding, yet compares equal to another empty string, so treating `''` as
 * present let two sides "match" on nothing at all and reach `pass`. Formerly note (A) as a
 * SHOULD; a SHOULD in a comment does not make an exported `pass` fail-closed, so it is
 * enforced here.
 */
const isIdentifier = (value: unknown): value is string =>
  typeof value === 'string' && value.trim().length > 0;

/**
 * Heights and indices must be NON-NEGATIVE INTEGERS. Finiteness alone admitted `-1` and
 * `0.5` as block heights and phase indices, which name no block and no phase; the profile
 * defines both as counting numbers.
 */
const isIndex = (value: unknown): value is number =>
  typeof value === 'number' && Number.isInteger(value) && value >= 0;

/**
 * Statuses that are consistent with a rolled-back Work. A rollback does not require every
 * operation to carry `rolled-back`: operations after the failure point were never applied,
 * so `not-executed` (and a `failed` operation, typically the failure itself) are part of a
 * coherent rollback sequence. Requiring `rolled-back` on every entry would degrade a
 * legitimate receipt to indeterminate. `committed` is absent from this set deliberately —
 * that is the self-contradiction handled as a reject above.
 */
const ROLLBACK_CONSISTENT_STATUSES: ReadonlySet<string> = new Set([
  'rolled-back',
  'not-executed',
  'failed',
]);

const isRecord = (value: unknown): value is Record<string, unknown> =>
  typeof value === 'object' && value !== null && !Array.isArray(value);

/**
 * The minimum proof-BINDING every receipt must carry before any verdict may rely on its
 * declared outcome: the identity chain this profile proposes in RFC #320,
 * workId -> txHash -> block -> receiptRoot.
 *
 * Without it, `outcome: 'committed'` is an unbacked claimant label — the receipt names no
 * Work, no transaction, and no block, so a caller receiving `pass` would be told a receipt
 * was verified when nothing tied it to chain state at all. Absent binding is UNKNOWN
 * (indeterminate), not contradicted (reject): missing evidence is not counter-evidence.
 */
function hasReceiptBinding(receipt: Record<string, unknown>): boolean {
  return isIdentifier(receipt.workId)
    && isIdentifier(receipt.txHash)
    && isIdentifier(receipt.receiptRoot)
    && isIndex(receipt.blockHeight);
}

function verifyProofChain(statuses: Array<ProofStatus | undefined>): Verdict {
  if (statuses.some((status) => status === 'invalid')) return 'reject';
  if (statuses.some((status) => status !== 'valid')) return 'indeterminate';
  return 'pass';
}

function verifyReceiptProof(obs: WorkReceiptProofObservation): Verdict {
  const common = [
    obs.receiptInclusionProof,
    obs.finalityProof,
    obs.validatorSetProof,
  ];

  // Contradiction outranks EVERY structural gate, including a missing receipt object. The
  // common chain applies to any outcome, so an invalid inclusion/finality/validator-set
  // proof rejects even when there is no receipt at all — otherwise a claimant could
  // downgrade contradicted proof material to "unknown" simply by omitting the receipt.
  if (common.some((status) => status === 'invalid')) return 'reject';

  if (!obs.receipt || typeof obs.receipt !== 'object') return 'indeterminate';

  // PRECEDENCE, consistent with verifyPaymentSlot: CONTRADICTED material outranks MISSING
  // material. An invalid proof, or a rollback whose roots disagree, is counter-evidence and
  // rejects regardless of how well-formed the receipt is — a well-bound receipt with a failed
  // inclusion proof is still a reject. Only after no contradiction is found does absent
  // structure degrade the verdict to indeterminate.
  //
  // The chain is OUTCOME-SCOPED, per note (B): only proofs that BEAR on the declared outcome
  // can contradict it. A stray invalid `winnerStateProof` (a committed-outcome proof) must not
  // reject a rolled-back receipt, and a stray invalid `businessRootEqualityProof` must not
  // reject a committed one. Scoping this globally was a regression against note (B), which
  // tells consumers explicitly not to assume any-invalid-proof-anywhere means reject.
  const outcome = obs.receipt.outcome;
  const scopedChain = outcome === 'committed'
    ? [...common, obs.winnerStateProof, obs.paymentSlotStateProof]
    : outcome === 'rolled-back'
      ? [...common, obs.businessRootEqualityProof]
      : common;
  if (scopedChain.some((status) => status === 'invalid')) return 'reject';
  const { preBusinessStateRoot, postBusinessStateRoot } = obs.receipt;
  if (obs.receipt.outcome === 'rolled-back') {
    if (
      isIdentifier(preBusinessStateRoot) && isIdentifier(postBusinessStateRoot) &&
      preBusinessStateRoot !== postBusinessStateRoot
    ) {
      return 'reject';
    }
    // A receipt that contradicts ITSELF is contradicted material: an operation still marked
    // `committed` under a `rolled-back` outcome is counter-evidence, and outranks any missing
    // binding below. Checked here so the self-contradiction is not masked as merely unknown.
    if (Array.isArray(obs.receipt.operationResults) && obs.receipt.operationResults.some(
      (result) => isRecord(result) && result.status === 'committed',
    )) {
      return 'reject';
    }
  }

  // Structure before labels. `outcome` is a claimant-supplied string and means nothing until
  // the receipt carrying it is bound to chain state, so a receipt object containing only
  // `outcome` can never reach `pass` on proof statuses alone.
  if (!hasReceiptBinding(obs.receipt)) return 'indeterminate';

  if (obs.receipt.outcome === 'committed') {
    return verifyProofChain([
      ...common,
      obs.winnerStateProof,
      obs.paymentSlotStateProof,
    ]);
  }

  if (obs.receipt.outcome === 'rolled-back') {
    const proofVerdict = verifyProofChain([
      ...common,
      obs.businessRootEqualityProof,
    ]);
    if (proofVerdict !== 'pass') return proofVerdict;

    if (!isIdentifier(preBusinessStateRoot) || !isIdentifier(postBusinessStateRoot)) {
      return 'indeterminate';
    }

    // Equal roots are necessary but NOT sufficient for a rollback verdict. A rollback asserts
    // that every operation in the Work was undone, and that claim lives in the operation
    // results — not in the root comparison. Two failure modes were reachable here:
    //   - no operation results at all: nothing states what was rolled back, so the claim is
    //     unproven -> indeterminate (unknown), not pass;
    //   - a result still marked `committed`: the receipt contradicts its own rollback outcome
    //     -> reject. Previously this field was ignored entirely, so a self-contradicting
    //     receipt returned `pass`.
    const { operationResults } = obs.receipt;
    if (!Array.isArray(operationResults) || operationResults.length === 0) {
      return 'indeterminate';
    }
    // Complete coverage: EVERY entry must be a record carrying a status this profile
    // recognises as consistent with a rollback. An unrecognised or missing status leaves
    // that operation's fate unknown, so the receipt degrades to indeterminate rather than
    // passing on the strength of its siblings.
    const allConsistent = operationResults.every(
      (result) => isRecord(result)
        && typeof result.status === 'string'
        && ROLLBACK_CONSISTENT_STATUSES.has(result.status),
    );
    return allConsistent ? 'pass' : 'indeterminate';
  }

  const commonVerdict = verifyProofChain(common);
  return commonVerdict === 'reject' ? 'reject' : 'indeterminate';
}

function verifyAbsenceClaim(obs: AbsenceClaimObservation): Verdict {
  const { evidence } = obs;
  if (!evidence || typeof evidence !== 'object') return 'indeterminate';

  if (evidence.proof === 'invalid') return 'reject';

  // PRESENT CONTRADICTION FIRST, uniformly. If both subjects are present and disagree, the
  // evidence is about a different Work — that is counter-evidence, and it outranks any
  // missing proof material below. Ordering the completeness returns ahead of this made a
  // mismatch with `proof: "absent"` report indeterminate, contradicting the precedence rule
  // this file states in its header.
  if (
    isIdentifier(evidence.subjectWorkId) && isIdentifier(obs.claimedWorkId) &&
    evidence.subjectWorkId !== obs.claimedWorkId
  ) {
    return 'reject';
  }
  if (
    isIndex(evidence.subjectAttempt) && isIndex(obs.claimedAttempt) &&
    evidence.subjectAttempt !== obs.claimedAttempt
  ) {
    return 'reject';
  }

  if (evidence.kind === 'included-rollback-receipt') return 'indeterminate';
  if (
    evidence.verifiedCannotLaterInclude !== true ||
    evidence.proof !== 'valid'
  ) {
    return 'indeterminate';
  }

  // SUBJECT BINDING. An absence verdict authorises real action — a terminal `fail`, or a
  // `pass` permitting exactly one replacement under the same workId — so the evidence must
  // name WHAT it proves absent, AND that subject must be the Work actually being asked
  // about. Requiring the field alone is not enough: evidence naming a different Work would
  // still be accepted, so a lifecycle-expiry proof over someone else's Work could license a
  // replacement here. Both sides must be present and must agree.
  if (
    !isIdentifier(evidence.subjectWorkId) || !isIndex(evidence.subjectAttempt) ||
    !isIdentifier(obs.claimedWorkId) || !isIndex(obs.claimedAttempt)
  ) {
    return 'indeterminate';
  }
  // A subject mismatch is CONTRADICTED material, not missing material: the evidence proves
  // something about a different Work than the one under question.
  if (
    evidence.subjectWorkId !== obs.claimedWorkId ||
    evidence.subjectAttempt !== obs.claimedAttempt
  ) {
    return 'reject';
  }

  if (evidence.kind === 'authenticated-pre-admission-rejection') return 'fail';
  if (evidence.kind === 'authenticated-lifecycle-expired') return 'pass';
  return 'indeterminate';
}

function verifySettlementEvidence(obs: SettlementEvidenceObservation): Verdict {
  // Proof material only. A bare `signatureValid: true` is a claimant assertion with no
  // verifier behind it, and the set's own contract is "PROOF MATERIAL (never bare
  // booleans)" — accepting the boolean contradicted that and let a `pass` rest on an
  // unbacked flag. `signatureValid` is still read for CONTRADICTION (an explicit false is
  // counter-evidence and rejects), but it can no longer support acceptance.
  if (obs.signatureProof === 'invalid' || obs.signatureValid === false) {
    return 'reject';
  }

  // "Present" means TRUSTED MATERIAL, the same definition the absence and payment-slot
  // lanes use. Testing only for null/undefined made `''` vs `'job-9'` and `'0'` vs `0`
  // read as genuine contradictions and reject, when note (A) says empty or malformed
  // identity material is absent/untrusted — i.e. unknown, not counter-evidence. Only a
  // disagreement between two well-formed values is a real contradiction.
  const slotKeyPairs: ReadonlyArray<readonly [unknown, unknown, (v: unknown) => boolean]> = [
    [obs.evidenceJobId, obs.anchorJobId, isIdentifier],
    [obs.evidenceRailId, obs.anchorRailId, isIdentifier],
    [obs.evidencePhaseIndex, obs.anchorPhaseIndex, isIndex],
  ];
  // A present contradiction outranks missing material ANYWHERE, including a missing
  // signature proof. Evidence whose job/rail/phase disagrees with the anchor is about a
  // different settlement, and that fact does not become unknown just because the signature
  // proof is also absent. Checking completeness first reported such a mismatch as
  // indeterminate, breaking the precedence rule stated in the header.
  if (slotKeyPairs.some(([evidence, anchor, isTrusted]) =>
    isTrusted(evidence) && isTrusted(anchor) && evidence !== anchor
  )) return 'reject';

  if (obs.signatureProof !== 'valid') {
    return 'indeterminate';
  }

  // Matching on empty or malformed identifiers is matching on nothing: `'' === ''` would
  // otherwise satisfy the equality check while binding the evidence to no job and no rail.
  // Every component must be trusted material on BOTH sides before a match means anything.
  if (slotKeyPairs.some(([evidence, anchor, isTrusted]) =>
    !isTrusted(evidence) || !isTrusted(anchor)
  )) return 'indeterminate';

  return 'pass';
}

function verifyPaymentSlot(obs: PaymentSlotObservation): Verdict {
  // Invalid proof material is evaluated before ANY structural or label gate.
  // It is the strongest and most certain signal in the observation: a proof
  // that fails verification is a reject regardless of what transition string a
  // claimant attached to it, and regardless of whether the counterpart Work was
  // supplied at all. Ordering either the unknown-transition check or the
  // missing-counterpart return ahead of it let contradicted material be
  // downgraded to `indeterminate` — in the missing-counterpart case, simply by
  // omitting the second Work.
  const presentWorks = [obs.firstWork, obs.secondWork].filter(
    (work): work is PaymentSlotWork => !isAbsent(work),
  );
  if (presentWorks.some((work) => work.slotStateProof === 'invalid')) return 'reject';

  if (!obs.firstWork || !obs.secondWork) return 'indeterminate';

  const works = [obs.firstWork, obs.secondWork];

  const allowedTransitions = new Set(['open', 'open->consumed']);
  if (works.some((work) =>
    work.slotTransition !== undefined &&
    !allowedTransitions.has(work.slotTransition)
  )) return 'indeterminate';

  // Note (E): a valid slotStateProof MUST carry a proof-derived transition.
  // Without one, half the pair's slot state is unknown, so the pair degrades to
  // indeterminate rather than reporting a non-consuming `pass`. Previously one
  // real commit paired with a transition-less valid proof returned `pass` —
  // contradicting this file's own documented profile note.
  if (works.some((work) =>
    work.slotStateProof === 'valid' && isAbsent(work.slotTransition)
  )) return 'indeterminate';

  const claimsConsumption = works.map(
    (work) => work.slotTransition === 'open->consumed',
  );
  if (works.some((work, index) =>
    claimsConsumption[index] && work.slotStateProof !== 'valid'
  )) return 'indeterminate';

  const trustedProvenSlots = works.map((work) => {
    const slot = work.provenSlot;
    // Every component must be REAL material: a non-empty identifier, or a finite index.
    // Empty strings compared equal to each other, so a pair whose proven slot was
    // ('', '', '', 0) on both sides satisfied the tuple comparison below and returned `pass`
    // while attesting to no network, no rail, and no job.
    if (
      work.slotStateProof !== 'valid' ||
      !slot ||
      !isIdentifier(slot.networkId) ||
      !isIdentifier(slot.railId) ||
      !isIdentifier(slot.jobId) ||
      !isIndex(slot.phaseIndex)
    ) {
      return undefined;
    }
    return slot as Required<PaymentSlotIdentity>;
  });

  const [firstSlot, secondSlot] = trustedProvenSlots;
  if (!firstSlot || !secondSlot) return 'indeterminate';
  if (
    firstSlot.networkId !== secondSlot.networkId ||
    firstSlot.railId !== secondSlot.railId ||
    firstSlot.jobId !== secondSlot.jobId ||
    firstSlot.phaseIndex !== secondSlot.phaseIndex
  ) return 'indeterminate';

  const verifiedCommitCount = works.filter(
    (work) =>
      work.slotStateProof === 'valid' &&
      work.slotTransition === 'open->consumed',
  ).length;

  // ledgerLevelCAS is merely a claim and cannot whitewash two committed sets.
  if (verifiedCommitCount === 2) return 'reject';
  if (verifiedCommitCount === 1) return 'pass';
  return 'indeterminate';
}

export function verifyWorkReceipt(obs: Observation): Verdict {
  switch (obs.kind) {
    case 'work-receipt-proof':
      return verifyReceiptProof(obs as WorkReceiptProofObservation);
    case 'absence-claim':
      return verifyAbsenceClaim(obs as AbsenceClaimObservation);
    case 'settlement-evidence':
      return verifySettlementEvidence(obs as SettlementEvidenceObservation);
    case 'payment-slot':
      return verifyPaymentSlot(obs as PaymentSlotObservation);
    default:
      // Fail-closed contract: embedders MUST treat this throw as non-accept.
      throw new Error(`Unknown work-receipt observation kind: ${String(obs.kind)}`);
  }
}

interface Vector {
  name: string;
  expected: Verdict;
  observation: Observation;
}

interface VectorSet {
  set: string;
  count: number;
  vectors: Vector[];
}

interface Result {
  name: string;
  expected: Verdict;
  computed: Verdict | 'error';
  matches: boolean;
  error?: string;
}

function run(): void {
  const here = dirname(fileURLToPath(import.meta.url));
  const vectorPath = join(
    here,
    'vectors',
    'security',
    'atomic-work-receipt-absence-v0.1.json',
  );
  const vectorSet = JSON.parse(readFileSync(vectorPath, 'utf8')) as VectorSet;

  // Fail closed on a missing/empty set: `matched === vectors.length` is
  // vacuously true at length 0, so an emptied or truncated corpus would
  // otherwise exit 0 and report a green gate that executed nothing.
  if (!Array.isArray(vectorSet.vectors) || vectorSet.vectors.length === 0) {
    console.error(
      `error: ${vectorPath} declares no vectors; refusing to report a vacuous pass`,
    );
    process.exit(1);
  }

  // Optional corpus-size pin for CI: `--expect-count <n>` makes the executed
  // case count an asserted property rather than whatever happens to be on disk.
  const expectFlag = process.argv.indexOf('--expect-count');
  if (expectFlag !== -1) {
    const expected = Number(process.argv[expectFlag + 1]);
    if (!Number.isInteger(expected) || expected < 1) {
      console.error('error: --expect-count requires a positive integer');
      process.exit(2);
    }
    if (vectorSet.vectors.length !== expected) {
      console.error(
        `error: expected ${expected} vectors, found ${vectorSet.vectors.length}`,
      );
      process.exit(1);
    }
  }

  const results: Result[] = vectorSet.vectors.map((vector) => {
    try {
      const computed = verifyWorkReceipt(vector.observation);
      return {
        name: vector.name,
        expected: vector.expected,
        computed,
        matches: computed === vector.expected,
      };
    } catch (error) {
      return {
        name: vector.name,
        expected: vector.expected,
        computed: 'error',
        matches: false,
        error: error instanceof Error ? error.message : String(error),
      };
    }
  });

  const matched = results.filter((result) => result.matches).length;
  const allMatched = matched === vectorSet.vectors.length;

  if (process.argv.includes('--json')) {
    console.log(JSON.stringify({
      set: vectorSet.set,
      matched,
      total: vectorSet.vectors.length,
      ok: allMatched,
      results,
    }, null, 2));
  } else {
    console.table(results.map((result) => ({
      result: result.matches ? 'PASS' : 'FAIL',
      name: result.name,
      expected: result.expected,
      computed: result.computed,
    })));
    console.log(`${matched}/${vectorSet.vectors.length} vectors matched`);
  }

  process.exit(allMatched ? 0 : 1);
}

const invokedPath = process.argv[1];
if (invokedPath && fileURLToPath(import.meta.url) === invokedPath) run();
