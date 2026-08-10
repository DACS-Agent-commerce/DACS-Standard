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
 * install — pinning the Node version alone makes it reproducible.
 *
 * Profile-hardening notes for the Standard profile (from adversarial review;
 * none affect the verdicts below, recorded so implementers normalize inputs):
 *  (A) Slot-key / root components: the Standard profile SHOULD require each
 *      component to be a non-empty string or a finite number. This verifier
 *      treats `undefined`/`null` as absent (-> indeterminate); an empty string
 *      or non-finite number is currently treated as present material.
 *  (B) Verdict chains are outcome-scoped: a `rolled-back` receipt is judged on
 *      its declared chain (inclusion/finality/validatorSet + businessRootEquality)
 *      and does NOT reject on a stray invalid proof outside that chain (e.g. a
 *      `winnerStateProof` that only applies to a `committed` outcome). Consumers
 *      MUST NOT assume any-invalid-proof-anywhere -> reject.
 *  (C) Slot-key comparison is TYPE-STRICT (`0 !== "0"`). Encoders MUST normalize
 *      phaseIndex to a number; a type mismatch fail-safes to reject, never pass.
 *  (D) Payment-slot identity is the structured canonical tuple attested by the
 *      verified slot-state proof, never a claimant-presented label. This closes
 *      encoding-drift evasions (alias, zero-padding, delimiter ambiguity) while
 *      refusing to reject on unbound labels alone.
 *  (E) A valid slotStateProof SHOULD carry a proof-derived `slotTransition`;
 *      the profile should treat valid-proof-with-absent-transition as degrading
 *      the pair to indeterminate rather than a non-consuming `pass`. phaseIndex
 *      is trusted only as a number; per note (A) the Standard should also exclude
 *      non-finite numbers from a trusted proven slot.
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
    [field: string]: unknown;
  };
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

function verifyProofChain(statuses: Array<ProofStatus | undefined>): Verdict {
  if (statuses.some((status) => status === 'invalid')) return 'reject';
  if (statuses.some((status) => status !== 'valid')) return 'indeterminate';
  return 'pass';
}

function verifyReceiptProof(obs: WorkReceiptProofObservation): Verdict {
  if (!obs.receipt || typeof obs.receipt !== 'object') return 'indeterminate';

  const common = [
    obs.receiptInclusionProof,
    obs.finalityProof,
    obs.validatorSetProof,
  ];

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

    const { preBusinessStateRoot, postBusinessStateRoot } = obs.receipt;
    if (
      typeof preBusinessStateRoot !== 'string' ||
      preBusinessStateRoot.length === 0 ||
      typeof postBusinessStateRoot !== 'string' ||
      postBusinessStateRoot.length === 0
    ) {
      return 'indeterminate';
    }

    return preBusinessStateRoot === postBusinessStateRoot
      ? 'pass'
      : 'reject';
  }

  const commonVerdict = verifyProofChain(common);
  return commonVerdict === 'reject' ? 'reject' : 'indeterminate';
}

function verifyAbsenceClaim(obs: AbsenceClaimObservation): Verdict {
  const { evidence } = obs;
  if (!evidence || typeof evidence !== 'object') return 'indeterminate';

  if (evidence.proof === 'invalid') return 'reject';
  if (evidence.kind === 'included-rollback-receipt') return 'indeterminate';
  if (
    evidence.verifiedCannotLaterInclude !== true ||
    evidence.proof !== 'valid'
  ) {
    return 'indeterminate';
  }

  if (evidence.kind === 'authenticated-pre-admission-rejection') return 'fail';
  if (evidence.kind === 'authenticated-lifecycle-expired') return 'pass';
  return 'indeterminate';
}

function verifySettlementEvidence(obs: SettlementEvidenceObservation): Verdict {
  if (obs.signatureProof === 'invalid' || obs.signatureValid === false) {
    return 'reject';
  }
  if (obs.signatureProof !== 'valid' && obs.signatureValid !== true) {
    return 'indeterminate';
  }

  const slotKeyPairs: ReadonlyArray<readonly [unknown, unknown]> = [
    [obs.evidenceJobId, obs.anchorJobId],
    [obs.evidenceRailId, obs.anchorRailId],
    [obs.evidencePhaseIndex, obs.anchorPhaseIndex],
  ];
  // A present contradiction outranks missing material elsewhere in the key.
  if (slotKeyPairs.some(([evidence, anchor]) =>
    !isAbsent(evidence) && !isAbsent(anchor) && evidence !== anchor
  )) return 'reject';

  if (slotKeyPairs.some(([evidence, anchor]) =>
    isAbsent(evidence) || isAbsent(anchor)
  )) return 'indeterminate';

  return 'pass';
}

function verifyPaymentSlot(obs: PaymentSlotObservation): Verdict {
  if (!obs.firstWork || !obs.secondWork) return 'indeterminate';

  const works = [obs.firstWork, obs.secondWork];

  // Invalid proof material is evaluated FIRST. It is the strongest and most
  // certain signal in the pair, and ordering the unknown-transition check ahead
  // of it let `slotTransition: "unexpected"` + `slotStateProof: "invalid"`
  // report `indeterminate`, masking contradictory proof material behind an
  // unknown label. A proof that fails verification is a reject regardless of
  // what transition the claimant attached to it.
  if (works.some((work) => work.slotStateProof === 'invalid')) return 'reject';

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
    if (
      work.slotStateProof !== 'valid' ||
      !slot ||
      isAbsent(slot.networkId) || typeof slot.networkId !== 'string' ||
      isAbsent(slot.railId) || typeof slot.railId !== 'string' ||
      isAbsent(slot.jobId) || typeof slot.jobId !== 'string' ||
      isAbsent(slot.phaseIndex) || typeof slot.phaseIndex !== 'number'
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
