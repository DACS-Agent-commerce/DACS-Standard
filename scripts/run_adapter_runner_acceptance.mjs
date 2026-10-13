#!/usr/bin/env node
/** Run the bounded issue-270 adapter-runner acceptance recipe. */
import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { readFileSync, realpathSync } from 'node:fs';
import * as path from 'node:path';
import { tmpdir } from 'node:os';
import { pathToFileURL } from 'node:url';
import { parseFocusedSuite } from './adapter_runner_focused_suite.mjs';

const STANDARD_REPOSITORY = 'https://github.com/DACS-Agent-commerce/DACS-Standard';
const STANDARD_HEAD = 'c799a163e80bff867ba01bc9e08f15ab7916e139';
const STANDARD_TREE = '2fadbac38d9013268b41dec47c1090d5ac9c5600';
const DESCRIPTOR = 'conformance/interop/dacs-adapter-release-proposal-v1.json';
const DESCRIPTOR_SHA256 = '723d344e1487361c699cd0750a8567d7e2021cbbcbc1ff90efa39e8a423fecca';
const RUNNER_REPOSITORY = 'https://github.com/cX3po/pathos-dacs-ref';
const RUNNER_BASE = '1297dd5f79d2e1305bfd4e8e4b2fa6830bc72eda';
const PATCH_SHA256 = '178d58f2682a145810e6ec7611d3b348c502c2cd94917231e97360973bb6639d';
const RUNNER_SOURCES = {
  'conformance/shared-suite/standard-405-pilot.mjs': '0374fda135a9b564caabaaa73d16988911e44dccb88e433c9c928c449c71b431',
  'conformance/shared-suite/adapter-contract.mjs': '0fb13bc47e0cf4ad068a422caa9c8ed73085a3f135c17ccd851ad412130deba9',
  'conformance/shared-suite/adapter-process-client.mjs': '17c268e72b82e639e7c053f564ce13fd10d00e84add35984aae24bf4238990c0',
  'conformance/shared-suite/adapter-registry.mjs': 'db42abb3177fe1ad3aeb113f19fdaef0fadaf212895a4e412e7569762259923b',
  'conformance/shared-suite/unsupported-case.test.mjs': 'a0416d52c4206564fa00bff2f7998c6de9e66f377ecb8a8d34ed6b8219cbb6ea',
  'conformance/shared-suite/cross-run.mjs': '56dd845387ec90a8e400613517e57a16b3e2f585eee2c1bb24b1c44b458b0ee2',
};
const sha256 = value => createHash('sha256').update(value).digest('hex');
const cleanOrigin = value => value.trim().replace(/\.git\/?$/, '').replace(/\/$/, '');
const git = (root, ...args) => execFileSync('git', ['--no-replace-objects', '-C', root, ...args], { encoding: 'utf8' }).trim();

function requireEqual(actual, expected, label) {
  if (actual !== expected) throw new Error(`${label}: expected ${expected}, got ${actual}`);
}
function verifyCheckout(root, repository, head, tree) {
  requireEqual(cleanOrigin(git(root, 'remote', 'get-url', 'origin')), repository, 'repository origin');
  requireEqual(git(root, 'rev-parse', 'HEAD'), head, 'checkout head');
  if (tree) requireEqual(git(root, 'rev-parse', 'HEAD^{tree}'), tree, 'checkout tree');
}
function loadRelease(root) {
  const descriptorBytes = readFileSync(path.join(root, DESCRIPTOR));
  requireEqual(sha256(descriptorBytes), DESCRIPTOR_SHA256, 'descriptor sha256');
  const descriptor = JSON.parse(descriptorBytes);
  for (const pin of [descriptor.adapter.source, ...descriptor.adapter.wrappedStandard.primitives,
    ...Object.values(descriptor.sources)]) {
    const raw = readFileSync(path.join(root, pin.path));
    requireEqual(sha256(raw), pin.sha256, `${pin.path} sha256`);
    requireEqual(git(root, 'rev-parse', `HEAD:${pin.path}`), pin.gitBlob, `${pin.path} git blob`);
  }
  const sources = Object.fromEntries(Object.entries(descriptor.sources)
    .map(([name, pin]) => [name, JSON.parse(readFileSync(path.join(root, pin.path), 'utf8'))]));
  return { descriptor, sources };
}
function verifyRunner(root, patchFile) {
  verifyCheckout(root, RUNNER_REPOSITORY, RUNNER_BASE);
  requireEqual(sha256(readFileSync(patchFile)), PATCH_SHA256, 'runner patch sha256');
  execFileSync('git', ['-C', root, 'apply', '--check', '--reverse', patchFile]);
  for (const [file, digest] of Object.entries(RUNNER_SOURCES)) {
    requireEqual(sha256(readFileSync(path.join(root, file))), digest, `${file} sha256`);
  }
}
function compact(row) {
  return { id: row.id, operation: row.fnName, expected: row.expected, status: row.status,
    participatingAdapters: row.participatingAdapters,
    independentImplementations: row.independentImplementations,
    adapters: Object.values(row.perAdapter).map(({ runId, name, status, outcome, errorCode }) =>
      ({ runId, name, status, outcome: outcome ?? null, ...(errorCode ? { errorCode } : {}) })) };
}
function counts(matrix) {
  return Object.fromEntries(['SELF-CHECK', 'ABSTAIN', 'INTEROP-AGREE', 'ERROR',
    'VECTOR-MISMATCH', 'IMPLEMENTATION-DIVERGENCE'].map(status =>
      [status, matrix.filter(row => row.status === status).length]));
}

async function main() {
  const args = Object.fromEntries(process.argv.slice(2).reduce((pairs, value, index, all) =>
    index % 2 ? pairs : [...pairs, [value, all[index + 1]]], []));
  if (!args['--runner'] || !args['--runner-patch'] || !args['--standard'] || !args['--python']) {
    throw new Error('usage: node run_adapter_runner_acceptance.mjs --runner DIR --runner-patch FILE --standard DIR --python PYTHON');
  }
  const runner = path.resolve(args['--runner']);
  const standard = path.resolve(args['--standard']);
  verifyRunner(runner, path.resolve(args['--runner-patch']));
  verifyCheckout(standard, STANDARD_REPOSITORY, STANDARD_HEAD, STANDARD_TREE);
  const release = loadRelease(standard);

  const shared = path.join(runner, 'conformance/shared-suite');
  const canonicalTmpdir = realpathSync(tmpdir());
  const focusedOutput = execFileSync(process.execPath,
    ['--test', '--test-reporter=tap', path.join(shared, 'unsupported-case.test.mjs')],
    { cwd: runner, env: { ...process.env, TMPDIR: canonicalTmpdir }, encoding: 'utf8' });
  const focusedSuite = parseFocusedSuite(focusedOutput);
  const { releaseVectors } = await import(pathToFileURL(path.join(shared, 'standard-405-pilot.mjs')));
  const { crossRun } = await import(pathToFileURL(path.join(shared, 'adapter-contract.mjs')));
  const { launchAdapters } = await import(pathToFileURL(path.join(shared, 'adapter-registry.mjs')));
  const command = [path.resolve(args['--python']), 'scripts/dacs_adapter.py'];
  const launched = await launchAdapters([{ command, cwd: standard }, { command, cwd: standard }]);
  if (launched.unavailable.length) throw new Error(`Standard adapter launch failed: ${launched.unavailable[0].reason}`);
  for (const item of launched.launched) {
    requireEqual(item.metadata.repository, STANDARD_REPOSITORY, 'adapter metadata repository');
    requireEqual(item.metadata.revision, `sha256:${release.descriptor.adapter.source.sha256}`, 'adapter metadata revision');
    requireEqual(item.metadata.wrappedStandard?.revision,
      release.descriptor.adapter.wrappedStandard.revision, 'adapter wrapped Standard revision');
  }
  const vectors = releaseVectors(release);
  const result = await crossRun(launched.adapters, vectors);

  const missing = await launchAdapters([{ command: ['/definitely-missing-dacs-adapter'] }]);
  const malformed = await launchAdapters([{ command: [process.execPath, '-e',
    `process.stdin.on('data',d=>{let q=JSON.parse(d);console.log(JSON.stringify({protocol:q.protocol,id:q.id,ok:'false'}))})`] }]);
  const controlVector = [{ id: 'failure-control', family: 'runner-control', fnName: 'canonicalize',
    description: 'runner failure control', expected: 'never', invoke: async adapter => adapter.canonicalize({}) }];
  const launchFailure = (await crossRun(missing.adapters, controlVector)).matrix[0];
  const protocolFailure = (await crossRun(malformed.adapters, controlVector)).matrix[0];
  const matrix = result.matrix.map(compact);
  const summary = counts(result.matrix);
  const mismatch = matrix.find(row => row.id === 'signing::reject-mismatched-ascii-hex-hash');
  const unsupported = new Set(['bigint-native-type', 'signing::valid-raw-digest-profile-boundary']);
  const accepted = vectors.length === 20 && summary['SELF-CHECK'] === 18 && summary.ABSTAIN === 2 &&
    summary['INTEROP-AGREE'] === 0 && summary.ERROR === 0 &&
    result.matrix.every(row => unsupported.has(row.id)
      ? row.status === 'ABSTAIN' && row.participatingAdapters === 0 && row.independentImplementations === 0
      : row.status === 'SELF-CHECK' && row.participatingAdapters === 2 && row.independentImplementations === 1) &&
    mismatch?.expected === 'false' && mismatch.adapters.every(item => item.outcome === 'false') &&
    launchFailure.status === 'ERROR' && protocolFailure.status === 'ERROR';
  const python = JSON.parse(execFileSync(command[0], ['-c',
    'import json,platform,cryptography,idna;print(json.dumps({"version":platform.python_version(),"cryptography":cryptography.__version__,"idna":idna.__version__}))'],
  { encoding: 'utf8' }));
  verifyRunner(runner, path.resolve(args['--runner-patch']));
  verifyCheckout(standard, STANDARD_REPOSITORY, STANDARD_HEAD, STANDARD_TREE);
  loadRelease(standard);
  const report = { schema: 'dacs-adapter-runner-acceptance/1', accepted,
    coordinates: { standard: { repository: STANDARD_REPOSITORY, head: STANDARD_HEAD, tree: STANDARD_TREE,
      descriptorSha256: DESCRIPTOR_SHA256, adapterSourceSha256: release.descriptor.adapter.source.sha256,
      wrappedStandard: release.descriptor.adapter.wrappedStandard.revision },
    runner: { repository: RUNNER_REPOSITORY, baseHead: RUNNER_BASE, patchSha256: PATCH_SHA256,
      issueComment: 'https://github.com/DACS-Agent-commerce/DACS-Standard/issues/270#issuecomment-5696719263', sourceSha256: RUNNER_SOURCES } },
    runtime: { node: process.version, openssl: process.versions.openssl, python },
    execution: { adapterCommand: ['python3', 'scripts/dacs_adapter.py'], adapterRuns: launched.adapters.length,
      contributorFocusedSuite: { command: ['node', '--test', 'conformance/shared-suite/unsupported-case.test.mjs'],
        canonicalTmpdirResolved: canonicalTmpdir === realpathSync(canonicalTmpdir),
        passed: focusedSuite.pass, failed: focusedSuite.fail, skipped: focusedSuite.skipped } },
    adapter: launched.launched[0].metadata,
    expected: { cases: 20, summary: { 'SELF-CHECK': 18, ABSTAIN: 2, 'INTEROP-AGREE': 0, ERROR: 0 } },
    observed: { summary, matrix }, controls: { rawDigestSignatureValidatedBeforeAdapter: true,
      inProfileCryptoMismatch: { id: mismatch.id, expected: false, observed: mismatch.adapters.map(item => JSON.parse(item.outcome)) },
      exportedLaunchFailureProbe: launchFailure.status,
      exportedMalformedProtocolProbe: protocolFailure.status },
    limitations: ['Two runs wrap one DACS-Standard implementation; every scored result is SELF-CHECK.',
      'No independent cross-implementation, full legacy/default corpus, live system, or generic domain-separation claim.',
      'This packet is separate from dacs-cross-run-evidence/1, which does not execute or assess adapters.',
      'The offline validator checks recorded pins, coverage and internal consistency; the producer execution supplies the run evidence and does not certify a hostile host.'] };
  console.log(JSON.stringify(report, null, 2));
  if (!accepted) process.exitCode = 1;
}
main().catch(error => { console.error(`adapter runner acceptance: FAIL: ${error.message}`); process.exitCode = 2; });
