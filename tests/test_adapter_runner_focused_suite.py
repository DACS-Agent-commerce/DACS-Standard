"""Producer regressions using real Node subprocesses, not the pinned recipe.

Execute the focused-suite and packet execution blocks read from the actual
producer. This avoids bypassing its gate while keeping unrelated repository
pins and adapter dependencies out of these bounded tests.
"""
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
HARNESS = r"""
import { execFileSync } from 'node:child_process';
import { readFileSync, realpathSync } from 'node:fs';
import * as path from 'node:path';
import { tmpdir } from 'node:os';
import { pathToFileURL } from 'node:url';
const [root, runner, mode] = process.argv.slice(1);
const source = readFileSync(path.join(root, 'scripts/run_adapter_runner_acceptance.mjs'), 'utf8');
const helperImport = source.match(/^import \{ parseFocusedSuite \} from '([^']+)';$/m);
const helper = helperImport
  ? await import(pathToFileURL(path.resolve(root, 'scripts', helperImport[1]))) : {};
const start = source.indexOf('  const shared =');
const end = source.indexOf('  const { releaseVectors }', start);
if (start < 0 || end < 0) throw new Error('producer focused-suite block not found');
const gate = new Function('execFileSync', 'path', 'realpathSync', 'tmpdir', 'runner',
  'parseFocusedSuite', source.slice(start, end) +
  '\nreturn { canonicalTmpdir, focusedSuite: typeof focusedSuite === "undefined" ? null : focusedSuite };');
let output;
const execute = (...args) => {
  if (mode === 'reporter' && !args[1].includes('--test-reporter=tap')) {
    throw new Error('explicit TAP reporter missing');
  }
  output = mode === 'output' ? runner : execFileSync(...args);
  return output;
};
const result = gate(execute, path, realpathSync, tmpdir, runner, helper.parseFocusedSuite);
if (mode === 'packet') {
  const start = source.indexOf('    execution: {');
  const end = source.indexOf('    adapter:', start);
  if (start < 0 || end < 0) throw new Error('producer execution block not found');
  const accessed = [];
  const focusedSuite = new Proxy(result.focusedSuite || {}, {
    get(target, key) { accessed.push(key); return target[key]; }
  });
  const packet = new Function('launched', 'canonicalTmpdir', 'realpathSync', 'focusedSuite',
    'return ({' + source.slice(start, end) + '});')(
      { adapters: [{}, {}] }, result.canonicalTmpdir, realpathSync, focusedSuite);
  console.log(JSON.stringify({ packet, accessed }));
} else {
  console.log(JSON.stringify({ ...result, output }));
}
"""


class AdapterRunnerFocusedSuiteTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.node = shutil.which("node")
        if cls.node is None:
            raise AssertionError("Node is required for producer regression tests; install Node before unittest discovery")

    def run_node(self, runner, mode):
        assert self.node is not None
        return subprocess.run(
            [self.node, "--input-type=module", "-e", HARNESS, str(ROOT), str(runner), mode],
            text=True, capture_output=True, check=False, timeout=30,
            env={**os.environ, "TMPDIR": str(ROOT)},
        )

    def run_producer_gate(self, extra="", mode="gate"):
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            runner = Path(directory)
            suite = runner / "conformance/shared-suite/unsupported-case.test.mjs"
            suite.parent.mkdir(parents=True)
            suite.write_text(
                "import { test } from 'node:test';\n"
                + "\n".join(f"test('passing-{i}', () => {{}});" for i in range(16))
                + "\n" + extra,
                encoding="utf-8",
            )
            return self.run_node(runner, mode)

    def assert_gate_rejected(self, output):
        completed = self.run_node(output, "output")
        self.assertNotEqual(0, completed.returncode, completed.stdout)
        self.assertIn("focused suite", completed.stderr)

    @staticmethod
    def summary(**changed):
        counts = dict(tests=16, pass_=16, fail=0, skipped=0, cancelled=0, todo=0)
        counts.update(changed)
        return "TAP version 13\n1..16\n" + "".join(
            f"# {key.rstrip('_')} {value}\n" for key, value in counts.items()
        )

    def test_producer_accepts_exact_sixteen_passes(self):
        completed = self.run_producer_gate()
        self.assertEqual(0, completed.returncode, completed.stderr)
        output = json.loads(completed.stdout)["output"]
        for line in ("# tests 16", "# pass 16", "# fail 0", "# skipped 0", "# cancelled 0", "# todo 0"):
            self.assertIn(line + "\n", output)

    def test_producer_requests_explicit_tap_reporter(self):
        completed = self.run_producer_gate(mode="reporter")
        self.assertEqual(0, completed.returncode, completed.stderr)

    def test_packet_counts_are_read_from_verified_result(self):
        completed = self.run_producer_gate(mode="packet")
        self.assertEqual(0, completed.returncode, completed.stderr)
        result = json.loads(completed.stdout)
        self.assertEqual(["pass", "fail", "skipped"], result["accessed"])
        self.assertEqual({
            "adapterCommand": ["python3", "scripts/dacs_adapter.py"],
            "adapterRuns": 2,
            "contributorFocusedSuite": {
                "command": ["node", "--test", "conformance/shared-suite/unsupported-case.test.mjs"],
                "canonicalTmpdirResolved": True, "passed": 16, "failed": 0, "skipped": 0,
            },
        }, result["packet"]["execution"])

    def test_missing_summary_counts_fail_closed(self):
        for key in ("tests", "pass", "fail", "skipped", "cancelled", "todo"):
            with self.subTest(key=key):
                output = "\n".join(line for line in self.summary().splitlines()
                                   if not line.startswith(f"# {key} ")) + "\n"
                self.assert_gate_rejected(output)

    def test_duplicate_summary_counts_fail_closed(self):
        for key, value in (("tests", 16), ("pass", 16), ("fail", 0),
                           ("skipped", 0), ("cancelled", 0), ("todo", 0)):
            for duplicate in (value, value + 1, "malformed"):
                with self.subTest(key=key, duplicate=duplicate):
                    self.assert_gate_rejected(self.summary() + f"# {key} {duplicate}\n")

    def test_malformed_summary_counts_fail_closed(self):
        for key, value in (("tests", 16), ("pass", 16), ("fail", 0),
                           ("skipped", 0), ("cancelled", 0), ("todo", 0)):
            for malformed in ("-1", "+0", "0.0", "0junk", "", "NaN", "0 0", "016"):
                with self.subTest(key=key, malformed=malformed):
                    self.assert_gate_rejected(self.summary().replace(
                        f"# {key} {value}\n", f"# {key} {malformed}\n"))

    def test_malformed_count_declarations_cannot_hide_behind_valid_counts(self):
        for key in ("tests", "pass", "fail", "skipped", "cancelled", "todo"):
            for declaration in (f"#  {key} 0", f"#{key} 0", f"#\t{key} 0", f"# {key}: 0"):
                with self.subTest(key=key, declaration=declaration):
                    self.assert_gate_rejected(self.summary() + declaration + "\n")

    def test_wrong_summary_counts_fail_closed(self):
        for key, value in (("tests", 17), ("pass_", 15), ("fail", 1),
                           ("skipped", 1), ("cancelled", 1), ("todo", 1)):
            with self.subTest(key=key):
                self.assert_gate_rejected(self.summary(**{key: value}))

    def test_indented_diagnostic_counts_are_not_summary(self):
        self.assert_gate_rejected("  " + self.summary().replace("\n", "\n  "))

    def test_crlf_summary_is_accepted(self):
        completed = self.run_node(self.summary().replace("\n", "\r\n"), "output")
        self.assertEqual(0, completed.returncode, completed.stderr)

    def test_real_todo_test_is_rejected(self):
        completed = self.run_producer_gate("test('todo-17', { todo: true }, () => {});\n")
        self.assertNotEqual(0, completed.returncode, completed.stdout)
        self.assertIn("focused suite", completed.stderr)

    def test_real_failed_subprocess_is_rejected(self):
        completed = self.run_producer_gate("test('failed-17', () => { throw new Error('fixture failure'); });\n")
        self.assertNotEqual(0, completed.returncode, completed.stdout)

    def test_producer_rejects_seventeenth_skipped_test(self):
        completed = self.run_producer_gate("test('skipped-17', { skip: true }, () => {});\n")
        self.assertNotEqual(0, completed.returncode, completed.stdout)
        self.assertIn("focused suite", completed.stderr)


if __name__ == "__main__":
    unittest.main()
