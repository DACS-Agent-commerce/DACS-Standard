"""Fresh-interpreter coverage for the Demos identity consumer's imports."""

import subprocess
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
IMPORT_CHECK = """
import importlib
import sys

assert "jcs" not in sys.modules
assert "dacs_reference" not in sys.modules
module = importlib.import_module(sys.argv[1])
key = "ab" * 32
assert module.demos_key_claim("KEY:" + key + "?unknown=ok") == ("key", key)
try:
    module.demos_key_claim("key:" + key + "?a=%xx")
except ValueError:
    pass
else:
    raise AssertionError("malformed qualifier accepted")
"""


class DemosIdentityImportTests(unittest.TestCase):
    def check_imports(self, prefix, cwd):
        for name in ("demos_identity", "settlement_finality_reference"):
            with self.subTest(module=prefix + name):
                completed = subprocess.run(
                    [sys.executable, "-E", "-s", "-c", IMPORT_CHECK, prefix + name],
                    cwd=cwd,
                    stdin=subprocess.DEVNULL,
                    capture_output=True,
                    text=True,
                    timeout=30,
                )
                self.assertEqual(0, completed.returncode, completed.stderr)

    def test_package_consumers_in_fresh_interpreters(self):
        self.check_imports("scripts.", ROOT)

    def test_script_consumers_in_fresh_interpreters(self):
        self.check_imports("", ROOT / "scripts")


if __name__ == "__main__":
    unittest.main()
