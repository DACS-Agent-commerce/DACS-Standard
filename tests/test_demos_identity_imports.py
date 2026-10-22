"""Isolated-consumer coverage for the Demos identity parser's provenance."""

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

COLLISION_CHECK = """
import importlib
import sys
import types

foreign = types.ModuleType("dacs_reference")
foreign.__file__ = "/another-checkout/scripts/dacs_reference.py"
foreign._parse_parameters = lambda value: ()
sys.modules["dacs_reference"] = foreign
before = list(sys.path)
module = importlib.import_module(sys.argv[1])
key = "ab" * 32
for scheme in ("KEY:", "KeY:", "DID:demos:agent:"):
    for suffix in ("", "?unknown=ok", "?z=1&a=2", "?a=1&a=2"):
        reference = scheme + key + suffix
        assert module.demos_key_claim(reference)[1] == key, reference
        assert module.demos_party_address(reference) == key, reference
for suffix in ("?", "?a", "?a=%xx", "?=v"):
    try:
        module.demos_key_claim("key:" + key + suffix)
    except ValueError:
        pass
    else:
        raise AssertionError("malformed qualifier accepted: " + suffix)
assert sys.modules["dacs_reference"] is foreign
if sys.argv[1].endswith("demos_identity"):
    assert sys.path == before, "identity import changed the consumer's sys.path"
"""

JCS_COLLISION_CHECK = """
import importlib
import sys
import types

foreign = types.ModuleType("jcs")
foreign.__file__ = "/another-checkout/scripts/jcs.py"
sys.modules["jcs"] = foreign
try:
    importlib.import_module(sys.argv[1])
except ImportError as error:
    assert "jcs" in str(error) and "sibling" in str(error), str(error)
else:
    raise AssertionError("foreign JCS dependency accepted")
assert sys.modules["jcs"] is foreign
"""

PAYMENT_COLLISION_CHECK = """
import copy
import json
import sys
import types

foreign = types.ModuleType("dacs_reference")
foreign.__file__ = "/another-checkout/scripts/dacs_reference.py"
foreign._parse_parameters = lambda value: ()
sys.modules["dacs_reference"] = foreign
sys.path.insert(0, "tests")
import test_pay_dem_execution_vectors as pay_dem
data = pay_dem.generator.load_vectors(pay_dem.VECTORS.read_text())
cases = [case for case in data["vectors"] if "-claim-read-" in case["name"]]
assert len(cases) == 40
for case in cases:
    actual = pay_dem.evaluate(case)[0]
    assert actual == case["expected"], (case["name"], actual, case["expected"])
case = copy.deepcopy(next(case for case in data["vectors"] if case["name"] == "consumer-confirmed-gate-passes"))
claims = [
    {"claim": "key:" + pay_dem.generator.OTHER_KEY, "control": "presentation-signature"},
    {"claim": "KEY:" + pay_dem.generator.PAYER_KEY + "?unknown=ok", "control": "presentation-signature"},
]
case["protocolInput"]["phase"]["payerKeyClaims"] = claims
assert pay_dem.evaluate(case)[0] == "pass", "second controlled payer key refused"
claims[1]["control"] = "none"
assert pay_dem.evaluate(case)[0] != "pass", "uncontrolled payer key admitted"
from scripts.settlement_finality_reference import verify_finality
fv = json.loads((pay_dem.ROOT / "conformance/vectors/security/settlement-finality-verification.json").read_text())
fv_cases = [case for case in fv["vectors"] if case["name"].startswith("fv-bft-final-claim-read-")]
assert len(fv_cases) == 8
for case in fv_cases:
    trust = dict(copy.deepcopy(fv["trustedFixturePolicy"]), **copy.deepcopy(case["trustedOverrides"]))
    actual = verify_finality(case["input"], trust)["decision"]
    assert actual == case["expected"], (case["name"], actual, case["expected"])
print("40 payment and 8 FV claim-read vectors passed with a foreign cached reference")
"""


class DemosIdentityImportTests(unittest.TestCase):
    def check_imports(self, prefix, cwd, check=IMPORT_CHECK, names=None):
        for name in names or ("demos_identity", "settlement_finality_reference"):
            with self.subTest(module=prefix + name):
                completed = subprocess.run(
                    [sys.executable, "-E", "-s", "-c", check, prefix + name],
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

    def test_cached_reference_cannot_supply_package_claim_grammar(self):
        self.check_imports("scripts.", ROOT, COLLISION_CHECK, ("demos_identity",))

    def test_cached_reference_cannot_supply_script_claim_grammar(self):
        self.check_imports("", ROOT / "scripts", COLLISION_CHECK, ("demos_identity",))

    def test_cached_foreign_jcs_is_refused_by_package_consumer(self):
        self.check_imports("scripts.", ROOT, JCS_COLLISION_CHECK, ("demos_identity",))

    def test_cached_foreign_jcs_is_refused_by_script_consumer(self):
        self.check_imports("", ROOT / "scripts", JCS_COLLISION_CHECK, ("demos_identity",))

    def test_payment_gates_keep_claim_verdicts_with_cached_reference(self):
        self.check_imports("", ROOT, PAYMENT_COLLISION_CHECK, ("payment-gates",))


if __name__ == "__main__":
    unittest.main()
