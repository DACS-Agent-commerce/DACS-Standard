import json
import re
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from dacs_reference import parse_claim_reference  # noqa: E402

VECTORS = (
    ROOT
    / "conformance"
    / "vectors"
    / "security"
    / "cci-native-identifier-rows-v0.8.json"
)
DACS1 = ROOT / "spec" / "DACS-1-IDENTIFY.md"

HUMANPASSPORT_ADDRESS_RE = re.compile(r"0x[0-9a-fA-F]{40}\Z")
PROOF_HASH_RE = re.compile(r"[0-9a-f]{64}\Z")
# The code points ECMAScript String.prototype.trim removes (WhiteSpace and LineTerminator), which is the
# trim the rows name. Python str.strip() differs: it strips U+0085 and U+001C..U+001F but not U+FEFF.
TRIM_CHARS = (
    "\u0009\u000a\u000b\u000c\u000d\u0020\u00a0\u1680\u2000\u2001\u2002\u2003\u2004\u2005"
    "\u2006\u2007\u2008\u2009\u200a\u2028\u2029\u202f\u205f\u3000\ufeff"
)


def humanpassport_claims(stored_entries):
    """Project stored `humanpassport` entries to canonical ClaimReferences."""
    claims = []
    for entry in stored_entries:
        address = entry.get("address")
        if isinstance(address, str):
            address = address.strip(TRIM_CHARS)
        if not isinstance(address, str) or HUMANPASSPORT_ADDRESS_RE.fullmatch(address) is None:
            continue
        claims.append(f"cci-humanpassport:{address.lower()}")
    return claims


TLSN_CONTEXTS = {"github", "discord", "telegram"}
# The platform keys a stored web2 entry needs for a cci-web2 claim (the `domain` key is not modelled).
WEB2_PLATFORMS = {"twitter"} | TLSN_CONTEXTS


def tlsn_user_id_present(user_id):
    """A non-blank string (after the trim) or a safe integer, as the producer requires."""
    if isinstance(user_id, str):
        return user_id.strip(TRIM_CHARS) != ""
    if isinstance(user_id, bool) or not isinstance(user_id, (int, float)):
        return False
    return float(user_id).is_integer() and abs(user_id) <= 2**53 - 1


def tlsn_projection(identities):
    """Project stored web2 entries to their `cci-web2` and `cci-tlsn` claims."""
    web2_claims = []
    tlsn_claims = []
    for platform, entries in identities.get("web2", {}).items():
        # The cci-tlsn context is trimmed then lowercased; the web2 platform lookup only lowercases.
        context = platform.strip(TRIM_CHARS).lower()
        for entry in entries:
            username = entry.get("username")
            if isinstance(username, str):
                username = username.strip(TRIM_CHARS)
            if not isinstance(username, str) or not username:
                continue
            if platform.lower() in WEB2_PLATFORMS:
                web2_claims.append(f"cci-web2:{platform.lower()}:{username}")
            proof_hash = entry.get("proofHash")
            if isinstance(proof_hash, str):
                proof_hash = proof_hash.strip(TRIM_CHARS).lower()
            if (
                context in TLSN_CONTEXTS
                and entry.get("proofType") == "tlsn"
                and tlsn_user_id_present(entry.get("userId"))
                and isinstance(proof_hash, str)
                and PROOF_HASH_RE.fullmatch(proof_hash) is not None
            ):
                tlsn_claims.append(f"cci-tlsn:{proof_hash}")
    return {"cciWeb2": web2_claims, "cciTlsn": tlsn_claims}


def evaluate(vector):
    if vector["row"] == "humanpassport":
        claims = humanpassport_claims(vector["stored"]["humanpassport"])
        return {
            "expected": "pass" if claims else "fail",
            "cciHumanpassport": claims,
        }
    projection = tlsn_projection(vector["stored"])
    return {
        "expected": "pass" if projection["cciTlsn"] else "fail",
        **projection,
    }


def table_row(text, scheme_prefix):
    rows = [line for line in text.splitlines() if line.startswith(f"| {scheme_prefix}")]
    if len(rows) != 1:
        raise AssertionError(f"expected exactly one {scheme_prefix} row, found {len(rows)}")
    cells = [cell.strip() for cell in rows[0].strip().strip("|").split(" | ")]
    return cells


class CciNativeIdentifierRowsVectorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = json.loads(VECTORS.read_text(encoding="utf-8"))
        cls.dacs1 = DACS1.read_text(encoding="utf-8")

    def vectors_for(self, row):
        return [vector for vector in self.data["vectors"] if vector["row"] == row]

    def test_every_vector_executes_to_its_pinned_result(self):
        for vector in self.data["vectors"]:
            with self.subTest(vector["name"]):
                self.assertEqual(vector["want"], evaluate(vector))
                self.assertEqual(vector["expected"], vector["want"]["expected"])

    def test_humanpassport_vectors_cover_canonical_and_rejected_shapes(self):
        by_name = {vector["name"]: vector for vector in self.vectors_for("humanpassport")}
        lowercase = by_name["humanpassport-lowercase-address-is-canonical"]
        self.assertEqual("pass", lowercase["expected"])
        canonical = lowercase["want"]["cciHumanpassport"]
        for name in (
            "humanpassport-checksum-case-address-canonicalises-to-lowercase",
            "humanpassport-uppercase-hex-address-canonicalises-to-lowercase",
            "humanpassport-whitespace-padded-address-is-trimmed-then-canonical",
        ):
            self.assertEqual(canonical, by_name[name]["want"]["cciHumanpassport"], name)
        for name in (
            "humanpassport-opaque-proof-id-is-not-an-identifier",
            "humanpassport-address-without-0x-prefix-is-rejected",
            "humanpassport-uppercase-0X-prefix-is-rejected",
            "humanpassport-short-address-is-rejected",
            "humanpassport-long-address-is-rejected",
            "humanpassport-non-hex-address-is-rejected",
        ):
            self.assertEqual("fail", by_name[name]["expected"], name)
            self.assertEqual([], by_name[name]["want"]["cciHumanpassport"], name)

    def test_emitted_humanpassport_claims_are_registered_lowercase_addresses(self):
        for vector in self.vectors_for("humanpassport"):
            for claim in vector["want"]["cciHumanpassport"]:
                parsed = parse_claim_reference(claim)
                self.assertEqual("cci-humanpassport", parsed.scheme, vector["name"])
                self.assertEqual(parsed.identifier, parsed.identifier.lower(), vector["name"])
                self.assertRegex(parsed.identifier, r"0x[0-9a-f]{40}\Z")

    def test_tlsn_vectors_cover_projection_and_rejected_shapes(self):
        by_name = {vector["name"]: vector for vector in self.vectors_for("tlsn")}
        projected = by_name["tlsn-web2-entry-projects-to-cci-tlsn-and-cci-web2"]
        self.assertEqual("pass", projected["expected"])
        self.assertEqual(1, len(projected["want"]["cciTlsn"]))
        self.assertEqual(1, len(projected["want"]["cciWeb2"]))
        uppercase = by_name["tlsn-uppercase-proof-hash-canonicalises-to-lowercase"]
        self.assertEqual("pass", uppercase["expected"])
        padded = by_name["tlsn-whitespace-padded-proof-hash-is-trimmed-then-canonical"]
        self.assertEqual("pass", padded["expected"])
        self.assertEqual(projected["want"]["cciTlsn"], padded["want"]["cciTlsn"])
        numeric = by_name["tlsn-numeric-safe-integer-user-id-projects-to-cci-tlsn"]
        self.assertEqual("pass", numeric["expected"])
        self.assertEqual(projected["want"]["cciTlsn"], numeric["want"]["cciTlsn"])
        padded_context = by_name["tlsn-whitespace-padded-context-projects-to-cci-tlsn-and-no-cci-web2"]
        self.assertEqual("pass", padded_context["expected"])
        self.assertEqual(projected["want"]["cciTlsn"], padded_context["want"]["cciTlsn"])
        self.assertEqual([], padded_context["want"]["cciWeb2"])
        for name in (
            "tlsn-web2-entry-without-tlsn-proof-type-has-no-cci-tlsn",
            "tlsn-short-proof-hash-has-no-cci-tlsn",
            "tlsn-0x-prefixed-proof-hash-has-no-cci-tlsn",
            "tlsn-missing-proof-hash-has-no-cci-tlsn",
            "tlsn-missing-user-id-has-no-cci-tlsn",
            "tlsn-blank-user-id-has-no-cci-tlsn",
            "tlsn-context-outside-the-set-has-no-cci-tlsn",
        ):
            self.assertEqual("fail", by_name[name]["expected"], name)
            self.assertEqual([], by_name[name]["want"]["cciTlsn"], name)
            self.assertEqual(1, len(by_name[name]["want"]["cciWeb2"]), name)
        blank_username = by_name["tlsn-blank-username-has-no-cci-tlsn"]
        self.assertEqual("fail", blank_username["expected"])
        self.assertEqual([], blank_username["want"]["cciTlsn"])
        self.assertEqual([], blank_username["want"]["cciWeb2"])

    def test_cci_tlsn_and_cci_web2_claims_are_distinct_registered_references(self):
        for vector in self.vectors_for("tlsn"):
            for claim in vector["want"]["cciTlsn"]:
                parsed = parse_claim_reference(claim)
                self.assertEqual("cci-tlsn", parsed.scheme, vector["name"])
                self.assertRegex(parsed.identifier, r"[0-9a-f]{64}\Z")
            for claim in vector["want"]["cciWeb2"]:
                self.assertEqual("cci-web2", parse_claim_reference(claim).scheme, vector["name"])

    def test_humanpassport_row_names_verified_address_not_proof_id(self):
        scheme, context, shape, _status = table_row(self.dacs1, "cci-humanpassport:")
        self.assertEqual("cci-humanpassport:<address>", scheme)
        self.assertEqual("humanpassport", context)
        self.assertNotIn("humanity proof id", shape)
        self.assertIn("verified EVM address", shape)
        self.assertIn("`0x` + 40 lowercase hex", shape)

    def test_tlsn_row_distinguishes_claim_from_web2_storage(self):
        scheme, context, shape, _status = table_row(self.dacs1, "cci-tlsn:")
        self.assertEqual("cci-tlsn:<proof-hash>", scheme)
        self.assertEqual("web2 (proof type `tlsn`)", context)
        self.assertIn("64 lowercase hex", shape)
        self.assertIn("`cci-web2`", shape)
        for condition in ("`github`, `discord` or `telegram`", "`username` is non-blank", "`userId` is a non-blank string or a safe integer"):
            self.assertIn(condition, shape)
        self.assertIn("projects to no `cci-tlsn` claim", shape)
        self.assertIn("its context, after the same trim and compared in any letter case, is", shape)
        self.assertIn("lowercases the context but does not trim it", shape)
        self.assertIn('`" github "`) projects to this claim and to no `cci-web2` claim', shape)

    def test_set_states_its_checker_and_cites_storage_sources(self):
        self.assertIn("not a ClaimReference", self.data["description"])
        self.assertIn("parse_claim_reference", self.data["description"])
        self.assertIn("does not yet apply", self.data["description"])
        sources = self.data["provenance"]["storageSources"]
        self.assertTrue(sources)
        for source in sources:
            self.assertIsInstance(source, str)
            self.assertRegex(source, r"commit [0-9a-f]{40}|at ac8f45f")

    def test_rows_state_producer_side_canonical_form(self):
        for prefix in ("cci-humanpassport:", "cci-tlsn:"):
            _scheme, _context, shape, _status = table_row(self.dacs1, prefix)
            self.assertIn("lowercase", shape, prefix)
            self.assertIn("the producer emits", shape, prefix)
            self.assertIn("trims surrounding whitespace", shape, prefix)
            self.assertNotIn("lowercased under CF-2", shape, prefix)
            self.assertNotIn("CF-2", shape, prefix)

    def test_tlsn_row_sends_the_proof_to_the_tlsnotary_method(self):
        _scheme, _context, _shape, status = table_row(self.dacs1, "cci-tlsn:")
        self.assertIn("DACS-2 verifies the TLSNotary proof the presenter supplies with the `tlsnotary` method (§7.3.3)", status)
        self.assertNotIn("NOT as an external tlsnotary method", status)
        vet = (ROOT / "spec" / "DACS-2-VET.md").read_text(encoding="utf-8")
        self.assertNotIn("does NOT re-run the external tlsnotary method", vet)
        for name in ("CORE.md", "DEMOS-MAPPING.md", "DACS-1-IDENTIFY.md", "DACS-2-VET.md"):
            text = (ROOT / "spec" / name).read_text(encoding="utf-8")
            self.assertNotIn("cci-tlsn claims name", text, name)
            self.assertNotIn("verifies the named proof", text, name)


if __name__ == "__main__":
    unittest.main()
