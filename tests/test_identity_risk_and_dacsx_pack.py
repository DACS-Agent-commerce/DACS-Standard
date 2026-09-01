import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ROADMAP = ROOT / "ROADMAP.md"
VERIFY_HTLC9 = ROOT / "scripts" / "verify_htlc9_st8_pack.py"
GENERATE_HTLC9 = ROOT / "scripts" / "generate_htlc9_st8_pack.py"
INTERIM = ROOT / "conformance/fixtures/settlement/htlc9-asymmetric.json"
RESOLVED = ROOT / "conformance/fixtures/settlement/htlc9-asymmetric-resolved.json"


class IdentityRiskAndDacsXPackTests(unittest.TestCase):
    def test_v01_spec_does_not_absorb_future_risk_or_dispute_improvements(self):
        text = "\n".join(p.read_text(encoding="utf-8") for p in sorted((ROOT / "spec").glob("*.md")))
        self.assertNotIn('identityTier?: "institutional" | "verified" | "self-declared"', text)
        self.assertNotIn("suspiciousPatternFlags?: string[]", text)
        self.assertNotIn("DACS-X interface seam (non-normative pack)", text)

    def test_roadmap_tracks_identity_reputation_and_dacsx_improvements(self):
        text = ROADMAP.read_text(encoding="utf-8")
        self.assertIn("`identityTier` on IdentityBundle (#103)", text)
        self.assertIn("`dacs-sybil-scan` — behavioural-Sybil flag scanner (#101)", text)
        self.assertIn("DACS-X (dispute / execution-verification)", text)
        self.assertIn("DACS-X shared dispute fixtures / verifier pack (#99)", text)
        # HTLC-9 asymmetric settlement resolves via the ST-8 `settle-asymmetric` state
        # at the settlement layer; the former "correction-amendment" close-out was retired
        # (Round-4 R4-A, §9.5.4). The roadmap references the current mechanism.
        self.assertIn("settle-asymmetric", text)
        self.assertIn("non-normative", text)

    def test_identity_tier_fixture_set_is_machine_readable(self):
        cases = {
            "institutional": "conformance/fixtures/identity/identity-tier-institutional.json",
            "verified": "conformance/fixtures/identity/identity-tier-verified.json",
            "self-declared": "conformance/fixtures/identity/identity-tier-self-declared.json",
        }
        for expected_tier, rel in cases.items():
            with self.subTest(rel=rel):
                data = json.loads((ROOT / rel).read_text(encoding="utf-8"))
                self.assertEqual(data["kind"], "IdentityTierCase")
                self.assertEqual(data["expectedIdentityTier"], expected_tier)
                self.assertIn("identityBundle", data)
                self.assertIn("claims", data["identityBundle"])

    def test_reputation_risk_fixture_is_advisory_only(self):
        fixture = ROOT / "conformance/fixtures/reputation/reputation-suspicious-pattern-flags.json"
        data = json.loads(fixture.read_text(encoding="utf-8"))
        self.assertEqual(data["kind"], "ReputationRiskCase")
        self.assertNotIn("reputationRecord", data)
        derivation = data["reputationDerivation"]
        self.assertEqual(derivation["derivationVersion"], "1")
        self.assertIsInstance(derivation["partyPrimaryClaim"], str)
        self.assertIn(derivation["windowingBasis"], {"finalisedAt", "sr2-anchor-timestamp"})
        self.assertIsInstance(derivation["suspiciousPatternFlags"], list)
        self.assertTrue(derivation["suspiciousPatternFlags"])
        self.assertEqual(data["expectedCoreMetricsUnchanged"], True)

    # ── HTLC-9 / ST-8 supersession pack ───────────────────────────────────────
    # The former DACS-X "correction amendment" fixture was retired (Round-4 R4-A):
    # DACS-4 §9.5.4 resolves the asymmetric branch through the non-terminal
    # settle-asymmetric state and a superseding success record, and states
    # "No `correction` amendment is used". The pack is now that supersession pair,
    # signed with the public orchestrator seed, and the verifier verifies Ed25519.
    # Every guard below is proven load-bearing by a RE-SIGNED mutation, so the
    # signature check alone cannot be what rejects it.

    @staticmethod
    def _load_pack_modules():
        sys.path.insert(0, str(ROOT / "scripts"))
        import generate_htlc9_st8_pack as gen  # noqa: WPS433
        import verify_htlc9_st8_pack as ver  # noqa: WPS433
        return gen, ver

    @staticmethod
    def _mutated(path, mutate, gen):
        data = json.loads(path.read_text(encoding="utf-8"))
        record = data["settlementEvidence"]
        mutate(record)
        record.pop("signature", None)
        gen.sign(record, gen.ORCHESTRATOR_SEED)  # re-sign so only the structural guard can reject
        out = Path(tempfile.mkstemp(suffix=".json")[1])
        out.write_text(json.dumps(data), encoding="utf-8")
        return out

    def test_htlc9_pack_is_deterministic_and_verifies(self):
        check = subprocess.run(["python3", str(GENERATE_HTLC9), "--check"], cwd=ROOT, text=True, capture_output=True)
        self.assertEqual(check.returncode, 0, check.stdout + check.stderr)
        result = subprocess.run(["python3", str(VERIFY_HTLC9)], cwd=ROOT, text=True, capture_output=True)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("both signatures verified", result.stdout)

    def test_htlc9_resolved_record_binds_the_interim_content_hash(self):
        gen, ver = self._load_pack_modules()
        interim = json.loads(INTERIM.read_text(encoding="utf-8"))["settlementEvidence"]
        resolved = json.loads(RESOLVED.read_text(encoding="utf-8"))["settlementEvidence"]
        self.assertEqual(resolved["supersedesEvidenceRef"]["contentHash"], "sha256:" + ver.content_hash_hex(interim))
        self.assertEqual(resolved["outcome"], "success")
        self.assertEqual(resolved["settlementFinality"]["model"], "htlc-reveal")
        self.assertEqual({r["kind"] for r in resolved["paymentTxRefs"]}, {"htlc-lock", "htlc-reveal", "htlc-claim"})
        self.assertNotIn("settlementAmendment", resolved)

    def test_htlc9_verifier_rejects_a_garbage_signature(self):
        gen, ver = self._load_pack_modules()
        for path in (INTERIM, RESOLVED):
            data = json.loads(path.read_text(encoding="utf-8"))
            data["settlementEvidence"]["signature"]["value"] = "NOT-A-SIGNATURE"
            out = Path(tempfile.mkstemp(suffix=".json")[1]); out.write_text(json.dumps(data))
            errors = ver.validate_pair(out, RESOLVED) if path is INTERIM else ver.validate_pair(INTERIM, out)
            self.assertTrue(any("signature" in e for e in errors), errors)

    def test_htlc9_structural_guards_are_load_bearing_under_resigned_mutation(self):
        gen, ver = self._load_pack_modules()
        cases = {
            "resolved without htlc-claim": (RESOLVED, lambda e: e.__setitem__("paymentTxRefs", [r for r in e["paymentTxRefs"] if r["kind"] != "htlc-claim"]), "htlc-claim"),
            "resolved with wrong supersedes hash": (RESOLVED, lambda e: e["supersedesEvidenceRef"].__setitem__("contentHash", "sha256:" + "00" * 32), "content hash"),
            "resolved smuggling a correction amendment": (RESOLVED, lambda e: e.__setitem__("settlementAmendment", {"amendmentType": "correction"}), "amendment"),
            "resolved without settlementFinality": (RESOLVED, lambda e: e.pop("settlementFinality"), "settlementFinality"),
            "resolved without paymentAmount": (RESOLVED, lambda e: e.pop("paymentAmount"), "paymentAmount"),
            "resolved with outcome failure": (RESOLVED, lambda e: e.__setitem__("outcome", "failure"), "outcome success"),
            "interim carrying an htlc-claim": (INTERIM, lambda e: e["paymentTxRefs"].append({"kind": "htlc-claim", "chainId": 84532, "contractAddress": "0x" + "0" * 40, "claimTxHash": "0x" + "cc" * 32}), "htlc-claim"),
            "interim with outcome success": (INTERIM, lambda e: e.__setitem__("outcome", "success"), "outcome failure"),
        }
        for name, (path, mutate, needle) in cases.items():
            with self.subTest(name=name):
                out = self._mutated(path, mutate, gen)
                errors = ver.validate_pair(out, RESOLVED) if path is INTERIM else ver.validate_pair(INTERIM, out)
                self.assertTrue(errors, f"{name}: accepted")
                self.assertFalse(any("signature does not verify" in e for e in errors), f"{name}: rejected only by the signature check, not the guard: {errors}")
                self.assertTrue(any(needle in e for e in errors), f"{name}: rejected for a different reason: {errors}")

    def test_dacsx_correction_zombie_is_gone(self):
        self.assertFalse((ROOT / "conformance/fixtures/dacsx").exists())
        self.assertFalse((ROOT / "scripts/verify_dacsx_dispute_pack.py").exists())
