import base64
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
    def _write(data):
        out = Path(tempfile.mkstemp(suffix=".json")[1])
        out.write_text(json.dumps(data), encoding="utf-8")
        return out

    @classmethod
    def _pair(cls, gen, mutate_interim=None, mutate_resolved=None):
        """Build a (interim, resolved) pair where the resolved record is REBOUND to the
        (possibly mutated) interim and both are RE-SIGNED, so the only thing that can
        reject a mutation is the structural guard it targets — never the signature check
        and never the supersession hash as a side effect."""
        interim = gen.interim_record()
        interim.pop("signature")
        if mutate_interim:
            mutate_interim(interim)
        gen.sign(interim, gen.ORCHESTRATOR_SEED)
        resolved = gen.resolved_record(interim)
        resolved.pop("signature")
        if mutate_resolved:
            mutate_resolved(resolved)
        gen.sign(resolved, gen.ORCHESTRATOR_SEED)
        wrap = lambda r: {"kind": "SettlementEvidenceCase", "settlementEvidence": r, "specRefs": ["§9.5.4"]}
        return cls._write(wrap(interim)), cls._write(wrap(resolved))

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
        ref = resolved["supersedesEvidenceRef"]
        self.assertEqual(set(ref), {"anchor", "contentHash"})            # DACS-2 §7.5.2 shape, not the pre-#308 flat form
        self.assertEqual(set(ref["anchor"]), {"kind", "locator"})
        self.assertEqual(ref["contentHash"], ver.content_hash_hex(interim))
        self.assertEqual(resolved["outcome"], "success")
        self.assertEqual(resolved["settlementFinality"]["model"], "htlc-reveal")
        self.assertEqual({r["kind"] for r in resolved["paymentTxRefs"]}, {"htlc-lock", "htlc-reveal", "htlc-claim"})
        self.assertNotIn("settlementAmendment", resolved)

    def test_htlc9_verifier_rejects_a_garbage_signature(self):
        gen, ver = self._load_pack_modules()
        for which in ("interim", "resolved"):
            i, r = self._pair(gen)
            data = json.loads((i if which == "interim" else r).read_text())
            data["settlementEvidence"]["signature"]["value"] = "NOT-A-SIGNATURE"
            out = self._write(data)
            errors = ver.validate_pair(out, r) if which == "interim" else ver.validate_pair(i, out)
            self.assertTrue(any("SIG-6" in e or "signature" in e for e in errors), errors)

    def test_htlc9_verifier_rejects_a_noncanonical_sig6_encoding(self):
        gen, ver = self._load_pack_modules()
        i, r = self._pair(gen)
        data = json.loads(r.read_text()); value = data["settlementEvidence"]["signature"]["value"]
        raw = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
        alt = next(value[:-1] + c for c in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
                   if c != value[-1] and base64.urlsafe_b64decode(value[:-1] + c + "=" * (-len(value) % 4)) == raw)
        data["settlementEvidence"]["signature"]["value"] = alt      # same bytes, non-canonical spelling
        errors = ver.validate_pair(i, self._write(data))
        self.assertTrue(any("SIG-6" in e for e in errors), errors)

    def test_htlc9_structural_guards_are_load_bearing_under_resigned_rebound_mutation(self):
        gen, ver = self._load_pack_modules()
        R, I = "resolved", "interim"
        cases = {
            "resolved without htlc-claim": (R, lambda e: e.__setitem__("paymentTxRefs", [x for x in e["paymentTxRefs"] if x["kind"] != "htlc-claim"]), "htlc-claim"),
            "resolved without htlc-lock": (R, lambda e: e.__setitem__("paymentTxRefs", [x for x in e["paymentTxRefs"] if x["kind"] != "htlc-lock"]), "htlc-lock"),
            "resolved without htlc-reveal": (R, lambda e: e.__setitem__("paymentTxRefs", [x for x in e["paymentTxRefs"] if x["kind"] != "htlc-reveal"]), "htlc-reveal"),
            "resolved kind-only claim (no claimTxHash)": (R, lambda e: e["paymentTxRefs"].__setitem__(2, {"kind": "htlc-claim"}), "claimTxHash"),
            "resolved lock differs from interim": (R, lambda e: e["paymentTxRefs"][0].__setitem__("lockTxHash", "0x" + "dd" * 32), "identical to the interim"),
            "resolved wrong supersedes hash": (R, lambda e: e["supersedesEvidenceRef"].__setitem__("contentHash", "00" * 32), "content hash"),
            "resolved flat pre-#308 AttestationRef": (R, lambda e: e.__setitem__("supersedesEvidenceRef", {"kind": "storage-program", "locator": "x", "contentHash": e["supersedesEvidenceRef"]["contentHash"]}), "unknown field"),
            "resolved smuggling settlementAmendment": (R, lambda e: e.__setitem__("settlementAmendment", {"amendmentType": "correction"}), "amendment"),
            "resolved smuggling amendmentRefs": (R, lambda e: e.__setitem__("amendmentRefs", []), "amendment"),
            "resolved smuggling amendsEvidenceRef": (R, lambda e: e.__setitem__("amendsEvidenceRef", {}), "amendment"),
            "resolved smuggling refundAmount": (R, lambda e: e.__setitem__("refundAmount", {"amount": "1", "currency": "USDC"}), "amendment"),
            "resolved without settlementFinality": (R, lambda e: e.pop("settlementFinality"), "settlementFinality"),
            "resolved finality model bft-final": (R, lambda e: e["settlementFinality"].__setitem__("model", "bft-final"), "htlc-reveal"),
            "resolved finalityObservedAt as string": (R, lambda e: e["settlementFinality"].__setitem__("finalityObservedAt", "1760000290000"), "finalityObservedAt"),
            "resolved without paymentAmount": (R, lambda e: e.pop("paymentAmount"), "paymentAmount"),
            "resolved paymentAmount zero": (R, lambda e: e["paymentAmount"].__setitem__("amount", "0"), "CD-1"),
            "resolved paymentAmount non-canonical 25.0": (R, lambda e: e["paymentAmount"].__setitem__("amount", "25.0"), "CD-1"),
            "resolved outcome failure": (R, lambda e: e.__setitem__("outcome", "failure"), "outcome success"),
            "resolved wrong evidenceVersion": (R, lambda e: e.__setitem__("evidenceVersion", "2"), "evidenceVersion"),
            "resolved wrong phase": (R, lambda e: e.__setitem__("phase", "pay-dem"), "phase"),
            "resolved observedAt as string": (R, lambda e: e.__setitem__("observedAt", "1"), "observedAt"),
            "resolved jobId differs from interim": (R, lambda e: e.__setitem__("jobId", "01OTHERJOB0000000000000000"), "jobId"),
            "interim carrying an htlc-claim": (I, lambda e: e["paymentTxRefs"].append({"kind": "htlc-claim", "chainId": 84532, "contractAddress": "0x" + "0" * 40, "claimTxHash": "0x" + "cc" * 32}), "htlc-claim"),
            "interim outcome success": (I, lambda e: e.__setitem__("outcome", "success"), "outcome failure"),
            "interim wrong reason": (I, lambda e: e.__setitem__("reason", "timeout"), "dest-revealed-source-unclaimed"),
            "interim without htlc-reveal": (I, lambda e: e.__setitem__("paymentTxRefs", [x for x in e["paymentTxRefs"] if x["kind"] != "htlc-reveal"]), "htlc-reveal"),
            "interim without htlc-lock": (I, lambda e: e.__setitem__("paymentTxRefs", [x for x in e["paymentTxRefs"] if x["kind"] != "htlc-lock"]), "htlc-lock"),
            "interim carrying settlementFinality": (I, lambda e: e.__setitem__("settlementFinality", {"model": "htlc-reveal", "finalityObservedAt": 1}), "settlementFinality"),
            # ── topology and closed arms (round-2 reviewer counterexamples) ──
            "resolved claim on the destination chain": (R, lambda e: next(r for r in e["paymentTxRefs"] if r["kind"] == "htlc-claim").__setitem__("chainId", 80002), "claim.chainId == lock.chainId"),
            "resolved claim against a different contract": (R, lambda e: next(r for r in e["paymentTxRefs"] if r["kind"] == "htlc-claim").__setitem__("contractAddress", "0x" + "9" * 40), "claim.contractAddress == lock.contractAddress"),
            "resolved second htlc-lock appended": (R, lambda e: e["paymentTxRefs"].append({"kind": "htlc-lock", "chainId": 84532, "contractAddress": "0x" + "0" * 39 + "8", "lockTxHash": "0x" + "99" * 32}), "exactly one htlc-lock"),
            "resolved second htlc-claim appended": (R, lambda e: e["paymentTxRefs"].append({"kind": "htlc-claim", "chainId": 84532, "contractAddress": "0x" + "0" * 39 + "8", "claimTxHash": "0x" + "ee" * 32}), "exactly one htlc-claim"),
            "resolved extra field on a txRef": (R, lambda e: next(r for r in e["paymentTxRefs"] if r["kind"] == "htlc-reveal").__setitem__("note", "x"), "unknown field"),
            "resolved anchor.kind outside the enum": (R, lambda e: e["supersedesEvidenceRef"]["anchor"].__setitem__("kind", "not-a-kind"), "anchor.kind"),
            "resolved empty anchor.locator": (R, lambda e: e["supersedesEvidenceRef"]["anchor"].__setitem__("locator", ""), "locator"),
            "resolved non-string signer on the ref": (R, lambda e: e["supersedesEvidenceRef"].__setitem__("signer", 7), "signer"),
            "resolved empty currency": (R, lambda e: e["paymentAmount"].__setitem__("currency", ""), "currency"),
            "resolved invalid ULID jobId (interim too, so they still match)": (R, lambda e: e.__setitem__("jobId", "01HTLC9ASYMMETRIC000000000000"), "ULID"),
            "resolved reveal differs from interim": (R, lambda e: next(r for r in e["paymentTxRefs"] if r["kind"] == "htlc-reveal").__setitem__("revealTxHash", "0x" + "ab" * 32), "identical to the interim"),
            "interim second htlc-lock appended": (I, lambda e: e["paymentTxRefs"].append({"kind": "htlc-lock", "chainId": 84532, "contractAddress": "0x" + "0" * 39 + "8", "lockTxHash": "0x" + "99" * 32}), "exactly one htlc-lock"),
            "interim invalid ULID jobId": (I, lambda e: e.__setitem__("jobId", "01HTLC9ASYMMETRIC000000000000"), "ULID"),
        }
        # Both-sides topology case: mutate the interim; the resolved record inherits the
        # mutated lock/reveal, so cross-pair identity holds and ONLY the topology guard can
        # reject. (A pair CONSISTENTLY mirrored onto the other chain is not a case here: with
        # no rail context, "source" is wherever the lock is, so that pair is indistinguishable
        # from a correct one — a documented scope limit of this pack, see the verifier docstring.)
        both = {
            "all three legs on one chain": (lambda e: next(r for r in e["paymentTxRefs"] if r["kind"] == "htlc-reveal").__setitem__("chainId", 84532), "reveal.chainId != lock.chainId"),
        }
        for name, (mutate, needle) in both.items():
            with self.subTest(name=name):
                i, r = self._pair(gen, mutate_interim=mutate, mutate_resolved=None)   # resolved inherits the mutated lock/reveal from the interim
                errors = ver.validate_pair(i, r)
                self.assertTrue(errors, f"{name}: accepted")
                self.assertFalse(any("signature does not verify" in e or "SIG-6" in e or "content hash" in e or "identical to the interim" in e for e in errors), f"{name}: rejected by a backstop, not topology: {errors}")
                self.assertTrue(any(needle in e for e in errors), f"{name}: rejected for a different reason: {errors}")
        for name, (which, mutate, needle) in cases.items():
            with self.subTest(name=name):
                if "interim too" in name:
                    i, r = self._pair(gen, mutate_interim=mutate, mutate_resolved=mutate)
                else:
                    i, r = self._pair(gen, mutate_interim=mutate if which == I else None, mutate_resolved=mutate if which == R else None)
                errors = ver.validate_pair(i, r)
                self.assertTrue(errors, f"{name}: accepted")
                self.assertFalse(any("signature does not verify" in e or "SIG-6" in e for e in errors), f"{name}: rejected by the signature check, not the guard: {errors}")
                if which == I and "content hash" not in needle:
                    self.assertFalse(any("content hash" in e for e in errors), f"{name}: rejected by the supersession hash backstop, not the guard: {errors}")
                self.assertTrue(any(needle in e for e in errors), f"{name}: rejected for a different reason: {errors}")

    def test_dacsx_correction_zombie_is_gone(self):
        self.assertFalse((ROOT / "conformance/fixtures/dacsx").exists())
        self.assertFalse((ROOT / "scripts/verify_dacsx_dispute_pack.py").exists())
