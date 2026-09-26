import base64
import hashlib
import json
import sys
import unittest
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tests"))
FLOW_TRACE = ROOT / "docs" / "flow-trace.md"
GOLDEN = ROOT / "conformance" / "vectors" / "golden.json"

import test_channel_message_vectors as channel_oracle  # noqa: E402
import jcs  # noqa: E402  (repository canonical-form implementation, CORE §B.2)


class FlowTraceSigningTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.signing = json.loads(GOLDEN.read_text())["signing"]
        canonical = json.dumps(
            cls.signing["doc"],
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        cls.digest_hex = hashlib.sha256(canonical).hexdigest()
        cls.signature = base64.urlsafe_b64decode(cls.signing["signature"] + "==")
        cls.public_key = Ed25519PublicKey.from_public_bytes(bytes.fromhex(cls.signing["publicKeyHex"]))

    def test_flow_trace_uses_ascii_hex_artifact_hash(self):
        text = FLOW_TRACE.read_text()
        self.assertIn('concat(utf8(domainSep(kind, "v1")), utf8(artifactHash))', text)
        self.assertNotIn("hexBytes(artifactHash)", text)

    def test_golden_signature_verifies_over_core_b7_preimage(self):
        preimage = self.signing["separator"].encode("utf-8") + self.digest_hex.encode("ascii")
        self.assertEqual(len(preimage), 80)
        self.public_key.verify(self.signature, preimage)

    def test_golden_signature_rejects_raw_digest_preimage(self):
        preimage = self.signing["separator"].encode("utf-8") + bytes.fromhex(self.digest_hex)
        self.assertEqual(len(preimage), 48)
        with self.assertRaises(InvalidSignature):
            self.public_key.verify(self.signature, preimage)

    def test_channel_example_passes_current_read(self):
        """PR #367 review row 3: the docs/flow-trace.md sendChannelMsg
        example emits the CH-7/CH-8 current wire — the exclusive
        discriminator, the version-1 signature envelope, the canonical
        registered-scheme ClaimReference sender, and the exact
        ``dacs-canonical-channel-message:v1: || ASCII(hex digest)`` signed
        bytes — and a message built exactly as documented passes the
        executable current-read oracle with deterministic real signing and
        an independently provisioned membership authority."""
        text = FLOW_TRACE.read_text(encoding="utf-8")

        # The documented example must carry every CH-7/CH-8 element.
        for needle in (
            'canonicalChannelMessageVersion: "1"',
            'signatureVersion: "1"',
            '"dacs-canonical-channel-message:v1:"',
            "sha256Hex(jcs(unsignedMessage))",
            "base64urlNoPad(await sender.sign(",
            "lookupPrimaryClaim(sender)",
            "registered DACS-1 scheme",
            'key:<64 lowercase hex>',
            "unregistered and refused",
            'algorithm: "ed25519"',
        ):
            self.assertIn(needle, text)
        # The retired bare-hex legacy call shape must not remain in the example.
        self.assertNotIn('signedBytes("channelmsg", envHash)', text)

        # Deterministic real signing: fresh labeled key, CH-8 recipe bytes.
        # The sender's primary claim is the canonical registered key: form —
        # the same Ed25519 key spelled with the historical generic cci:
        # scheme is unregistered and must be refused on current-read.
        sender_private = Ed25519PrivateKey.from_private_bytes(
            hashlib.sha256(b"dacs-flow-trace-channel-sender").digest()
        )
        sender_public_hex = (
            sender_private.public_key()
            .public_bytes(
                serialization.Encoding.Raw, serialization.PublicFormat.Raw
            )
            .hex()
        )
        sender_claim = f"key:{sender_public_hex}"
        channel_id = "channel-flow-trace"
        unsigned_message = {
            "canonicalChannelMessageVersion": "1",
            "channelId": channel_id,
            "sequence": 1,
            "sender": sender_claim,
            "sentAt": 1_900_000_000_000,
            "type": "counter",
            "body": {"price": {"amount": "85", "currency": "USDC"}},
        }
        message_hash = hashlib.sha256(
            jcs.canonicalize(unsigned_message).encode("utf-8")
        ).hexdigest()
        signed_bytes = (
            b"dacs-canonical-channel-message:v1:" + message_hash.encode("ascii")
        )
        signature_bytes = sender_private.sign(signed_bytes)
        message = {
            **unsigned_message,
            "signature": {
                "signatureVersion": "1",
                "signer": sender_claim,
                "algorithm": "ed25519",
                "value": base64.urlsafe_b64encode(signature_bytes)
                .rstrip(b"=")
                .decode("ascii"),
            },
        }

        # Independently provisioned authority: this member binding is built
        # from the sender's public key alone, not from the message, and is
        # distinct from the shipped fixture authority.
        authority = channel_oracle.AuthenticatedChannelAuthority({
            channel_id: [
                {
                    "claim": sender_claim,
                    "algorithm": "ed25519",
                    "authorityType": "primary-key",
                    "resolution": "resolved",
                    "publicKeyEncoding": "ed25519-raw-lowercase-hex",
                    "publicKey": sender_public_hex,
                }
            ]
        })
        profile_context = channel_oracle.trusted_profile_admission(channel_id)
        profile_context["participantIdentities"] = [sender_claim]

        def live_issuer():
            return channel_oracle.LiveNegotiationStateIssuer(
                channel_oracle.RetainedChannelRegistry(),
                channel_oracle.AuthenticatedProfileAuthority(profile_context),
                [sender_claim],
            )

        issuer = live_issuer()
        state = issuer.issue(channel_id)

        self.assertEqual(
            "pass",
            channel_oracle.evaluate(message, "current-read", authority, state),
        )
        self.assertEqual(1, state.last_sequence)

        # The same bytes are refused on the archival arm (no fallback), and a
        # tampered body no longer passes current-read.
        fresh_issuer = live_issuer()
        fresh_state = fresh_issuer.issue(channel_id)
        self.assertEqual(
            "error",
            channel_oracle.evaluate(message, "legacy-import", authority, fresh_state),
        )
        tampered = {
            **message,
            "body": {"price": {"amount": "1", "currency": "USDC"}},
        }
        tampered_state = live_issuer().issue(channel_id)
        self.assertEqual(
            "fail",
            channel_oracle.evaluate(tampered, "current-read", authority, tampered_state),
        )
        self.assertEqual(0, tampered_state.last_sequence)

        # Registered-scheme boundary (PR #367 review row 1): the historical
        # generic cci:<64hex> spelling of the same key is unregistered, so an
        # otherwise correctly signed message carrying it is refused by
        # current-read, while the canonical key: spelling above passes.
        generic = {
            **message,
            "sender": f"cci:{sender_public_hex}",
            "signature": {
                **message["signature"],
                "signer": f"cci:{sender_public_hex}",
            },
        }
        generic_unsigned = {
            key: value for key, value in generic.items() if key != "signature"
        }
        generic["signature"]["value"] = base64.urlsafe_b64encode(
            sender_private.sign(
                b"dacs-canonical-channel-message:v1:"
                + hashlib.sha256(
                    jcs.canonicalize(generic_unsigned).encode("utf-8")
                ).hexdigest().encode("ascii")
            )
        ).rstrip(b"=").decode("ascii")
        generic_state = live_issuer().issue(channel_id)
        self.assertEqual(
            "error",
            channel_oracle.evaluate(generic, "current-read", authority, generic_state),
        )
        self.assertEqual(0, generic_state.last_sequence)


if __name__ == "__main__":
    unittest.main()
