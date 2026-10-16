"""Independent wire/signature tests for the x402 Solana identity witness."""

import base64
import hashlib
import unittest

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from scripts.solana_authorization import authorization_identity, base58, decode_transaction


class SolanaAuthorizationTests(unittest.TestCase):
    def setUp(self):
        self.sponsor = Ed25519PrivateKey.from_private_bytes(bytes([11]) * 32)
        self.client = Ed25519PrivateKey.from_private_bytes(bytes([12]) * 32)
        self.keys = [key.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw)
            for key in (self.sponsor, self.client)]
        self.payer, self.fee_payer = base58(self.keys[1]), base58(self.keys[0])

    def message(self, *, versioned=True, lookups=b"\0"):
        # One harmless instruction, using a static program account. Identity
        # is deliberately independent of the ledger's transfer-outcome mock.
        return ((b"\x80" if versioned else b"") + b"\x02\x01\x01\x03"
                + b"".join(self.keys) + bytes([13]) * 32 + bytes([14]) * 32
                + b"\x01\x02\x01\x01\x01x" + (lookups if versioned else b""))

    def transaction(self, message=None, *, full=False, client_signature=None):
        message = self.message() if message is None else message
        sponsor = self.sponsor.sign(message) if full else bytes(64)
        client = self.client.sign(message) if client_signature is None else client_signature
        return base64.b64encode(b"\x02" + sponsor + client + message).decode()

    def identity(self, transaction, **kwargs):
        return authorization_identity(transaction, self.payer, self.fee_payer, **kwargs)

    def test_sponsor_cosigning_keeps_message_and_client_identity(self):
        for versioned in (False, True):
            with self.subTest(versioned=versioned):
                message = self.message(versioned=versioned)
                partial = self.transaction(message)
                full = self.transaction(message, full=True)
                identity, unknown = self.identity(partial)
                resolved, transaction_id = self.identity(full, finalized=True)
                self.assertEqual(identity, resolved)
                self.assertIsNone(unknown)
                self.assertEqual(transaction_id, base58(self.sponsor.sign(message)))
                self.assertEqual(identity, {
                    "payer": self.payer,
                    "messageHash": hashlib.sha256(message).hexdigest(),
                    "clientSignatures": [{"publicKey": self.payer,
                                          "signature": base58(self.client.sign(message))}],
                })

    def test_different_signed_message_has_a_different_identity(self):
        first = self.message()
        second = first.replace(bytes([14]) * 32, bytes([15]) * 32)
        self.assertNotEqual(self.identity(self.transaction(first))[0],
                            self.identity(self.transaction(second))[0])

    def test_signatures_are_verified_over_the_exact_message(self):
        partial = self.transaction()
        full = self.transaction(full=True)
        for slot in (0, 1):
            raw = bytearray(base64.b64decode(full))
            raw[1 + slot * 64] ^= 1
            with self.subTest(slot=slot), self.assertRaisesRegex(ValueError, "signature"):
                self.identity(base64.b64encode(raw).decode(), finalized=True)
        with self.assertRaisesRegex(ValueError, "signature"):
            self.identity(partial, finalized=True)
        unsigned = self.transaction(client_signature=bytes(64))
        self.identity(unsigned, before_signing=True)
        with self.assertRaisesRegex(ValueError, "signature"):
            self.identity(unsigned)

    def test_payer_and_sponsor_must_be_the_message_signers(self):
        for payer, sponsor in ((self.fee_payer, self.payer),
                               (base58(bytes([22]) * 32), self.fee_payer),
                               (self.payer, base58(bytes([23]) * 32)),
                               (self.fee_payer, self.fee_payer)):
            with self.subTest(payer=payer, sponsor=sponsor), self.assertRaises(ValueError):
                authorization_identity(self.transaction(), payer, sponsor)

    def test_lookup_table_framing_is_consumed_and_committed(self):
        lookups = b"\x01" + bytes([25]) * 32 + b"\x01\x02\x01\x03"
        message = self.message(lookups=lookups)
        self.assertEqual(decode_transaction(self.transaction(message))[0], message)
        self.assertNotEqual(self.identity(self.transaction(message))[0],
                            self.identity(self.transaction())[0])

    def test_malformed_framing_is_refused_even_before_signing(self):
        message = self.message()
        raw = base64.b64decode(self.transaction())
        malformed = [
            b"", raw[:-1], raw + b"extra", bytes(1233),
            b"\x82\x00" + raw[1:],  # noncanonical signature count
            b"\xff\xff\x04",       # compact-u16 overflow
            raw[:129] + b"\x81" + message[1:],  # unknown message version
            raw[:130] + b"\x01" + message[2:],  # signer count != slots
            raw[:131] + b"\x02" + message[3:],  # every signer readonly
            raw[:129] + message.replace(self.keys[1], self.keys[0]),
            raw[:129] + message[:-7] + b"\x01\xff\x01\x01\x01x\0",
        ]
        for value in malformed:
            with self.subTest(raw=value[:6]), self.assertRaises(ValueError):
                self.identity(base64.b64encode(value).decode(), before_signing=True)
        for value in (None, 7, "not base64!", "A" * 1648):
            with self.subTest(encoded=value), self.assertRaises(ValueError):
                self.identity(value, before_signing=True)


if __name__ == "__main__":
    unittest.main()
