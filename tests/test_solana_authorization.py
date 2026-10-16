"""Independent wire/signature tests for the x402 Solana identity witness."""

import base64
import hashlib
import sys
import unittest
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from scripts.solana_authorization import (
    SignerMismatch, associated_token_account, authorization_identity, base58, decode_transaction,
    on_curve, payment_instruction_defect, program_address, public_key_bytes,
)


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

    def test_messages_the_cluster_sanitizer_refuses_are_refused(self):
        # solana-sdk message sanitize: no program at index 0 (the fee payer),
        # no program loaded from a lookup table, no lookup entry loading nothing.
        table = bytes([25]) * 32
        for name, message in (
            ("program-index-zero", self.message().replace(b"\x01\x02\x01\x01\x01x", b"\x01\x00\x01\x01\x01x")),
            ("program-from-lookup", self.message(lookups=b"\x01" + table + b"\x01\x00\x00").replace(
                b"\x01\x02\x01\x01\x01x", b"\x01\x03\x01\x01\x01x")),
            ("empty-lookup-entry", self.message(lookups=b"\x01" + table + b"\x00\x00")),
            ("legacy-program-index-zero", self.message(versioned=False).replace(
                b"\x01\x02\x01\x01\x01x", b"\x01\x00\x01\x01\x01x")),
        ):
            with self.subTest(name), self.assertRaisesRegex(ValueError, "framing"):
                self.identity(self.transaction(message), before_signing=True)
        # An account (not a program) may still come from a lookup table.
        loaded = self.message(lookups=b"\x01" + table + b"\x01\x00\x00").replace(
            b"\x01\x02\x01\x01\x01x", b"\x01\x02\x01\x03\x01x")
        self.identity(self.transaction(loaded))

    def test_other_signers_are_a_mismatch_not_a_malformed_transaction(self):
        other = Ed25519PrivateKey.from_private_bytes(bytes([24]) * 32)
        other_key = other.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        message = self.message().replace(self.keys[1], other_key)
        full = base64.b64encode(b"\x02" + self.sponsor.sign(message) + other.sign(message) + message).decode()
        with self.assertRaises(SignerMismatch):
            self.identity(full, finalized=True)
        for signer, fee_payer in ((self.payer, base58(other_key)), (base58(other_key), self.fee_payer)):
            with self.subTest(signer=signer), self.assertRaises(SignerMismatch):
                authorization_identity(self.transaction(full=True), signer, fee_payer, finalized=True)
        # A bad signature is a malformed transaction, whoever the signers are.
        raw = bytearray(base64.b64decode(full))
        raw[1] ^= 1
        with self.assertRaises(ValueError) as caught:
            self.identity(base64.b64encode(raw).decode(), finalized=True)
        self.assertNotIsInstance(caught.exception, SignerMismatch)

    def test_program_addresses_match_the_solana_sdk_vectors(self):
        # solana-web3.js v1.x test/publickey.test.ts createProgramAddress vectors.
        loader = public_key_bytes("BPFLoader1111111111111111111111111111111111")

        def created(seeds, program):
            address = hashlib.sha256(b"".join(seeds) + program + b"ProgramDerivedAddress").digest()
            self.assertFalse(on_curve(address))
            return base58(address)
        self.assertEqual(created([b"", b"\x01"], loader), "3gF2KMe9KiC6FNVBmfg9i267aMPvK37FewCip4eGBFcT")
        self.assertEqual(created(["☉".encode()], loader), "7ytmC1nT1xY4RfxCV2ZgyA7UakC93do5ZdyhdF3EtPj7")
        self.assertEqual(created([b"Talking", b"Squirrels"], loader),
                         "HwRVBufQ4haG5XSgpspwKtNd3PC9GM9m1196uJW36vds")
        self.assertEqual(created([public_key_bytes("SeedPubey1111111111111111111111111111111111")], loader),
                         "GUs5qLUfsEHkcMB9T38vjr18ypEhRuNWiePW2LoK4E3K")
        self.assertEqual(created([public_key_bytes("H4snTKK9adiU15gP22ErfZYtro3aqR9BTMXiH3AwiUTQ"),
                                  (2).to_bytes(8, "little")],
                                 public_key_bytes("4ckmDgGdxQoPDLUkDT3vHgSAkzA3QRdNq5ywwY4sUSJn")),
                         "12rqwuEgBYiGhBrDJStCiqEtzQpTTiZbh7teNVLuYcFA")
        # Real public keys decompress; find_program_address skips such bumps.
        for seed in range(40):
            key = Ed25519PrivateKey.from_private_bytes(bytes([seed]) * 32).public_key().public_bytes(
                serialization.Encoding.Raw, serialization.PublicFormat.Raw)
            self.assertTrue(on_curve(key))
        derived = program_address([b"", b"x"], loader)
        self.assertFalse(on_curve(derived))
        for bump in range(255, 0, -1):
            candidate = hashlib.sha256(b"x" + bytes([bump]) + loader + b"ProgramDerivedAddress").digest()
            if candidate == derived:
                break
            self.assertTrue(on_curve(candidate))
        self.assertNotEqual(associated_token_account(self.payer, self.fee_payer, "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"),
                            associated_token_account(self.payer, self.fee_payer, "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb"))

    def test_public_keys_are_canonical_32_byte_base58(self):
        self.assertEqual(public_key_bytes("1" * 32), bytes(32))
        self.assertEqual(public_key_bytes(self.payer), self.keys[1])
        for value in ("1" * 31, "1" * 33, self.payer + "1", "0" + self.payer[1:], "", None, 7):
            with self.subTest(value=value), self.assertRaises(ValueError):
                public_key_bytes(value)

    def test_instruction_bounds_and_memo_forms(self):
        sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
        try:
            import generate_x402_negotiated_protocol_vectors as generator
        finally:
            sys.path.pop(0)
        terms = {"payer": generator.SOLANA_BUYER, "fee_payer": generator.SOLANA_FEE_PAYER,
                 "pay_to": generator.SOLANA_SELLER, "mint": generator.SOLANA_ASSET,
                 "amount": generator.SOLANA_AMOUNT, "decimals": 6,
                 "token_program": generator.SOLANA_TOKEN_PROGRAM}
        budget = generator.COMPUTE_BUDGET_PROGRAM

        def defect(memo=None, edit=None, signed_memo=None, **changed):
            transaction = generator.solana_transactions(memo=signed_memo, edit=edit)[0]
            return payment_instruction_defect(transaction, **{**terms, **changed}, memo=memo)

        self.assertIsNone(defect())
        self.assertIsNone(defect(edit=lambda ins: ins[2:]))  # compute budget is optional
        self.assertIsNone(defect(edit=lambda ins: [
            (budget, [], b"\x02" + (400_000).to_bytes(4, "little")),
            (budget, [], b"\x03" + (5_000_000).to_bytes(8, "little"))] + ins[2:]))
        self.assertEqual(defect(edit=lambda ins: ins[:1] + ins), "compute-budget")  # a repeated limit
        self.assertEqual(defect(edit=lambda ins: [(budget, [], b"\x02" + bytes(3))] + ins[1:]),
                         "compute-budget")
        self.assertIsNone(defect(memo="dacs-274", signed_memo="dacs-274"))
        self.assertIsNone(defect(memo="é" * 128, signed_memo="é" * 128))
        self.assertIsNone(defect(signed_memo="0f" * 16))
        for memo in ("0f" * 15 + "0", "0F" * 16, "dacs-274"):
            with self.subTest(nonce=memo):
                self.assertEqual(defect(signed_memo=memo), "memo")
        self.assertEqual(defect(memo="dacs-274"), "memo")
        self.assertEqual(defect(edit=lambda ins: ins[:3] + [
            (generator.MEMO_PROGRAM, [], b"\xff" * 16)]), "memo")
        self.assertEqual(defect(amount=generator.SOLANA_AMOUNT + 1), "transfer")
        self.assertEqual(defect(token_program="TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb"), "instruction")
        self.assertEqual(defect(token_program=generator.SOLANA_ASSET), "token-program")
        for amount, decimals in ((2**64, 6), (-1, 6), ("1250000", 6), (1, 256)):
            with self.subTest(amount=amount, decimals=decimals), self.assertRaises(ValueError):
                defect(amount=amount, decimals=decimals)


if __name__ == "__main__":
    unittest.main()
