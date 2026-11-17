"""Local signing adapter for conformance tests; no network or live credentials."""
import hashlib

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


class FixtureSigner:
    def __init__(self, label="settlement-runtime-fixture"):
        # Public deterministic fixture material, unrelated to any live account.
        self.key = Ed25519PrivateKey.from_private_bytes(hashlib.sha256(label.encode()).digest())
        self.sign_calls = 0

    def is_available(self):
        return True

    def sign(self, payload):
        self.sign_calls += 1
        return self.key.sign(payload)
