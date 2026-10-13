import hashlib
import hmac
import unittest
from unittest import mock

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

from scripts import evm_crypto
from scripts.evm_crypto import (
    SECP256K1_ORDER,
    _keccak_f1600,
    _rfc6979_nonce,
    deterministic_ecdsa_sha256,
    evm_address,
    keccak256,
    uncompressed_public_key,
)


RATE = 136
N = SECP256K1_ORDER
# Published RFC 6979 secp256k1 / SHA-256 known answers (the set in bitcoinjs-lib's
# ecdsa fixtures and trezor-crypto's tests): private scalar, message, nonce k,
# and the low-S signature (r, s).
RFC6979_SECP256K1_SHA256 = (
    (1, b"Satoshi Nakamoto",
     0x8F8A276C19F4149656B280621E358CCE24F5F52542772691EE69063B74F15D15,
     0x934B1EA10A4B3C1757E2B0C017D0B6143CE3C9A7E6A4A49860D7A6AB210EE3D8,
     0x2442CE9D2B916064108014783E923EC36B49743E2FFA1C4496F01A512AAFD9E5),
    (1, b"All those moments will be lost in time, like tears in rain. Time to die...",
     0x38AA22D72376B4DBC472E06C3BA403EE0A394DA63FC58D88686C611ABA98D6B3,
     0x8600DBD41E348FE5C9465AB92D23E3DB8B98B873BEECD930736488696438CB6B,
     0x547FE64427496DB33BF66019DACBF0039C04199ABB0122918601DB38A72CFC21),
    (0xF8B8AF8CE3C7CCA5E300D33939540C10D45CE001B8F252BFBC57BA0342904181, b"Alan Turing",
     0x525A82B70E67874398067543FD84C83D30C175FDC45FDEEE082FE13B1D7CFDF1,
     0x7063AE83E7F62BBB171798131B4A0564B956930092B33B07B395615D9EC7E15C,
     0x58DFCC1E00A35E1572F366FFE34BA0FC47DB1E7189759B9FB233C5B05AB388EA),
    (0xE91671C46231F833A6406CCBEA0E3E392C76C167BAC1CB013F6F1013980455C2,
     b"There is a computer disease that anybody who works with computers knows about. "
     b"It's a very serious disease and it interferes completely with the work. The "
     b"trouble with computers is that you 'play' with them!",
     0x1F4B84C23A86A221D233F2521BE018D9318639D5B8BBD6374A8A59232D16AD3D,
     0xB552EDD27580141F3B2A5463048CB7CD3E047B97C9F98076C32DBDF85A68718B,
     0x279FA72DD19BFAE05577E06C7C0C1900C371FCD5893F7E1D56A37D30174671F6),
)
# The same set's nonce for the largest private scalar, n - 1.
RFC6979_LARGEST_SCALAR_NONCE = 0x33A19B60E25FB6F4435AF53A3D42D493644827367E6453928554F43E49AA6F90


def reference_sponge(data, suffix):
    """Textbook Keccak[r=1088, c=512] sponge with pad10*1, independent of keccak256.

    The domain bits and the final 0x80 bit are XORed into the same zero-filled
    padding, so a message of length 135 mod 136 receives the single byte
    ``suffix | 0x80`` and no extra block. SHA3-256 (suffix 0x06) and legacy
    Keccak-256 (suffix 0x01) differ only in that suffix.
    """
    padded = bytearray(data) + bytearray(RATE - len(data) % RATE)
    padded[len(data)] ^= suffix
    padded[-1] ^= 0x80
    state = [0] * 25
    for offset in range(0, len(padded), RATE):
        for lane in range(RATE // 8):
            start = offset + lane * 8
            state[lane] ^= int.from_bytes(padded[start:start + 8], "little")
        _keccak_f1600(state)
    return b"".join(value.to_bytes(8, "little") for value in state)[:32]


# Every length across three rate blocks, so each block boundary and each
# "one byte short of a boundary" length is exercised.
LENGTHS = range(3 * RATE + 2)


def message(length):
    return bytes((index * 7 + 3) & 0xFF for index in range(length))


class EvmCryptoTests(unittest.TestCase):
    def test_reference_sponge_matches_openssl_sha3_256(self):
        # Anchors the permutation and the reference padding to an independent
        # implementation: with the SHA3 suffix they must agree with hashlib.
        for length in LENGTHS:
            with self.subTest(length=length):
                data = message(length)
                self.assertEqual(
                    reference_sponge(data, 0x06), hashlib.sha3_256(data).digest()
                )

    def test_keccak256_pads_every_length_like_the_reference_sponge(self):
        for length in LENGTHS:
            with self.subTest(length=length):
                data = message(length)
                self.assertEqual(keccak256(data), reference_sponge(data, 0x01))

    def test_keccak256_known_answers(self):
        self.assertEqual(
            keccak256(b"").hex(),
            "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470",
        )
        self.assertEqual(
            keccak256(b"abc").hex(),
            "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45",
        )

    def test_generator_point_address(self):
        generator_public_key = bytes.fromhex(
            "0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
            "483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8"
        )
        self.assertEqual(
            evm_address(generator_public_key),
            "0x7e5f4552091a69125d5dfcb7b8c2659029395bdf",
        )

    def test_rfc6979_known_answers(self):
        """The nonce and the low-S signature equal the published secp256k1 vectors."""
        for scalar, payload, nonce, r, s in RFC6979_SECP256K1_SHA256:
            with self.subTest(message=payload[:24]):
                self.assertEqual(_rfc6979_nonce(scalar, hashlib.sha256(payload).digest()), nonce)
                signature = deterministic_ecdsa_sha256(scalar, payload)
                self.assertEqual(decode_dss_signature(signature), (r, s))
                public = ec.EllipticCurvePublicKey.from_encoded_point(
                    ec.SECP256K1(), uncompressed_public_key(scalar))
                public.verify(signature, payload, ec.ECDSA(hashes.SHA256()))
        self.assertEqual(
            _rfc6979_nonce(N - 1, hashlib.sha256(b"Satoshi Nakamoto").digest()),
            RFC6979_LARGEST_SCALAR_NONCE,
        )

    def test_signatures_are_low_s(self):
        """s <= n/2 always; a high raw s is replaced by n - s, the same signature's low form."""
        normalized = 0
        for index in range(32):
            payload = f"low-s {index}".encode("ascii")
            z = int.from_bytes(hashlib.sha256(payload).digest(), "big")
            nonce = _rfc6979_nonce(1, hashlib.sha256(payload).digest())
            r, s = decode_dss_signature(deterministic_ecdsa_sha256(1, payload))
            raw = pow(nonce, -1, N) * (z + r) % N
            with self.subTest(payload=payload):
                self.assertLessEqual(s, N // 2)
                self.assertEqual(s, raw if raw <= N // 2 else N - raw)
            normalized += raw > N // 2
        self.assertGreater(normalized, 0)

    def test_rfc6979_nonce_retry_updates_k_and_v(self):
        """RFC 6979 §3.2 step h.3: an out-of-range candidate updates K and V before the next.

        With secp256k1's order a retry is about a 2**-128 event, so no published
        vector reaches it. The order is patched down to 2**255, where about half
        of the first candidates fall outside [1, q-1], and the nonce is compared
        with step h written out from the RFC.
        """
        order = 2**255

        def step_h(scalar, message_hash):
            x = scalar.to_bytes(32, "big")
            h1 = (int.from_bytes(message_hash, "big") % order).to_bytes(32, "big")
            k = hmac.new(b"\x00" * 32, b"\x01" * 32 + b"\x00" + x + h1, hashlib.sha256).digest()
            v = hmac.new(k, b"\x01" * 32, hashlib.sha256).digest()
            k = hmac.new(k, v + b"\x01" + x + h1, hashlib.sha256).digest()
            v = hmac.new(k, v, hashlib.sha256).digest()
            retries = 0
            while True:
                v = hmac.new(k, v, hashlib.sha256).digest()
                candidate = int.from_bytes(v, "big")
                if 1 <= candidate < order:
                    return candidate, retries
                k = hmac.new(k, v + b"\x00", hashlib.sha256).digest()
                v = hmac.new(k, v, hashlib.sha256).digest()
                retries += 1

        retried = 0
        with mock.patch.object(evm_crypto, "SECP256K1_ORDER", order):
            for index in range(16):
                message_hash = hashlib.sha256(f"retry {index}".encode("ascii")).digest()
                want, retries = step_h(7, message_hash)
                with self.subTest(index=index):
                    self.assertEqual(_rfc6979_nonce(7, message_hash), want)
                retried += retries > 0
        self.assertGreater(retried, 0)


if __name__ == "__main__":
    unittest.main()
