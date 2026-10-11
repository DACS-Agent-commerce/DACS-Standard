import hashlib
import unittest

from scripts.evm_crypto import _keccak_f1600, evm_address, keccak256


RATE = 136


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


if __name__ == "__main__":
    unittest.main()
