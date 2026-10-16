"""Solana wire-transaction identity for the negotiated x402 reference adapter.

This decodes transaction framing and verifies signer identity, not token-program
execution. Transfer outcomes and finality still come from authenticated ledger
data. The sponsor may fill its signature slot without changing this identity.
"""

import base64
import hashlib

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def base58(raw):
    number = int.from_bytes(raw, "big")
    result = ""
    while number:
        number, digit = divmod(number, 58)
        result = ALPHABET[digit] + result
    return "1" * (len(raw) - len(raw.lstrip(b"\0"))) + result


def decode_transaction(encoded):
    """Return (exact message bytes, static signer keys, signature slots).

    Solana's packet bound limits all loops. Compact lengths must be canonical
    u16 values; both legacy and v0 messages must be consumed in full.
    """
    if not isinstance(encoded, str) or len(encoded) > 1644:
        raise ValueError("transaction encoding")
    try:
        raw = base64.b64decode(encoded, validate=True)
    except (TypeError, ValueError) as exc:
        raise ValueError("transaction encoding") from exc
    if not 1 <= len(raw) <= 1232:
        raise ValueError("transaction size")
    offset = 0

    def take(size):
        nonlocal offset
        end = offset + size
        if end > len(raw):
            raise ValueError("truncated transaction")
        result = raw[offset:end]
        offset = end
        return result

    def length():
        result = 0
        for index in range(3):
            byte = take(1)[0]
            result |= (byte & 127) << (7 * index)
            if not byte & 128:
                if result > 65535 or (index and byte == 0):
                    break
                return result
        raise ValueError("noncanonical compact-u16")

    signatures = [take(64) for _ in range(length())]
    message_start = offset
    first = take(1)[0]
    versioned = bool(first & 128)
    if versioned:
        if first != 128:
            raise ValueError("unsupported message version")
        required = take(1)[0]
    else:
        required = first
    readonly_signed, readonly_unsigned = take(2)
    keys = [take(32) for _ in range(length())]
    if (not 1 <= required <= len(keys) <= 256 or required != len(signatures)
            or readonly_signed >= required or readonly_unsigned > len(keys) - required
            or len(set(keys)) != len(keys)):
        raise ValueError("invalid signer header")
    take(32)  # recent blockhash, part of the exact signed message
    # Indices may reference lookup-table addresses; check against the complete
    # count after the lookup-table framing has been read.
    indices = []
    for _ in range(length()):
        indices.append(take(1)[0])
        indices.extend(take(length()))
        take(length())
    loaded = 0
    if versioned:
        for _ in range(length()):
            take(32)
            for _ in range(2):
                count = length()
                take(count)
                loaded += count
    if offset != len(raw) or len(keys) + loaded > 256 or any(
            index >= len(keys) + loaded for index in indices):
        raise ValueError("invalid message framing")
    return raw[message_start:], keys[:required], signatures


def authorization_identity(encoded, payer, fee_payer, *, before_signing=False, finalized=False):
    """Bind the exact message and every non-sponsor client signature.

    The first signature is the sponsor's transaction ID, unknown before it
    co-signs. A finalized transaction must verify that signature as well.
    """
    message, keys, signatures = decode_transaction(encoded)
    if base58(keys[0]) != fee_payer or payer == fee_payer or payer not in {
            base58(key) for key in keys[1:]}:
        raise ValueError("payer/sponsor signer mismatch")
    clients = []
    for index, (key, signature) in enumerate(zip(keys, signatures)):
        if index == 0 and not finalized:
            continue
        if finalized or not before_signing:
            try:
                Ed25519PublicKey.from_public_bytes(key).verify(signature, message)
            except InvalidSignature as exc:
                raise ValueError("invalid transaction signature") from exc
        if index:
            clients.append({"publicKey": base58(key), "signature": base58(signature)})
    identity = {
        "payer": payer,
        "messageHash": hashlib.sha256(message).hexdigest(),
        "clientSignatures": clients,
    }
    return identity, base58(signatures[0]) if finalized else None
