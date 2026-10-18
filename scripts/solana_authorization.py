"""Solana wire-transaction identity for the negotiated x402 reference adapter.

This decodes transaction framing, verifies signer identity, and checks that
the message's instructions are exactly the payment the signed terms allow
(§9.5.7.1). Transfer outcomes and finality still come from authenticated
ledger data. The sponsor may fill its signature slot without changing this
identity.
"""

import base64
import hashlib
import re

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
TOKEN_PROGRAMS = frozenset({
    "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA",  # SPL Token
    "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb",  # Token-2022
})
ASSOCIATED_TOKEN_PROGRAM = "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL"
COMPUTE_BUDGET_PROGRAM = "ComputeBudget111111111111111111111111111111"
MEMO_PROGRAM = "MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr"
# The pinned scheme's reference sponsor bounds (scheme_exact_svm.md §2.2.1, §3.1).
MAX_COMPUTE_UNITS = 400_000
MAX_COMPUTE_UNIT_PRICE = 5_000_000  # micro-lamports: 5 lamports per compute unit
MEMO_NONCE = re.compile(r"[0-9a-f]{32,256}")
TRANSFER_CHECKED = 12
# ed25519 over GF(2^255 - 19), for the off-curve test of a program address.
FIELD = 2**255 - 19
CURVE_D = -121665 * pow(121666, FIELD - 2, FIELD) % FIELD


class SignerMismatch(ValueError):
    """A well-formed, validly signed transaction whose signers are not this payment's."""


def base58(raw):
    number = int.from_bytes(raw, "big")
    result = ""
    while number:
        number, digit = divmod(number, 58)
        result = ALPHABET[digit] + result
    return "1" * (len(raw) - len(raw.lstrip(b"\0"))) + result


def public_key_bytes(value):
    """A base58 public key's 32 bytes; anything else is ValueError."""
    if not isinstance(value, str) or not value or any(char not in ALPHABET for char in value):
        raise ValueError("public key form")
    number = 0
    for char in value:
        number = number * 58 + ALPHABET.index(char)
    zeroes = len(value) - len(value.lstrip("1"))
    raw = b"\0" * zeroes + (number.to_bytes((number.bit_length() + 7) // 8, "big") if number else b"")
    if len(raw) != 32 or base58(raw) != value:
        raise ValueError("public key form")
    return raw


def on_curve(raw):
    """Whether 32 bytes decompress to an ed25519 point, as Solana's is_on_curve decides."""
    y = int.from_bytes(raw, "little") & (2**255 - 1)
    u = (y * y - 1) % FIELD
    v = (CURVE_D * y * y + 1) % FIELD
    square = u * pow(v, FIELD - 2, FIELD) % FIELD
    return square == 0 or pow(square, (FIELD - 1) // 2, FIELD) == 1


def program_address(seeds, program):
    """find_program_address: the highest-bump off-curve address."""
    for bump in range(255, 0, -1):
        candidate = hashlib.sha256(b"".join(seeds) + bytes([bump]) + program
                                   + b"ProgramDerivedAddress").digest()
        if not on_curve(candidate):
            return candidate
    raise ValueError("no program address")


def associated_token_account(owner, mint, token_program):
    """The associated token account of base58 `owner` for `mint` under `token_program`."""
    return base58(program_address(
        [public_key_bytes(owner), public_key_bytes(token_program), public_key_bytes(mint)],
        public_key_bytes(ASSOCIATED_TOKEN_PROGRAM)))


def parse_transaction(encoded):
    """Return the decoded transaction as a dict.

    `message` is the exact message bytes, `keys` the static account keys,
    `required` the signer count, `signatures` the slots, `instructions`
    (program index, account indices, data) and `lookups` the lookup-table count.
    Solana's packet bound limits all loops. Compact lengths must be canonical
    u16 values; both legacy and v0 messages must be consumed in full, and the
    message must pass the sanitizer rules a cluster applies before it lands.
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
    # Account indices may reference lookup-table addresses; check them against
    # the complete count after the lookup-table framing has been read.
    instructions = []
    for _ in range(length()):
        program = take(1)[0]
        accounts = list(take(length()))
        instructions.append((program, accounts, take(length())))
    loaded = 0
    lookups = 0
    if versioned:
        for _ in range(length()):
            take(32)
            counts = []
            for _ in range(2):
                count = length()
                take(count)
                counts.append(count)
            # The sanitizer refuses a lookup-table entry that loads nothing.
            if not sum(counts):
                raise ValueError("invalid message framing")
            loaded += sum(counts)
            lookups += 1
    # The sanitizer also refuses a program at index 0 (the fee payer) and a
    # program that is not a static key, since a lookup table cannot load one.
    if offset != len(raw) or len(keys) + loaded > 256 or any(
            not 0 < program < len(keys) or any(index >= len(keys) + loaded for index in accounts)
            for program, accounts, _ in instructions):
        raise ValueError("invalid message framing")
    return {"message": raw[message_start:], "keys": keys, "required": required,
            "signatures": signatures, "instructions": instructions, "lookups": lookups}


def decode_transaction(encoded):
    """Return (exact message bytes, static signer keys, signature slots)."""
    parsed = parse_transaction(encoded)
    return parsed["message"], parsed["keys"][:parsed["required"]], parsed["signatures"]


def authorization_identity(encoded, payer, fee_payer, *, before_signing=False, finalized=False):
    """Bind the exact message and every non-sponsor client signature.

    The first signature is the sponsor's transaction ID, unknown before it
    co-signs. A finalized transaction must verify that signature as well.
    Framing and signature faults are ValueError; a validly signed transaction
    whose signers are not this payment's is SignerMismatch.
    """
    message, keys, signatures = decode_transaction(encoded)
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
    if base58(keys[0]) != fee_payer or payer == fee_payer or payer not in {
            base58(key) for key in keys[1:]}:
        raise SignerMismatch("payer/sponsor signer mismatch")
    identity = {
        "payer": payer,
        "messageHash": hashlib.sha256(message).hexdigest(),
        "clientSignatures": clients,
    }
    return identity, base58(signatures[0]) if finalized else None


def payment_instruction_defect(encoded, *, payer, fee_payer, pay_to, mint, amount, decimals,
                               token_program, memo=None):
    """§9.5.7.1: the first way the message is not exactly this payment, else None.

    The message must carry exactly one TransferChecked of `amount` (no more,
    no less) and `decimals` from the payer's associated token account for
    `mint` to that of `pay_to`, under `token_program`, with the payer as
    authority; exactly one Memo instruction carrying `memo` (or, without one,
    upstream's hex nonce of at least 16 bytes); at most one SetComputeUnitLimit
    and one SetComputeUnitPrice within the pinned bounds; no other
    instruction; no lookup table; and no signer but the sponsor and the payer.
    Malformed framing raises ValueError.
    """
    if token_program not in TOKEN_PROGRAMS:
        return "token-program"
    if type(amount) is not int or not 0 <= amount < 2**64 or type(decimals) is not int or not 0 <= decimals < 256:
        raise ValueError("transfer terms")
    parsed = parse_transaction(encoded)
    keys = [base58(key) for key in parsed["keys"]]
    if parsed["lookups"]:
        return "lookup-table"
    if keys[:parsed["required"]] != [fee_payer, payer]:
        return "signers"
    source = associated_token_account(payer, mint, token_program)
    destination = associated_token_account(pay_to, mint, token_program)
    transfers, memos, budget = [], [], []
    for program, accounts, data in parsed["instructions"]:
        program, accounts = keys[program], [keys[index] for index in accounts]
        if program == token_program and data[:1] == bytes([TRANSFER_CHECKED]):
            transfers.append((accounts, data))
        elif program == MEMO_PROGRAM:
            memos.append((accounts, data))
        elif program == COMPUTE_BUDGET_PROGRAM:
            budget.append((accounts, data))
        else:
            return "instruction"
    if len(transfers) != 1:
        return "transfer-count"
    accounts, data = transfers[0]
    if accounts != [source, mint, destination, payer] or data != (
            bytes([TRANSFER_CHECKED]) + amount.to_bytes(8, "little") + bytes([decimals])):
        return "transfer"
    if len(memos) != 1 or memos[0][0]:
        return "memo"
    try:
        text = memos[0][1].decode("utf-8")
    except UnicodeDecodeError:
        return "memo"
    if (text != memo) if memo is not None else not MEMO_NONCE.fullmatch(text):
        return "memo"
    seen = set()
    for accounts, data in budget:
        kind = data[:1]
        if accounts or kind in seen or (kind, len(data)) not in ((b"\x02", 5), (b"\x03", 9)):
            return "compute-budget"
        seen.add(kind)
        if int.from_bytes(data[1:], "little") > (
                MAX_COMPUTE_UNITS if kind == b"\x02" else MAX_COMPUTE_UNIT_PRICE):
            return "compute-budget"
    return None
