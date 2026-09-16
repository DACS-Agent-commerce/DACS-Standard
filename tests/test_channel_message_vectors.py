"""Executable oracle for canonical and historical DACS-3 channel messages."""
from __future__ import annotations

import base64
import copy
import hashlib
import json
import re
import subprocess
import sys
import threading

import unittest
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, utils
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT / "tests"))
from channel_message_fixture_authority import (  # noqa: E402
    CURRENT_MODULE_VERSIONS,
    CURRENT_PARTICIPANTS,
    CURRENT_RELEASE_PIN,
    TRUSTED_CONTEXTS,
    TRUSTED_PROFILE_ADMISSIONS,
    trusted_profile_admission,
)
import generate_channel_message_vectors as channel_fixture_generator  # noqa: E402
import jcs  # noqa: E402
from dacs_reference import parse_claim_reference  # noqa: E402


VECTORS = (
    ROOT / "conformance" / "vectors" / "security"
    / "canonical-channel-message-v0.6.json"
)
LEGACY = (
    ROOT / "conformance" / "vectors" / "security"
    / "channel-message-replay-v0.1.json"
)
GENERATOR = ROOT / "scripts" / "generate_channel_message_vectors.py"
DACS3 = ROOT / "spec" / "DACS-3-NEGOTIATE.md"
CORE = ROOT / "spec" / "CORE.md"
DEMOS = ROOT / "spec" / "DEMOS-MAPPING.md"
CURRENT_DOMAIN = b"dacs-canonical-channel-message:v1:"
LEGACY_DOMAIN = b"dacs-channelmsg:v1:"
LEGACY_FILE_SHA256 = "ce43b226e358e15cb126b4b7d53b8638648c14ca55250eb57e6db68e451ba13f"
LEGACY_VECTOR_HASH = "3f0664c434a6727f7578434cba9ea47b804e0dff12249081c7abdd4fdc03803b"
LOWER_HEX_64 = re.compile(r"^[0-9a-f]{64}$")
LOWER_HEX_128 = re.compile(r"^[0-9a-f]{128}$")
BASE64URL = re.compile(r"^[A-Za-z0-9_-]+$")
MESSAGE_TYPES = {
    "offer", "counter", "accept", "reject", "sealed-envelope-commit",
    "sealed-envelope-reveal", "abort",
}
ALGORITHMS = {"ed25519", "ecdsa-secp256k1", "sr1-aggregate"}
SECP256K1_ORDER = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
ECDSA_REF = "did:example:dacs-349-ecdsa"
ECDSA_PUBLIC = bytes.fromhex(
    "02eebd1f7b69e1d253e9c13c28660dc74d31eb7b54132f6218a1d748cd2cc2b60b"
)
SR1_REF = "did:example:dacs-349-sr1-root"
SR1_PUBLIC = bytes.fromhex(
    "ad1c29b30511eb51de06962d03b5d89f1c7be5d40ba49537bf9e31383cf6f04c"
)
# Current-wire Ed25519 members carry the canonical registered DACS-1
# key:<pubkeyhex> claims.  The historical generic cci:<64hex> spellings below
# are frozen legacy-era identities: they resolve only on the explicit
# legacy-import arm and the current scheme registry refuses the scheme.
ALICE_REF = "key:e70a5bcf97758337d7191df8e32ddd310933ce077937e36723b8b3be4dd69f57"
ALICE_PUBLIC = bytes.fromhex(ALICE_REF.removeprefix("key:"))
BOB_REF = "key:ea0c2afe8504c5500e1c28d05d4a2f214c076c8fc2c0db3225d13d1c1513d693"
BOB_PUBLIC = bytes.fromhex(BOB_REF.removeprefix("key:"))
LEGACY_MEMBER_REF = "cci:acdcc8494d458f44a7aaac1d6a84ec624daee88436db2ae26e67ba645a106228"
LEGACY_PUBLIC = bytes.fromhex(LEGACY_MEMBER_REF.removeprefix("cci:"))
UNRESOLVED_REF = "did:example:unresolved"
LEGACY_UNRESOLVED_REF = "did:demos:placeholder"
# The historical spelling of the Alice fixture key on the frozen-era wire.
HISTORICAL_ALICE_REF = "cci:e70a5bcf97758337d7191df8e32ddd310933ce077937e36723b8b3be4dd69f57"


def canonical_bytes(value):
    return jcs.canonicalize(value).encode("utf-8")


def message_digest(unsigned):
    return hashlib.sha256(canonical_bytes(unsigned)).digest()


def decode_b64url(value):
    if not isinstance(value, str) or not value or not BASE64URL.fullmatch(value):
        raise ValueError("not unpadded Base64URL")
    if len(value) % 4 == 1:
        raise ValueError("impossible Base64URL length")
    raw = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    if base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii") != value:
        raise ValueError("non-canonical Base64URL")
    return raw


def parse_current_claim_ref(value):
    """Current-arm ClaimReference parse.

    This is exactly the shared DACS-1 registered-scheme parser and registry
    from ``scripts/dacs_reference.py`` (``parse_claim_reference`` /
    ``REGISTERED_SCHEMES``): the current wire accepts only registered
    schemes — ``key:``, ``did:``, and the specific ``cci-*`` schemes — and
    refuses the generic ``cci:<64hex>`` historical spelling.  No permissive
    local variant of this parse exists on the current arm.
    """

    parsed = parse_claim_reference(value)
    return parsed.scheme, parsed.identifier


def parse_historical_claim_ref(value):
    """Frozen historical ClaimReference grammar for the legacy-import arm only.

    The frozen ``channel-message-replay-v0.1.json`` corpus carries its
    Ed25519 senders as generic ``cci:<64 lowercase hex>`` claims and its
    unresolved sender as a pre-profile Demos DID.  This grammar is closed to
    exactly those two historical spellings so the archival bytes keep
    verifying byte-for-byte; it is never reachable from ``current-read``,
    which uses the registered current parser above.
    """

    if (
        not isinstance(value, str)
        or not value
        or value != value.lower()
        or "?" in value
    ):
        raise ValueError("malformed historical ClaimReference")
    scheme, separator, identifier = value.partition(":")
    if not separator or not identifier:
        raise ValueError("malformed historical ClaimReference")
    if scheme == "cci":
        if LOWER_HEX_64.fullmatch(identifier) is None:
            raise ValueError("historical cci identifier must be 64 lowercase hex")
    elif scheme == "did":
        if re.fullmatch(r"[a-z0-9]+:[A-Za-z0-9._-]+", identifier) is None:
            raise ValueError("malformed historical did ClaimReference")
    else:
        raise ValueError("scheme is outside the frozen historical registry")
    return scheme, identifier


def validate_context(ctx):
    if not isinstance(ctx, dict) or set(ctx) != {
        "sessionChannelId", "lastSequence", "priorChannelIds"
    }:
        return False
    return (
        isinstance(ctx["sessionChannelId"], str)
        and bool(ctx["sessionChannelId"])
        and isinstance(ctx["lastSequence"], int)
        and not isinstance(ctx["lastSequence"], bool)
        and ctx["lastSequence"] >= 0
        and isinstance(ctx["priorChannelIds"], list)
        and all(isinstance(item, str) and item for item in ctx["priorChannelIds"])
    )


def validate_authenticated_members(members, *, parse_ref=parse_current_claim_ref):
    """Validate the verifier-owned member capability for one arm.

    ``parse_ref`` is the arm's ClaimReference parser: the current arm uses
    the shared registered-scheme parser; the historical arm uses the frozen
    historical grammar.  Both authorities share the same member shape rules.
    """

    if not isinstance(members, list) or not members:
        return False
    seen = set()
    for member in members:
        if not isinstance(member, dict):
            return False
        resolution = member.get("resolution")
        algorithm = member.get("algorithm")
        authority_type = member.get("authorityType")
        if (
            not isinstance(resolution, str)
            or resolution not in {"resolved", "unavailable"}
            or not isinstance(algorithm, str)
            or algorithm not in ALGORITHMS
            or not isinstance(authority_type, str)
            or authority_type not in {"primary-key", "sr1-root"}
        ):
            return False
        common_keys = {"claim", "algorithm", "authorityType", "resolution"}
        expected_keys = (
            common_keys
            if resolution == "unavailable"
            else common_keys | {"publicKeyEncoding", "publicKey"}
        )
        if set(member) != expected_keys:
            return False
        try:
            identity = parse_ref(member["claim"])
        except (TypeError, ValueError):
            return False
        if (
            identity in seen
            or (algorithm == "sr1-aggregate")
            != (authority_type == "sr1-root")
        ):
            return False
        seen.add(identity)
        if resolution == "unavailable":
            continue
        public_key = member["publicKey"]
        public_key_encoding = member["publicKeyEncoding"]
        if (
            not isinstance(public_key, str)
            or not isinstance(public_key_encoding, str)
        ):
            return False
        try:
            if algorithm in {"ed25519", "sr1-aggregate"}:
                if (
                    public_key_encoding != "ed25519-raw-lowercase-hex"
                    or not LOWER_HEX_64.fullmatch(public_key)
                ):
                    return False
                Ed25519PublicKey.from_public_bytes(bytes.fromhex(public_key))
            elif (
                public_key_encoding != "sec1-compressed-lowercase-hex"
                or not re.fullmatch(r"0[23][0-9a-f]{64}", public_key)
            ):
                return False
            else:
                ec.EllipticCurvePublicKey.from_encoded_point(
                    ec.SECP256K1(), bytes.fromhex(public_key)
                )
        except ValueError:
            return False
    return True


class ReusedChannelIdError(ValueError):
    """A trusted state issuer has already retained this channel identifier."""


class ProfileAdmissionError(ValueError):
    def __init__(self, verdict, message):
        super().__init__(message)
        self.verdict = verdict


class AuthenticatedProfileAuthority:
    """Verifier-owned exact-profile capability for one current session."""

    KEYS = {
        "source", "authenticated", "sessionId", "participantIdentities",
        "releasePin", "moduleVersions",
    }

    def __init__(self, context):
        if context is None:
            raise ProfileAdmissionError("indeterminate", "profile authority unavailable")
        if not isinstance(context, dict) or set(context) != self.KEYS:
            raise ProfileAdmissionError("error", "malformed profile authority")
        participants = context.get("participantIdentities")
        modules = context.get("moduleVersions")
        if (
            context.get("source") != "fixture-verifier-owned"
            or context.get("authenticated") is not True
            or not isinstance(context.get("sessionId"), str)
            or not context["sessionId"]
            or not isinstance(participants, list)
            or not participants
            or any(not isinstance(item, str) or not item for item in participants)
            or len(participants) != len(set(participants))
            or not isinstance(context.get("releasePin"), str)
            or not isinstance(modules, dict)
            or set(modules) != set(CURRENT_MODULE_VERSIONS)
            or any(not isinstance(value, str) for value in modules.values())
        ):
            raise ProfileAdmissionError("error", "malformed profile authority")
        self._context = copy.deepcopy(context)

    def admit(self, session_id, participant_identities):
        if (
            self._context["sessionId"] != session_id
            or self._context["participantIdentities"] != list(participant_identities)
            or self._context["releasePin"] != CURRENT_RELEASE_PIN
            or self._context["moduleVersions"] != CURRENT_MODULE_VERSIONS
        ):
            raise ProfileAdmissionError("fail", "profile authority mismatch")


_STATE_ISSUANCE_CAPABILITY = object()


class _VerifierOwnedChannelState:
    """Opaque replay/terminal state mutated only through its issuing authority."""

    def __init__(self, capability, issuer, channel_id, initial_sequence):
        if capability is not _STATE_ISSUANCE_CAPABILITY:
            raise TypeError("channel state must be created by a trusted issuer")
        self._issuer = issuer
        self._channel_id = channel_id
        self._last_sequence = initial_sequence
        self._terminal_status = None

    @property
    def channel_id(self):
        return self._channel_id

    @property
    def last_sequence(self):
        return self._issuer._snapshot(self)[0]

    @property
    def terminal_status(self):
        return self._issuer._snapshot(self)[1]

    def _known_contradiction(self, channel_id, sequence):
        return self._issuer._known_contradiction(self, channel_id, sequence)

    def _consume_validated(self, channel_id, sequence, message_type):
        return self._issuer._consume_validated(
            self, channel_id, sequence, message_type
        )


class LiveNegotiationState(_VerifierOwnedChannelState):
    """Verifier-owned state for one live current-message negotiation."""


class HistoricalAuditState(_VerifierOwnedChannelState):
    """Independent validation cursor with no live-publication authority."""


class RetainedChannelRegistry:
    """Trusted in-memory registry retained across issuer facade reconstruction.

    Production implementations must supply transactional persistence covering
    their replay horizon and restarts. This reference models one process only.
    Live and audit registries must be distinct.
    """

    def __init__(self, used_channel_ids=()):
        if not isinstance(used_channel_ids, (list, tuple)) or any(
            not isinstance(item, str) or not item for item in used_channel_ids
        ):
            raise ValueError("invalid trusted used-channel identifiers")
        if len(used_channel_ids) != len(set(used_channel_ids)):
            raise ValueError("duplicate trusted used-channel identifier")
        self._lock = threading.RLock()
        self._used_channel_ids = set(used_channel_ids)
        self._issued_states = {}

        self._state_type = None


class _VerifierStateIssuer:
    """Issue states and serialize identifier, sequence, and terminal updates."""

    state_type = None

    def __init__(self, registry):
        if not isinstance(registry, RetainedChannelRegistry):
            raise TypeError("a trusted retained channel registry is required")
        with registry._lock:
            if registry._state_type not in (None, self.state_type):
                raise ValueError("live and audit registries must be distinct")
            registry._state_type = self.state_type
        self._lock = registry._lock
        self._used_channel_ids = registry._used_channel_ids
        self._issued_states = registry._issued_states
        self._registry = registry

    @property
    def used_channel_ids(self):
        with self._lock:
            return frozenset(self._used_channel_ids)

    def issue(self, channel_id, initial_sequence=0):
        if not isinstance(channel_id, str) or not channel_id:
            raise ValueError("invalid trusted channel identifier")
        if (
            not isinstance(initial_sequence, int)
            or isinstance(initial_sequence, bool)
            or initial_sequence < 0
        ):
            raise ValueError("invalid trusted initial sequence")
        with self._lock:
            if channel_id in self._used_channel_ids:
                raise ReusedChannelIdError("channel identifier was already used")
            state = self.state_type(
                _STATE_ISSUANCE_CAPABILITY,
                self,
                channel_id,
                initial_sequence,
            )
            self._used_channel_ids.add(channel_id)
            self._issued_states[channel_id] = state
            return state

    def _is_issued(self, state):
        return (
            state._channel_id in self._used_channel_ids
            and self._issued_states.get(state._channel_id) is state
        )

    def _snapshot(self, state):
        with self._lock:
            if not self._is_issued(state):
                raise ValueError("state was not issued by this authority")
            return state._last_sequence, state._terminal_status

    def _known_contradiction(self, state, channel_id, sequence):
        with self._lock:
            return (
                not self._is_issued(state)
                or channel_id != state._channel_id
                or state._terminal_status is not None
                or sequence <= state._last_sequence
            )

    def _consume_validated(self, state, channel_id, sequence, message_type):
        # This single critical section is the commit point after shape,
        # membership, algorithm, and signature validation have all succeeded.
        with self._lock:
            if (
                not self._is_issued(state)
                or channel_id != state._channel_id
                or state._terminal_status is not None
                or sequence <= state._last_sequence
            ):
                return "fail"
            state._last_sequence = sequence
            if message_type == "abort":
                state._terminal_status = "abort"
            return "pass"


class LiveNegotiationStateIssuer(_VerifierStateIssuer):
    """Trusted lifecycle authority for current live negotiation state."""

    state_type = LiveNegotiationState

    def __init__(self, registry, profile_authority, participant_identities):
        if not isinstance(profile_authority, AuthenticatedProfileAuthority):
            raise TypeError("authenticated profile authority required")
        if (
            not isinstance(participant_identities, (list, tuple))
            or not participant_identities
            or any(
                not isinstance(identity, str) or not identity
                for identity in participant_identities
            )
            or len(participant_identities) != len(set(participant_identities))
        ):
            raise ValueError("authenticated participant identities required")
        super().__init__(registry)
        self._profile_authority = profile_authority
        self._participant_identities = tuple(participant_identities)

    def issue(self, channel_id, initial_sequence=0):
        self._profile_authority.admit(channel_id, self._participant_identities)
        return super().issue(channel_id, initial_sequence)

    def _record_closure(self, state, terminal_status):
        with self._lock:
            if not isinstance(state, LiveNegotiationState) or not self._is_issued(state):
                raise ValueError("live state was not issued by this authority")
            if state._terminal_status is not None:
                return False
            state._terminal_status = terminal_status
            return True

    def record_agreement(self, state):
        """Record a separately verified signed AgreementArtifact event."""

        return self._record_closure(state, "agreement")

    def record_timeout(self, state):
        """Record a trusted channel-liveness timeout event."""

        return self._record_closure(state, "timeout")


class HistoricalAuditStateIssuer(_VerifierStateIssuer):
    """Trusted issuer for historical validation cursors, never live state."""

    state_type = HistoricalAuditState


class AuthenticatedChannelAuthority:
    """Verifier-owned capability containing authenticated CH-1 bindings.

    Untrusted message/session input cannot construct or replace this capability.
    A production implementation obtains equivalent data only after its DACS-1/
    DACS-2 membership-binding verification has succeeded.

    Channels named in ``historical_channels`` are historical audit channels:
    their member claims are validated and resolved with the frozen
    historical ClaimReference grammar (generic ``cci:<64hex>`` primary keys
    and pre-profile DIDs) so the archival ``legacy-import`` arm keeps
    verifying frozen bytes.  Every other channel is a current channel: its
    members must parse under the shared current DACS-1 registered-scheme
    registry, and no unregistered generic ``cci:`` claim can ever bind, be
    resolved, or be admitted there.
    """

    def __init__(self, bindings, *, historical_channels=frozenset()):
        if not isinstance(bindings, dict) or not bindings:
            raise ValueError("authenticated channel bindings required")
        if not isinstance(historical_channels, (set, frozenset)):
            raise ValueError("historical channels must be a set of identifiers")
        self._historical_channels = frozenset(historical_channels)
        self._bindings = {}
        for channel_id, members in bindings.items():
            if not isinstance(channel_id, str) or not channel_id:
                raise ValueError("invalid authenticated channel identifier")
            parse_ref = self._claim_parser(channel_id)
            if not validate_authenticated_members(members, parse_ref=parse_ref):
                raise ValueError("invalid authenticated channel membership")
            self._bindings[channel_id] = {
                parse_ref(member["claim"]): copy.deepcopy(member)
                for member in members
            }

    def _claim_parser(self, channel_id):
        return (
            parse_historical_claim_ref
            if channel_id in self._historical_channels
            else parse_current_claim_ref
        )

    def resolve(self, channel_id, sender):
        members = self._bindings.get(channel_id)
        if members is None:
            return "unavailable", None
        try:
            identity = self._claim_parser(channel_id)(sender)
        except (TypeError, ValueError):
            # A sender that cannot be parsed under the bound channel's
            # registry is never a member; fail closed without mutation.
            return "resolved", None
        return "resolved", copy.deepcopy(members.get(identity))


def current_members():
    """Current-channel membership: every claim is a registered DACS-1 scheme."""

    return [
        {
            "claim": ALICE_REF,
            "algorithm": "ed25519",
            "authorityType": "primary-key",
            "resolution": "resolved",
            "publicKeyEncoding": "ed25519-raw-lowercase-hex",
            "publicKey": ALICE_PUBLIC.hex(),
        },
        {
            "claim": BOB_REF,
            "algorithm": "ed25519",
            "authorityType": "primary-key",
            "resolution": "resolved",
            "publicKeyEncoding": "ed25519-raw-lowercase-hex",
            "publicKey": BOB_PUBLIC.hex(),
        },
        {
            "claim": ECDSA_REF,
            "algorithm": "ecdsa-secp256k1",
            "authorityType": "primary-key",
            "resolution": "resolved",
            "publicKeyEncoding": "sec1-compressed-lowercase-hex",
            "publicKey": ECDSA_PUBLIC.hex(),
        },
        {
            "claim": SR1_REF,
            "algorithm": "sr1-aggregate",
            "authorityType": "sr1-root",
            "resolution": "resolved",
            "publicKeyEncoding": "ed25519-raw-lowercase-hex",
            "publicKey": SR1_PUBLIC.hex(),
        },
        {
            "claim": UNRESOLVED_REF,
            "algorithm": "ed25519",
            "authorityType": "primary-key",
            "resolution": "unavailable",
        },
    ]


def historical_members():
    """Historical audit-channel membership for the frozen legacy wire only.

    These bindings keep the frozen corpus's historical claim spellings
    (generic ``cci:<64hex>`` and the pre-profile Demos DID); they authenticate
    only through the explicitly selected ``legacy-import`` arm.  The
    historical spelling of the Alice fixture key is bound so the synthetic
    legacy-framing negatives fail for their intended framing/domain reasons.
    """

    return [
        {
            "claim": HISTORICAL_ALICE_REF,
            "algorithm": "ed25519",
            "authorityType": "primary-key",
            "resolution": "resolved",
            "publicKeyEncoding": "ed25519-raw-lowercase-hex",
            "publicKey": ALICE_PUBLIC.hex(),
        },
        {
            "claim": LEGACY_MEMBER_REF,
            "algorithm": "ed25519",
            "authorityType": "primary-key",
            "resolution": "resolved",
            "publicKeyEncoding": "ed25519-raw-lowercase-hex",
            "publicKey": LEGACY_PUBLIC.hex(),
        },
        {
            "claim": LEGACY_UNRESOLVED_REF,
            "algorithm": "ed25519",
            "authorityType": "primary-key",
            "resolution": "unavailable",
        },
    ]


HISTORICAL_CHANNELS = frozenset({"chan-session-1", "chan-session-7"})
AUTHORITY = AuthenticatedChannelAuthority(
    {
        "channel-349": current_members(),
        "channel-reused": current_members(),
        **{
            channel_id: historical_members()
            for channel_id in sorted(HISTORICAL_CHANNELS)
        },
    },
    historical_channels=HISTORICAL_CHANNELS,
)


def common_shape(message, parse_ref=parse_current_claim_ref):
    required = {"channelId", "sequence", "sender", "sentAt", "type", "body", "signature"}
    if not required <= set(message):
        return False
    message_type = message["type"]
    try:
        parse_ref(message["sender"])
        canonical_bytes({key: value for key, value in message.items() if key != "signature"})
    except (TypeError, ValueError):
        return False
    refs_present = "refs" in message
    refs = message.get("refs")
    return (
        isinstance(message["channelId"], str)
        and bool(message["channelId"])
        and isinstance(message["sequence"], int)
        and not isinstance(message["sequence"], bool)
        and message["sequence"] >= 1
        and isinstance(message["sentAt"], int)
        and not isinstance(message["sentAt"], bool)
        and message["sentAt"] >= 0
        and isinstance(message_type, str)
        and message_type in MESSAGE_TYPES
        and (
            not refs_present
            or (
                isinstance(refs, dict)
                and set(refs) <= {"repliesTo"}
                and (
                    "repliesTo" not in refs
                    or (
                        isinstance(refs["repliesTo"], int)
                        and not isinstance(refs["repliesTo"], bool)
                        and refs["repliesTo"] >= 1
                    )
                )
            )
        )
    )


def resolve_signing_key(sender, channel_id, authority):
    """Resolve only from verifier-owned authenticated channel membership."""

    binding_resolution, member = authority.resolve(channel_id, sender)
    if binding_resolution == "unavailable":
        return "unavailable", None, None
    if member is None:
        return "outsider", None, None
    if member["resolution"] == "unavailable":
        return "unavailable", member["algorithm"], None
    raw = bytes.fromhex(member["publicKey"])
    if member["algorithm"] in {"ed25519", "sr1-aggregate"}:
        public_key = Ed25519PublicKey.from_public_bytes(raw)
    else:
        public_key = ec.EllipticCurvePublicKey.from_encoded_point(
            ec.SECP256K1(), raw
        )
    return "resolved", member["algorithm"], public_key


def verify_ed25519(public_key, signature, payload):
    try:
        public_key.verify(signature, payload)
    except (InvalidSignature, ValueError):
        return False
    return True


def verify_algorithm(algorithm, public_key, signature, payload):
    if algorithm in {"ed25519", "sr1-aggregate"}:
        return len(signature) == 64 and verify_ed25519(public_key, signature, payload)
    if algorithm == "ecdsa-secp256k1":
        try:
            r, s = utils.decode_dss_signature(signature)
            if (
                utils.encode_dss_signature(r, s) != signature
                or not 1 <= r < SECP256K1_ORDER
                or not 1 <= s <= SECP256K1_ORDER // 2
            ):
                return False
            public_key.verify(signature, payload, ec.ECDSA(hashes.SHA256()))
        except (InvalidSignature, ValueError):
            return False
        return True
    return False


def trusted_inputs_status(message, authority, state, expected_state_type):
    """Resolve capability availability and proven state contradictions."""

    if state is None:
        return "indeterminate"
    if not isinstance(state, expected_state_type):
        return "error"
    if state._known_contradiction(message["channelId"], message["sequence"]):
        return "fail"
    if authority is None:
        return "indeterminate"
    if not isinstance(authority, AuthenticatedChannelAuthority):
        return "error"
    return None


def evaluate_current(message, authority, state):
    message_version = message.get("canonicalChannelMessageVersion")
    if (
        not isinstance(message_version, str)
        or message_version != "1"
        or not common_shape(message)
    ):
        return "error"
    signature = message.get("signature")
    if not isinstance(signature, dict) or set(signature) != {
        "signatureVersion", "signer", "algorithm", "value"
    }:
        return "error"
    signature_version = signature.get("signatureVersion")
    if not isinstance(signature_version, str) or signature_version != "1":
        return "error"
    algorithm = signature.get("algorithm")
    if not isinstance(algorithm, str) or algorithm not in ALGORITHMS:
        return "error"
    try:
        parse_current_claim_ref(signature.get("signer"))
        raw_signature = decode_b64url(signature.get("value"))
    except (TypeError, ValueError):
        return "error"
    if parse_current_claim_ref(signature["signer"]) != parse_current_claim_ref(message["sender"]):
        return "fail"
    trusted_status = trusted_inputs_status(
        message, authority, state, LiveNegotiationState
    )
    if trusted_status is not None:
        return trusted_status
    try:
        resolution, key_algorithm, public_key = resolve_signing_key(
            message["sender"], state.channel_id, authority
        )
    except ValueError:
        return "error"
    if resolution == "outsider":
        return "fail"
    # Authenticated algorithm metadata is useful even when key bytes are not.
    if key_algorithm is not None and algorithm != key_algorithm:
        return "fail"
    if resolution == "unavailable":
        return "indeterminate"
    unsigned = {key: value for key, value in message.items() if key != "signature"}
    payload = CURRENT_DOMAIN + message_digest(unsigned).hex().encode("ascii")
    if not verify_algorithm(algorithm, public_key, raw_signature, payload):
        return "fail"
    return state._consume_validated(
        message["channelId"], message["sequence"], message["type"]
    )


def evaluate_legacy(message, authority, state):
    if "canonicalChannelMessageVersion" in message or not common_shape(
        message, parse_historical_claim_ref
    ):
        return "error"
    if not isinstance(message.get("signature"), str) or not LOWER_HEX_128.fullmatch(message["signature"]):
        return "error"
    trusted_status = trusted_inputs_status(
        message, authority, state, HistoricalAuditState
    )
    if trusted_status is not None:
        return trusted_status
    try:
        resolution, key_algorithm, public_key = resolve_signing_key(
            message["sender"], state.channel_id, authority
        )
    except ValueError:
        return "error"
    if resolution == "outsider":
        return "fail"
    # The historical envelope's algorithm is fixed to Ed25519.  Compare any
    # known authenticated metadata before treating missing key bytes as open.
    if key_algorithm is not None and key_algorithm != "ed25519":
        return "fail"
    if resolution == "unavailable":
        return "indeterminate"
    unsigned = {key: value for key, value in message.items() if key != "signature"}
    payload = LEGACY_DOMAIN + message_digest(unsigned)
    if not verify_ed25519(public_key, bytes.fromhex(message["signature"]), payload):
        return "fail"
    return state._consume_validated(
        message["channelId"], message["sequence"], message["type"]
    )


def evaluate(message, operation, authority, state):
    if not isinstance(message, dict):
        return "error"
    # The trusted caller selects the read operation before structural parsing.
    # Neither operation can auto-detect or fall back to the other wire arm.
    if operation == "current-read":
        if "canonicalChannelMessageVersion" not in message:
            return "error"
        return evaluate_current(message, authority, state)
    if operation == "legacy-import":
        if "canonicalChannelMessageVersion" in message:
            return "error"
        if isinstance(message.get("signature"), str) and LOWER_HEX_128.fullmatch(message["signature"]):
            return evaluate_legacy(message, authority, state)
    return "error"


def trusted_fixture_state(ctx, operation, profile_context=None):
    """Provision state from independently reviewed harness configuration."""
    if not validate_context(ctx):
        return "error", None
    if operation == "current-read":
        try:
            profile_authority = AuthenticatedProfileAuthority(profile_context)
            issuer = LiveNegotiationStateIssuer(
                RetainedChannelRegistry(ctx["priorChannelIds"]),
                profile_authority,
                CURRENT_PARTICIPANTS,
            )
            state = issuer.issue(ctx["sessionChannelId"], ctx["lastSequence"])
        except ProfileAdmissionError as exc:
            return exc.verdict, None
        except ReusedChannelIdError:
            return "fail", None
        except (TypeError, ValueError):
            return "error", None
        return None, state
    elif operation == "legacy-import":
        issuer_type = HistoricalAuditStateIssuer
    else:
        return "error", None
    try:
        issuer = issuer_type(RetainedChannelRegistry(ctx["priorChannelIds"]))
        state = issuer.issue(ctx["sessionChannelId"], ctx["lastSequence"])
    except ReusedChannelIdError:
        return "fail", None
    except ValueError:
        return "error", None
    return None, state


def trusted_live_issuer(registry, session_id):
    """Construct a live issuer only after exact current-profile admission."""

    return LiveNegotiationStateIssuer(
        registry,
        AuthenticatedProfileAuthority(trusted_profile_admission(session_id)),
        CURRENT_PARTICIPANTS,
    )


class ChannelMessageVectorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.document = json.loads(VECTORS.read_text(encoding="utf-8"))
        cls.legacy = json.loads(LEGACY.read_text(encoding="utf-8"))

    def fixture_result(self, vector, operation, authority):
        # Test selection uses the separate reviewed setup table. The retained
        # vector ctx is compared as metadata; it is never the setup authority.
        expected = TRUSTED_CONTEXTS[vector["name"]]
        if (
            not validate_context(vector.get("ctx"))
            or canonical_bytes(vector["ctx"]) != canonical_bytes(expected)
        ):
            return "error"
        expected_profile = TRUSTED_PROFILE_ADMISSIONS.get(vector["name"])
        if vector.get("profileAdmission") != expected_profile:
            return "error"
        setup_verdict, state = trusted_fixture_state(
            expected, operation, expected_profile
        )
        if setup_verdict is not None:
            return setup_verdict
        return evaluate(vector.get("message"), operation, authority, state)

    def test_generator_is_byte_deterministic(self):
        subprocess.run(
            [sys.executable, str(GENERATOR), "--check"], cwd=ROOT, check=True
        )

    def test_header_count_hash_and_unique_names(self):
        vectors = self.document["vectors"]
        self.assertEqual(self.document["count"], len(vectors))
        self.assertEqual(
            self.document["hash"], hashlib.sha256(canonical_bytes(vectors)).hexdigest()
        )
        names = [vector["name"] for vector in vectors]
        self.assertEqual(len(names), len(set(names)))

    def test_all_current_and_dispatch_vectors_execute(self):
        for vector in self.document["vectors"]:
            with self.subTest(vector=vector["name"]):
                self.assertEqual(
                    vector["expected"],
                    self.fixture_result(vector, vector["operation"], AUTHORITY),
                )

    def test_frozen_historical_corpus_executes_without_reinterpretation(self):
        self.assertEqual(
            LEGACY_FILE_SHA256, hashlib.sha256(LEGACY.read_bytes()).hexdigest()
        )
        self.assertEqual(LEGACY_VECTOR_HASH, self.legacy["hash"])
        for vector in self.legacy["vectors"]:
            with self.subTest(vector=vector["name"]):
                self.assertEqual(
                    vector["expected"],
                    self.fixture_result(vector, "legacy-import", AUTHORITY),
                )

    def test_legacy_import_preserves_signature_bytes(self):
        vector = next(
            item for item in self.document["vectors"]
            if item["name"] == "legacy-byte-preserving-read-only-import"
        )
        raw = bytes.fromhex(vector["message"]["signature"])
        self.assertEqual(
            vector["expectedSignatureBytesBase64Url"],
            base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii"),
        )
        self.assertEqual(
            "pass", self.fixture_result(vector, "legacy-import", AUTHORITY)
        )
        current_context = {
            "sessionChannelId": "channel-349",
            "lastSequence": 0,
            "priorChannelIds": ["channel-100", "channel-200"],
        }
        setup_verdict, live_state = trusted_fixture_state(
            current_context,
            "current-read",
            trusted_profile_admission("channel-349"),
        )
        self.assertIsNone(setup_verdict)
        self.assertEqual(
            "error", evaluate(vector["message"], "current-read", AUTHORITY, live_state)
        )

    def test_four_mixed_wire_barriers_are_distinguishing(self):
        by_name = {item["name"]: item for item in self.document["vectors"]}
        expected = {
            "mixed-current-discriminator-legacy-signature": "error",
            "neither-selector-no-discriminator-current-envelope": "error",
            "mixed-current-raw-digest-framing": "fail",
            "mixed-legacy-hex-digest-framing": "fail",
        }
        for name, verdict in expected.items():
            with self.subTest(vector=name):
                self.assertEqual(
                    verdict,
                    self.fixture_result(
                        by_name[name], by_name[name]["operation"], AUTHORITY
                    ),
                )

    def test_all_advertised_algorithms_have_positive_and_negative_coverage(self):
        by_name = {item["name"]: item for item in self.document["vectors"]}
        for stem in ("ecdsa", "sr1-aggregate"):
            expected = {
                f"canonical-{stem}-valid": "pass",
                f"canonical-{stem}-tampered-body": "fail",
                f"canonical-{stem}-cross-domain": "fail",
                f"canonical-{stem}-raw-digest-framing": "fail",
            }
            for name, verdict in expected.items():
                with self.subTest(vector=name):
                    vector = by_name[name]
                    self.assertEqual(
                        verdict,
                        self.fixture_result(vector, vector["operation"], AUTHORITY),
                    )

    def test_non_ed25519_keys_are_bound_by_authenticated_fixtures(self):
        self.assertEqual(
            self.document["authenticatedKeyFixtures"],
            [
                {
                    "claim": ECDSA_REF,
                    "algorithm": "ecdsa-secp256k1",
                    "publicKeyEncoding": "sec1-compressed-lowercase-hex",
                    "publicKey": ECDSA_PUBLIC.hex(),
                    "signatureEncoding": "canonical-DER-low-S",
                },
                {
                    "claim": SR1_REF,
                    "algorithm": "sr1-aggregate",
                    "presentation": "sr1-root",
                    "publicKeyEncoding": "ed25519-raw-lowercase-hex",
                    "publicKey": SR1_PUBLIC.hex(),
                },
            ],
        )

    def test_sender_authority_comes_from_authenticated_channel_membership(self):
        by_name = {item["name"]: item for item in self.document["vectors"]}
        outsider = by_name["canonical-outsider-valid-signature"]
        wrong_key = by_name["canonical-member-wrong-key"]
        self.assertEqual(
            "fail", self.fixture_result(outsider, outsider["operation"], AUTHORITY)
        )
        self.assertEqual(
            "fail", self.fixture_result(wrong_key, wrong_key["operation"], AUTHORITY)
        )

        valid = copy.deepcopy(by_name["canonical-valid-first"])
        valid["ctx"]["authenticatedMembers"] = [{
            "claim": valid["message"]["sender"],
            "algorithm": "ed25519",
            "publicKey": BOB_PUBLIC.hex(),
        }]
        self.assertEqual(
            "error", self.fixture_result(valid, "current-read", AUTHORITY)
        )

        issuer = trusted_live_issuer(
            RetainedChannelRegistry(["channel-100", "channel-200"]), "channel-349"
        )
        state = issuer.issue("channel-349")
        self.assertEqual(
            "pass",
            evaluate(valid["message"], "current-read", AUTHORITY, state),
        )

    def test_membership_uses_cf3_identity_and_rejects_qualifier_duplicates(self):
        by_name = {item["name"]: item for item in self.document["vectors"]}
        qualified = by_name["canonical-qualified-member-identity"]
        self.assertEqual(
            "pass", self.fixture_result(qualified, "current-read", AUTHORITY)
        )

        first = copy.deepcopy(current_members()[0])
        second = copy.deepcopy(first)
        first["claim"] += "?role=a"
        second["claim"] += "?role=b"
        second["publicKey"] = BOB_PUBLIC.hex()
        with self.assertRaisesRegex(ValueError, "invalid authenticated channel membership"):
            AuthenticatedChannelAuthority({"channel-duplicate": [first, second]})

    def test_current_read_refuses_generic_cci_while_canonical_key_passes(self):
        """Registered-scheme boundary regression (PR #367 review row 1).

        Integrated current DACS-1 registers ``key:``, ``did:``, and the
        specific ``cci-*`` schemes; the generic ``cci:<64hex>`` spelling is a
        frozen historical form.  A correctly signed current-envelope message
        whose sender/signer use the generic spelling is refused by
        ``current-read`` (malformed unregistered claim, no retry), the same
        spelling can never be bound as a current-channel member, and the
        canonical ``key:`` spelling of the very same key passes unchanged.
        """
        by_name = {item["name"]: item for item in self.document["vectors"]}
        canonical = by_name["canonical-valid-first"]["message"]
        issuer = trusted_live_issuer(
            RetainedChannelRegistry(["channel-100", "channel-200"]), "channel-349"
        )
        state = issuer.issue("channel-349")
        self.assertEqual(
            "pass", evaluate(canonical, "current-read", AUTHORITY, state)
        )
        self.assertEqual(1, state.last_sequence)

        # The corpus-level refusal case executes the same boundary.
        self.assertEqual(
            "error",
            self.fixture_result(
                by_name["canonical-generic-cci-sender-refused"],
                "current-read",
                AUTHORITY,
            ),
        )

        # An independently signed generic-cci message is refused too, the
        # refusal never advances live state, and the archival arm never
        # retries it (the current envelope is not a legacy shape).
        generic_refused = channel_fixture_generator.sign_current(
            channel_fixture_generator.unsigned_message(
                sequence=2, sender=channel_fixture_generator.HISTORICAL_ALICE_REF
            ),
            signer=channel_fixture_generator.HISTORICAL_ALICE_REF,
        )
        self.assertEqual(
            "error", evaluate(generic_refused, "current-read", AUTHORITY, state)
        )
        self.assertEqual(1, state.last_sequence)
        audit_state = HistoricalAuditStateIssuer(RetainedChannelRegistry()).issue(
            "channel-349"
        )
        self.assertEqual(
            "error",
            evaluate(generic_refused, "legacy-import", AUTHORITY, audit_state),
        )

        # The generic spelling cannot become a current-channel member: the
        # current membership authority enforces the same shared registry.
        with self.assertRaisesRegex(
            ValueError, "invalid authenticated channel membership"
        ):
            AuthenticatedChannelAuthority({"channel-generic": [{
                "claim": channel_fixture_generator.HISTORICAL_ALICE_REF,
                "algorithm": "ed25519",
                "authorityType": "primary-key",
                "resolution": "resolved",
                "publicKeyEncoding": "ed25519-raw-lowercase-hex",
                "publicKey": ALICE_PUBLIC.hex(),
            }]})

        # The historical spelling still verifies archival bytes only through
        # the explicit legacy-import arm on a historical audit channel.
        historical_authority = AuthenticatedChannelAuthority(
            {"chan-archival": historical_members()},
            historical_channels={"chan-archival"},
        )
        legacy_unsigned = {
            "channelId": "chan-archival",
            "sequence": 1,
            "sender": channel_fixture_generator.HISTORICAL_ALICE_REF,
            "sentAt": channel_fixture_generator.NOW,
            "type": "offer",
            "body": {"currency": "DEM", "price": "10"},
        }
        legacy_message = channel_fixture_generator.sign_legacy(legacy_unsigned)
        audit_state = HistoricalAuditStateIssuer(
            RetainedChannelRegistry()
        ).issue("chan-archival")
        self.assertEqual(
            "pass",
            evaluate(legacy_message, "legacy-import", historical_authority, audit_state),
        )

    def test_current_entry_point_advances_only_valid_live_state(self):
        by_name = {item["name"]: item for item in self.document["vectors"]}
        issuer = trusted_live_issuer(
            RetainedChannelRegistry(["channel-100", "channel-200"]), "channel-349"
        )
        state = issuer.issue("channel-349")

        self.assertEqual(
            "fail",
            evaluate(
                by_name["canonical-tampered-body"]["message"],
                "current-read",
                AUTHORITY,
                state,
            ),
        )
        self.assertEqual(0, state.last_sequence)
        for name, sequence in (
            ("canonical-valid-first", 1),
            ("canonical-valid-next", 2),
            ("canonical-valid-sequence-gap", 5),
        ):
            with self.subTest(vector=name):
                self.assertEqual(
                    "pass",
                    evaluate(
                        by_name[name]["message"], "current-read", AUTHORITY, state
                    ),
                )
                self.assertEqual(sequence, state.last_sequence)

    def test_live_issuance_and_terminal_transitions_are_trusted(self):
        issuer = trusted_live_issuer(
            RetainedChannelRegistry(["channel-100", "channel-200"]), "channel-349"
        )
        state = issuer.issue("channel-349")
        self.assertIn("channel-349", issuer.used_channel_ids)
        with self.assertRaisesRegex(ReusedChannelIdError, "already used"):
            issuer.issue("channel-349")

        first = self.document["vectors"][0]["message"]
        self.assertEqual(
            "pass", evaluate(first, "current-read", AUTHORITY, state)
        )
        accepted = channel_fixture_generator.sign_current(
            channel_fixture_generator.unsigned_message(
                sequence=2, type="accept", body={"acceptedSequence": 1}
            )
        )
        self.assertEqual(
            "pass", evaluate(accepted, "current-read", AUTHORITY, state)
        )
        self.assertIsNone(state.terminal_status)
        self.assertTrue(issuer.record_agreement(state))
        self.assertEqual("agreement", state.terminal_status)

        after_agreement = channel_fixture_generator.sign_current(
            channel_fixture_generator.unsigned_message(sequence=3)
        )
        self.assertEqual(
            "fail", evaluate(after_agreement, "current-read", AUTHORITY, state)
        )
        self.assertEqual(2, state.last_sequence)

        abort_issuer = trusted_live_issuer(RetainedChannelRegistry(), "channel-349")
        abort_state = abort_issuer.issue("channel-349")
        abort = channel_fixture_generator.sign_current(
            channel_fixture_generator.unsigned_message(
                type="abort", body={"reason": "channel-failure"}
            )
        )
        self.assertEqual(
            "pass", evaluate(abort, "current-read", AUTHORITY, abort_state)
        )
        self.assertEqual("abort", abort_state.terminal_status)
        after_abort = channel_fixture_generator.sign_current(
            channel_fixture_generator.unsigned_message(sequence=2)
        )
        self.assertEqual(
            "fail",
            evaluate(after_abort, "current-read", AUTHORITY, abort_state),
        )
        self.assertEqual(1, abort_state.last_sequence)

        timeout_issuer = trusted_live_issuer(RetainedChannelRegistry(), "channel-349")
        timeout_state = timeout_issuer.issue("channel-349")
        self.assertTrue(timeout_issuer.record_timeout(timeout_state))
        self.assertEqual("timeout", timeout_state.terminal_status)

    def test_registry_continuity_across_issuer_facades(self):
        registry = RetainedChannelRegistry(["channel-100"])
        first = trusted_live_issuer(registry, "channel-349")
        state = first.issue("channel-349")
        message = self.document["vectors"][0]["message"]
        self.assertEqual("pass", evaluate(message, "current-read", AUTHORITY, state))
        second = trusted_live_issuer(registry, "channel-349")
        self.assertIn("channel-349", second.used_channel_ids)
        self.assertEqual(1, state.last_sequence)
        with self.assertRaises(ReusedChannelIdError):
            second.issue("channel-349")
        self.assertTrue(second.record_timeout(state))
        self.assertEqual("timeout", state.terminal_status)
        with self.assertRaisesRegex(ValueError, "must be distinct"):
            HistoricalAuditStateIssuer(registry)

    def test_historical_import_uses_an_independent_audit_cursor(self):
        by_name = {item["name"]: item for item in self.legacy["vectors"]}
        issuer = HistoricalAuditStateIssuer(RetainedChannelRegistry(["chan-session-1", "chan-session-2"]))
        state = issuer.issue("chan-session-7")

        for name, sequence in (
            ("valid-first-message", 1),
            ("valid-next-message", 2),
            ("valid-sequence-gap", 5),
        ):
            with self.subTest(vector=name):
                self.assertEqual(
                    "pass",
                    evaluate(
                        by_name[name]["message"],
                        "legacy-import",
                        AUTHORITY,
                        state,
                    ),
                )
                self.assertEqual(sequence, state.last_sequence)

        live_state = trusted_live_issuer(
            RetainedChannelRegistry(), "chan-session-7"
        ).issue("chan-session-7")
        self.assertEqual(
            "error",
            evaluate(
                by_name["valid-first-message"]["message"],
                "legacy-import",
                AUTHORITY,
                live_state,
            ),
        )

    def test_known_algorithm_mismatch_precedes_unavailable_key(self):
        current = next(
            item for item in self.document["vectors"]
            if item["name"] == "canonical-unresolved-sender"
        )
        historical = next(
            item for item in self.legacy["vectors"]
            if item["name"] == "sender-not-cci"
        )
        mismatch_authority = AuthenticatedChannelAuthority(
            {
                "channel-349": [{
                    "claim": UNRESOLVED_REF,
                    "algorithm": "ecdsa-secp256k1",
                    "authorityType": "primary-key",
                    "resolution": "unavailable",
                }],
                "chan-session-7": [{
                    "claim": LEGACY_UNRESOLVED_REF,
                    "algorithm": "ecdsa-secp256k1",
                    "authorityType": "primary-key",
                    "resolution": "unavailable",
                }],
            },
            historical_channels={"chan-session-7"},
        )

        for vector, operation in (
            (current, "current-read"),
            (historical, "legacy-import"),
        ):
            with self.subTest(operation=operation):
                setup_verdict, matching_state = trusted_fixture_state(
                    TRUSTED_CONTEXTS[vector["name"]], operation,
                    TRUSTED_PROFILE_ADMISSIONS.get(vector["name"]),
                )
                self.assertIsNone(setup_verdict)
                self.assertEqual(
                    "indeterminate",
                    evaluate(
                        vector["message"], operation, AUTHORITY, matching_state
                    ),
                )
                setup_verdict, mismatch_state = trusted_fixture_state(
                    TRUSTED_CONTEXTS[vector["name"]], operation,
                    TRUSTED_PROFILE_ADMISSIONS.get(vector["name"]),
                )
                self.assertIsNone(setup_verdict)
                self.assertEqual(
                    "fail",
                    evaluate(
                        vector["message"],
                        operation,
                        mismatch_authority,
                        mismatch_state,
                    ),
                )

    def test_absent_authority_is_indeterminate_without_state_mutation(self):
        message = self.document["vectors"][0]["message"]
        issuer = trusted_live_issuer(RetainedChannelRegistry(), "channel-349")
        state = issuer.issue("channel-349")
        self.assertEqual(
            "indeterminate", evaluate(message, "current-read", None, state)
        )
        self.assertEqual(0, state.last_sequence)
        self.assertEqual(
            "indeterminate", evaluate(message, "current-read", AUTHORITY, None)
        )

        unavailable_authority = AuthenticatedChannelAuthority({
            "channel-unrelated": current_members()
        })
        self.assertEqual(
            "indeterminate",
            evaluate(message, "current-read", unavailable_authority, state),
        )
        self.assertEqual(0, state.last_sequence)

        foreign_state = trusted_live_issuer(
            RetainedChannelRegistry(), "channel-foreign"
        ).issue("channel-foreign")
        self.assertEqual(
            "fail", evaluate(message, "current-read", None, foreign_state)
        )

    def test_malformed_enum_containers_return_controlled_errors(self):
        current = self.document["vectors"][0]["message"]
        issuer = trusted_live_issuer(RetainedChannelRegistry(), "channel-349")
        state = issuer.issue("channel-349")
        mutations = (
            ("message type", lambda value: value.__setitem__("type", [])),
            (
                "signature algorithm",
                lambda value: value["signature"].__setitem__("algorithm", []),
            ),
            (
                "signature version",
                lambda value: value["signature"].__setitem__(
                    "signatureVersion", []
                ),
            ),
            (
                "message version",
                lambda value: value.__setitem__(
                    "canonicalChannelMessageVersion", []
                ),
            ),
        )
        for label, mutate in mutations:
            malformed = copy.deepcopy(current)
            mutate(malformed)
            with self.subTest(field=label):
                self.assertEqual(
                    "error",
                    evaluate(malformed, "current-read", AUTHORITY, state),
                )
        self.assertEqual(0, state.last_sequence)

        historical = copy.deepcopy(self.legacy["vectors"][0]["message"])
        historical["type"] = []
        historical_state = HistoricalAuditStateIssuer(RetainedChannelRegistry()).issue("chan-session-7")
        self.assertEqual(
            "error",
            evaluate(
                historical,
                "legacy-import",
                AUTHORITY,
                historical_state,
            ),
        )

        for field in ("algorithm", "authorityType", "resolution"):
            member = copy.deepcopy(current_members()[0])
            member[field] = []
            with self.subTest(authenticated_member_field=field):
                with self.assertRaisesRegex(
                    ValueError, "invalid authenticated channel membership"
                ):
                    AuthenticatedChannelAuthority({"channel-malformed": [member]})

    def test_current_and_historical_payloads_pin_digest_representation(self):
        current = self.document["vectors"][0]["message"]
        current_unsigned = {
            key: value for key, value in current.items() if key != "signature"
        }
        current_payload = CURRENT_DOMAIN + message_digest(current_unsigned).hex().encode("ascii")
        self.assertEqual(len(CURRENT_DOMAIN) + 64, len(current_payload))
        _, _, current_public = resolve_signing_key(
            current["sender"],
            self.document["vectors"][0]["ctx"]["sessionChannelId"],
            AUTHORITY,
        )
        self.assertTrue(verify_ed25519(
            current_public, decode_b64url(current["signature"]["value"]), current_payload
        ))
        self.assertFalse(verify_ed25519(
            current_public,
            decode_b64url(current["signature"]["value"]),
            CURRENT_DOMAIN + message_digest(current_unsigned),
        ))

        legacy = self.legacy["vectors"][0]["message"]
        legacy_unsigned = {
            key: value for key, value in legacy.items() if key != "signature"
        }
        legacy_payload = LEGACY_DOMAIN + message_digest(legacy_unsigned)
        self.assertEqual(len(LEGACY_DOMAIN) + 32, len(legacy_payload))
        _, _, legacy_public = resolve_signing_key(
            legacy["sender"],
            self.legacy["vectors"][0]["ctx"]["sessionChannelId"],
            AUTHORITY,
        )
        self.assertTrue(verify_ed25519(
            legacy_public, bytes.fromhex(legacy["signature"]), legacy_payload
        ))
        self.assertFalse(verify_ed25519(
            legacy_public,
            bytes.fromhex(legacy["signature"]),
            LEGACY_DOMAIN + message_digest(legacy_unsigned).hex().encode("ascii"),
        ))

    def test_v05_positive_compatibility_contract(self):
        """PR #367 review row 1: the v0.6 replacement keeps an explicit
        positive v0.5 compatibility contract. Valid historical bytes are
        accepted by the explicitly selected ``legacy-import`` operation,
        refused by ``current-read``, and never retried on the other arm; the
        current wire stays independently acceptable on ``current-read``."""
        by_name = {item["name"]: item for item in self.legacy["vectors"]}
        issuer = HistoricalAuditStateIssuer(
            RetainedChannelRegistry(["chan-session-1", "chan-session-2"])
        )
        state = issuer.issue("chan-session-7")

        # (1) Positive legacy-import acceptance: every valid v0.5 message
        # (pass-expected corpus members) is accepted by the explicitly invoked
        # historical operation, byte-for-byte with its frozen signature.
        for name in (
            "valid-first-message",
            "valid-next-message",
            "valid-sequence-gap",
        ):
            with self.subTest(legacy_import=name):
                message = copy.deepcopy(by_name[name]["message"])
                signature_before = message["signature"]
                self.assertEqual(
                    "pass", evaluate(message, "legacy-import", AUTHORITY, state)
                )
                self.assertEqual(signature_before, message["signature"])

        # (2) Current-read refusal of the same valid legacy bytes: a fresh
        # historical cursor must reject them without fallback, and the
        # refused bytes stay unchanged (no re-encode, no retry).
        refused_issuer = HistoricalAuditStateIssuer(
            RetainedChannelRegistry(["chan-session-1", "chan-session-2"])
        )
        refused_state = refused_issuer.issue("chan-session-7")
        for name in (
            "valid-first-message",
            "valid-next-message",
            "valid-sequence-gap",
        ):
            with self.subTest(current_read_refuses=name):
                message = copy.deepcopy(by_name[name]["message"])
                signature_before = message["signature"]
                self.assertEqual(
                    "error",
                    evaluate(message, "current-read", AUTHORITY, refused_state),
                )
                self.assertEqual(signature_before, message["signature"])
        # The current-read refusal did not advance historical or live state.
        self.assertEqual(5, state.last_sequence)
        self.assertEqual(0, refused_state.last_sequence)

        # (3) No fallback in either direction: legacy-import rejects a current
        # wire message (discriminator present) and current-read rejects a
        # legacy wire message (discriminator absent); neither operation ever
        # returns the other arm's verdict for the same bytes.
        current_message = copy.deepcopy(self.document["vectors"][0]["message"])
        live_issuer = trusted_live_issuer(RetainedChannelRegistry(), "channel-349")
        live_state = live_issuer.issue("channel-349")
        self.assertEqual(
            "error",
            evaluate(current_message, "legacy-import", AUTHORITY, live_state),
        )
        self.assertEqual(
            "pass", evaluate(current_message, "current-read", AUTHORITY, live_state)
        )

        # (4) The archival-only legacy rule is stated, and no legacy fallback
        # is added anywhere in the current arm.
        dacs3 = DACS3.read_text(encoding="utf-8")
        for text in (
            "read/import-only compatibility",
            "New producers MUST NOT emit it",
            "rejects on this operation without trying",
            "MUST NOT try the other arm",
        ):
            self.assertIn(text, dacs3)
        self.assertNotIn("legacy fallback", dacs3)
        self.assertNotIn("fallback to legacy", dacs3)

    def test_spec_and_mapping_define_the_accepted_boundary(self):
        dacs3 = DACS3.read_text(encoding="utf-8")
        core = CORE.read_text(encoding="utf-8")
        demos = DEMOS.read_text(encoding="utf-8")
        for rule in range(7, 11):
            self.assertIn(f"(CH-{rule})", dacs3)
        for text in (
            "type CanonicalChannelMessage = {",
            "type ChannelMessageSignature = {",
            "type LegacyDemosChannelMessage = {",
            'UTF8("dacs-canonical-channel-message:v1:") || ASCII(message_hash)',
            'UTF8("dacs-channelmsg:v1:") || legacy_message_hash_bytes',
            "selected by trusted caller policy",
            "explicitly invoked `legacy-import` operation",
            "MUST NOT try the other arm",
            "verifier-owned replay/session/terminal capability",
            "distinct historical audit cursor",
            "`accept` message alone is not a signed AgreementArtifact",
        ):
            self.assertIn(text, dacs3)
        self.assertIn('"dacs-canonical-channel-message:v1:"', core)
        self.assertIn("read/import-only", core)
        self.assertIn("@kynesyslabs/demosdk@4.0.16", demos)
        self.assertIn("historical read/import arm", demos)


if __name__ == "__main__":
    unittest.main()
