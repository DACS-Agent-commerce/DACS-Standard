"""Offline provisioning of the DEMOS-MAPPING §A.2 effective nonce fork."""
import hashlib
import re

from raw_json_profile import loads


NODE_COMMIT = "61b8e75aa8db5e408c49e1c3a89db4d673f45578"
PINNED_GENESIS_HASH = "a6b140dd38f05558d2319243656d2ff2f93cc5f6ffb16dcd6b13077e10d56184"
MAX_SEALED_GENESIS_BYTES = 1024 * 1024


def nonce_enforcement(network, sealed_genesis, pinned_digest, node_commit=NODE_COMMIT):
    """Bind the clean build's default plus exact operator-pinned overrides.

    The network identity and digest are independent provisioning roots. The
    genesis block hash does not authenticate fork configuration. None means
    explicitly unscheduled, whereas an absent fork uses this build's default.
    """
    if node_commit != NODE_COMMIT:
        raise ValueError("unsupported node build for nonce enforcement")
    if not (isinstance(network, dict) and set(network) == {"networkId", "genesisHash"}
            and isinstance(network["networkId"], str) and network["networkId"]
            and isinstance(network["genesisHash"], str)
            and re.fullmatch(r"[0-9a-f]{64}", network["genesisHash"])):
        raise ValueError("malformed provisioned network identity")
    if not isinstance(sealed_genesis, bytes) or len(sealed_genesis) > MAX_SEALED_GENESIS_BYTES:
        raise ValueError("sealed genesis must be bounded exact bytes")
    if hashlib.sha256(sealed_genesis).hexdigest() != pinned_digest:
        raise ValueError("sealed genesis digest mismatch")
    genesis = loads(sealed_genesis)
    if not isinstance(genesis, dict):
        raise ValueError("sealed genesis must be an object")
    forks = genesis.get("forks", {})
    if not isinstance(forks, dict):
        raise ValueError("malformed genesis forks")
    height = 0  # DEFAULT_FORK_CONFIG.nonceEnforcement at NODE_COMMIT.
    if "nonceEnforcement" in forks:
        entry = forks["nonceEnforcement"]
        if not isinstance(entry, dict) or "activationHeight" not in entry:
            raise ValueError("missing nonce activation override")
        height = entry["activationHeight"]
    if height is not None and not (
            isinstance(height, (int, float)) and not isinstance(height, bool)
            and 0 <= height <= 2**53 - 1 and height == int(height)):
        raise ValueError("nonce activation must be null or a non-negative safe integer")
    return dict(network, nodeCommit=node_commit, activationHeight=height, sealedGenesisHash=pinned_digest)
