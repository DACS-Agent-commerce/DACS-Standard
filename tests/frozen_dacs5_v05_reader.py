"""Frozen DACS-5 v0.5 discriminator dispatch from baseline 3426faa.

This module exists only to execute old-reader compatibility checks. Keep its
recognized discriminator set frozen; adding a new type here would defeat the test.
"""


def bundle_type(bundle):
    if not isinstance(bundle, dict):
        return None
    candidates = []
    if bundle.get("bundleVersion") == "1":
        candidates.append("legacy")
    if bundle.get("faultBundleVersion") == "1":
        candidates.append("fault")
    if bundle.get("evidenceBoundFaultBundleVersion") == "1":
        candidates.append("evidence-bound")
    known_keys = {
        "bundleVersion",
        "faultBundleVersion",
        "evidenceBoundFaultBundleVersion",
    }
    unknown_discriminators = {
        key for key in bundle
        if isinstance(key, str) and key.endswith("BundleVersion") and key not in known_keys
    }
    if unknown_discriminators:
        return None
    if any(key in bundle and bundle.get(key) != "1" for key in known_keys):
        return None
    return candidates[0] if len(candidates) == 1 else None


def pointer_type(pointer):
    """Frozen pre-#392 extended-pointer discriminator read."""
    if not isinstance(pointer, dict):
        return None
    known = {"bundleVersion", "faultBundleVersion", "evidenceBoundFaultBundleVersion"}
    if any(
        isinstance(key, str) and key.endswith("BundleVersion") and key not in known
        for key in pointer
    ):
        return None
    present = {key for key in known if key in pointer}
    if len(present) != 1:
        return None
    discriminator = next(iter(present))
    if discriminator == "bundleVersion" or pointer.get(discriminator) != "1":
        return None
    return {
        "faultBundleVersion": "fault",
        "evidenceBoundFaultBundleVersion": "evidence-bound",
    }.get(discriminator)
