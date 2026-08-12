import base64
import json
import unittest

from scripts.generate_artifact_reference_fixtures import (
    BUNDLE_FIXTURES,
    MANIFEST,
    bundle_hash,
    keys,
    regenerate_all,
)


class ArtifactReferenceFixtureGenerationTests(unittest.TestCase):
    def test_one_sided_manifest_hash_tracks_regenerated_signed_bundle(self):
        outputs = regenerate_all()
        fixture_path = next(
            path
            for path in BUNDLE_FIXTURES
            if path.name == "session-bundle-one-sided.json"
        )
        bundle = json.loads(outputs[fixture_path])
        manifest = json.loads(outputs[MANIFEST])
        case = next(
            item
            for item in manifest["cases"]
            if item["id"] == "verify-consume-one-sided"
        )

        expected_hash = bundle_hash(bundle)
        self.assertEqual(case["want"]["buyerHash"], expected_hash)

        signature = bundle["signatures"][0]["value"]
        raw_signature = base64.urlsafe_b64decode(
            signature + "=" * (-len(signature) % 4)
        )
        payload = ("dacs-bundle:v1:" + expected_hash).encode("utf-8")
        keys()["buyer"].public_key().verify(raw_signature, payload)


if __name__ == "__main__":
    unittest.main()
