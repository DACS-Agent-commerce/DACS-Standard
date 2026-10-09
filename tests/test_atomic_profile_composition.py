"""The Atomic composition table must track the live coordinated tuple."""

from __future__ import annotations

import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PROFILE = ROOT / "spec" / "PROFILE.md"
ROW = re.compile(r"^\| \[([A-Z0-9-]+)\]\([A-Z0-9-]+\.md\) \| ([0-9.]+) \| (.+) \|$")


def section_table(text: str, heading: str) -> dict[str, tuple[str, str]]:
    body = text.split(heading, 1)[1].split("\n## ", 1)[0]
    rows = {}
    for line in body.splitlines():
        if rows and not line.startswith("|"):
            break
        match = ROW.match(line)
        if match is not None:
            rows[match.group(1)] = (match.group(2), match.group(3))
    return rows


class AtomicProfileCompositionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        text = PROFILE.read_text(encoding="utf-8")
        cls.live = section_table(text, "\n## Unreleased corrective candidate\n")
        cls.atomic = section_table(text, "\n## Candidate Atomic amendment composition\n")

    def test_atomic_composition_pins_the_live_tuple_versions(self):
        self.assertEqual(
            {name: version for name, (version, _) in self.atomic.items()},
            {name: version for name, (version, _) in self.live.items()},
        )

    def test_vet_row_reports_live_corrective_candidate_status(self):
        _, live_status = self.live["DACS-2-VET"]
        _, atomic_status = self.atomic["DACS-2-VET"]
        self.assertTrue(live_status.startswith("Draft corrective candidate"))
        self.assertEqual(atomic_status, live_status)
        self.assertNotIn("current composed module", atomic_status)


if __name__ == "__main__":
    unittest.main()
