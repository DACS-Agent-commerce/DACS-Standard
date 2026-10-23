"""CH-6 process-death witnesses at persistence and authority transitions."""
import os
import signal
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from test_channel_message_vectors import (
    DurableChannelIdStore, RetainedChannelRegistry, ReusedChannelIdError,
    ch6_live_issuer,
)


CHILD = r'''
import os, signal, stat, sys
from pathlib import Path
sys.path.insert(0, str(Path.cwd() / "tests"))
from test_channel_message_vectors import (
    DurableChannelIdStore, RetainedChannelRegistry, ch6_live_issuer,
)
path, transition = sys.argv[1:]
registry = RetainedChannelRegistry(store=DurableChannelIdStore(path))
issuer = ch6_live_issuer(registry, "interrupted")
real_fsync, real_replace = os.fsync, os.replace

def cut(point):
    if transition == point:
        os.kill(os.getpid(), signal.SIGKILL)

def fsync(fd):
    kind = "directory" if stat.S_ISDIR(os.fstat(fd).st_mode) else "file"
    cut("before-" + kind + "-fsync")
    real_fsync(fd)
    cut("after-" + kind + "-fsync")

def replace(source, destination):
    cut("before-rename")
    real_replace(source, destination)
    cut("after-rename")

class Grants(dict):
    def __setitem__(self, key, value):
        cut("before-grant")
        super().__setitem__(key, value)
        os.write(1, b"ADMITTED\n")
        cut("after-grant")

registry._issued_states = issuer._issued_states = Grants()
os.fsync, os.replace = fsync, replace
issuer.issue("interrupted")
cut("after-return")
raise AssertionError("crash point not reached")
'''


class ChannelRegistryCrashTests(unittest.TestCase):
    def test_ch6_process_death_at_every_durable_issuance_transition(self):
        transitions = (
            "before-file-fsync", "after-file-fsync", "before-rename", "after-rename",
            "before-directory-fsync", "after-directory-fsync",
            "before-grant", "after-grant", "after-return",
        )
        for transition in transitions:
            with self.subTest(transition=transition), tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / "used.json"
                store = DurableChannelIdStore(path)
                store.record("already-admitted")
                child = subprocess.run(
                    [sys.executable, "-c", CHILD, str(path), transition],
                    cwd=Path(__file__).resolve().parents[1], capture_output=True, timeout=10,
                )
                self.assertEqual(-signal.SIGKILL, child.returncode, child.stderr.decode())
                admitted = b"ADMITTED\n" in child.stdout
                self.assertEqual(transition in {"after-grant", "after-return"}, admitted)
                retained = DurableChannelIdStore(path).load()
                self.assertIn("already-admitted", retained)
                # A completed rename is visible after process death. A power
                # loss before directory fsync is outside this process test.
                after_rename = transition not in {
                    "before-file-fsync", "after-file-fsync", "before-rename"
                }
                self.assertEqual(after_rename, "interrupted" in retained)
                restarted = RetainedChannelRegistry(store=DurableChannelIdStore(path))
                for channel_id in retained:
                    with self.assertRaises(ReusedChannelIdError):
                        ch6_live_issuer(restarted, channel_id).issue(channel_id)
                # An ungranted, uncommitted operation can be admitted once;
                # after another restart no second authority can be issued.
                if "interrupted" not in retained:
                    ch6_live_issuer(restarted, "interrupted").issue("interrupted")
                again = RetainedChannelRegistry(store=DurableChannelIdStore(path))
                with self.assertRaises(ReusedChannelIdError):
                    ch6_live_issuer(again, "interrupted").issue("interrupted")
                ch6_live_issuer(again, "fresh-after-crash").issue("fresh-after-crash")


if __name__ == "__main__":
    unittest.main()
