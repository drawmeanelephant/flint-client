"""Gate wrapper for tools/hostile_server.py (#101).

Runs the mutating-proxy scenario suite (clone/pull/push against a real
flintd through a hostile proxy) inside `python3 tools/check.py`'s
unittest discovery. Skips with an explicit reason when no server binary
is available, matching test_sync_contracts.py — a skip is not a pass, so
keep a real flintd built before trusting a local gate run.
"""

import os
from pathlib import Path
import subprocess
import unittest

ROOT = Path(__file__).resolve().parents[2]
SERVER = Path(os.environ.get("FLINTD", ROOT.parent / "flint-server" / "zig-out" / "bin" / "flintd"))
SCRIPT = ROOT / "tools" / "hostile_server.py"


class HostileServerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not SERVER.is_file():
            raise unittest.SkipTest("real flintd not built; build sibling server or set FLINTD")

    def test_hostile_scenarios(self):
        env = {k: v for k, v in os.environ.items() if not k.startswith("FLINT_")}
        env["FLINTD"] = str(SERVER)
        p = subprocess.run(
            ["python3", str(SCRIPT)],
            cwd=ROOT, env=env, capture_output=True, text=True, timeout=300)
        tail = (p.stdout + p.stderr).strip().splitlines()[-5:]
        self.assertEqual(p.returncode, 0,
                         "hostile_server.py failed (rc=%s):\n%s" % (p.returncode, "\n".join(tail)))


if __name__ == "__main__":
    unittest.main()
