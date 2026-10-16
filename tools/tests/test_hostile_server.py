"""Gate for the live hostile-server suite; set FLINTD when it is not a sibling build.

tools/check.py runs this through unittest discovery, so the mutating-proxy
scenarios in tools/hostile_server.py run in the same gate as every other
tooling test whenever a real flintd resolves — and skip explicitly otherwise.
"""

import os
from pathlib import Path
import subprocess
import sys
import unittest

ROOT = Path(__file__).resolve().parents[2]
SERVER = Path(os.environ.get("FLINTD", ROOT.parent / "flint-server" / "zig-out" / "bin" / "flintd"))
SUITE = ROOT / "tools" / "hostile_server.py"


class HostileServerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not SERVER.is_file():
            raise unittest.SkipTest("real flintd not built; build sibling server or set FLINTD")
        subprocess.run(["zig", "build"], cwd=ROOT, check=True, capture_output=True, timeout=120)

    def test_mutating_proxy_scenarios_refuse_bad_replies(self):
        result = subprocess.run([sys.executable, str(SUITE)], cwd=ROOT,
                                capture_output=True, text=True, timeout=600)
        print(result.stdout, end="")
        self.assertEqual(result.returncode, 0,
                         "hostile-server suite exited %d; stderr: %s"
                         % (result.returncode, result.stderr.strip()[-500:]))
