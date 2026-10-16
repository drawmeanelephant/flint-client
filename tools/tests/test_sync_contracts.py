"""Real-flintd sync invariants; set FLINTD when it is not a sibling build."""

import importlib.util
import json
import os
from pathlib import Path
import re
import select
import subprocess
import tempfile
import threading
import unittest

ROOT = Path(__file__).resolve().parents[2]
CLIENT = ROOT / "zig-out/bin/flint"
SERVER = Path(os.environ.get("FLINTD", ROOT.parent / "flint-server/zig-out/bin/flintd"))
SPEC = importlib.util.spec_from_file_location("hostile_proxy", ROOT / "tools/hostile_server.py")
PROXY = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PROXY)


def snapshot(root):
    return {str(p.relative_to(root)): p.read_bytes() for p in root.rglob("*") if p.is_file()}


class SyncContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not SERVER.is_file():
            raise unittest.SkipTest("real flintd not built; build sibling server or set FLINTD")
        subprocess.run(["zig", "build"], cwd=ROOT, check=True, capture_output=True, timeout=120)

    def setUp(self):
        self.env = {k: v for k, v in os.environ.items() if not k.startswith("FLINT_")}
        temporary = tempfile.TemporaryDirectory(prefix="flint-sync-contract-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.server_store = self.root / "server"
        subprocess.run([str(SERVER), "init", f"--store={self.server_store}"],
                       env=self.env, check=True, capture_output=True, timeout=10)
        self.server = subprocess.Popen(
            # 30s (not 2s): a debug client re-reading a multi-MB local log can
            # pause longer than 2s between requests (#60 made such logs legal).
            [str(SERVER), "serve", f"--store={self.server_store}",
             "--listen=127.0.0.1:0", "--read-timeout=30"],
            env=self.env, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
        self.addCleanup(self.stop_server)
        self.assertTrue(select.select([self.server.stderr], [], [], 5)[0], "startup deadline")
        match = re.fullmatch(r"flintd: listening 127\.0\.0\.1:(\d+)\n", self.server.stderr.readline())
        self.assertIsNotNone(match, "unexpected startup response")
        self.port = int(match[1])
        self.remote = f"tcp://127.0.0.1:{self.port}"
        self.drain = threading.Thread(target=self.drain_stderr, daemon=True)
        self.drain.start()
        self.author = self.root / "author"
        self.source = self.root / "source"
        self.source.mkdir()
        self.ok(self.author, "init", "--name=main", f"--src={self.source}")
        self.ok(self.author, "keygen", "--name=test")
        self.count = 0
        self.commit()
        self.push()

    def drain_stderr(self):
        for _ in self.server.stderr:
            pass

    def stop_server(self):
        self.server.terminate()
        try:
            self.server.wait(5)
        except subprocess.TimeoutExpired:
            self.server.kill()
            self.server.wait(5)
        if hasattr(self, "drain"):
            self.drain.join(5)
        self.server.stderr.close()

    def run_client(self, store, *args):
        return subprocess.run([str(CLIENT), f"--store={store}", *args], env=self.env,
                              capture_output=True, text=True, timeout=60)

    def ok(self, store, *args):
        result = self.run_client(store, *args)
        self.assertEqual(result.returncode, 0, f"{args[0]}: {result.stdout}{result.stderr}")
        return result

    def commit(self):
        self.count += 1
        (self.source / "main.zig").write_text(
            f"pub const alpha: u32 = {self.count};\npub const beta: u32 = 10;\n")
        self.ok(self.author, "add")
        self.ok(self.author, "commit", f"-m=change-{self.count}")

    def push(self):
        self.ok(self.author, "push", f"--remote={self.remote}")

    def receiver(self, name):
        store = self.root / name
        self.ok(store, "clone", self.remote, "--stream=main", "--name=main",
                f"--src={self.root / (name + '-src')}")
        return store

    def proxy(self, mutate):
        proxy = PROXY.Proxy(self.port, mutate)
        self.addCleanup(proxy.close)
        return f"tcp://127.0.0.1:{proxy.port}"

    def head(self, store):
        return json.loads(next((store / "streams").glob("*.json")).read_text())["head"]

    def log(self, store):
        return next((store / "streams").glob("*.jsonl")).read_bytes()

    def pin_known(self, issue, fixed, reproduced):
        self.assertFalse(fixed, f"fixed; remove KNOWN {issue} and require the invariant")
        self.assertTrue(reproduced, f"unexpected behavior, not the tracked bug {issue}")
        print(f"KNOWN {issue}", flush=True)

    def test_lost_append_ack_never_retries_and_explicit_push_reconciles(self):
        self.commit()
        before = snapshot(self.author)
        appends = []

        def lose_ack(op, reply, raw):
            if op == "append":
                self.assertTrue(reply["ok"])
                appends.append(1)
                return []
            return [raw]

        remote = self.proxy(lose_ack)
        result = self.run_client(self.author, "push", f"--remote={remote}", "--read-timeout=1")
        self.assertEqual(result.returncode, 1)
        self.assertIn("timed out", result.stdout + result.stderr)
        self.assertEqual(appends, [1])
        self.assertEqual(snapshot(self.author), before)
        accepted = self.log(self.server_store)
        self.assertEqual(accepted, self.log(self.author))
        self.assertEqual(self.head(self.server_store), self.head(self.author))
        ids = [json.loads(line)["id"] for line in accepted.splitlines()]
        self.assertEqual(len(ids), len(set(ids)))
        self.assertEqual(self.ok(self.author, "push", f"--remote={self.remote}").stdout,
                         "flint: push up to date\n")
        self.assertEqual(self.log(self.server_store), accepted)
        self.ok(self.server_store, "verify", "--all")

    def test_later_page_signature_failure_is_byte_atomic_with_valid_paging_control(self):
        clients = {name: self.receiver(name) for name in ("valid", "corrupt")}
        self.commit()
        self.commit()
        self.push()
        for name, receiver in clients.items():
            with self.subTest(name=name):
                reads = []

                def paginate(op, reply, raw):
                    if op != "read":
                        return [raw]
                    reads.append(1)
                    if len(reads) == 1:
                        reply["changes"] = reply["changes"][:1]
                        reply["more"] = True
                    elif name == "corrupt":
                        return PROXY.tamper(reply, raw)
                    return [PROXY.enc(reply)]

                before = snapshot(receiver)
                remote = self.proxy(paginate)
                result = self.run_client(receiver, "pull", f"--remote={remote}", "--read-timeout=2")
                self.assertEqual(len(reads), 2)
                if name == "corrupt":
                    self.assertEqual(result.returncode, 1)
                    self.assertIn("refuse sig_invalid", result.stdout)
                    self.assertEqual(snapshot(receiver), before)
                else:
                    self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                    self.assertEqual(self.head(receiver), self.head(self.author))
                    self.assertEqual(self.log(receiver), self.log(self.author))
                self.ok(receiver, "verify", "--all")

    def test_short_signed_pull_must_reach_advertised_head(self):
        """flint-client#58: a signed-but-short pull must refuse, not publish."""
        receiver = self.receiver("short")
        self.commit()
        self.commit()
        self.push()

        def shorten(op, reply, raw):
            if op == "read":
                reply["changes"] = reply["changes"][:1]
                reply["more"] = False
                return [PROXY.enc(reply)]
            return [raw]

        before = snapshot(receiver)
        remote = self.proxy(shorten)
        result = self.run_client(receiver, "pull", f"--remote={remote}", "--read-timeout=2")
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("refuse stream_malformed", result.stdout)
        self.assertEqual(snapshot(receiver), before)
        self.ok(receiver, "verify", "--all")

    def test_aggregate_pull_bytes_must_not_publish_an_unreadable_store(self):
        """flint-client#59: per-page bounds are not an aggregate bound."""
        receiver = self.receiver("bounded")
        for _ in range(5):
            self.commit()
        self.push()
        pages = []

        def expand(op, reply, raw):
            if op == "read":
                original = reply["changes"]
                reply["changes"] = [line + " " * (900000 - len(line.encode()))
                                    for line in original[:3]]
                reply["more"] = len(original) > 3
                encoded = PROXY.enc(reply)
                pages.append(len(encoded))
                return [encoded]
            return [raw]

        before = snapshot(receiver)
        remote = self.proxy(expand)
        result = self.run_client(receiver, "pull", f"--remote={remote}", "--read-timeout=2")
        self.assertEqual(len(pages), 2)
        self.assertTrue(all(size < 4 * 1024 * 1024 for size in pages))
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("refuse store_too_large", result.stdout)
        self.assertEqual(snapshot(receiver), before)
        self.ok(receiver, "verify", "--all")

    def test_maximum_atom_commit_must_clone_from_real_server(self):
        """flint-client#60: a producer-valid Change must be receivable."""
        (self.source / "main.zig").write_text(
            "pub const alpha: u32 = 1;\npub const beta: u32 = 10;\n"
            + "".join(f"pub const item_{i:04}: u32 = {i};\n" for i in range(4094)))
        self.ok(self.author, "add")
        self.ok(self.author, "commit", "-m=maximum-atoms")
        self.push()
        source = self.log(self.author)
        self.assertGreater(len(source.splitlines()[-1]), 1024 * 1024)
        self.assertLess(len(source), 4 * 1024 * 1024)
        self.assertEqual(source, self.log(self.server_store))
        self.ok(self.author, "verify", "--all")
        self.ok(self.server_store, "verify", "--all")
        receiver = self.root / "large"
        self.ok(receiver, "clone", self.remote, "--stream=main", "--name=main",
                f"--src={self.root / 'large-src'}")
        self.assertEqual(self.log(receiver), source)
        self.ok(receiver, "verify", "--all")

    def test_clean_merge_after_reset_updates_workspace_atoms(self):
        """flint-client#64: a clean merge must leave ATOMS describing the merged head."""
        b = self.receiver("b")
        self.ok(b, "keygen", "--name=b")

        def edit(store, src, alpha, beta):
            (src / "main.zig").write_text(
                f"pub const alpha: u32 = {alpha};\npub const beta: u32 = {beta};\n")
            self.ok(store, "add")
            self.ok(store, "commit", "-m=independent-edit")

        edit(self.author, self.source, 2, 10)
        edit(b, self.root / "b-src", 1, 20)
        self.push()
        for args in [("fork", "main", "saved-b"),
                     ("pull", "--reset", f"--remote={self.remote}"),
                     ("merge", "saved-b"),
                     ("push", f"--remote={self.remote}")]:
            self.ok(b, *args)

        def atoms(store):
            return {a["name"]: a["hash"]
                    for line in (store / "ws/main/ATOMS.jsonl").read_text().splitlines()
                    for a in [json.loads(line)]}

        # A pre-fix workspace table still described alpha=1 while the merged
        # head's signed history has alpha=2 — compare against a fresh clone.
        c = self.receiver("c")
        self.assertEqual(atoms(b), atoms(c))
        self.assertEqual({"main.alpha", "main.beta"}, set(atoms(b)))

    def test_recovery_fork_degrades_cleanly_until_deposit_lands(self):
        """flint-client#73: `deposit` attempts degrade to the spec_rev 2
        re-anchor on a server that does not know the op. The fork still
        pushes and clones; the original signed Change stays local-only
        until flintd implements `deposit` (companion issue filed)."""
        b = self.receiver("b")
        self.ok(b, "keygen", "--name=b")
        (self.source / "main.zig").write_text(
            "pub const alpha: u32 = 2;\npub const beta: u32 = 10;\n")
        self.ok(self.author, "add")
        self.ok(self.author, "commit", "-m=alpha=2")
        self.push()
        (self.root / "b-src/main.zig").write_text(
            "pub const alpha: u32 = 1;\npub const beta: u32 = 20;\n")
        self.ok(b, "add")
        self.ok(b, "commit", "-m=original-b")

        def head(store):
            return next(r["head"] for p in (store / "streams").glob("*.json")
                        for r in [json.loads(p.read_text())] if r["name"] == "main")

        original = head(b)
        for args in [("fork", "main", "saved-b"),
                     ("pull", "--reset", f"--remote={self.remote}"),
                     ("merge", "saved-b"),
                     ("push", f"--remote={self.remote}"),
                     ("push", "--stream=saved-b", f"--remote={self.remote}")]:
            self.ok(b, *args)

        handoff = self.root / "handoff"
        self.ok(handoff, "clone", self.remote, "--stream=saved-b", "--name=main",
                f"--src={self.root / 'handoff-src'}")
        self.ok(handoff, "verify", "--all")

        # The preserved original is still not retrievable: today's flintd
        # refuses `deposit` with `usage`, so push fell back to re-anchoring.
        result = self.run_client(handoff, "verify", original)
        self.assertEqual(result.returncode, 1)
        self.assertIn("refuse change_missing", result.stdout + result.stderr)

    def test_merge_after_reset_guards_unmaterialized_source(self):
        """flint-client#72: stale src must refuse src_behind, not silently revert."""
        b = self.receiver("b")
        self.ok(b, "keygen", "--name=b")

        def edit(store, src, alpha, beta):
            (src / "main.zig").write_text(
                f"pub const alpha: u32 = {alpha};\npub const beta: u32 = {beta};\n")
            self.ok(store, "add")
            self.ok(store, "commit", "-m=independent-edit")

        edit(self.author, self.source, 2, 10)
        edit(b, self.root / "b-src", 1, 20)
        self.push()
        for args in [("fork", "main", "saved-b"),
                     ("pull", "--reset", f"--remote={self.remote}"),
                     ("merge", "saved-b"),
                     ("push", f"--remote={self.remote}")]:
            self.ok(b, *args)

        # B's src still holds its pre-recovery bytes (alpha=1); `add` must
        # refuse rather than stage a silent revert of A's accepted edit.
        result = self.run_client(b, "add")
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("src_behind", result.stdout + result.stderr)
        self.ok(b, "verify", "--all")

    def test_version_revision_is_additive_and_needs_no_store(self):
        absent = object()
        for value in (absent, None, "future", True, -1, 1.25, 4294967296, 0, 42):
            with self.subTest(revision="absent" if value is absent else value):
                def announce(op, reply, raw):
                    if op == "hello":
                        reply.pop("spec_rev", None)
                        if value is not absent:
                            reply["spec_rev"] = value
                        return [PROXY.enc(reply)]
                    return [raw]

                remote = self.proxy(announce)
                missing_store = self.root / "must-not-exist"
                result = self.ok(missing_store, "version", f"--remote={remote}")
                expected = str(value) if type(value) is int and 0 <= value <= 4294967295 else "unannounced"
                self.assertIn(f"flint: remote {remote} proto=FLINT-SYNC/1 spec_rev={expected}\n",
                              result.stdout)
                self.assertFalse(missing_store.exists())


if __name__ == "__main__":
    unittest.main()
