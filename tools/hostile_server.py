#!/usr/bin/env python3
"""Hostile-server checks for the flint client.

Runs the real client against a real flintd through a mutating TCP proxy that
corrupts, truncates, delays or lies in server replies. Every scenario must end
with a refusal (never a crash, a hang, or silent acceptance of bad data), and a
failed clone/pull must leave the local store verifiable and unchanged.

Needs a flintd binary: FLINTD=<path> (default ../flint-server/zig-out/bin/flintd).
"""

import json
import os
import shutil
from pathlib import Path
import re
import socket
import subprocess
import sys
import tempfile
import threading
import time

ROOT = Path(__file__).resolve().parents[1]
FLINT = ROOT / "zig-out" / "bin" / "flint"
FLINTD = Path(os.environ.get("FLINTD", ROOT.parent / "flint-server" / "zig-out" / "bin" / "flintd"))
TIMEOUT = 8  # seconds a client invocation may take before it counts as hung

# Scenarios that reproduce a tracked issue report KNOWN; once fixed they fail the
# run so the marker gets removed.
KNOWN = {}
RESULTS = []


def flint(*args):
    started = time.time()
    try:
        p = subprocess.run([str(FLINT), *map(str, args)], capture_output=True, text=True, timeout=TIMEOUT)
        return p.returncode, p.stdout + p.stderr, time.time() - started
    except subprocess.TimeoutExpired:
        return "HANG", "", time.time() - started


class Proxy:
    """Forwards each request to flintd and passes the reply through `mutate`."""

    def __init__(self, upstream, mutate):
        self.upstream, self.mutate = upstream, mutate
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(8)
        self.port = self.sock.getsockname()[1]
        threading.Thread(target=self.accept, daemon=True).start()

    def accept(self):
        while True:
            try:
                conn, _ = self.sock.accept()
            except OSError:
                return
            threading.Thread(target=self.serve, args=(conn,), daemon=True).start()

    def serve(self, conn):
        up = socket.create_connection(("127.0.0.1", self.upstream))
        cf, uf = conn.makefile("rb"), up.makefile("rb")
        try:
            while True:
                line = cf.readline()
                if not line:
                    return
                req = json.loads(line)
                up.sendall(line)
                reply = uf.readline()
                if not reply:
                    return
                out = self.mutate(req.get("op"), json.loads(reply), reply)
                if out == "HANG":
                    time.sleep(3600)
                for chunk in out:
                    conn.sendall(chunk)
        except (OSError, ValueError):
            pass
        finally:
            conn.close()
            up.close()

    def close(self):
        self.sock.close()


def enc(obj):
    return (json.dumps(obj, separators=(",", ":")) + "\n").encode()


def on(op_name, fn):
    return lambda op, reply, raw: fn(reply, raw) if op == op_name else [raw]


def tamper(r, raw):
    r["changes"][0] = re.sub(r'("message":")(.)', lambda m: m[1] + ("Z" if m[2] != "Z" else "Y"), r["changes"][0], count=1)
    return [enc(r)]


def rename(name):
    def fn(r, raw):
        r["record"]["name"] = name
        return [enc(r)]
    return fn


def seq_off(r, raw):
    r["seq"] += 1000
    return [enc(r)]


def mutate_changes(fn):
    def inner(r, raw):
        r["changes"] = fn(r["changes"])
        return [enc(r)]
    return inner


def drop_changes(r, raw):
    r.pop("changes", None)
    return [enc(r)]


# (name, op, mutator, must_refuse). A "pull" run always has one new remote change.
SCENARIOS = [
    ("tampered change", "read", tamper, True),
    ("wrong seq on hello", "hello", seq_off, True),
    ("wrong seq on read", "read", seq_off, True),
    ("silent server on hello", "hello", lambda r, raw: "HANG", True),
    ("silent server on read", "read", lambda r, raw: "HANG", True),
    ("truncated read reply", "read", lambda r, raw: [raw[: len(raw) // 2]], True),
    ("5 MiB reply line", "read", lambda r, raw: [b'{"seq":%d,"ok":true,"pad":"' % r["seq"] + b"A" * (5 << 20) + b'"}\n'], True),
    ("9 MiB reply without newline", "read", lambda r, raw: [b"A" * (9 << 20)], True),
    ("200k-element changes array", "read", mutate_changes(lambda c: c[:1] * 200000), True),
    ("100k-deep JSON", "read", lambda r, raw: [b'{"seq":%d,"ok":true,"x":' % r["seq"] + b"[" * 100000 + b"]" * 100000 + b"}\n"], True),
    ("binary garbage", "read", lambda r, raw: [b"\x00\xff\xfe not json\n"], True),
    ("empty object", "read", lambda r, raw: [b"{}\n"], True),
    ("invalid UTF-8", "read", lambda r, raw: [raw.replace(b'"ok":true', b'"ok":true,"x":"\xff\xfe"')], True),
    ("non-string changes", "read", mutate_changes(lambda c: [1, None, {"a": 1}]), True),
    ("changes missing", "read", drop_changes, True),
    ("duplicated changes", "read", mutate_changes(lambda c: c + c), True),
    ("hello protocol lie", "hello", lambda r, raw: [enc({**r, "proto": "FLINT-SYNC/2"})], True),
    ("ok:false without refuse name", "read", lambda r, raw: [enc({"seq": r["seq"], "ok": False})], True),
]
CLONE_ONLY = [
    ("reversed changes", "read", mutate_changes(lambda c: c[::-1]), True),
    ("first change skipped", "read", mutate_changes(lambda c: c[1:]), True),
    ("remote stream name is path-like", "open", rename("../../../tmp/evil"), True),
    ("remote stream name has ANSI escapes", "open", rename("A\x1b[2J" * 100), True),
]


class Fixture:
    def __init__(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="flint-hostile-"))
        subprocess.run([str(FLINTD), "init", f"--store={self.tmp / 'srv'}"], check=True, capture_output=True)
        probe = socket.socket()
        probe.bind(("127.0.0.1", 0))
        self.port = probe.getsockname()[1]
        probe.close()
        self.server = subprocess.Popen(
            [str(FLINTD), "serve", f"--store={self.tmp / 'srv'}", f"--listen=127.0.0.1:{self.port}", "--read-timeout=5"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        for _ in range(50):
            try:
                socket.create_connection(("127.0.0.1", self.port), timeout=0.2).close()
                break
            except OSError:
                time.sleep(0.1)
        self.count = 0
        self.author = self.tmp / "author"
        (self.author / "src").mkdir(parents=True)
        flint(f"--store={self.author}", "init", "--name=main", f"--src={self.author / 'src'}")
        flint(f"--store={self.author}", "keygen", "--name=a")
        for _ in range(3):
            self.commit()
        rc, out, _ = flint(f"--store={self.author}", "push", f"--remote=tcp://127.0.0.1:{self.port}")
        assert rc == 0, out

    def commit(self):
        self.count += 1
        (self.author / "src" / "main.zig").write_text("pub const alpha: u32 = %d;\npub const beta: u32 = 10;\n" % self.count)
        flint(f"--store={self.author}", "add")
        rc, out, _ = flint(f"--store={self.author}", "commit", f"-m=c{self.count}")
        assert rc == 0, out

    def new_client(self, name):
        path = self.tmp / name
        (path / "src").mkdir(parents=True)
        return path

    def close(self, keep=False):
        self.server.terminate()
        self.server.wait()
        if keep:
            print("fixture kept at %s" % self.tmp)
        else:
            shutil.rmtree(self.tmp, ignore_errors=True)


def tree(path):
    return {os.path.join(r, f): os.path.getsize(os.path.join(r, f)) for r, _, files in os.walk(path) for f in files}


def record(name, ok, detail):
    issue = KNOWN.get(name)
    if issue:
        status = "KNOWN " + issue if not ok else "FAIL (fixed; remove from KNOWN)"
        RESULTS.append((name, not ok))
    else:
        status = "ok" if ok else "FAIL"
        RESULTS.append((name, ok))
    print("%-6s %s%s" % (status if status in ("ok", "FAIL") else status.split()[0], name, "" if ok and not issue else "  -> " + detail))


def run_scenario(fx, verb, title, op, mutate, must_refuse):
    client = fx.new_client("c%d" % len(RESULTS))
    if verb == "pull":
        rc, out, _ = flint(f"--store={client}", "clone", f"tcp://127.0.0.1:{fx.port}", "--stream=main", "--name=main", f"--src={client / 'src'}")
        assert rc == 0, out
        flint(f"--store={client}", "keygen", "--name=b")
        fx.commit()
        flint(f"--store={fx.author}", "push", f"--remote=tcp://127.0.0.1:{fx.port}")
    before = tree(client)
    proxy = Proxy(fx.port, on(op, mutate))
    remote = f"tcp://127.0.0.1:{proxy.port}"
    # --read-timeout=2 keeps silent/truncated-reply scenarios inside the 8s
    # invocation budget while still exercising the client's read deadline.
    if verb == "clone":
        args = [f"--store={client}", "clone", remote, "--stream=main", "--name=main", f"--src={client / 'src'}", "--read-timeout=2"]
    else:
        args = [f"--store={client}", "pull", f"--remote={remote}", "--stream=main", "--read-timeout=2"]
    rc, out, secs = flint(*args)
    proxy.close()
    problems = []
    if rc == "HANG":
        problems.append("hung >%ds" % TIMEOUT)
    elif not isinstance(rc, int) or rc < 0 or rc > 2 or "panic" in out:
        problems.append("crashed rc=%s" % rc)
    elif must_refuse and rc == 0:
        problems.append("accepted bad data: " + out.strip()[-80:])
    elif "\x1b" in out:
        problems.append("terminal escape reached output")
    if rc != 0 and not problems or rc == 0 and verb == "clone" and title.startswith("remote stream name"):
        if verb == "pull" and tree(client) != before:
            problems.append("failed pull changed the store")
        if verb == "clone" and rc != 0 and (client / "streams").is_dir() and os.listdir(client / "streams"):
            problems.append("failed clone left streams behind")
        if verb == "clone" and rc == 0 and title.startswith("remote stream name"):
            problems.append("stored/accepted malformed stream name")
    if verb == "pull" and rc != 0 and not problems:
        vrc, vout, _ = flint(f"--store={client}", "verify", "--all")
        if vrc != 0:
            problems.append("store fails verify afterwards")
    record("%s: %s" % (verb, title), not problems, "; ".join(problems))


def pull_prefix(fx):
    """A signed proper prefix with `more:false` never reaches the advertised
    head; pull must refuse and leave the store untouched (#58)."""
    client = fx.new_client("prefix")
    rc, out, _ = flint(f"--store={client}", "clone", f"tcp://127.0.0.1:{fx.port}", "--stream=main", "--name=main", f"--src={client / 'src'}", "--read-timeout=2")
    assert rc == 0, out
    for _ in range(2):
        fx.commit()
    flint(f"--store={fx.author}", "push", f"--remote=tcp://127.0.0.1:{fx.port}")
    before = tree(client)
    proxy = Proxy(fx.port, on("read", lambda r, raw: [enc({**r, "changes": r["changes"][:1], "more": False})]))
    rc, out, _ = flint(f"--store={client}", "pull", f"--remote=tcp://127.0.0.1:{proxy.port}", "--stream=main", "--read-timeout=2")
    proxy.close()
    problems = []
    if rc == "HANG":
        problems.append("hung >%ds" % TIMEOUT)
    elif rc == 0:
        problems.append("published incomplete head: " + out.strip()[-80:])
    if tree(client) != before:
        problems.append("failed pull changed the store")
    vrc, _, _ = flint(f"--store={client}", "verify", "--all")
    if vrc != 0:
        problems.append("store fails verify afterwards")
    record("pull: signed proper prefix with more:false", not problems, "; ".join(problems))


def pull_padded_pages(fx):
    """Every reply/line stays under its own bound, but the padded suffix would
    push the log past 4 MiB; pull must refuse and leave the store untouched (#59)."""
    client = fx.new_client("padded")
    rc, out, _ = flint(f"--store={client}", "clone", f"tcp://127.0.0.1:{fx.port}", "--stream=main", "--name=main", f"--src={client / 'src'}", "--read-timeout=2")
    assert rc == 0, out
    for _ in range(5):
        fx.commit()
    flint(f"--store={fx.author}", "push", f"--remote=tcp://127.0.0.1:{fx.port}")
    before = tree(client)
    calls = [0]

    def pad(r, raw):
        calls[0] += 1
        r["changes"] = [c + " " * (900_000 - len(c.encode())) for c in r["changes"]]
        if calls[0] == 1 and len(r["changes"]) > 3:
            r["changes"] = r["changes"][:3]
            r["more"] = True
        return [enc(r)]

    proxy = Proxy(fx.port, on("read", pad))
    rc, out, _ = flint(f"--store={client}", "pull", f"--remote=tcp://127.0.0.1:{proxy.port}", "--stream=main", "--read-timeout=2")
    proxy.close()
    problems = []
    if rc == "HANG":
        problems.append("hung >%ds" % TIMEOUT)
    elif rc == 0:
        problems.append("wrote oversized log: " + out.strip()[-80:])
    if tree(client) != before:
        problems.append("failed pull changed the store")
    vrc, _, _ = flint(f"--store={client}", "verify", "--all")
    if vrc != 0:
        problems.append("store fails verify afterwards")
    record("pull: padded pages exceed 4 MiB log bound", not problems, "; ".join(problems))


def pull_reset_duplicated(fx):
    """`pull --reset` must refuse a reply repeating Change ids, all-or-
    nothing — never append a repeat (#99)."""
    client = fx.new_client("resetdup")
    rc, out, _ = flint(f"--store={client}", "clone", f"tcp://127.0.0.1:{fx.port}", "--stream=main", "--name=main", f"--src={client / 'src'}")
    assert rc == 0, out
    flint(f"--store={client}", "keygen", "--name=b")
    fx.commit()
    flint(f"--store={fx.author}", "push", f"--remote=tcp://127.0.0.1:{fx.port}")
    before = tree(client)
    proxy = Proxy(fx.port, on("read", mutate_changes(lambda c: c + c)))
    remote = f"tcp://127.0.0.1:{proxy.port}"
    rc, out, secs = flint(f"--store={client}", "pull", f"--remote={remote}", "--stream=main", "--reset", "--read-timeout=2")
    proxy.close()
    problems = []
    if rc == "HANG":
        problems.append("hung >%ds" % TIMEOUT)
    elif rc == 0:
        problems.append("accepted duplicated changes: " + out.strip()[-80:])
    if rc != 0 and not problems:
        if tree(client) != before:
            problems.append("failed pull changed the store")
        vrc, vout, _ = flint(f"--store={client}", "verify", "--all")
        if vrc != 0:
            problems.append("store fails verify afterwards")
    record("pull --reset: duplicated changes", not problems, "; ".join(problems))


def push_hang(fx):
    proxy = Proxy(fx.port, on("hello", lambda r, raw: "HANG"))
    fx.commit()
    rc, out, _ = flint(f"--store={fx.author}", "push", f"--remote=tcp://127.0.0.1:{proxy.port}", "--read-timeout=2")
    proxy.close()
    record("push: silent server on hello", rc != "HANG", "hung >%ds" % TIMEOUT)


def main():
    for path in (FLINT, FLINTD):
        if not path.exists():
            print("missing binary: %s (zig build; set FLINTD)" % path, file=sys.stderr)
            return 2
    print("flintd: %s" % FLINTD)
    fx = Fixture()
    try:
        for title, op, mutate, must in SCENARIOS:
            run_scenario(fx, "clone", title, op, mutate, must)
            run_scenario(fx, "pull", title, op, mutate, must)
        for title, op, mutate, must in CLONE_ONLY:
            run_scenario(fx, "clone", title, op, mutate, must)
        pull_prefix(fx)
        pull_padded_pages(fx)
        pull_reset_duplicated(fx)
        push_hang(fx)
    finally:
        fx.close(keep=any(not ok for _, ok in RESULTS))
    failed = [n for n, ok in RESULTS if not ok]
    print("\n%d scenarios, %d failed" % (len(RESULTS), len(failed)))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
