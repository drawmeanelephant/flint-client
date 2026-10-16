#!/usr/bin/env python3
"""B3 acceptance journey (issue #80, docs/flint-blobs-spec.md §10).

A fresh agent clone must obtain complete source content from FLINT itself —
manifests and blobs served by a real flintd over the FLINT-SYNC/1 content
ops — and `flint checkout` must reproduce the publisher's tree
byte-identically, with no access to the publisher's directory, shared dirs,
fixture copies, or a git checkout.

Needs a spec_rev >= 4 flintd binary: FLINTD=<path> (default
../flint-server/zig-out/bin/flintd). Uses this repo's zig-out/bin/flint.
"""

import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
FLINT = ROOT / "zig-out" / "bin" / "flint"
FLINTD = Path(os.environ.get("FLINTD", ROOT.parent / "flint-server" / "zig-out" / "bin" / "flintd"))
TIMEOUT = 30


def flint(*args, key=None):
    env = dict(os.environ)
    for var in (k for k in env if k.startswith("FLINT_")):
        del env[var]
    if key:
        env["FLINT_SIGN_KEY"] = key
    p = subprocess.run([str(FLINT), *map(str, args)], capture_output=True, text=True,
                       timeout=TIMEOUT, env=env)
    return p.returncode, p.stdout + p.stderr


def drive(store, *args, expect=0, key=None):
    rc, out = flint(f"--store={store}", *args, key=key)
    if rc != expect:
        raise RuntimeError(f"flint {' '.join(map(str, args))} rc={rc} (want {expect})\n{out}")
    return out


def free_port():
    probe = socket.socket()
    probe.bind(("127.0.0.1", 0))
    port = probe.getsockname()[1]
    probe.close()
    return port


def start_flintd(store):
    subprocess.run([str(FLINTD), "init", f"--store={store}"], check=True, capture_output=True)
    port = free_port()
    proc = subprocess.Popen(
        [str(FLINTD), "serve", f"--store={store}", f"--listen=127.0.0.1:{port}", "--read-timeout=5"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    for _ in range(50):
        try:
            socket.create_connection(("127.0.0.1", port), timeout=0.2).close()
            break
        except OSError:
            time.sleep(0.1)
    else:
        raise RuntimeError("flintd did not start listening")
    return proc, port


def tree(root):
    """path -> (bytes, mode) for every regular file under `root`."""
    root = Path(root)
    return {
        str(p.relative_to(root)): (p.read_bytes(), p.stat().st_mode & 0o777)
        for p in sorted(root.rglob("*"))
        if p.is_file() and not p.is_symlink()
    }


def commit_id(out):
    marker = "flint: commit ok id="
    assert out.startswith(marker), out
    return out[len(marker):].split()[0]


def main():
    for path, name in ((FLINT, "flint"), (FLINTD, "flintd")):
        if not path.exists():
            print("missing binary: %s (zig build; set FLINTD)" % name, file=sys.stderr)
            return 1

    with tempfile.TemporaryDirectory(prefix="flint-b3-") as tmpdir:
        tmp = Path(tmpdir)
        server, port = start_flintd(tmp / "srv")
        remote = f"tcp://127.0.0.1:{port}"
        try:
            # --- Agent A: mixed project, two revisions, push. -------------
            a_store, a_src = tmp / "a" / "store", tmp / "a" / "src"
            a_src.mkdir(parents=True)
            (a_src / "calc.go").write_text("package calc\n\nfunc Add(a, b int) int { return a + b }\n")
            (a_src / "main.zig").write_text("pub fn alpha() void {}\n")
            (a_src / "README.md").write_text("# Era One\n")
            (a_src / "asset.bin").write_bytes(bytes([0, 1, 0xFE, 0xFF, 0x7F]))
            (a_src / "run.sh").write_text("#!/bin/sh\necho ok\n")
            os.chmod(a_src / "run.sh", 0o755)
            (a_src / "notes.txt").write_text("opaque file, no ops\n")
            (a_src / "pkg" / "deep.py").parent.mkdir()
            (a_src / "pkg" / "deep.py").write_text("print('hi')\n")

            drive(a_store, "init", "--name=a", f"--src={a_src}")
            drive(a_store, "keygen", "--name=a")
            drive(a_store, "add", str(a_src))
            out = drive(a_store, "commit", "-m", "c1", key="a")
            c1 = commit_id(out)
            # Content-only revision: README edit yields ops:[] yet still signs
            # a complete manifest.
            (a_src / "README.md").write_text("# Era One\n\nv2\n")
            out = drive(a_store, "commit", "-m", "docs only", key="a")
            assert "ops=0" in out, out
            drive(a_store, "push", f"--remote={remote}", key="a")

            # --- Agent B: fresh clone + checkout, byte-identical. ----------
            b_store, b_src, b_out = tmp / "b" / "store", tmp / "b" / "src", tmp / "b" / "out"
            b_store.mkdir(parents=True)
            drive(b_store, "clone", remote, "--stream=main", "--name=b", f"--src={b_src}")
            drive(b_store, "verify", "--all")
            drive(b_store, "checkout", "--head", f"--into={b_out}")
            if tree(b_out) != tree(a_src):
                raise RuntimeError(
                    "checkout tree differs from publisher tree:\n"
                    f"  only-a: {sorted(set(tree(a_src)) - set(tree(b_out)))}\n"
                    f"  only-b: {sorted(set(tree(b_out)) - set(tree(a_src)))}\n"
                    f"  differing: {[k for k in tree(a_src) if tree(b_out).get(k) != tree(a_src)[k]]}")
            # Historical revision snapshot materializes byte-identically too.
            b_out1 = tmp / "b" / "out1"
            drive(b_store, "checkout", f"--change={c1}", f"--into={b_out1}")
            era1 = tree(b_out1)
            assert era1["README.md"][0] == b"# Era One\n", era1["README.md"]

            # --- Agent B commits + pushes; Agent A pulls the content back. -
            drive(b_store, "keygen", "--name=b")
            (b_src / "bnotes.md").write_text("b's opaque note\n")
            (b_src / "calc.go").write_text("package calc\n\nfunc Add(a, b int) int { return a + b }\n\nfunc Sub(a, b int) int { return a - b }\n")
            drive(b_store, "add", str(b_src))
            drive(b_store, "commit", "-m", "c3 from b", key="b")
            drive(b_store, "push", f"--remote={remote}", key="b")

            drive(a_store, "pull", f"--remote={remote}", key="a")
            a_out = tmp / "a" / "out"
            drive(a_store, "checkout", "--head", f"--into={a_out}")
            if tree(a_out) != tree(b_src):
                raise RuntimeError("pulled checkout tree differs from B's src")

            print("B3 journey passed: fresh clone + checkout reproduced byte-identical source,"
                  " historical snapshots materialized, and pulled content verified.")
        finally:
            server.terminate()
            server.wait()
    return 0


if __name__ == "__main__":
    sys.exit(main())
