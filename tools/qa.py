#!/usr/bin/env python3
"""Exercise the built CLI without touching a user's workspace or keys."""

import argparse
import json
import os
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, default=ROOT / "zig-out/bin/flint")
    args = parser.parse_args()
    binary = args.binary.resolve()
    environment = {k: v for k, v in os.environ.items() if not k.startswith("FLINT_")}
    with tempfile.TemporaryDirectory(prefix="flint-qa-") as directory:
        cwd = Path(directory)
        source, store = cwd / "source", cwd / "store"
        source.mkdir()
        (source / "calc.go").write_text("package calc\nfunc Add(a, b int) int { return a + b }\n")

        def drive(*arguments, expected=0, contains=None):
            command = [str(binary), "--store", str(store), *arguments]
            result = subprocess.run(command, cwd=cwd, env=environment, capture_output=True, text=True, timeout=30)
            print(result.stdout, end="")
            if result.returncode != expected or (contains and contains not in result.stdout):
                raise RuntimeError(f"QA failed: {arguments[0]} returned {result.returncode}; {result.stderr}")
            return result.stdout

        drive("verify", f"--file={ROOT / 'testdata/sig/good.jsonl'}", contains="sig: verified")
        drive("verify", f"--file={ROOT / 'testdata/sig/bad.jsonl'}", expected=1, contains="sig_invalid")
        drive("init", "--name=qa", f"--src={source}", contains="flint: init ok")
        drive("keygen", "--name=qa", contains="flint: keygen")
        drive("add", contains="new=1")
        drive("status", contains="staged=1")
        drive("commit", "-m", "CLI smoke test", contains="flint: commit ok")
        drive("verify", "--all", contains="sig: verified")
        drive("log", contains="msg=CLI smoke test")
        drive("fork", "main", "feature", contains="flint: fork ok")
        drive("status", contains="staged=0")
        key = store / "keys/qa"
        if os.name == "posix" and key.stat().st_mode & 0o777 != 0o600:
            raise RuntimeError("QA signing key must be mode 0600")
        record = json.loads((store / "ws/qa/WORKSPACE.json").read_text())
        if record["name"] != "qa":
            raise RuntimeError("Workspace record did not round-trip")
    print("CLI QA passed; temporary store and signing key removed.")


if __name__ == "__main__":
    main()
