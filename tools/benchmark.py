#!/usr/bin/env python3
"""Measure actual CLI parsing throughput without touching the golden corpus."""

import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--seconds", type=float, default=5)
    args = parser.parse_args()
    if not 0 < args.seconds <= 300:
        parser.error("--seconds must be greater than zero and at most 300")
    binary = ROOT / "zig-out/bin/flint"
    environment = {k: v for k, v in os.environ.items() if not k.startswith("FLINT_")}
    iterations = 0
    with tempfile.TemporaryDirectory(prefix="flint-benchmark-") as temporary:
        corpus = Path(temporary) / "go"
        shutil.copytree(ROOT / "testdata/corpus/go", corpus)
        started = time.monotonic()
        while iterations == 0 or time.monotonic() - started < args.seconds:
            result = subprocess.run(
                [str(binary), "parse-corpus", str(corpus)],
                env=environment, capture_output=True, text=True, timeout=30,
            )
            if result.returncode or "parse_errors=0" not in result.stdout:
                raise RuntimeError(f"Corpus benchmark failed: {result.stdout} {result.stderr}")
            iterations += 1
        elapsed = time.monotonic() - started
    report = {"iterations": iterations, "seconds": round(elapsed, 4),
              "corpus_runs_per_second": round(iterations / elapsed, 4)}
    output = ROOT / "build/reports"
    output.mkdir(parents=True, exist_ok=True)
    (output / "benchmark.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
