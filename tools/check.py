#!/usr/bin/env python3
"""Execute the marked AGENTS.md commands, retaining logs and phase timings."""

import argparse
import json
from pathlib import Path
import re
import shlex
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]


def documented_commands(text):
    pairs = re.findall(r"<!-- ci:(\w+) -->\s*```sh\n([^\n]+)\n```", text)
    commands = dict(pairs)
    expected = {"format", "lint", "build", "test", "qa"}
    if set(commands) != expected or len(pairs) != len(expected):
        raise ValueError(f"AGENTS.md must document exactly these CI phases: {sorted(expected)}")
    return {name: shlex.split(command) for name, command in commands.items()}


def check_links(root):
    failures = []
    paths = [root / name for name in ("README.md", "AGENTS.md", "CONTRIBUTING.md")]
    paths += list((root / "docs").rglob("*.md"))
    paths += list((root / ".factory/skills").rglob("SKILL.md"))
    for path in paths:
        if not path.exists():
            failures.append(f"Missing documentation: {path.relative_to(root)}")
            continue
        for target in re.findall(r"(?<!!)\[[^\]]*\]\(([^ )]+)(?: [^)]*)?\)", path.read_text()):
            if "://" in target or target.startswith(("#", "mailto:")):
                continue
            target = target.split("#", 1)[0]
            if target and not (path.parent / target).exists():
                failures.append(f"{path.relative_to(root)}: broken local link {target}")
    return failures


def run(name, command, output):
    print(f"[{name}] {shlex.join(command)}", flush=True)
    started = time.monotonic()
    # Stream output, preserving the original exit status and a diagnostic log.
    with (output / f"{name}.log").open("w") as log:
        try:
            with subprocess.Popen(command, cwd=ROOT, stdout=subprocess.PIPE,
                                  stderr=subprocess.STDOUT, text=True) as process:
                for line in process.stdout:
                    print(line, end="", flush=True)
                    log.write(line)
                status = process.wait()
        except OSError as error:
            message = f"Could not launch {command[0]}: {error}\n"
            print(message, end="", file=sys.stderr)
            log.write(message)
            status = 127
    return {"phase": name, "command": command, "seconds": round(time.monotonic() - started, 3), "exit_code": status}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--phase", choices=["format", "lint", "build", "test", "qa"])
    parser.add_argument("--quick", action="store_true", help="Formatting, AST, policy, docs, and tooling tests only")
    parser.add_argument("--repeat-tests", type=int, default=1, choices=range(1, 6))
    args = parser.parse_args()
    output = ROOT / "build/reports"
    output.mkdir(parents=True, exist_ok=True)
    commands = documented_commands((ROOT / "AGENTS.md").read_text())
    failures = check_links(ROOT)
    for failure in failures:
        print(failure, file=sys.stderr)
    if failures:
        return 1
    phases = [args.phase] if args.phase else (["format", "lint"] if args.quick else list(commands))
    results = []
    failed = False
    for phase in phases:
        if phase == "lint":
            lint_commands = [
                ["zig", "ast-check", str(p.relative_to(ROOT))]
                for p in [ROOT / "build.zig", ROOT / "build.zig.zon", *sorted((ROOT / "src").rglob("*.zig"))]
            ]
            lint_commands.append([sys.executable, "-m", "unittest", "discover", "-s", "tools/tests", "-v"])
            for index, command in enumerate(lint_commands):
                result = run(f"lint-{index}", command, output)
                results.append(result)
                failed |= result["exit_code"] != 0
        for repeat in range(args.repeat_tests if phase == "test" else 1):
            # Direct zig test always executes, rather than reusing a build-step
            # result. Never turn a first-attempt failure into a green retry.
            command = ["zig", "test", "src/main.zig"] if phase == "test" and args.repeat_tests > 1 else commands[phase]
            name = f"{phase}-{repeat + 1}" if phase == "test" else phase
            result = run(name, command, output)
            results.append(result)
            failed |= result["exit_code"] != 0
            if result["exit_code"] and phase != "test":
                break
    existing_path = output / "timings.json"
    existing = json.loads(existing_path.read_text()) if existing_path.exists() else []
    # Keep other phases from this CI job, replacing previous invocations.
    names = {r["phase"] for r in results}
    existing = [r for r in existing if r["phase"] not in names]
    existing_path.write_text(json.dumps(existing + results, indent=2) + "\n")
    print(f"Reports: {output.relative_to(ROOT)}; failures: {failed}")
    return int(failed)


if __name__ == "__main__":
    raise SystemExit(main())
