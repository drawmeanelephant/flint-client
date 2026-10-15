#!/usr/bin/env python3
"""Build and checksum one release archive. This script never publishes."""

import argparse
import hashlib
import io
from pathlib import Path
import re
import subprocess
import tarfile

ROOT = Path(__file__).resolve().parents[1]
TARGETS = ("x86_64-linux", "aarch64-linux", "x86_64-macos", "aarch64-macos")


def release_version(manifest, tag):
    match = re.search(r'\.version\s*=\s*"([^"]+)"', manifest)
    if not match:
        raise ValueError("Missing package version")
    version = match.group(1)
    valid = re.fullmatch(
        r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)"
        r"(?:-(?P<prerelease>[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?"
        r"(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?", version,
    )
    if not valid or any(
        part.isdecimal() and len(part) > 1 and part.startswith("0")
        for part in (valid.group("prerelease") or "").split(".")
    ):
        raise ValueError("Package version must be SemVer")
    if tag != f"v{version}":
        raise ValueError(f"Tag must match package version v{version}, not {tag}")
    return version


def archive_readme(source, tag):
    base = f"https://github.com/drawmeanelephant/flint-client/blob/{tag}/"

    def link(match):
        target = match.group(2)
        if "://" not in target and not target.startswith(("#", "mailto:")):
            target = base + target
        return match.group(1) + target + ")"

    linked = re.sub(r"(\[[^\]]*\]\()([^ )]+)\)", link, source)
    return (
        "# Prebuilt FLINT binary\n\n"
        "After verifying the downloaded SHA-256 checksum, extract this archive "
        "and run `./flint --help`, or place `flint` on your PATH.\n"
        "Documentation links below refer to the matching source release.\n\n"
        + linked
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", required=True, choices=TARGETS)
    parser.add_argument("--tag", required=True)
    parser.add_argument("--output", type=Path, default=ROOT / "dist")
    args = parser.parse_args()
    version = release_version((ROOT / "build.zig.zon").read_text(), args.tag)
    name = f"flint-{version}-{args.target}"
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    archive = output / f"{name}.tar.gz"
    if archive.exists():
        raise FileExistsError(f"Refusing to overwrite existing archive {archive}")
    prefix = ROOT / "build/release" / args.target
    subprocess.run(["zig", "build", f"-Dtarget={args.target}", "-Doptimize=ReleaseSafe",
                    "--prefix", str(prefix)], cwd=ROOT, check=True)
    with tarfile.open(archive, "x:gz") as tar:
        for source, target in [(prefix / "bin/flint", "flint"), (ROOT / "LICENSE", "LICENSE")]:
            tar.add(source, arcname=f"{name}/{target}", recursive=False)
        content = archive_readme((ROOT / "README.md").read_text(), args.tag).encode()
        entry = tarfile.TarInfo(f"{name}/README.md")
        entry.size = len(content)
        entry.mode = 0o644
        tar.addfile(entry, io.BytesIO(content))
    digest = hashlib.sha256(archive.read_bytes()).hexdigest()
    with archive.with_suffix(archive.suffix + ".sha256").open("x") as checksum:
        checksum.write(f"{digest}  {archive.name}\n")
    print(archive)


if __name__ == "__main__":
    main()
