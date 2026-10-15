from pathlib import Path
import io
import re
import os
import subprocess
import sys
import tempfile
import unittest
import textwrap
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import check_coverage
import release


class ReportTests(unittest.TestCase):
    def test_coverage_merges_duplicate_records_without_inflating_totals(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name, hits in (("one", 0), ("two", 1)):
                (root / name).mkdir()
                (root / name / "cobertura.xml").write_text(
                    f'<coverage><class filename="src/a.zig"><lines>'
                    f'<line number="1" hits="{hits}"/><line number="2" hits="0"/>'
                    '</lines></class></coverage>'
                )
            result = check_coverage.measure(root)
            self.assertEqual(result, {"covered": 1, "total": 2, "percent": 50.0})

    def test_no_reports_or_no_lines_is_not_a_coverage_pass(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with self.assertRaises(ValueError):
                check_coverage.measure(root)
            (root / "cobertura.xml").write_text("<coverage/>")
            with self.assertRaises(ValueError):
                check_coverage.measure(root)

    def test_coverage_threshold_enforces_boundary_and_reports_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "cobertura.xml").write_text(
                '<coverage><class filename="src/a.zig"><lines>'
                '<line number="1" hits="1"/><line number="2" hits="0"/>'
                '</lines></class></coverage>'
            )
            for minimum, status in (("50", 0), ("51", 1)):
                with patch.object(sys, "argv", ["coverage", str(root), "--minimum", minimum]), patch("sys.stdout", io.StringIO()):
                    self.assertEqual(check_coverage.main(), status)

    def test_release_tag_must_match_manifest(self):
        self.assertEqual(release.release_version('.{ .version = "0.1.0" }', "v0.1.0"), "0.1.0")
        with self.assertRaises(ValueError):
            release.release_version('.{ .version = "0.1.0" }', "v1.0.0")
        with self.assertRaises(ValueError):
            release.release_version('.{ .version = "../../file" }', "v../../file")

    def test_release_semver_accepts_metadata_and_rejects_invalid_identifiers(self):
        for version in ("1.2.3-rc.1+build.01", "0.1.0+build-linux.1"):
            self.assertEqual(release.release_version(f'.{{ .version = "{version}" }}', f"v{version}"), version)
        for version in ("01.2.3", "1.2.3-alpha..1", "1.2.3-01", "1.2.3+"):
            with self.subTest(version=version), self.assertRaises(ValueError):
                release.release_version(f'.{{ .version = "{version}" }}', f"v{version}")

    def test_archive_creation_remains_exclusive_after_precheck_race(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "build.zig.zon").write_text('.{ .version = "0.1.0" }')
            output = root / "dist"
            output.mkdir()
            archive = output / "flint-0.1.0-x86_64-linux.tar.gz"
            archive.write_bytes(b"existing archive")
            args = ["release", "--target", "x86_64-linux", "--tag", "v0.1.0", "--output", str(output)]
            with patch.object(release, "ROOT", root), patch.object(sys, "argv", args), \
                    patch.object(Path, "exists", return_value=False), patch.object(release.subprocess, "run"):
                with self.assertRaises(FileExistsError):
                    release.main()
            self.assertEqual(archive.read_bytes(), b"existing archive")

    def test_archive_readme_links_to_matching_source_release(self):
        content = release.archive_readme("[guide](AGENTS.md) [web](https://example.com)", "v0.1.0")
        self.assertIn("blob/v0.1.0/AGENTS.md", content)
        self.assertIn("[web](https://example.com)", content)
        self.assertIn("./flint --help", content)

    def test_toolchain_pins_match_existing_package_manifest(self):
        root = Path(__file__).resolve().parents[2]
        version = re.search(r'\.minimum_zig_version\s*=\s*"([^"]+)"',
                            (root / "build.zig.zon").read_text()).group(1)
        pins = []
        for path in (root / ".github/workflows").glob("*.yml"):
            pins.extend(re.findall(r"uses: mlugg/setup-zig@[^\n]*\n\s*with:\n\s*version: \"([^\"]+)\"",
                                   path.read_text()))
        self.assertTrue(pins)
        self.assertEqual(set(pins), {version})
        for name in ("README.md", "AGENTS.md"):
            self.assertIn(f"Zig {version}", (root / name).read_text())
        self.assertIn(f"/download/{version}/zig-${{arch}}-linux-{version}.tar.xz",
                      (root / ".devcontainer/Dockerfile").read_text())

    def test_publish_workflow_marks_only_real_prereleases(self):
        root = Path(__file__).resolve().parents[2]
        workflow = (root / ".github/workflows/release.yml").read_text()
        script = textwrap.dedent(workflow[workflow.index("          flags=("):])
        # Replace the external publisher with a shell function. No GitHub API
        # call occurs; this exercises the actual checked-in shell condition.
        script = 'gh() { printf "%s\\n" "$@"; }\n' + script
        for tag, prerelease in (("v1.2.3", False), ("v1.2.3-rc.1", True),
                                ("v1.2.3+build-linux", False)):
            with self.subTest(tag=tag):
                result = subprocess.run(["bash", "-c", script], env={**os.environ, "TAG": tag},
                                        capture_output=True, text=True, check=True)
                self.assertEqual("--prerelease" in result.stdout.splitlines(), prerelease)


if __name__ == "__main__":
    unittest.main()
