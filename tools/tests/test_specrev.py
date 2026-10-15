from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[2]


def specrev_file_value():
    text = (ROOT / "SPECREV").read_text().strip()
    if not re.fullmatch(r"[0-9]+", text):
        raise ValueError("SPECREV must contain a single decimal integer")
    return int(text)


class SpecRevTests(unittest.TestCase):
    """Keep the repo-root SPECREV file, the binary's reported rev, and the
    versioning doc's history in lockstep (docs/spec-versioning.md)."""

    def test_specrev_file_is_a_positive_decimal_integer(self):
        self.assertGreater(specrev_file_value(), 0)

    def test_zig_spec_rev_constant_matches_specrev_file(self):
        source = (ROOT / "src" / "sync.zig").read_text()
        match = re.search(r"pub const SpecRev: u32 = (\d+);", source)
        self.assertIsNotNone(match, "src/sync.zig must define `pub const SpecRev: u32`")
        self.assertEqual(int(match.group(1)), specrev_file_value())

    def test_versioning_doc_documents_current_rev(self):
        doc = (ROOT / "docs" / "spec-versioning.md")
        self.assertTrue(doc.exists(), "docs/spec-versioning.md must exist")
        row = re.compile(rf"^\|\s*{specrev_file_value()}\s*\|", re.MULTILINE)
        self.assertRegex(doc.read_text(), row)


if __name__ == "__main__":
    unittest.main()
