from pathlib import Path
import sys
import tempfile
import unittest

TOOLS = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(TOOLS))
import quality
import check


class QualityTests(unittest.TestCase):
    def test_lexer_ignores_comment_and_string_imports(self):
        source = '// @import("bad.zig")\nconst text = "@import(\\"bad.zig\\")";\nconst real = @import("std");'
        tokens, comments = quality.tokenize(source)
        self.assertEqual(list(quality.imports(tokens)), [("std", 3)])
        self.assertEqual(len(comments), 1)

    def test_multiline_strings_are_atomic(self):
        tokens, _ = quality.tokenize('const x =\n\\\\ fn fake() { if (x) {} }\n;')
        self.assertEqual(list(quality.functions(tokens)), [])

    def test_complexity_counts_decisions_not_literals(self):
        tokens, _ = quality.tokenize('pub fn run(x: bool) error{Bad}!void { if (x and true) {} while (x) {} _ = "if"; }')
        functions = list(quality.functions(tokens))
        self.assertEqual(functions[0][0], "run")
        self.assertEqual(functions[0][3], 4)
        self.assertTrue(functions[0][4])

    def test_prototypes_do_not_consume_next_function(self):
        tokens, _ = quality.tokenize('extern fn external() void; fn local() void {}')
        self.assertEqual([f[0] for f in quality.functions(tokens)], ["local"])

    def test_inline_aggregate_return_is_not_the_implementation_body(self):
        for return_type in ("struct { value: u8 }", "error{Bad}!struct { value: u8 }",
                            "union(enum) { value: u8, none }"):
            with self.subTest(return_type=return_type):
                tokens, _ = quality.tokenize(
                    f"fn parse() {return_type} {{ if (true) {{}} return undefined; }}"
                )
                functions = list(quality.functions(tokens))
                self.assertEqual(functions[0][3], 2)
                self.assertIn("return", [token.text for token in functions[0][2]])

    def test_unused_dependencies_and_quoted_names(self):
        zon = '.{ .dependencies = .{ .unused = .{ .url = "url" }, .@"used-name" = .{ .path = "path" } } }'
        findings = quality.dependency_findings(zon, 'const x = b.dependency("used-name", .{});')
        self.assertEqual(len(findings), 1)
        self.assertIn("unused", findings[0].message)
        self.assertEqual(quality.dependency_findings('.{ .dependencies = .{} }', ""), [])

    def test_dependency_strings_and_comments_do_not_count_as_use(self):
        findings = quality.dependency_findings(
            '.{ .dependencies = .{ .unused = .{} } }',
            '// b.dependency("unused", .{})\nconst x = "dependency(\\"unused\\")";',
        )
        self.assertEqual(len(findings), 1)

    def test_boundary_blocks_parser_import_of_sync(self):
        policy = {"layers": {
            "parser": {"files": ["src/parser/"], "may_import": ["parser"]},
            "sync": {"files": ["src/sync.zig"], "may_import": []},
        }}
        tokens, _ = quality.tokenize('const sync = @import("../sync.zig");')
        findings, edges = quality.boundary_findings("src/parser/zig.zig", tokens, policy)
        self.assertEqual(findings[0].rule, "module-boundary")
        self.assertEqual(edges, [("src/parser/zig.zig", "src/sync.zig")])

    def test_duplicate_nonoverlapping_blocks(self):
        tokens, _ = quality.tokenize("fn first() void { return; }")
        findings = quality.duplicate_findings({"a.zig": tokens, "b.zig": tokens}, 5)
        self.assertTrue(findings)
        self.assertEqual(findings[0].path, "b.zig")
        self.assertEqual(quality.duplicate_findings({"a.zig": tokens}, 5), [])

    def test_debt_requires_issue_reference(self):
        _, comments = quality.tokenize("// TODO: later\n// FIXME(#31): linked\n")
        findings = quality.debt_findings("a.zig", comments)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].line, 1)

    def test_size_and_private_path_gates(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / ".env").write_text("not-a-secret")
            (root / ".env.example").write_text("safe")
            (root / "large").write_bytes(b"x" * 11)
            findings = quality.file_findings(root, [".env", ".env.example", "large"],
                                             {"max_file_bytes": 10, "max_source_lines": 4})
            self.assertEqual([f.rule for f in findings], ["private-file", "large-file", "large-file"])

    def test_document_commands_are_parsed_without_shell(self):
        text = "\n".join(f'<!-- ci:{phase} -->\n```sh\nzig "{phase} argument"\n```'
                         for phase in ("format", "lint", "build", "test", "qa"))
        self.assertEqual(check.documented_commands(text)["build"], ["zig", "build argument"])
        with self.assertRaises(ValueError):
            check.documented_commands("")
        with self.assertRaises(ValueError):
            check.documented_commands(text + "\n<!-- ci:build -->\n```sh\nzig build\n```")

    def test_command_failure_and_missing_executable_preserve_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)
            result = check.run("failed", [sys.executable, "-c", "raise SystemExit(23)"], output)
            self.assertEqual(result["exit_code"], 23)
            result = check.run("missing", [str(output / "missing-executable")], output)
            self.assertEqual(result["exit_code"], 127)
            self.assertIn("Could not launch", (output / "missing.log").read_text())

    def test_broken_document_links_fail(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name in ("README.md", "AGENTS.md", "CONTRIBUTING.md"):
                (root / name).write_text("[missing](missing.md)\n[web](https://example.com)")
            self.assertEqual(len(check.check_links(root)), 3)

    def test_generated_module_map_is_stable(self):
        edges = [("src/a.zig", "src/b.zig"), ("src/a.zig", "src/b.zig")]
        self.assertEqual(quality.module_document(edges).count("-->"), 1)


if __name__ == "__main__":
    unittest.main()
