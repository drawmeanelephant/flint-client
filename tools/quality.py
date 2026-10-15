#!/usr/bin/env python3
"""Dependency-free, token-aware quality checks for this Zig repository.

Hard gates: AST errors (in check.py), file limits, import boundaries, unused
build dependencies, issue-less debt markers, private key paths, and stale docs.
Review findings: estimated complexity, duplicate token blocks, unused private
functions. These are heuristics, not a substitute for the Zig compiler.
"""

import argparse
from collections import Counter, defaultdict
from dataclasses import asdict, dataclass
import json
from pathlib import Path
import re
import subprocess

ROOT = Path(__file__).resolve().parents[1]
TOKEN_PATTERN = re.compile(r"[A-Za-z_][A-Za-z_0-9]*|[0-9][A-Za-z_0-9.]*|=>")


@dataclass(frozen=True)
class Token:
    text: str
    line: int
    kind: str = "code"


@dataclass(frozen=True)
class Finding:
    rule: str
    path: str
    line: int
    message: str
    severity: str = "error"


def tokenize(source):
    """Discard comments; keep quoted literals atomic and retain line numbers."""
    tokens, comments = [], []
    i, line = 0, 1
    while i < len(source):
        char = source[i]
        if char.isspace():
            line += char == "\n"
            i += 1
            continue
        start, start_line = i, line
        if source.startswith("//", i) or source.startswith("\\\\", i):
            end = source.find("\n", i)
            end = len(source) if end < 0 else end
            text = source[i:end]
            if text.startswith("//"):
                comments.append(Token(text, line, "comment"))
            else:
                tokens.append(Token(text, line, "literal"))
            i = end
            continue
        if char in "\"'":
            quote = char
            i += 1
            while i < len(source):
                if source[i] == "\\":
                    i += 2
                elif source[i] == quote:
                    i += 1
                    break
                else:
                    i += 1
            text = source[start:i]
            tokens.append(Token(text, start_line, "literal"))
            line += text.count("\n")
            continue
        match = TOKEN_PATTERN.match(source, i)
        text = match.group() if match else char
        tokens.append(Token(text, line))
        i += len(text)
    return tokens, comments


def closing(tokens, start, left="{", right="}"):
    depth = 0
    for index in range(start, len(tokens)):
        depth += tokens[index].text == left
        depth -= tokens[index].text == right
        if depth == 0:
            return index
    raise ValueError(f"unbalanced {left} on line {tokens[start].line}")


def functions(tokens):
    """Find named function bodies, including functions nested in test fixtures."""
    for index, token in enumerate(tokens):
        if token.text != "fn" or index + 2 >= len(tokens):
            continue
        name = tokens[index + 1].text
        if tokens[index + 2].text != "(":
            continue
        cursor = closing(tokens, index + 2, "(", ")") + 1
        while cursor < len(tokens) and tokens[cursor].text not in (";", "{"):
            if tokens[cursor].text in ("error", "struct", "union", "enum", "opaque"):
                aggregate = cursor + 1
                if aggregate < len(tokens) and tokens[aggregate].text == "(":
                    aggregate = closing(tokens, aggregate, "(", ")") + 1
                if aggregate < len(tokens) and tokens[aggregate].text == "{":
                    cursor = closing(tokens, aggregate) + 1
                    continue
            cursor += 1
        if cursor >= len(tokens) or tokens[cursor].text != "{":
            continue
        end = closing(tokens, cursor)
        body = tokens[cursor + 1:end]
        decisions = {"if", "for", "while", "catch", "orelse", "and", "or", "=>"}
        complexity = 1 + sum(t.kind == "code" and t.text in decisions for t in body)
        public = index > 0 and tokens[index - 1].text in ("pub", "export")
        yield name, token.line, body, complexity, public


def imports(tokens):
    for index in range(len(tokens) - 4):
        if [t.text for t in tokens[index:index + 3]] == ["@", "import", "("]:
            value = tokens[index + 3]
            if value.kind == "literal" and value.text.startswith('"'):
                yield json.loads(value.text), value.line


def dependency_names(tokens):
    """Read the immediate .dependencies ZON map, not nested URL/hash fields."""
    for index in range(len(tokens) - 3):
        if [t.text for t in tokens[index:index + 3]] != [".", "dependencies", "="]:
            continue
        start = index + 3
        if tokens[start].text != "." or tokens[start + 1].text != "{":
            raise ValueError("dependencies must be an explicit ZON struct")
        start += 1
        end, depth, names = closing(tokens, start), 0, []
        for cursor in range(start + 1, end):
            text = tokens[cursor].text
            if depth == 0 and text == "." and cursor + 2 < end:
                name_index = cursor + 1
                if tokens[name_index].text == "@":
                    name_index += 1
                if tokens[name_index + 1].text == "=":
                    names.append(tokens[name_index].text.strip('"'))
            depth += text == "{"
            depth -= text == "}"
        return names
    raise ValueError("build.zig.zon must declare .dependencies")


def dependency_findings(zon, build):
    declared = dependency_names(tokenize(zon)[0])
    build_tokens = tokenize(build)[0]
    used = set()
    for i in range(len(build_tokens) - 3):
        if build_tokens[i].text in ("dependency", "lazyDependency") and build_tokens[i + 1].text == "(":
            used.add(build_tokens[i + 2].text.strip('"'))
    return [
        Finding("unused-dependency", "build.zig.zon", 1, f"Dependency {name} is never requested by the build.")
        for name in declared if name not in used
    ]


def duplicate_findings(streams, width):
    seen, findings, reported_until = defaultdict(list), [], {}
    for path, tokens in sorted(streams.items()):
        for start in range(max(0, len(tokens) - width + 1)):
            if start < reported_until.get(path, 0):
                continue
            window = tuple(t.text for t in tokens[start:start + width])
            candidates = seen[window]
            peer = next(((p, s, line) for p, s, line in candidates
                         if p != path or abs(start - s) >= width), None)
            if peer:
                peer_path, _, peer_line = peer
                findings.append(Finding(
                    "duplicate-block", path, tokens[start].line,
                    f"{width} identical tokens also at {peer_path}:{peer_line}; review for extraction.",
                    "warning",
                ))
                reported_until[path] = start + width
            else:
                candidates.append((path, start, tokens[start].line))
    return findings


def layer_for(path, policy):
    for name, layer in policy["layers"].items():
        if any(path == member or (member.endswith("/") and path.startswith(member))
               for member in layer["files"]):
            return name
    return None


def boundary_findings(path, tokens, policy):
    findings, edges = [], []
    layer = layer_for(path, policy)
    if layer is None:
        return [Finding("module-boundary", path, 1, "Assign this source file to an architecture layer.")], edges
    for target, line in imports(tokens):
        if target in ("std", "builtin"):
            continue
        if not target.endswith(".zig"):
            findings.append(Finding("module-boundary", path, line, f"Unapproved package import: {target}"))
            continue
        normalized = (ROOT / path).parent.joinpath(target).resolve()
        try:
            relative = normalized.relative_to(ROOT).as_posix()
        except ValueError:
            relative = ""
        target_layer = layer_for(relative, policy)
        edges.append((path, relative))
        if target_layer not in policy["layers"][layer]["may_import"]:
            findings.append(Finding(
                "module-boundary", path, line,
                f"{layer} must not depend on {target_layer or target}; update the architecture deliberately.",
            ))
    return findings, edges


def module_document(edges):
    lines = ["# Module map", "", "Generated by `python3 tools/quality.py --write-docs`. Do not edit by hand.",
             "", "Edges are literal Zig imports; standard-library imports are omitted.", "", "```mermaid", "flowchart LR"]
    for source, target in sorted(set(edges)):
        src_id = re.sub(r"\W", "_", source)
        dst_id = re.sub(r"\W", "_", target)
        lines.append(f'  {src_id}["{source}"] --> {dst_id}["{target}"]')
    return "\n".join(lines + ["```", ""])


def repository_files(root):
    result = subprocess.check_output(
        ["git", "-C", str(root), "ls-files", "--cached", "--others", "--exclude-standard", "-z"]
    )
    return sorted(set(name.decode() for name in result.split(b"\0") if name))


def file_findings(root, paths, policy):
    findings = []
    for name in paths:
        path = root / name
        if path.is_symlink() or not path.is_file():
            continue
        parts = Path(name).parts
        if ".flint" in parts or ("keys" in parts and "testdata" not in parts) or (
            Path(name).name.startswith(".env") and Path(name).name not in (".env.example", ".env.template")
        ):
            findings.append(Finding("private-file", name, 1, "Private environment/key-store path must not be committed."))
        if path.stat().st_size > policy["max_file_bytes"]:
            findings.append(Finding("large-file", name, 1, f"File exceeds {policy['max_file_bytes']} bytes."))
        if name.startswith("src/") and path.suffix == ".zig":
            if len(path.read_text().splitlines()) > policy["max_source_lines"]:
                findings.append(Finding("large-file", name, 1, f"Split source before exceeding {policy['max_source_lines']} lines."))
    return findings


def debt_findings(path, comments):
    findings = []
    for comment in comments:
        for match in re.finditer(r"\b(TODO|FIXME|HACK|XXX)\b", comment.text):
            if not re.match(r"\(#\d+\)", comment.text[match.end():]):
                findings.append(Finding(
                    "untracked-debt", path, comment.line,
                    "Debt markers must include a GitHub issue, for example TODO(#31).",
                ))
    return findings


def markdown_report(findings, metrics):
    lines = ["# FLINT quality report", "", "## Source metrics", "",
             "| Source | Lines | Functions | Maximum estimated complexity |",
             "| --- | ---: | ---: | ---: |"]
    for path, values in sorted(metrics.items()):
        lines.append(f"| `{path}` | {values['lines']} | {values['functions']} | {values['max_complexity']} |")
    lines += ["", "## Findings", ""]
    lines += [f"- **{f.severity}: {f.rule}** `{f.path}:{f.line}`: {f.message}" for f in findings]
    if not findings:
        lines.append("No findings.")
    lines += ["", "Complexity, duplicate blocks, and unused private functions are review heuristics.",
              "See docs/quality.md for limits and interpretation.", ""]
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, help="Retain Markdown and JSON reports")
    parser.add_argument("--write-docs", action="store_true", help="Regenerate the import diagram")
    args = parser.parse_args()
    policy = json.loads((ROOT / "tools/quality.json").read_text())
    findings = file_findings(ROOT, repository_files(ROOT), policy)
    metrics, streams, edges = {}, {}, []
    counts = Counter()
    parsed = {}
    for path in sorted((ROOT / "src").rglob("*.zig")):
        name = path.relative_to(ROOT).as_posix()
        source = path.read_text()
        tokens, comments = tokenize(source)
        parsed[name] = tokens
        counts.update(t.text for t in tokens if t.kind == "code")
        findings.extend(debt_findings(name, comments))
        violations, imports_found = boundary_findings(name, tokens, policy)
        findings.extend(violations)
        edges.extend(imports_found)
        funcs = list(functions(tokens))
        metrics[name] = {
            "lines": len(source.splitlines()), "functions": len(funcs),
            "max_complexity": max((f[3] for f in funcs), default=0),
        }
        # Test bodies intentionally repeat CLI journeys and fixture setup.
        # Production functions, not fixtures or inline tests, form the CPD scope.
        production_end = next((i for i, t in enumerate(tokens)
                               if t.text == "test" and (i == 0 or tokens[i - 1].text == "}")), len(tokens))
        streams[name] = tokens[:production_end]
    for path, tokens in parsed.items():
        for name, line, _, complexity, public in functions(tokens):
            if complexity > policy["complexity_warning"]:
                findings.append(Finding(
                    "complexity", path, line, f"{name}: estimated complexity {complexity} exceeds review threshold {policy['complexity_warning']}.",
                    "warning",
                ))
            if not public and counts[name] == 1:
                findings.append(Finding(
                    "unused-private-function", path, line,
                    f"{name} has no lexical references; confirm before deleting (reflection may use it).",
                    "warning",
                ))
    findings.extend(duplicate_findings(streams, policy["duplicate_tokens"]))
    findings.extend(dependency_findings((ROOT / "build.zig.zon").read_text(), (ROOT / "build.zig").read_text()))
    document = module_document(edges)
    destination = ROOT / "docs/module-map.md"
    if args.write_docs:
        destination.write_text(document)
    elif not destination.exists() or destination.read_text() != document:
        findings.append(Finding("stale-module-doc", "docs/module-map.md", 1, "Run python3 tools/quality.py --write-docs."))
    findings.sort(key=lambda f: (f.path, f.line, f.rule))
    report = markdown_report(findings, metrics)
    print(report)
    if args.output:
        args.output.mkdir(parents=True, exist_ok=True)
        (args.output / "quality.md").write_text(report)
        (args.output / "quality.json").write_text(json.dumps({
            "metrics": metrics, "findings": [asdict(f) for f in findings],
        }, indent=2) + "\n")
    return int(any(f.severity == "error" for f in findings))


if __name__ == "__main__":
    raise SystemExit(main())
