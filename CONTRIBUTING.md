# Contributing

Start with [AGENTS.md](AGENTS.md). The project intentionally has no
third-party runtime dependencies.

1. Install Zig 0.17.0 and Python 3.11+, then run `python3 tools/check.py`.
2. Enable the local hook: `git config --local core.hooksPath .githooks`.
3. Add focused tests for the behavior you change. Run the complete checks
   before submitting a PR. Never modify conformance vectors to hide a failure.
4. Include the issue, behavior change, test commands/results, compatibility
   impact, and recovery considerations in the PR template.
5. Review the staged diff. Do not commit generated reports or local stores.

## Naming

Use camelCase Zig functions, snake_case variables/fields, and PascalCase
types. New inline Zig tests use `test "component: behavior"`; Python tooling
tests use `tools/tests/test_*.py` and `test_*` methods. Preserve existing
wire-format names and externally consumed test filters.

## Dependency updates

Adding a runtime dependency changes a deliberate portability/security
constraint and needs maintainer approval. Every new dependency must be
requested by `b.dependency`/`b.lazyDependency`, use a fixed version/content
hash, and have an approved license (no GPL-family code). The analyzer rejects
unused declarations.

Wait **at least seven days after publication** before adopting or merging
any new dependency/tool/action release. Renovate enforces this for GitHub
Actions; reviewers must enforce it for manual upgrades, including Zig.
An urgent security exception requires a maintainer's written explanation
in the PR, including the advisory and verification performed.

## Reporting problems

Use the bug/feature forms. Never attach key files, seeds, auth material, or
an unredacted store. A minimal source fixture and exact refusal name are
usually enough. Follow [SECURITY.md](SECURITY.md) for sensitive reports.
Track debt with an issue-linked marker and the process in
[technical-debt tracking](docs/technical-debt.md).
