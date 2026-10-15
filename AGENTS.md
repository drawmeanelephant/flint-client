# Working on FLINT

This is one standalone Zig CLI, not a monorepo. Use **Zig 0.17.0** and
**Python 3.11+** (standard library only, for developer tooling). Install Zig
from its [official downloads](https://ziglang.org/download/) and put `zig` on
`PATH`. Linux and macOS are supported. No database, package installation,
account, remote daemon, or environment variable is needed for local checks.

## Commands

Run from the repository root. `python3 tools/check.py` executes the exact
marked commands below, checks documentation links, runs Zig AST analysis and
Python tooling tests, and saves logs/timings in `build/reports/`.
CI uses these same commands, so changes to this guide are exercised.

<!-- ci:format -->
```sh
zig fmt --check build.zig build.zig.zon src
```

<!-- ci:lint -->
```sh
python3 tools/quality.py --output build/reports
```

<!-- ci:build -->
```sh
zig build
```

<!-- ci:test -->
```sh
zig build test --summary all
```

<!-- ci:qa -->
```sh
python3 tools/qa.py
```

For a narrow test, use `zig test src/main.zig --test-filter 'stage fold rules'`.
`zig fmt build.zig build.zig.zon src` applies formatting. Never format the
conformance corpus: some fixture files intentionally contain invalid syntax.
Install the checked-in hook with
`git config --local core.hooksPath .githooks`. It checks the working tree;
review the staged diff separately before committing.

## Code and test conventions

- `camelCase` for functions/methods, `snake_case` for variables and fields,
  `PascalCase` for types. Preserve public names and ADR-defined wire fields.
- Keep Zig tests inline in the owning `.zig` file. Use descriptive
  `test "component: behavior"` names for new tests, including the failure
  condition when relevant. Existing journey names remain stable for filtering.
- Tooling tests belong in `tools/tests/test_*.py`, with `unittest.TestCase`
  classes and `test_*` methods.
- Use `std.testing.allocator`, fresh `TestHarness`/`MemFS` instances, and
  injected clock/RNG/transport. Do not depend on a user's FLINT store or keys.
- Never add an unlinked debt marker. Use `TODO(#123)` / `FIXME(#123)` and
  explain the issue, owner, and acceptance condition in the linked issue.
  See [technical-debt tracking](docs/technical-debt.md).

## Architecture and contracts

Read [the spec](docs/flint-client-spec.md), [ADR 0049](docs/adr-0049.md), and
the generated [module map](docs/module-map.md) before changing semantics.
`tools/quality.json` enforces the dependency layers:
foundation → model → parsers → operations → sync → CLI (arrows describe
increasing responsibility, not permitted reverse imports). The explicit
`may_import` lists are authoritative. Model/JSON/crypto currently form a
mutually dependent layer; do not introduce parser/network imports there.

- `src/main.zig`: dispatch and the CLI/conformance harness.
- `src/parser/`: tokenizers and declaration scanners, not a full compiler.
- `store.zig`, `workspace.zig`: bounded JSONL storage, replay, and staging.
- `ed25519.zig`, `canon.zig`, `sign.zig`: byte contracts and signing.
- `merge.zig`, `sync.zig`: semantic merge and FLINT-SYNC/1.

Preserve canonical bytes, refusal names, exit codes, CLI output, append-only
logs, crash-safe writes, store bounds, and cross-implementation compatibility.
Do not edit fixture expectations to hide regressions. Changes to crypto,
store recovery, or sync must include focused refusal/all-or-nothing tests.
Do not automatically retry `append`/push after an ambiguous network failure.

## Environment and secrets

All variables are optional. The CLI does **not** auto-load `.env`.

| Variable | Meaning |
| --- | --- |
| `FLINT_STORE` | Store path; overridden by `--store`; otherwise discover `.flint/` or `FLINT/`. |
| `FLINT_SIGN_KEY` | Signing key **name**, preferably created with `keygen`; overridden by `--key`. |
| `FLINT_REMOTE` | Optional `tcp://host:port` for remote verbs; overridden by `--remote`, then falls back to `REMOTE.json`. |
| `FLINT_AUTH_KEY` | Optional shared-auth key **file path**; overridden by `--auth-key`. |

Never pass seed literals on the command line or in the environment. Key names
and mode-0600 files avoid shell-history/process-list exposure. Never print
seeds, auth keys, raw environment dumps, or store key contents. Published
`testdata/sig/` vectors are test-only, never production keys.

## QA, services, and recovery

[QA instructions](docs/qa.md) cover a complete local journey and the
in-process/loopback flintd fixture, including authentication and teardown.
`tools/qa.py` clears inherited `FLINT_*` variables and uses a disposable
store. No login or externally managed service is required.
Use [runbooks](docs/runbooks.md) for divergent histories, torn logs, bad keys,
or release regressions. Never reset, truncate, or overwrite a user's store.

See [quality checks](docs/quality.md), [contributing](CONTRIBUTING.md), and
[maintainer setup](docs/maintainers.md) for reports, releases, external
settings, dependency policy, and remaining integrations.
