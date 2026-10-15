# flint-client

A standalone, cross-platform (Linux + macOS) client for **FLINT**, the
agent-native source-control system designed for VirelaiOS
([ADR 0049](docs/adr-0049.md)) and implemented in Go as `FLINT.ELF` in the
[VirelaiOS](https://github.com/drawmeanelephant/VirelaiOS) repository.

This repository is the host port: a single static `flint` binary written in
**Zig 0.17.0**, standard library only, no dependencies. It is byte-compatible
with the ADR 0049 contract — store format, canonical byte forms, the
Op/Change/Stream/Atom data model, refusal names, and CLI output lines — so a
store produced by this client loads in the guest implementation and vice
versa.

## Documents

- `docs/flint-client-spec.md` — the implementation spec for this port
  (landed in VirelaiOS as PR #2282).
- `docs/adr-0049.md` — the normative FLINT design, copied verbatim from
  VirelaiOS ADR 0049.
- `testdata/` — the conformance corpus, copied verbatim from the Go
  implementation's `user/go/flint/testdata/`. This is the acceptance suite
  for the port; the Go implementation in VirelaiOS stays the reference
  oracle.

## Tracking

VirelaiOS milestone **M105** — an index issue plus cards M105a–f, which build
the port in order: skeleton/wire format → Zig scanner → Go scanner → store +
staging → commit → fork/merge. See `docs/flint-client-spec.md` §5.

## Status

Implemented: Go/Zig scanners, canonical hashing, bounded stores and staging,
Ed25519 commits/verification, semantic fork/merge, and authenticated TCP
clone/push/pull. See [the implementation spec](docs/flint-client-spec.md)
for the compatibility contract and current limitations.

## Build and run

Install **Zig 0.17.0** from [ziglang.org](https://ziglang.org/download/) and
put it on `PATH`. Developer checks additionally use **Python 3.11+**, with
no pip packages. No database, account, daemon, or environment variable is
needed for the local CLI.

From a fresh clone:

```sh
zig build
./zig-out/bin/flint verify --file=testdata/sig/good.jsonl
```

The second command prints `flint: verify <id> sig: verified` and exits zero.
Run all unit/conformance tests with `zig build test --summary all`, or run
the build, checks, tests, and a disposable CLI journey with:

```sh
python3 tools/check.py
```

For a development invocation, use `zig build run -- --help`. Release builds
use `zig build -Doptimize=ReleaseSafe`; cross-compilation additionally accepts
`-Dtarget=x86_64-linux`, `aarch64-linux`, `x86_64-macos`, or `aarch64-macos`.

## Development

- [AGENTS.md](AGENTS.md): exact build/check commands, environment variables,
  architecture, code/test naming conventions, and agent safety rules.
- [Contributing](CONTRIBUTING.md): Git hook setup and dependency policy.
- [QA](docs/qa.md): isolated CLI smoke test and local authenticated sync fixture.
- [Quality](docs/quality.md): lint, complexity/duplication reports, and profiling.
- [Runbooks](docs/runbooks.md): safe store and release recovery.
- [Maintainer setup](docs/maintainers.md): releases, labels, branch protection,
  CI reports, and external integrations.

Optional variables are `FLINT_STORE` (store path), `FLINT_SIGN_KEY` (key
**name**), `FLINT_REMOTE` (`tcp://host:port`), and `FLINT_AUTH_KEY` (auth-key
**file path**). Flags override them. See the complete table in
[AGENTS.md](AGENTS.md) or copy [.env.example](.env.example). The CLI does not
auto-load `.env`; none of these variables is required for tests or smoke QA.
Never put signing seed literals in flags or environment variables.

## License

See [LICENSE](LICENSE) (carried over from VirelaiOS).
