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

Scaffold only. No implementation yet.

## License

See [LICENSE](LICENSE) (carried over from VirelaiOS).
