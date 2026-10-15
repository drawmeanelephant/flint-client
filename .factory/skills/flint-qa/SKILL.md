---
name: flint-qa
description: Build and exercise the FLINT CLI safely, including signing, store journeys, and authenticated loopback sync.
---

# FLINT QA

1. Read `AGENTS.md` and `docs/qa.md`. Confirm `zig version` is 0.17.0 and
   Python is at least 3.11. Work from the repository root.
2. Run `python3 tools/check.py`. It checks formatting/AST/policy/docs,
   builds, runs tests, and drives the real binary in an isolated temporary
   source/store. Report the exact failing command; never hide a failed test.
3. For sync changes, additionally run
   `zig test src/main.zig --test-filter 'M106e auth challenge'` and
   `zig test src/main.zig --test-filter 'M106e remote verbs'`.
   The fixture provides its own test auth and loopback server; no external
   endpoint or user key is needed.
4. For recovery changes, run
   `zig test src/main.zig --test-filter 're-clone never overwrites'`.
5. Inspect `build/reports/quality.md` and `timings.json`. Explain warnings
   rather than suppressing them. Do not format/edit golden fixtures.
6. Report commands, exit codes, and observed behavior. Never attach seeds,
   auth keys, raw environment dumps, or private store contents. Do not push,
   publish a release, contact an external flintd, or change GitHub settings.
