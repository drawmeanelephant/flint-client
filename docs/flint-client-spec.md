# FLINT host client — implementation spec

A standalone, cross-platform (Linux + macOS) port of FLINT, the agent-native
SCM designed in VirelaiOS **ADR 0049** and implemented in Go as `FLINT.ELF`
(`user/go/flint/`). This document is the spec for the host port. Where it
says "the ADR," it means ADR 0049; where it says "the Go implementation" it
means `user/go/flint/` in the VirelaiOS repository.

**Read this with the reference material.** Copy into the new repo before
starting:

- `docs/decisions/0049-flint-scm.md` → `docs/adr-0049.md` (normative)
- `user/go/flint/testdata/` → `testdata/` (the conformance corpus, verbatim)

The Go implementation stays in VirelaiOS as the reference oracle. Its
`testdata/` is the acceptance suite for this port.

## 0. Identity and hard rules

- Binary name: `flint`. Single static executable, **Zig 0.17.0**, no
  dependencies outside the Zig standard library.
- Targets (must compile and pass the full suite on each):
  `x86_64-linux`, `aarch64-linux`, `aarch64-macos`, `x86_64-macos`.
- The **store format, canonical byte forms, Op/Change/Stream/Atom data
  model, refusal names, and CLI output line formats are the ADR 0049
  contract — byte-for-byte.** A store produced by this client must be
  loadable by the Go implementation and vice versa. Anything not listed
  under "Deltas" (§2) is identical to the ADR.
- No GPL-family code anywhere (VirelaiOS rule; carries over).
- Non-goals are the ADR's M103 non-goals: no content store or
  materialization, no `rename`/`mv` verbs, no push/pull, no concurrent
  writers, no Git interop, no GUI. Same milestone scope, new platform.

## 1. CLI surface (M103 verb parity)

Verbs, output lines (`flint: `-prefixed), refusal names, and exit codes
match the Go implementation exactly:

| Verb | Notes |
|---|---|
| `init --name=<n> --src=<dir> [--stream=<s>]` | `--stream` attaches to an existing stream and replays (ADR M103d semantics). |
| `add [file ...]` | Diff src tree → stage fold. No args = scan whole src root. |
| `status` | `flint: status atoms=<n> staged=<n> add=<a> modify=<m> delete=<d> duplicates=0` |
| `commit -m <msg>` | Signs with the selected key; `secret_not_found` refusal preserved. |
| `log` | `author=<8-hex> msg=…` lines, newest first. |
| `verify [--all] [--file=<log>]` | `sig: verified` / `sig_invalid`; `--file` checks a standalone log. |
| `fork <from> <to>` | Fork a stream at its head. |
| `merge <from>` | Net-effect 3-way merge on Ops; `merge: ok`, `merge: up to date`, `merge: conflict atom=<n> type=<t>` (exit 2), `merge: src not materialized files=<n>`. |
| `parse-corpus <dir>` | Dev/conformance verb: parse every `.go`/`.zig` file, print `flint: parse files=<n> atoms=<m> parse_errors=0`. Keep — it is how the corpus gate runs. |
| `keygen [--name=<n>]` | **New, host-only.** Generate a 32-byte seed, store it, print the derived public key hex. See §2.3. |

Exit codes: `0` success, `1` refusal/error, `2` usage error or merge
conflict. Refusals print `flint: refuse <name>` — the refusal name
vocabulary (`stream_torn`, `store_too_large`, `stale_head`,
`secret_not_found`, `src_behind`, `parse_unsupported`, `clock_unset`,
`change_malformed`, `atom_malformed`, `stage_malformed`,
`stream_malformed`, `ws_malformed`, …) is part of the contract; use the
same names the Go implementation uses for the same conditions.

## 2. Deltas from ADR 0049 (everything else is identical)

### 2.1 Store root and workspace model

- Guest: global store at `/host/FLINT`, workspaces registered under
  `ws/<name>/` with `src` a `/host` path.
- Host: store root resolves in order: `--store <dir>` flag →
  `FLINT_STORE` env var → walk up from cwd for a directory containing
  `.flint/` → error `store_not_found` naming where it looked.
- The interior layout is **unchanged**: `streams/<id>.json`,
  `streams/<id>.jsonl`, `ws/<name>/{WORKSPACE,ATOMS,STAGE,MERGE}.json*`
  — same names, same JSON fields, same bounds (4 MiB reads, 4096 Atoms,
  4096 Changes).
- `WORKSPACE.json.src` is a host path. `Atom.span.file` stays relative
  to the src root **with `/` separators on every platform** (store and
  canonical bytes never see `\`).
- A store copied out of a guest `/host/FLINT` directory loads as-is on
  the host. Streams and Changes are fully portable; a workspace's
  recorded `src` may not exist locally, which is honest — `add`
  reports the missing files, `verify`/`log`/`merge` on Streams work
  regardless.

### 2.2 Filesystem semantics

- `vi.WriteFileSafe` → host equivalent: write `<path>.tmp-<pid>-<rand>`,
  `fsync` file, `rename` over destination, `fsync` the containing
  directory. The publish must survive a crash mid-write.
- Append + fsync for `streams/*.jsonl` (never rewritten).
- Commit order, torn-append rule (`stream_torn`), and head roll-forward
  are exactly the ADR's.
- Key files (below) are created `0600`; creation fails rather than
  weakening an existing file's mode.

### 2.3 Signing keys (replaces the guest secret store)

- The guest reads `agent-sign` via `shlib.StoreGet` app-bound to
  `FLINT.ELF`. The host has no secret store. Instead:
  - `flint keygen --name=<n>` writes `<store>/keys/<n>` containing **64
    lowercase hex chars (a 32-byte seed) + newline**, mode `0600`.
    Refuses `key_exists` if present.
  - `commit` selects a key by `--key <n>` → `FLINT_SIGN_KEY` env (a key
    name or a 64-hex seed literal) → the store's sole key if exactly one
    exists → else `secret_not_found`.
  - The seed is wiped from memory after signing. `author` =
    Ed25519 public key derived from the seed, identical derivation to
    `sshlib.EdDerivePublic` (which is RFC 8032; `std.crypto.sign.Ed25519`
    gives the same key pair from the same seed — **verify against
    `testdata/sig/` before assuming**).
  - The seed must never appear in stdout, stderr, or any store file.

### 2.4 Clock, randomness, UUIDv7

- `vi.Now()` → `std.time.timestamp()` (Unix seconds). `ts` fields are
  `now*1000` (ms), one-second resolution retained.
- `vi.Random` → `std.crypto.random`.
- UUIDv7 per RFC 9562 §6.2 method 1 (monotonic `rand_a` counter within a
  millisecond tick), exactly as the ADR specifies. `clock_unset` cannot
  fire on a POSIX host; keep the refusal name in the vocabulary but it
  is unreachable.

### 2.5 JSON I/O

- Field names, `omitempty` behavior, lowercase-hex binary fields, and
  canonical UUID strings are the contract (ADR: "JSON is the carrier,
  not the signed form"). Emit fields in the same order as the Go
  struct declarations (`store.go`, `change.go`) so host- and
  guest-written files diff cleanly.
- Line-oriented files end every record with `\n`; a payload whose final
  byte is not `\n` is `stream_torn`. An empty line inside a JSONL is
  `change_malformed` (atoms: `atom_malformed`, stage: `stage_malformed`).

### 2.6 What does NOT change

- Canonical bytes: `op_bytes`, `ops_hash`, `sig_msg`, domain separators
  `"FLINT-OPS/1\x00"`, `"FLINT-CHANGE/1\x00"`, `"FLINT-ATOM/1\x00"`,
  `"FLINT-SIG/1\x00"` — verbatim from the ADR.
- Atom/Sig hash construction and the per-language Atom table (ADR §3).
- Op rules, stage fold rules, the net-effect fold, the 5×6 pairwise
  merge table, conflict naming (sorted field pairs), merge-Change
  semantics (`merged` field, always-write-a-merge-Change, never
  fast-forward), `MERGE.json` shape, and the `src_behind` /
  `origin: merge` guard.
- Output line formats for every verb (tests grep them).

## 3. The parsers — the real work

The guest had `go/parser` free and hand-wrote only a Zig scanner. The
host port needs **both scanners written in Zig**, producing
byte-identical canonical token streams, spans, and hashes to the Go
implementation. Conformance is measured, not argued: `testdata/` pins
the expected output of every scanner decision.

### 3.1 Zig declaration scanner

Port `user/go/flint/parser/zig.go` + `zigtok.go` to Zig (~1:1 is the
lowest-risk path; it carries the scanner's exact refusal behavior).
Using `std.zig.Ast` for declaration discovery is permitted **only** if
the result reproduces the corpus spans and hashes exactly — the
`parse_unsupported` refusal cases (e.g. `anon_ret.zig`) must refuse by
the same name, not silently succeed or fail differently. If std.zig.Ast
is used, the Go scanner remains the semantic reference either way.

Required tokenizer coverage (from the ADR): `//`, `///`, `//!` comments;
`"…"` strings with escapes; `\\` multiline strings; `'…'` chars;
`@"…"` identifiers; `()[]{}` nesting; qualifiers `pub`/`export`/
`extern`/`inline`; `test "label"` atoms (`stem.test:label`); anonymous
`test {}`/`comptime {}`/`usingnamespace`/`@import` consts ignored;
`const T = struct/enum/union{…}` container kinds with any layout prefix.

### 3.2 Go declaration scanner — new component, biggest work item

There is no Go parser in Zig. Write a Go tokenizer + minimal
declaration-level parser that reproduces `go/parser` +
`parser.SkipObjectResolution` behavior **for top-level declarations
only** — the Atom boundary the ADR defines:

- **Tokenizer:** all Go token kinds; `//` and `/* */` comments dropped;
  interpreted/raw strings, runes; **semicolon insertion** per the Go
  spec (insert after ident/literal/`break`/`continue`/`return`/`++`/
  `--`/`)`/`]`/`}` at newline); operators/delimiters. Getting semicolon
  insertion right is the subtle part — it decides where top-level decls
  end.
- **Declarations:** `func` (incl. receiver → `method`, pointer stripped,
  `receiver` metadata), `func TestXxx(t *testing.T)` → `test` kind
  (`pkg.test:Name`), `type` specs distinguishing
  `struct`/`interface`/`type_alias`/`type`, `const`/`var` specs with one
  Atom **per name** in a spec group (implicit iota repeat appends
  ` iota=<index>` to the canonical stream), generics (type parameters
  in `func` and `type` — the corpus has `generics.go`), grouped specs
  `const (…)`.
- **Qualified names:** `package` clause prefix; `pkg.T.M` for methods.
- **Ignored:** imports, comments, `init`, `_` names.
- **Spans:** the `FuncDecl` range, or the `TypeSpec`/`ValueSpec` range
  excluding group parens — byte offsets matching the MANIFEST.
- **Refusals:** syntax errors refuse (the corpus `bad.go` case) without
  staging anything (all-or-nothing per file).

Do not aim for a full Go parser — aim for the declaration grammar the
corpus exercises, refusing (`parse_unsupported` or a syntax refusal)
on anything it cannot place. Match the Go oracle: where the corpus is
ambiguous, `go/parser`'s span/hash decisions in the MANIFEST win.

### 3.3 Canonical token stream

Identical to the ADR §3: decl byte range → tokenize → drop comments →
join single-spaced → declared identifier → `_` (multi-name specs: only
this Atom's name). `hash` and `sig_hash` domains and signature-boundary
rules (before body `{`; whole decl for types; type+value for const;
qualifiers+type for var) unchanged. `testdata/canon/*.txt` pins the
token streams themselves; `corpus/MANIFEST.json` pins spans + both
hashes for all 245 atoms.

## 4. Conformance suite (the acceptance bar)

All of it ports from `testdata/`; none of it is optional.

| Suite | Source | Pass condition |
|---|---|---|
| Corpus | `testdata/corpus/` + `MANIFEST.json` | Parse all 100 files; atom count, per-atom (file, kind, name, start, end, hash, sig_hash) all equal MANIFEST; `parse_errors=0`. |
| Canon | `testdata/canon/*.txt` | Canonical token streams byte-equal. |
| Pairs/refusals | corpus pair files + `anon_ret.zig`, `bad.go` | Same hash-movement behavior (rename=none, body=hash only, ws/comments=none, param=both, field reorder=both) and same refusal names. |
| Signatures | `testdata/sig/{good,bad}.jsonl, preimage.hex, seed.hex` | `verify --file` → `sig: verified` on good, `sig_invalid` on bad; recomputed sig_msg equals `preimage.hex`; Ed25519 derive/sign/verify matches stdlib-independent vectors. |
| Merge | `testdata/merge/*.json` (20 scenarios) | For each scenario: build `into`/`from` op histories over `base_atoms`, run the merge fold, compare `want.clean`, emitted ops, and conflict list — including `into`↔`from` symmetry where the Go suite asserts it. |
| Store | ported from `flint_test.go` memFS suite | Init layout; idempotent re-add; edit→`modified`/`deleted` counts; stage fold rules; duplicate-decl all-or-nothing; torn line; 4096 bounds; `stale_head`. |
| UUIDv7 | ported | Monotonic ordering within a tick; version/variant bits; RFC 9562 layout. |
| Commit/verify | ported | Roll-forward on stale stream record; `secret_not_found` leaves stage intact and writes nothing; flip-any-field fails verify; JSON key-order/whitespace invariance. |

Test harness note: the Go suite drives the merge scenarios through an
in-memory FS. The Zig port may drive them through the CLI against a
tmpdir, or through an internal FS abstraction — either is fine, but the
scenario JSON files must be consumed **verbatim, unmodified**.

## 5. Suggested card breakdown

Claimable in order (each is landable with its own tests):

| # | Card | Delivers | Suite legs |
|---|---|---|---|
| C1 | Skeleton + wire format | `build.zig` (0.17), arg parsing, store-model types, JSON emit/parse in Go field order, UUIDv7, Ed25519 sign/verify, `keygen`, `verify --file`/`--all` | Signatures, UUIDv7, JSON invariance |
| C2 | Zig scanner | `zigtok` + `zig.go` port, canonical hashing, `parse-corpus` | Corpus (.zig half), canon zig_* goldens, `parse_unsupported` refusals |
| C3 | Go scanner | Go tokenizer + decl parser (§3.2) | Corpus (full MANIFEST), canon go_* goldens, `bad.go` refusal |
| C4 | Store + staging | `init`/`add`/`status`, index load, stage fold, atom matching, WriteFileSafe | Store suite legs |
| C5 | Commit | `commit`/`log`, signed Changes, roll-forward, key resolution | Commit/verify suite legs |
| C6 | Fork + merge | `fork`, `init --stream` replay, merge fold + pairwise table, `MERGE.json`, `src_behind` | Merge suite (20 scenarios + symmetry) |

If Go support needs to be cut for a first usable binary, ship C1+C2+C4–C6
with `.go` files ignored and defer C3 — but the corpus suite only goes
fully green with C3.

## 6. Explicitly out of scope (v1)

- Content store / checkout / materializing merged source (needs a blob
  store; it is FLINT M1 in VirelaiOS too).
- `flint rename` / `flint mv` verbs; heuristic rename detection (never).
- Push/pull, networking, a daemon, leases/concurrent writers.
- Trust roots/policy for `author`; `verify` proves integrity + which
  key signed, not that the key is trusted.
- Reading VirelaiOS guest internals (SECRETS.TXT, OWNERS.TXT, `/host`
  semantics) — stores are portable, the guest's secret mechanism is not.
