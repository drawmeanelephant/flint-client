# ADR 0049: FLINT — agent-native source control for VirelaiOS

- Date: 2026-10-13
- Status: **Accepted (design)**. Cards #2251–#2254; claim them in order
  with `just claim-card`.
- Milestone: **M103** (FLINT-local name "FLINT M0"). Later arcs are named
  FLINT M1–M3 here. Each gets a VirelaiOS milestone number and its own ADR
  when it is scheduled.

> FLINT is source control **for VirelaiOS**, not a general-purpose VCS. It is
> designed to work with INIT (ADR 0042), the agent channel (ADR 0044), GOSELF
> (ADR 0031) and RFB (ADR 0037), but none of that integration is in M103.
> No Git compatibility, no web UI, no GitHub.

## Mission

Every FLINT primitive is structured, queryable and signed, so an agent asks
"which Changes touched `auth.Login`?" instead of reading diffs. M103 delivers
the foundation: a guest Go CLI, `FLINT.ELF`, that does the following.

- Parses Zig and Go files into **Atoms** (top-level declarations).
- Stages add/modify/delete **Ops** by diffing the working tree against the
  last-known Atom table.
- Commits staged Ops as an Ed25519-signed **Change**, appended to a
  **Stream**.
- Forks Streams and merges them with a semantic three-way merge **on Ops**,
  not on text or ASTs.

## Grounding (observed in tree `8780f3c7`, 2026-10-13)

The first draft of this ADR assumed several things the guest does not have.
Each line below records what was checked, with **observed** and **inferred**
kept apart. Build-only probes used the pinned `../go-virelai` fork
(`GOOS=virelai GOARCH=arm64 -ldflags "-s -w"`). None of them was booted.

- **SQLite does not build for the guest (observed).** `modernc.org/sqlite`
  v1.34.5 fails because `modernc.org/libc` has no virelai files ("build
  constraints exclude all Go files in …/libc/errno"). It is also a libc
  emulation, which `AGENTS.md` rules out. `github.com/ncruces/go-sqlite3`
  v0.21.3 fails inside wazero v1.8.2 (`undefined: syscall.ENOTSOCK`,
  duplicate `syscall.EISDIR`). Owner ruling (2026-10-13): **use flat files
  with an in-memory index for M103, and add no SQL and no new dependency**
  (§Store).
- **`zig ast` does not exist (observed).** Zig 0.17.0's subcommands include
  `ast-check` and `fmt`, but nothing dumps a JSON AST. The guest has no Zig
  toolchain anyway. FLINT therefore carries its own **Go-native Zig
  declaration scanner**. Its reference is a host-only Zig program built on
  `std.zig.Ast` (§3).
- **`go/parser` compiles for the guest (observed, build-only).**
  `go/parser` + `go/ast` + `go/token` produce a 1,835,168 B ELF, against
  1,245,344 B for a bare `vi` program. No guest program in tree runs
  `go/parser` today (`gsport/guard` is host tooling), so the first
  in-guest run is M103a's gate. That makes it the arc's biggest unknown,
  and it is why M103a goes first.
- **ELF size is not the 2 MiB `exec_program_max` (observed).**
  `kernel/src/exec.zig:16-19` streams gap-layout Go ELFs; the bounds are
  `exec_image_max` = 32 MiB (file) and `elf.map_max` = 64 MiB (mapped).
  A probe importing `go/parser`, `encoding/json`, `sshlib` Ed25519/SHA-256
  and `shlib.StoreGet` built to 3,080,352 B. `build-flint.sh` sets an
  explicit **8 MiB** budget and says why, rather than copying the 2 MiB
  ceiling other build scripts carry.
- **Crypto is already in tree (observed).** `sshlib.EdSign`,
  `sshlib.EdVerify` and `sshlib.EdDerivePublic` (`user/go/sshlib/ed25519.go`,
  pinned to RFC 8032 §7.1) and `sshlib.SHA256Sum` add ~0 B to the probe ELF.
  FLINT uses them, not `crypto/*`. (Stdlib `crypto/ed25519` did build in the
  probe, despite the old comment in `sshlib/ed25519.go`, but nothing ran it
  in-guest.)
- **Secrets need no `vi` change (observed).** `shlib.StoreGet(name, out)`
  (`user/go/shlib/netauth.go:51`) reads an app-bound row over slot 70.
  `vi.SecretValMax` = 64 bytes holds a 32-byte seed as 64 hex characters
  exactly. The `go-agentd` spec shows the binding: `SECRETS.TXT` row
  `name\t1000\tvalue\tIMAGE.ELF` plus `OWNERS.TXT` `IMAGE.ELF\t644\t0\t-`.
- **There is no `/home` (observed).** Every guest path is under `/host`
  (no `"/home` in `user/go`). Directories are created with
  `vi.FileOpen(path, ModeWrite|ModeCreate|ModeDir)`, treating -9 EEXIST as
  success (`gotabwm/snapshot.go:128`). `vi.WriteFileSafe` is temp + fsync +
  rename, `vi.FileSync` is slot 77, and `vi.FileAppend` exists.
- **Wall time has one-second resolution (observed).** `vi.Now()` returns
  Unix seconds, or -ENOSYS when EFI supplied no epoch (`vi/vi.go:304-307`).
  `vi.Nanos()` is monotonic, not calendar time. `vi.Random` is slot 72.
- **Gates boot one VM at a time (observed).** `tools/gate/vgate.sh` has no
  multi-VM mode. The armed share lives for the whole gate
  (`tools/lib/gate-run.sh`: created at `gate_begin`, deleted at `gate_end`),
  so consecutive `vgate_run` boots share `/host`. A run can switch to an
  alternate share with its own `--cvc-file` (the `go-agentd` runs 07/08
  pattern).
- **One exec per boot; argv is bounded (observed).** `exec` returns
  immediately (`tools/gate/SPEC.md`, "exec ordering"), so a script cannot
  sequence two programs. Exec argv is 8×256 bytes (M71m). GOSH waits for
  foreground children and has `source FILE`, so each journey is a GOSH
  script: `exec GOSH.ELF -c "source /host/FLINTJ/NN.SH"`.
- **Fixtures follow the per-package `testdata/` convention (observed).**
  34 `user/go/*/testdata` directories exist. `test/fixtures/` holds only
  `gpu3d`.
- **Number collisions (observed).** ADR 0045 is RFB authenticated
  transport, so this ADR is 0049. "M0" is milestone 0 (the boot pipeline)
  in `docs/status.md`, so FLINT M0 is M103.

## Primitives

```
Atom {
    id:        UUIDv7          // assigned when first seen; never changes
    kind:      fn | method | test | struct | enum | union | interface
               | type | type_alias | const | var            (§3 per language)
    name:      string          // qualified: "pkg.Fn", "pkg.Recv.Method", "pkg.test:label"
    hash:      SHA-256         // canonical declaration, body INCLUDED, name EXCLUDED (§3)
    sig_hash:  SHA-256         // canonical signature,  body EXCLUDED, name EXCLUDED (§3)
    span:      {file, start, end}  // file is relative to the workspace src root; byte offsets
    metadata:  map[string]string   // "visibility": "pub", "receiver": "T", ...
}

Op {
    type:          add | modify | delete | move | rename
    atom_id:       UUIDv7
    kind?:         add only
    new_name?:     add, rename
    new_span?:     add, move
    new_hash?:     add, modify
    new_sig_hash?: add, modify
    old_hash?:     modify, delete, move, rename (the pre-state)
}

Change {
    id:       UUIDv7
    parent:   ChangeID | null  // null only for a stream's root Change
    stream:   StreamID
    ts:       UnixMs           // vi.Now()*1000; one-second resolution in M103
    author:   [32]byte         // Ed25519 public key derived from the agent-sign seed
    message:  string           // ≤ 512 bytes, valid UTF-8
    ops:      Op[]             // sorted by (atom_id, type code)
    merged:   ChangeID | null  // set on a merge Change: the other head folded in
    sig:      [64]byte         // Ed25519 over sig_msg (§Canonical bytes)
}

Stream {
    id:          UUIDv7
    name:        string        // unique across the store
    head:        ChangeID | null
    created:     UnixMs
    forked_from: {stream, change} | null
}

Workspace {                    // /host/FLINT/ws/<name>/
    name, src (absolute /host dir), stream (StreamID), created
    atoms:   the working Atom table (last-known state of src)
    stage:   Op[] staged but not committed
}
```

**Rules on Ops.** Within one Change an Atom has at most one Op of each type.
`add` and `delete` never share a Change with any other Op on the same Atom.
A **refactor** is `rename` + `modify` on one Atom in one Change. That is
legal and clean. M103 has no `policy_ref` and no `Policy` (FLINT M1).

**Ops M103 produces.** Diffing the working tree produces only
`add`/`modify`/`delete`. `rename` and `move` (a move means the Atom's
*file* changed) are part of the data model, the canonical bytes and the
merge algorithm, and the merge fixtures exercise them. The verbs that
produce them, `flint rename` and `flint mv`, are FLINT M1. Until then, a
renamed or moved declaration shows up as `delete` + `add`. A byte-offset
shift inside the same file is not an Op: the working table updates the
span silently.

## Store (owner ruling: flat files + an in-memory index)

```
/host/FLINT/
  streams/<stream-uuid>.json    Stream record; rewritten with vi.WriteFileSafe on every head move
  streams/<stream-uuid>.jsonl   Change log: one Change per line, append + FileSync, never rewritten
  ws/<name>/WORKSPACE.json      {name, src, stream, created}
  ws/<name>/ATOMS.jsonl         the working Atom table; rewritten with WriteFileSafe
  ws/<name>/STAGE.jsonl         staged Ops; rewritten with WriteFileSafe; removed by commit
  ws/<name>/MERGE.json          the last conflicted merge (M103d)
```

- **Index.** Every invocation scans `streams/` and its own workspace into
  Go maps: Changes by id, Streams by id and by name, Atoms by id and by
  `(file, kind, name)`. There is no query engine; FLINT M1 builds one on these
  files if it is needed.
- **Bounds, refused by name.** Each file read is capped at 4 MiB
  (`vi.ReadFileAll` max; 4096 Atoms at ~300 B per JSON line need ~1.2 MiB).
  The store holds at most 4096 Atoms per workspace and 4096 Changes. Past
  a bound, FLINT refuses with `store_too_large`, naming the bound.
- **Commit order.** (1) Append the Change line, then `FileSync`.
  (2) Rewrite the Stream record. (3) Remove `STAGE.jsonl`. On load, the log
  is the truth. If the log's last Change has `parent == record.head`, the
  record is stale, so roll the head forward. A final line with no trailing
  `\n` is a torn append: refuse with `stream_torn` and never auto-truncate.
- **JSON is the carrier, not the signed form.** Binary fields are lowercase
  hex and ids are canonical UUID strings. Signatures and `ops_hash` cover
  the binary preimage below, which is recomputed from the parsed fields, so
  key order and whitespace never matter.
- **Single writer.** M103 assumes one `flint` process per workspace and
  sequential writers per Stream. Before appending, commit re-reads the
  Stream record and refuses `stale_head` if the head moved under it.
  Advisory leases (M81d `vi` lease) are FLINT M1.

## Canonical bytes

```
str(s)    = u32le(len(s)) || s
opt(x)    = 0x00                      (absent)
          | 0x01 || x                 (present)
span(s)   = str(file) || u32le(start) || u32le(end)

op_bytes  = u8(type)                  // add=1 modify=2 delete=3 move=4 rename=5
            || atom_id[16]
            || opt(str(kind)) || opt(str(new_name)) || opt(span(new_span))
            || opt(new_hash[32]) || opt(new_sig_hash[32]) || opt(old_hash[32])

ops_hash  = SHA-256("FLINT-OPS/1\x00" || u32le(n) || op_bytes(op_1) || … || op_bytes(op_n))
            // ops sorted by (atom_id bytes, type code)

sig_msg   = "FLINT-CHANGE/1\x00" || id[16] || opt(parent[16]) || stream[16]
            || u64le(ts) || author[32] || str(message) || opt(merged[16]) || ops_hash[32]

sig       = sshlib.EdSign(sig_msg, seed)
```

- **Key.** Secret `agent-sign`, 64 lowercase hex characters (a 32-byte
  seed), app-bound to `FLINT.ELF` through `OWNERS.TXT`. FLINT reads it with
  `shlib.StoreGet` and wipes it after use. `author` =
  `sshlib.EdDerivePublic(seed)`.
- **Verify (M103 scope).** `flint verify` recomputes `ops_hash` and
  `sig_msg` from the stored fields and runs `sshlib.EdVerify` against the
  Change's own `author`. It proves **integrity and which key signed**, not
  that the key is trusted. Trust roots and policy are FLINT M1+.
  `verify --file=<log>` checks every line of a given log without loading
  the store; that is how the pinned vectors are checked in-guest.
- **UUIDv7** follows RFC 9562: a 48-bit ms timestamp (`vi.Now()*1000`),
  version 7, a 12-bit `rand_a` monotonic counter (§6.2 method 1, so ids
  minted within one second still sort), variant `10`, and 62 bits from
  `vi.Random`. With no epoch, FLINT refuses `clock_unset`.

## Hard decisions

### 1. Stable Atom IDs: UUIDv7 at creation, explicit move/rename

- An Atom's `id` is minted the first time `flint add` sees it and never
  changes.
- Re-adding a file matches its declarations to existing Atoms by
  `(file, kind, name)`:
  - a match whose `hash` differs → `modify`;
  - a match whose `hash` is unchanged → nothing (the span refreshes);
  - an existing Atom with no match → `delete`;
  - a new declaration → `add` with a fresh id.
- **Staging folds.** A new Op on an Atom that already has a staged Op
  composes with it under §2 step 2's fold rules (add + modify → add with
  the new hash; add + delete → nothing staged). So the stage is always one
  net Op per Atom (or a rename + modify pair, once FLINT M1 can produce
  renames).
- **Why not content hashes?** Identity would change on every body edit.
- **Why not names?** Names change, collide, and are only unique per
  package.
- **Trade-off.** Renames are not detected heuristically. Intent is captured
  explicitly (FLINT M1 verbs). Until then, a rename is a delete plus an add,
  which is honest but noisy.

### 2. Semantic merge on Ops

`flint merge <from>` folds Stream `<from>` into the workspace's Stream
(`into`).

1. **Common ancestor.** `anc(X)` is X plus everything reachable through
   `parent` and `merged` links. If `from.head ∈ anc(into.head)`, print
   `merge: up to date` and stop. Otherwise the ancestor `A` is the first
   Change on `from.head`'s parent chain that is in `anc(into.head)`.
2. **Net effect per side.** Fold each side's Ops from `A` (exclusive) to
   its head into one Effect per Atom, `{added, deleted, hash, name, span}`:
   - add then modify → add with the newest hash;
   - add then delete → no effect;
   - modify then modify → modify(first old_hash → last new_hash);
   - repeated renames or moves → keep the last value;
   - anything then delete → delete.
3. **Pairwise rules** (one result per Atom):

   | into \ from | — | add | delete | modify | rename | move |
   |---|---|---|---|---|---|---|
   | — | — | clean | clean | clean | clean | clean |
   | add | clean | equal hash → clean, else `concurrent_add` (keyed by `(kind, name)`; the ids differ) | n/a | n/a | n/a | n/a |
   | delete | clean | n/a | clean | `delete_vs_modify` | `delete_vs_rename` | `delete_vs_move` |
   | modify | clean | n/a | `delete_vs_modify` | equal new hash → clean, else `concurrent_modify` | `modify_vs_rename` | `modify_vs_move` |
   | rename | clean | n/a | `delete_vs_rename` | `modify_vs_rename` | equal → clean, else `concurrent_rename` | `move_vs_rename` |
   | move | clean | n/a | `delete_vs_move` | `modify_vs_move` | `move_vs_rename` | equal → clean, else `concurrent_move` |

   - A side whose Effect has several fields (a refactor: rename + modify),
     facing an untouched side, merges **clean**.
   - Cross names are the two field names sorted (`delete < modify < move <
     rename`), so `merge a←b` and `merge b←a` report the same type.
   - When several rules apply to one Atom, priority is: `delete_*` first,
     then `concurrent_*`, then cross-field (first in sorted order).
4. **Clean result.** FLINT signs and appends a Change on `into` with
   `parent = into.head`, `merged = from.head`, and as `ops` the `from`-side
   Effects re-expressed as Ops. Effects already equal on both sides are
   dropped. FLINT always writes a merge Change and never fast-forwards: a
   Stream's log only holds Changes signed for that Stream.
5. **Conflict result.** FLINT writes `MERGE.json`
   (`{into, from, ancestor, conflicts:[{atom_id, name, type}]}`), prints one
   `merge: conflict atom=<name> type=<type>` line per conflict, and exits 2.
   It appends nothing and moves no head.

FLINT never runs a three-way AST diff. Conflict resolution is out of scope:
an agent resolves by committing on one side and merging again.

**FLINT stores structure, not text.** A Change carries hashes, not source.
So `merge` updates history and the workspace's Atom table, but **it cannot
rewrite source files**. It prints `merge: src not materialized files=<n>`
and marks the merged Atoms `origin: merge` in `ATOMS.jsonl`. If a later
`flint add` finds such an Atom missing or different on disk, it refuses
`src_behind <file>` rather than staging a silent revert. The mark clears
once disk matches. A content store (blobs keyed by hash), checkout and
materialization are **FLINT M1**.

### 3. Parsing: what becomes an Atom, and the canonical forms

| | Go (`go/parser` + `go/ast`, `parser.SkipObjectResolution`) | Zig (FLINT's Go-native scanner) |
|---|---|---|
| Qualified prefix | the `package` clause | the file stem (`alloc.zig` → `alloc.`) |
| `fn` | top-level `func` | top-level `fn` (with `pub`/`export`/`extern`/`inline` qualifiers) |
| `method` | `func (r T) M` → `pkg.T.M` (pointer stripped; `receiver` metadata) | — (container members are part of the container's hash in M103) |
| `test` | top-level `func TestXxx(*testing.T)` → `pkg.test:TestXxx` | `test "label" {}` → `stem.test:label` |
| `struct` / `enum` / `union` | `type T struct{…}` → struct | `const T = struct/enum/union {…}` (any layout prefix: `extern`, `packed`) |
| `interface` | `type T interface{…}` | — |
| `type` / `type_alias` | `type T U` / `type T = U` | — (a type alias and a value `const` look identical without semantic analysis, so both are `const`) |
| `const` / `var` | each name in a `const`/`var` spec | other top-level `const`; top-level `var` |
| **Ignored** | imports, comments, `init`, `_` names | `@import` consts, anonymous `test {}`, `comptime {}`, `usingnamespace`, comments, doc comments |

**Canonical token stream.** Take the declaration's byte range (Go: the
`FuncDecl`, or the `TypeSpec`/`ValueSpec` without its group parentheses;
Zig: from the first qualifier to the terminating `;` or closing `}` at
depth 0). Tokenize it (Go: `go/scanner`; Zig: FLINT's tokenizer). Drop
comments, join tokens with a single space, and replace the declared
identifier with `_`. For a multi-name Go spec, only *this* Atom's name
becomes `_`. An implicit iota repeat appends ` iota=<index>`.

- `hash` = SHA-256(`"FLINT-ATOM/1\x00"` || kind || `"\x00"` || all tokens)
- `sig_hash` = SHA-256(`"FLINT-SIG/1\x00"` || kind || `"\x00"` || signature
  tokens). The signature is:
  - fn/method/test: everything before the body `{`;
  - struct/enum/union/interface/type/type_alias: the whole declaration;
  - const: type + value;
  - var: qualifiers + type.

Consequences, each pinned by a corpus fixture:

- Whitespace-only and comment-only edits change neither hash.
- A rename alone changes neither hash.
- A body edit changes `hash` only: it is a `modify` whose `sig_hash` is
  unchanged.
- A parameter edit changes both. A breaking API change is a `modify` whose
  `sig_hash` moved.
- **Field order is significant.** The draft said struct fields hash
  order-insensitively. That is wrong for both languages: field order is
  memory layout and ABI.

**Zig scanner scope.** The scanner handles:

- line, doc (`///`) and top-level doc (`//!`) comments;
- `"…"` strings with escapes, `\\` multiline strings and `'…'` chars;
- `@"…"` identifiers;
- `()[]{}` nesting.

Anything it cannot place it refuses as `parse_unsupported <file>:<offset>`
and never guesses. For example, a `fn` whose return type contains an
anonymous container `{`. Its reference is `tools/flint/zigdecls.zig`, a
host-only Zig 0.17 program over `std.zig.Ast`. It lists every top-level
declaration as `kind\tname\tstart\tend`, and the class-A suite requires the
Go scanner to agree with it on every `.zig` file in the corpus.

## Non-goals (M103)

| Non-goal | Where it goes |
|---|---|
| SQL, any query engine, any new dependency | FLINT M1 query layer over the flat files, only if needed |
| Content store, checkout, materializing merged source | FLINT M1 |
| `flint rename` / `flint mv`; heuristic rename detection (never) | FLINT M1 verbs |
| Push/pull over the agent channel (ADR 0044) | FLINT M1 |
| Policy (WASM), `policy_ref`, trust roots for `author` | FLINT M1 |
| `FLINTD.ELF` daemon under INIT; GOSELF test runs per commit; RFB review | FLINT M1+ |
| Concurrent writers, leases | FLINT M1 |
| Nested Atoms (Zig container members), cross-file references, dep graph | FLINT M2 |
| Git import/export, web UI, LFS, partial clone, multi-repo | not planned |
| Conflict-resolution UI, auto-resolve, rebase, cherry-pick, octopus merge | not planned |
| Key rotation, amend, history rewriting | Streams are immutable; amend = a new Change |
| Any kernel, runner, boot, `user/src` or boot-default change | — |

## Cards (M103)

The cards form a chain: each card's `Touches` overlap the next card's
(`main.go`, the spec, the build script), so **claim them in order**.

| Card | Issue | Delivers | Depends on |
|---|---|---|---|
| **M103a** | #2253 | Parser package (Go + Zig scanner), canonical hashing, host Zig oracle, a 100-file corpus with an exact MANIFEST, a `FLINT.ELF` skeleton with `parse-corpus`, `build-flint.sh`, and spec run 01: `go/parser` runs **in-guest** | — |
| **M103b** | #2251 | Store and in-memory index, UUIDv7, `init` / `add` / `status`, the working-tree diff → staged Ops; spec run 02 | M103a |
| **M103c** | #2252 | Canonical bytes, `commit` / `log` / `verify`, `agent-sign`, pinned signed vectors; spec runs 03–04 | M103b |
| **M103d** | #2254 | `fork`, `init --stream` (attach + replay), net-effect merge, `MERGE.json`, the `src_behind` guard; spec runs 05–10 | M103c |

## Gate: `go-flint` (class B, grown one card at a time)

The spec stages `FLINT.ELF`, `GOSH.ELF`, the corpus (`/host/FLINTC`, read
only) and a working copy of it (`/host/FLINTW`), the journey scripts
(`/host/FLINTJ/NN.SH`), the pinned signature vectors (`/host/FLINTV`),
`SECRETS.TXT` (`agent-sign`, a pinned test seed) and `OWNERS.TXT`.

- Each run is one boot.
- Runs 01–03 share the primary share, so each builds on the last.
- Run 04 and each merge journey get their own alternate share
  (`--cvc-file $RUN_DIR/<x>-share`, staged by the setup hook). Run 02
  already created stream `main` on the primary share, and a journey must
  start from an empty store.
- Because the journeys are stateful, the spec is not
  `vgate_repeat`-safe and says so in its header.

| Run | Card | Share | Boot does | Key asserts |
|---|---|---|---|---|
| 01 | a | primary | `FLINT.ELF parse-corpus /host/FLINTC` | `flint: parse files=100 atoms=<M> parse_errors=0`; `share-equals FLINTC.OUT` (byte-equal to the host's rendering of `MANIFEST.json`) |
| 02 | b | primary | in `/host/FLINTW`: init → add → add again → body edit + decl removal + whitespace-only edit → add → status | second add `new=0 modified=0 deleted=0`; edit pass exactly `modified=1 deleted=1`; `status atoms=<M-1> staged=<M-1> duplicates=0` |
| 03 | c | primary | commit → log → `verify --all` → `verify --file` on the pinned good and bad vectors | `commit ok … ops=<M-1>`; `sig: verified` ×2; `sig_invalid` ×1 |
| 04 | c | `nosign` | init → add → commit, with no `agent-sign` row | `refuse secret_not_found`; python: no `streams/*.jsonl`, `STAGE.jsonl` intact |
| 05–07 | d | `clean` | **A:** base commit + fork. **B:** `init --stream=feature`, edit fn X, commit. **A:** edit disjoint fn Y, commit, `merge feature`, merge again | `merge: ok conflicts=0`; then `merge: up to date`; the last Change on main has `merged` = feature head |
| 08–10 | d | `conflict` | same three boots; both sides edit fn X differently | `merge: conflict atom=<X> type=concurrent_modify` (exit 2); python: main head unchanged, `MERGE.json` holds one conflict |

"Two VMs" in the draft means **separate boots sharing one `/host`**. That
is honest for M103, because two machines only meet through the shared
store until push/pull lands in FLINT M1.

## Touches (union across the four cards)

```
user/go/flint/**                 (package main + parser/ subpackage + testdata/)
tools/flint/zigdecls.zig         (host-only oracle)
tools/go/build-flint.sh
tools/gate/specs/go-flint.spec
docs/testing.md                  (one go-flint entry, M103a; rows extended later)
docs/status.md                   (the M103 row)
```

## Changes from the first draft

- ADR 0045 → 0049; M0 → M103. Issues retitled; the stale `claim` labels
  were removed.
- SQLite → flat files + in-memory index (owner ruling). CBOR → JSONL.
- `/home/.flint/` → `/host/FLINT/ws/`.
- `zig ast` → a Go-native scanner with a `std.zig.Ast` oracle.
- `FLINTD.ELF` daemon → `FLINT.ELF` CLI (the daemon is FLINT M1).
- Hash split into `hash` (body included) and `sig_hash` (signature only).
  The draft hashed signatures only, yet also said a body change yields a
  `modify` Op, which cannot both be true.
- The card's `SHA256(kind|name|sig)` included the name and contradicted the
  rename-tolerance fixture; names are now excluded.
- Field order is now significant.
- `add` Ops carry `kind`, `new_name`, `new_span`, `new_hash` and
  `new_sig_hash`. The draft compared `op.hash` on adds, a field adds did
  not have.
- `concurrent_add` is keyed by `(kind, name)`, because random ids never
  collide.
- Merge folds whole histories into net Effects. The draft merged exactly
  two Changes and put both sides' Ops into the result, which would replay
  `into`'s own Ops.
- The draft's "one Op per Atom per Change" contradicted its own refactor
  rule; the Op rules above now allow a refactor.
- A merge Change records `merged`, so a re-merge reports up to date.
- Conflict names are symmetric (sorted pairs).
- The `old_hash`-chaining clauses in `(modify, modify)` were dropped: they
  cannot fire when both sides fold from the same ancestor.
- Corpus counts reconciled: one corpus, and its `MANIFEST.json` is the
  authority instead of the inconsistent 6/10/2-atoms-per-file figures.
- Signature preimage defined byte-exactly, with domain separation.
- Fixtures moved from `test/fixtures/flint/` to `user/go/flint/testdata/`.
- `user/go/vi/trust.go` dropped from Touches: `shlib.StoreGet` already
  exists.

## Future arcs

- **FLINT M1:** content store + checkout; `rename`/`mv` verbs;
  push/pull over ADR 0044; WASM policy and trust roots; `FLINTD.ELF` under
  INIT; leases; a query layer if the flat files are too slow.
- **FLINT M2:** nested Atoms, dep graph, lazy materialization,
  chunked storage.
- **FLINT M3:** federated identity, signed policy distribution.
