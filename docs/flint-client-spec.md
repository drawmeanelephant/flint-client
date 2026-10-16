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
  model, and refusal names are the ADR 0049 contract — byte-for-byte.**
  The ADR does not pin CLI output lines: **the Go implementation is
  normative for output formats** — its `consoleFn("flint: …")` calls and
  `flint_test.go` are the reference, matched exactly. A store produced
  by this client must be loadable by the Go implementation and vice
  versa. Anything not listed under "Deltas" (§2) is identical to the ADR.
- No GPL-family code anywhere (VirelaiOS rule; carries over).
- Non-goals are the ADR's M103 non-goals: no content store or
  materialization, no `rename`/`mv` verbs, no push/pull, no concurrent
  writers, no Git interop, no GUI. Same milestone scope, new platform.

## 1. CLI surface (M103 verb parity)

Verbs, output lines (`flint: `-prefixed), refusal names, and exit codes
match the Go implementation exactly — the lines below are observed from
`user/go/flint/`, not inferred:

| Verb | Notes |
|---|---|
| `init --name=<n> --src=<dir> [--stream=<s>]` | Workspace names `[a-z0-9-]{1,32}` (`usage`); `--src` must exist (`src_missing`). Fresh: `flint: init ok ws=<n> stream=main` (refuses `stream_exists` when `main` exists). Attach `--stream=<s>`: replays the stream head into ATOMS (ADR M103d semantics), prints `flint: init ok ws=<n> stream=<s> atoms=<n> replayed=<m>`. Also `ws_exists`, `stream_missing`. |
| `add [--ws=<n>] [file ...]` | `flint: add files=<n> new=<n> modified=<n> deleted=<n> unchanged=<n>`. No paths = scan the whole src root. Every `add` also rewrites `ws/<ws>/BASE.json` (`{"head":"<id>"}` or `{"head":null}`) with the stream head the stage is asserted against — the staging base `commit` checks (`stage_stale`). Re-running `add` is therefore the explicit restage after the head moves. |
| `status [--ws=<n>]` | `flint: status ws=<n> stream=<s> atoms=<n> staged=<n> add=<a> modify=<m> delete=<d> duplicates=<n>`, then up to 64 `flint: stage <type> <qualified-name>` lines, plus `flint: stage … +<n>` when the stage exceeds 64. |
| `commit [-m=<msg> \| --message=<msg>] [--ws=<n>]` | Message 1–512 bytes valid UTF-8 → `message_invalid`; empty stage → `nothing_to_commit`; `secret_not_found` preserved. Refuses `stage_stale` when `ws/<ws>/BASE.json` is absent (unknown staging base — e.g. a stage written before the record existed) or records a head different from the stream's current head (a `pull`, `pull --reset`, or a sibling workspace's commit moved it): committing would silently reparent the old staged intent over peer edits. The refusal preserves STAGE/ATOMS/history; re-run `add` to restage explicitly — there is no bypass flag. On success the commit removes `STAGE.jsonl` and `BASE.json`. Every successful commit also captures the complete source inventory — content-addressed blobs under `blobs/` plus a signed manifest line on `manifests/<stream-id>.jsonl` (docs/flint-blobs-spec.md §3) — so a src change that produces no Ops still commits (`ops=0`), while an empty stage with an unchanged inventory keeps `nothing_to_commit`. A merge resolution or clean merge whose merged content is not materialized in src lands the Change without a manifest rather than advertising a substituted tree. Prints `flint: commit ok id=<uuid> ops=<n> parent=<id\|none>`. When a conflicted merge is in progress (`ws/<ws>/MERGE.json` present), the commit resolves it: the Change records `merged=<report.from>` and MERGE.json is removed after the commit lands; the commit additionally prints `flint: merge completed merged=<id>`. |
| `log [--stream=<s>] [--ws=<n>]` | `flint: change <id> parent=<id\|none> ops=<n> author=<8-hex> msg=<first line>`, newest first, capped at 64. |
| `verify <id> \| --all \| --file=<log>` | Per change: `flint: verify <id> sig: verified` or `flint: verify <id> sig_invalid`; exit 1 when any line is invalid. Bare `<id>` verifies one change (`change_missing`); `--file` checks a standalone log. |
| `fork <from> <to>` | Fork a stream at its head; `flint: fork ok stream=<to> head=<id>`. Refuses `stream_missing`, `stream_exists`, `fork_empty`. |
| `merge <from> [--ws=<n>]` | Net-effect 3-way merge on Ops. The resulting workspace `ATOMS.jsonl` is rebuilt by replaying the merged head's history plus the merge Ops — it always describes the merged stream head, even when `pull --reset` previously moved the head past the workspace table. Merged atoms whose content the pre-merge workspace table did not describe are marked `origin=merge` — that content was never materialized into src, so `add` refuses `src_behind` until src actually carries it. `flint: merge up to date`; on success `flint: merge ok conflicts=0 ops=<n> id=<id>` followed by `flint: merge src not materialized files=<n>`; conflicts print one `flint: merge conflict atom=<name> type=<t>` per conflict plus `flint: merge conflicts=<n>` (exit 2). Refuses `stage_dirty` when the workspace stage is non-empty. On conflict the client writes `ws/<ws>/MERGE.json`; resolve the conflicts in src, `add`, then `commit` — the commit consumes the marker and records the merged-in head, after which re-running the merge reports up to date. |
| `parse-corpus <dir>` | Dev/conformance verb: parse every `.go`/`.zig` file, write `<dir>.OUT` = `parser.Render(atoms)` via the crash-safe write (**contractual — the corpus gate compares it byte-for-byte**), print `flint: parse files=<n> atoms=<m> parse_errors=<e>`. Keep — it is how the corpus gate runs. |
| `keygen [--name=<n>]` | **New, host-only.** Generate a 32-byte seed, store it, print the derived public key hex. See §2.3. |
| `clone <remote> --stream=<name\|id> [--name=<ws>] --src=<dir> [--auth-key=<file>] [--read-timeout=<sec>]` | **M106e remote verb.** Initialize store, follow `forked_from` chains (`open` + `read`), re-verify every Change (`sig_invalid` aborts before writing), replay atoms into `ws/<name>/ATOMS.jsonl`, write `WORKSPACE.json` and `REMOTE.json`. `--src` is created when absent (unlike `init`, which registers an existing source tree and keeps `src_missing`). **Clone gives you history, not files:** atoms land in `ATOMS.jsonl`, but no source files are materialized — the src dir stays empty, so a first `flint status` shows a clean workspace with nothing on disk; `verify`/`log`/`merge`/`push`/`pull` work regardless. Prints `flint: clone ok stream=<name> changes=<n>`. Never silently overwrites a stream that already exists locally: re-clone is allowed only as a fast-forward — the remote log filtered to local Change ids must equal the local log line-for-line (**id order**, not byte position, since a remote log may carry detached lines, §2.7), then remote lines the local log lacks append in remote order; the log is never rewritten. Refuses `fork_needed` when local and remote history diverge, `stream_exists` when local is strictly ahead or the record conflicts. On peers announcing `spec_rev >= 4` clone also fetches content (docs/flint-blobs-spec.md §9): `get_manifest` the whole remote manifest log per cloned stream, append missing lines verbatim after re-verification (stream binding, `change` resolves in the fetched log — an unbound line stays unfetched — `author` equals the Change's author and `sig` verifies; `sig_invalid` aborts before writing), then `blob_get` each referenced id absent from `blobs/` (SHA-256 checked before storing). Pre-content peers degrade to history-only at exit 0 with a `proto_version` stderr note, and `checkout` later refuses `blob_missing` explicitly. |
| `push [--remote=<url>] [--stream=<s>] [--ws=<n>] [--auth-key=<file>] [--read-timeout=<sec>]` | **M106e remote verb.** `create` any streams in the `forked_from` ancestry missing on the server, then `append` the client's unsent **first-parent** suffix — `pull --reset` can leave unreachable sibling lines in the local log that `append` never sends. Then publish incorporated work (§2.7): for each Change in the stream's log whose `merged` link names a locally-held Change unreachable from the head, `deposit` that Change's detached ancestry onto the same stream so the signed link resolves remotely — retried on every push, including heads-equal pushes. When `create` refuses `change_missing` on an absent `forked_from.change`, `deposit` the origin's detached ancestry onto the origin stream and retry `create` with the original `forked_from` — no re-anchor; a fork carrying its own Changes publishes fully this way (record, then the ordinary `append` suffix). A server that predates `deposit` refuses `usage`; push then falls back to the spec_rev 2 path — a bare fork pointer re-anchors, locally and in the retried `create`, to the merge Change on the origin stream's first-parent chain that incorporated it (`merged == forked_from.change`), and a fork with its own Changes still refuses `change_missing`. Other `deposit` refusals surface normally; deposits are idempotent, so an interrupted push reconciles on the next run. On peers announcing `spec_rev >= 4` push then publishes content (docs/flint-blobs-spec.md §9): per stream in the pushed chain, `blob_get` probes every blob the manifest set references and `blob_put` uploads each miss (`blob_missing` is the miss signal; idempotent, content-addressed), then `put_manifest` sends the local lines the remote log lacks in bounded ≤256-line batches — a `change_missing` batch refusal falls back to per-line so a manifest bound to unpublished detached work skips without starving the rest. Blobs land before manifests, so a served manifest always resolves; the reconcile runs on every push including heads-equal, healing a transfer cut anywhere between Change acceptance and manifest publication. Pre-content peers degrade identically to clone/pull. Prints `flint: push ok stream=<s> changes=<n>` (head-chain count only) or `flint: push up to date`. |
| `pull [--remote=<url>] [--stream=<s>] [--ws=<n>] [--auth-key=<file>] [--reset] [--read-timeout=<sec>]` | **M106e remote verb.** `open`/`read after=<head>`, re-verify every pulled Change (`sig_invalid` aborts and writes nothing), require the fetched chain to reach the remote record's advertised head (`stream_malformed head mismatch` on a signed proper prefix), refuse `store_too_large` when the resulting log would exceed the 4 MiB file bound, append raw lines, roll local stream record forward. The read runs even when the record heads already match — detached lines deposited since the last sync sit in the log suffix and still arrive (§2.7). Fetched lines dedupe by id: identical bytes skip, the same id under different bytes refuses `stream_malformed` (`id conflict`). Prints `flint: pull ok stream=<s> changes=<n>` (newly appended lines) or `flint: pull up to date`. Refuses `fork_needed` when remote head diverges from local head. With `--reset`: fetch and verify the whole remote log, append the remote Changes the local log lacks, and roll the local head to the remote head — refusing `fork_needed` unless the local head stays reachable through another stream's ancestry (i.e. `flint fork <stream> <aside>` first). Divergent local Changes remain in the log as unreachable sibling lines. Prints `flint: pull reset stream=<s> changes=<n> head=<id>`. On `spec_rev >= 4` peers pull then reconciles content (docs/flint-blobs-spec.md §9): `get_manifest` the whole remote manifest log (healing needs the full set — matching heads are not proof content finished), verify each missing line, append verbatim, and `blob_get` each referenced id absent locally. A refusal mid-pull (`blob_missing`, `blob_malformed`, `sig_invalid`) leaves the Change log correct and the next pull re-heals. Recovery journey: `fork` → `pull --reset` → `merge <aside>` → `push`. Pull never rewrites `STAGE.jsonl` or `BASE.json`: a stage prepared before the pull keeps its recorded base, so a later `commit` refuses `stage_stale` until `add` restages it. |
| `checkout [--stream=<s>] [--ws=<n>] --change=<id>\|--head --into=<dir> [--force]` | **New, host-only.** Materializes a historical revision from the local content layer (`docs/flint-blobs-spec.md`). `--change` names a Change id (the manifest binds it to its own stream); `--head` resolves the workspace's (or sole stream's) head and requires `--stream`/`--ws` when ambiguous, resolving through `forked_from` ancestry when the head Change lives on an origin stream's log (bare forks). The manifest signature, its stream/change/author binding, and every blob's SHA-256 id verify before any write; a Change with no manifest line, a null `blob` entry, or an absent blob refuses `blob_missing`, a corrupt blob refuses `blob_malformed`, a malformed or torn manifest refuses `manifest_torn`, and a signature failure refuses `sig_invalid`. `--into` must be absent or an empty directory — never the tracked src, never inside the store root — unless `--force` allows writing into a non-empty directory; any refusal names the destination `checkout_exists`. Symlinks and other non-regular entries ride the manifest as `"reason":"unsupported"` and are never followed. Prints `flint: checkout ok stream=<s> change=<id> files=<n> bytes=<n>`. Refuses `usage` on missing/conflicting selectors, `stream_missing`, `change_missing`. |
| `handoff propose\|attest\|accept\|supersede\|withdraw\|list\|inspect\|export\|import\|verify` | **New, host-only** (spec_rev 6, `docs/flint-handoffs-spec.md`). Signed `FLINT-HANDOFF/1` records append to `handoffs/<stream-id>.jsonl` under the record's `stream` field; records are immutable — lifecycle transitions are new records, and state is folded from the log, never stored. `propose --stream=<t> --work=<s> [--candidate=<id>] [--base=<id>] [--snapshot=<ref>] -m=<intent> [--scope-file=<f>] [--validations=<f>] [--key=<k>]` defaults candidate to the work-stream head and base to the target head; scope is derived from the candidate delta's Ops union unless `--scope-file` supplies `{"paths":[…],"atoms":[…]}`; snapshot defaults to the candidate's own Change id when the work log carries its manifest (it is the opaque #77-era reference until that contract lands). `attest <h> --command=<s> --result=pass\|fail\|skip [--toolchain=<s>] [--env=<s>] [--evidence=<s>] [--key=<k>]` records a self-asserted validation bound to the proposal's candidate/snapshot — commands are data, never executed. `accept <h> [--note=<s>]` binds the locally observed target head as `observed_head`; `supersede <h> [--replacement=<id>]`, `withdraw <h>` (proposer only, `handoff_author`), `list [--stream=<s>] [--state=<s>]`, `inspect <h>` (prints `state=` plus the computed `verdict=` — `ready`/`stale`/`conflicting`/`incomplete`/`invalid`/`unknown`/`accepted`/`accepted_stale`/`superseded`/`withdrawn` — re-verified against the current head, ancestry, and content), and standalone `verify <file>` (record file or `FLINT-HANDOFF-PACKET/1`; no store needed, nothing written). `export <h> --out=<f> [--with-changes]` writes the §7 packet — header plus the proposal's record lines byte-verbatim in append order, optionally the candidate's first-parent ancestry from the work log in deposit-batch order; `--out=-` streams the packet to stdout with the ok line on stderr. `import <f>` verifies the whole packet before writing anything (signatures, stream/handoff binding, lifecycle legality, detached-ancestry rules), then appends the missing Change lines to `streams/<work>.jsonl` under deposit discipline — the stream head never moves — creating the work stream record from the header when absent and ancestry permits, and appends the missing record lines to `handoffs/<target>.jsonl`; both sections dedupe by id (byte-identical lines skip, same id under different bytes refuses) so re-import is a no-op. Refusals: `handoff_malformed` (`unknown format`, `id conflict`, `attestor mismatch`, `binding`, `work mismatch`, `packet header`, `count mismatch`), `handoff_missing`, `handoff_closed`, `handoff_author`, `handoff_torn`, `sig_invalid`, `stream_missing`, `change_missing`, `change_malformed` (`id conflict`, `extends head`, `detached parent unknown`), `store_too_large`. Handoff verbs never touch workspaces, stage, or source, and never move a stream head or rewrite Change history. |
| `release --elf=<f> --name=<n> --version=<v> [--manifest-row=<r>] [--ws=<n>] [--key=<k>] [-m <msg>] [--dry-run]` | **New, host-only.** Mints a release Change for the release-stream convention: computes `sha256(<elf>)`, renders `release.go` (`ReleaseName`, `ReleaseVersion`, `ReleaseELFSHA256`, `ReleaseManifestRow` consts in `package release`), writes it to the workspace src root, then stages and commits it through the existing `add`/`commit` machinery so the normal signing path applies. `--manifest-row` supplies the apps.txt v2 row; the default is the documented `<name> <version> <sha256>` placeholder. `-m` overrides the default `release <name> <version>` message. `--dry-run` prints the rendered file and touches nothing, not even the store root. Refuses `usage` on missing/invalid fields, `src_missing` on an unreadable ELF, and `stage_dirty` when the workspace stage is non-empty (a release Change carries exactly the release.go update). Prints the `add`/`commit` lines plus `flint: release ok name=<n> version=<v> sha256=<h>`. |
| `version [--remote=<url>] [--auth-key=<file>]` | **New, host-only.** Prints `flint: version spec_rev=<n> proto=FLINT-SYNC/1` — `spec_rev` is the repo-root `SPECREV` integer (see `docs/spec-versioning.md`). With `--remote` or `FLINT_REMOTE`, performs the `hello` handshake and prints `flint: remote <url> proto=FLINT-SYNC/1 spec_rev=<n|unannounced>`. Needs no store. |

Remote resolution for `push`/`pull`/`clone`: `--remote <url>` flag →
`FLINT_REMOTE` env var → `ws/<name>/REMOTE.json` (`{"remote":"tcp://<host>:<port>","stream":"<id>"}`) →
refuse `remote_missing`. Optional shared-secret authentication (`--auth-key=<file>` or
`FLINT_AUTH_KEY`) answers `flintd`'s 16-byte `nonce` challenge with
`HMAC-SHA256(key, "FLINT-SYNC-AUTH/1\x00" || nonce_bytes)`. A `hello` success
reply may carry an optional `spec_rev` integer naming the server's spec
revision — absent on servers that predate the field, and clients must
tolerate both (`version` reports it; see `docs/spec-versioning.md`). Wire refusals from
`FLINT-SYNC/1` (`proto_version`, `auth_required`, `auth_failed`, `author_not_allowed`,
`change_too_large`, `stale_head`, `stream_exists`, `stream_missing`, `change_missing`,
`change_malformed`, `sig_invalid`, etc.) print directly as `flint: refuse <name>`.
On a remote `stream_missing` or `stream_exists` refusal the client additionally
issues `list` and annotates the refusal detail with
`(available streams: <name>, …)`. On `stale_head` the refusal detail names the
recovery (`remote head advanced; pull to catch up (diverged: fork <stream>
<aside>, pull --reset, merge <aside>, push)`). Stream records returned by `open`
and `list` must carry names in `[a-z0-9-]{1,32}`; anything else refuses
`stream_malformed` before the name is stored or printed. Each reply line is
read under a per-reply deadline: `--read-timeout=<sec>` (default 30s; `0`
refuses `usage`) ends a silent peer's hang with `flint: error <verb> <remote>:
timed out`.
Local failures inside a sync verb — dial errors, transport drops, and other
non-refusal errors — print `flint: error <verb> <remote>: <reason>` with the
resolved remote URL, so a failure surfaced through `REMOTE.json` or
`FLINT_REMOTE` still names where it dialed; `<reason>` is a lowercase phrase
(`connection refused`, `unknown host`, `connection timed out`, …), never a
raw error-name token.

Workspace selection for `add`/`status`/`commit`/`log`/`merge` follows the
Go `resolveWorkspace`: `--ws=` names it (`ws_missing`); otherwise the sole
workspace wins; with several workspaces, path args under a `src` select it,
else the single workspace holding a stage, else `ws_ambiguous`.

Exit codes: `0` success, `1` refusal/error, `2` usage error or merge
conflict. Refusals print `flint: refuse <name>` — the refusal name
vocabulary is part of the contract. The full set used for these verbs:
`usage`, `src_missing`, `ws_exists`, `ws_missing`, `ws_ambiguous`,
`stream_missing`, `stream_exists`, `stream_torn`, `stream_malformed`,
`stale_head`, `fork_empty`, `stage_dirty`, `stage_stale`, `nothing_to_commit`,
`message_invalid`, `secret_not_found`, `src_behind`, `parse_unsupported`,
`syntax`, `duplicate_decl`, `change_missing`, `change_malformed`,
`atom_malformed`, `stage_malformed`, `ws_malformed`, `store_too_large`,
`store_not_found`, `key_exists`, `manifest_torn`, `blob_missing`,
`blob_malformed`, `checkout_exists`, `clock_unset` (unreachable on a POSIX
host — keep the name), and for the sync verbs `fork_needed`,
`remote_missing`, `remote_malformed`, `secret_malformed` plus the
wire-refusal names of the FLINT-SYNC/1 spec (`proto_version`,
`auth_required`, `auth_failed`, `author_not_allowed`, …), which print
through unchanged. Use the same name the Go implementation uses for
the same condition.

## 2. Deltas from ADR 0049 (everything else is identical)

### 2.1 Store root and workspace model

- Guest: global store at `/host/FLINT`, workspaces registered under
  `ws/<name>/` with `src` a `/host` path.
- Host: store root resolves in order: `--store <dir>` flag →
  `FLINT_STORE` env var → walk up from cwd for a directory containing
  `.flint/` **or `FLINT/`** → error `store_not_found` naming where it
  looked — the shell's logical `$PWD` when it resolves to the same
  directory, so the named path is the one the user typed rather than a
  canonicalized spelling. (The guest store dir is `FLINT`, uppercase; accepting both
  names means a store copied off the guest as `./FLINT` is discovered
  without a rename.)
- The interior layout is `streams/<id>.json`, `streams/<id>.jsonl`,
  `ws/<name>/{WORKSPACE,ATOMS,STAGE,MERGE,BASE}.json*` — same names, same
  JSON fields, same bounds (4 MiB reads, 4096 Atoms, 4096 Changes) as the
  guest layout, plus `BASE.json` (`{"head":"<id>"}` or `{"head":null}`),
  the staging-base record written by `add` and checked by `commit`
  (`stage_stale`, #67, spec_rev 2), plus the content layer `blobs/<2-hex>/<62-hex>` (SHA-256 addressed whole-file payloads, crash-safe temp+rename writes, deduplicated by content id) and `manifests/<stream-id>.jsonl` (one signed complete-inventory line per manifest-writing Change). Both are optional additive directories — pre-content stores load unchanged, and a Change with no manifest line is a content-less revision, not corruption (docs/flint-blobs-spec.md §8). Likewise `handoffs/<stream-id>.jsonl` (spec_rev 6) is an optional append-only directory of `FLINT-HANDOFF/1` records, created lazily by the `handoff` verbs and never read by the every-invocation store index (docs/flint-handoffs-spec.md §2).
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
  - **Exposure, documented:** a seed literal passed via `--key` or
    `FLINT_SIGN_KEY` is visible in `/proc/<pid>/environ` (Linux), `ps e`
    output, and shell history. Key names are the preferred form; the
    literal form exists for tests and harnesses. `--help`/docs say so.
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
- Go's `encoding/json` HTML-escapes `<`, `>`, `&` (and U+2028/2029) in
  emitted strings; `std.json` does not. The port must replicate Go's
  escaping byte-for-byte or host- and guest-written files will not diff
  cleanly.
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

### 2.7 Detached Change lines and `deposit` (spec_rev 3, #73)

A stream's `.jsonl` is append-only and may contain **detached** Change
lines — valid signed Changes of that stream that do not sit on the
head's first-parent chain. `pull --reset` already produces them locally
(divergent local history stays in the log as unreachable siblings).
spec_rev 3 makes the same representation publishable: a `deposit`
request appends detached lines to a remote stream's log without moving
its head, so preserved work — the original signed Change behind a saved
recovery fork, or any work a merge's signed `merged` link names —
becomes retrievable by a fresh agent. Nothing is re-signed, no id is
rewritten, and the signed `stream` binding is preserved: a detached
Change only ever travels to the log of the stream it was signed for.

**Wire op** (one request, one reply):

```json
{"op":"deposit","seq":9,"stream":"<stream-id-or-name>","changes":["<raw line>",…]}
{"seq":9,"ok":true,"head":"<head-id-or-null>","stored":<m>}
```

- `changes` carries raw Change lines, quoted exactly as `append` does;
  1–256 per request (`change_malformed` on an empty or oversize batch).
- Server-side validation mirrors `append`: well-formed Change,
  `stream` field equals the target stream id, message bounds
  (`message_invalid`), signature verifies (`sig_invalid`), and the
  `--allow-author` gate (`author_not_allowed`). Refusals reuse the
  existing vocabulary: `stream_missing`, `change_malformed`,
  `change_too_large`, `message_invalid`, `sig_invalid`,
  `author_not_allowed`, `store_too_large` (the 4096-Change and 4 MiB
  log bounds apply to detached lines too).
- **Detached rules.** A non-duplicate Change whose `parent` equals the
  current head refuses `change_malformed` (`extends head` — that is an
  `append`, not a `deposit`). Every deposited Change's `parent` must be
  null, an id already in the target log, the stream's
  `forked_from.change`, or an id earlier in the same batch —
  `change_malformed` (`detached parent unknown`) otherwise. Deposits
  are therefore **ancestry-complete**: a stored detached Change's whole
  first-parent ancestry back to a root or to existing log content is
  present in the same log.
- **Deduplication.** An id already in the log with byte-identical
  content is skipped and does not count toward `stored`; the same id
  under different bytes refuses `change_malformed` (`id conflict`).
  Deposits are idempotent — an interrupted transfer reconciles by
  re-sending the same lines.
- **All-or-nothing, head untouched.** The whole batch validates before
  anything is written; the stream record is never rewritten — `head`
  does not move and is echoed back for confirmation. Detached lines are
  ordinary log lines for retention purposes and are returned verbatim
  by `read` — no new retrieval op is needed.

**Reader rules** — every client must tolerate a remote log that
interleaves detached lines with the head chain:

- Fetch verification classifies each line: a Change whose `parent`
  continues the first-parent chain advances the chain cursor; anything
  else is detached and must verify (`sig_invalid` unchanged) with a
  `parent` that is null or already-seen content (local ids, the
  `forked_from.change`, or an earlier fetched id) — `change_malformed`
  otherwise, so orphan preservation is detectable.
- The pull/clone head check runs on the chain cursor, not the last log
  line: the advertised record head must be reached through the
  first-parent chain (#58's rule, generalized).
- Pulled lines dedupe by id against the local log (identical bytes
  skip; different bytes under a shared id refuse `stream_malformed`,
  `id conflict`).

**Client push policy** — the wire mechanism is general, but `push`
uses it in exactly two bounded ways:

1. When `create` refuses `change_missing` on a `forked_from.change`,
   `push` deposits the origin's detached first-parent ancestry onto the
   origin stream and retries `create` with the original `forked_from`.
2. After appending the head-chain suffix — and again when heads are
   already equal — `push` deposits, for each locally-held `merged`
   target unreachable from the head, that Change's detached ancestry
   onto the same stream. A `merged` link thereby becomes resolvable
   remotely while staying a signed id, not a dereference.

A `merged` target whose bytes live on a different stream is covered by
that stream's own push (`deposit` never crosses the signed `stream`
binding). A server that predates `deposit` refuses `usage` — push then
falls back to the spec_rev 2 behavior: bare fork pointers re-anchor to
the incorporating merge, forks with their own Changes refuse
`change_missing`, and incorporated-work deposits are skipped. Old
peers reading a log with detached lines already behave correctly under
the reader rules above — the representation has always been legal in a
local store. A same-head `pull` keeps working on old servers too: the
log suffix is simply empty there.

`deposit` transfers original bytes only — a merge author's signed
`merged` assertion stays distinct from independently verified original
evidence, and `verify <id>` on a fresh clone checks the original
Change against its own author's key, unchanged.

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
- Push/pull, networking, a daemon, leases/concurrent writers. (The
  host-side sync verbs — `push`/`pull`/`clone` against `flintd` — are
  spec'd in `docs/flint-server-spec.md` §4 in the flint-server repo and
  land under VirelaiOS milestone M106, not this arc.)
- Trust roots/policy for `author`; `verify` proves integrity + which
  key signed, not that the key is trusted.
- Reading VirelaiOS guest internals (SECRETS.TXT, OWNERS.TXT, `/host`
  semantics) — stores are portable, the guest's secret mechanism is not.
