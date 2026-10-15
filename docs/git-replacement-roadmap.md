# FLINT as a Git replacement — vision and roadmap

Status: **vision document.** Nothing here is scheduled. Every arc
below becomes a spec PR for review before work starts, same
discipline as the five wave-1 arcs (blobs, ssh, workspace-sync,
history, patch bundles — all merged).

Read with `docs/adr-0049.md`, `docs/flint-client-spec.md` §1 (the
observed verb table this roadmap diffs against), and
`docs/flint-server-spec.md`.

## 0. Identity and hard rules

- Binary `flint` + `flintd`, Zig 0.17.0, standard library only. One
  static binary per platform; no runtime dependencies.
- Platforms: **macOS, Linux, VirelaiOS**. VirelaiOS provides Zig,
  wasm, and QuickJS (limited JS). Consequences:
  - no shell assumptions in shipped code or hooks — hooks are wasm
    modules or QuickJS scripts (§6.3);
  - networking is optional — where the OS has no TCP, sync falls back
    to signed patch bundles (§6.5);
  - OS-specific code sits behind `builtin.os.tag` comptime guards;
    the wasm target is a first-class build with a CI leg (§7).
- Contracts do not move to get here: canonical bytes, `sig_msg`,
  refusal names, exit codes (0/1/2), append-only logs, crash-safe
  writes, store bounds. A git replacement must not fork the format.
- The store stays byte-portable: JSONL + content-addressed blobs. A
  store written on macOS verifies identically on VirelaiOS.

## 1. The pitch

Git is a content tracker with a human CLI bolted on. FLINT is an
agent-first, declaration-native, signed-by-default VCS whose entire
surface is contractual: stable output lines, refusal names, exit
codes, JSON mode. This document maps "full Git replacement" onto
concrete arcs, and fixes the shortcomings of git *and* of its
would-be replacements (jj, pijul, fossil, sapling) — not just git's.

## 2. Where FLINT already beats git

| Git pain | FLINT answer |
|---|---|
| Textual 3-way merge; conflicts on every overlap | Semantic merge on declarations (`merge`); conflicts are the exception |
| Rename detection is heuristic; `log --follow` lies | Atom identity (UUIDv7) survives renames/moves; blame follows identity (H1–H2) |
| Force-push rewrites shared history | Append-only logs; pushed Changes are immutable; `revert`/`supersede` instead (G2) |
| Detached HEAD; index/staging confusion | Workspace bound to a stream; the stage is a readable file (`STAGE.jsonl`) |
| Porcelain output changes between versions | Contractual `flint: ` lines, refusal names, exit codes; `--json` on every verb (§6.1) |
| Signing is opt-in (GPG/ssh), rarely verified | Every Change is Ed25519-signed at commit; `verify` is a first-class verb |
| One transport family (ssh/http) | tcp, ssh (T1–T3), stdio, signed patch bundles (P1–P2) — airgap included |
| Unbounded, unverifiable history | Bounded logs + `verify --all` + signed stream snapshots (G5) |
| `checkout <sha> -- .` mutates the tree | `checkout --into=<dir>` materializes any era read-only, workspace untouched (B2) |
| Submodules/LFS are bolt-ons | Blobs are the content layer (B1–B5); large files are just blobs |
| `clone` needs the whole history up front | Bounded logs make full verification cheap; partial materialization is M2 (G9) |

## 3. Git parity gap analysis

"Today" is the verb table in `flint-client-spec.md` §1: `init`,
`add`, `status`, `commit`, `log`, `verify`, `fork`, `merge`,
`keygen`, `clone`, `push`, `pull` (+ dev verb `parse-corpus`).

| Git capability | Today | Arc |
|---|---|---|
| init / clone / push / pull | done | — |
| `add` at file granularity + ignore rules | atom-granular scan of src; no ignore file | G1 |
| `status` | done | — |
| `diff` (atom-level and file-level) | none | G1 |
| `commit` | done | — |
| amend / squash / fixup | none | G2 |
| revert / supersede | none | G2 |
| `log` paging (`--limit`, `--after`) | capped at 64, newest first | G1 |
| stream (branch) list / rename / delete / protect / nesting | `fork` only | G1 |
| `switch` stream into a workspace | `init --stream` attach only | G1 |
| worktrees (parallel agents, one store) | none | G1 |
| merge | done | — |
| conflict resolution flow | conflicts print as lines + `MERGE.json`; no conflict objects, no resolve verbs | G4 |
| cherry-pick / rebase (atom granularity) | none | G3 |
| log / blame | spec'd (H1–H2) | — |
| tags (signed annotated + lightweight) | none | G1 |
| stash / workspace snapshots | none | G1 local; W1–W3 cross-machine |
| bisect (change granularity) | none | G7 |
| remotes: add/rm/rename/list, multi-remote, fetch, prune | `REMOTE.json` + `--remote` only | G6 |
| hooks (portable, sandboxed) | none | G8 |
| scripting / query surface | none | G8 |
| fsck / verify / gc | `verify` done; `gc` spec'd (B4) | — |
| reflog / undo | none | G2 |
| sparse / partial materialization | none | G9 (M2) |
| stream archival (stay in bounds long-term) | none | G5 |
| config layering (global/local) | env + flags + `REMOTE.json` | G1 |
| git interop (import/export) | none | G10 |
| VirelaiOS port (wasm target, offline-first) | none | G11 |

## 4. Shortcomings of git and other SCM — and our answer

| Shortcoming (whose) | FLINT answer |
|---|---|
| Textual conflicts (git) | Semantic merge; conflicts as structured data (G4) |
| History-rewriting footguns (git) | Append-only + supersede; local rewrite only pre-push (G2) |
| Rewrite-by-default loses the audit trail (jj) | Keep the audit, gain the ergonomics: amend/squash locally, never remotely |
| Working-copy-centric model confuses (jj) | Streams are explicit; a workspace is a view, not the truth |
| Channel/patch complexity (pijul, darcs) | Streams + Changes + signatures; nothing else |
| Monolith and self-host weight (fossil) | One static binary; the server is optional; bundles for airgap |
| Hidden state: phases, evolve (hg, sapling) | No hidden state; the stage is a file agents can read |
| Rename heuristics (all of them) | Atom identity |
| Signing opt-in (all of them) | Signed by default; `verify` built in |
| Platform lock (all of them) | One Zig binary; wasm target; QuickJS hooks run identically everywhere |
| No offline/airgap story (git) | Patch bundles are a first-class transport (P1–P2) |

## 5. Wave plan

**Wave 1 — foundations (spec'd, merged).** B1–B5 blobs/checkout/gc ·
T1–T3 ssh transport · W1–W3 workspace sync · H1–H2 history/blame ·
P1–P2 patch bundles.

**Wave 2 — git parity (next up).** Makes FLINT feel like git to a
human and to a muscle-memory script:

- **G1 Porcelain pack** — `diff` (atom + file), `remote
  add/rm/rename/list`, `tag` (signed annotated + lightweight),
  `switch`, `worktree add/rm/list`, workspace snapshots
  (stash-equivalent), `.flintignore`, layered config, `log` paging.
- **G2 History-editing policy** — local amend/squash/fixup pre-push;
  signed `revert`/`supersede` post-push; operation log + bounded
  `undo`; "no force-push, ever" stated as a feature. (Precedent:
  `pull --reset` already refuses `fork_needed` unless ancestry keeps
  the local head reachable — recovery without rewriting.)
- **G3 Cherry-pick / rebase** — atom-granular apply of a Change onto
  another stream; `rebase --onto`; conflicts surface through G4.
- **G6 Multi-remote** — `remote` verbs, `fetch`, `prune`, per-remote
  auth keys.

**Wave 3 — agent-native superpowers (the "far better" half).** What
no SCM can do, because none of them were built for agents:

- **G4 Conflicts as data** — conflict objects (JSON), `flint conflicts
  list/show/resolve`; the resolution is recorded and referenced by the
  merge Change.
- **G7 Bisect** — change-granularity bisect with a predicate command.
- **G8 Sandbox scripting** — QuickJS query surface (`flint query`,
  `log --where`) and wasm hooks (pre-commit, merge policy) behind a
  stable host ABI; identical behavior on macOS, Linux, VirelaiOS.
- **Proposals** — in-store change proposals with signed approvals
  (pull requests as store objects, not platform objects).

**Wave 4 — scale and port.**

- **G5 Stream archival** — signed snapshots + roll-forward so long-lived
  streams stay within bounds without losing auditability.
- **G9 Partial materialization (M2)** — sparse checkout, on-demand
  blobs for monorepo-scale stores.
- **G10 Git bridge** — `flint import-git` / `flint export-git` via
  fast-export/fast-import streams; the adoption path.
- **G11 VirelaiOS port** — wasm (or native) target, offline-first
  client, bundle sync, CI leg, comptime OS guards.

Sequencing suggestion: G1+G2 first (git parity), then G4+G8 (the
agent superpowers), G3/G6 as collaboration demands, G5/G9/G10/G11
as scale and port demand.

## 6. Design notes for the agent-first half

### 6.1 Machine surface

Every verb gets `--json` with a versioned schema. Refusal names and
exit codes are already contractual. Agents never parse prose.

### 6.2 Parallel agents, one store

`flint worktree add <name> --stream=<s>` gives each agent an isolated
workspace over one store. No shared index, no `index.lock`, no staging
contention — the failure modes that make scripted git painful.

### 6.3 Hooks without a shell

Hooks are wasm modules (sandboxed; host functions grant store reads
and nothing else by default) or QuickJS scripts (limited JS, portable).
The same hook runs identically on all three OSes. No `#!/bin/sh`, no
`core.hooksPath` divergence, nothing to install.

### 6.4 Conflicts as data

A merge that cannot auto-resolve writes conflict objects:
`{change, path, atom, local, remote, policy_hint}`. `flint conflicts
resolve --with=<decision>` records the resolution; the merge Change
references it. Agents resolve semantically, never by editing markers
in files.

### 6.5 Offline and airgap

Where TCP is unavailable (VirelaiOS), `export`/`import` bundles
(P1–P2) are the sync path. The client is fully functional offline;
sync is an explicit verb, never a side effect.

### 6.6 Immutability after push

Pushed Changes are permanent. Recovery is `revert` (a new signed
Change undoing ops) or `supersede` (marks a Change replaced; history
shows the chain). There is no force-push to get wrong.

### 6.7 Agent identity

Each agent signs with its own `keygen` key. Provenance is queryable
(`log --json`, `flint query`) — an agent fleet's output is
attributable and auditable, which git cannot offer without extra
tooling.

## 7. VirelaiOS port strategy

- Build targets: a native Zig target if the OS runs ELF; otherwise
  `wasm32-wasi` (wasm is available). One source tree, comptime
  `builtin.os.tag` guards at the OS edges.
- Stdlib-only already pays off: no openssl, no libgit2, no curl.
- Networking sits behind a capability flag; bundles are the default
  sync path.
- QuickJS embeds as C and compiles anywhere; it powers `flint query`
  and the script hooks.
- CI leg: build the wasm artifact and run the journey suite under a
  wasm runtime where supported.
- The store format (JSONL + blobs) is byte-portable across all three
  OSes; a bundle written on macOS imports on VirelaiOS.

## 8. Non-goals

- A hosted service or web UI (fossil's weight is a warning, not a goal).
- Git object-format compatibility — the G10 bridge converts at the
  boundary instead.
- GUI, IDE plugins, LFS-style pointer files (blobs handle content).
- Rewriting the wire protocol; FLINT-SYNC/1 grows by appending ops.

## 9. How this gets tested (the loop that got us here)

Contract-led, black-box dogfooding: the live-journey harness
(`flint-server/tools/live-journey`, scenarios in
`tools/live-journey.d/`) runs real client/server journeys and turns
reproducible surprises into regression scenarios, then into issues
(`tools/file-findings`). Current state: 11/11 PASS after the wave-0
findings (#20, #21, flint-client#36) were fixed by agents. The loop
itself is documented in `flint-server/docs/dogfood.md`.

To shop the strategy around to more models: give each model one
lens, not the same prompt — (a) spec-vs-implementation audit,
(b) protocol/failure-case exploration, (c) independent reproduction
and challenge of candidate findings. Isolated temp stores only; no
code changes, no pushes, no issue filing; one consolidator dedupes.

## 10. Open questions

- Native VirelaiOS target vs `wasm32-wasi`: which the OS supports
  better. Decide before G11.
- QuickJS vs wasm-first for hooks: wasm is safer, QuickJS is easier
  to write. Possibly both — QuickJS for policy, wasm for heavy hooks.
- Snapshot cadence for G5: per-N-Changes, time-based, or explicit
  `flint archive`.
- Proposals (wave 3): in-store signed approvals vs platform PRs as
  the review surface. In-store is more portable; platform PRs are
  more social.
- `log` paging shape: `--after=<change-id>` cursor vs numeric offset.
