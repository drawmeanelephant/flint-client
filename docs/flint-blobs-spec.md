# FLINT content layer — blob store, snapshot manifests, checkout, and content sync

This is FLINT M1's keystone: file *content*, alongside the declaration
graph the store already holds. This revision resolves the
content-completeness contract reviewed in flint-client#77: manifests are
**complete signed inventories** of the tracked source root, not hints
about Op-touched files. Read with `docs/adr-0049.md` (§Primitives,
§Store, §Canonical bytes — the ADR stays the contract),
`docs/flint-client-spec.md`, and `docs/flint-server-spec.md` §2 for the
wire protocol this extends.

## 0. Identity and hard rules

- Binary `flint`, Zig 0.17.0, standard library only. No new dependency.
- **Canonical Change bytes and signatures do not change.** `sig_msg`,
  `ops_hash`, the Change/Op/Stream field sets, and the golden corpora
  are untouched. A blobs-enabled store must verify byte-identically with
  today's `verify`. A Change's `ops` array may be empty (`"ops":[]`) —
  that is a legal, already-parseable shape used for content-only
  revisions (§3).
- **Manifests are signed records.** A manifest line carries an Ed25519
  signature by the owning Change's author over a domain-separated
  canonical form (§5). "Signature-verified source" is claimed only when
  the manifest signature verifies *and* every materialized blob passes
  its content-id check. A manifest is an author's attestation of the
  revision's source inventory; for merge Changes the attester is the
  merging agent, which authored the merge Change — publisher and author
  are the same key.
- **The Change log is the truth; manifests bind content to it.** Blob
  integrity additionally rests on content addressing (blob id =
  SHA-256 of bytes, checked at every read). A corrupt or tampered
  manifest fails signature verification (`sig_invalid`); a corrupt or
  substituted blob fails its id check (`blob_malformed`). Neither can
  corrupt the Change log.
- **Logs stay append-only.** `streams/*.jsonl` is never rewritten. The
  manifest log (`manifests/<stream-id>.jsonl`) follows the same
  discipline: append + fsync, never rewritten, torn final line refuses
  `manifest_torn`.
- **Portability both ways.** A blobs-enabled store loads read-only in a
  pre-blobs client and in the Go oracle (new top-level dirs are ignored;
  nothing new lands in `streams/`). A pre-blobs store loads in a
  blobs-enabled client; `checkout` refuses `blob_missing` cleanly.
- Refusal names are snake_case and contractual. Exactly three new names:
  `manifest_torn`, `blob_missing`, `blob_malformed`. Manifest signature
  failures reuse `sig_invalid`; merge materialization gaps reuse
  `src_behind`; bounds reuse `store_too_large`/`change_too_large`. Exit
  codes unchanged: 0 success, 1 refusal, 2 usage.
- Never print blob content or key material; diagnostics on stderr.

## 1. Store layout deltas

```
<store>/
  blobs/<2 hex>/<62 hex>          whole-file content, id = SHA-256(raw bytes)
  manifests/<stream-uuid>.jsonl   one signed manifest line per Change, append-only
```

- **Blob.** Raw file bytes at `blobs/<aa>/<rest>`. Written once
  (content-addressed ⇒ idempotent), via the crash-safe write
  (temp + fsync + rename + dir fsync). Never rewritten, never mutated.
- **Manifest line** — one signed JSON object per Change, Go field order,
  sorted `files` by `path`:

```json
{"stream":"<stream-uuid>","change":"<change-uuid>","author":"<64-hex>","files":[{"path":"src/main.zig","blob":"<64-hex>","bytes":1234,"mode":644}],"sig":"<128-hex>"}
```

  `files` is the **complete inventory** of the tracked source root at
  that revision (§2), not just the files the Change's Ops touched. A
  file that is tracked but uncapturable appears with `"blob":null` and
  a `"reason"` — `"too_large"` (over the §6 cap) or `"unsupported"`
  (non-regular entry: symlink, fifo, socket, device). Every entry has
  `"path"`, `"blob"`, `"bytes"`, `"mode"`; `"reason"` appears only on
  null-blob entries. A null-blob entry makes the snapshot *explicitly
  incomplete*: `checkout` of it refuses `blob_missing` naming the path
  rather than silently omitting the file.
- **Commit order (extended).** (1) Append Change line, fsync.
  (2) Rewrite Stream record. (3) Append signed manifest line, fsync.
  (4) Remove STAGE.jsonl. Steps (1)–(2) are unchanged and sufficient on
  their own: a crash before (3) leaves a valid store whose newest Change
  lacks a manifest line. Reading manifests, a final line without `\n`
  refuses `manifest_torn`; a Change with no manifest line is *not* torn
  — it is simply content-less (pre-blobs or crashed commit), and
  `checkout` of that revision refuses `blob_missing` naming the change.
- **Index impact: none.** The every-invocation index still scans only
  `streams/` and the selected workspace. Manifests and blobs are loaded
  lazily by `commit` (prior snapshot diff), `checkout`, `gc`, and the
  sync verbs.

## 2. Tracking policy — what a snapshot covers

The inventory is defined by the filesystem, independent of declaration
parsing:

- Root = the workspace's registered `src` directory.
- **Tracked**: every regular file under the root, identified by a
  normalized relative path (`/` separators; `.`/`..` segments and
  absolute spellings are refused `manifest_torn` on read and never
  produced on write).
- **Excluded, deterministically and documented**: the resolved FLINT
  store root whenever it sits beneath the source root (the store is
  never recursively captured), and nothing else — no `.gitignore`-style
  rules in v1. Key material lives under the store (`keys/` or the
  configured keys dir), so store exclusion already covers it; a key
  file placed elsewhere in src is user error and IS captured like any
  other regular file.
- **Unsupported entries** (symlinks, fifos, sockets, devices, and any
  path that is not a regular file) are never followed — a symlink is
  recorded by its own path with `"blob":null,"reason":"unsupported"`,
  so a checkout can never be induced to write through a link or outside
  the target directory.
- Ordering: `files` is sorted by path — the inventory is deterministic
  given the tree.

## 3. Content-only revisions

Semantic staging and content capture are orthogonal signals feeding one
commit:

- `commit` computes the new inventory by hashing the tracked tree and
  diffing it against the head revision's manifest (a missing parent
  manifest means "everything differs").
- A commit is legal when the semantic stage is non-empty **or** the
  inventory differs from the parent snapshot. A content-only commit —
  README edit, comment-only change, config churn, asset swap, deletion
  of a file that produced no Ops — produces a Change with `"ops":[]`,
  a normal signed Change line, and a signed manifest line. Comment and
  whitespace edits that leave Atom hashes unchanged are still captured
  because inventory keys are file bytes, not Atom hashes.
- `nothing_to_commit` is unchanged: it fires only when the stage is
  empty *and* the inventory is identical to the parent's. Old stores are
  not reinterpreted — a store whose head has no manifest line and whose
  src matches nothing is simply a content-less tip; the first
  blobs-enabled commit records a full inventory from scratch.

## 4. Snapshot identity and checkout selection

- A revision's snapshot identity is the Change id itself. There is no
  second version namespace: `checkout --change=<id>` selects exactly one
  manifest — the line whose `change` equals the target — on the stream
  that Change was signed for (the `stream` field binds it). Head,
  ancestor, forked, and detached Changes are all valid targets; a
  Change without a manifest line is a content-less revision (§1).
- Because each manifest is a complete inventory, checkout is a single
  lookup: verify the manifest signature (§5), then for each `files`
  entry materialize the blob — no newest-to-oldest walk, no atom-replay
  stopping rule.
- `checkout` is all-or-nothing: every entry's blob presence and id
  check is resolved before any file is written. Missing or corrupt
  content, or a null-blob (`too_large`/`unsupported`) entry, refuses
  `blob_missing`/`blob_malformed` naming the path; nothing partial is
  materialized.

## 5. Manifest signing — domain, canonical form, author policy

- Domain: `sig_msg` for manifests is a **new, separate domain** —
  `"flint-manifest-v1\n" || canonical(<stream,change,author,files>)` —
  deliberately disjoint from the Change preimage. Canonical JSON uses
  the existing Go-compatible marshaling (field order as above, sorted
  `files`, lowercase hex, the same escaping rules) with `sig` excluded.
- Signer: the Ed25519 key of the Change's `author`. Verification of a
  manifest line therefore requires its referenced Change: lookup by
  `change` id on the bound `stream`, then `sig` must verify against
  `change.author`. Server-side `put_manifest` enforces exactly this —
  `change_missing` for an unknown/absent Change id, `sig_invalid` for
  a signature that fails under the Change author's key, `manifest_torn`/
  `change_malformed` for unparseable lines. The same author/key policy
  applies to manifests as to Changes under `--allow-author`.
- Trust model, stated plainly: the signature proves the *naming
  authority* bound a revision to a path→blob inventory; the blob id
  proves the bytes. Substituting a different *valid* blob into the
  mapping requires forging the author's signature — a conformance case
  (§9), not a trust hole. A pusher re-serving a manifest it did not
  author is fine: the signature is self-contained and verifiable by
  anyone holding the Change log.

## 6. Bounds

- Blob decoded size ≤ **1,800,000 bytes** per file in v1 (its 3.6 MB hex
  form fits the existing 4 MiB NDJSON line bound with envelope headroom).
  Over-cap files ride in manifests as `"blob":null,"reason":"too_large"`.
- Manifest line ≤ 4 MiB (`store_too_large`) — a complete inventory of
  ~40k typical paths fits; larger trees hit the bound and refuse
  `store_too_large` at commit (explicit, not truncated).
- Manifest log ≤ 4096 lines per stream (the Change bound's shadow; same
  refusal name) — one line per Change, so the Change bound dominates.
- `blobs/` total size is unbounded in v1; `gc` is the management verb.
- `put_manifest` batches ≤ 256 lines per request, mirroring `deposit`.

## 7. Merge and content publication

Merge Changes get manifests like any commit, with one extra rule —
**no last-writer-wins substitution of file bytes**:

- A path whose accepted content came from exactly one side of the merge
  adopts that side's blob id directly — the bytes are known and
  immutable.
- A path whose semantic state was built from *both* sides (merged atoms
  of a file edited on both branches) has no existing blob equal to its
  merged bytes. The merging workspace must materialize it: `merge`
  refuses `src_behind` naming the path when the file's merged bytes are
  not present in src. Materialized merged bytes are blobbed fresh and
  signed by the merge author — the attestation honestly says "the
  merging agent asserts these bytes," never "an original author
  produced them."
- Paths untouched by the merge carry their pre-merge blob ids
  unchanged. Deletions on the accepted side drop the path from the
  inventory.
- For conflicted merges the existing `MERGE.json` flow already requires
  resolution in src before commit; the commit then captures the
  inventory from materialized bytes in the ordinary way.

## 8. CLI surface

| Verb | Notes |
|---|---|
| `checkout [--stream=<s>] --change=<id>|--head --into=<dir> [--force]` | Materialize a complete inventory (§4). Prints `flint: checkout ok stream=<s> change=<id> files=<n> bytes=<n>`. Refuses `checkout_exists` (non-empty `--into` without `--force`), `manifest_torn`, `sig_invalid` (bad manifest signature), `blob_missing` (content-less revision or null-blob entry, naming path or change), `blob_malformed` (id mismatch), `change_missing`, `stream_missing`. Never writes outside `--into`; paths with `..`/absolute components refuse `manifest_torn`. |
| `gc [--store=<dir>]` | Delete blobs unreachable from every manifest. Prints `flint: gc ok kept=<n> removed=<n> bytes=<n>`. |
| `commit` | Extended: inventory capture + signed manifest append as step (3) (§1, §3). Output line unchanged. |
| `push` / `pull` / `clone` | Extended to sync manifests and blobs (§9). Output lines unchanged. |

`checkout` reconstruction is per §4: one manifest lookup, verify, then
materialize every entry all-or-nothing.

`gc` reachability: full manifest walk across all streams must succeed
first (any `manifest_torn` aborts the sweep, removing nothing); then
unreferenced blobs move to a `.trash/` dir inside the store and are
deleted. A crash mid-sweep leaves extra blobs only — reachable content
is never deleted, because the sweep set is computed before any unlink.

## 9. Wire protocol deltas (FLINT-SYNC/1)

Four ops, appended to the op table in this order. Envelope, `seq`,
one-request-in-flight, and Go-compatible escaping are unchanged. This is
a spec-revisioned feature: `SPECREV` bumps under the normal review
process when the ops land.

| `op` | Request fields | Response fields | Refusals |
|---|---|---|---|
| `put_manifest` | `stream`, `lines` (array of signed manifest line strings) | `ok`, `stored` | `stream_missing`, `change_missing` (a line's `change` not in the log — including detached lines), `change_malformed`, `sig_invalid` (signature fails under the Change's author), `store_too_large`, `author_not_allowed` |
| `get_manifest` | `stream`, `after` (change id or null) | `lines` | `stream_missing`, `change_missing` |
| `blob_put` | `id`, `hex` | `ok` | `blob_malformed` (id ≠ SHA-256 of decoded bytes), `change_too_large` |
| `blob_get` | `id` | `hex` | `blob_missing` |

- `put_manifest` dedupes by `change` id like `deposit` dedupes by
  Change id: byte-identical repeats skip (not counted in `stored`), the
  same `change` under different bytes refuses `change_malformed`
  (`id conflict`). All-or-nothing batches; manifest lines append in
  order and never rewrite.
- `push`: after `append`/`deposit` succeed, `blob_put` every blob the
  pushed manifest lines reference that the server lacks (`blob_get`
  probe; `blob_missing` is the miss signal), then `put_manifest` the
  lines. Blobs land before manifests so a fetched manifest is always
  resolvable. **This covers detached Changes too**: a `deposit`ed
  ancestry gets its manifests and blobs published the same way — a
  fresh clone can `verify` *and* `checkout` the preserved original
  revision.
- `pull`/`clone`: after fetching change lines, `get_manifest` for the
  new range, append missing lines verbatim (each re-verified: parse,
  `change` resolves in the fetched log, signature checks against the
  Change author — `sig_invalid` aborts before writing), then `blob_get`
  each referenced id not already in `blobs/`, id-checked before storing.
  A `blob_malformed` mid-pull leaves the Change log correct — the
  manifest/blob state re-heals on the next pull.
- A pre-content server refuses these ops with its generic unknown-op
  refusal; the client maps that to `proto_version` with detail naming
  the missing op and completes the sync *without* content (degraded,
  never failed, streams still replicate). On such a server, checkout of
  any synced revision refuses `blob_missing` — never fabricated
  content.
- Publication never moves stream heads and never rewrites accepted
  bytes: blobs are immutable, manifests append-only, stream records
  untouched by these ops. A partial upload (blobs without manifest, or
  manifest without blobs) is simply unresolvable, not usable: fetchers
  verify signatures and blob ids before treating a snapshot as real.

## 10. Conformance suite

| Suite | Pass condition |
|---|---|
| Round trip | init→add files→commit→`checkout --into`; checked-out tree byte-equal to src. Edit→commit→checkout at both changes; each tree byte-equal to its era. Two historical revisions materialize independently. |
| Completeness matrix | Mixed tree — Zig/Go declarations, comment-only edits, README, build/config file, an unsupported-language file, a binary asset, a deletion, an executable (`mode:755`) — commits, clones, and checkouts byte-equal; comment-only and README-only commits produce `ops:[]` Changes with valid signed manifests. |
| Manifest | Golden lines (field order, sorted paths, null-blob delete/too_large/unsupported entries, signature); torn final line → `manifest_torn`; manifest `change` pointing at no log Change → `change_missing`; old store without `manifests/` loads and commits (lazily creates the dir). |
| Signature binding | Manifest signed by a key other than the Change author → `sig_invalid`; path→blob substitution of a different *valid* blob id → `sig_invalid` at checkout/pull; corrupt blob bytes → `blob_malformed`. |
| Blobs | id = SHA-256 vectors; re-commit of unchanged file writes no blob (dedupe); corrupt a blob on disk → `blob_malformed` at checkout. |
| Wire | Golden NDJSON transcripts for the four ops incl. refusal envelopes; `blob_put` of wrong-hash bytes refused; `put_manifest` idempotent resend and `id conflict` leg. |
| Sync journey | Two clients + server: A commits with content, pushes; B clones, checks out — byte-equal; B edits, pushes; A pulls, checks out new head — byte-equal. Recovery leg: divergent edits → `fork`/`pull --reset`/`merge`/`push` deposits ancestry *and* manifests/blobs; a fresh clone `checkout`s the preserved original revision byte-equal. Pre-content server leg: streams replicate, content degrades with `proto_version` detail, exit 0. |
| Merge content | Merge touching a both-sides-edited file requires materialization (`src_behind` without it); merged checkout byte-equals the resolved tree; one-side-touched paths reuse their blob ids. |
| Containment | Manifest `path` with `..`, absolute, or store-prefix spellings → `manifest_torn`; symlink entries never followed. |
| GC | Fixture store with known garbage; `gc` removes exactly the unreachable set; `manifest_torn` anywhere aborts with zero deletions. |
| Portability | Blobs-enabled store opens read-only in the pre-content client (streams verify byte-identically, `verify` on original Changes unchanged); pre-content store opens in the new client; `checkout` refuses `blob_missing` and nothing else changes. |

## 11. Suggested card breakdown

| # | Card | Delivers | Suite legs |
|---|---|---|---|
| B1 | Tracking policy + blob store + commit capture | inventory walker, `blobs/` write path, manifest sign/append, content-only commit, dedupe | Manifest, Blobs, Completeness matrix |
| B2 | checkout | single-manifest lookup + all-or-nothing materialization, containment, refusal set | Round trip, Signature binding, Containment |
| B3 | Wire + sync | four ops, push/pull/clone/deposit integration, degraded-mode mapping | Wire, Sync journey |
| B4 | gc | reachability sweep, `.trash/` protocol | GC |
| B5 | Portability + hardening | both portability legs, bounds, fuzz of manifest parser | Portability |

## 12. Resolved questions (from the pre-review draft)

- **Go oracle acceptance.** New `blobs/`/`manifests/` top-level dirs are
  ignored by the pre-content readers by design (streams only); the §7
  layout-under-`content/` fallback remains available if the oracle's
  scanner turns out strict — decide at B1.
- **Signed manifests.** Chosen (§5). The draft's "unsigned hints + trust
  via content addressing" could not authenticate the path→blob mapping;
  #77 requires distinguishing that binding. A new domain-separated
  signature delivers it without touching Change bytes.

## 13. Explicitly out of scope (v1)

- Atom-level or chunk-level blobs; lazy/partial materialization (M2).
- Delta compression and packing; encryption at rest.
- `checkout` into a workspace (wiring materialization into `ws/` is a
  separate decision about what a workspace *means*).
- Server-side GC scheduling, quotas, and per-stream blob ACLs.
- `.gitignore`-style tracking rules (§2's exclusion set is fixed in v1);
  full POSIX mode bits, xattrs, and symlink preservation.
- Renaming `streams/`-relative layouts for the guest's benefit (that's
  the oracle's call).
