# FLINT content layer — blob store, checkout, and blob sync spec

This is FLINT M1's keystone: file *content*, alongside the declaration
graph the store already holds. Read with `docs/adr-0049.md` (§Primitives,
§Store, §Canonical bytes — the ADR stays the contract),
`docs/flint-client-spec.md`, and `docs/flint-server-spec.md` §2 for the
wire protocol this extends.

## 0. Identity and hard rules

- Binary `flint`, Zig 0.17.0, standard library only. No new dependency.
- **Canonical bytes and signatures do not change.** `sig_msg`,
  `ops_hash`, the Change/Op/Stream field sets, and the golden corpora
  are untouched. A blobs-enabled store must verify byte-identically with
  today's `verify`.
- **The Change log is the truth; manifests are derived.** A manifest
  line is a hint about where content lives. Content integrity comes from
  content addressing (blob id = SHA-256 of bytes, checked at every
  read), not from signatures. A corrupt or tampered manifest is detected
  at checkout time as `blob_missing`/`blob_malformed`; it can never
  corrupt the Change log.
- **Logs stay append-only.** `streams/*.jsonl` is never rewritten. The
  manifest log (`manifests/<stream-id>.jsonl`) follows the same
  discipline: append + fsync, never rewritten, torn final line refuses.
- **Portability both ways.** A blobs-enabled store loads read-only in a
  pre-blobs client and in the Go oracle (new top-level dirs are ignored;
  nothing new lands in `streams/`). A pre-blobs store loads in a
  blobs-enabled client; `checkout` refuses `blob_missing` cleanly.
- Refusal names are snake_case and contractual. Exactly three new names:
  `manifest_torn`, `blob_missing`, `blob_malformed`. Exit codes
  unchanged: 0 success, 1 refusal, 2 usage.
- Never print blob content or key material; diagnostics on stderr.

## 1. Store layout deltas

```
<store>/
  blobs/<2 hex>/<62 hex>          whole-file content, id = SHA-256(raw bytes)
  manifests/<stream-uuid>.jsonl   one manifest line per Change, append-only
```

- **Blob.** Raw file bytes at `blobs/<aa>/<rest>`. Written once
  (content-addressed ⇒ idempotent), via the crash-safe write
  (temp + fsync + rename + dir fsync). Never rewritten, never mutated.
- **Manifest line** (one JSON object, Go field order):

```json
{"change":"<change-uuid>","files":[{"path":"src/main.zig","blob":"<64-hex>","bytes":1234}]}
```

  `files` covers exactly the files touched by the Change's staged Ops
  (the union of span files across add/modify and the pre-state files of
  delete), capturing post-commit on-disk bytes. A deleted file appears
  with `"blob":null,"bytes":0`. A file over the v1 size cap (§2) appears
  with `"blob":null` and `"reason":"too_large"` — commit proceeds, the
  omission is explicit, checkout of a range needing that blob refuses
  `blob_missing` naming the path.
- **Commit order (extended).** (1) Append Change line, fsync.
  (2) Rewrite Stream record. (3) Append manifest line, fsync.
  (4) Remove STAGE.jsonl. Steps (1)–(2) are unchanged and sufficient on
  their own: a crash before (3) leaves a valid store whose newest Change
  lacks a manifest line. Reading manifests, a final line without `\n`
  refuses `manifest_torn`; a Change with no manifest line is *not* torn
  — it is simply content-less (pre-blobs or crashed commit), and only
  `checkout` of a range covering it refuses `blob_missing`.
- **Index impact: none.** The every-invocation index still scans only
  `streams/` and the selected workspace. Manifests and blobs are loaded
  lazily by `checkout`, `gc`, and the sync verbs.

## 2. Bounds

- Blob decoded size ≤ **1,800,000 bytes** per file in v1 (its 3.6 MB hex
  form fits the existing 4 MiB NDJSON line bound with envelope headroom).
  Over-cap files ride in manifests as `"blob":null,"reason":"too_large"`.
- Manifest line ≤ 4 MiB (`store_too_large`), manifest log ≤ 4096 lines
  per stream (the Change bound's shadow; same refusal name).
- `blobs/` total size is unbounded in v1; `gc` is the management verb.

## 3. CLI surface

| Verb | Notes |
|---|---|
| `checkout [--stream=<s>] [--change=<id>] --into=<dir> [--force]` | Materialize file bytes at a change (default: stream head). Prints `flint: checkout ok stream=<s> change=<id> files=<n> bytes=<n>`. Refuses `checkout_exists` when `--into` is non-empty without `--force`, `blob_missing` (naming path and blob prefix) when content is unavailable, `blob_malformed` when a blob's bytes fail the id check, `change_missing`, `stream_missing`. Never writes outside `--into`; paths are validated to stay under it (`..` and absolute paths in manifests refuse `manifest_torn`). |
| `gc [--store=<dir>]` | Delete blobs unreachable from every manifest. Prints `flint: gc ok kept=<n> removed=<n> bytes=<n>`. |
| `commit` | Extended: after the stage fold, blob each touched file (§1) and append the manifest line as step (3). Output line unchanged. |
| `push` / `pull` / `clone` | Extended to sync manifests and blobs (§4). Output lines unchanged. |

`checkout` reconstruction: walk manifest lines newest→oldest from the
target change, filling each path from the newest manifest that names it;
stop when every path seen in the stream's atom replay is filled or the
walk exhausts. A needed path never blobbed refuses `blob_missing` naming
it. Files write with the manifest-recorded byte count verified against
the blob.

`gc` reachability: full manifest walk across all streams must succeed
first (any `manifest_torn` aborts the sweep, removing nothing); then
unreferenced blobs move to a `.trash/` dir inside the store and are
deleted. A crash mid-sweep leaves extra blobs only — reachable content
is never deleted, because the sweep set is computed before any unlink.

## 4. Wire protocol deltas (FLINT-SYNC/1)

Four ops, appended to the §2.3 op table in this order. Envelope, `seq`,
one-request-in-flight, and Go-compatible escaping are unchanged.

| `op` | Request fields | Response fields | Refusals |
|---|---|---|---|
| `put_manifest` | `stream`, `lines` (array of manifest line strings) | `ok` | `stream_missing`, `change_missing` (a line's `change` not in the log), `change_malformed`, `store_too_large` |
| `get_manifest` | `stream`, `after` (change id or null) | `lines` | `stream_missing`, `change_missing` |
| `blob_put` | `id`, `hex` | `ok` | `blob_malformed` (id ≠ SHA-256 of decoded bytes), `change_too_large` |
| `blob_get` | `id` | `hex` | `blob_missing` |

- `push`: after `append` succeeds, `put_manifest` the manifest lines for
  the pushed changes, then `blob_put` every blob those lines reference
  that the server lacks (query with `blob_get`; a `blob_missing` reply
  is the miss signal). Order matters: blobs land before the manifest is
  meaningful to fetchers, so blobs go first, manifest second.
  Correction to the table order above: the *sending* order is `blob_put`
  then `put_manifest`; the ops are declared in table order for reading.
- `pull`/`clone`: after appending change lines, `get_manifest` for the
  new range, append missing lines verbatim, then `blob_get` each
  referenced id not already in `blobs/`. Each fetched blob is verified
  against its id before storing (`blob_malformed` aborts mid-pull having
  written only the change log — the manifest/blob state is re-healed by
  the next pull; the log is never wrong).
- A pre-blobs server refuses these ops with its generic unknown-op
  refusal; the client maps that to `proto_version` with detail naming
  the missing op and completes the sync *without* content (degraded,
  never failed, streams still replicate).

## 5. Conformance suite

| Suite | Pass condition |
|---|---|
| Round trip | init→add files→commit→`checkout --into`; checked-out tree byte-equal to src. Edit→commit→checkout at both changes; each tree byte-equal to its era. |
| Manifest | Golden manifest lines for scripted commits (field order, null-blob delete entries, too_large entries); torn final line → `manifest_torn`; old store without `manifests/` loads and commits (lazily creates the dir). |
| Blobs | id = SHA-256 vectors; re-commit of unchanged file writes no blob (dedupe); corrupt a blob on disk → `blob_malformed` at checkout. |
| Wire | Golden NDJSON transcripts for the four ops incl. refusal envelopes; `blob_put` of wrong-hash bytes refused. |
| Sync journey | Two clients + server: A commits with content, pushes; B clones, checks out — byte-equal; B edits, pushes; A pulls, checks out new head — byte-equal. Pre-blobs server leg: streams replicate, content degrades with `proto_version` detail, exit 0. |
| GC | Fixture store with known garbage; `gc` removes exactly the unreachable set; `manifest_torn` anywhere aborts with zero deletions. |
| Portability | Blobs-enabled store opens read-only in the pre-blobs client (streams verify); pre-blobs store opens in the new client; `checkout` refuses `blob_missing` and nothing else changes. |

## 6. Suggested card breakdown

| # | Card | Delivers | Suite legs |
|---|---|---|---|
| B1 | Blob store + commit capture | `blobs/` write path, manifest append, commit step (3), dedupe | Manifest, Blobs |
| B2 | checkout | reconstruction walk, path validation, refusal set | Round trip |
| B3 | Wire + sync | four ops, push/pull/clone integration, degraded-mode mapping | Wire, Sync journey |
| B4 | gc | reachability sweep, `.trash/` protocol | GC |
| B5 | Portability + hardening | both portability legs, bounds, fuzz of manifest parser | Portability |

## 7. Open questions

- **Go oracle acceptance.** The `blobs/` + `manifests/` dirs are new
  top-level store entries; the guest `FLINT.ELF` must ignore them. If it
  scans store roots strictly, the dirs move under a single `content/`
  root. Check before B1 lands.
- **Manifest lines are unsigned.** Trust rests on content addressing.
  If a signed-manifest variant is ever wanted, it is a new arc (and a
  new `sig_msg` version), not a patch on this one.

## 8. Explicitly out of scope (v1)

- Atom-level or chunk-level blobs; lazy/partial materialization (M2).
- Delta compression and packing; encryption at rest.
- `checkout` into a workspace (wiring materialization into `ws/` is a
  separate decision about what a workspace *means*).
- Server-side GC scheduling, quotas, and per-stream blob ACLs.
- Renaming `streams/`-relative layouts for the guest's benefit (that's
  the oracle's call, §7).
