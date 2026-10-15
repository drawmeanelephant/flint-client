# FLINT patch bundles — implementation spec

Signed patch bundles are the **airgap/email/sneakernet transport** for
FLINT Changes: one NDJSON file carries a single stream's first-parent
range, byte-verbatim, moved out-of-band (cp, email, USB). This is the
`git format-patch`/`git am` analogue — a *bundle*, not a diff: imported
Changes keep their ids, signatures, and parent links unchanged.

Read with `docs/flint-client-spec.md` (vocabulary, verify semantics, the
M106e pull machinery) and `docs/adr-0049.md` §Primitives + §Store +
§Canonical bytes; the ADR stays the contract. Everything here is
offline: **no server is involved** — the verbs never dial, never read
`FLINT_REMOTE`/`FLINT_AUTH_KEY`, never speak FLINT-SYNC/1. `REMOTE.json`
is read only for export's default (§2.4).

## 0. Identity and hard rules

- Binary `flint`, **Zig 0.17.0**, stdlib only, the client spec's host
  targets; one framing module owns the format.
- **Byte-verbatim transport — the hard rule.** Bundle lines 2..n+1 are
  the exact bytes of `streams/<id>.jsonl` lines: export never
  re-serializes a Change to build a bundle, import never re-serializes
  one to append it (pull's discipline — parse only to verify, move the
  original bytes). The round trip must not perturb one byte.
- **Verify before write.** Import re-verifies every inbound Change
  before writing anything; `sig_invalid` aborts and writes nothing
  (pull's rule). All-or-nothing: one append, then one record rewrite.
- **Logs are append-only, never rewritten.** Import appends raw lines,
  fsyncs, rolls the record forward, and never touches `ws/` (a
  workspace replays later via the existing `init --stream`).
- **Round-trip invariant — the acceptance bar.** Export, then import
  into a fresh store with the same base, produces a stream log whose
  appended lines are byte-identical to the source lines; `verify --all`
  green on both sides.
- **Refusal vocabulary is contractual.** Exactly three new names —
  `bundle_malformed`, `bundle_torn`, `nothing_to_export`; everything
  else reuses the client spec's vocabulary, `flint: refuse <name>`
  printing, and exit codes. Bundles never sign anything — none of
  these verbs reads a key.

## 1. Bundle format

NDJSON: one JSON object per line, every line ending in `\n`.

```
line 1    {"format":"FLINT-PATCH/1","stream":{"id":"<stream-uuid>","name":"<stream-name>"},"base":<change-uuid>|null,"head":"<change-uuid>","changes":<n>}
line 2..  the raw Change lines of streams/<stream-uuid>.jsonl, byte-verbatim
last      the file's final byte must be '\n'
```

- **Header.** Emitted with exactly the key order above (client spec §2.5
  field-order discipline); `format` is the literal `"FLINT-PATCH/1"`.
  `base` is the exclusive lower bound — the parent of the first bundled
  Change — or `null` for whole history. `head` is the last Change's id,
  `changes` = n ≥ 1, UUIDs canonical lowercase. The header is parsed,
  never byte-matched: received key order and whitespace never matter.
- **Framing.** A non-empty payload whose final byte is not `\n` refuses
  `bundle_torn` (mirror of `stream_torn`; never auto-truncate). An
  unparseable line 1, wrong `format`, a bad UUID, a `changes` count
  that disagrees with the line count, or a Change whose `stream` field
  ≠ the header's stream id refuses `bundle_malformed`; a change line
  that fails to parse refuses `change_malformed`. Reads are capped at
  4 MiB and 4096 Changes (`store_too_large`).
- **Chain.** The bundled Changes must be first-parent connected:
  `c1.parent == base`, `c(i).parent == c(i-1).id`, `c(n).id == head`,
  `n == changes`; a violation refuses `bundle_malformed`.
- **First-parent only.** A merge Change travels with `merged` pointing
  at the other stream's head, but that stream's own Changes are not in
  this bundle. The merge Change still verifies — `merged` is a signed
  id, not a reference the store must hold — and ancestor walks see only
  Changes present locally. The other side's history travels as its own
  bundle.

## 2. CLI surface

### 2.1 `flint export`

`flint export [--stream=<s>] [--ws=<n>] [--from=<change-id>] [--to=<change-id>] --out=<file>`

- Stream/workspace resolution matches the sync verbs (`--stream` name or
  id; else the sole workspace's stream).
- `--to` names the range's head (inclusive); default is the stream's
  rolled-forward head. `--from` names the base (exclusive — the
  header's `base`); default is the §2.4 watermark when a `REMOTE.json`
  is resolved, else `null` (the whole log). Both ids must exist in the
  local log (`change_missing`).
- The range is the **first-parent chain** base..head, every hop in the
  local log; a chain that does not reach base refuses `fork_needed`,
  and sibling or unreachable lines outside the chain are not exported.
  An empty range — base == head, or an empty log — refuses
  `nothing_to_export`.
- `--out=<file>` is required (`usage`), written via `WriteFileSafe`;
  `--out=-` streams the bundle to stdout and the ok line to stderr.
- Output: `flint: export ok stream=<name> changes=<n> out=<file>`.
- Export does not re-verify — it copies bytes; verification is the
  receiver's job (import always verifies; `bundle-verify` is standalone).

### 2.2 `flint import`

`flint import <file> [--stream=<s>]`

`--stream=<s>`, when given (name or id), must agree with the header's
stream; a disagreement is `usage` — a guard against importing a bundle
into the wrong store. Checks run in order, all before the single write:

1. **Frame** (§1): read the file (missing file → `flint: error file not
   found`); enforce `bundle_torn`, `bundle_malformed`, `change_malformed`,
   the chain rule, and the stream-id match.
2. **Verify every Change** — recompute `ops_hash`/`sig_msg`, Ed25519
   against the Change's own `author`. Any failure refuses `sig_invalid`
   and **writes nothing**.
3. **Resolve the target stream** by header id and name. A local record
   under the header's id with a different name, or under the header's
   name with a different id, refuses `stream_exists`. With H the local
   head after roll-forward and the index store-wide:
   - stream absent, base `null` → create the record (id and name from
     the header, `forked_from` null, `created` = now);
   - stream absent, base present in the index → create the record with
     `forked_from = {stream: <the stream id inside the base Change's
     signed bytes>, change: base}` — the `flint fork` shape, from
     verified data only;
   - stream absent, base absent → `fork_needed`, detail = the base id;
   - stream present, H `null` → base must be `null` or present in the
     index (else `fork_needed` naming the base id);
   - stream present, H non-null → base must equal H (else `fork_needed`
     naming the missing base id, or the local head when base ≠ H).
4. **Write**: append the change lines verbatim + fsync, then rewrite
   the stream record (head = the bundle's head; id, name, `forked_from`,
   `created` preserved on existing streams). Change-count bounds apply
   (`store_too_large`).

Output: `flint: import ok stream=<name> changes=<n> head=<id>`.

### 2.3 `flint bundle-verify`

`flint bundle-verify <file>`

Standalone, like `verify --file`: no store is loaded or needed, nothing
is written. Frames the file per §1 (same refusals), then prints one
`flint: verify <id> sig: verified` or `flint: verify <id> sig_invalid`
per Change, exiting `1` when any is invalid, `0` otherwise.

### 2.4 The pushed watermark (`REMOTE.json` delta)

Export's default base is "the changes not yet pushed", and a file
transport has no server to ask. `REMOTE.json` gains one optional field:

`{"remote":"tcp://host:port","stream":"<id>","pushed_head":"<change-id>"}`

- `pushed_head` is the local head as of the last successful sync —
  maintained by `push` (also on `up to date`), `clone`, `pull`, `pull
  --reset`; absent or `null` means nothing known pushed, and loaders
  treat an absent field as `null`, so existing files load unchanged.
- Export's default uses the same walk push uses against the server's
  head: locate `pushed_head` in the log, take the first-parent chain
  after it; a watermark missing from the log falls back to `null` —
  the whole log.
- The watermark only advances after the server accepts, so a crash
  mid-push leaves it stale-low and export **over-exports** — the safe
  direction: import refuses overlapping ranges, so nothing duplicates.

## 3. Conformance suite (the acceptance bar)

All legs drive the CLI against tmpdir stores with `FLINT_*` cleared;
golden fixtures live in `testdata/bundles/`:

| Suite | Source | Pass condition |
|---|---|---|
| Golden fixtures | `good-3` (3-Change bundle, byte-pinned: header + 3 verbatim lines + trailing `\n`), `torn` (final `\n` stripped), `tampered` (line 2's `sig` flipped), `wrong-base` (`base` names an id no store holds) | `good-3` imports and verifies; the others refuse by the pinned names — `bundle_torn`, `sig_invalid`, `fork_needed <base-id>` in the detail — and **write nothing** (log length and record bytes unchanged). |
| Round trip | 3 commits on a source stream → export → import into a fresh store | The fresh log's appended lines byte-equal the source lines; `verify --all` green on both; `log` output identical. |
| Two-host journey | stores A and B, **bundles only** — no flintd, no `FLINT_REMOTE`, the file moved with `cp` | A: keygen → init → add → commit ×3 → export; B imports (stream created, base null); `verify --all` green on both; B's log byte-equals A's. |
| Export ranges | explicit `--from`/`--to` legs | Unknown id → `change_missing`; `--from` == `--to` → `nothing_to_export`; `--to` on an unreachable or sibling Change → `fork_needed`. |
| Watermark default | loopback push (qa fixture) → commit more → export with no `--from` | Default bundle base = the pushed head (unsent suffix only); a `REMOTE.json` without `pushed_head` defaults to the whole log. |
| Import discipline | re-import the same bundle; import onto a diverged store | Both refuse `fork_needed`, write nothing, and leave **no duplicate Change ids** in any log; a clean fast-forward grows the log only by append and moves only the record head. |
| bundle-verify standalone | `FLINT_STORE` unset, empty cwd | `good-3` → 3 × `sig: verified`, exit 0; `tampered` → one `sig_invalid` line, exit 1; `torn` → `bundle_torn`, exit 1. |

## 4. Suggested card breakdown

Claimable in order; P2 depends on P1's framing module.

| # | Card | Delivers | Suite legs |
|---|---|---|---|
| P1 | Format + export + bundle-verify | Bundle framing module (header emit/parse, torn/malformed checks, chain rule); `export` with flags, defaults, refusals; `REMOTE.json` `pushed_head` plus its four sync maintainers; `bundle-verify`; fixtures `good-3`, `torn`, `tampered` | Golden fixtures, export ranges, watermark default, bundle-verify standalone |
| P2 | Import + journeys | `import` (verify-all-before-write, target resolution, stream creation, verbatim append + record roll); `wrong-base` fixture; divergence and idempotence legs | Round trip, two-host journey, import discipline |

## 5. Explicitly out of scope (v1)

- Bundle encryption, or signing the bundle itself (Changes are already
  signed; the header is framing, not a claim); compression or any
  non-NDJSON encoding.
- Multi-stream bundles: one file, one stream, first-parent only.
- `--onto`/base rewriting: ids and parent links are immutable — a
  Change is signed, so any rewrite breaks signatures. Cut by decision.
- Full-history export from a watermarked workspace (needs a `--root`-style
  spelling for base `null`; v1 ships only the unsent suffix and explicit
  `--from` ranges).
- Server involvement: no flintd, no FLINT-SYNC, no auto-send or
  email/USB integration, no partial-import resume (import is one
  atomic append).
