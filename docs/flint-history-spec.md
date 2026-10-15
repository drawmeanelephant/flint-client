# FLINT atom-native history spec

Atom history is a pure client query over the signed Changes in a local store.
It is the history of declaration identity, not a line-oriented source diff.

## 0. Identity and hard rules

- An Atom's UUIDv7 `atom_id` is its identity for its entire lifetime.
  Name and file are attributes of that identity's history, not its identity.
- `rename` and `move` preserve `atom_id`. A byte-offset shift in the same
  file is not an Op and must not appear as history.
- Both commands read the ordinary FLINT store and workspace Atom table.
  They add no configuration, store files, server protocol, or server query.
- The commands are client-only and work against any compatible store,
  including a cloned store. A server is never contacted.
- Use Zig 0.17.0 and the standard library only. Preserve the store, Op,
  Change, signing, and refusal contracts in ADR 0049.
- Output is UTF-8, deterministic, one record per line, and `flint: `-prefixed.
  IDs are canonical UUIDs; hashes and author prefixes are lowercase hex.
- Atom names and file paths in the new records use percent-encoding on UTF-8
  bytes: leave ASCII letters, digits, `.`, `_`, `~`, `/`, and `-` unchanged;
  encode every other byte as `%HH` with uppercase hex. For a span file,
  encode `:` too, to reserve it as the file/offset separator.
- Exit codes: `0` success, `1` refusal, `2` usage. Refusals print
  `flint: refuse <name>`. Add `atom_missing` to the refusal vocabulary.

## 1. CLI surface

| Command | Behavior |
|---|---|
| `flint log --atom=<qualified-name> [--stream=<s>] [--ws=<n>] [--all]` | Print matching changes in the selected stream history. |
| `flint blame <qualified-name> [--ws=<n>] [--all]` | Print one identity summary and its rename/move chain. |

`--ws` uses the existing workspace resolution rules. `log` selects the
workspace's stream unless `--stream` is given. `blame` always uses the
selected workspace's stream. Missing workspaces/streams use the existing
`ws_missing`, `ws_ambiguous`, and `stream_missing` refusals. Unknown options
or malformed arguments refuse `usage`.

The existing Change record is unchanged and must retain its field order:

```text
flint: change <id> parent=<id|none> ops=<n> author=<8-hex> msg=<first line>
```

For `log --atom`, emit that record once for each walked Change with at least
one Op whose `atom_id` is the resolved id. Immediately follow it with one
line for every Op on that id in the Change's stored Op order:

```text
flint:   op <type> name=<new_name|-> hash=<8-hex-prefix|-> span=<file:start-end|->
```

`type` is the stored Op type (`add`, `modify`, `delete`, `move`, `rename`).
The optional values come from `new_name`, `new_hash`, and `new_span`;
missing values are `-`. Hash is the first eight lowercase hex digits.
Span offsets are decimal byte offsets and use the stored slash-separated
relative path. The `name` and `file` values follow the encoding rule in §0.

`blame` emits exactly this block, in this order:

```text
flint: blame atom=<uuid> kind=<kind> name=<qualified-name> span=<file:start-end|-> visibility=<value|->
flint:   born=<change-id>
flint:   last_modified=<change-id>
flint:   changes=<n>
flint: rename <old-name> -> <new-name> in <change-id>
flint: move <old-file> -> <new-file> in <change-id>
flint:   authors=<n> keys=<8-hex>[,<8-hex>...]
```

Emit zero or more rename/move lines between `changes` and `authors`.
`born` is the Change containing the Atom's `add`; `last_modified` is the
newest walked Change containing any Op for that Atom. `changes` counts
distinct Changes that contain one or more such Ops. The author list contains
distinct full author keys, ordered by full key bytes; render each as its
first eight lowercase hex digits. `authors=<n>` counts full keys, not
prefixes. The summary metadata comes from the current Atom table when the
resolved id is present there. Otherwise use the latest state reconstructible
from its history, and `-` for unavailable span or visibility. Encode names
and paths as specified in §0.

## 2. Atom resolution and history walk

1. Resolve the workspace and stream using §1. Read the workspace's current
   Atom table and the selected stream history using normal store validation.
   Do not mutate the store or workspace.
2. Resolve the query by exact qualified-name match in the current Atom table.
   If it matches, that Atom's id wins, even if another historical Atom once
   had the same name.
3. If there is no current match, scan reachable Changes in the walk order
   below. Within each Change inspect its stored Op order. A `new_name` on an
   `add` or `rename` equal to the query selects that Op's `atom_id`; the first
   match wins. Do not match `modify`, `move`, or `delete` by name.
4. If neither phase finds an id, refuse `atom_missing`. Do not fall back to
   text search, fuzzy matching, parsing source files, or line-number blame.
5. Start a walk at the selected stream head. Default traversal follows only
   `parent`, newest to oldest, stopping at null. `merged` is ignored.
6. With `--all`, traverse both `parent` and `merged` edges. Use breadth-first
   levels from the head. Within each level order Changes by `(ts descending,
   id descending)`. Enqueue each Change's `parent` and then `merged`; mark an
   id visited when enqueued, and never visit or emit an id twice. This order
   is also the order used by historical name resolution.
7. `log --atom` visits at most 64 Changes by default or 256 with `--all`,
   then emits matches among those visited Changes. The cap applies to
   visited Changes, not just matching output lines. The traversal and
   de-duplication rules apply before the cap.
8. `blame` uses the same parent selection and deterministic ordering, but
   walks all reachable Changes, bounded by the store's existing 4096-Change
   limit, so its birth, count, authors, and chain describe the full history.
9. For blame, collect each matching Change once. `born` is its oldest `add`;
   `last_modified` is the first matching Change in walk order. Emit rename
   and move records oldest-first (reverse walk order); within one Change use
   stored Op order. `changes` counts matching Changes, not Ops. A refactor
   with rename and modify therefore contributes one Change.
10. To reconstruct historical state when an id is absent from the current
    Atom table, begin with its `add` fields and apply later `rename` and
    `move` fields in history order. A `delete` does not erase the historical
    state shown by blame. Visibility unavailable from the Atom table is `-`.

## 3. Worked examples

Suppose Change `c1` adds `pkg.alpha` in `src/a.go`, Change `c2` renames
that id to `pkg.beta`, and Change `c3` modifies its body. A current workspace
lookup of `pkg.beta` resolves the id directly. The blame output includes:

```text
flint: blame atom=018f0000-0000-7000-8000-000000000001 kind=fn name=pkg.beta span=src/a.go:10-42 visibility=pub
flint:   born=018f0000-0000-7000-8000-000000000002
flint:   last_modified=018f0000-0000-7000-8000-000000000004
flint:   changes=3
flint: rename pkg.alpha -> pkg.beta in 018f0000-0000-7000-8000-000000000003
flint:   authors=2 keys=01234567,89abcdef
```

The `born` id is the add Change, whose add used the original name. The rename
does not create a new identity. `log --atom=pkg.beta` prints the existing
Change line and the per-Atom Op line for each matching Change within its cap.

For a move chain `src/a.go` → `src/lib/a.go` → `src/archive/a.go`, both
move lines name the same Atom id and appear oldest-first. A same-file span
shift emits no line because it is not an Op.

For a merge Change `m` with `parent=p` and `merged=q`, default history follows
`m`, `p`, then `p`'s parents; it does not traverse `q`. `--all` visits both
ancestries by the BFS ordering in §2 and reports any matching Change only
once, even if it is reachable through both edges.

## 4. Conformance suite

Use golden-output fixtures built from synthetic, signed streams. Compare
stdout byte-for-byte, refusal name, and exit code:

- Rename then modify: stable Atom id, original birth, rename line, `log`
  Change and Op lines, exact field order and eight-hex prefixes.
- Move chain: same id, oldest-first file transitions, encoded file paths.
- Merge with `--all`: both-parent traversal, timestamp/id ordering, visited
  set behavior, no duplicate Change output; default excludes `merged`.
- `atom_missing`: current-table miss plus historical-name miss refuses;
  current-table hit takes precedence over a historical name collision.
- Cap legs: 64 Changes by default and 256 with `--all`; matching output at
  the boundary is included and later Changes are not visited by `log`.
- Blame metadata, author de-duplication/order, and a rename+modify Change
  counting once.

Add a corpus leg that reads every Atom in `testdata/corpus/MANIFEST.json`,
builds its scripted history, runs `blame` for every qualified name, and
compares the golden block for each Atom. Include names and paths requiring
percent encoding. All fixtures run locally without a server or network.

## 5. Suggested card breakdown

| Card | Delivers | Acceptance |
|---|---|---|
| H1 | Shared history selection, `log --atom`, resolution, refusal and exact output | Synthetic rename/move/missing/cap goldens; default and `--all` merge walk. |
| H2 | `blame`, identity replay, metadata, authors and corpus leg | Synthetic blame goldens and blame for every corpus MANIFEST Atom. |

Keep both cards in the CLI/operations dependency layers; do not add query
logic to the model or store format. Each card is independently testable
against a disposable store and scripted history.

## 6. Explicitly out of scope

- Line-level blame, line history, diff attribution, and heuristic rename
  detection.
- TUI or web UI.
- Server-side history/query endpoints or any server involvement.
- New top-level configuration, store files, database, or dependencies.
- Rewriting history, changing merge semantics, or changing existing `log`
  output for calls without `--atom`.
