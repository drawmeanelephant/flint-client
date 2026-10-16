# FLINT `--json` result envelopes — spec

Status: **normative.** This document freezes the versioned JSON result
schema for `flint` collaboration verbs (issue
[#79](https://github.com/drawmeanelephant/flint-client/issues/79)), the
first bounded slice of the machine surface in
`docs/git-replacement-roadmap.md` §6.1. A port implementing the `flint`
CLI must reproduce this schema byte-for-byte given the same store state,
ids, and inputs.

Read with `docs/flint-client-spec.md` §1 (the verb table), `docs/adr-0049.md`,
and `docs/spec-versioning.md`. Text output, refusal names, and exit codes
remain the contract in `flint-client-spec.md`; `--json` is strictly
additive opt-in and changes none of them.

## 1. Invocation and framing

`--json` is a global flag accepted anywhere in argv (like `--store`),
including before the verb. Bare `--json` only; there is no `--json=<v>`
form — an unrecognized `--json*` argument reaches the verb parser and
refuses `usage` as today.

When `--json` is in effect:

- stdout carries **exactly one JSON object** followed by a single `\n`.
  No other bytes appear on stdout — no `flint: ` lines, no progress, no
  diagnostics.
- stderr may carry the legacy `flint: refuse …` / `flint: error …`
  diagnostic line; agents must not depend on it (stderr is not part of
  this schema).
- `-h`/`--help` is documentation, not an operation result: it prints the
  text help even when `--json` is present.
- A process-level refusal before the verb is known (no verb, unknown
  verb, bad global arguments) still emits an envelope with
  `"verb":""` and `kind="refused"`, `refusal.name="usage"`, exit 2.

The result is generated from operation results at the point they are
computed. It is never produced by re-parsing the text output.

## 2. Envelope

One object, keys in this fixed order:

| Key | Type | Meaning |
|---|---|---|
| `v` | int | Envelope schema version. Always `1` here. |
| `verb` | string | The verb as invoked (`status`, `add`, …); `""` when no verb was parsed. |
| `ok` | bool | `true` iff `kind` is `ok` or `noop`. |
| `exit` | int | The process exit code: `0`, `1`, or `2`. Always equals the code the process exits with. |
| `kind` | string | Outcome classifier; see §3. |
| `workspace` | string \| null | Selected workspace name, when one was resolved. |
| `stream` | string \| null | Selected stream **name** (as the CLI displays it), when one was resolved. |
| `heads` | object \| null | `{"base":…, "result":…, "remote":…}` — each a Change id or `null`. The object is present iff the verb observed stream heads; inner `null` means "no head" (e.g. an empty stream), not "unknown". Per-verb meanings in §4. |
| `changes` | object \| null | `{"affected":[<id>…], "affected_omitted":<n>}` — Change ids created, published, or received by this invocation, first-parent order where meaningful. Present iff at least one Change was affected. `affected_omitted` is the count beyond the `affected` cap (§7). |
| `conflicts` | array \| null | Structured merge conflicts `[{"atom":<id>,"name":<qualified>,"type":<t>}…]`, capped at 256 — `merge`'s `data.conflicts_omitted` counts the rest. `merge` always emits an array (possibly `[]`); other verbs emit `null`. Conflict `type` is the existing `MERGE.json`/text vocabulary (`concurrent_add`, `concurrent_modify`, `concurrent_move`, `concurrent_rename`, `delete_vs_modify`, `delete_vs_move`, `delete_vs_rename`, `modify_vs_move`, `modify_vs_rename`, `move_vs_rename`). |
| `refusal` | object \| null | `{"name":<refusal-name>, "detail":<string>}` — `name` is the existing refusal vocabulary verbatim (§5 of `flint-client-spec.md`); `detail` is present only when non-empty. Present iff `kind="refused"`. |
| `error` | object \| null | `{"name":<string>}` — the same friendly error name the text path prints (`connection refused`, `timed out`, …). Present iff `kind="error"`. |
| `local` | string | Local store/workspace content outcome: `unchanged`, `applied`, `partial`, `unknown`; see §4. |
| `remote` | object \| null | `{"url":<resolved remote URL>, "outcome":<enum>, "sent":<n>, "received":<n>, "spec_rev":<int\|null>}` — present only for remote verbs (`clone`, `push`, `pull`) once a remote URL resolved; see §4. |
| `data` | object | Per-verb payload, §5. Always an object (possibly `{}`). |

Normative examples live in `testdata/results/*.json` — one frozen envelope
per behavior class (`commit-ok`, `status-noop`, `refused-nothing-to-commit`,
`merge-conflicts`, `push-lost-ack`, `push-partial`, `pull-unknown`). A
conformance test asserts their fixed key order, kind/refusal/error
invariants, and framing; the inline examples below are illustrative.

Example (push, up to date):

```json
{"v":1,"verb":"push","ok":true,"exit":0,"kind":"noop","workspace":"w","stream":"main","heads":{"base":"<head>","result":"<head>","remote":"<head>"},"changes":null,"conflicts":null,"refusal":null,"error":null,"local":"unchanged","remote":{"url":"tcp://127.0.0.1:4748","outcome":"unchanged","sent":0,"received":0,"spec_rev":4},"data":{"sent":0,"created":false}}
```

Example (commit refused because the stage is stale):

```json
{"v":1,"verb":"commit","ok":false,"exit":1,"kind":"refused","workspace":"w","stream":"main","heads":{"base":"<staged-base>","result":"<current-head>","remote":null},"changes":null,"conflicts":null,"refusal":{"name":"stage_stale","detail":"staged against <staged-base>; stream head is now <current-head>; re-run add to restage"},"error":null,"local":"unchanged","remote":null,"data":{}}
```

Example (merge with conflicts — exit 2, distinguishable from `usage`):

```json
{"v":1,"verb":"merge","ok":false,"exit":2,"kind":"conflicts","workspace":"w","stream":"main","heads":{"base":"<into-head>","result":null,"remote":null},"changes":null,"conflicts":[{"atom":"<atom-id>","name":"main.go:fn:parse","type":"concurrent_modify"}],"refusal":null,"error":null,"local":"applied","remote":null,"data":{"from":"feature","from_head":"<from-head>","ancestor":"<anc>"}}
```

## 3. `kind` vocabulary

`kind` is closed under v1 — a producer must not emit other values without
bumping `v`.

| `kind` | `ok` | `exit` | Meaning |
|---|---|---|---|
| `ok` | true | 0 | The operation completed; its result applied or its verdict positive. |
| `noop` | true | 0 | Completed; there was nothing to do (`push`/`pull`/`merge` up to date). |
| `conflicts` | false | 2 | `merge` could not auto-resolve; `conflicts` carries the structured conflicts and `ws/<ws>/MERGE.json` was written. Distinct from a `usage` refusal despite the shared exit 2. |
| `refused` | false | 1 or 2 | Refusal; `refusal.name` holds the existing refusal name. Exit is 2 iff `name=="usage"`, else 1 — the legacy mapping is unchanged. |
| `failed` | false | 1 | The operation ran to completion but its verdict is negative (`verify` found a bad signature). Not an operational failure. |
| `error` | false | 1 | Transport/internal failure before a verdict; `error.name` diagnoses. A consumer determines the next safe action from `local`/`remote` outcomes, never from `error.name` text. |

## 4. Heads and outcome honesty

`heads`:

- `base` — the head the operation observed or asserted before acting:
  `status`: the stage base recorded in `ws/<ws>/BASE.json` (`null` when
  absent); `add`: the head stamped into `BASE.json`; `commit`: the parent
  the Change asserted; `merge`: the into-head; `push`/`pull`: the local
  head before the sync; `clone`: `null`.
- `result` — the resulting head: `commit`: the new Change id; `merge`:
  the merge Change id (`null` on conflicts, `=base` on noop);
  `push`/`pull`: the head after the operation; `clone`: the cloned
  stream's head; `status`/`add`: the stream head observed.
- `remote` — the last head the remote confirmed or advertised
  (`push`: remote head after the operation; `pull`/`clone`: the
  advertised remote head); `null` when not observed.

`local` describes mutations to local store/workspace **content** —
stream Change logs and records, `ATOMS.jsonl`, `STAGE.jsonl`,
`MERGE.json`. Bookkeeping files outside content (`REMOTE.json`) do not
count:

- `unchanged` — no content write occurred or none was needed.
- `applied` — the operation's writes completed.
- `partial` — a bounded subset of writes completed before failure
  (e.g. `clone` wrote some stream logs, then failed).
- `unknown` — a write was in flight when the operation failed; it may or
  may not have landed.

`remote` (present for `clone`, `push`, `pull` once `url` resolved):

- `url` — resolved remote URL (`--remote` → `FLINT_REMOTE` →
  `REMOTE.json`). Never a credential.
- `sent` — Change lines confirmed stored remotely this invocation
  (`append` + `deposit`). A confirmed count.
- `received` — Change lines fetched and stored locally (`pull`, `clone`).
- `spec_rev` — the server's announced `spec_rev`, or `null` when
  unannounced.
- `outcome` — per verb:
  - `push`: `unchanged` (nothing to send or remote provably untouched),
    `applied` (all submitted appends acknowledged), `partial` (≥1
    mutation confirmed, then a later mutation's outcome became
    uncertain), `unknown` (a mutation request was sent and never
    confirmed — e.g. a lost append acknowledgment. It must **not** be
    reported as `unchanged`).
  - `pull`/`clone` (read-only remote): `applied` (remote data verified
    and stored locally), `unchanged` (remote fully observed, nothing new
    applied — including post-observation refusals such as
    `store_too_large`), `unknown` (the remote could not be fully
    observed — dial, handshake, transport, signature-verification,
    incomplete-prefix, or `fork_needed` refusals before the remote log
    is fully verified).
- The ban on automatic `append` retries is unchanged: on `partial` or
  `unknown` the CLI does not retry; the next safe action is a fresh
  `push` — appends dedupe by Change id, so re-pushing is safe.

## 5. Per-verb `data` payloads

`data` is a flat object per verb. Keys listed are v1-frozen for the
instrumented verbs; new keys may appear additively (§6).

| Verb | `data` keys |
|---|---|
| `status` | `atoms` int, `staged` int, `add` int, `modify` int, `delete` int, `duplicates` int, `ops` array of `{"type":<add\|modify\|delete>,"atom":<id>,"name":<qualified>,"file":<rel\|null>}`, `ops_omitted` int (present iff >0). |
| `add` | `files` int (source files seen), `new`, `modified`, `deleted`, `unchanged` ints, `affected` array of relative file paths whose staged atoms were rewritten, `affected_omitted` int (present iff >0). |
| `commit` | `id` string (the new Change id — same as `heads.result`), `ops` int, `message` string (the commit message), `merged` string (present iff this commit resolved an in-progress merge), `merge_resolution` bool. |
| `merge` | `from` string (source stream name), `from_head` string, `ancestor` string\|null. On clean merges also `ops` int and `unmaterialized_files` int (src files whose merged atoms were never materialized — the `origin=merge`/`src_behind` set). `conflicts_omitted` int when conflicts exceed the §7 cap. |
| `push` | `sent` int (head-chain Changes appended — the text `changes=` count), `created` bool (the target stream's record was created remotely). |
| `pull` | `received` int (newly appended lines — the text `changes=` count), `reset` bool (`--reset` path taken). |
| `clone` | `replayed` int (the text `changes=` count), `streams` int (stream records written), `received` int (newly stored lines across the fork chain). |
| `verify` | `verified` int, `failed` int, `changes` array of `{"id":<id>,"sig":"verified"\|"sig_invalid"}`, `changes_omitted` int (present iff >0). |

Verbs outside this slice (`init`, `fork`, `log`, `keygen`, `version`,
`release`, `parse-corpus`) accept `--json` and emit the same envelope
with `data:{}` and `heads`/`changes`/scope fields `null` unless the
invocation populates them. Their payloads are frozen by later slices
(#80/#81 arcs), not by this document.

## 6. Forward compatibility and extension points

- Consumers MUST ignore unknown keys at every level, and MUST NOT
  depend on key order beyond the documented emission order.
- Within `v=1`: producers may add envelope keys, `data` keys, and list
  element keys additively. Producers must not remove keys, change a
  key's type, or change a listed `kind`/`local`/`remote.outcome` value's
  meaning; new enum values require `v=2`.
- `refusal.name` values are the existing refusal vocabulary; new refusal
  names may appear as the refusal vocabulary itself grows (they are
  already additive).
- Extension points reserved under this envelope, used by later arcs:
  - `data.source` / `data.snapshot` — source and snapshot completeness
    for content-bearing verbs (B-series); absent today.
  - `data.handoff` — thin-handoff transfer metadata; absent today.
  - `checkout` (B2) joins `verb` under this same envelope with
    `data.materialized` etc.; it does not get a second schema.
  - `data.content` — when a peer lacks content support, history success
    is reported separately from content incompleteness rather than
    folding them into one boolean.
- The envelope promises no stronger atomicity than the operation has:
  `partial`/`unknown` exist precisely because sync is not transactional.

## 7. Bounds, escaping, and secrecy

- A serialized envelope MUST be ≤ 64 KiB. Ordered id/path/conflict lists
  are capped at 256 entries; the remainder is counted in a sibling
  `<list>_omitted` key (`affected_omitted`, `ops_omitted`,
  `changes_omitted`, `conflicts_omitted`). Conflicts and stage ops are
  bounded by the store bounds and always fit under the cap once omitted
  counts apply.
- Strings are escaped exactly like the wire format — the Go-compatible
  escaping of `appendGoJSONString` (`\"`, `\\`, `\n`, `\r`, `\t`, control
  bytes as `\u00xx`, `<`, `>`, `&`, U+2028, U+2029). Adversarial commit
  messages and file names therefore stay valid JSON.
- Results never contain seeds, key material, auth files or their paths
  beyond what argv already carried, environment dumps, blob contents, or
  raw signed Change lines. Change ids, stream/workspace names, heads,
  counts, refusal names, and the resolved remote URL only.

## 8. Relationship to `SPECREV`

The envelope is a spec'd output surface a port implements against, so
this document and its fixtures are protocol-visible: `SPECREV` bumps
when the envelope or a listed `data` payload changes. `v` and `SPECREV`
are independent counters — `v` covers this schema's shape; `SPECREV`
covers the repo's whole protocol-visible surface including this schema.
A peer's `spec_rev` announcement is reported in `remote.spec_rev` when
present.
