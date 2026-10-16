# Operational runbooks

These procedures concern the local client, not administration of flintd.
Stop concurrent writers first. Preserve evidence and use a mode-0700 backup
directory outside the repository before a recovery operation. Backups can
contain private keys: never attach them to issues or upload them.

## Diverged remote history (`fork_needed`)

1. Stop push/pull attempts. Confirm the selected store, workspace, stream,
   and remote. Run `flint --store <store> log --stream=<stream>` and
   `flint --store <store> verify --all`. If verification fails, stop here.
2. Preserve the local head through another stream:
   `flint --store <store> fork <stream> rescue-<unique-name>`.
   Record the rescue stream and head. Do not re-clone over divergence.
3. With an authorized remote/auth configuration, run
   `flint --store <store> pull --ws=<workspace> --reset`.
   This refuses unless divergent local history remains reachable.
4. Run `flint --store <store> merge rescue-<unique-name> --ws=<workspace>`.
   On conflict, inspect `MERGE.json` and resolve intentionally.
   Do not repeatedly reset to make the conflict disappear.
5. Verify history again, inspect the log, then push only after reviewing the
   merge. A merge/clone changes metadata, **not source materialization**.
   Reconcile disk source before `add`; `src_behind` prevents a silent revert.
   To hand the rescue stream to another agent, `push --stream=<rescue-name>`.
   On a deposit-capable server (spec_rev 3) push deposits the preserved
   origin Change — with its unreachable ancestry — onto its own stream's
   remote log as detached lines: the fork record keeps the original
   `forked_from`, and a fresh clone can `verify` the original Change id
   against its original author's key. On an older server the origin can
   never join a remote log (its `stream` field is inside the signed
   preimage), so push falls back to re-anchoring the fork record to the
   merge that incorporated it — the merge's signed `merged` link keeps the
   original Change id for attribution, but the original bytes remain local.
   See the client spec §2.7 for the `deposit` wire contract.

Success: expected heads/ancestry, valid signatures, no missing local history.
The regression test filter `re-clone never overwrites` exercises this recovery.

## Stale staging base (`stage_stale`)

`commit` refuses `stage_stale` when the pending `STAGE.jsonl` was prepared
against a different stream head than the current one — typically a `pull`
(or `pull --reset`) or a sibling workspace's commit moved the head after
`add` ran — or when `ws/<name>/BASE.json` is missing entirely (unknown
staging provenance, e.g. a stage written by an older client).

The refusal is safe: staged ops, `ATOMS.jsonl`, source bytes, and history
are untouched. The guard exists because the staged diff was computed
against the old base; replaying it onto the moved head would silently
reparent old intent over peer edits.

1. Inspect what moved: `flint --store <store> log --stream=<stream>` and
   `flint --store <store> status --ws=<workspace>`. Compare the recorded
   base in `ws/<name>/BASE.json` with the current head.
2. Reconcile disk source with the pulled head intentionally (the workspace
   Atom table still reflects the old base until `add` re-diffs it).
3. Re-run `flint --store <store> add --ws=<workspace>` — this re-stamps
   `BASE.json` at the current head and is the explicit acknowledgment.
4. `flint --store <store> commit --ws=<workspace> -m <msg>` then succeeds.

There is no bypass flag; restaging is the documented acknowledgment. Do not
hand-edit `BASE.json` to force a commit — that reintroduces the silent
reparenting the guard prevents.

## Torn/malformed store or invalid signature

For `stream_torn`, `change_malformed`, or `sig_invalid`, stop writes and
preserve the original files. Never truncate JSONL, repair signatures, or
rewrite a stream in place. Record the refusal, client version, affected
stream/change identifiers, and reproduction without exposing keys/source.
Recover to a separate store from a verified backup or trusted remote only
after a maintainer reviews the history. Keep the original for diagnosis.

## Stream log with a repeated Change id

`flint verify --all` refuses `stream_malformed` naming the duplicated Change
and its stream log: an append-only log carries one line per id, and a repeat
is structurally invalid even though the line itself verifies (inflation can
arrive from a hostile or buggy peer response — the ingest path refuses it).
Detection changes no bytes; the store stays readable, and `status` still
loads it.

Recovery is explicit only — never truncate the log or rewrite the stream:

1. Copy the entire store directory to a backup location before touching it.
2. On a *copy*, remove the duplicated line(s) from `streams/<id>.jsonl`
   (the first occurrence is canonical; identical-byte repeats later in the
   log are the inflation).
3. `flint verify --all` against the copy confirms the log is sound again.
4. If the copy verifies, replace the original directory with the copy;
   otherwise restore the backup and escalate with the refusal detail.

## Missing/bad signing or auth key

Use a key **name** or private key-file path, not a seed literal. Check that
the selected store/key exists and that the file is owner-readable only.
Do not `cat` the key, dump the environment, or copy it into logs.
`secret_not_found` / `secret_malformed` must leave stage/history intact.
Generating a new key changes author identity; do not silently substitute it
for a lost key. For remote auth, confirm flintd's shared-secret/author policy
with its owner.

## Suspected bad release

1. Stop promotion; link the release tag, CI run, and redacted reproduction.
2. Inspect the release workflow's test, QA, coverage, quality, and checksum
   artifacts. The Actions summary is the deploy-impact entry point for this
   standalone binary, not a fictional production dashboard.
3. Reinstall the previous verified release binary if its store compatibility
   is suitable. Preserve stores first and verify after installation.
4. Fix forward through a reviewed PR and a **new** version tag. Never move a
   published tag or overwrite published artifacts. Re-run QA/conformance.

An owner must enable GitHub Actions failure notifications for active
alerting. This repository does not deploy a continuously monitored service.
