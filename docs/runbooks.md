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
   To hand the rescue stream to another agent, `push --stream=<rescue-name>`:
   the preserved origin Change can never join a remote log (its `stream`
   field is inside the signed preimage), so push re-anchors the fork record
   to the merge that incorporated it — the merge's signed `merged` link keeps
   the original Change id for attribution.

Success: expected heads/ancestry, valid signatures, no missing local history.
The regression test filter `re-clone never overwrites` exercises this recovery.

## Torn/malformed store or invalid signature

For `stream_torn`, `change_malformed`, or `sig_invalid`, stop writes and
preserve the original files. Never truncate JSONL, repair signatures, or
rewrite a stream in place. Record the refusal, client version, affected
stream/change identifiers, and reproduction without exposing keys/source.
Recover to a separate store from a verified backup or trusted remote only
after a maintainer reviews the history. Keep the original for diagnosis.

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
