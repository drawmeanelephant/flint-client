---
title: The verb surface
parent: index
status: published
summary: init, add, status, commit, log, verify, fork, merge — plus keygen, release, version.
---

# Every verb is a contract

Output lines are `flint: `-prefixed, refusal names are contractual, and
exit codes are `0` success, `1` refusal or error, `2` usage error or
merge conflict. These lines match the Go reference implementation
exactly — they are observed behavior, not suggestions.

## Store and workspace

```bash
flint init --name=<n> --src=<dir> [--stream=<s>]
flint add [--ws=<n>] [file ...]
flint status [--ws=<n>]
```

`init` registers a workspace over an existing `--src` directory and a
stream (`main` unless named). Attaching to an existing stream replays
its head into the workspace's atom table.

`add` with no paths scans the whole src root. It prints a count line —
`flint: add files=<n> new=<n> modified=<n> deleted=<n> unchanged=<n>` —
and folds the diff into the stage. `status` prints the workspace,
stream, atom count, and up to 64 staged entries.

Workspace selection follows the Go `resolveWorkspace`: `--ws` names it;
otherwise the sole workspace wins; with several, path args under a `src`
select it, else the single workspace holding a stage, else the refusal
`ws_ambiguous`.

## History

```bash
flint commit [-m=<msg> | --message=<msg>] [--ws=<n>] [--key=<k>]
flint log [--stream=<s>] [--ws=<n>]
flint verify <id> | --all | --file=<log>
```

`commit` signs the staged ops as one Change — Ed25519 over the canonical
`FLINT-SIG/1` preimage — and appends it to the stream log. Messages are
1–512 bytes of valid UTF-8 (`message_invalid`); an empty stage refuses
`nothing_to_commit`. When a conflicted merge is in progress, the commit
resolves it: the Change records `merged=<id>` and prints
`flint: merge completed merged=<id>`.

`verify` checks signatures: `sig: verified` or `sig_invalid` per change,
exit 1 on any failure. `--file` checks a standalone log without a store.

## Streams

```bash
flint fork <from> <to>
flint merge <from> [--ws=<n>]
```

`fork` creates a stream at another's head. `merge` runs a net-effect
3-way merge on ops: clean merges print `flint: merge ok conflicts=0`,
conflicts print one `flint: merge conflict atom=<name> type=<t>` line
each and exit 2. On conflict the client writes `ws/<ws>/MERGE.json` —
edit the source, `add`, then `commit` to resolve it.

Merge refuses `stage_dirty` when the stage is non-empty. A merge Change
is always written; merges never fast-forward.

## Host-only verbs

```bash
flint keygen [--name=<n>]
flint parse-corpus <dir>
flint version [--remote=<url>]
```

`keygen` mints a named seed under `<store>/keys/`. `parse-corpus` is the
conformance harness — it parses every `.go`/`.zig` file in a directory
and writes `<dir>.OUT` for byte-for-byte corpus comparison. `version`
needs no store: it prints `flint: version spec_rev=<n>
proto=FLINT-SYNC/1`, and with `--remote` additionally reports what the
server announced in `hello` — see [[release|spec versioning]].

## Refusals are names, not sentences

A refusal prints `flint: refuse <name>` and the name is the API:
`usage`, `src_missing`, `ws_exists`, `ws_ambiguous`, `stream_missing`,
`stream_exists`, `stream_torn`, `stale_head`, `fork_empty`,
`stage_dirty`, `nothing_to_commit`, `message_invalid`,
`secret_not_found`, `store_too_large`, `store_not_found`, `key_exists`,
and the sync verbs' `fork_needed`, `remote_missing`, `remote_malformed`,
plus the FLINT-SYNC/1 wire refusals (`proto_version`, `auth_required`,
`auth_failed`, `author_not_allowed`, …), which print through unchanged.

<Aside kind="tip">

Local failures inside a sync verb — dial errors, transport drops —
print `flint: error <verb> <remote>: <reason>` with the resolved remote
URL and a lowercase phrase (`connection refused`, `unknown host`,
`timed out`), never a raw error token.

</Aside>
