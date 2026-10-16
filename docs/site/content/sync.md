---
title: Remote sync
parent: index
status: published
summary: clone, push, pull over FLINT-SYNC/1 — authenticated, verified, named refusals.
---

# History over TCP

The sync verbs speak `FLINT-SYNC/1` to a `flintd` server at
`tcp://host:port`. Remote resolution for `push`, `pull`, and `clone`
walks `--remote <url>`, then `FLINT_REMOTE`, then the workspace's
`REMOTE.json` — anything else refuses `remote_missing`.

## Clone a stream

```bash
flint clone tcp://127.0.0.1:4748 --stream=main --name=mirror --src=./src
```

Clone initializes the store, follows `forked_from` ancestry chains, and
re-verifies every Change before writing — `sig_invalid` aborts before
anything lands. It prints `flint: clone ok stream=<name> changes=<n>`.

Clone gives you history, not files: atoms land in `ATOMS.jsonl`, but no
source files are materialized. The src dir is created empty, a first
`status` shows a clean workspace, and `verify`/`log`/`merge`/`push`/`pull`
work regardless. Re-clone is allowed only as a fast-forward — divergent
histories refuse `fork_needed`.

## Push and pull

```bash
flint push --remote=tcp://127.0.0.1:4748 --stream=main
flint pull --remote=tcp://127.0.0.1:4748 --stream=main
```

`push` creates any ancestry streams missing on the server, then appends
the unsent suffix: `flint: push ok stream=<s> changes=<n>` or
`flint: push up to date`. `pull` reads after the local head, re-verifies
every pulled Change (`sig_invalid` writes nothing), and appends raw
lines: `flint: pull ok stream=<s> changes=<n>` or `up to date`.

Wire refusals print through unchanged: `flint: refuse stale_head`,
`flint: refuse auth_required`, and friends. On `stale_head` the refusal
detail names the recovery; on `stream_missing`/`stream_exists` the
client issues `list` and annotates the available streams.

## Authentication

Servers may challenge with a 16-byte nonce. The client answers with
`HMAC-SHA256(key, "FLINT-SYNC-AUTH/1\x00" || nonce)` where the key comes
from `--auth-key <file>` or `FLINT_AUTH_KEY` — a file path, never a
literal. Wrong or missing credentials refuse `auth_required` or
`auth_failed`.

## Divergence and recovery

When remote and local heads diverge, `pull` refuses `fork_needed`. The
recovery journey keeps both histories:

```bash
flint fork main aside          # keep the local head reachable
flint pull --reset             # append the remote log, roll to its head
flint merge aside              # net-effect 3-way merge
flint push                     # append the merge Change
```

`pull --reset` fetches and verifies the whole remote log, appends the
Changes the local log lacks, and rolls the head forward — refusing
`fork_needed` unless the local head stays reachable through another
stream's ancestry. Divergent local Changes remain in the log as
unreachable siblings; nothing is rewritten.

## Dead peers get deadlines

Every reply line is read under a per-reply deadline:
`--read-timeout=<sec>`, default 30. A silent peer ends with
`flint: error <verb> <remote>: timed out` instead of an open-ended hang.
`--read-timeout=0` refuses `usage` — zero is a config error, not
"forever."

<Aside kind="tip">

`flint version --remote=tcp://host:port` performs the `hello` handshake
without a store and reports the server's announced `spec_rev` (or
`unannounced` on older servers). It is the cheapest way to check that a
remote is alive and speaking `FLINT-SYNC/1`.

</Aside>
