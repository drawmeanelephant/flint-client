# FLINT host client — `ssh://` remote transport spec

Adds `ssh://` remotes to the `flint` client (`docs/flint-client-spec.md`),
alongside the existing `tcp://` form. The client spawns
`flintd serve --stdio` as an `ssh` child process and speaks `FLINT-SYNC/1`
over that child's stdin/stdout. No TCP, no new dependency: Zig 0.17.0
standard library only (`std.process.Child`).

`--stdio` exists precisely for this. The server spec says it "exists so the
same protocol can be hung behind any byte-stream transport — a TCP socket on
a POSIX host today, the runner's `--net-tcp-connect-stream` agent channel
(ADR 0044) when `FLINTD.ELF` lands in-guest, an `ssh` forced-command, or a
test harness pipe" (`flint-server-spec.md` §1). `FLINT-SYNC/1` is
"newline-delimited JSON over an ordered byte stream" and "transport-agnostic"
(§2), so `ssh` is a transport swap, not a protocol change.

## 0. Identity and hard rules

- Binary stays `flint`; Zig 0.17.0 stdlib only. `ssh` is spawned as a child
  process (`std.process.Child`); there is no in-process SSH client and
  **no shell on the local side, ever** — the child argv is passed as an
  array, and the remote command is one argv element, shell-quoted (§2).
- `ssh://` is a second remote form; `tcp://` behavior is unchanged.
  Remote resolution precedence is unchanged: `--remote` flag (or `clone`'s
  positional `<remote>`) → `FLINT_REMOTE` → `ws/<name>/REMOTE.json` →
  `remote_missing`.
- `REMOTE.json` round-trips `ssh://` URLs verbatim (`{"remote":"ssh://…","stream":"<id>"}`),
  query string included, and is validated at resolution time by the
  scheme-dispatched parser.
- The remote store path is **absolute**; a relative path is
  `remote_malformed`.
- Refusal names are snake_case. Exit codes are unchanged: `0` success, `1`
  refusal/error, `2` usage; `flint: refuse <name>`, or
  `flint: error <verb> <remote>: <reason>` for local failures, as today.
- Child stdout is protocol data only; the client never writes protocol bytes
  to its own stdout. Diagnostics go to stderr.
- Never print seeds, auth keys, or raw environment dumps. No GPL-family code.

## 1. CLI surface

URL grammar (EBNF-ish; anything else is `remote_malformed`):

```
ssh-url    = "ssh://" [ userinfo "@" ] host [ ":" port ] store-path [ "?" auth-query ]
userinfo   = user
user       = 1*( ALPHA / DIGIT / "." / "_" / "-" )     ; must not begin with "-"
host       = reg-name / ipv6-literal
reg-name   = 1*( ALPHA / DIGIT / "." / "_" / "-" )     ; must not begin with "-"
ipv6-lit   = "[" 1*( HEXDIG / ":" / "." ) "]"
port       = 1*5DIGIT                                  ; 1..65535; absent = ssh default
store-path = "/" segment *( "/" segment )              ; absolute; no "." / ".." segment
auth-query = "auth-key=" abs-path                      ; at most once; only recognized key
```

Refuse `remote_malformed` for: unknown scheme, empty user before `@`, empty
host, malformed bracketed literal, empty/non-numeric/`0`/`>65535` port,
missing or non-absolute store path, an empty path segment, `.`/`..`
segments, a fragment (`#`), an unknown query key, or a duplicate
`auth-key`. Path and query values refuse NUL, LF, and CR; they must be valid
UTF-8. Other bytes (including spaces) are legal and handled by quoting.

| Verb | Form |
|---|---|
| `clone` | `flint clone ssh://[<user>@]<host>[:<port>]/<path> --stream=… --name=… --src=… [--auth-key=<file>]` |
| `push` / `pull` | `flint push --remote=ssh://… [--stream=…] [--ws=…] [--auth-key=<file>]` (same for `pull`, `[--reset]`) |

| Flag | Meaning |
|---|---|
| `--remote=<url>` | Accepts `tcp://` or `ssh://` (unchanged otherwise). |
| `--ssh-flag=<f>` | Repeatable. When present at least once, replaces the `FLINT_SSH_OPTS` contribution for this invocation. |
| `--auth-key=<file>` | Unchanged: the local HMAC secret used to answer `flintd`'s challenge. |

| Env var | Meaning |
|---|---|
| `FLINT_REMOTE` | `tcp://` or `ssh://` URL; overridden by `--remote`. |
| `FLINT_SSH_OPTS` | Extra `ssh` flags, word-split on ASCII whitespace, no quote processing, no shell; appended after the base options. Empty ⇒ adds nothing. |
| `FLINTD_PATH` | Name of the remote `flintd` binary; default `flintd`. `PATH` lookup on the remote shell. Read locally; never exported to the remote. |
| `FLINT_AUTH_KEY` | Unchanged: local HMAC secret file path. |

**Layered auth (orthogonal).** `ssh` authenticates the channel.
`flintd --auth-key=<file>` may still gate the session with its HMAC
challenge on top. The remote command line carries `--auth-key=<remote path>`
**only** when the URL has `?auth-key=<remote path>`; otherwise the remote
`flintd` runs without it and decides for itself. The client's own
`--auth-key`/`FLINT_AUTH_KEY` supplies the local secret answering the
challenge; the two are independent and may be combined. A remote
`auth_required`/`auth_failed` envelope prints `flint: refuse <name>`,
distinct from the ssh-level `remote_auth_failed` (§3).

## 2. Spawn contract

### 2.1 argv

A pure builder `buildSshArgv(allocator, parsed_url, opts) ![][]const u8`
produces exactly:

```
[ ssh_exe,
  "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=accept-new",
  <FLINT_SSH_OPTS word-split…>,
  <--ssh-flag values, in order…>,
  (["-p", "<port>"] if the URL had a port),
  "<user@host>" | "<host>",
  "<remote-command>" ]
```

- `ssh_exe` defaults to `ssh` (local PATH lookup); tests inject a shim path
  (§4). A spawn error (`FileNotFound`, `AccessDenied`) is
  `remote_spawn_failed`.
- The host token is one argv element. `user`/`host` beginning with `-` are
  refused `remote_malformed` (ssh option injection); the grammar in §1
  bounds the rest.
- The port is `-p <port>`, never appended to the host token.
- Flag precedence: mandatory base options, then `FLINT_SSH_OPTS`, then
  `--ssh-flag` values in order. `ssh` resolves repeated `-o` last-wins, so a
  later flag overrides an earlier one, including a base option.

### 2.2 Remote command and quoting rule

Tokens: `[FLINTD_PATH, "serve", "--store=<path>", "--stdio"]`, plus
`"--auth-key=<remote path>"` only when `?auth-key=` is present. Each token
is shell-quoted, then the tokens are joined with single spaces; the result
is the final argv element.

Quoting rule (normative): wrap each token in `'` … `'` and replace every
embedded `'` with the four bytes `'\''`. A token containing NUL, LF, or CR
is `remote_malformed`. After quoting, `ssh`'s concatenation of its command
argv and the remote shell's single re-parse reproduce exactly the intended
token list; no token can widen into shell syntax. The store path and flags
are never interpolated into a shell string unquoted.

### 2.3 stdio discipline

- Three pipes: child stdin, stdout, stderr.
- stdout carries `FLINT-SYNC/1` NDJSON only, one request in flight. The
  client writes one request line, flushes, reads one response line.
- The first response the client reads must be a well-formed `hello` reply
  (`proto:"FLINT-SYNC/1"`). Anything else maps per §3.
- stderr is drained by a dedicated reader thread for the child's lifetime
  into a bounded tail (last 8 KiB) and is **never parsed**. It surfaces only
  as diagnostic text when a refusal/error is reported (`flint: ssh: …` on
  the client's stderr). ssh banners/MOTD land here and cannot corrupt the
  protocol stream.
- The client's stdout carries only normal CLI output (`flint: push ok …`);
  protocol bytes never leak to it.

### 2.4 Child lifecycle

- Normal: complete the session, close the child's stdin (EOF), wait with a
  bounded grace period (2 s), kill on timeout, reap. Exit status maps per
  §3.
- Refusal envelope mid-stream (`ok:false`): print `flint: refuse <name>`,
  stop sending, close stdin, grace-wait, kill, reap. The client never hangs
  on a non-fatal server refusal.
- Local protocol error (garbled stdout, wrong `seq`, EOF before a reply):
  tear down identically, then refuse `remote_proto`.
- Every child handle is torn down via `defer` (kill + wait); no verb returns
  with a live `ssh` child. One child per verb invocation; no session reuse.

## 3. Refusal mapping table

| Trigger | Detection | Result |
|---|---|---|
| URL syntax | user/host/port/path/query rule violated (§1) | `remote_malformed` |
| local `ssh` missing / not executable | `Child.spawn` errors | `remote_spawn_failed` |
| BatchMode auth refused | exit `255` and lowercased stderr contains `permission denied`, `authentication failed`, `no supported authentication methods`, or `too many authentication failures` | `remote_auth_failed` |
| other ssh transport failure | exit `255`, stderr without an auth pattern (connection refused/reset/timed out, unknown host, host key verification failed) | `remote_spawn_failed` |
| remote command missing | exit `127`, stderr contains `command not found` | `remote_spawn_failed` |
| remote `flintd` refusal | well-formed `ok:false` envelope | `flint: refuse <name>` (name passed through unchanged) |
| remote `flintd` usage error | exit `2` with no refusal envelope | `remote_proto` |
| remote `flintd` failure | exit `1` with no refusal envelope | `remote_proto` |
| stdout not flintd | first stdout line is not a well-formed `hello` reply, or `proto` mismatches | `remote_proto` |
| stdout EOF before reply | EOF mid-session | `remote_proto` |

`remote_auth_failed` is the ssh-channel failure; a wire `auth_failed`
envelope keeps its own name. All mapped refusals exit `1`, codes unchanged.

## 4. Conformance suite

- **fake-ssh shim** (`tools/fake-ssh`, checked in): records its full argv
  (NUL-separated) to `$FAKE_SSH_ARGV_LOG`, then replays `$FAKE_SSH_SESSION`
  on stdin/stdout. It first verifies that the last argv element, shell-word
  split, is exactly `flintd serve --store=… --stdio [--auth-key=…]`;
  otherwise it writes to stderr and exits `127`. Variants reproduce each §3
  row (exit `255` + `Permission denied`; exit `127`; `Welcome to Ubuntu` on
  stdout). No real `sshd` is needed. Unit tests inject the shim path as
  `ssh_exe`; black-box legs put the shim on `PATH` ahead of the real `ssh`.
- **Golden artifacts** (`testdata/ssh/`): expected argv (NUL-separated) and
  session NDJSON transcripts, byte-exact (field order, escaping). Covers
  `clone`/`push`/`pull`, an IPv6 literal, an explicit port, a space-bearing
  store path, a `'`-bearing store path, and `?auth-key=`.
- **Refusal-mapping leg**: table-driven; every §3 row asserts its refusal
  name and exit code.
- **Precedence leg**: `--remote` → `FLINT_REMOTE` → `REMOTE.json` →
  `remote_missing`; `--ssh-flag` vs `FLINT_SSH_OPTS`; `FLINTD_PATH` default;
  `REMOTE.json` `ssh://` round-trip.
- **Loopback leg** (optional): with a local `sshd`, run a throwaway tmpdir
  store through a real `ssh localhost`; skipped with a printed reason
  otherwise. Never touches an operator's store or keys.

## 5. Suggested card breakdown

| # | Card | Delivers | Suite legs |
|---|---|---|---|
| T1 | URL + argv builder | `parseSshRemoteUrl` (grammar §1), scheme dispatch in `resolveRemoteUrl`, pure `buildSshArgv` + quoting (§2.1–2.2), `remote_malformed` refusals | argv goldens, precedence, URL-grammar refusals |
| T2 | Spawn + stdio + lifecycle | `std.process.Child` spawn, three pipes, stderr reader thread, stdin/stdout framing, teardown/kill/wait (§2.3–2.4), §3 mapping, `remote_spawn_failed`/`remote_auth_failed`/`remote_proto` | fake-ssh shim, refusal-mapping table, golden sessions |
| T3 | Verb integration | `clone`/`push`/`pull` over `ssh://`, `--ssh-flag`/`FLINT_SSH_OPTS`/`FLINTD_PATH`, `?auth-key=` layered auth, `REMOTE.json` round-trip, loopback leg, docs | end-to-end sync journey over ssh, loopback |

## 6. Explicitly out of scope

- `ssh-agent` forwarding (`-A`) and agent/key selection policy.
- `ControlMaster`/connection multiplexing and persistent sessions.
- `ProxyJump`/`ProxyCommand` configuration and `known_hosts` management
  beyond `FLINT_SSH_OPTS` passthrough and `StrictHostKeyChecking=accept-new`
  (the user supplies the rest; the client adds none).
- Windows `ssh`; host targets stay linux/macos only.
- `scp`/`sftp`, remote store provisioning, and any remote binary discovery
  beyond `FLINTD_PATH`/`PATH`.
- Remote shell-profile/MOTD suppression (handled by the stderr policy).
- TLS and transport encryption: `ssh` is the encryption layer.
