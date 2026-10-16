---
title: Start here
parent: index
status: published
summary: Build once, init a store, mint a key, and land a signed commit.
---

# Make your first commit

Start with the local path. It proves the binary works without a server,
a network, or anyone else's permission.

## 1. Get the source

Install [Zig 0.17.0](https://ziglang.org/download/) and Git on macOS or
Linux. Run these commands in a terminal:

```bash
git clone https://github.com/drawmeanelephant/flint-client.git
cd flint-client
zig version
zig build -Doptimize=ReleaseSafe
```

`zig version` should print `0.17.0`. The build installs one executable,
`zig-out/bin/flint`. There is no npm install step, no daemon, and no
package manager involvement — the binary is static and stdlib-only.

## 2. Init a store and a workspace

```bash
export FLINT_STORE=/tmp/flint-demo
./zig-out/bin/flint init --name=demo --src=/path/to/your/source
```

Workspace names match `[a-z0-9-]{1,32}`. `--src` must already exist —
`init` registers an existing source tree rather than creating one.
The store root resolves in order: `--store <dir>`, then `FLINT_STORE`,
then a walk upward for a `.flint/` or `FLINT/` directory. If none is
found, the refusal is `store_not_found`.

## 3. Mint a signing key

```bash
./zig-out/bin/flint keygen --name=main
```

`keygen` writes `<store>/keys/main` — a 32-byte seed as 64 lowercase hex
chars, mode `0600` — and prints the derived Ed25519 public key. Commits
select a key by `--key <name>`, then `FLINT_SIGN_KEY`, then the store's
sole key; anything else refuses `secret_not_found`.

<Aside kind="tip">

Never pass a seed literal via `--key` or `FLINT_SIGN_KEY` on a shared
machine — it is visible in `/proc/<pid>/environ`, `ps` output, and shell
history. Key names are the preferred form; the literal exists for tests
and harnesses.

</Aside>

## 4. Stage and commit

```bash
./zig-out/bin/flint add --ws=demo
./zig-out/bin/flint status --ws=demo
./zig-out/bin/flint commit -m "initial structure" --ws=demo
```

`add` scans the src root and folds the result into the stage; `status`
reports staged additions, modifications, and deletions; `commit` signs a
Change and appends it to the stream's JSONL log — crash-safe, never
rewritten. The commit line names its id, op count, and parent.

## 5. Verify

```bash
./zig-out/bin/flint verify --all
./zig-out/bin/flint log
```

Each verified Change prints `flint: verify <id> sig: verified`. `log`
lists changes newest-first, capped at 64.

| You want | Next step |
|---|---|
| The full verb vocabulary | [[verbs|The verb surface]] |
| A remote server | [[sync|Remote sync]] |
| Signed binary releases | [[release|Release streams]] |

## Verify the build

```bash
zig build test --summary all
python3 tools/check.py
```

The test suite consumes `testdata/` — the conformance corpus copied
verbatim from the Go implementation — plus inline unit tests. `check.py`
runs the full gate: format, lint, build, tests, and a disposable CLI
journey against an in-process flintd fixture.
