# Local QA

## Fresh clone to an end-to-end CLI journey

Install Zig 0.17.0 from https://ziglang.org/download/ and Python 3.11+;
both executables must be on `PATH`. No pip packages, login, environment
variables, database, or external service is required.

From the repository root:

```sh
zig version
zig build
python3 tools/qa.py
```

The harness launches the real binary, verifies both good and bad signature
vectors, creates a source directory/workspace/key, stages a Go declaration,
commits, verifies history, reads the log, forks, and checks the clean stage.
It asserts exit codes, meaningful output, stored workspace identity, and key
permissions. It clears inherited `FLINT_*` variables and cleans its
temporary store/key on success or failure. Expected final line:
`CLI QA passed; temporary store and signing key removed.`

For a single manual interaction:

```sh
zig build run -- verify --file=testdata/sig/good.jsonl
```

Expected exit: 0, with `sig: verified`. The corresponding bad vector
`testdata/sig/bad.jsonl` must exit 1 with `sig_invalid`.
Do not run QA against a user's store.

## Local flintd substitute and remote/auth QA

The actual flintd service has its own deployment lifecycle outside this
repository. Local sync development does **not** require cloning that repo,
running a production daemon, or obtaining server credentials.

The checked-in `sync.InProcServer` fixture implements FLINT-SYNC/1 with
in-memory stores. This focused integration command starts a real listener
on **127.0.0.1 with an ephemeral port**, checks missing/wrong shared secrets,
author allowlists, fork ancestry, push, and clone, then closes the listener
and joins its server thread:

```sh
zig test src/main.zig --test-filter 'M106e auth challenge'
```

The fixture supplies test-only credentials and injects all required state.
No manual auth step is needed. This is the reproducible local service setup.
The broader remote journey is:

```sh
zig test src/main.zig --test-filter 'M106e remote verbs'
```

The complete-source sync journey (B3, `docs/flint-blobs-spec.md` §10) runs
against a real flintd on loopback — a fresh `clone` + `checkout` must
reproduce the publisher's tree byte-identically from FLINT content alone:

```sh
FLINTD=/path/to/flint-server/zig-out/bin/flintd python3 tools/content_sync_journey.py

The hostile-server suite (`tools/hostile_server.py`, mutating-proxy
clone/pull/push scenarios) is part of the automated gate:
`tools/tests/test_hostile_server.py` runs it under `tools/check.py`,
skipping with an explicit reason when no real `flintd` is found
(`FLINTD=<path>` overrides the default sibling checkout). A CI run without
a built `flintd` skips real-server tests — a skip is not a pass.
```

For an existing, explicitly authorized external flintd, configure
`FLINT_REMOTE=tcp://host:port` and a private key-file path in
`FLINT_AUTH_KEY`, using that server's documented auth/author policy.
Never send real stores/keys to an unknown server. Raw TCP is not TLS:
use an authenticated secure tunnel on untrusted networks.

## Instability

`python3 tools/check.py --phase test --repeat-tests 3` executes the tests
three times and retains every exit status and timing. A successful repeat
never hides an earlier failure. CI also runs this on a weekly schedule.
File an issue with the failing test name, platform, and redacted logs;
fix isolation or nondeterminism rather than adding skips or blind retries.
