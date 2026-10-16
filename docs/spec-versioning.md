# Spec versioning — `SPECREV` and downstream pinning

FLINT's wire protocol, store format, and conformance corpus are consumed
verbatim by independent ports (the VirelaiOS guest FLINT in Go is the
first). `SPECREV` gives those ports a pin-able answer to "which protocol
do you speak": a single integer that bumps on every protocol-visible
change, plus a tag + corpus story for reproducing conformance runs.

## 1. The `SPECREV` file

The repo-root `SPECREV` file contains one decimal integer — the current
protocol-visible spec revision. `src/sync.zig`'s `SpecRev` constant must
equal it (`tools/tests/test_specrev.py` enforces the match), and
`flint version` prints it:

```
flint: version spec_rev=1 proto=FLINT-SYNC/1
```

`FLINT-SYNC/1` is the compatibility gate: a `proto` mismatch refuses
`proto_version` and nothing interoperates. `spec_rev` is a finer-grained
drift signal carried *inside* `/1` — two endpoints with the same `proto`
but different `spec_rev` interoperate, and the delta is exactly the
revision-history rows between the two revs.

## 2. What is protocol-visible

Bump `SPECREV` (+1, no skipping) when a change alters anything a
downstream port or a `flintd` peer must reproduce:

- **Wire surface** — `FLINT-SYNC/1` ops, request/response field names
  and shapes, the refusal-name vocabulary, wire bounds (4 MiB lines,
  read limits), auth challenge semantics.
- **Byte contracts** — canonical bytes, domain separators, hash
  construction, Go-compatible JSON escaping, JSONL framing, store layout
  and record fields.
- **Spec text** — normative changes to `docs/flint-client-spec.md`,
  `docs/adr-0049.md` errata, or any `docs/*-spec.md` section a port
  implements against.
- **Corpus** — any change under `testdata/` that alters expected output
  (MANIFEST rows, canon goldens, merge scenarios, sig vectors). Adding
  new fixtures counts; the corpus at rev N is the conformance artifact.

Do **not** bump for: internal refactors, test-only changes, CLI wording
that adds no wire-visible field, comment/typo fixes, tooling under
`tools/`, or performance work.

Every bump adds one row to the revision history below with the rev, the
change, and the issue/PR that drove it. One row per rev — a PR that
makes several protocol-visible changes still bumps once.

| Rev | Change | Ref |
|---|---|---|
| 1 | `SPECREV` convention; client parses optional `spec_rev` in `hello` replies; `flint version` verb | [#50](https://github.com/drawmeanelephant/flint-client/issues/50) |
| 2 | `ws/<name>/BASE.json` staging-base record (`{"head":…}`); `add` stamps it, `commit` refuses `stage_stale` when the recorded base differs from the current head or is missing | [#67](https://github.com/drawmeanelephant/flint-client/issues/67) |
| 3 | `deposit` op: detached Change lines in stream logs (store + wire contract, reader rules, push policy); `pull` reads the log suffix even when heads match; re-clone fast-forward compares id order | [#73](https://github.com/drawmeanelephant/flint-client/issues/73) |
| 4 | `--json` result envelopes v1 (`docs/flint-json-results-spec.md`): one structured result per invocation for `status`, `add`, `commit`, `merge`, `push`, `pull`, `clone`, `verify` | [#79](https://github.com/drawmeanelephant/flint-client/issues/79) |

## 3. The `hello` `spec_rev` field

A server may announce its spec rev in the `hello` success reply:

```json
{"seq":1,"ok":true,"proto":"FLINT-SYNC/1","server":"flintd","spec_rev":1}
```

The field is **optional and additive**. This client parses a
non-negative integer `spec_rev` when present, tolerates its absence (and
a non-integer value) as unannounced, and never refuses on it —
`proto` remains the only hard gate. Server-side announcement is tracked
in [flint-server#34](https://github.com/drawmeanelephant/flint-server/issues/34).

`flint version --remote=<url>` (or `FLINT_REMOTE`) performs the
handshake and reports what the server announced:

```
flint: version spec_rev=1 proto=FLINT-SYNC/1
flint: remote tcp://127.0.0.1:4748 proto=FLINT-SYNC/1 spec_rev=unannounced
```

## 4. Pinning and the conformance corpus

A downstream port pins a spec revision by pinning a commit:

1. Pick the rev (e.g. `spec_rev=1`). The matching tag is `spec-r<rev>`
   — maintainers tag the commit that lands each bump.
2. Vendor or submodule the repo at that tag. The versioned artifact is
   the tag itself: `docs/` specs plus the full `testdata/` corpus.
3. Run the corpus verbatim — `testdata/corpus/` + `MANIFEST.json` (atom
   spans and both hashes), `testdata/canon/*.txt` (canonical token
   streams), `testdata/merge/*.json` (net-effect merge scenarios),
   `testdata/sig/*` (Ed25519/sign preimage vectors). This repo's
   conformance legs live in `src/main.zig`'s `zig build test`; a port
   reimplements the legs, not the fixtures. §4 of
   `docs/flint-client-spec.md` is the acceptance bar.
4. Never modify fixtures locally — a corpus that needs editing to pass
   is a divergence report upstream, not a patch downstream.

Tags: `git tag spec-r<N> <merge-commit>` when `SPECREV` bumps. There is
no release machinery; a signed note on the tag is optional. If the repo
later gains GitHub releases, attach the same `testdata/` tree as the
artifact — the tag remains the canonical pin.

## 5. Both repos

`SPECREV` exists independently in `flint-client` and `flint-server`
([flint-server#34](https://github.com/drawmeanelephant/flint-server/issues/34)).
The two revs need not match — each tracks its own repo's
protocol-visible surface. A port pinning the pair records both.
