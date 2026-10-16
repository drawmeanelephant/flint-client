---
title: Release streams
parent: index
status: published
summary: A signed release.go convention — the manifest rides the stream, the ELF rides anything.
---

# Signed manifests, untrusted bytes

FLINT stores structure, not bytes — a Change carries atom hashes, no
content. So a release stream is an *ordinary* stream whose workspace
carries `release.go`, a file with four ordinary `const` atoms that
announce a binary artifact. The signed manifest travels inside the
Change log; the ELF travels any untrusted channel — HTTP, a share drop,
sneakernet — and verification is signature plus hash, end to end.

Nothing in FLINT changes for this: no new ops, wire fields, store files,
or signature domains. The convention is a profile over the existing
model.

## The manifest

```go
package release

const ReleaseName = "FLINTDEMO"
const ReleaseVersion = "1.4.2"
const ReleaseELFSHA256 = "9f86d08…"   // 64 lowercase hex
const ReleaseManifestRow = "…"        // apps.txt schema-v2 row, one line
```

Each const must be a single-name spec with exactly one interpreted
string literal — multi-name specs, iota repeats, type annotations, and
computed expressions are all `release_malformed`. The signature covers
the literal's raw source spelling, quotes and escapes included.

## Mint a release

```bash
flint release --elf=./zig-out/bin/flint --name=FLINTCLIENT --version=1.4.2
```

`flint release` computes `sha256(<elf>)`, renders `release.go`, writes
it to the workspace src root, and stages + commits it through the normal
`add`/`commit` machinery — the usual signing path applies. Options:
`--manifest-row=<r>` supplies the apps.txt v2 row, `--key` selects the
signing key, `-m` overrides the `release <name> <version>` message, and
`--dry-run` prints the rendered file while touching nothing, not even
the store root.

A release carries exactly the `release.go` update, so a non-empty stage
refuses `stage_dirty`. Success prints the `add`/`commit` lines plus
`flint: release ok name=<n> version=<v> sha256=<h>`.

## The consumer's pipeline

Consumers — VirelaiOS's install seam, or any host-side verifier — run a
fixed-order pipeline, refusing at the first failure:

1. **Sync and verify.** `clone`, `pull`, or a patch bundle; re-verify
   every Change on the first-parent chain to head.
2. **Resolve release state.** The four atoms must exist at head under
   `release.go` → else `release_missing`.
3. **Trust.** The *declaring* changes of each const — both the change
   that bound `(file, name)` and the change that set the hash — must be
   authored by release-keyring keys → else `release_untrusted`. This
   covers `rename`/`move` rebinding, which carries no `new_hash`.
4. **Authenticate `release.go` bytes.** Re-scan the file; a hash
   mismatch against the signed head → `release_malformed`.
5. **Decode and grammar-check** the four literals → `release_malformed`.
6. **Fetch and check the ELF.** `sha256` mismatch → `release_mismatch`.
7. **Materialize, last.** Crash-safe write only after every check has
   passed; a crash earlier leaves installed state untouched.

The signature authenticates the hash; the hash authenticates the bytes.
No trusted intermediary anywhere.

## Spec revisions

`SPECREV` at the repo root is the pin-able protocol-visible revision.
`flint version` prints it:

```text
flint: version spec_rev=1 proto=FLINT-SYNC/1
flint: remote tcp://127.0.0.1:4748 proto=FLINT-SYNC/1 spec_rev=unannounced
```

`proto` is the hard gate — a mismatch refuses `proto_version`.
`spec_rev` is a finer-grained drift signal *inside* `/1`: two endpoints
with the same proto and different revs interoperate, and the delta is
exactly the revision-history rows between them. Servers announce their
rev optionally in `hello`; clients tolerate its absence.

Downstream ports pin a spec revision by pinning a commit — tag
`spec-r<rev>` names each bump, and the tag's `testdata/` corpus is the
conformance artifact, consumed verbatim. A corpus that needs editing to
pass is a divergence report upstream, not a patch downstream.
