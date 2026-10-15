# FLINT release streams — signed `release.go` manifest convention spec

A **convention**, not a feature arc: how an ordinary FLINT stream announces a
signed release of a binary artifact. FLINT stores structure, not bytes — a
Change carries atom hashes, no content — so distributing an ELF means the
stream carries a signed manifest declaration, the bytes travel an untrusted
path (HTTP, share drop), and verification is signature + hash end to end.

This is the consumer/producer contract VirelaiOS's install seam
(VirelaiOS#2315) implements against, and the basis for bringing
flint-produced artifacts into the guest. Read with `docs/adr-0049.md`
(§Primitives, §Store, §Canonical bytes — the ADR stays the contract),
`docs/flint-client-spec.md` (refusal vocabulary, verify semantics), and
`docs/flint-blobs-spec.md` (the optional content layer this convention does
not require).

## 0. Identity and hard rules

- **Nothing in FLINT changes.** No new verbs, ops, wire operations, store
  files, canonical bytes, or signature domains. A release stream is an
  ordinary stream; `release.go` is an ordinary Go file; the four release
  consts are ordinary `const` atoms. The convention is a *profile* over the
  existing model plus a verification pipeline the consumer runs.
- **The Change log is the only trusted artifact.** `release.go` bytes and
  ELF bytes are untrusted input at every step; each is authenticated
  against signed structure before use. `flint verify` proves integrity and
  *which key* signed (ADR §Canonical bytes); whether that key may publish
  releases is the consumer's keyring policy (§3), not FLINT's.
- **Order is the contract.** No consumer step may create or modify
  installed state before every earlier check passes (§3).
- **Refusal names are snake_case and contractual.** Exactly four new
  names: `release_missing`, `release_malformed`, `release_untrusted`,
  `release_mismatch`. Everything else reuses the client spec's
  vocabulary. `release_untrusted` deliberately does not reuse the wire
  `author_not_allowed`: that name is the server's append allowlist
  (who may write the stream at all), while this refusal is the
  consumer's release-keyring decision (who may declare release values)
  — a writer the server allows need not be a publisher the consumer
  trusts. Exit codes follow the client spec unchanged: `0` success,
  `1` refusal or error, `2` usage error (its merge-conflict `2` does
  not arise in this pipeline); `flint: refuse <name>`.
- Never print ELF content, key material, or seeds; diagnostics on stderr.

## 1. The release stream and `release.go`

A release stream is a stream whose workspace src root carries `release.go`
(span file exactly `release.go`). The file's package clause is pinned so
qualified atom names are uniform:

```go
package release

const ReleaseName = "FLINTDEMO"
const ReleaseVersion = "1.4.2"
const ReleaseELFSHA256 = "9f86d08…"   // 64 lowercase hex
const ReleaseManifestRow = "…"        // apps.txt schema-v2 row, one line
```

Normative form, enforced by the consumer at decode time:

- Each release const is a **single-name `const` spec whose value is exactly
  one interpreted string literal** — `const ReleaseName = "…"`, standalone
  or inside a `const (…)` group. Multi-name specs (`const A, B = …`),
  implicit-repeat (iota) specs, type annotations (`const N string = …`),
  and computed expressions are all `release_malformed`: the consumer
  decodes literal text per Go interpreted-string rules, it never evaluates
  Go.
- The Go declaration scanner makes each spec one atom of kind `const`,
  qualified name `release.Release{Name,Version,ELFSHA256,ManifestRow}`.
  The atom span runs from the const name through the value literal (the
  `const` keyword is outside the span), so the canonical token stream is
  `_ = "<literal>"` — the signed `new_hash` covers the literal's raw
  source spelling, quotes and escapes included, not the decoded value:
  `"\x46"` and `"F"` decode identically but hash differently, and the
  consumer decodes only after the hash check (§3 step 4). The name is
  bound through the op's `atom_id`/`new_name`, inside `ops_hash`,
  inside `sig`. Other declarations in `release.go` are ordinary atoms and
  carry no release meaning.
- A **release event** is a signed Change whose ops touch the
  release-atom positions: `add`/`modify` on one of the four atoms, or a
  `rename`, `move`, or `delete` that binds an atom into or out of a
  `(release.go, release.Release*)` position — a rename landing a new
  `release.go` atom counts even though it changes no hash. The
  **release state** at a Change is the atom-table state of the four
  consts there. Consts whose literals do not change produce no op, so a
  typical release Change modifies only `ReleaseVersion`,
  `ReleaseELFSHA256`, and `ReleaseManifestRow`.

## 2. Value grammar

All four consts must decode to these forms; a violation is
`release_malformed` naming the const:

| Const | Grammar | Meaning |
|---|---|---|
| `ReleaseName` | `[A-Z0-9][A-Z0-9_]{0,31}` | Installed image stem; the artifact installs as `<ReleaseName>.ELF`. The guest's ELF-stem rules are authoritative where stricter. |
| `ReleaseVersion` | semver 2.0 core `X.Y.Z` with optional `-prerelease`/`+build`, or calendar `YYYY-MM-DD` | Human-facing release label. |
| `ReleaseELFSHA256` | `[0-9a-f]{64}` | SHA-256 of the delivered ELF bytes, exactly as distributed. |
| `ReleaseManifestRow` | single line; no `\r`/`\n` after literal decoding | The apps.txt schema-v2 row the installer writes. Opaque to this convention — the installer validates it against the schema-v2 rules before writing it. |

## 3. Consumer verification pipeline

The consumer (VirelaiOS's install seam; any host-side verifier follows the
same order) runs these steps **in order**, refusing at the first failure:

1. **Sync and verify.** Obtain the stream by any transport — `clone`,
   `pull`, or a patch bundle — and re-verify every Change on the
   first-parent chain to head (pull's rule: `sig_invalid` aborts; nothing
   unverified is used). `flint verify` checks each Change's signature —
   integrity and which key signed — only; it does not establish parent
   linkage or that a log is the stream's current head. `clone` and
   `pull` enforce the chain-to-head rule on their own fetches; any other
   channel leaves the consumer to do that walk itself.
2. **Resolve the release state.** In the atom table at head, resolve the
   four release atoms by `(file="release.go", kind="const",
   name="release.Release*")`. Any absent → `release_missing`. A const that
   was renamed away or deleted is absent.
3. **Trust.** For each release const, find its **declaring changes** —
   the newest Change that established the atom's current `(file, name)`
   binding (`add`, `rename`, or `move`) and the newest Change that
   established its current hash (`add` or `modify`); one Change may be
   both. Every distinct declaring change's `author` must be a member of
   the consumer's release keyring (a set of Ed25519 public keys;
   VirelaiOS sources it from the M101b keyring path) →
   `release_untrusted`. Checking the declaring changes — not only the
   head — is required: a trusted head cannot vouch for consts last set
   by an untrusted earlier Change. Covering the binding, not only the
   hash, is required too: `rename` and `move` carry no `new_hash`, so a
   hash-only check would let an untrusted Change rebind a trusted-hash
   atom into a release position — recombining previously-signed values
   (v1's manifest row beside v2's ELF hash, or a rolled-back version
   label) that no trusted author announced. Both lookups ride the same
   first-parent walk of already-verified Changes: the binding ops carry
   `atom_id` + `new_name`/`new_span` inside `ops_hash`, inside `sig`, so
   each binding's author is authenticated. The normal case is one
   release Change declaring all four: one author check.
4. **Authenticate `release.go` bytes.** Obtain the file's text at head
   state by any channel — a blob checkout, a source export, or the same
   untrusted path the ELF will take — and run the declaration scanner.
   A file that fails to scan, or any of the four atoms whose recomputed
   hash differs from the signed head value → `release_malformed`. This step
   is what binds the literal text to the signature: any transport may carry
   the bytes.
5. **Decode and grammar-check** the four literals per §2 →
   `release_malformed`.
6. **Fetch and check the ELF.** The bytes arrive over the untrusted
   channel; a transport failure is an ordinary error (`flint: error …`),
   not a refusal. `sha256(elf) != ReleaseELFSHA256` → `release_mismatch`.
   The signature authenticates the *hash*; the hash authenticates the
   *bytes* — end to end with no trusted intermediary.
7. **Materialize, last.** Crash-safe write of the ELF to its install path
   (temp + fsync + rename + dir fsync), then the installer writes
   `ReleaseManifestRow` into `apps.txt` under its own atomic-update
   discipline. A crash anywhere earlier leaves installed state untouched.

## 4. Refusal table

| Condition | Refusal |
|---|---|
| A release atom absent at the verified head (missing const, renamed away, file never present) | `release_missing` |
| `release.go` fails to scan; recomputed atom hash ≠ signed head hash; const violates §1 form or §2 grammar | `release_malformed` |
| A binding- or hash-declaring change's `author` not in the consumer's release keyring — including an untrusted `rename`/`move` rebinding a trusted-hash atom into a release position | `release_untrusted` |
| `sha256(fetched ELF)` ≠ `ReleaseELFSHA256` | `release_mismatch` |
| Any Change signature failure during step 1 | `sig_invalid` (existing) |
| Stream unknown | `stream_missing` (existing) |

## 5. Producer contract

Producer tooling is the sibling issue (flint-client#49) and out of scope
here; the contract it must satisfy is §1 + §2: emit `release.go` in the
normative form with consts in the pinned order for readability, compute
`ReleaseELFSHA256` over the exact bytes to be distributed, then `flint add
release.go` + `flint commit` on the release stream with a key the target
consumers' keyrings trust. Nothing requires the tool — a hand-written
`release.go` committed by any FLINT client is a conforming release.

## 6. Conformance suite (the acceptance bar)

| Suite | Pass condition |
|---|---|
| Format goldens | A reference `release.go` scans to exactly the four `const` atoms with pinned names, spans, and hashes; each §2 grammar accepts its good fixtures and refuses its bad ones (uppercase hex, 63-char hash, `\n` in the row, typed const, multi-name spec). |
| Pipeline | Trusted declaring author → pass through step 6. Untrusted declaring author → `release_untrusted`. Untrusted `rename`/`move` rebinding a trusted-hash atom into a release position → `release_untrusted`. Missing const → `release_missing`. Literal edited after signing (hash no longer matches) → `release_malformed`. ELF byte flip → `release_mismatch`. Each leg asserts no installed state was created or modified. |
| Partial coverage | A head reachable only through Changes whose declaring authors mix trusted and untrusted keys → `release_untrusted`; a release where only some consts moved declares only those consts' authors. |

## 7. Open questions

- **Weaker trust rule.** "Head author ∈ keyring" alone was considered and
  rejected: it authenticates the announcement but not who set the consts.
  The declaring-change rule costs one extra walk and no new machinery.
- **Hash-only declaring change.** Anchoring trust to "who set the hash"
  alone would leave the `(file, name)` binding unauthenticated —
  `rename`/`move` carry no `new_hash` — so §3 step 3 checks the
  binding-establishing Change as well, on the same verified-log walk.
- **`ReleaseManifestRow` as structured consts.** Splitting the row into
  typed fields (name/version/paths) would make it self-checking but
  duplicates the guest's schema-v2 grammar in FLINT's vocabulary; the row
  stays opaque until the guest schema demands otherwise.

## 8. Explicitly out of scope (v1)

- `blob_get`/`blob_put` as a *requirement*. The convention deliberately
  keeps FLINT-SYNC/1 unchanged: `release.go` and the ELF may travel any
  untrusted channel, and where the optional content layer
  (`flint-blobs-spec` §4) is deployed it may carry `release.go`, but no
  step of §3 requires it.
- Producer tooling (flint-client#49).
- Guest-side install mechanics: the apps.txt schema-v2 grammar, ELF
  loader behavior, and atomic `apps.txt` update policy (VirelaiOS#2315's
  own spec).
- Keyring provisioning and distribution (M101b supplies it).
- Signing the ELF itself, multi-artifact releases, delta updates, and
  channel/latest pointers.
