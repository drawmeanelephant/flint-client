# FLINT handoffs and proposals — spec

Signed **handoff records** let one agent hand revision-bound work to
another: who owns it, what it is based on, which exact candidate and
source snapshot were validated, and whether it is ready to integrate.
This is the first slice of the
[roadmap](git-replacement-roadmap.md) §5 wave-3 "Proposals" arc — pull
requests as store objects — scoped to a minimal, portable record over the
existing signed store. It is not a scheduling, code-hosting, or approval
platform.

Read with `docs/adr-0049.md` (primitives, canonical bytes — the ADR stays
the contract), `docs/flint-client-spec.md` (vocabulary, verify semantics,
the spec_rev 3 detached-Change rules of §2.7), and
`docs/flint-patch-spec.md` (the byte-verbatim file-transport discipline
the handoff packet reuses).

**Dependencies.** This spec is written against contracts still in
review; the citations are load-bearing, not blocking:

- [#77](https://github.com/drawmeanelephant/flint-client/issues/77)
  defines complete source snapshot identity/trust. The record's
  `snapshot` field is an opaque, bounded string whose concrete shape is
  **inherited from #77's reviewed contract** when it lands; until then it
  may be `null` (proposal is still valid; completeness reports honestly).
- [#78](https://github.com/drawmeanelephant/flint-client/issues/78),
  [#80](https://github.com/drawmeanelephant/flint-client/issues/80), and
  [flint-server#43](https://github.com/drawmeanelephant/flint-server/issues/43)
  provide materializable source handoff. The `ready` verdict's content
  leg is defined here but only reports `complete` once the reviewed
  snapshot/content path exists.
- [#79](https://github.com/drawmeanelephant/flint-client/issues/79)
  supplies the versioned JSON result envelope. `--json` on these verbs
  uses that schema; this spec invents no parallel envelope.
- Change availability uses the resolved #67/#72/#73 guarantees:
  `stage_stale`/`src_behind` untouched, and `deposit` (spec_rev 3)
  carries original signed work wherever it must travel.

## 0. Identity and hard rules

- Binary `flint`, Zig 0.17.0, standard library only. No new dependency.
- **Existing signatures do not change.** `sig_msg`, `ops_hash`, the
  Change/Op/Stream field sets, and all corpora are untouched. A
  handoffs-enabled store verifies byte-identically with today's
  `verify`. Handoff records are a *new signed record type* with their
  own domain separator — never a Change, never an Op.
- **Logs stay append-only.** `handoffs/<stream-id>.jsonl` follows the
  `manifests/` discipline: append + fsync, never rewritten, torn final
  line refuses. Records are immutable; lifecycle is expressed by
  appending new records, never by editing one.
- **Byte-verbatim transport.** Packets carry record lines and Change
  lines exactly as stored — parsed only to verify, never re-serialized
  (the patch-spec rule).
- **Verify before write.** Every record appended locally or imported
  re-verifies its Ed25519 signature first; `sig_invalid` writes nothing.
- **Assertions are not evidence.** A signed `pass` claim is the
  attestor's signed statement, not proof the command ran. No FLINT verb
  ever executes a validation command found in a record — commands are
  inert data.
- **Scope grants nothing.** Declared owner/scope is an advisory claim,
  never a lock, lease, or access grant.
- **Readiness is revision-bound.** Verdicts bind to the observed target
  head and the candidate/snapshot ids. Any head movement after
  validation or acceptance invalidates readiness until re-established;
  nothing is silently reused.
- **Handoffs never move heads.** Creation, inspection, export, and
  import never advance a stream head, rewrite history, discard staged
  work, or bypass `stage_stale`/`src_behind`. Integration happens only
  through the existing semantic `merge`/`commit`/`push` path.
- Refusal names are snake_case and contractual. Exactly five new names:
  `handoff_torn`, `handoff_malformed`, `handoff_missing`,
  `handoff_closed`, `handoff_author`. Exit codes unchanged: 0 success,
  1 refusal, 2 usage.
- Never print record payloads' free-text fields unbounded, key
  material, blob content, or store internals; diagnostics on stderr.
- **SPECREV:** this document is spec-first. The bump lands with the
  first implementation card (H1) per `docs/spec-versioning.md` — the
  record format, `handoffs/` layout, refusal names, and corpus fixtures
  are protocol-visible vocabulary.

## 1. Record format

A handoff record is one JSON object, UTF-8, emitted in the field order
below (client spec §2.5 discipline: fixed order, Go-compatible escaping,
lowercase hex, canonical UUIDs). `format` is the literal
`"FLINT-HANDOFF/1"`; the `/N` suffix is the version, handled per §6.

### 1.1 Envelope fields (all kinds)

| Field | Type | Meaning |
|---|---|---|
| `format` | `"FLINT-HANDOFF/1"` | Record version marker. |
| `id` | uuid | This record's id (UUIDv7, minted at write). |
| `handoff` | uuid | The proposal this record applies to — the `id` of its `propose` record. On `propose`, `handoff == id`. |
| `kind` | string | `propose` \| `attest` \| `accept` \| `supersede` \| `withdraw`. |
| `stream` | uuid | The **target** stream the work proposes to integrate into. The record lives in that stream's `handoffs/` log. |
| `ts` | int | `now*1000` ms, same clock contract as Change `ts`. |
| `author` | 64-hex | Ed25519 public key of the signer. |
| `sig` | 128-hex | Ed25519 over `handoff_msg` (§1.4). |

### 1.2 Payload fields (per kind)

All payload fields are optional at the *encoding* layer; requiredness
per kind is a validation rule (§1.5). Writers omit absent fields
entirely — an explicit `null` (allowed on `snapshot`/`replacement`) and
an empty array/object are read identically to an omitted field and are
never emitted.

| Field | Type | Kinds | Meaning |
|---|---|---|---|
| `base` | uuid | propose (required) | The target stream head the candidate is based on — the revision the work was cut at and validated against. |
| `work` | uuid | propose (required) | The stream hosting the candidate chain. May equal `stream` when proposing detached work already on the target's log. |
| `candidate` | uuid | propose (required); attest, accept, supersede (required) | Tip Change of the proposed work on `work`. Immutable once proposed — a revised candidate is a new proposal (supersede + propose). |
| `snapshot` | string \| null | propose, attest | Immutable source-snapshot reference, opaque here, shape per #77's reviewed contract. `null` pre-#77 or when content was not captured. |
| `intent` | string | propose (required) | What the work does and why, 1–512 bytes valid UTF-8 (the `message` bound). |
| `note` | string | accept, supersede, withdraw | Optional free text, ≤512 bytes UTF-8. |
| `scope` | object | propose | Advisory write-set claim `{"paths":[…],"atoms":[…]}` — relative src paths (`/` separators) and qualified Atom names the work claims to touch. A claim, not a lock. §4. |
| `validations` | array | propose (optional, self-asserted); attest (exactly one) | Validation objects, §1.3. On `propose` every entry's `attestor` must equal the record's `author` (self-assertion). On `attest` the single entry is an independent assertion; its `attestor` must equal the `attest` author. |
| `observed_head` | uuid | accept (required) | The target stream head the acceptor observed at acceptance. Binds acceptance to a revision; a head move afterwards makes the acceptance stale (§5). |
| `replacement` | uuid \| null | supersede | The `handoff` id of the replacing proposal, if any. |

### 1.3 Validation object

```json
{"command":"zig build test --summary all","result":"pass",
 "toolchain":"zig 0.17.0","env":"aarch64-macos, clean worktree",
 "attestor":"<64-hex>","ts":1760000000000,"evidence":"<opaque ref>"}
```

- `command` (string, ≤1024 bytes): the asserted invocation, **data
  only**. `args` are part of the string; there is no structured argv.
- `result` (string): `pass` \| `fail` \| `skip`.
- `toolchain`, `env` (string, ≤256 bytes each): toolchain/environment
  context — advisory, free-form.
- `attestor` (64-hex): the asserting key; must equal the enclosing
  record's `author` (§1.5).
- `ts` (int): assertion time, ms.
- `evidence` (string \| null, ≤256 bytes): an opaque reference (digest,
  log pointer) to captured output — never the output itself.

### 1.4 Canonical signing — `handoff_msg`

Ed25519 over a typed preimage, same construction style as `sig_msg`
(ADR §Canonical bytes; `str`, `opt`, `u32le`, `u64le` helpers are the
ADR's). JSON is the carrier, not the signed form.

```
kind_code: propose=1 attest=2 accept=3 supersede=4 withdraw=5
result_code: pass=1 fail=2 skip=3

val_bytes(v) = str(command) || u8(result_code) || opt(str(toolchain))
             || opt(str(env)) || attestor[32] || u64le(ts)
             || opt(str(evidence))

scope_bytes  = u32le(n_paths) || str(path_i)…    // paths sorted byte-wise
             || u32le(n_atoms) || str(atom_j)…   // atoms sorted byte-wise
scope_hash   = SHA-256("FLINT-HANDOFF-SCOPE/1\x00" || scope_bytes)

vals_bytes   = u32le(n) || val_bytes(v_i)…       // in emitted array order
vals_hash    = SHA-256("FLINT-HANDOFF-VALS/1\x00" || vals_bytes)

handoff_msg  = "FLINT-HANDOFF/1\x00"
             || id[16] || handoff[16] || u8(kind_code) || stream[16]
             || u64le(ts) || author[32]
             || opt(base[16]) || opt(work[16]) || opt(candidate[16])
             || opt(observed_head[16]) || opt(replacement[16])
             || opt(str(snapshot)) || opt(str(intent)) || opt(str(note))
             || opt(scope_hash) || opt(vals_hash)

sig          = Ed25519(handoff_msg, seed); author = derivePublic(seed)
```

`scope`/`validations` enter as digests so the preimage stays
fixed-shape; `opt()` distinguishes absent from empty on every payload
field, so an `accept` can never be confused with a `propose` carrying
empty claims.

### 1.5 Validation rules (write path and import)

In order; every check runs before any append:

1. Framing: parses as one JSON object; `format` is exactly
   `FLINT-HANDOFF/1`; all ids are canonical UUIDs; `author`/`sig` are
   lowercase hex of the right length; `ts` > 0; free-text fields valid
   UTF-8 within bound. Violations: `handoff_malformed`.
2. Per-kind required fields and exclusivity (a `propose` must not carry
   `observed_head`; a `withdraw` carries no ids, etc.) and `handoff ==
   id` iff `kind == propose`. Violations: `handoff_malformed`.
3. `attestor` equality inside `validations` per §1.2/§1.3. Violation:
   `handoff_malformed` (`attestor mismatch`).
4. Signature verifies against `author`. Violation: `sig_invalid`.
5. Lifecycle (against the target stream's `handoffs/` log): a `propose`
   whose id is already present, or any record reusing an existing record
   `id` under different bytes, refuses `handoff_malformed`
   (`id conflict`); an event record naming an unknown `handoff` refuses
   `handoff_missing`; an `accept`/`supersede`/`withdraw` on a terminated
   proposal refuses `handoff_closed` (`attest` is allowed on terminated
   proposals — evidence may arrive late); `withdraw` signed by any key
   other than the proposer's refuses `handoff_author`; `supersede`
   naming a `replacement` that is not a known live proposal refuses
   `handoff_missing`.
6. Local resolvability for `propose` via the write verb: `stream` and
   `work` must name local streams (`stream_missing`), `base` must be a
   Change in `stream`'s log and `candidate` a Change in `work`'s log
   (`change_missing`). Packet **import** does not apply this rule —
   records are portable claims; a receiver that lacks the ancestry gets
   an honest `incomplete` verdict from `inspect` (§5), not a refusal.

## 2. Store layout

```
<store>/
  handoffs/<stream-uuid>.jsonl   one record line per lifecycle event, append-only
```

- One log per **target** stream — "what is proposed for `main`" is one
  file read. A record is appended under the id in its `stream` field.
- Line bound 64 KiB per record (`handoff_malformed`); log bound 4096
  lines (`store_too_large`, the Change bound's shadow). An empty line is
  `handoff_malformed`; a final line not ending in `\n` is
  `handoff_torn` (never auto-truncate).
- **Index impact: none.** The every-invocation index still scans only
  `streams/` and the selected workspace; `handoffs/` is loaded lazily by
  the handoff verbs, like `manifests/`.
- **Portability both ways.** A handoffs-enabled store opens read-only
  in a pre-handoffs client (new top-level dir ignored, same rule as
  `blobs/`). A pre-handoffs store gains `handoffs/` lazily on first
  write.

## 3. Lifecycle

A **proposal** is the set of records sharing one `handoff` id, folded in
append order. The fold produces exactly one state:

```
proposed ──accept──▶ accepted          (terminal)
   │  └──supersede─▶ superseded        (terminal; may name replacement)
   └──withdraw───▶ withdrawn          (terminal; proposer only)
```

`attest` records attach evidence to a live or terminated proposal and
never change its state. The fold stops at the first terminal record;
records after it are counted and reported as `extra_records=<n>` by
`inspect` rather than silently dropped — an append-only log shows what
it holds.

There is no "rejected" kind: a declined proposal is `supersede`d (by
anyone — it simply asserts the proposal is no longer the live one) or
`withdraw`n (proposer only). No record ever deletes or revises a prior
record; "the proposal changed" means "a new proposal exists".

## 4. Trust model

- `author` proves **integrity and which key signed** — identical
  semantics to `verify` on a Change. Trust roots/policy remain out of
  scope; receivers apply their own acceptance policy.
- A `propose` asserts: *this key claims this candidate, on this work
  stream, based on this target head, with this intent, this advisory
  scope, and these self-reported validations.* The proposer need not be
  the candidate Changes' author — a coordinator may propose another
  agent's work; the Changes carry their own signatures regardless.
- An `attest` is an **independently signed** assertion bound to
  `candidate` + `snapshot` — this is the "independently verified
  evidence" lane. It is still a claim, not proof of execution; its
  value is that it is a *different* key making a bound, inspectable
  statement. `inspect` keeps self-asserted (`propose`-embedded) and
  independent (`attest`) validations visibly separate in its output.
- An `accept` is the integrator's signed assertion bound to
  `observed_head` + `candidate`. It cannot be replayed onto a different
  head or candidate without failing verification of intent — the ids
  are inside the signature.
- `scope` never authorizes anything. `inspect` compares the declared
  scope against the actual Ops union of the Changes reachable from
  `candidate` but not from `base`, and reports `scope=honest` /
  `scope=exceeded` / `scope=unverifiable` (ancestry incomplete) as
  advisory output — a discrepancy is information for the receiver, not
  a refusal.
- Validation commands are inert data. Importing, listing, or inspecting
  a record never spawns a process; an operator re-runs a command
  deliberately in its own environment and records the outcome as their
  own `attest`.

## 5. Inspection and readiness

`inspect` verifies every record for the handoff id (signature + §1.5
rules 1–4), folds the lifecycle, and computes a **verdict** from
locally observed state — never from claims alone:

| Verdict | Meaning |
|---|---|
| `ready` | `proposed`, no terminal record; candidate ancestry fully present locally; observed target head == `base`; content complete for `snapshot` (post-#77 path) or explicitly content-degraded. |
| `accepted` | Terminal `accept` whose `observed_head` still equals the current target head and whose `candidate` still resolves. Integration may proceed through `merge`. |
| `accepted_stale` | `accept` exists but the target head moved past `observed_head` (or the candidate no longer resolves): the signed acceptance is intact, readiness must be re-established — re-inspect, re-`attest`, re-`accept`. |
| `stale` | `proposed`, but the observed target head no longer equals `base`: prior validation may no longer describe this integration. |
| `conflicting` | The candidate chain is present and a **dry** semantic merge fold (pure, writes nothing) reports conflicts against the current head. |
| `incomplete` | Referenced Changes are missing locally (unknown `base`/`candidate` ancestry), or required content/snapshot is unavailable. Nothing was refused; the state is reported, not hidden. |
| `invalid` | Any record fails signature or framing, or violates a per-kind rule. |
| `unknown` | The only records carry an unrecognized `format` version (§6). |
| `superseded`, `withdrawn` | Terminal states with no live acceptance; the verdict echoes the state. |

Verdicts compose state + freshness + completeness; they are computed,
never stored, so a moved head invalidates `ready`/`accepted` on the very
next `inspect` — there is nothing to go stale silently.

Integration flow for an accepted (or ready) proposal: the receiver
pulls `work` to hold the candidate ancestry, then runs the ordinary
`merge <work>` → resolve → `commit` → `push` path on the target
workspace. The merge Change's `merged` link already names the folded-in
head; `push`'s spec_rev 3 deposit policy publishes whatever detached
ancestry that link resolves to. Handoffs add no second history-mutation
mechanism.

## 6. Invalid and unknown-version handling

- Writers produce only `FLINT-HANDOFF/1` records; a writer asked to emit
  anything else is a bug, not a mode.
- A record whose `format` is `FLINT-HANDOFF/2+`, a different domain, or
  absent is **not** refused at read time: `inspect`/`list` classify it
  `unknown_version`, exclude it from the lifecycle fold, and report the
  count — a distinguishable safe outcome, not a silent skip. On the
  write/import path an unrecognized `format` refuses
  `handoff_malformed` (`unknown format`) — a v1 store only stores what
  it fully understands; forward compatibility is a reader property.
- A non-JSON line is `handoff_malformed`; a torn final line is
  `handoff_torn`; a well-formed `/1` record failing signature is
  `sig_invalid` (import writes nothing; inspect verdict `invalid`).

## 7. Portable transfer — the handoff packet

Records replicate by **file**, not wire op: server-side proposal
hosting/approval RPCs are the separate V6 arc and are not required for a
usable handoff. The packet follows the FLINT-PATCH/1 discipline
(NDJSON, byte-verbatim payload lines, header parsed never byte-matched):

```
line 1              {"format":"FLINT-HANDOFF-PACKET/1","handoff":"<id>",
                     "stream":"<target-uuid>","work":{"id":"<work-uuid>","name":"<work-name>"},
                     "records":<n>,"changes":<m>}
lines 2..n+1        the handoff's record lines, byte-verbatim, append order
lines n+2..n+m+1    optional: the candidate's detached ancestry — raw Change
                    lines of the work stream's log, byte-verbatim
```

- `changes` is the ancestry-complete detached set ending at `candidate`,
  under exactly the deposit batch rules (every `parent` null, already
  in the target log / `forked_from.change`, or earlier in the section;
  dedupe by id; same-id-different-bytes is malformed). `m == 0` when the
  receiver is expected to fetch via sync.
- Framing refusals reuse the record vocabulary: `handoff_torn`,
  `handoff_malformed` (bad header, count mismatch, malformed line,
  Change `stream` field ≠ `work.id`, broken ancestry), plus the
  Change-level `change_malformed`, `sig_invalid`, `store_too_large`.
- **Import** verifies everything before writing: record signatures,
  lifecycle legality for what is being appended, Change signatures and
  detached-ancestry rules. Then, all-or-nothing per section: append the
  missing Change lines to `streams/<work>.jsonl` (creating the work
  stream record from header name + verified fork data when absent and
  ancestry permits — the bundle-import trick), and append the record
  lines to `handoffs/<stream>.jsonl`. Dedupe by id applies to both
  sections: byte-identical lines skip, the same record or Change id
  under different bytes refuses `handoff_malformed`/`change_malformed`
  (`id conflict`); re-import of the same packet is a no-op, not an
  error. `stream` (target) must exist locally — `stream_missing`
  otherwise; records are claims *on* a stream the receiver holds.
- **Online path:** the proposer `push`es `work` — append publishes the
  candidate chain, and spec_rev 3 `deposit` already covers detached
  ancestry (e.g. rescued fork work) — then moves the packet out of
  band. The receiver `pull`s/imports, runs `handoff import`, then
  `handoff inspect`.
- **Offline path:** `flint export --stream=<work>` produces the
  companion bundle; the packet carries `changes=0`. Or `--with-changes`
  for a single artifact. Either way the receiver holds the original
  signed bytes — `verify` checks them against their own authors'
  keys, unchanged.

## 8. CLI surface

`handoff` is one verb family; sub-verbs below. Workspace/stream
resolution, key resolution (`--key` → `FLINT_SIGN_KEY` → sole key →
`secret_not_found`), exit codes, and `flint: `-prefixed contractual
lines are the existing rules. `--json` lands under #79's envelope, not
a bespoke one.

| Verb | Notes |
|---|---|
| `flint handoff propose --stream=<target> --work=<s> [--candidate=<id>] [--base=<id>] [--snapshot=<ref>] -m=<intent> [--scope-file=<f>] [--validations=<f>] [--key=<k>]` | `candidate` defaults to `work`'s head, `base` to the target's current head. `scope` is derived from the actual Ops union of the candidate's delta (§4) unless overridden by `--scope-file=<f>` (JSON `{"paths":[],"atoms":[]}`) — derived-by-default keeps the claim honest. `--validations=<f>` embeds self-asserted §1.3 objects (a JSON array; `attestor` is the signer). Writes the `propose` record to `handoffs/<target>.jsonl`; the workspace and stage are never touched (`stage_dirty` does not apply). Prints `flint: handoff <id> kind=propose stream=<s> candidate=<id>`. Refuses `stream_missing`, `change_missing`, `handoff_malformed`, `secret_not_found`. |
| `flint handoff attest <handoff-id> --command=<s> --result=pass\|fail\|skip [--toolchain=<s>] [--env=<s>] [--evidence=<s>] [--key=<k>]` | Appends an `attest` record binding the proposal's current `candidate`/`snapshot`. Prints `flint: handoff <handoff> kind=attest id=<rid>`. Unknown id → `handoff_missing`; terminated is *allowed* (evidence may arrive late). |
| `flint handoff accept <handoff-id> [--note=<s>] [--key=<k>]` | Appends `accept` bound to the proposal's `candidate` and `observed_head` — recorded from the local stream record, never an argument (you accept what you can see). Refuses `stream_missing` when the target is absent, `change_missing` when the candidate's ancestry is not held locally, `handoff_missing` / `handoff_closed` as applicable. Prints `flint: handoff <handoff> kind=accept id=<rid> observed_head=<id>`. |
| `flint handoff supersede <handoff-id> [--replacement=<id>] [--note=<s>] [--key=<k>]` | Prints `flint: handoff <handoff> kind=supersede id=<rid>`. |
| `flint handoff withdraw <handoff-id> [--note=<s>] [--key=<k>]` | Proposer's key only — `handoff_author` otherwise. Prints `flint: handoff <handoff> kind=withdraw id=<rid>`. |
| `flint handoff list [--stream=<s>] [--state=<s>]` | One line per proposal, newest first: `flint: handoff <id> state=<s> candidate=<id> author=<8-hex> intent=<first line>`. |
| `flint handoff inspect <handoff-id>` | Prints `flint: handoff <id> state=<s> verdict=<v> stream=<s> work=<s>`, then `flint: handoff <id> base=<id> candidate=<id> observed_head=<id\|none> snapshot=<ref\|none> scope=<honest\|exceeded\|unverifiable>`, then one `flint: record <rid> kind=<k> author=<8-hex> sig=<verified\|invalid>` per record, then one `flint: validation via=propose\|attest attestor=<8-hex> result=<r> command=<truncated>` per validation — `via` keeps self-asserted and independent claims visibly separate. `handoff_missing` when unknown. |
| `flint handoff export <handoff-id> --out=<file> [--with-changes]` | Writes the packet (§7). `--out=-` streams to stdout, ok line to stderr. Prints `flint: handoff export <id> records=<n> changes=<m> out=<file>`. |
| `flint handoff import <file>` | §7 import rules; prints `flint: handoff import <id> records=<n> changes=<m>`. |
| `flint handoff verify <file>` | Standalone, like `bundle-verify`: no store, nothing written. Accepts a bare NDJSON record file (every line a record) or a packet (line 1 `FLINT-HANDOFF-PACKET/1`). Prints `flint: record <id> kind=<k> sig: verified` / `sig_invalid` per record and `flint: verify <cid> sig: verified` / `sig_invalid` per bundled Change; exit 1 on any invalid. |

## 9. Worked example — three agents, one receiver

Agents `a`, `b`, `c` hold separately `keygen`ed keys and work on forks
`a-work`, `b-work`, `c-work` of `main`. Agent `d` is a fresh clone.

```sh
# A: work, then propose to main — validations.json holds A's
# self-reported check (a claim, not proof)
flint commit -m "rework tokenizer"          # on ws bound to a-work
flint push                                  # publishes candidate chain
flint handoff propose --stream=main --work=a-work \
    -m "tokenizer rewrite; ready for review" --validations=self.json
# flint: handoff 019a…01 kind=propose stream=main candidate=019a…c7

# B does the same on b-work; C revises: propose the new candidate first
# (the replacement must already be a live proposal), then supersede
flint handoff propose --stream=main --work=c-work -m "v2, rebased"
flint handoff supersede 019a…44 --replacement=019a…52 \
    --note="rebased onto newer main"

# D receives: pull main + a-work + b-work + c-work, then
flint handoff import proposals.packet       # records for main
flint handoff list --stream=main
# flint: handoff 019a…01 state=proposed candidate=019a…c7 author=a1b2c3d4 intent=tokenizer rewrite…

flint handoff inspect 019a…01
# flint: handoff 019a…01 state=proposed verdict=ready stream=<main> work=<a-work>
# flint: handoff 019a…01 base=… candidate=019a…c7 observed_head=none snapshot=none scope=honest
# flint: record 019a…01 kind=propose author=a1b2c3d4 sig=verified
# flint: validation via=propose attestor=a1b2c3d4 result=pass command=zig build test --summary all

# D independently re-runs the check in its own workspace, then:
flint handoff attest 019a…01 --command="zig build test --summary all" \
    --result=pass --key=d
flint handoff accept 019a…01 --key=d
# flint: handoff 019a…01 kind=accept id=019a…9e observed_head=<main-head>

# Integration is the ordinary path — handoffs added no mutation:
flint merge a-work && flint commit && flint push

# Overlap: b-work touches the same atoms as accepted work —
flint handoff inspect 019a…44   # verdict=superseded
flint handoff inspect 019a…52   # verdict=conflicting (dry merge), or stale
                                 # if main moved; rebase + new attest + new accept
```

## 10. Conformance suite

Fixtures live in `testdata/handoffs/`, generated once with the test-only
`testdata/sig/seed.hex` key and pinned byte-for-byte:

| Suite | Source | Pass condition |
|---|---|---|
| Golden records | `propose.json`, `attest.json`, `accept.json`, `supersede.json`, `withdraw.json` — one coherent lifecycle over pinned ids/ts | `handoff verify` → `sig: verified` on each; `handoff_msg` recomputation equals `preimage.hex` for the `propose` record. |
| Refusals | `tampered.json` (flipped sig byte), `unknown-version.json` (`FLINT-HANDOFF/9`), `torn.jsonl` (final `\n` stripped), `attestor-mismatch.json` | `sig_invalid` / `handoff_malformed` (unknown format) / `handoff_torn` / `handoff_malformed` (attestor mismatch) — and import writes nothing. |
| Packet | `packet.ndjson` (header + 2 records + 2 detached Changes) | `handoff verify` covers both sections; import into a store holding the target + base is byte-verbatim and dedupes on re-import. |
| Lifecycle | scripted write-verb sequence | legal fold: propose→attest→accept; `handoff_closed` on a second terminal; `handoff_author` on foreign withdraw; `handoff_missing` on unknown id. |
| Verdicts | two-agent stores | `ready`→`stale` when the target head advances; `accepted`→`accepted_stale` likewise; `conflicting` on overlapping candidates (dry merge, zero writes); `incomplete` on missing ancestry; `unknown` on version-only records. |
| Round trip | propose→export→fresh store import | record bytes identical; `verify` green both sides; packet with `--with-changes` leaves the receiver able to `verify` the candidate's original signature. |
| Offline journey | two stores, files only (packet + `flint export` bundle), no server | §9 flow end-to-end; receiver distinguishes ready/stale/incomplete/tampered without out-of-band prose. |
| Harmlessness | stage + workspace fixtures | propose/inspect/import never alter heads, `STAGE.jsonl`, `BASE.json`, ATOMS, or src bytes; `stage_stale`/`src_behind` behavior unchanged. |

## 11. Suggested card breakdown

| # | Card | Delivers | Depends on |
|---|---|---|---|
| H1 | Record module + `handoff verify` | Record type/parse/emit, `handoff_msg`, sign/verify, golden fixtures | — (nothing unmerged; `snapshot` is opaque) |
| H2 | Store log + write verbs | `handoffs/` layout, propose/attest/accept/supersede/withdraw, lifecycle fold | H1 |
| H3 | `list` + `inspect` | verdicts, scope derivation + `scope=` comparison, dry-merge conflict leg | H2; content leg of `ready` sharpens when #77/#78 land |
| H4 | Packet + offline path | export/import/`--with-changes`, companion-bundle flow | H2 |
| H5 | `--json` | structured results under #79's reviewed envelope | #79 |

H1–H4 ship without any #77/#78/#79/#80 merge — `snapshot` rides as an
opaque bound string until #77 fixes its shape, and verdicts report
`incomplete`/degraded content honestly until #78/#80 exist.

## 12. Open questions

- Whether `supersede` should be restricted to proposer + an operator
  identity class once trust roots exist (M1+). v1 allows any key; the
  record says who asserted it.
- Whether packets need a `store_rev`/peer-capability hint for degraded
  receivers (pre-#77 stores can't resolve `snapshot`; reported as
  `incomplete`, which may already be enough).

## 13. Explicitly out of scope (v1)

- Schedulers, leases, dashboards, hosted web UI, policy engines,
  automated test runners, approval systems, new merge algorithms —
  restating the issue's list because the record invites featuritis.
- Server-side proposal hosting/approval RPCs (the V6 arc); records
  transfer by file and sync of underlying Changes only.
- Executing or sandboxing validation commands — they are data.
- Signing snapshots/manifests themselves (#77's lane), trust roots for
  `author`, encrypting records, multi-target proposals, revocable
  acceptances (a moved head already invalidates them).
