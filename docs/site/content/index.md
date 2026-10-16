---
title: flint
status: published
summary: An agent-native source-control client. Signed structure, portable stores, no daemon.
---

<p class="eyebrow">Field manual / flint spec_rev=1</p>

# Structure, not bytes.<br>Signatures, not trust. {#welcome .hero-heading}

A standalone FLINT client written in Zig. One static binary, standard
library only, byte-compatible with ADR 0049 — the store format, canonical
byte forms, and refusal names are the contract, not an approximation.

<div class="home-actions">
<a href="getting-started.html">Make your first commit</a>
<a href="sync.html">Talk to flintd</a>
</div>

<div class="specimen-card">
<div class="specimen-card__header">One build. One binary. Zero dependencies.</div>
<div class="specimen-card__body">

```bash
zig build
./zig-out/bin/flint verify --file=testdata/sig/good.jsonl
```

No daemon, database, or account required. The second command prints
`flint: verify <id> sig: verified` and exits zero.

</div>
</div>

## Pick your surface

<div class="feature-grid">
<div class="feature-card"><span class="edition-card__tag">01 / Local</span><h3 id="the-verb-surface">The verb surface</h3><p>init, add, status, commit, log, verify — declaration-level staging and signed Changes over an append-only store.</p><a href="verbs.html">Read the verbs</a></div>
<div class="feature-card"><span class="edition-card__tag">02 / Remote</span><h3 id="remote-sync">Remote sync</h3><p>clone, push, pull, fork, merge against flintd over FLINT-SYNC/1, with authenticated transport and named refusals.</p><a href="sync.html">Sync with a server</a></div>
<div class="feature-card"><span class="edition-card__tag">03 / Release</span><h3 id="release-streams">Release streams</h3><p>A signed release.go convention that announces binary artifacts — hash inside the signature, bytes over any channel.</p><a href="release.html">Ship a release</a></div>
</div>

## The contract is the product

FLINT stores the structure of source code — declaration atoms, hashed
canonically — rather than file contents. A store produced by this client
loads in the Go reference implementation and vice versa. Every Change is
Ed25519-signed; `verify` proves integrity and which key signed, not
whether you should trust it.

- [[getting-started|Start here]] for a working first run.
- [[verbs|The verb surface]] for local commands and refusal names.
- [[sync|Remote sync]] for clone/push/pull against flintd.
- [[release|Release streams]] for the signed manifest convention and `spec_rev`.

This manual is compiled to static files by
[Boris](https://github.com/drawmeanelephant/boris) from a pinned,
proof-verified build. No tracking, remote fonts, or framework.
