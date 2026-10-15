# Maintainer setup and release operations

The checked-in automation is not proof that remote integrations/settings
have been enabled. The following actions need a repository owner. Nothing
in the local check suite changes GitHub settings, opens issues, sends source
to an external service, or publishes a release.

## Enable and observe CI

After merging, enable GitHub Actions and allow the pinned actions in
`.github/workflows/`. CI runs the exact marked `AGENTS.md` commands on
Linux/macOS. Inspect [Actions](https://github.com/drawmeanelephant/flint-client/actions)
for checks, source-quality reports, command timings, coverage, and weekly
three-run stability/throughput reports. Artifacts expire after 30 days.
Enable GitHub Actions failure notifications for the maintainers.

The Linux job builds pinned kcov v43 from source rather than depending on an
unavailable Ubuntu 24.04 `kcov` package. Its build dependencies come from apt;
the resulting tool is installed only under the runner's temporary directory.
The coverage binary uses Zig's LLVM backend for kcov-readable DWARF line
tables; the ordinary Linux checks still exercise the default backend.

The first Linux kcov run must establish the real source-line coverage
baseline against the enforced 70% floor. The reporter fails on absent/empty
coverage. Do not silently lower the threshold or skip tests if it fails;
inspect missing paths and add meaningful tests. kcov cannot be validated on
a macOS host without a working Linux container/VM.

`Workflow review` produces actionlint inline PR review comments for
same-repository workflow changes. It is deliberately **not** a general Zig
AI reviewer and does not run privileged scripts from untrusted fork PRs.
Forks still receive normal read-only CI checks. `Security` runs Gitleaks with
readable/redacted reports. An organization moving this repo may need a
Gitleaks license secret; check its license before adoption. Native GitHub
secret scanning should remain enabled.

Factory AI review/security review requires its GitHub App, a separately
provisioned API key, and explicit review/cost permissions. It has not been
silently installed or wired to an unavailable key. Follow Factory's
[automated review guide](https://docs.factory.ai/software-factory/code-review-ci.md)
when the owner chooses to enable it. Zig is not currently covered by a
CodeQL language configuration here; do not add a fake successful CodeQL job.

## Branch protection

`.github/rulesets/main.json` is an owner-reviewable ruleset, **not an applied
setting**. It requires PRs, one approval, code-owner review, resolved threads,
current CI, and prohibits deletion/force pushes.

**Do not apply this proposal with the current single-person CODEOWNERS.**
First add a second eligible, write-authorized reviewer to the relevant
CODEOWNERS patterns and confirm they can approve the owner's PRs.
An ordinary second reviewer is insufficient when code-owner review is
required. A sole owner cannot approve their own PR, and this proposal has
no bypass actor. Agree on emergency access explicitly, not by silently
weakening the rules. Then verify every required check name against an actual
successful run.

Only after resolving those prerequisites and owner approval can an
authenticated admin apply the reviewed file:

```sh
gh api repos/drawmeanelephant/flint-client/rulesets --method POST --input .github/rulesets/main.json
```

Inspect existing rulesets first and update an existing matching ruleset
rather than repeatedly creating duplicates. This command is intentionally
not run by CI or the developer setup script.

## Labels and issue triage

The bug/feature forms request a priority and area. Maintainers apply exactly
one `P0`–`P3`, a type (`bug`, `enhancement`, `chore`, `documentation`), and an
`area:*` label. Labels are defined in `.github/labels.json`.

Run **Synchronize labels** from Actions with the default dry run first.
Review the output, then rerun with `dry_run=false` to create/update labels.
It never deletes existing labels. This explicit dispatch is required;
adding the file alone does not populate the remote label taxonomy.

## Dependency updates

Install/enable Renovate for this repository to activate
`.github/renovate.json`. It groups pinned GitHub Actions updates, waits seven
days, and never auto-merges. There are no third-party runtime dependencies.
Manual Zig/tool updates follow the same seven-day minimum release age and
review/license policy in [CONTRIBUTING.md](../CONTRIBUTING.md).

## Release

Release frequency follows reviewed changes, not artificial scheduled tags.
The workflow automates packaging/publishing; frequent shipping and actual
CI latency can only be established from real runs.

1. Run `python3 tools/check.py` and inspect coverage/security checks on the
   intended commit. Confirm store/wire/output compatibility.
2. Update `build.zig.zon` to the intended SemVer in a reviewed PR. Release
   tags must exactly match `v<package version>`.
3. Only after explicit release approval, create/push that version tag.
   The tag triggers validation, four ReleaseSafe target builds, archives,
   SHA-256 manifests, and a GitHub Release with generated notes.
4. Inspect the release's Actions run and downloaded checksums. Published tags
   and assets are immutable by policy. Failed reruns do not overwrite them.

For a local packaging rehearsal (no network publishing):

```sh
python3 tools/release.py --tag v0.1.0 --target x86_64-linux
```

Use the current package version if it has changed. Archives go to ignored
`dist/`; the tool refuses to overwrite an existing archive. Cross-built
archives still need native-platform smoke tests before promoting them.
See [runbooks](runbooks.md) for release regression response.

## Development container

With Docker running and the Dev Container extension/CLI installed, reopen
the repository in its devcontainer, or run `devcontainer up --workspace-folder .`.
The amd64/arm64 Linux image installs the checksum-verified Zig 0.17.0 archive
and Python, then runs quick checks as the non-root development user.
No host secrets, Docker socket, privileged capabilities, or external
services are mounted by the repository configuration.

## Deliberately not added

The client is a local, contract-compatible developer utility. Adding product
analytics, cloud error collection, consent SDKs, or experimental feature flags
solely for a score would introduce data handling, dependencies, and behavior
that the application does not need. No such integrations were added.

Likewise, generic automatic retries on FLINT-SYNC/1 writes could duplicate an
ambiguous append. A circuit-breaker/retry design needs an explicit protocol
and compatibility decision; it is not replaced with a blind retry loop.
