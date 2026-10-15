# Technical debt tracking

Use GitHub issues as the durable debt backlog, not unexplained source notes.
Every TODO/FIXME/HACK/XXX in Zig comments must have an issue reference:
`TODO(#123): explain the limitation`. The quality gate rejects bare markers.

Each debt issue should identify the affected module, user impact, owner,
priority, compatibility risks, and a verifiable acceptance condition. Apply
the appropriate area label and `chore` or `bug`. Close the issue only after
the fix and regression test land, then remove the marker.

Historical tracking examples include [transport-error normalization (#31)](https://github.com/drawmeanelephant/flint-client/issues/31)
and [clone/materialization documentation (#32)](https://github.com/drawmeanelephant/flint-client/issues/32).
Both fixes have landed on main. Retain them as context, not outstanding debt;
the setup/QA docs also preserve the history-only clone semantics.

Quality reports also identify current high-complexity scanner/sync functions
and repeated blocks. Review findings before opening an issue to avoid
duplicates. Do not suppress findings, add arbitrary skip lists, or change
canonical behavior just to reduce a metric. Small extractions require the
full conformance suite and a clear compatibility argument.
