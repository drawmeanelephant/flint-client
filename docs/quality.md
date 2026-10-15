# Quality checks and performance

Run `python3 tools/check.py --quick` for formatting, Zig AST analysis,
architecture/dependency/file/debt checks, tooling tests, and local doc links.
Run `python3 tools/check.py` to include build, tests, and CLI QA.
The pre-commit hook runs the quick checks; install it with
`git config --local core.hooksPath .githooks`.

`zig ast-check` analyzes every production Zig file and the build/ZON files
without waiting for lazy compilation to reach a declaration. `zig fmt`
is the formatter. The golden corpus is not linted/formatted as application
code because it intentionally includes unsupported/invalid declarations.

## Maintained quality signals

`tools/quality.py` tokenizes Zig before analysis, so comments and strings
cannot invent imports or function declarations. Its regression tests cover
lexing, error-set returns, prototype declarations, architectural violations,
unused dependencies, duplicate blocks, file limits, and issue-less debt.

`tools/quality.json` controls:

- An absolute 512 KiB file limit and 4,000-line source-file limit.
  `main.zig` is already large because it holds CLI journeys. Put new focused
  unit tests beside their module; split responsibilities before these limits.
- Allowed import layers. Adding a source file requires assigning its layer.
  The model/JSON/crypto cycle is explicit; higher-level imports there fail.
- Review warnings for estimated function complexity above 30.
  Decisions count conditional/loop/error/boolean branches and switch arms.
- Exact duplicate windows of 100 tokens in production code. Inline test
  bodies and conformance fixtures are outside the duplication scope because
  repeated setup/expected journeys are intentional, not reusable application
  logic. String contents are retained, not normalized into false duplicates.
- Private functions with no lexical references across the sources.
  Reflective references can cause false positives; never delete solely on
  this heuristic. The compiler additionally rejects unused locals/parameters.
- Build dependencies declared in ZON but never requested in `build.zig`.
- Unlinked debt markers and committed environment/key-store paths.

Complexity, duplicate-block, and unused-private-function findings are
**non-blocking review findings**, not suppressed successes. They remain
visible in every report, including existing findings, and should become
tracked issues before a substantial refactor. The structural checks are
hard gates. This avoids pretending a lexical estimate proves reachability
or justifying risky scanner/crypto rewrites only to hit a score.

CI retains `build/reports/quality.{json,md}`, per-command logs, and
`timings.json` for 30 days and adds the quality/timing reports to its summary.
Use those artifacts to compare build/test duration and source complexity
across commits. Normal PR jobs have a ten-minute timeout and cache Zig's
compilation cache; observed CI latency still needs real workflow runs.

## Generated architecture documentation

After changing imports:

```sh
python3 tools/quality.py --write-docs
```

Commit the generated [module map](module-map.md). Normal checks fail when
the diagram differs from source imports. This is generation and freshness
validation, not a hand-maintained architecture picture.

## Coverage

The Linux coverage job builds pinned upstream kcov v43 from source because
Ubuntu 24.04 does not provide the `kcov` apt package. It installs build
dependencies from Ubuntu and installs kcov under the runner's temporary
directory, without adding a runtime dependency to FLINT.

The job builds a Debug test binary with Zig's LLVM backend (`-fllvm`) for
kcov-readable DWARF line tables. The normal Linux checks continue using
Zig's default backend, which produced an empty kcov report.
It executes the coverage binary under kcov,
retains Cobertura reports, and enforces **70% measured source-line coverage**
with `tools/check_coverage.py`. No report or no measured lines is a failure.
This requires Linux ptrace support and kcov, not a new application dependency.
The macOS test job remains a separate native compatibility check.

## Profiling

Keep optimizations separate from compatibility fixes. For repeatable
measurements without transmitting telemetry:

```sh
zig build -Doptimize=ReleaseSafe
python3 tools/benchmark.py --seconds 5
```

This repeatedly parses a temporary copy of the Go corpus, asserts successful
output, and writes elapsed-time/throughput metrics under `build/reports/`.
It never rewrites the golden corpus or a real store.

On a Linux development host with `perf` installed and profiling permission:

```sh
zig build
perf record --call-graph dwarf -o build/flint.perf -- python3 tools/benchmark.py --seconds 20
perf report -i build/flint.perf
```

`perf` follows child processes, including the Debug FLINT binary. Inspect
parser/hash stacks and compare benchmark reports before/after a change.
Use a Debug build for readable stacks. Profiling tools/permissions are
host-specific and are not required by the default checks.
