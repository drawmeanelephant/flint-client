#!/usr/bin/env bash
# Build a pinned Boris site, enforce its proof policy, and package only public
# inventory records. External checkouts are verified, never reset or deleted.
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
SITE="$ROOT/docs/site"
PIN=$(tr -d '\r\n' < "$ROOT/docs/boris-pin.txt")
[[ "$PIN" =~ ^[0-9a-f]{40}$ ]] || { echo "invalid Boris commit pin" >&2; exit 1; }
[[ $# -le 1 ]] || { echo "usage: bash docs/build.sh [PROFILE]" >&2; exit 2; }
PROFILE=${1:-"$SITE/boris.json"}
[[ "$PROFILE" = /* ]] || PROFILE="$ROOT/$PROFILE"
case "$PROFILE" in
  "$SITE/boris.json"|"$SITE/.pages-profile.json") ;;
  *) echo "profile must be the docs/site profile or its resolved Pages overlay" >&2; exit 2 ;;
esac
SOURCE=${BORIS_CHECKOUT:-"$ROOT/zig-cache/docs-boris-$PIN"}
[[ "$SOURCE" = /* ]] || { echo "BORIS_CHECKOUT must be absolute" >&2; exit 2; }
command -v jq >/dev/null || { echo "jq is required" >&2; exit 1; }
[[ -f "$PROFILE" && ! -L "$PROFILE" ]] || { echo "docs profile must be a regular file" >&2; exit 1; }
jq -e '.input == "content" and (.targets | length == 1) and
  .targets[0].name == "public" and .targets[0].output == "dist" and
  .targets[0].public == true' "$PROFILE" >/dev/null ||
  { echo "docs profile must own content -> public/dist" >&2; exit 1; }
[[ "$(zig version)" = "0.16.0" ]] || { echo "Zig 0.16.0 is required" >&2; exit 1; }

if [[ ! -e "$SOURCE" ]]; then
  [[ -z "${BORIS_CHECKOUT:-}" ]] || { echo "external Boris checkout is missing" >&2; exit 1; }
  mkdir -p "$(dirname "$SOURCE")"
  mkdir "$SOURCE"
  git -C "$SOURCE" init -q
  git -C "$SOURCE" remote add origin https://github.com/drawmeanelephant/boris.git
  git -C "$SOURCE" fetch --depth 1 origin "$PIN"
  git -C "$SOURCE" checkout --detach FETCH_HEAD
fi
[[ "$(git -C "$SOURCE" rev-parse HEAD)" = "$PIN" ]] || { echo "Boris checkout pin mismatch" >&2; exit 1; }
[[ -z "$(git -C "$SOURCE" status --porcelain)" ]] || { echo "Boris checkout must be clean" >&2; exit 1; }
(cd "$SOURCE" && zig build -Doptimize=ReleaseSafe)
BORIS="$SOURCE/zig-out/bin/boris"

mkdir -p "$SITE/evidence"
EVIDENCE=$(mktemp -d "$SITE/evidence/run.XXXXXX")
PUBLIC="$EVIDENCE/public-site"
if [[ -n "${GITHUB_OUTPUT:-}" ]]; then
  printf 'public_dir=%s\nevidence_dir=%s\n' "$PUBLIC" "$EVIDENCE" >> "$GITHUB_OUTPUT"
fi
DIRTY=false
[[ -z "$(git -C "$ROOT" status --porcelain)" ]] || DIRTY=true
jq -n --arg source "$(git -C "$ROOT" rev-parse HEAD)" \
  --arg pin "$PIN" --arg compiler "$("$BORIS" --version)" --argjson dirty "$DIRTY" \
  '{source_commit: $source, source_dirty: $dirty, boris_commit: $pin, compiler: $compiler}' \
  > "$EVIDENCE/toolchain.json"
"$BORIS" validate --profile "$PROFILE"
"$BORIS" plan --profile "$PROFILE" > "$EVIDENCE/publication-plan.json"
"$BORIS" build --profile "$PROFILE" --quiet
cp -R "$SITE/dist/_boris/proof" "$EVIDENCE/proof"
"$BORIS" proof verify --html-dir "$SITE/dist"
bash "$SOURCE/scripts/prepare-github-pages-artifact.sh" \
  "$SITE/dist" "$PUBLIC" "$SITE/dist/_boris/proof/artifacts.json" \
  public "$EVIDENCE/public-artifact-verification.json"
printf 'Boris pin: %s\nPublic artifact: %s\nEvidence: %s\n' "$PIN" "$PUBLIC" "$EVIDENCE"
