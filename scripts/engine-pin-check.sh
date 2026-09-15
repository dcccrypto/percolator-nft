#!/usr/bin/env bash
# DOES THE VENDORED MIRROR STILL MATCH THE ENGINE THE WRAPPER SHIPS?
#
# WHY THIS EXISTS
#
# `src/slab_types_v16.rs` vendors the engine's portfolio layout and `decode_portfolio`
# reads every security-relevant field out of it at a fixed byte offset. `tests/
# layout_parity_160.rs` checks that mirror against the REAL engine crate -- but against
# the engine PINNED in Cargo.toml (`[dev-dependencies.percolator] rev`), and a pin is only
# a guard while it points at the engine we actually ship against.
#
# It stopped. The pin sat at 99bc9c8d while the shipping engine moved 228 commits to
# 2c38570a, straight through bf2fda46 ("Adopt upstream 92ed4a1a: track K/F settlement
# cohorts by generation (layout 18)"), which inserted `PortfolioLegV16::kf_epoch_snap`
# (+8 B per leg, x16 legs) and four `funding_*_atoms_total` counters (+64 B). The mirror
# was 192 bytes and two insertions short: `legs`, `stale_state`, `b_stale_state`,
# `rebalance_lock`, `liquidation_lock`, `close_progress` and `resolved_payout_receipt`
# were ALL at the wrong offset. Every test was green, because the pinned engine and the
# stale mirror were field-identical -- the test compared the mirror to a copy of itself.
# N-1 found it by hand. Nothing in CI could have.
#
# So: this script re-runs the SAME parity test against the engine percolator-prog
# compiles, instead of the engine this repo happens to name.
#
# WHAT "IN SYNC" MEANS HERE -- and what it deliberately does NOT mean
#
#   IN SYNC  <=>  the vendored mirror is LAYOUT-IDENTICAL to the engine the wrapper
#                 ships against, AND the pin names a commit in that engine's history.
#
# NOT "the pin equals the wrapper's engine SHA". That test would be red on almost every
# run -- the engine moved 234 commits in eleven days -- and would demand a no-op pin bump
# per engine commit. A check that fires constantly and is fixed by a reflex edit is a
# check nobody reads; that is how the 228-commit rot survived in the first place. What
# `decode_portfolio` depends on is the LAYOUT, so the layout is what is asserted. A pin
# that is behind but layout-identical is harmless and stays green; a pin that is behind
# and layout-divergent is the N-1 defect and turns red at the FIRST engine commit that
# moves the layout, not 228 later.
#
# The ancestry half is not a proxy, it is a separate property: a pin that is not an
# ancestor of the wrapper's engine names a commit the wrapper does not ship -- a branch,
# a rebased-away commit, a fork -- and the parity test could then be green against an
# engine that exists nowhere. That is cheap to check, cannot churn, and is checked.
#
# WHICH ENGINE DOES THE WRAPPER SHIP?
#
# Not assumed: read out of percolator-prog's own ci.yml. Its engine checkout carries no
# `ref:` ("The ENGINE is deliberately NOT pinned: it compiles into the wrapper, so main is
# exactly what we are shipping and what these tests must cover"), so the reference is the
# engine repository's DEFAULT BRANCH TIP. If percolator-prog ever starts pinning the
# engine -- a `ref:` naming a `ci/deployed-refs.env` variable, the way the matcher, stake
# and nft siblings are pinned -- scripts/gha_checkout_ref.py reports that instead and this
# script follows the pin. If the shape becomes one it cannot classify, it HARD FAILS
# rather than falling back to a default.
#
# ANTI-VACUITY
#
# Every extraction hard-fails (exit 2) instead of yielding an empty string: the prog
# workflow, the deployed-refs variable, the Cargo.toml git URL and rev, the engine SHA.
# The `[patch]` that redirects the engine dev-dependency is PROVEN to have applied, by
# reading the resolved package out of `cargo metadata` -- an unapplied `[patch]` is a
# cargo WARNING, not an error, and would leave this script testing the pinned engine
# again while claiming to test the wrapper's. The engine checkout is required to be clean,
# because a dirty engine tree would make the whole measurement a statement about somebody's
# uncommitted edit.
#
# USAGE
#   scripts/engine-pin-check.sh
#   PROG_REPO=/path ENGINE_REPO=/path scripts/engine-pin-check.sh
#   REF_PROG=origin/main scripts/engine-pin-check.sh          # default HEAD (the CI checkout)
#   REF_ENGINE=<sha> scripts/engine-pin-check.sh              # demonstration/debug override
#
# EXIT  0 in sync   1 out of sync (mirror drifted, or pin off the shipping history)
#       2 could not measure (extractor missed, ref unresolvable, patch did not apply)
#
# Written for bash 3.2 (macOS) as well as CI's bash 5 -- no associative arrays.

set -uo pipefail

# Every directory this script compares or prints is CANONICAL -- no `..` segments, symlinks
# resolved. The default engine path is `$ROOT/../percolator`, and `cargo metadata` reports the
# canonical form, so comparing the two as strings said "[patch] applied to the wrong tree" for
# the one directory that was right. That is what happened on the first real CI run (GH run
# 34926926638): the check is correct, the comparison was not. It never showed up locally
# because a local run passes ENGINE_REPO explicitly, and only CI uses the `..` default.
canon() { ( CDPATH='' cd -- "$1" 2>/dev/null && pwd -P ); }

ROOT="$(canon "$(dirname "$0")/..")" || exit 2
[ -n "$ROOT" ] || { printf '::error::cannot resolve the repository root from %s\n' "$0" >&2; exit 2; }
cd "$ROOT" || exit 2

PROG_REPO_IN="${PROG_REPO:-$ROOT/../percolator-prog}"
ENGINE_REPO_IN="${ENGINE_REPO:-$ROOT/../percolator}"
PROG_REPO="$(canon "$PROG_REPO_IN")"
ENGINE_REPO="$(canon "$ENGINE_REPO_IN")"
REF_PROG="${REF_PROG:-HEAD}"
SELF_WORKFLOW="${SELF_WORKFLOW:-$ROOT/.github/workflows/test.yml}"
EXTRACTOR="$ROOT/scripts/gha_checkout_ref.py"

WORKTREE=""
die() { printf '::error::%s\n' "$*" >&2; cleanup; exit 2; }
fail() { printf '::error::%s\n' "$*" >&2; }
cleanup() {
  if [ -n "$WORKTREE" ] && [ -d "$WORKTREE" ]; then
    git -C "$ENGINE_REPO" worktree remove --force "$WORKTREE" >/dev/null 2>&1 || true
  fi
}

command -v python3 >/dev/null 2>&1 || die "python3 not found -- scripts/gha_checkout_ref.py cannot run"
[ -r "$EXTRACTOR" ] || die "$EXTRACTOR missing"
[ -n "$PROG_REPO" ] \
  || die "PROG_REPO='$PROG_REPO_IN' does not exist -- without percolator-prog there is nothing to tie the pin TO"
[ -n "$ENGINE_REPO" ] || die "ENGINE_REPO='$ENGINE_REPO_IN' does not exist"
git -C "$PROG_REPO" rev-parse --git-dir >/dev/null 2>&1 \
  || die "PROG_REPO='$PROG_REPO' is not a git repository -- without percolator-prog there is nothing to tie the pin TO"
git -C "$ENGINE_REPO" rev-parse --git-dir >/dev/null 2>&1 \
  || die "ENGINE_REPO='$ENGINE_REPO' is not a git repository"

# ---------------------------------------------------------------------------------------
# 1. THE WRAPPER'S ENGINE REFERENCE
# ---------------------------------------------------------------------------------------
echo "::group::the wrapper's engine reference"

SHA_PROG="$(git -C "$PROG_REPO" rev-parse --verify --quiet "${REF_PROG}^{commit}")" \
  || die "REF_PROG='$REF_PROG' does not resolve in $PROG_REPO"
[ -n "$SHA_PROG" ] || die "REF_PROG='$REF_PROG' resolved to nothing in $PROG_REPO"
printf '  percolator-prog        %s  (%s)\n' "$SHA_PROG" "$REF_PROG"

PROG_CI="$(mktemp "${TMPDIR:-/tmp}/progci.XXXXXX")" || die "mktemp failed"
git -C "$PROG_REPO" show "${SHA_PROG}:.github/workflows/ci.yml" > "$PROG_CI" 2>/dev/null \
  || die "EXTRACTOR MISSED: cannot read .github/workflows/ci.yml at ${SHA_PROG} in $PROG_REPO"
[ -s "$PROG_CI" ] || die "EXTRACTOR MISSED: percolator-prog ci.yml is empty at ${SHA_PROG}"

STEP="$(python3 "$EXTRACTOR" "$PROG_CI" dcccrypto/percolator)" || { rm -f "$PROG_CI"; cleanup; exit 2; }
rm -f "$PROG_CI"
# Parsed key by key, never eval'd: a ref value is `${{ steps.refs.outputs.X }}`, and
# eval'ing that in bash is a syntax error at best and an expansion at worst.
PINNED="$(printf '%s\n' "$STEP" | sed -nE 's/^PINNED=(.*)$/\1/p')"
STEP_LINE="$(printf '%s\n' "$STEP" | sed -nE 's/^STEP_LINE=(.*)$/\1/p')"
REF="$(printf '%s\n' "$STEP" | sed -nE 's/^REF=(.*)$/\1/p')"
[ -n "$PINNED" ] || die "EXTRACTOR MISSED: gha_checkout_ref.py produced no PINNED line"
printf '  ci.yml engine step     line %s, pinned=%s\n' "${STEP_LINE}" "${PINNED}"

if [ "$PINNED" = "no" ]; then
  MODE="default-branch"
  echo "  => percolator-prog checks the engine out with NO ref: the engine it compiles is"
  echo "     the DEFAULT BRANCH TIP of dcccrypto/percolator."
  # Machine-checked symmetry: our own engine checkout must be unpinned too, or the tip we
  # measure is not the tip percolator-prog compiles. A comment asserting this would rot;
  # this does not.
  [ -r "$SELF_WORKFLOW" ] || die "$SELF_WORKFLOW missing -- cannot confirm THIS workflow checks the engine out unpinned"
  SELF_STEP="$(python3 "$EXTRACTOR" "$SELF_WORKFLOW" dcccrypto/percolator)" || { cleanup; exit 2; }
  SELF_PINNED="$(printf '%s\n' "$SELF_STEP" | sed -nE 's/^PINNED=(.*)$/\1/p')"
  [ "$SELF_PINNED" = "no" ] || die \
"this workflow pins its engine checkout (ref present) while percolator-prog does not.
     The engine checked out here would then NOT be the engine the wrapper compiles, and
     every comparison below would be about the wrong commit. Remove the ref: from the
     engine checkout in ${SELF_WORKFLOW}."
  echo "  => this workflow checks the engine out with no ref either (verified, not asserted)"
  SHA_ENGINE="$(git -C "$ENGINE_REPO" rev-parse --verify --quiet "${REF_ENGINE:-HEAD}^{commit}")" \
    || die "cannot resolve '${REF_ENGINE:-HEAD}' in $ENGINE_REPO"
  if [ -n "${REF_ENGINE:-}" ]; then
    printf '  !! REF_ENGINE OVERRIDE in effect: %s -- this run is a demonstration, not a verdict\n' "$REF_ENGINE"
    printf '  !! the default-branch confirmation below is SKIPPED for the same reason\n'
  else
    # N-3 gap 1. Everything above only establishes that NOBODY WROTE a `ref:`. It does not
    # establish that what is checked out here IS the default branch -- a stale clone, a
    # `git checkout` in an earlier step, or a `ref` supplied some other way would all still
    # read PINNED=no while HEAD sits on something else entirely, and the job would then
    # report a confident verdict about the wrong commit. Ask the remote.
    LSR="$(git -C "$ENGINE_REPO" ls-remote --symref origin HEAD 2>/dev/null)" \
      || die "cannot reach the engine remote to confirm its default branch.
    Without that confirmation this job cannot tell whether the engine checked out here is the
    engine percolator-prog compiles, and a guard that cannot tell must not report OK."
    DEFAULT_BRANCH="$(printf '%s\n' "$LSR" | sed -nE 's#^ref:[[:space:]]+refs/heads/(.+)[[:space:]]+HEAD$#\1#p' | head -1)"
    REMOTE_TIP="$(printf '%s\n' "$LSR" | sed -nE 's/^([0-9a-f]{40})[[:space:]]+HEAD$/\1/p' | head -1)"
    [ -n "$DEFAULT_BRANCH" ] && [ -n "$REMOTE_TIP" ] \
      || die "EXTRACTOR MISSED: cannot read the default branch and its tip out of \`git ls-remote --symref origin HEAD\`:
${LSR}"
    if [ "$SHA_ENGINE" = "$REMOTE_TIP" ]; then
      printf '  default-branch check   OK -- HEAD == origin/%s tip %s\n' "$DEFAULT_BRANCH" "$REMOTE_TIP"
    else
      # STRICT. Not "on the branch somewhere" -- equal to the tip. An engine checkout seven
      # commits behind the tip is precisely the silent-green this job exists to remove: the
      # independent verifier demonstrated it (detached at 2c38570a, seven behind, reported
      # `ancestry ok / layout=ok / OK: the vendored mirror matches the engine percolator-prog
      # ships` and exited 0 -- green against the wrong commit). An ancestry-only check would
      # print a note and still exit 0, i.e. a quieter version of the same thing.
      #
      # The known benign cause is a push to the engine between the checkout step and this
      # line. It is named in the message so the reader re-runs instead of investigating; a
      # re-run is cheap, and a guard that is occasionally loud for a good reason is worth
      # much more than one that is quietly wrong.
      ADVICE="this is what a push to the engine between the checkout step and now looks like;
    re-run the job and it will clear."
      git -C "$ENGINE_REPO" cat-file -e "${REMOTE_TIP}^{commit}" 2>/dev/null \
        || git -C "$ENGINE_REPO" fetch --no-tags --quiet origin "$DEFAULT_BRANCH" >/dev/null 2>&1 || true
      if git -C "$ENGINE_REPO" cat-file -e "${REMOTE_TIP}^{commit}" 2>/dev/null \
         && git -C "$ENGINE_REPO" merge-base --is-ancestor "$SHA_ENGINE" "$REMOTE_TIP" 2>/dev/null; then
        RELATION="HEAD is on origin/${DEFAULT_BRANCH} but $(git -C "$ENGINE_REPO" rev-list --count "${SHA_ENGINE}..${REMOTE_TIP}") commit(s) behind its tip --
    ${ADVICE}
    If a re-run does not clear it, this checkout is stale and every number below would be a
    measurement of an engine the wrapper has already moved past."
      else
        RELATION="HEAD is not even an ancestor of that tip, so this checkout is some other
    branch, a fork, or a rebased-away commit -- not the engine percolator-prog compiles."
      fi
      die "the engine checkout is NOT the remote's default-branch tip.
    HEAD                          ${SHA_ENGINE}
    origin/${DEFAULT_BRANCH} tip  ${REMOTE_TIP}
    ${RELATION}"
    fi
  fi
else
  MODE="pinned"
  # shellcheck disable=SC2016  # these are GitHub Actions expressions, matched literally
  case "$REF" in
    *'${{'*steps.refs.outputs.*'}}'*)
      VARNAME="$(printf '%s' "$REF" | sed -nE 's/.*steps\.refs\.outputs\.([A-Z0-9_]+).*/\1/p')"
      [ -n "$VARNAME" ] || die "EXTRACTOR MISSED: cannot read a deployed-refs variable name out of ref '$REF'"
      REFS_ENV="$(git -C "$PROG_REPO" show "${SHA_PROG}:ci/deployed-refs.env" 2>/dev/null)" \
        || die "EXTRACTOR MISSED: ref '$REF' names ci/deployed-refs.env but that file is unreadable at ${SHA_PROG}"
      PINVAL="$(printf '%s\n' "$REFS_ENV" | sed -nE "s/^${VARNAME}=([0-9a-f]{40})[[:space:]]*\$/\\1/p" | head -1)"
      [ -n "$PINVAL" ] || die "EXTRACTOR MISSED: ${VARNAME} is not a 40-hex sha in percolator-prog ci/deployed-refs.env at ${SHA_PROG}"
      printf '  ci/deployed-refs.env   %s=%s\n' "$VARNAME" "$PINVAL"
      ;;
    *[0-9a-f]*)
      PINVAL="$(printf '%s' "$REF" | sed -nE "s/.*([0-9a-f]{40}).*/\\1/p")"
      [ -n "$PINVAL" ] || die "EXTRACTOR MISSED: engine ref '$REF' is neither a deployed-refs variable nor a 40-hex sha"
      ;;
    *)
      die "EXTRACTOR MISSED: engine ref '$REF' is a shape this script cannot classify. Teach it, do not guess."
      ;;
  esac
  git -C "$ENGINE_REPO" cat-file -e "${PINVAL}^{commit}" 2>/dev/null \
    || git -C "$ENGINE_REPO" fetch --no-tags --quiet origin "$PINVAL" >/dev/null 2>&1 || true
  SHA_ENGINE="$(git -C "$ENGINE_REPO" rev-parse --verify --quiet "${PINVAL}^{commit}")" \
    || die "the engine commit percolator-prog pins (${PINVAL}) does not resolve in $ENGINE_REPO"
  echo "  => percolator-prog PINS the engine; that pin is the reference."
fi

[ -n "${SHA_ENGINE:-}" ] || die "the wrapper's engine reference resolved to nothing"
printf '  engine reference       %s\n' "$SHA_ENGINE"
printf '                         %s\n' "$(git -C "$ENGINE_REPO" log -1 --format='%ad  %s' --date=short "$SHA_ENGINE")"
echo "::endgroup::"

# ---------------------------------------------------------------------------------------
# 2. THE PIN IN Cargo.toml
# ---------------------------------------------------------------------------------------
echo "::group::the engine pin in Cargo.toml"
[ -r "$ROOT/Cargo.toml" ] || die "Cargo.toml missing"

# Section-scoped so a `rev =` under some other dependency cannot be read as this one.
# awk, not grep: the value has to come from inside [dev-dependencies.percolator].
DEP_GIT="$(awk '/^\[dev-dependencies\.percolator\]/{s=1;next} /^\[/{s=0} s && /^[[:space:]]*git[[:space:]]*=/{print; exit}' "$ROOT/Cargo.toml" | sed -E 's/.*"([^"]+)".*/\1/')"
DEP_REV="$(awk '/^\[dev-dependencies\.percolator\]/{s=1;next} /^\[/{s=0} s && /^[[:space:]]*rev[[:space:]]*=/{print; exit}' "$ROOT/Cargo.toml" | sed -E 's/.*"([^"]+)".*/\1/')"
[ -n "$DEP_GIT" ] || die "EXTRACTOR MISSED: no git url under [dev-dependencies.percolator] in Cargo.toml"
[ -n "$DEP_REV" ] || die "EXTRACTOR MISSED: no rev under [dev-dependencies.percolator] in Cargo.toml"
case "$DEP_REV" in
  [0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f]*) ;;
  *) die "EXTRACTOR MISSED: [dev-dependencies.percolator] rev parsed as '$DEP_REV', not a git sha";;
esac
printf '  git                    %s\n' "$DEP_GIT"
printf '  rev                    %s\n' "$DEP_REV"

git -C "$ENGINE_REPO" cat-file -e "${DEP_REV}^{commit}" 2>/dev/null \
  || git -C "$ENGINE_REPO" fetch --no-tags --quiet origin "$DEP_REV" >/dev/null 2>&1 || true
SHA_PIN="$(git -C "$ENGINE_REPO" rev-parse --verify --quiet "${DEP_REV}^{commit}")" \
  || die "the pinned engine commit ${DEP_REV} does not exist in $ENGINE_REPO -- the pin names a phantom engine"
printf '                         %s\n' "$(git -C "$ENGINE_REPO" log -1 --format='%ad  %s' --date=short "$SHA_PIN")"

rc=0

if git -C "$ENGINE_REPO" merge-base --is-ancestor "$SHA_PIN" "$SHA_ENGINE" 2>/dev/null; then
  ANCESTRY=ok
  BEHIND="$(git -C "$ENGINE_REPO" rev-list --count "${SHA_PIN}..${SHA_ENGINE}")"
  printf '  ancestry               OK -- the pin is on the history the wrapper ships\n'
  printf '  distance               %s commits behind the reference (informational: layout is what is asserted)\n' "$BEHIND"
else
  ANCESTRY=FAILED
  fail "the engine pin is NOT an ancestor of the engine the wrapper ships.
    pin        ${SHA_PIN}
    reference  ${SHA_ENGINE}
    The pin names a commit that is not in the shipping engine's history -- a branch, a
    rebased-away commit, or another fork. The layout test below may well be green against
    it and still be green against an engine nobody ships. Repoint
    [dev-dependencies.percolator] rev at a commit on the wrapper's engine."
  rc=1
fi
echo "::endgroup::"

# ---------------------------------------------------------------------------------------
# 3. LAYOUT PARITY AGAINST THE REFERENCE -- the measurement, not a proxy for it
# ---------------------------------------------------------------------------------------
echo "::group::layout parity against the wrapper's engine (not against the pin)"

HEAD_ENGINE="$(git -C "$ENGINE_REPO" rev-parse --verify --quiet 'HEAD^{commit}')" || HEAD_ENGINE=""
if [ "$HEAD_ENGINE" = "$SHA_ENGINE" ]; then
  ENGINE_DIR="$ENGINE_REPO"
  DIRT="$(git -C "$ENGINE_DIR" status --porcelain)"
  [ -z "$DIRT" ] || die "the engine checkout at $ENGINE_DIR is DIRTY:
${DIRT}
    Every number below would then describe somebody's uncommitted edit rather than
    ${SHA_ENGINE}."
else
  WORKTREE="$(mktemp -d "${TMPDIR:-/tmp}/enginewt.XXXXXX")" || die "mktemp -d failed"
  rmdir "$WORKTREE" 2>/dev/null || true
  git -C "$ENGINE_REPO" worktree add --detach --quiet "$WORKTREE" "$SHA_ENGINE" \
    || die "cannot create a worktree of $ENGINE_REPO at ${SHA_ENGINE}"
  ENGINE_DIR="$WORKTREE"
fi
ENGINE_DIR="$(canon "$ENGINE_DIR")"
[ -n "$ENGINE_DIR" ] || die "the engine source directory does not resolve"
printf '  engine source          %s\n' "$ENGINE_DIR"

PATCH_CFG="patch.\"${DEP_GIT}\".percolator.path=\"${ENGINE_DIR}\""

# PROOF the patch applied. An unapplied [patch] is a cargo warning, and this whole job
# would then re-test the pinned engine while reporting the reference's sha.
META="$(cargo metadata --format-version 1 --config "$PATCH_CFG" 2>/dev/null)" \
  || die "cargo metadata failed under the [patch] override (cargo must be new enough for --config)"
PROOF="$(printf '%s' "$META" | python3 -c '
import json, sys
m = json.load(sys.stdin)
for p in m["packages"]:
    if p["name"] == "percolator":
        print("%s\t%s" % (p["source"], p["manifest_path"]))
')" || die "cannot read the resolved percolator package out of cargo metadata"
[ -n "$PROOF" ] || die "cargo metadata resolved NO package named percolator -- the dev-dependency is gone?"
PROOF_SRC="$(printf '%s' "$PROOF" | cut -f1)"
PROOF_MAN="$(printf '%s' "$PROOF" | cut -f2)"
[ "$PROOF_SRC" = "None" ] || die "[patch] DID NOT APPLY: percolator still resolves to source '${PROOF_SRC}'.
    The test below would compare the mirror against the PINNED engine while this script
    reported the wrapper's -- vacuous, and worse than no check at all."
# Compare DIRECTORIES, canonicalised on both sides, not the raw strings. cargo normalises the
# path it is handed lexically (it collapses `..`) but does not resolve symlinks, and ENGINE_DIR
# above is `pwd -P`, so the two agree only once both have been through the same treatment. The
# first real CI run failed exactly here, on `<ws>/percolator-nft/../percolator` versus
# `<ws>/percolator` -- one directory, two spellings. The CHECK is right and is kept; only the
# comparison was wrong.
[ "$(basename "$PROOF_MAN")" = "Cargo.toml" ] || die "[patch] resolved to a non-manifest path: ${PROOF_MAN}"
PROOF_DIR="$(canon "$(dirname "$PROOF_MAN")")"
[ -n "$PROOF_DIR" ] || die "[patch] resolved to a directory that does not exist: ${PROOF_MAN}"
[ "$PROOF_DIR" = "$ENGINE_DIR" ] || die "[patch] applied to the wrong tree.
    expected  ${ENGINE_DIR}
    resolved  ${PROOF_DIR}   (from ${PROOF_MAN})
    Both paths above are canonical (symlinks resolved, no '..'), so this is a genuinely
    different directory and not a spelling difference."
printf '  patch proof            percolator -> %s  (source=none)\n' "$PROOF_MAN"

DISC_REF="$(sed -nE 's/^[[:space:]]*pub const V16_LAYOUT_DISCRIMINATOR[^=]*=[[:space:]]*([0-9_]+)[[:space:]]*;.*$/\1/p' "${ENGINE_DIR}/src/v16.rs" | head -1)"
[ -n "$DISC_REF" ] || die "EXTRACTOR MISSED: V16_LAYOUT_DISCRIMINATOR not found in ${ENGINE_DIR}/src/v16.rs"
DISC_PIN="$(git -C "$ENGINE_REPO" show "${SHA_PIN}:src/v16.rs" | sed -nE 's/^[[:space:]]*pub const V16_LAYOUT_DISCRIMINATOR[^=]*=[[:space:]]*([0-9_]+)[[:space:]]*;.*$/\1/p' | head -1)"
[ -n "$DISC_PIN" ] || die "EXTRACTOR MISSED: V16_LAYOUT_DISCRIMINATOR not found in src/v16.rs at the pin ${SHA_PIN}"
printf '  V16_LAYOUT_DISCRIMINATOR   pin=%s  reference=%s\n' "$DISC_PIN" "$DISC_REF"

echo
TEST_LOG="$(mktemp "${TMPDIR:-/tmp}/parity.XXXXXX")" || die "mktemp failed"
cargo test --config "$PATCH_CFG" --test layout_parity_160 2>&1 | tee "$TEST_LOG"
TEST_RC=${PIPESTATUS[0]}

# N-3 gap 2. cargo exits 0 for "ran 6 tests, all passed" AND for "ran 0 tests" -- a filter
# that matches nothing, a test file emptied or renamed, a `#[ignore]` sprayed over it. The
# LOOP.md §5 trap ("`cargo test -- --exact` on the wrong name reports 0 passed; 0 failed")
# is that shape, and a guard reading only the exit code cannot tell the two apart. Read the
# COUNT. Anything that stops it being readable is exit 2 -- could not measure -- never a
# green.
EXPECTED_MIN_TESTS=6   # 5 offset/size tests + the constant-value test. Adding tests is fine.
RUN_LINES="$(grep -cE '^running [0-9]+ tests?$' "$TEST_LOG" | tr -d ' ')"
TEST_COUNT="$(sed -nE 's/^running ([0-9]+) tests?$/\1/p' "$TEST_LOG" | head -1)"
RESULT_LINE="$(grep -E '^test result: ' "$TEST_LOG" | head -1)"
rm -f "$TEST_LOG"
if [ "$RUN_LINES" != "1" ] || [ -z "$TEST_COUNT" ] || [ -z "$RESULT_LINE" ]; then
  die "the parity test did not run: found ${RUN_LINES} \`running N tests\` line(s) and $([ -n "$RESULT_LINE" ] && echo 1 || echo 0)
    \`test result:\` line(s) in the cargo output above, expected exactly 1 of each. Either it
    failed to COMPILE -- which is drift too, and a worse kind: a field the mirror names by
    offset_of! no longer exists in the engine -- or the target/filter no longer selects it.
    Read the cargo output above; do not treat this as green."
fi
# Every number out of the result line, not just the headline. cargo exits 0 for "ran 0 tests"
# AND for "ran 6, ignored 6" -- in the second, `running 6 tests` is still printed, so a bare
# count would wave it through while nothing at all was asserted.
r_passed="$(printf '%s\n' "$RESULT_LINE"   | sed -nE 's/.*[^0-9]([0-9]+) passed.*/\1/p')"
r_failed="$(printf '%s\n' "$RESULT_LINE"   | sed -nE 's/.*[^0-9]([0-9]+) failed.*/\1/p')"
r_ignored="$(printf '%s\n' "$RESULT_LINE"  | sed -nE 's/.*[^0-9]([0-9]+) ignored.*/\1/p')"
r_filtered="$(printf '%s\n' "$RESULT_LINE" | sed -nE 's/.*[^0-9]([0-9]+) filtered out.*/\1/p')"
for v in "$r_passed" "$r_failed" "$r_ignored" "$r_filtered"; do
  case "$v" in ''|*[!0-9]*) die "EXTRACTOR MISSED: cannot read the counts out of '${RESULT_LINE}'";; esac
done
r_ran=$((r_passed + r_failed))
[ "$r_ran" -ge "$EXPECTED_MIN_TESTS" ] || die "the parity test EXECUTED only ${r_ran} test(s) (${r_passed} passed,
    ${r_failed} failed), expected at least ${EXPECTED_MIN_TESTS}.  ${RESULT_LINE}
    cargo exits 0 for an empty run, so this would otherwise have been reported as a PASS.
    tests/layout_parity_160.rs is the whole measurement this job makes -- a shrunken one is not
    a smaller check, it is a green light with nothing behind it."
[ "$r_ignored" = "0" ] || die "${r_ignored} parity test(s) are #[ignore]d.  ${RESULT_LINE}
    An ignored test still prints in \`running N tests\` and still exits 0. Un-ignore them or
    this job asserts nothing."
[ "$r_filtered" = "0" ] || die "${r_filtered} parity test(s) were filtered out.  ${RESULT_LINE}
    This job must run the whole file; a filter makes the verdict about a subset."
printf '  test count             %s executed, %s ignored, %s filtered (>= %s required)\n' \
  "$r_ran" "$r_ignored" "$r_filtered" "$EXPECTED_MIN_TESTS"
echo "::endgroup::"

if [ "$TEST_RC" -ne 0 ]; then
  fail "the vendored portfolio mirror has DRIFTED from the engine percolator-prog ships.
    engine reference  ${SHA_ENGINE}
    engine pin        ${SHA_PIN}
    tests/layout_parity_160.rs passes against the pin and FAILS against the reference, so
    src/slab_types_v16.rs describes an engine we no longer ship. decode_portfolio reads
    owner, legs, the market_id slot-reuse anchor and every transfer-gate flag at fixed
    offsets through that mirror.
    Fix: re-vendor src/slab_types_v16.rs at the reference layout, bump LAYOUT_REVISION and
    its fingerprint, and move [dev-dependencies.percolator] rev to the reference. That is
    what N-1 did by hand; this job is here so the next one is not found by hand."
  rc=1
fi

cleanup

echo
if [ "$TEST_RC" -eq 0 ]; then LAYOUT=ok; else LAYOUT=FAILED; fi
printf 'SUMMARY: mode=%s  reference=%s  pin=%s  ancestry=%s  layout=%s\n' \
  "$MODE" "${SHA_ENGINE}" "${SHA_PIN}" "$ANCESTRY" "$LAYOUT"

if [ "$rc" -eq 0 ]; then
  echo "OK: the vendored mirror matches the engine percolator-prog ships, and the pin is on its history"
fi
exit $rc
