#!/usr/bin/env python3
"""Answer one question about a GitHub Actions workflow: does its checkout of
`<owner>/<repo>` pin a `ref:`, and if so, to what?

Used by scripts/engine-pin-check.sh to derive, from percolator-prog's OWN ci.yml,
which engine commit the wrapper ships against -- rather than hardcoding an
assumption about it here. percolator-prog checks the engine out with no `ref:`
today ("The ENGINE is deliberately NOT pinned: it compiles into the wrapper, so
main is exactly what we are shipping"), so the answer today is "unpinned". If
that ever changes, the answer changes with it and the guard follows.

ANTI-VACUITY IS THE POINT. This never guesses and never returns a default. If it
cannot find exactly one checkout of the repository, or cannot classify the `ref:`
it finds, it exits 2 with a message. A wrong answer here would make the whole
guard compare against the wrong engine and go quietly green -- which is the exact
failure (a check that cannot fail) the guard exists to remove.

stdlib only, deliberately: PyYAML is not guaranteed on every runner, and a guard
that dies on a missing import is a false red.

Usage:
    gha_checkout_ref.py <workflow.yml> <owner/repo>

Output on success (stdout, one key=value per line):
    FOUND_STEPS=<n>          -- always 1 on success
    STEP_LINE=<n>            -- 1-based line where the step starts
    PINNED=yes|no
    REF=<raw ref expression> -- empty when PINNED=no

Exit: 0 found and classified; 2 anything else.
"""

import re
import sys

# `repository: owner/name`. The character class excludes ',' and '}' so the flow
# form `{ repository: dcccrypto/percolator, path: ... }` yields the bare name,
# and it INCLUDES '-' so `dcccrypto/percolator-prog` is captured whole and then
# compared for EXACT equality -- a prefix match would confuse the engine with the
# wrapper, which are different repositories with nearly the same name.
REPO_RE = re.compile(r"repository:[ \t]*([A-Za-z0-9_.\-]+/[A-Za-z0-9_.\-]+)")

# `ref:` as its own key, not the tail of `xref:` / `something.ref:`.
#
# The first alternative exists because a `${{ ... }}` expression contains '}',
# which the plain-scalar alternative has to treat as the end of a flow mapping.
# Without it, `ref: '${{ steps.refs.outputs.MATCHER_DEPLOYED }}', token: ...`
# extracts as `'${{ steps.refs.outputs.MATCHER_DEPLOYED` -- a value that still
# looks plausible and would be resolved against the wrong thing. Verified against
# both the flow form above and the block form nft/stake use.
REF_RE = re.compile(
    r"(?:^|[^A-Za-z0-9_.\-])ref:[ \t]*('?\$\{\{.*?\}\}'?|[^,}\n]*)",
    re.S,
)

# A list item: the step boundary. Both `- name: x` and a bare `-` count.
ITEM_RE = re.compile(r"^([ \t]*)-(?:[ \t]|$)")


def die(msg):
    sys.stderr.write("EXTRACTOR MISSED: %s\n" % msg)
    sys.stderr.write(
        "This is NOT a parity failure -- the workflow no longer has the shape this "
        "extractor understands, which would make every comparison downstream "
        "VACUOUS. Fix the extractor before trusting any result from it.\n"
    )
    raise SystemExit(2)


def indent_of(line):
    return len(line) - len(line.lstrip(" \t"))


def strip_comment(line):
    # Drop ` # ...` trailers. Workflow values here are `dcccrypto/percolator`,
    # `percolator`, `0` and `'${{ secrets.GITHUB_TOKEN }}'` -- none contains '#'.
    return re.sub(r"[ \t]#.*$", "", line.rstrip("\n"))


def steps(lines):
    """Yield (start_line_1based, text) for every YAML list item in the file."""
    cur_start = None
    cur_indent = None
    buf = []
    for i, raw in enumerate(lines):
        line = strip_comment(raw)
        m = ITEM_RE.match(line)
        if m is not None and (cur_indent is None or indent_of(line) <= cur_indent):
            if cur_start is not None:
                yield cur_start, "\n".join(buf)
            cur_start, cur_indent, buf = i + 1, indent_of(line), [line]
            continue
        if cur_start is None:
            continue
        # A non-blank line dedented past the item ends it -- otherwise the last
        # step of a job would swallow the next job's keys and could pick up a
        # `ref:` that belongs to something else entirely.
        if line.strip() and indent_of(line) <= cur_indent:
            yield cur_start, "\n".join(buf)
            cur_start, cur_indent, buf = None, None, []
            continue
        buf.append(line)
    if cur_start is not None:
        yield cur_start, "\n".join(buf)


def main(argv):
    if len(argv) != 3:
        die("usage: gha_checkout_ref.py <workflow.yml> <owner/repo>")
    path, want = argv[1], argv[2]
    try:
        with open(path, "r", encoding="utf-8") as fh:
            lines = fh.readlines()
    except OSError as exc:
        die("cannot read %s (%s)" % (path, exc))
    if not lines:
        die("%s is empty" % path)

    hits = []
    for start, text in steps(lines):
        for name in REPO_RE.findall(text):
            if name == want:
                hits.append((start, text))
                break

    if len(hits) == 0:
        die(
            "no checkout step naming repository '%s' in %s. Either the workflow "
            "stopped checking it out, or the step is written in a shape this "
            "scanner does not parse." % (want, path)
        )
    if len(hits) > 1:
        die(
            "%d checkout steps name repository '%s' in %s (lines %s) -- ambiguous, "
            "so which ref the build uses cannot be determined."
            % (len(hits), want, path, ", ".join(str(h[0]) for h in hits))
        )

    start, text = hits[0]
    refs = REF_RE.findall(text)
    if len(refs) > 1:
        die("checkout step at %s:%d has %d `ref:` keys" % (path, start, len(refs)))

    print("FOUND_STEPS=1")
    print("STEP_LINE=%d" % start)
    if refs and refs[0].strip():
        print("PINNED=yes")
        print("REF=%s" % refs[0].strip())
    else:
        print("PINNED=no")
        print("REF=")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
