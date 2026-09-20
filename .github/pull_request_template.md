<!--
Fill in the sections below. Delete any that genuinely don't apply, but
default to filling them in rather than deleting them.
-->

## Summary

<!-- What changed and why, in a few bullet points. -->

-

## Upstream compatibility

<!--
Ground rule from CONTRIBUTING.md: this installer must not drift from the
official Xen Orchestra installation docs
(https://docs.xen-orchestra.com/install-from-sources). If this PR changes
install, build, or configuration behavior, cite the relevant upstream docs
here. If it deviates from upstream, say so explicitly and why.
-->

## Checklist

- [ ] `shellcheck -S warning install-xen-orchestra.sh` passes
- [ ] `bash -n install-xen-orchestra.sh` passes
- [ ] `bats tests/unit/` passes
- [ ] Ran an integration image, if this touches install/build behavior
- [ ] Added a `CHANGELOG.md` entry under `[Unreleased]`, if this is a
      user-facing change (see `CHANGELOG.md`'s own guidance on what counts)
- [ ] Updated any docs this change makes wrong (README, `docs/`, in-script
      help text, plugin READMEs)

## Test plan

<!-- How was this actually verified? What was run, against what. -->
