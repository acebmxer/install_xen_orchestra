---
name: Bug report
about: Something in the installer does not work as documented
title: '[Bug] '
labels: bug
assignees: ''
---

## What happened

<!-- A clear description of what went wrong. Include the script's output
     around the failure. -->

## What you expected

## Steps to reproduce

1. Run `./install-xen-orchestra.sh ...`
2. Select / enter `...`
3. See error

## Output

<!-- The output, or the file from --log-file, with addresses, usernames,
     passwords, tokens and anything else sensitive removed. -->

```
(paste output here)
```

## Environment

| Field | Value |
|-------|-------|
| Installer version | <!-- output of `./install-xen-orchestra.sh --version` --> |
| OS running the script | <!-- from `cat /etc/os-release`, e.g. Debian 13, Ubuntu 26.04 --> |
| XCP-ng / pool version | <!-- if the problem involves --deploy, --proxy or --build-templates --> |
| Fresh install or update | <!-- and the Xen Orchestra commit or branch, if known --> |
| Function affected | <!-- e.g. install, update, --deploy, --proxy, --twinstor, --build-templates, menu --> |

## Does the same happen following Vates' docs by hand?

<!-- If you can, try the same step from the official install docs
     (https://docs.xen-orchestra.com/install-from-sources). This tells us
     whether the problem is in the installer or in Xen Orchestra itself. -->

- [ ] Same problem following the docs by hand
- [ ] Works by hand, fails only with the installer
- [ ] Not tried

## Additional context

<!-- Screenshots or anything else that might help. -->
