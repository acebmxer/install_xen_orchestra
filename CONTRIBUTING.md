# Contributing

Thanks for helping improve the Xen Orchestra installation script!

## Ground rule: follow upstream documentation

This installer must not drift from the official Xen Orchestra
[installation documentation](https://docs.xen-orchestra.com/installation#from-the-sources).
When you change install, build, or configuration behavior, cite the relevant
upstream docs in your pull request. Only deviate where upstream gives no
guidance — and say so explicitly.

## Development setup

The project is a single Bash script (`install-xen-orchestra.sh`) plus helper
files. To work on it you need:

- `bash`
- [ShellCheck](https://www.shellcheck.net/) (>= 0.9)
- [bats-core](https://github.com/bats-core/bats-core) for the unit tests
- Docker (optional) for the multi-distro integration tests

## Before opening a pull request

Run the same checks CI runs:

1. **Lint** the main script (CI gates at warning level):
   ```bash
   shellcheck -S warning install-xen-orchestra.sh
   ```
2. **Syntax-check** the script:
   ```bash
   bash -n install-xen-orchestra.sh
   ```
3. **Run the unit tests:**
   ```bash
   bats tests/unit/
   ```
4. **(Optional) Run an integration image**, e.g. Debian 12:
   ```bash
   docker build -f tests/integration/Dockerfile.debian12 -t xo-test-debian12 .
   docker run --rm xo-test-debian12
   ```

CI runs steps 1, 3, and 4 (across Debian 12, Ubuntu 24.04, and Rocky Linux 9)
on every push and pull request.

## Coding conventions

- Keep `set -euo pipefail` semantics intact. Declare and assign separately when
  a command substitution's exit status matters (avoids ShellCheck SC2155):
  ```bash
  local foo
  foo=$(some_command)
  ```
- Prefer the existing `log_info` / `log_success` / `log_warning` / `log_error`
  helpers over raw `echo`.
- Wrap privileged actions in the existing `run_cmd` helper so `--dry-run` keeps
  working.
- If you must suppress a ShellCheck finding, use a narrowly-scoped
  `# shellcheck disable=SCxxxx` with a comment explaining why. Genuinely global
  suppressions live in [.shellcheckrc](.shellcheckrc).

## Commit messages

Use [Conventional Commits](https://www.conventionalcommits.org/): `feat:`,
`fix:`, `refactor:`, `docs:`, `test:`, `chore:`, etc. Add notable user-facing
changes to [CHANGELOG.md](CHANGELOG.md) under the `[Unreleased]` heading.
