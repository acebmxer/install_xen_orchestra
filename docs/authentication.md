# Running task detection and REST API authentication

[← back to the README](../README.md)

Before applying an update, the script queries the Xen Orchestra REST API for
active tasks (e.g. running backups, VM exports). If any are found, the update
is aborted to prevent data loss or corruption.

## Authentication

Only **admin-level** XO accounts can access the REST API. Authentication is
resolved in priority order:

| Priority | Method | Source |
|----------|--------|--------|
| 1 | Auth token | `XO_TASK_CHECK_TOKEN` in `xo-config.cfg` |
| 2 | Credentials | `XO_TASK_CHECK_USER` / `XO_TASK_CHECK_PASS` in `xo-config.cfg` |
| 3 | Interactive | Prompted at runtime (press Enter to skip) |

## Recommended: dedicated XO account

It is recommended to create a **dedicated XO web UI account** solely for the
task check (e.g. `task-checker@local.net`). This account:

- Must have **Admin** privileges (required by the REST API)
- Exists only within the XO web interface — no shell access, SSH keys, or
  OS-level permissions are needed
- Provides a clear audit trail separate from personal accounts
- Prevents shared credentials from being used for unrelated actions

You are free to use any admin account you choose, but a dedicated account is
the safest approach.

## Using an auth token (recommended)

Tokens are more secure than storing a password — they can be revoked
independently and expire after 30 days by default.

> [!IMPORTANT]
> **Tokens must have a description or they will be deleted during updates.**
>
> During an update the installer flushes stale session tokens from Redis to
> prevent schema-mismatch 401 errors after XO restarts. It tells session
> tokens apart from API tokens by checking for a non-empty `description` field
> in the token's stored JSON:
>
> - Tokens **with** a description → treated as API/integration tokens → **kept**
> - Tokens **without** a description → treated as browser session tokens → **deleted**
>
> This applies to `XO_TASK_CHECK_TOKEN` and to **any other API tokens** used
> by third-party tools (monitoring agents, Terraform, scripts, etc.) that
> connect to this XO server. Always create tokens with a meaningful
> description.

**Option 1 — XO web UI (always prompts for a description):**

1. Log into the XO web UI with the dedicated account
2. Go to **Settings → Authentication tokens → New token**
3. Enter a description (e.g. `installer-task-check`) and copy the generated token value
4. Add to `xo-config.cfg`:
   ```bash
   XO_TASK_CHECK_TOKEN=UlTBEnFeL12XocK-7Qx-DKvOYbPn0eG7Z2oMvOniNjg
   ```

**Option 2 — curl (include a description in the request body):**

1. Log into the XO web UI with the dedicated account
2. Generate a token with a description:
   ```bash
   curl -X POST -u 'task-checker@local.net:yourpassword' \
     https://localhost/rest/v0/users/me/authentication_tokens \
     -H 'Content-Type: application/json' \
     -d '{"description":"installer-task-check"}' -k
   ```
3. Copy the `id` field from the response
4. Add to `xo-config.cfg`:
   ```bash
   XO_TASK_CHECK_TOKEN=UlTBEnFeL12XocK-7Qx-DKvOYbPn0eG7Z2oMvOniNjg
   ```

## Using credentials

Alternatively, store the account credentials directly:

```bash
XO_TASK_CHECK_USER=task-checker@local.net
XO_TASK_CHECK_PASS=changeme
```

> [!NOTE]
> If neither token nor credentials are configured, the script will prompt
> interactively during each update.

