# Design: `switch-org` command + storage permission fix

Date: 2026-05-29
Status: Approved (draft 1)
Component: `legion-auth` (github.com/picogrid/legion-system-auth)

## Summary

Add the ability to switch a provisioned device from one Legion organization to
another. The primary work is re-provisioning the device's integration and
terminal entity in the new org, reusing the existing terminal where possible,
and optionally removing the terminal from the old org. A pre-existing storage
permission regression (the daemon cannot read tokens after re-running setup) is
fixed as part of this work.

## Background

Today, switching orgs is *mostly* achievable by re-running `setup` (or
`setup --org-id <id>`): it re-authenticates, picks a new org, creates/selects an
org-scoped integration, overwrites `oauth_config.json` + token files, and
`createTerminalEntity` already validates the cached `terminal_entity.json`
against the *new* org and resolves by serial number — so an existing terminal in
the new org is reused, not duplicated.

What is missing:
1. A clear, intentional UX for switching orgs.
2. Handling the terminal entity left behind in the **old** org.
3. A storage permission regression that breaks token refresh after a re-run.

### Architectural constraint

Stored tokens are **integration tokens scoped to the old org**, and integrations
are created **per-org**. Therefore `switch-org` must re-authenticate the user
(password grant → user token). That user token is org-agnostic (the org is
selected per request via the `X-ORG-ID` header), which is also what enables
deleting the old org's entity. So `switch-org` is a focused, old-context-aware
re-run of setup's provisioning steps.

## Decisions (confirmed)

- **UX:** dedicated `switch-org` subcommand.
- **Old-org terminal:** prompt to delete (interactive); `--remove-old` flag in
  non-interactive mode, default = keep.
- **Permission fix:** bundled into this work.
- **Non-interactive:** full flag + `LEGION_AUTH_*` env parity with `setup`.
- **Delete failure:** warn and continue, exit 0 (the switch already succeeded).
- **Delete endpoint:** assume `DELETE /v3/entities/{id}` with `X-ORG-ID`.
  Not critical for the first draft; revise if the real endpoint/semantics differ.

## Design

### 1. `switch-org` subcommand

Add a `switch-org` case to the argument dispatch in `main.go`, with its own
`flag.FlagSet`. Flags:

- `--org-id`            target organization (skips org selector)
- `--username` / `--password`  user credentials for re-authentication
- `--api-url`          Legion API URL (default: stored `LegionBaseURL`)
- `--storage-path`     custom storage path
- `--entity-name` / `--entity-type`  optional overrides; default reuses the
  existing device's serial/type so it keeps its identity in the new org
- `--remove-old`       delete the old org's terminal (non-interactive control)
- `--non-interactive`  run without prompts

Env fallbacks via the existing `applySetupEnvDefaults` pattern, plus a new
`LEGION_AUTH_REMOVE_OLD` (`true`/`1`).

**Precondition:** an existing `oauth_config.json` is required (setup must have
run before). Otherwise error and direct the user to `setup`.

Non-interactive validation mirrors setup: require `--org-id`, `--username`,
`--password`; fail fast listing any missing flags.

### 2. Flow (order matters for safety)

1. `setupStorage` (applies the permission fix from §4).
2. **Capture old context before any overwrite:** read current
   `oauth_config.json` + `terminal_entity.json` →
   `oldOrgID`, `oldOrgName`, `oldEntityID`, `oldSerial`, `oldType`, `apiURL`.
3. **Guard:** if target org == old org → no-op message, exit 0.
4. Authenticate user (password grant) → org-agnostic user token
   (`getWellKnownConfig` + `authenticateUser`).
5. Resolve new org (`getOrganization` via `--org-id`, else `selectOrganization`).
6. **Provision integration in new org**, reusing the manifest from the old
   config (keeps permissions/redirect consistent): `createIntegration` → on 409
   find/select existing → fetch/regenerate client secret.
7. Headless OAuth PKCE in new org → new integration tokens; overwrite
   `oauth_config.json` / `access_token.json` / `refresh_token.json`
   (`performHeadlessOAuthFlow` / `exchangeCodeForTokens`).
8. **Terminal in new org** (watch-out #1): call `createTerminalEntity` for the
   new org with the reused serial/type. Existing `resolveEntityBySerialNumber`
   finds-and-reuses an existing terminal, creating only if absent.
9. **Old-org cleanup last** (watch-out #2): if `oldEntityID` exists and orgs
   differ → interactive prompt (or `--remove-old`, default keep) → delete old
   entity using the user token + `X-ORG-ID: oldOrgID`. On failure: warn and
   continue, exit 0.

Performing cleanup last guarantees a cleanup failure never leaves the device
stranded between orgs.

### 3. New code (small, composes existing helpers)

- `deleteEntity(apiURL, orgID, token, entityID) error` — the one net-new Legion
  call (`DELETE /v3/entities/{id}`, `Authorization` + `X-ORG-ID`).
- `loadCurrentContext()` — reads old config + entity into a small struct.
- `switchOrg(opts)` — orchestrator composing the existing setup helpers above.

### 4. Permission fix (bundled)

Root cause: `setupStorage` creates the dir via `os.MkdirAll(path, 0755)` (subject
to umask). The dir mode is corrected only inside `setOwnership`, which
early-returns when the `pg` user is absent or `chown` fails — before reaching its
`chmod`. Under a restrictive umask the dir stays e.g. `0700`/`0750` and is never
fixed; on re-run `MkdirAll` is a no-op and `setOwnership` early-returns again, so
the daemon (different user/group) cannot traverse the dir to read tokens.

Fix:
- In `setupStorage`, **unconditionally** `os.Chmod(StoragePath, 0750)` right after
  `MkdirAll`, independent of the `pg`-user path; ensure parent `/etc/picogrid` is
  traversable.
- Keep `setOwnership` for `chown` when `pg`/`picogrid` exist.
- Files remain `0640` (already force-chmod'd in `saveJSON`).

Net effect: the manual `chmod 750 <dir>` + `chmod 640 *.json` workaround now
happens automatically on every run.

### 5. Testing

Following `main_test.go` patterns with `httptest`:
- Flag/env parsing + non-interactive validation (missing flags).
- "Already in target org" no-op guard.
- Old-context capture from config + entity.
- `deleteEntity` request shape + warn-and-continue on failure.
- Terminal reuse-by-serial in new org.
- Permission fix: `setupStorage` under a restrictive `syscall.Umask` still
  yields dir `0750` / files `0640`.

## Open items (non-blocking)

- Confirm the entity-delete endpoint and semantics (hard vs soft delete);
  adjust `deleteEntity` if it differs from `DELETE /v3/entities/{id}`.

## Out of scope

- Removing the old org's *integration* (only the terminal entity is handled).
- Multi-org / simultaneous-org support (one active org at a time, as today).
