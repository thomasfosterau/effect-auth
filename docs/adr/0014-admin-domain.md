# Admin domain

The Admin module lives under `packages/effect-auth/src/admin/` in the `effect-auth` core package,
following the same bounded-context-in-core pattern as Organization (ADR-0008). Three decisions
shape it.

**Scope: every pure auth-logic admin operation, no audit logging.** Ships: `listUsers`,
`getUserDetail`, `banUser`/`unbanUser` (creates/deletes a `Ban { userId, reason, expiresAt? }`
feature-local entity per ADR-0015 — not a column on User), `deleteUserAsAdmin` (bypasses
`preventLastCredentialUnlink`), `revokeUserSessions`, `revokeSession`, `forceUpdateUser`,
`impersonate`. Audit logging is deliberately excluded — ADR-0003 places better-auth's commercial
audit/dashboard infrastructure out of scope. Deployers can log admin actions by composing their
own observers around the admin Effects.

**Permission model: reserved `"system-admin"` role checked through the existing
`AuthorizationPolicy`/`RoleStore`.** Mirrors the org pattern from ADR-0009 — a library-reserved
name anchors the check (`AdminAccessControl.requireSystemAdmin(actingUserId)`), but the role-to-
user resolution flows through the existing `RoleStore`. Deployers wire system-admin membership
however they want (env-configured singleton, a `SystemRole` table, an external SSO group claim).
Layered checks (org-scoped admins, IP-allowlist) compose with the policy.

**Impersonation as a Session field, with explicit destructive-op guards.** `Session` grows an
optional `impersonatedBy?: string` (the admin's `userId`), set when the Session was created via
`impersonate(adminUserId, targetUserId)` and never afterwards. The library does not hide the
state — downstream code can inspect it from any Session, and we ship `assertNotImpersonating
(session)` (returning `OperationForbiddenDuringImpersonationError`) as a default-deny guard used
internally on `changePassword`, `deleteUser` (self-delete), `unlinkAccount`, `add2FA`, and
`removeBackupCode`. Deployers wrap their own destructive ops with the same helper.
`endImpersonation(sessionId)` invalidates the session so the admin re-authenticates as
themselves; we don't try to mutate a Session out of impersonation in place.

The Session-field choice here contradicts the active-org placement in ADR-0009, where we chose a
separate `ActiveOrgSelection` entity rather than a Session column. The difference is the security
profile: active-org is a deployment-optional UX concern, but impersonation, if shipped at all, is
a security-critical state that **must** be visible at every authorisation checkpoint. A separate
`ImpersonationMarker` entity would mean every auth check joins a second table to learn whether
impersonation is in effect — exactly the wrong pattern for a signal this load-bearing. We accept
the always-null column on non-impersonated Sessions as the cost of guaranteed inspection.

The broader trade-off in this ADR: shipping impersonation at all. We considered punting it (the
"power tool with abuse potential" argument) and rejected that on the grounds that consumers will
build it themselves — almost certainly worse, almost certainly without the marker, and almost
certainly without the destructive-op guards.
