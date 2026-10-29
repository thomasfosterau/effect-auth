# The browser client

`@thomasfosterau/effect-auth-client` is the front-end half of effect-auth: a dependency-free client over the auth HTTP contract (plain `fetch`, no Effect runtime in the bundle) with an observable session store. Thin React / Svelte / Vue / Solid bindings — with out-of-the-box form components (§4) — ship as their own packages on top of it (§3). Only the _types_ come from `@thomasfosterau/effect-auth`, and those erase at compile time — nothing server-side reaches the browser bundle.

## 1. Setup

```ts
import { createAuthClient } from "@thomasfosterau/effect-auth-client";

export const client = createAuthClient({
  // Where the auth handler is mounted. Same-origin ("/api/auth") or absolute.
  baseUrl: "/api/auth",
});
```

| Option    | Purpose                                                         |
| --------- | --------------------------------------------------------------- |
| `baseUrl` | Mount point of the auth handler.                                |
| `fetch`   | Custom `fetch` — SSR, tests, or an in-process handler.          |
| `headers` | Extra headers on every request (e.g. a tenant header).          |
| `refresh` | Opt-in background refresh; see §2. All of it is off by default. |

Every call sends `credentials: "include"`, so the session cookie flows on cross-origin deployments too (the server must list your origin in `trustedOrigins`). A non-2xx response rejects with an `AuthClientError` carrying the HTTP `status` and the server's message:

```ts
import { AuthClientError } from "@thomasfosterau/effect-auth-client";

try {
  await client.signIn({ email, password });
} catch (error) {
  if (error instanceof AuthClientError && error.status === 401) showBadCredentials();
}
```

Optional server modules that are not configured answer `404` — a client method existing does not mean the deployment mounted the feature.

## 2. The session store

`client.session` is a tiny observable holding `{ data, isPending, error }`. `data` is the `SessionWithUserView` or `null` when signed out; a `401` resolves to `data: null` rather than an error, and a _transient_ failure keeps the last known session while surfacing `error`.

```ts
const unsubscribe = client.session.subscribe(() => render(client.session.get()));
await client.session.refetch(); // manual refresh
```

Two behaviours worth knowing:

- **Lazy**: the first subscriber triggers the initial `GET /sessions/current` read. The store starts as `isPending: true` so a UI never flashes "signed out" on first paint.
- **Refetch-skipping**: session-changing calls (sign-in/up/out, second-factor redemption, `setActive`, impersonation, …) refresh the store only while something is subscribed — with no observers, the round trip is skipped.

Background refresh is opt-in per client:

```ts
createAuthClient({
  baseUrl: "/api/auth",
  refresh: {
    intervalMs: 60_000, // poll while subscribed
    onFocus: true, // refetch on tab focus / visibility change
    crossTab: true, // mirror changes across tabs via BroadcastChannel
  },
});
```

The interval starts with the first subscriber and is cleared when the last one leaves; `onFocus` and `crossTab` degrade to no-ops outside the browser.

## 3. Framework bindings

Each binding is its own package, depends on `@thomasfosterau/effect-auth-client`, and subscribes to the same store — so an app installs only the framework it uses:

| Framework | Package                              | Exports                                                |
| --------- | ------------------------------------ | ------------------------------------------------------ |
| React     | `@thomasfosterau/effect-auth-react`  | `useSession`, `useListSessions`, form components       |
| Svelte    | `@thomasfosterau/effect-auth-svelte` | `sessionStore`, `listSessionsStore`, form components   |
| Vue       | `@thomasfosterau/effect-auth-vue`    | `useSession`, `useListSessions`, form components       |
| Solid     | `@thomasfosterau/effect-auth-solid`  | `createSession`, `createListSessions`, form components |

```tsx
// React — @thomasfosterau/effect-auth-react
import { useSession, useListSessions } from "@thomasfosterau/effect-auth-react";

function Navbar() {
  const { data, isPending } = useSession(client);
  if (isPending) return <Spinner />;
  return data ? <b>{data.user.email}</b> : <a href="/login">Sign in</a>;
}
```

```svelte
<!-- Svelte — @thomasfosterau/effect-auth-svelte -->
<script>
  import { sessionStore } from "@thomasfosterau/effect-auth-svelte";
  const session = sessionStore(client);
</script>
{#if $session.data}Signed in as {$session.data.user.email}{/if}
```

```vue
<!-- Vue — @thomasfosterau/effect-auth-vue -->
<script setup>
import { useSession } from "@thomasfosterau/effect-auth-vue";
const session = useSession(client);
</script>
<template>
  <span v-if="session.data">{{ session.data.user.email }}</span>
</template>
```

The Svelte session stores implement Svelte's readable-store contract by hand; the components and context helpers use Svelte 5 runes, so the package requires `svelte >= 5.20` as a peer.

The Vue composables unsubscribe with the current effect scope. Called outside one (plain scripts, tests) they warn and hand back a `dispose()` to call yourself.

```tsx
// Solid — @thomasfosterau/effect-auth-solid
import { createSession } from "@thomasfosterau/effect-auth-solid";

function Navbar() {
  const session = createSession(client);
  return <span>{session().data?.user.email}</span>;
}
```

## 4. Form components

Every framework package ships the same six headless form components out of the box: `SignInForm` (email or `variant="username"`), `SignUpForm`, `PasswordResetRequestForm`, `PasswordResetConfirmForm`, `MagicLinkForm`, and `EmailOtpForm` (request + verify in one). Each owns its submit/pending/error state, calls the typed client from context (a provider per framework, overridable with a `client` prop), reports through `onSuccess`/`onError` (Vue: `success`/`error` events), never navigates, and renders semantic, unstyled markup addressable through stable `ea-*` classes (`ea-form`, `ea-field`, `ea-label`, `ea-input`, `ea-submit`, `ea-error`, ...) with every visible string overridable via a `labels` prop. Each package's README documents provider setup and a styling example.

## 5. Endpoint coverage

Methods mirror the contract's endpoint names and are grouped by feature. Their payload and view types are the contract's own — import them from the `@thomasfosterau/effect-auth/http` subpath (`import type * as Http from "@thomasfosterau/effect-auth/http"`, then `Http.SignUpPayload`); being type-only, they cost the browser bundle nothing.

**Core** — `signUp`, `signIn`, `signOut`, `getSession`, `sendVerificationEmail`, `verifyEmail`, `passwordResetRequest`, `passwordResetConfirm`, `changePassword`, `updateUser`, `listSessions`, `revokeSession`, `revokeOtherSessions`.

**Identifiers** — the login handles (email / username / phone) behind an account. Deleting the last one is refused by the server (`400`), so an account is never orphaned.

```ts
const handles = await client.identifiers.list();
await client.identifiers.delete(handles[0].id);
```

**Alternative sign-in** — `signInUsername`, `signInAnonymous` (guest accounts), `magicLink.{send,verify}`, `emailOtp.{send,signIn}`, `phoneOtp.{send,signIn}`, `googleOneTap.{nonce,signIn}`, `sso.{register,signIn,callback}`.

SAML's two endpoints are deliberately absent: the assertion consumer service (`POST /sso/saml/acs/:providerId`) is a form POST the IdP makes through the browser, and SP metadata (`GET /sso/saml/metadata/:providerId`) is an XML document an IdP admin imports by URL. Neither is a call JavaScript makes.

**Device authorization (RFC 8628)** — `device.code()` and `device.token()` on the input-constrained device, `device.approve()` / `device.deny()` on the verification page the signed-in user opens:

```ts
const { deviceCode, userCode, verificationUri, interval } = await client.device.code();
// …show userCode + verificationUri, then poll:
const session = await client.device.token({ deviceCode }); // 400 until decided
```

**Account management** — `changeEmail.{request,confirm}`, `deleteUser.{request,confirm}`. Requests are session-authenticated and always answer `{ status: true }` (anti-enumeration); the confirm endpoints take the token from the email.

**Multi-session** — several accounts signed in on one device: `multiSession.list()`, `multiSession.setActive({ sessionId })`, `multiSession.revoke({ sessionId })`. Requires the server's `multiSession` option; the active account is the primary session cookie.

**Multi-factor** — `multiFactor.enable`, `confirm`, `disable`, `regenerateBackupCodes`, `verifyTotp`, `verifyBackupCode`, plus the continuation helper in §5.

**Organizations** — orgs, members, invitations, claimed email domains, teams and per-organization roles, all under `client.organization`:

```ts
const org = await client.organization.create({ name: "Acme", slug: "acme" });
await client.organization.invite(org.id, { email: "new@acme.test", role: "member" });
await client.organization.acceptInvitation(invitationId); // as the invitee
await client.organization.resendInvitation(invitationId); // same id, fresh expiry

const team = await client.organization.createTeam(org.id, { name: "Engineering" });
await client.organization.addTeamMember(team.id, { userId });

// Dynamic access control: redefine a role for this organization only.
await client.organization.upsertRole(org.id, "member", { permissions: ["team:create"] });

// The role members added without one receive (owner-only).
await client.organization.setDefaultRole(org.id, { role: "member" });
await client.organization.addMember(org.id, { userId }); // ...gets that role

// Suspend a membership instead of deleting it. The row and the member's role
// survive (the role comes back on reactivate), every permission check in this
// organization now denies them, and their app session is left alone.
await client.organization.deactivateMember(org.id, userId);
await client.organization.reactivateMember(org.id, userId);

// Claim a domain, publish the TXT record, then verify it. A verified domain
// plus `update(org.id, { jitProvisioning: true })` provisions membership on
// SSO sign-in for anyone with a verified address at that domain.
const claim = await client.organization.addDomain(org.id, { domain: "acme.test" });
claim.verificationToken; // publish as a TXT record, then:
const verified = await client.organization.verifyDomain(org.id, claim.id);
verified.verificationState; // "verified" | "failed" — retry a failed check

await client.organization.setActive({ organizationId: org.id }); // recorded on the session
```

Full surface: `create`, `list`, `get`, `update`, `delete`, `setActive`, `setDefaultRole`, `addMember`, `updateMemberRole`, `removeMember`, `deactivateMember`, `reactivateMember`, `invite`, `listInvitations`, `acceptInvitation`, `rejectInvitation`, `cancelInvitation`, `resendInvitation`, `listDomains`, `addDomain`, `verifyDomain`, `removeDomain`, `upsertRole`, `listRoles`, `deleteRole`, `createTeam`, `listTeams`, `listTeamsForMember`, `updateTeam`, `deleteTeam`, `addTeamMember`, `listTeamMembers`, `removeTeamMember`. Calls answer `403` when the actor's role lacks the required permission — including a domain call when the server has no `OrganizationDomainStore` wired, and a DNS verification when it has no `DomainVerifier` (claim the domain with `verificationStrategy: "manual"` instead).

**API keys** — `apiKeys.{create,list,update,delete}`. The plaintext key comes back exactly once, from `create`.

**JWT** — `jwtToken()` mints a signed token for the current session; `jwks()` serves the keys that verify it.

**Admin** — `admin.{listUsers,setRole,banUser,unbanUser,removeUser,revokeSessions,impersonate,stopImpersonating}`. The actor must satisfy the server's `isAdmin`; everyone else gets `403`. `impersonate`/`stopImpersonating` swap the session cookie, so the store refreshes.

**OIDC provider** — the surfaces a first-party app drives: `oidc.{registerClient,listClients,updateClient,deleteClient}` (admin-gated) and `oidc.consent()` for the consent page's decision. The protocol endpoints (`/oauth2/authorize`, `/oauth2/token`, `/oauth2/userinfo`, discovery, RFC 7591 registration) are for OAuth clients rather than this SDK — see the [MCP provider guide](./mcp-provider.md).

## 6. Continuing a second-factor challenge

When multi-factor is enrolled, a password sign-in issues **no session**. It returns an `AuthResult` with no `user` and a `secondFactor` carrying `{ token, expiresAt }`, and the challenge must be redeemed for a session. `continueChallenge` takes that result and hands back the verify calls already bound to the token:

```ts
const result = await client.signIn({ email, password });

if (result.secondFactor) {
  const challenge = client.multiFactor.continueChallenge(result);
  // challenge.token / challenge.expiresAt / challenge.isExpired() are available
  // for a countdown in the UI.
  await challenge.verifyTotp(codeFromUser); // or:
  await challenge.verifyBackupCode(backupCode); // single-use
}
// Signed in — the session store has refreshed.
```

Failure modes are typed as `SecondFactorChallengeError`:

- `reason: "missing"` — thrown synchronously by `continueChallenge` when the result carries no challenge (the user is already signed in).
- `reason: "expired"` — the verify calls reject with this _without issuing a request_ once `expiresAt` has passed on the device's clock. The server enforces expiry as well; this just saves a doomed round trip.

A wrong code is a server-side rejection (`AuthClientError`, status `401`) and leaves the challenge redeemable until it expires. Already holding a `SecondFactorChallengeView` (e.g. restored from component state)? `client.multiFactor.challenge(view)` returns the same object.

## 7. Plugins

`extend` bolts typed methods onto a client — for endpoints a deployment adds itself, or for composing several calls into one app-level operation.

```ts
import { definePlugin } from "@thomasfosterau/effect-auth-client";

const billingPlugin = definePlugin((ctx) => ({
  listInvoices: () => ctx.request<Invoice[]>("GET", "/billing/invoices"),
  // `mutating` runs the call, then refreshes the session store if observed.
  switchPlan: (plan: string) =>
    ctx.mutating(() => ctx.request<void>("POST", "/billing/plan", { plan })),
}));

const client = createAuthClient({ baseUrl: "/api/auth" }).extend(billingPlugin);
await client.listInvoices(); // typed, alongside every built-in method
```

The install context gives a plugin `request` (raw call), `mutating` (call + conditional session refresh) and `session` (the store). `extend` returns a new client — the original is untouched — and plugins compose by chaining `.extend()`.

## 8. Testing against a real server

The client's `fetch` option is the whole seam: point it at your auth handler in-process and the suite needs no network, no ports and no mock of the protocol.

```ts
const { handler } = Http.make({ services, cookie: { secure: false } });

const client = createAuthClient({
  baseUrl: "http://app.test",
  // A `fetch` that dispatches to `handler` and keeps a cookie jar between
  // calls — the client relies on `credentials: "include"`.
  fetch: cookieJarFetch(handler),
});

await client.signUp({ email, password });
expect((await client.getSession())?.user.email).toBe(email);
```

The package's own suite does exactly this: `src/testing/fixture.ts` builds the real handler over in-memory stores (`makeServerFixture({ features, organization, multiSession })`) and pairs it with `makeCookieJarFetch`. It is test-only — excluded from the published build — so copy the ~30-line pattern rather than importing it. For groups whose server module is disproportionate to stand up (API keys, admin, …), a recording `fetch` that asserts method/path/body is enough.
