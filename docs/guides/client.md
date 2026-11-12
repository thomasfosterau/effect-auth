# The browser client

`@thomasfosterau/effect-auth/client` is the front-end half of effect-auth: a dependency-free client over the auth HTTP contract (plain `fetch`, no Effect runtime in the bundle). The session is an `effect/reactivity` Atom graph over that client, in `@thomasfosterau/effect-auth/client/atoms` (§2), so it lives in the same registry as the rest of a page's Atoms. A thin Svelte binding, with out-of-the-box form components (§4), ships as its own package on top of it (§3). Only the _types_ come from `@thomasfosterau/effect-auth`, and those erase at compile time — nothing server-side reaches the browser bundle.

## 1. Setup

```ts
import { createAuthClient } from "@thomasfosterau/effect-auth/client";

export const client = createAuthClient({
  // Where the auth handler is mounted. Same-origin ("/api/auth") or absolute.
  baseUrl: "/api/auth",
});
```

| Option    | Purpose                                                |
| --------- | ------------------------------------------------------ |
| `baseUrl` | Mount point of the auth handler.                       |
| `fetch`   | Custom `fetch` — SSR, tests, or an in-process handler. |
| `headers` | Extra headers on every request (e.g. a tenant header). |

Every call sends `credentials: "include"`, so the session cookie flows on cross-origin deployments too (the server must list your origin in `trustedOrigins`). A non-2xx response rejects with an `AuthClientError` carrying the HTTP `status` and the server's message:

```ts
import { AuthClientError } from "@thomasfosterau/effect-auth/client";

try {
  await client.signIn({ email, password });
} catch (error) {
  if (error instanceof AuthClientError && error.status === 401) showBadCredentials();
}
```

Optional server modules that are not configured answer `404` — a client method existing does not mean the deployment mounted the feature.

## 2. The session Atoms

The client keeps no session state. `makeSessionAtoms(client)` from `@thomasfosterau/effect-auth/client/atoms` builds the session as Atoms, which you read through your application's `AtomRegistry` — the same one your other Atoms (a sync engine's live queries, say) live in, so one runtime serves the whole page:

```ts
import { AtomRegistry } from "effect/reactivity";
import { makeSessionAtoms } from "@thomasfosterau/effect-auth/client/atoms";

export const registry = AtomRegistry.make();
export const auth = makeSessionAtoms(client);

const unsubscribe = registry.subscribe(auth.state, render, { immediate: true });
registry.refresh(auth.result); // manual refetch
```

`auth.result` is the session read as an `AsyncResult<SessionWithUserView | null, AuthClientError>`; `state` (`{ data, isPending, error }`), `data`, `isSignedIn`, `isPending` and `error` derive from it, and `sessions` / `sessionsState` are the signed-in user's session list. A `401` is `data: null` rather than an error, and a _transient_ failure keeps the last known session while surfacing `error`.

Commands stay plain calls on the client. The Atoms observe them through `client.onSessionChange`, and four behaviours follow:

- **Lazy**: the first read or subscription starts the `GET /sessions/current` read. It starts pending, so a UI never flashes "signed out" on first paint.
- **Awaited**: while a session Atom is mounted, a session-changing call (sign-in/up/out, second-factor redemption, `setActive`, impersonation, …) refetches it and resolves only once the refetch has settled, so the code after `await client.signIn(...)` sees the new session.
- **Refetch-skipping**: with nothing mounted, the round trip is skipped; the next subscriber starts from the last read.
- **Last dispatch wins**: a refetch superseded by a later one is interrupted, so a stale answer never lands.

A session change propagates through the graph, with no invalidation list: an Atom that reads `auth.data` or `auth.isSignedIn` recomputes on sign-in and sign-out, and `auth.sessions` refetches when the session's id changes.

```ts
import { Atom } from "effect/reactivity";

const greeting = Atom.make((get) => {
  const user = get(auth.data)?.user;
  return user === undefined ? "Hello, guest" : `Hello, ${user.email}`;
});
```

Background refresh is opt-in per set of Atoms:

```ts
makeSessionAtoms(client, {
  refresh: {
    intervalMs: 60_000, // poll while observed
    onFocus: true, // refetch on tab focus / visibility change
    crossTab: true, // mirror changes across tabs via BroadcastChannel
  },
});
```

Each feature starts with the first subscriber and stops with the last; `onFocus` and `crossTab` degrade to no-ops outside the browser.

Server-side rendering has no hydration story yet: the Atoms start pending in the browser even when the server knew the session (follow-up to #206).

## 3. Framework binding

The Svelte binding is its own package, depends on the core for its `/client` and `/client/atoms` subpaths, and adapts the session Atoms to Svelte stores, so an app that doesn't use Svelte installs only the client:

| Framework | Package                              | Exports                                                           |
| --------- | ------------------------------------ | ----------------------------------------------------------------- |
| Svelte    | `@thomasfosterau/effect-auth-svelte` | `atomStore`, `sessionStore`, `listSessionsStore`, form components |

```svelte
<!-- Svelte — @thomasfosterau/effect-auth-svelte -->
<script>
  import { sessionStore } from "@thomasfosterau/effect-auth-svelte";
  const session = sessionStore(registry, auth);
</script>
{#if $session.data}Signed in as {$session.data.user.email}{/if}
```

`atomStore(registry, atom)` is the whole Svelte↔Atom binding — any Atom as a readable store, mounted while subscribed — and the session stores are it applied to the session Atoms. The stores implement Svelte's readable-store contract by hand; the components and context helpers use Svelte 5 runes, so the package requires `svelte >= 5.20` as a peer.

## 4. Form components

The Svelte package ships six headless form components out of the box: `SignInForm` (email or `variant="username"`), `SignUpForm`, `PasswordResetRequestForm`, `PasswordResetConfirmForm`, `MagicLinkForm`, and `EmailOtpForm` (request + verify in one). Each owns its submit/pending/error state, calls the typed client from context (`setAuthClient`, overridable with a `client` prop), reports through `onSuccess`/`onError`, never navigates, and renders semantic, unstyled markup addressable through stable `ea-*` classes (`ea-form`, `ea-field`, `ea-label`, `ea-input`, `ea-submit`, `ea-error`, ...) with every visible string overridable via a `labels` prop. The package's README documents context setup and a styling example.

## 5. Endpoint coverage

Methods mirror the contract's endpoint names and are grouped by feature. Their payload and view types are the contract's own — import them from the `@thomasfosterau/effect-auth/http` subpath (`import type * as Http from "@thomasfosterau/effect-auth/http"`, then `Http.SignUpPayload`); being type-only, they cost the browser bundle nothing. The endpoint each one calls is in the core README's [endpoint reference](../../packages/effect-auth/README.md#http-endpoint-reference); a client from before the JSON:API conversion is mapped onto the current methods in the [migration guide](./jsonapi-migration.md).

**Core** — `signUp`, `signIn`, `signOut`, `getSession`, `sendVerificationEmail`, `verifyEmail`, `passwordResetRequest`, `passwordResetConfirm`, `changePassword`, `updateUser`, `listSessions`, `revokeSession`, `revokeOtherSessions`.

**Identifiers** — the login handles (email / username / phone) behind an account. Deleting the last one is refused by the server (`403`), so an account is never orphaned.

```ts
const handles = await client.identifiers.list();
await client.identifiers.delete(handles[0].id);
```

**Alternative sign-in** — `signInUsername`, `signInAnonymous` (guest accounts), `magicLink.{send,verify}`, `emailOtp.{send,signIn}`, `phoneOtp.{send,signIn}`, `googleOneTap.{nonce,signIn}`, `sso.{register,signIn,callback}` (`register` is `POST /sso-providers`, `signIn` `POST /sso-authorizations`; the callback keeps the OIDC binding's format).

SAML's two endpoints are deliberately absent: the assertion consumer service (`POST /sso/saml/acs/:providerId`) is a form POST the IdP makes through the browser, and SP metadata (`GET /sso/saml/metadata/:providerId`) is an XML document an IdP admin imports by URL. Neither is a call JavaScript makes.

**Device authorization (RFC 8628)** — `device.code()` and `device.token()` on the input-constrained device (RFC 8628's own wire format), `device.approve()` / `device.deny()` on the verification page the signed-in user opens (`POST /device-authorizations/decisions`, the user code in the body; approving needs the session, denying does not):

```ts
const { deviceCode, userCode, verificationUri, interval } = await client.device.code();
// …show userCode + verificationUri, then poll:
const session = await client.device.token({ deviceCode }); // 400 until decided
```

**Account management** — `changeEmail.{request,confirm}`, `deleteUser.{request,confirm}`. Requests are session-authenticated and always answer `{ status: true }` (anti-enumeration); the confirm endpoints take the token from the email.

**Multi-session** — several accounts signed in on one device: `multiSession.list()`, `multiSession.setActive({ sessionId })`, `multiSession.revoke({ sessionId })`, where `sessionId` is the id the list gave (the session's stored id, never its token). Requires the server's `multiSession` option; the active account is the primary session cookie.

**Multi-factor** — `multiFactor.enable`, `confirm`, `disable`, `regenerateBackupCodes`, `verifyTotp`, `verifyBackupCode`, plus the continuation helper in §5.

**Organizations** — orgs, members, invitations, claimed email domains, teams and per-organization roles, all under `client.organization`:

```ts
const org = await client.organization.create({ name: "Acme", slug: "acme" });
await client.organization.invite(org.id, { email: "new@acme.test", role: "member" });
// As the invitee, with the token the invitation email's link carried:
await client.organization.acceptInvitation(invitationId, token);
await client.organization.resendInvitation(invitationId); // same id, fresh token and expiry

const team = await client.organization.createTeam(org.id, { name: "Engineering" });
const teamMember = await client.organization.addTeamMember(team.id, { userId });
await client.organization.removeTeamMember(teamMember.id); // by the team membership's own id

// Dynamic access control: redefine a role for this organization only. A role
// the organization already defines answers 409; change it by its own id.
const role = await client.organization.createRole(org.id, { role: "member", permissions: [] });
await client.organization.updateRole(role.id, { permissions: ["team:create"] });

// The role members added without one receive (owner-only).
await client.organization.setDefaultRole(org.id, { role: "member" });
await client.organization.addMember(org.id, { userId }); // ...gets that role

// Suspend a membership instead of deleting it. The row and the member's role
// survive (the role comes back on reactivate), every permission check in this
// organization now denies them, and their app session is left alone.
// Memberships are addressed by their own id (`member.id`).
const member = await client.organization.addMember(org.id, { userId, role: "admin" });
await client.organization.deactivateMember(member.id);
await client.organization.reactivateMember(member.id);

// Claim a domain, publish the TXT record, then verify it. A verified domain
// plus `update(org.id, { jitProvisioning: true })` provisions membership on
// SSO sign-in for anyone with a verified address at that domain.
const claim = await client.organization.addDomain(org.id, { domain: "acme.test" });
claim.verificationToken; // publish as a TXT record, then:
const verified = await client.organization.verifyDomain(claim.id); // by the claim's own id
verified.verificationState; // "verified" | "failed" — retry a failed check

await client.organization.setActive({ organizationId: org.id }); // recorded on the session
```

Full surface: `create`, `list`, `get`, `update`, `delete`, `setActive`, `setDefaultRole`, `addMember`, `updateMemberRole`, `removeMember`, `deactivateMember`, `reactivateMember`, `invite`, `listInvitations`, `acceptInvitation`, `rejectInvitation`, `cancelInvitation`, `resendInvitation`, `listDomains`, `addDomain`, `verifyDomain`, `removeDomain`, `createRole`, `listRoles`, `updateRole`, `deleteRole`, `createTeam`, `listTeams`, `listTeamsForMember`, `updateTeam`, `deleteTeam`, `addTeamMember`, `listTeamMembers`, `removeTeamMember`. A record the server addresses by id (a membership, a domain claim, a role definition, a team membership) is passed by its own `id`, as the call that created or listed it answers it. Calls answer `403` when the actor's role lacks the required permission — including a domain call when the server has no `OrganizationDomainStore` wired, and a DNS verification when it has no `DomainVerifier`. An organization proves a domain only through DNS; manual attestation is the operator's, after checking ownership out of band, through the `isAdmin`-gated `client.admin.attestDomain({ organizationId, domain })` (#598).

**API keys** — `apiKeys.{create,list,update,delete}` over `/api-keys`. The plaintext key comes back exactly once, from `create` (the server sends it in the create's `meta.key`). Creating one needs the session cookie: over a bearer credential it is `403`.

**JWT** — `jwtToken()` mints a signed token for the current session (`POST /tokens`, so the trusted-origin check covers it); `jwks()` serves the keys that verify it.

**Admin** — `admin.{listUsers,setRole,banUser,unbanUser,removeUser,revokeSessions,impersonate,stopImpersonating}` over `/admin/users`, `/user-bans` and `/impersonations`. The actor must satisfy the server's `isAdmin`; everyone else gets `403`. `unbanUser` resolves with nothing (the lifted ban is a `204`). `impersonate`/`stopImpersonating` swap the session cookie, so the observed session refetches; `stopImpersonating` answers `404` on a session that is not an impersonation.

**OIDC provider** — the surfaces a first-party app drives: `oidc.{registerClient,listClients,updateClient,deleteClient}` over `/oauth-clients` (admin-gated; a confidential client's secret comes back once, from `registerClient`) and `oidc.consent()` for the consent page's decision. The protocol endpoints (`/oauth2/authorize`, `/oauth2/token`, `/oauth2/userinfo`, discovery, RFC 7591 registration) are for OAuth clients rather than this SDK — see the [MCP provider guide](./mcp-provider.md).

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
// Signed in — the observed session has refetched.
```

Failure modes are typed as `SecondFactorChallengeError`:

- `reason: "missing"` — thrown synchronously by `continueChallenge` when the result carries no challenge (the user is already signed in).
- `reason: "expired"` — the verify calls reject with this _without issuing a request_ once `expiresAt` has passed on the device's clock. The server enforces expiry as well; this just saves a doomed round trip.

A wrong code is a server-side rejection (`AuthClientError`, status `401`) and leaves the challenge redeemable until it expires. Already holding a `SecondFactorChallengeView` (e.g. restored from component state)? `client.multiFactor.challenge(view)` returns the same object.

## 7. Plugins

`extend` bolts typed methods onto a client — for endpoints a deployment adds itself, or for composing several calls into one app-level operation.

```ts
import { definePlugin } from "@thomasfosterau/effect-auth/client";

const billingPlugin = definePlugin((ctx) => ({
  listInvoices: () => ctx.request<Invoice[]>("GET", "/billing/invoices"),
  // `mutating` runs the call, then notifies the session observers.
  switchPlan: (plan: string) =>
    ctx.mutating(() => ctx.request<void>("POST", "/billing/plan", { plan })),
}));

const client = createAuthClient({ baseUrl: "/api/auth" }).extend(billingPlugin);
await client.listInvoices(); // typed, alongside every built-in method
```

The install context gives a plugin `request` (raw call) and `mutating` (call, then notify the session observers). `extend` returns a new client — the original is untouched — and plugins compose by chaining `.extend()`.

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

`@thomasfosterau/effect-auth/client/testing` packages exactly this: `makeServerFixture({ features, organization, multiSession })` builds the real handler over in-memory stores, and `makeCookieJarFetch(handler)` is the cookie-jar `fetch`. It imports the core and `effect` at runtime, so keep it to tests. For groups whose server module is disproportionate to stand up (API keys, admin, …), a recording `fetch` that asserts method/path/body is enough.
