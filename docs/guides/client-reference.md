# Browser client reference

The `/client`, `/client/atoms` and `/client/testing` subpaths in detail. The [client guide](./client.md) walks through a setup.

The browser half of [effect-auth](https://github.com/thomasfosterau/effect-auth), in two subpaths:

- `/client`: a small client over the effect-auth HTTP contract (plain `fetch`; absence is an `Option`, so `effect/Option` is the one Effect module in the bundle). It holds no session state; it tells its observers when a call changed the session.
- `/client/atoms`: the session as [`effect/reactivity`](https://effect.website/) Atoms over that client, read through your application's `AtomRegistry`, so auth shares one Atom graph and one runtime with the rest of the page.

Only the wire _types_ come from the `/http` subpath, and those erase at compile time, so nothing server-side reaches the browser bundle. `/client` imports only `effect/Option` at runtime; `/client/atoms` adds the rest of `effect` and `effect/reactivity`. The root barrel re-exports neither.

## Usage

```ts
import { AuthClientError, createAuthClient } from "@thomasfosterau/effect-auth/client";
import { makeSessionAtoms } from "@thomasfosterau/effect-auth/client/atoms";
import { AtomRegistry } from "effect/reactivity";

const client = createAuthClient({ baseUrl: "/api/auth" });

// The session, as Atoms over the client, read through the page's one registry.
const registry = AtomRegistry.make();
const auth = makeSessionAtoms(client, { refresh: { onFocus: true } });
const unsubscribe = registry.subscribe(
  auth.state,
  ({ data, isPending, error }) => {
    console.log(isPending ? "loading" : (data?.user.id ?? "signed out"), error?.message);
  },
  { immediate: true },
);

// Commands are plain calls named after the contract's endpoints. A
// session-changing call resolves once the observed session has refetched.
const result = await client.signIn({ email: "ada@example.com", password: "correct horse" });
if (result.secondFactor) {
  // Password accepted; a second factor is required before a session is issued.
  await client.multiFactor.continueChallenge(result).verifyTotp("123456");
}
console.log(registry.get(auth.isSignedIn)); // true

try {
  await client.signIn({ email: "ada@example.com", password: "wrong" });
} catch (error) {
  if (error instanceof AuthClientError && error.status === 401) {
    console.log("bad credentials");
  }
}

unsubscribe();
```

Every request is sent with `credentials: "include"`, so the session cookie flows on cross-origin deployments too (the server must list your origin in `trustedOrigins`). A non-2xx response rejects with an `AuthClientError` carrying the HTTP `status` and the server's `message`. Optional server features that are not configured answer `404`: a method existing on the client does not mean the server mounted it.

## Options

`createAuthClient(options: AuthClientOptions): AuthClient`

| Option    | Type                     | Purpose                                                              |
| --------- | ------------------------ | -------------------------------------------------------------------- |
| `baseUrl` | `string`                 | Where the auth handler is mounted: `"/api/auth"` or an absolute URL. |
| `fetch`   | `typeof fetch`           | Custom `fetch`: SSR, tests, or an in-process handler.                |
| `headers` | `Record<string, string>` | Extra headers on every request.                                      |

`client.onSessionChange(listener)` registers an observer of session-changing calls (every sign-in and sign-up, sign-out, second-factor redemption, email verification, the email-change and account-deletion confirmations, `updateUser`, `multiSession.setActive`, `organization.setActive`, impersonation, the SSO callback and the device token poll) and returns its removal; the call resolves only once every observer's promise has settled, and an observer's rejection never fails it. `client.invalidateSession()` notifies the observers by hand, for a change the client did not make. The session Atoms are such an observer; you rarely register one yourself.

## The session Atoms (`/client/atoms`)

`makeSessionAtoms(client, options?: SessionAtomsOptions): SessionAtoms`. Make them once per client and read them through your registry:

| Atom            | Value                                                                                 |
| --------------- | ------------------------------------------------------------------------------------- |
| `result`        | `AsyncResult<Option<SessionWithUserView>, AuthClientError>`, the session read itself  |
| `state`         | `SessionState`: `{ data, isPending, error }`                                          |
| `data`          | `Option<SessionWithUserView>`: `None` when signed out                                 |
| `isSignedIn`    | `boolean`                                                                             |
| `isPending`     | `boolean`: the read is in flight                                                      |
| `error`         | `Option<AuthClientError>`: the last unexpected error                                  |
| `sessions`      | `AsyncResult<readonly SessionView[], AuthClientError>`, the signed-in user's sessions |
| `sessionsState` | `SessionListState`: `{ data, isPending, error }` over `sessions`                      |

The read is lazy: nothing is fetched until a registry reads or mounts an Atom, and it starts pending, so a UI never flashes "signed out" before the first fetch. A `401` is `data: None`, not an error; any other failure keeps the last `data` and sets `error`; a refetch superseded by a later one is interrupted, so its answer never lands. While a session Atom is mounted, every session-changing call refetches it before it resolves; with nothing mounted, the round trip is skipped, and the next subscriber starts from the last read. `registry.refresh(auth.isSignedIn)` (or any session Atom) refetches; `registry.refresh(auth.sessions)` re-reads the list.

A session change propagates through the graph: an Atom of your own that reads `auth.data` or `auth.isSignedIn` recomputes on sign-in and sign-out with no invalidation list, and `sessions` refetches when the session's id changes (signed out, it is empty without a request).

`options.refresh` (`RefreshOptions`) turns on background refresh while the session is observed, all off by default: `intervalMs` polls `GET /sessions/current`; `onFocus` refetches on window focus and when the tab becomes visible; `crossTab` mirrors session changes across tabs over a `BroadcastChannel` (`true` for the default channel name `"effect-auth-session"`, or a name of your own). Each starts with the first subscriber, stops with the last, and degrades to a no-op outside a browser.

## Methods

Each method resolves to the contract's own view type (`Http.*`). Groups:

| Group            | Methods                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| ---------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Session and user | `signUp`, `signIn`, `signOut`, `signInAnonymous`, `signInUsername`, `getSession` (`None` when signed out), `updateUser`, `changePassword`, `listSessions`, `revokeSession`, `revokeOtherSessions`, `jwtToken`, `jwks`                                                                                                                                                                                                                                                         |
| Email            | `sendVerificationEmail`, `verifyEmail`, `passwordResetRequest`, `passwordResetConfirm`, `magicLink.send` / `.verify`, `emailOtp.send` / `.signIn`, `changeEmail.request` / `.confirm`                                                                                                                                                                                                                                                                                         |
| Phone and others | `phoneOtp.send` / `.signIn`, `googleOneTap.nonce` / `.signIn`, `device.code` / `.token` / `.lookup` / `.approve` / `.deny` (RFC 8628)                                                                                                                                                                                                                                                                                                                                         |
| Account          | `identifiers.list` / `.delete`, `deleteUser.request` / `.confirm`, `multiSession.list` / `.setActive` / `.revoke`                                                                                                                                                                                                                                                                                                                                                             |
| Multi-factor     | `multiFactor.enable`, `.confirm`, `.disable`, `.regenerateBackupCodes`, `.verifyTotp`, `.verifyBackupCode`, `.challenge(challenge)`, `.continueChallenge(result)`                                                                                                                                                                                                                                                                                                             |
| Organizations    | `organization.create`, `list`, `get`, `update`, `delete`, `setActive`, members (`addMember`, then by the membership's own `id`: `updateMemberRole`, `removeMember`, `deactivateMember`, `reactivateMember`, `listTeamsForMember`; `setDefaultRole`), invitations, domains (`removeDomain` / `verifyDomain` by the claim's `id`), roles (`createRole`, then `updateRole` / `deleteRole` by the definition's `id`) and teams (`removeTeamMember` by the team membership's `id`) |
| API keys         | `apiKeys.create` (the plaintext key is returned once), `list`, `update`, `delete`                                                                                                                                                                                                                                                                                                                                                                                             |
| Admin            | `admin.listUsers`, `setRole`, `banUser`, `unbanUser` (resolves with nothing), `removeUser`, `revokeSessions`, `impersonate`, `stopImpersonating`, `attestDomain`, `lookupDomain` and `releaseDomain` (the operator's domain attestation, lookup and release)                                                                                                                                                                                                                  |
| SSO and OIDC     | `sso.register` / `.signIn` / `.callback`; `oidc.registerClient`, `listClients`, `updateClient`, `deleteClient`, `consent`                                                                                                                                                                                                                                                                                                                                                     |

`multiFactor.continueChallenge(result)` takes the `AuthResult` a sign-in returned and binds its pending challenge, so the caller passes only the code. It throws `SecondFactorChallengeError` (`reason: "missing"`) when the result carries no challenge, and its `verifyTotp` / `verifyBackupCode` reject with `reason: "expired"` once the challenge window has passed, without a request.

## Plugins

`definePlugin(install)` builds a plugin whose `install(context)` returns extra methods; `client.extend(plugin)` returns the client with them added. The context (`AuthClientPluginContext`) exposes `request(method, path, body?)` and `mutating(run)` (run a session-changing call, then notify the session observers).

```ts
import { createAuthClient, definePlugin } from "@thomasfosterau/effect-auth/client";

interface Profile {
  readonly bio: string;
}

const profilePlugin = definePlugin((ctx) => ({
  profile: () => ctx.request<Profile>("GET", "/profile"),
}));

const client = createAuthClient({ baseUrl: "/api/auth" }).extend(profilePlugin);
const profile = await client.profile();
```

## Testing: `/client/testing`

An in-process effect-auth server for end-to-end client tests: the real `Http.make` handler over in-memory stores, and a `fetch` that emulates the browser's cookie jar. Unlike `/client`, it imports the core and `effect` at runtime (and `@thomasfosterau/effect-jsonapi`, through the HTTP tier), so keep it to tests.

```ts
import { createAuthClient } from "@thomasfosterau/effect-auth/client";
import { makeCookieJarFetch, makeServerFixture } from "@thomasfosterau/effect-auth/client/testing";

const server = makeServerFixture({ features: true });
const client = createAuthClient({
  baseUrl: "http://localhost", // the fixture handler is mounted at the root
  fetch: makeCookieJarFetch(server.handler),
});

await client.signUp({ email: "ada@example.com", password: "correct horse battery staple" });
console.log(server.sessions.size); // 1
```

`makeServerFixture(options?)` serves with the per-address IP limit off (`ipRateLimit: false`), since its one client has no address, and mounts optional modules only when asked: `features` (username and anonymous sign-in, multi-factor, account management, phone OTP, device authorization, with an in-memory `RateLimiter`), `organization`, and `multiSession`. It returns the `handler` plus the in-memory state and the messages the server "sent" (`sentChangeEmail`, `sentDeleteTokens`, `sentPhoneOtps`, `sentInvitations` with each invitation's token), for assertions.

## API

- `createAuthClient(options)`, `AuthClient`, `AuthClientOptions`, `SessionChangeListener`
- `AuthClientError` (`status`), `SecondFactorChallengeError` (`reason`), `SecondFactorContinuation`
- `definePlugin`, `AuthClientPlugin`, `AuthClientPluginContext`
- `./client/atoms`: `makeSessionAtoms`, `SessionAtoms`, `SessionAtomsOptions`, `RefreshOptions`, `SessionState`, `SessionListState`, `SessionResult`, `SessionListResult`
- `./client/testing`: `makeServerFixture`, `ServerFixtureOptions`, `makeCookieJarFetch`

## Framework bindings

| Framework | Package                                                                                                  |
| --------- | -------------------------------------------------------------------------------------------------------- |
| Svelte    | [`@thomasfosterau/effect-auth-svelte`](https://www.npmjs.com/package/@thomasfosterau/effect-auth-svelte) |

The [client guide](https://github.com/thomasfosterau/effect-auth/blob/trunk/docs/guides/client.md) walks through the binding and its form components.
