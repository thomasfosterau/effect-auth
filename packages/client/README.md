# @thomasfosterau/effect-auth-client

The browser half of [effect-auth](https://github.com/thomasfosterau/effect-auth): a small client over the effect-auth HTTP contract (plain `fetch`, no Effect runtime in the bundle) with an observable session store. Only the wire _types_ come from `@thomasfosterau/effect-auth`, and those erase at compile time, so nothing server-side reaches the browser bundle.

## Install

```sh
pnpm add @thomasfosterau/effect-auth-client effect
```

`effect` (`>=4.0.0-rc.118`) is a peer dependency, for the types; the client's runtime code imports nothing from it.

## Usage

```ts
import { AuthClientError, createAuthClient } from "@thomasfosterau/effect-auth-client";

const client = createAuthClient({ baseUrl: "/api/auth" });

// Typed methods named after the contract's endpoints.
const result = await client.signIn({ email: "ada@example.com", password: "correct horse" });
if (result.secondFactor) {
  // Password accepted; a second factor is required before a session is issued.
  await client.multiFactor.continueChallenge(result).verifyTotp("123456");
}

// The observable session store the framework bindings subscribe to.
const unsubscribe = client.session.subscribe(() => {
  const { data, isPending, error } = client.session.get();
  console.log(isPending ? "loading" : (data?.user.id ?? "signed out"), error?.message);
});

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

| Option    | Type                     | Purpose                                                                  |
| --------- | ------------------------ | ------------------------------------------------------------------------ |
| `baseUrl` | `string`                 | Where the auth handler is mounted: `"/api/auth"` or an absolute URL.     |
| `fetch`   | `typeof fetch`           | Custom `fetch`: SSR, tests, or an in-process handler.                    |
| `headers` | `Record<string, string>` | Extra headers on every request.                                          |
| `refresh` | `RefreshOptions`         | Opt-in background refresh: `intervalMs`, `onFocus`, `crossTab`. All off. |

`refresh.intervalMs` polls `GET /sessions/current` while something is subscribed; `onFocus` refetches on window focus and when the tab becomes visible; `crossTab` mirrors session changes across tabs over a `BroadcastChannel` (`true` for the default channel name `"effect-auth-session"`, or a name of your own). Each degrades to a no-op outside a browser.

## The session store

`client.session` is a `SessionStore`:

| Member                | Behaviour                                                                   |
| --------------------- | --------------------------------------------------------------------------- |
| `get()`               | The current `SessionState`: `{ data, isPending, error }`. Stable reference. |
| `subscribe(listener)` | Returns an unsubscribe function. The first subscriber triggers the fetch.   |
| `refetch()`           | Re-reads `GET /sessions/current` and notifies subscribers.                  |

`data` is the `SessionWithUserView` or `null` when signed out. The store starts at `isPending: true`, so a UI never flashes "signed out" before the first fetch. A `401` resolves to `data: null`, not an error; any other failure keeps the last `data` and sets `error`. Session-changing calls (every sign-in and sign-up, sign-out, second-factor redemption, email verification, the email-change and account-deletion confirmations, `updateUser`, `multiSession.setActive`, `organization.setActive`, impersonation, the SSO callback and the device token poll) refetch the store only while something is subscribed.

## Methods

Each method resolves to the contract's own view type (`Http.*`). Groups:

| Group            | Methods                                                                                                                                                                                                                           |
| ---------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Session and user | `signUp`, `signIn`, `signOut`, `signInAnonymous`, `signInUsername`, `getSession` (`null` when signed out), `updateUser`, `changePassword`, `listSessions`, `revokeSession`, `revokeOtherSessions`, `jwtToken`, `jwks`             |
| Email            | `sendVerificationEmail`, `verifyEmail`, `passwordResetRequest`, `passwordResetConfirm`, `magicLink.send` / `.verify`, `emailOtp.send` / `.signIn`, `changeEmail.request` / `.confirm`                                             |
| Phone and others | `phoneOtp.send` / `.signIn`, `googleOneTap.nonce` / `.signIn`, `device.code` / `.token` / `.approve` / `.deny` (RFC 8628)                                                                                                         |
| Account          | `identifiers.list` / `.delete`, `deleteUser.request` / `.confirm`, `multiSession.list` / `.setActive` / `.revoke`                                                                                                                 |
| Multi-factor     | `multiFactor.enable`, `.confirm`, `.disable`, `.regenerateBackupCodes`, `.verifyTotp`, `.verifyBackupCode`, `.challenge(challenge)`, `.continueChallenge(result)`                                                                 |
| Organizations    | `organization.create`, `list`, `get`, `update`, `delete`, `setActive`, members (`addMember`, `updateMemberRole`, `removeMember`, `deactivateMember`, `reactivateMember`, `setDefaultRole`), invitations, domains, roles and teams |
| API keys         | `apiKeys.create` (the plaintext key is returned once), `list`, `update`, `delete`                                                                                                                                                 |
| Admin            | `admin.listUsers`, `setRole`, `banUser`, `unbanUser`, `removeUser`, `revokeSessions`, `impersonate`, `stopImpersonating`                                                                                                          |
| SSO and OIDC     | `sso.register` / `.signIn` / `.callback`; `oidc.registerClient`, `listClients`, `updateClient`, `deleteClient`, `consent`                                                                                                         |

`multiFactor.continueChallenge(result)` takes the `AuthSuccess` a sign-in returned and binds its pending challenge, so the caller passes only the code. It throws `SecondFactorChallengeError` (`reason: "missing"`) when the result carries no challenge, and its `verifyTotp` / `verifyBackupCode` reject with `reason: "expired"` once the challenge window has passed, without a request.

## Plugins

`definePlugin(install)` builds a plugin whose `install(context)` returns extra methods; `client.extend(plugin)` returns the client with them added. The context (`AuthClientPluginContext`) exposes `request(method, path, body?)`, `mutating(run)` (run a session-changing call, then refetch when observed) and the `session` store.

```ts
import { createAuthClient, definePlugin } from "@thomasfosterau/effect-auth-client";

interface Profile {
  readonly bio: string;
}

const profilePlugin = definePlugin((ctx) => ({
  profile: () => ctx.request<Profile>("GET", "/profile"),
}));

const client = createAuthClient({ baseUrl: "/api/auth" }).extend(profilePlugin);
const profile = await client.profile();
```

## Testing: `@thomasfosterau/effect-auth-client/testing`

An in-process effect-auth server for end-to-end client tests: the real `Http.make` handler over in-memory stores, and a `fetch` that emulates the browser's cookie jar. Unlike the main entry, it imports `@thomasfosterau/effect-auth` and `effect` at runtime, so keep it to tests.

```ts
import { createAuthClient } from "@thomasfosterau/effect-auth-client";
import { makeCookieJarFetch, makeServerFixture } from "@thomasfosterau/effect-auth-client/testing";

const server = makeServerFixture({ features: true });
const client = createAuthClient({
  baseUrl: "http://localhost", // the fixture handler is mounted at the root
  fetch: makeCookieJarFetch(server.handler),
});

await client.signUp({ email: "ada@example.com", password: "correct horse battery staple" });
console.log(server.sessions.size); // 1
```

`makeServerFixture(options?)` mounts optional modules only when asked: `features` (username and anonymous sign-in, multi-factor, account management, phone OTP, device authorization, with an in-memory `RateLimiter`), `organization`, and `multiSession`. It returns the `handler` plus the in-memory state and the messages the server "sent" (`sentChangeEmail`, `sentDeleteTokens`, `sentPhoneOtps`), for assertions.

## API

- `createAuthClient(options)`, `AuthClient`, `AuthClientOptions`, `RefreshOptions`
- `SessionStore`, `SessionState`
- `AuthClientError` (`status`), `SecondFactorChallengeError` (`reason`), `SecondFactorContinuation`
- `definePlugin`, `AuthClientPlugin`, `AuthClientPluginContext`
- `./testing`: `makeServerFixture`, `ServerFixtureOptions`, `makeCookieJarFetch`

## Framework bindings

| Framework | Package                                                                                                  |
| --------- | -------------------------------------------------------------------------------------------------------- |
| React     | [`@thomasfosterau/effect-auth-react`](https://www.npmjs.com/package/@thomasfosterau/effect-auth-react)   |
| Svelte    | [`@thomasfosterau/effect-auth-svelte`](https://www.npmjs.com/package/@thomasfosterau/effect-auth-svelte) |
| Vue       | [`@thomasfosterau/effect-auth-vue`](https://www.npmjs.com/package/@thomasfosterau/effect-auth-vue)       |
| Solid     | [`@thomasfosterau/effect-auth-solid`](https://www.npmjs.com/package/@thomasfosterau/effect-auth-solid)   |

The [client guide](https://github.com/thomasfosterau/effect-auth/blob/trunk/docs/guides/client.md) walks through the bindings and their form components.

## License

MIT
