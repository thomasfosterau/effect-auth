# @thomasfosterau/effect-auth-better-auth

[BetterAuth](https://www.better-auth.com/) as the backend for [`@thomasfosterau/effect-auth`](https://github.com/thomasfosterau/effect-auth/tree/trunk/packages/effect-auth)'s services. The app keeps BetterAuth's runtime, tables, routes and browser client. It gains effect-auth's Effect services, authorization kernel and guards on top. This is stage 1 of the [migration from BetterAuth](../../docs/guides/better-auth-migration.md): keep BetterAuth and adopt the kernel. Moving the data comes later, if at all.

> [!NOTE]
> The package is private and not published to npm yet.

## Install

```sh
pnpm add @thomasfosterau/effect-auth-better-auth @thomasfosterau/effect-auth better-auth effect
```

`better-auth` (`^1.7.28`) and `effect` are peer dependencies.

## Usage

```ts
import { Layer } from "effect";
import { betterAuth } from "better-auth";
import { BetterAuth, Credentials, Session, Users } from "@thomasfosterau/effect-auth-better-auth";

export const auth = betterAuth({/* your existing configuration */});

export const AuthLayer = Layer.mergeAll(
  Session.BetterAuthSessions.layer, // request → session, for the SvelteKit `handle`
  Session.sessionServiceLayer, // Auth.SessionService.SessionService
  Users.usersLayer(), // Auth.User.UserService, UserStore, IdentifierStore, AccountDeletion
  Credentials.BetterAuthCredentials.layer, // sign-up, sign-in, sign-out
).pipe(Layer.provideMerge(BetterAuth.BetterAuthInstance.layer(auth)));
```

With SvelteKit, `BetterAuthSessions` feeds the `handle` hook directly. Its `lookup` answers BetterAuth's `Set-Cookie` lines, so a session BetterAuth slides on read reaches the browser.

```ts
const runtime = ManagedRuntime.make(AuthLayer);
const sessions = await runtime.runPromise(Effect.service(Session.BetterAuthSessions));

export const handle = SvelteKit.handle({
  cookies: sessions.credentialConfig, // BetterAuth's cookie name, read from the instance
  lookup: (request) => sessions.lookup(request),
  failure: { mode: "closed" },
});
```

## What maps where

| effect-auth                               | BetterAuth                                                            |
| ----------------------------------------- | --------------------------------------------------------------------- |
| `BetterAuthSessions.lookup(request)`      | `auth.api.getSession({ headers })`                                    |
| `SessionService.validateSession(token)`   | `internalAdapter.findSession(token)`, with expiry and bans            |
| `SessionService.listSessions` / `revoke*` | `internalAdapter.listSessions` / `deleteSession(s)`                   |
| `SessionService.setSessionAttributes`     | `internalAdapter.updateSession`, declared columns only                |
| `UserStore`, `UserService`                | `internalAdapter.findUserById` / `updateUser` / `deleteUser`          |
| `IdentifierStore` reads                   | `user.email`, `username` (plugin), `phoneNumber` (plugin)             |
| `BetterAuthCredentials`                   | `auth.api.signUpEmail` / `signInEmail` / `signInUsername` / `signOut` |
| `PasswordHasher.betterAuthHasher()`       | `better-auth/crypto`'s scrypt                                         |

Sessions are named by BetterAuth's stored `session.id`. The token never appears in a domain value.

## What it does not do

- **No sessions issued here.** `SessionService.createSession` fails: BetterAuth's routes issue sessions and their signed cookie.
- **No identifier writes.** `IdentifierStore.create`, `replace` and `delete*` are refused. An email change that skipped BetterAuth's verification would be an account-takeover vector; use `auth.api.changeEmail`.
- **No effect-auth hooks or plugins.** BetterAuth's `hooks` and `databaseHooks` still run.
- **Pass-through.** OAuth, magic links, OTPs, two-factor, passkeys, password reset and email verification stay with BetterAuth. Organizations, admin and API keys have no service here.
- **The SvelteKit `credentialAction` and two-factor.** BetterAuth answers a held two-factor sign-in with `200 { twoFactorRedirect: true }`, not `202`, so the action redirects as if signed in (BetterAuth clears the session cookie, so the viewer arrives signed out). Send two-factor users to your second-factor page yourself, or use `BetterAuthCredentials`, which answers `status: "second-factor"`.
- **`UserService.deleteUser` skips `/delete-user`'s checks** (fresh session, verification). It is for trusted server code.

## Licence

MIT
