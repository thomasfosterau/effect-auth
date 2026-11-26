# @thomasfosterau/effect-auth-workos

> [!WARNING]
> Private and unpublished: some WorkOS API details are still unverified against a live environment.

WorkOS AuthKit as the backend for [effect-auth](../effect-auth): WorkOS keeps users, passwords and sessions; effect-auth's services, hooks and HTTP tier run over its API. The session is a sealed, stateless cookie that validates without a WorkOS call until its access token needs a refresh. Runs on Cloudflare Workers (no WorkOS SDK, no `node:` imports).

## Usage

```ts
import { Layer, Redacted } from "effect";
import * as Auth from "@thomasfosterau/effect-auth";
import * as Http from "@thomasfosterau/effect-auth/http";
import * as WorkOS from "@thomasfosterau/effect-auth-workos";

const services = WorkOS.layer({
  apiKey: Redacted.make(env.WORKOS_API_KEY),
  clientId: env.WORKOS_CLIENT_ID,
  cookiePassword: Redacted.make(env.WORKOS_COOKIE_PASSWORD), // 32+ bytes
  redirectUri: "https://app.example.com/auth/callback",
}).pipe(
  Layer.provideMerge(
    Layer.mergeAll(
      Auth.Hooks.Default,
      Auth.OAuthStateStoreKV, // over your KeyValueStore
      Auth.RootSecret.RootSecret.layer(env.AUTH_SECRET),
      WorkOS.Session.RevokedSessions.layerKeyValueStore,
    ),
  ),
);

export const { handler } = Http.make({ services });
```

`WorkOS.WorkOS.config` reads `WORKOS_API_KEY`, `WORKOS_CLIENT_ID`, `WORKOS_COOKIE_PASSWORD`, `WORKOS_REDIRECT_URI` and `WORKOS_ISSUER` instead.

## What it covers

- Email and password sign-up, sign-in and change (WorkOS holds the password); email verification with `<userId>:<code>`; password reset; Magic Auth as the email OTP.
- AuthKit sign-in (hosted UI, Google, Microsoft, GitHub, Apple, an SSO connection or organization) through `OAuthService` and `SsoService`.
- Organizations read-only: the token's `org_id`, `role`, `roles` and `permissions` are on the session (`workos.*`), `Authorization.entityResolverLayer` feeds roles to the core's policies, and `WorkOSSessions.switchOrganization` moves a session to another organization.
- Webhooks (`Webhook.verify`, `WorkOSEvents`) and the Events API (`Events.list`); a `session.revoked` event ends the cookie before its token expires.
- WorkOS sends the emails by default; `delivery: "app"` hands Magic Auth codes and reset links to your `EmailSender`.

Not in v1: WorkOS MFA, passkeys and organization management.
