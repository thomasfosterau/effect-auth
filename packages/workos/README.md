# @effect-auth/workos

Effect-native bindings for the [WorkOS](https://workos.com) Node SDK. This
package exposes the **entire WorkOS feature set** as typed Effects, so you get
WorkOS's full platform — SSO, AuthKit / User Management, Directory Sync (SCIM),
Organizations, MFA, Audit Logs, Events, Webhooks, Fine-Grained Authorization
(FGA), Vault, Widgets, the Admin Portal, Passwordless / Magic Auth and more —
with Effect's error handling, dependency injection and composition.

Rather than hand-wrapping each endpoint, every WorkOS module is re-exposed
through a typed proxy derived from the SDK's own types. Each method keeps its
exact signature but returns an `Effect<Result, WorkOSError>` instead of a
`Promise<Result>`. The surface therefore stays in lock-step with the installed
`@workos-inc/node` version — new endpoints become available automatically.

## What you get

A single [`WorkOS`](./src/WorkOS.ts) service whose properties mirror the WorkOS
client, with every method lifted into an Effect:

| Property              | WorkOS feature                                           |
| --------------------- | -------------------------------------------------------- |
| `sso`                 | Enterprise Single Sign-On                                |
| `userManagement`      | AuthKit / User Management (auth, sessions, MFA, invites) |
| `directorySync`       | Directory Sync (SCIM)                                    |
| `organizations`       | Organizations                                            |
| `organizationDomains` | Organization domain verification                         |
| `multiFactorAuth`     | Standalone Multi-Factor Authentication                   |
| `passwordless`        | Magic Link / passwordless sessions                       |
| `auditLogs`           | Audit Logs (events, exports, schemas)                    |
| `events`              | Events API                                               |
| `webhooks`            | Webhook endpoints + signature verification               |
| `authorization`       | Fine-Grained Authorization (FGA)                         |
| `vault`               | Vault (encryption / secrets)                             |
| `widgets`             | Widgets (embeddable UI session tokens)                   |
| `adminPortal`         | Admin Portal links                                       |
| `actions`             | Actions (signed responses)                               |
| `apiKeys`             | API Keys                                                 |
| `connect`             | Connect applications                                     |
| `featureFlags`        | Feature Flags                                            |
| `groups`              | Groups                                                   |
| `pipes`               | Pipes                                                    |
| `radar`               | Radar                                                    |
| `client`              | The raw `@workos-inc/node` client (escape hatch)         |
| `use`                 | Run any client call as an Effect                         |

## Installation

```sh
bun add @effect-auth/workos @workos-inc/node effect
```

## Configuration

The recommended `WorkOS.layer` reads credentials from the environment via
Effect `Config`:

| Variable              | Required | Description                                   |
| --------------------- | -------- | --------------------------------------------- |
| `WORKOS_API_KEY`      | yes      | Server API key (`sk_...`), read as `Redacted` |
| `WORKOS_CLIENT_ID`    | no       | Client ID (`client_...`) for AuthKit / PKCE   |
| `WORKOS_API_HOSTNAME` | no       | Override the API hostname                     |
| `WORKOS_HTTPS`        | no       | Use HTTPS (boolean)                           |
| `WORKOS_PORT`         | no       | Override the API port                         |

## Usage

### Authenticate a user with AuthKit

```ts
import { Effect } from "effect";
import { WorkOS } from "@effect-auth/workos";

const authenticate = (email: string, password: string) =>
  Effect.gen(function* () {
    const workos = yield* WorkOS;
    return yield* workos.userManagement.authenticateWithPassword({
      clientId: process.env.WORKOS_CLIENT_ID!,
      email,
      password,
    });
  });

// Reads WORKOS_API_KEY / WORKOS_CLIENT_ID from the environment.
authenticate("user@example.com", "secret").pipe(Effect.provide(WorkOS.layer));
```

### Start an SSO flow and handle the callback

```ts
import { Effect } from "effect";
import { WorkOS } from "@effect-auth/workos";

const authorizationUrl = (organizationId: string) =>
  Effect.gen(function* () {
    const workos = yield* WorkOS;
    return yield* workos.sso.getAuthorizationUrl({
      clientId: process.env.WORKOS_CLIENT_ID!,
      redirectUri: "https://example.com/callback",
      organizationId,
    });
  });

const handleCallback = (code: string) =>
  Effect.gen(function* () {
    const workos = yield* WorkOS;
    const { profile } = yield* workos.sso.getProfileAndToken({
      clientId: process.env.WORKOS_CLIENT_ID!,
      code,
    });
    return profile;
  });
```

### Verify a webhook signature

`webhooks.constructEvent` (signature verification + parsing) is wrapped just
like every other method:

```ts
import { Effect } from "effect";
import { WorkOS } from "@effect-auth/workos";

const handleWebhook = (payload: unknown, signature: string) =>
  Effect.gen(function* () {
    const workos = yield* WorkOS;
    return yield* workos.webhooks.constructEvent({
      payload,
      sigHeader: signature,
      secret: process.env.WORKOS_WEBHOOK_SECRET!,
    });
  });
```

### Other layers

```ts
import { WorkOS } from "@effect-auth/workos";

// Build from explicit options (e.g. a public PKCE client with only a clientId).
WorkOS.layerOptions({ apiKey: process.env.WORKOS_API_KEY, clientId: "client_..." });

// Reuse a client you constructed yourself or share across libraries.
import { WorkOS as WorkOSClient } from "@workos-inc/node";
WorkOS.layerClient(new WorkOSClient(process.env.WORKOS_API_KEY));
```

### Escape hatch

Anything not surfaced as a dedicated module — for instance the low-level
`get`/`post` helpers, or a brand-new endpoint — is reachable via `use`:

```ts
Effect.gen(function* () {
  const workos = yield* WorkOS;
  return yield* workos.use((client) => client.get("/some/endpoint"));
});
```

## Error handling

Every failure is surfaced as a single [`WorkOSError`](./src/Errors.ts) tagged
error. It preserves the rich metadata WorkOS attaches to its exceptions while
keeping the original thrown value under `cause`:

```ts
import { Effect } from "effect";
import { WorkOS, WorkOSError } from "@effect-auth/workos";

program.pipe(
  Effect.catchTag("WorkOSError", (error) => {
    error.status; // HTTP status, e.g. 404 / 401 / 429
    error.code; // machine-readable error code
    error.requestID; // WorkOS request id, for support
    error.retryAfter; // seconds to wait (rate limits)
    error.operation; // e.g. "userManagement.authenticateWithPassword"
    error.authenticationCode; // AuthKit step required, e.g. "mfa_challenge"
    error.pendingAuthenticationToken; // token to resume the AuthKit flow
    return Effect.fail(error);
  }),
);
```

`WorkOSError.is(value)` is a convenience type guard.

## Notes

- The WorkOS SDK's types and value exports (event payloads, option/response
  interfaces, exception classes, enums) are re-exported under the `WorkOSSDK`
  namespace from the package entry point.
- Building a client does no network I/O; calls are only made when an Effect is
  run, and each run re-invokes the underlying SDK method (no shared promises).
- API keys passed as Effect `Redacted` values stay redacted in logs and traces.
