# effect-auth

Batteries-included authentication and authorization for [Effect](https://effect.website/) v4: a headless core of services and layers (sessions, passwords, passkeys, multi-factor, OAuth, SSO, organizations, API keys, JWT and one policy-based authorization kernel), plus an optional HTTP API, a typed browser client, framework bindings, and storage and vendor adapters, each opt-in. How it relates to effect-jsonapi and legation is stated once in [the three-library boundary](docs/BOUNDARY.md).

**Disclaimer:** This is an experimental project, mostly written using Claude Code, and is not production-ready. If you want something usable, BetterAuth is probably the best option.

## Packages

| Package                                                   | Purpose                                                                                                     |
| --------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------- |
| [`@thomasfosterau/effect-auth`](packages/effect-auth)     | The core library; `effect` is its only dependency. Start with its [README](packages/effect-auth/README.md). |
| [`@thomasfosterau/effect-auth-client`](packages/client)   | Typed browser client over the HTTP contract, with an observable session store                               |
| [`@thomasfosterau/effect-auth-react`](packages/react)     | React hooks and form components over the client                                                             |
| [`@thomasfosterau/effect-auth-svelte`](packages/svelte)   | Svelte bindings and form components over the client                                                         |
| [`@thomasfosterau/effect-auth-vue`](packages/vue)         | Vue composables and form components over the client                                                         |
| [`@thomasfosterau/effect-auth-solid`](packages/solid)     | Solid primitives and form components over the client                                                        |
| [`@thomasfosterau/effect-auth-sql`](packages/sql)         | Driver-agnostic SQL storage layers (`effect/sql`)                                                           |
| [`@thomasfosterau/effect-auth-drizzle`](packages/drizzle) | Drizzle storage layers for PostgreSQL, SQLite and MySQL                                                     |
| [`@thomasfosterau/effect-auth-alchemy`](packages/alchemy) | Alchemy v2 `AuthSchema` resource and D1 storage layers                                                      |
| [`@thomasfosterau/effect-auth-argon2`](packages/argon2)   | Argon2id `PasswordHasher` on WebAssembly (`hash-wasm`), Workers-safe                                        |
| [`@thomasfosterau/effect-auth-resend`](packages/resend)   | Resend `EmailSender` over plain `fetch`                                                                     |
| [`@thomasfosterau/effect-auth-twilio`](packages/twilio)   | Twilio `SmsSender` over plain `fetch`                                                                       |
| [`@thomasfosterau/effect-auth-saml`](packages/saml)       | SAML 2.0 `SamlVerifier` over `@node-saml/node-saml`                                                         |

## Install

```bash
pnpm add @thomasfosterau/effect-auth effect
```

`effect` is a peer dependency (`>=4.0.0-rc.118`; `>=4.0.0` for effect-auth-alchemy). Add a storage adapter, a vendor adapter or the client as you need them; each package's README lists its own peers.

## Example

Email and password sign-up and sign-in on the headless core, with in-memory stores. Every service is a `Context.Service` with a static `layer`, and its stores are resolved when the layer is built.

```ts
import { Effect, Layer } from "effect";
import * as Auth from "@thomasfosterau/effect-auth";

// In-memory stores. Lookups return `null` on a miss; the services turn that
// into typed errors. Swap these for an adapter (effect-auth-sql, -drizzle).
const users = new Map<string, Auth.User>();
const sessions = new Map<string, Auth.Session>();
const passwordHashes = new Map<string, string>();

const sessionStore: typeof Auth.SessionStore.Service = {
  create: (session) => Effect.sync(() => (sessions.set(session.id, session), session)),
  get: (id) => Effect.sync(() => sessions.get(id) ?? null),
  update: (session) => Effect.sync(() => (sessions.set(session.id, session), session)),
  delete: (id) => Effect.sync(() => void sessions.delete(id)),
  deleteByUserId: (userId) =>
    Effect.sync(() => {
      for (const [id, s] of sessions) if (s.userId === userId) sessions.delete(id);
    }),
  listByUserId: (userId) =>
    Effect.sync(() => [...sessions.values()].filter((s) => s.userId === userId)),
};

const userStore: typeof Auth.UserStore.Service = {
  get: (id) => Effect.sync(() => users.get(id) ?? null),
};

const emailPasswordStore: typeof Auth.Email.EmailPasswordStore.Service = {
  createUser: ({ name, attributes }) =>
    Effect.sync(() => {
      const now = new Date();
      const user: Auth.User = {
        id: crypto.randomUUID(),
        ...(name !== undefined && { name }),
        createdAt: now,
        updatedAt: now,
        attributes: attributes ?? {},
      };
      users.set(user.id, user);
      return { user, created: true };
    }),
  getPasswordHash: (userId) => Effect.sync(() => passwordHashes.get(userId) ?? null),
  setPasswordHash: (userId, hash) => Effect.sync(() => void passwordHashes.set(userId, hash)),
};

const Stores = Layer.mergeAll(
  Layer.succeed(Auth.SessionStore)(sessionStore),
  Layer.succeed(Auth.UserStore)(userStore),
  Layer.succeed(Auth.Email.EmailPasswordStore)(emailPasswordStore),
  Layer.succeed(Auth.IdentifierStore)(Auth.memoryIdentifierStore()),
  Auth.Hooks.Default, // no plugins
);

const Sessions = Auth.SessionService.layer({
  sessionExpiresIn: { activePeriod: 30 * 86_400_000, idlePeriod: 14 * 86_400_000 },
});

const AuthLive = Auth.Email.EmailPasswordService.layer().pipe(
  Layer.provideMerge(Sessions),
  Layer.provideMerge(Auth.Password.PasswordHasher.layer()), // PBKDF2-SHA256
  Layer.provideMerge(Stores),
);

const program = Effect.gen(function* () {
  const auth = yield* Auth.Email.EmailPasswordService;
  yield* auth.signUp({ email: "ada@example.com", password: "correct horse battery staple" });

  const { session, secondFactor } = yield* auth.signIn({
    email: "ada@example.com",
    password: "correct horse battery staple",
  });
  if (session === undefined) return `second factor required until ${secondFactor?.expiresAt}`;

  // `session.id` is the raw token for the cookie; the store only sees its hash.
  const sessionService = yield* Auth.SessionService;
  const { user } = yield* sessionService.validateSession(session.id);
  return `signed in as ${user.id}`;
});

console.log(await Effect.runPromise(program.pipe(Effect.provide(AuthLive))));
```

From here: mount the HTTP API with `Auth.Http.make({ services })`, swap the in-memory stores for [`effect-auth-sql`](packages/sql) or [`effect-auth-drizzle`](packages/drizzle), and talk to it from the browser with [`effect-auth-client`](packages/client). The [core README](packages/effect-auth/README.md) covers every feature.

## Documentation

- [Architecture](docs/ARCHITECTURE.md) (module map and security model), [design decisions](docs/DESIGN.md), [ADRs](docs/adr/README.md) and the [domain vocabulary](docs/CONTEXT.md).
- Guides in [docs/guides/](docs/guides/): bring your own store, the browser client, MCP provider, SCIM, auth as a separate service, rate limits and sessions on Cloudflare Durable Objects, migrating from Better Auth, migrating to the authorization kernel.
- [Observability](docs/OBSERVABILITY.md): spans and metrics.

## Development

See [CONTRIBUTING.md](CONTRIBUTING.md); agents read [AGENTS.md](AGENTS.md) and each package's `CLAUDE.md`. Report vulnerabilities as described in [SECURITY.md](SECURITY.md).

## License

MIT — see [LICENSE.md](LICENSE.md).
