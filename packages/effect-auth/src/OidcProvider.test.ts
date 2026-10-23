import { assert, describe, it, expect } from "vite-plus/test";
import {
  Array as Arr,
  Clock,
  DateTime,
  Effect,
  FileSystem,
  Layer,
  Path,
  Redacted,
  Schema,
} from "effect";
import { Etag, HttpPlatform, HttpRouter } from "effect/http";
import { HttpApiBuilder } from "effect/http-api";
import { Hooks } from "./Hooks.ts";
import * as PlatformCrypto from "./PlatformCrypto.ts";
import { SessionStore } from "./SessionStore.ts";
import { UserStore } from "./UserStore.ts";
import { SessionService } from "./SessionService.ts";
import { hashToken } from "./TokenHash.ts";
import { UserServiceStore, UserService } from "./User.ts";
import { AuthLifecycleService } from "./AuthLifecycle.ts";
import {
  IdentifierStore,
  makeIdentifier,
  memoryIdentifierStore,
  type Identifier,
} from "./Identifier.ts";
import { PasswordHasher } from "./password/Password.ts";
import { EmailPasswordService } from "./email/EmailPassword.ts";
import { EmailVerificationService, EmailVerificationStore } from "./email/EmailVerification.ts";
import {
  PasswordResetService,
  PasswordResetStore,
  PasswordResetUserStore,
} from "./password/PasswordReset.ts";
import { type AuthServices } from "./http/HttpServer.ts";
import * as HttpServer from "./http/HttpServer.ts";
import { AuthApi } from "./http/HttpApi.ts";
import { ClientIP, type TrustedProxyConfig } from "./ClientIP.ts";
import { RateLimiter, RateLimitStore, type RateLimitEntry } from "./RateLimit.ts";
import { JwtKeyStore, type JwtKeyPair, JwtService } from "./Jwt.ts";
import { generatePKCE, verifyIdToken } from "./oauth/OAuth.ts";
import {
  OidcClientStore,
  OidcCodeStore,
  OidcTokenStore,
  OidcConsentStore,
  OidcProviderError,
  OidcRegistrationError,
  hashOidcSecret,
  mcpProviderPreset,
  type OidcAuthorizationCode,
  type OidcClient,
  type OidcConsent,
  type OidcDynamicRegistrationConfig,
  type OidcProviderConfig,
  type OidcToken,
  OidcProviderService,
} from "./OidcProvider.ts";
import * as OidcProvider from "./OidcProvider.ts";
import { ClientAddressConfigError, RateLimiterConfigError } from "./Errors.ts";
import type * as Types from "./Types.ts";

const ISSUER = "http://idp.test/api/auth";

// -----------------------------------------------------------------------------
// In-memory stores
// -----------------------------------------------------------------------------

const makeOidcStores = () => {
  const clients = new Map<string, OidcClient>();
  const codes = new Map<string, OidcAuthorizationCode>();
  const tokens = new Map<string, OidcToken>();
  const consents = new Map<string, OidcConsent>();
  const jwtKeys: JwtKeyPair[] = [];

  const clientStore: typeof OidcClientStore.Service = {
    create: (c) => Effect.sync(() => (clients.set(c.clientId, c), c)),
    getByClientId: (id) => Effect.succeed(clients.get(id) ?? null),
    update: (c) => Effect.sync(() => (clients.set(c.clientId, c), c)),
    delete: (id) => Effect.sync(() => void clients.delete(id)),
    list: () => Effect.succeed([...clients.values()]),
  };
  const codeStore: typeof OidcCodeStore.Service = {
    create: (c) => Effect.sync(() => (codes.set(c.codeHash, c), c)),
    get: (hash) => Effect.succeed(codes.get(hash) ?? null),
    delete: (hash) => Effect.sync(() => void codes.delete(hash)),
  };
  const tokenStore: typeof OidcTokenStore.Service = {
    create: (t) => Effect.sync(() => (tokens.set(t.tokenHash, t), t)),
    get: (hash) => Effect.succeed(tokens.get(hash) ?? null),
    delete: (hash) => Effect.sync(() => void tokens.delete(hash)),
    listByFamily: (familyId) =>
      Effect.succeed([...tokens.values()].filter((t) => t.familyId === familyId)),
  };
  const consentStore: typeof OidcConsentStore.Service = {
    get: (userId, clientId) => Effect.succeed(consents.get(`${userId}:${clientId}`) ?? null),
    upsert: (c) => Effect.sync(() => (consents.set(`${c.userId}:${c.clientId}`, c), c)),
    delete: (userId, clientId) => Effect.sync(() => void consents.delete(`${userId}:${clientId}`)),
  };
  const jwtKeyStore: typeof JwtKeyStore.Service = {
    getActive: () => Effect.succeed(jwtKeys[0] ?? null),
    create: (pair) => Effect.sync(() => (jwtKeys.push(pair), pair)),
    list: () => Effect.succeed([...jwtKeys]),
  };

  return { clientStore, codeStore, tokenStore, consentStore, jwtKeyStore, clients, codes, tokens };
};

// -----------------------------------------------------------------------------
// Service-level tests
// -----------------------------------------------------------------------------

const makeUser = (id: string): Types.User => {
  const now = DateTime.toDateUtc(DateTime.nowUnsafe());
  return {
    id,
    name: "Test User",
    createdAt: now,
    updatedAt: now,
    attributes: {},
  };
};

describe("OidcProviderService", () => {
  const config = {
    issuer: ISSUER,
    loginPage: "http://idp.test/login",
    consentPage: "http://idp.test/consent",
  };

  const setup = () => {
    const stores = makeOidcStores();
    // `OidcProvider.make` also resolves `UserStore` and `JwtService` at
    // construction time (even though these service-level tests never exercise
    // the userinfo/token-signing paths), so both must be satisfiable here too.
    const userStore: typeof UserStore.Service = {
      get: () => Effect.succeed(null),
    };
    const jwtServiceLayer = JwtService.layer({ issuer: ISSUER }).pipe(
      Layer.provide(Layer.succeed(JwtKeyStore)(stores.jwtKeyStore)),
    );
    const layer = Layer.mergeAll(
      Layer.succeed(OidcClientStore)(stores.clientStore),
      Layer.succeed(OidcCodeStore)(stores.codeStore),
      Layer.succeed(OidcTokenStore)(stores.tokenStore),
      Layer.succeed(OidcConsentStore)(stores.consentStore),
      Layer.succeed(UserStore)(userStore),
      Layer.succeed(IdentifierStore)(memoryIdentifierStore()),
      jwtServiceLayer,
      PlatformCrypto.layer,
    );
    return { stores, layer };
  };

  it("registers web clients with a secret and native clients without", async () => {
    const { layer } = setup();
    const service = await Effect.runPromise(OidcProvider.make(config).pipe(Effect.provide(layer)));

    const { web, native } = await Effect.runPromise(
      Effect.gen(function* () {
        const web = yield* service.registerClient({
          name: "Web App",
          redirectUris: ["https://rp.test/callback"],
        });
        const native = yield* service.registerClient({
          name: "CLI",
          redirectUris: ["http://127.0.0.1:8123/callback"],
          type: "native",
        });
        return { web, native };
      }).pipe(Effect.provide(layer)),
    );

    assert(web.clientSecret !== undefined, "a web client gets a secret");
    expect(web.client.type).toBe("web");
    expect(web.client.clientSecretHash).toBe(hashOidcSecret(web.clientSecret));
    expect(native.clientSecret).toBeUndefined();
    expect(native.client.type).toBe("native");
  });

  it("rejects registration without redirect URIs", async () => {
    const { layer } = setup();
    const service = await Effect.runPromise(OidcProvider.make(config).pipe(Effect.provide(layer)));
    const err = await Effect.runPromise(
      Effect.flip(service.registerClient({ name: "x", redirectUris: [] })).pipe(
        Effect.provide(layer),
      ),
    );
    expect(err).toBeInstanceOf(OidcProviderError);
  });

  it("refuses to redirect for unknown clients or unregistered redirect URIs", async () => {
    const { layer } = setup();
    const service = await Effect.runPromise(OidcProvider.make(config).pipe(Effect.provide(layer)));
    const user = makeUser("u1");

    const { unknownClient, badRedirect } = await Effect.runPromise(
      Effect.gen(function* () {
        const { client } = yield* service.registerClient({
          name: "App",
          redirectUris: ["https://rp.test/callback"],
        });
        const unknownClient = yield* Effect.flip(
          service.authorize(user, {
            responseType: "code",
            clientId: "nope",
            redirectUri: "https://rp.test/callback",
            scope: "openid",
          }),
        );
        const badRedirect = yield* Effect.flip(
          service.authorize(user, {
            responseType: "code",
            clientId: client.clientId,
            redirectUri: "https://evil.test/callback",
            scope: "openid",
          }),
        );
        return { unknownClient, badRedirect };
      }).pipe(Effect.provide(layer)),
    );

    expect(unknownClient).toBeInstanceOf(OidcProviderError);
    expect(badRedirect).toBeInstanceOf(OidcProviderError);
  });

  it("redirects spec-level errors back to the client", async () => {
    const { layer } = setup();
    const service = await Effect.runPromise(OidcProvider.make(config).pipe(Effect.provide(layer)));
    const user = makeUser("u1");

    const results = await Effect.runPromise(
      Effect.gen(function* () {
        const { client } = yield* service.registerClient({
          name: "App",
          redirectUris: ["https://rp.test/callback"],
          skipConsent: true,
        });
        const base = {
          clientId: client.clientId,
          redirectUri: "https://rp.test/callback",
          state: "s1",
        };
        const badResponseType = yield* service.authorize(user, {
          ...base,
          responseType: "token",
          scope: "openid",
        });
        const badScope = yield* service.authorize(user, {
          ...base,
          responseType: "code",
          scope: "openid admin:everything",
        });
        const missingOpenid = yield* service.authorize(user, {
          ...base,
          responseType: "code",
          scope: "profile",
        });
        const plainPkce = yield* service.authorize(user, {
          ...base,
          responseType: "code",
          scope: "openid",
          codeChallenge: "challenge",
          codeChallengeMethod: "plain",
        });
        return { badResponseType, badScope, missingOpenid, plainPkce };
      }).pipe(Effect.provide(layer)),
    );

    Arr.forEach(
      [
        [results.badResponseType, "unsupported_response_type"],
        [results.badScope, "invalid_scope"],
        [results.missingOpenid, "invalid_scope"],
        [results.plainPkce, "invalid_request"],
      ] as const,
      ([result, error]) => {
        expect(result.type).toBe("error");
        const url = new URL(result.redirectTo);
        expect(url.origin + url.pathname).toBe("https://rp.test/callback");
        expect(url.searchParams.get("error")).toBe(error);
        expect(url.searchParams.get("state")).toBe("s1");
      },
    );
  });

  it("requires PKCE from native (public) clients", async () => {
    const { layer } = setup();
    const service = await Effect.runPromise(OidcProvider.make(config).pipe(Effect.provide(layer)));
    const user = makeUser("u1");

    const result = await Effect.runPromise(
      Effect.gen(function* () {
        const { client } = yield* service.registerClient({
          name: "CLI",
          redirectUris: ["http://127.0.0.1:8123/callback"],
          type: "native",
          skipConsent: true,
        });
        return yield* service.authorize(user, {
          responseType: "code",
          clientId: client.clientId,
          redirectUri: "http://127.0.0.1:8123/callback",
          scope: "openid",
        });
      }).pipe(Effect.provide(layer)),
    );

    expect(result.type).toBe("error");
    expect(new URL(result.redirectTo).searchParams.get("error")).toBe("invalid_request");
  });

  it("rejects redirect URIs that are not https or loopback http", async () => {
    const { layer } = setup();
    const service = await Effect.runPromise(OidcProvider.make(config).pipe(Effect.provide(layer)));

    const bad = [
      "javascript:alert(1)",
      "data:text/html,hi",
      "http://evil.example.com/cb",
      "http://192.168.1.1/cb",
      "ftp://example.com/cb",
    ];
    await Arr.reduce(bad, Promise.resolve(), async (previous, uri) => {
      await previous;
      const err = await Effect.runPromise(
        Effect.flip(service.registerClient({ name: "x", redirectUris: [uri] })).pipe(
          Effect.provide(layer),
        ),
      );
      assert.instanceOf(err, OidcProviderError);
      expect(err.message).toContain("https or loopback http");
    });

    const good = [
      "https://app.example.com/cb",
      "http://127.0.0.1:8080/cb",
      "http://[::1]/cb",
      "http://localhost/cb",
    ];
    await Arr.reduce(good, Promise.resolve(), async (previous, uri) => {
      await previous;
      const result = await Effect.runPromise(
        service.registerClient({ name: "x", redirectUris: [uri] }).pipe(Effect.provide(layer)),
      );
      expect(result.client.redirectUris).toContain(uri);
    });
  });

  it("returns interaction_required for prompt=none when consent is needed", async () => {
    const { layer } = setup();
    const service = await Effect.runPromise(OidcProvider.make(config).pipe(Effect.provide(layer)));
    const user = makeUser("u1");

    const result = await Effect.runPromise(
      Effect.gen(function* () {
        const { client } = yield* service.registerClient({
          name: "App",
          redirectUris: ["https://rp.test/callback"],
          skipConsent: false,
        });
        return yield* service.authorize(user, {
          responseType: "code",
          clientId: client.clientId,
          redirectUri: "https://rp.test/callback",
          scope: "openid",
          prompt: "none",
          state: "s1",
        });
      }).pipe(Effect.provide(layer)),
    );

    expect(result.type).toBe("error");
    const url = new URL(result.redirectTo);
    expect(url.searchParams.get("error")).toBe("interaction_required");
    expect(url.searchParams.get("state")).toBe("s1");
  });

  it("prompt=none succeeds when consent has already been granted", async () => {
    const { layer } = setup();
    const service = await Effect.runPromise(OidcProvider.make(config).pipe(Effect.provide(layer)));
    const user = makeUser("u1");

    const result = await Effect.runPromise(
      Effect.gen(function* () {
        const { client } = yield* service.registerClient({
          name: "App",
          redirectUris: ["https://rp.test/callback"],
          skipConsent: false,
        });
        // Grant consent first.
        const consentStore = yield* OidcConsentStore;
        yield* consentStore.upsert({
          userId: user.id,
          clientId: client.clientId,
          scopes: ["openid"],
          createdAt: yield* Clock.currentTimeMillis,
          updatedAt: yield* Clock.currentTimeMillis,
        });
        return yield* service.authorize(user, {
          responseType: "code",
          clientId: client.clientId,
          redirectUri: "https://rp.test/callback",
          scope: "openid",
          prompt: "none",
        });
      }).pipe(Effect.provide(layer)),
    );

    expect(result.type).toBe("code");
  });

  it("resolves trusted config clients without touching the store", async () => {
    const { layer } = setup();
    const service = await Effect.runPromise(
      OidcProvider.make({
        ...config,
        trustedClients: [
          {
            clientId: "first-party",
            clientSecret: Redacted.make("shh"),
            name: "First Party",
            redirectUris: ["https://fp.test/cb"],
          },
        ],
      }).pipe(Effect.provide(layer)),
    );
    const user = makeUser("u1");

    const result = await Effect.runPromise(
      service
        .authorize(user, {
          responseType: "code",
          clientId: "first-party",
          redirectUri: "https://fp.test/cb",
          scope: "openid",
        })
        .pipe(Effect.provide(layer)),
    );

    // Trusted clients skip consent by default.
    expect(result.type).toBe("code");
    expect(new URL(result.redirectTo).searchParams.get("code")).toBeTruthy();
  });

  describe("updateClient", () => {
    it("applies every supplied field and keeps the rest", async () => {
      const { layer, stores } = setup();
      const service = await Effect.runPromise(
        OidcProvider.make(config).pipe(Effect.provide(layer)),
      );

      const { before, updated } = await Effect.runPromise(
        Effect.gen(function* () {
          const { client } = yield* service.registerClient({
            name: "App",
            redirectUris: ["https://rp.test/callback"],
          });
          const updated = yield* service.updateClient(client.clientId, {
            name: "Renamed",
            redirectUris: ["https://rp.test/other"],
            skipConsent: true,
            disabled: true,
            metadata: { team: "core" },
          });
          return { before: client, updated };
        }).pipe(Effect.provide(layer)),
      );

      expect(updated.clientId).toBe(before.clientId);
      expect(updated.name).toBe("Renamed");
      expect(updated.redirectUris).toEqual(["https://rp.test/other"]);
      expect(updated.skipConsent).toBe(true);
      expect(updated.disabled).toBe(true);
      expect(updated.metadata).toEqual({ team: "core" });
      expect(updated.clientSecretHash).toBe(before.clientSecretHash);
      expect(stores.clients.get(before.clientId)).toEqual(updated);
    });

    it("leaves the client unchanged, bar updatedAt, when no field is supplied", async () => {
      const { layer } = setup();
      const service = await Effect.runPromise(
        OidcProvider.make(config).pipe(Effect.provide(layer)),
      );

      const { before, updated } = await Effect.runPromise(
        Effect.gen(function* () {
          const { client } = yield* service.registerClient({
            name: "App",
            redirectUris: ["https://rp.test/callback"],
          });
          const updated = yield* service.updateClient(client.clientId, {});
          return { before: client, updated };
        }).pipe(Effect.provide(layer)),
      );

      const { updatedAt: _beforeAt, ...beforeRest } = before;
      const { updatedAt: _updatedAt, ...updatedRest } = updated;
      expect(updatedRest).toEqual(beforeRest);
    });

    it("fails for an unknown client", async () => {
      const { layer } = setup();
      const service = await Effect.runPromise(
        OidcProvider.make(config).pipe(Effect.provide(layer)),
      );
      const err = await Effect.runPromise(
        Effect.flip(service.updateClient("nope", { name: "x" })).pipe(Effect.provide(layer)),
      );
      expect(err).toBeInstanceOf(OidcProviderError);
      expect(err.message).toBe("Client not found");
    });

    it("refuses to update a trusted config client", async () => {
      const { layer } = setup();
      const service = await Effect.runPromise(
        OidcProvider.make({
          ...config,
          trustedClients: [
            {
              clientId: "first-party",
              clientSecret: Redacted.make("shh"),
              name: "First Party",
              redirectUris: ["https://fp.test/cb"],
            },
          ],
        }).pipe(Effect.provide(layer)),
      );
      const err = await Effect.runPromise(
        Effect.flip(service.updateClient("first-party", { name: "x" })).pipe(Effect.provide(layer)),
      );
      expect(err).toBeInstanceOf(OidcProviderError);
      expect(err.message).toBe("Trusted clients are configured statically and cannot be updated");
    });
  });
});

// -----------------------------------------------------------------------------
// RFC 7591 dynamic client registration / RFC 7592 management (service level)
// -----------------------------------------------------------------------------

describe("OidcProviderService dynamic client registration", () => {
  const baseConfig = {
    issuer: ISSUER,
    loginPage: "http://idp.test/login",
    consentPage: "http://idp.test/consent",
  };

  const setup = (dynamicRegistration?: OidcDynamicRegistrationConfig) => {
    const stores = makeOidcStores();
    const userStore: typeof UserStore.Service = {
      get: () => Effect.succeed(null),
    };
    const jwtServiceLayer = JwtService.layer({ issuer: ISSUER }).pipe(
      Layer.provide(Layer.succeed(JwtKeyStore)(stores.jwtKeyStore)),
    );
    const layer = Layer.mergeAll(
      Layer.succeed(OidcClientStore)(stores.clientStore),
      Layer.succeed(OidcCodeStore)(stores.codeStore),
      Layer.succeed(OidcTokenStore)(stores.tokenStore),
      Layer.succeed(OidcConsentStore)(stores.consentStore),
      Layer.succeed(UserStore)(userStore),
      Layer.succeed(IdentifierStore)(memoryIdentifierStore()),
      jwtServiceLayer,
      PlatformCrypto.layer,
    );
    const config = {
      ...baseConfig,
      ...(dynamicRegistration !== undefined && { dynamicRegistration }),
    };
    const service = Effect.runSync(OidcProvider.make(config).pipe(Effect.provide(layer)));
    return { stores, layer, service };
  };

  const publicMetadata = {
    redirectUris: ["http://127.0.0.1:9876/callback"],
    tokenEndpointAuthMethod: "none",
    clientName: "MCP Client",
    scope: "openid profile email",
  };

  it("issues a public client without a secret and a confidential one with a secret", async () => {
    const { service } = setup({});

    const publicClient = await Effect.runPromise(service.registerDynamicClient(publicMetadata));
    expect(publicClient.clientSecret).toBeUndefined();
    expect(publicClient.client.type).toBe("native");
    expect(publicClient.client.tokenEndpointAuthMethod).toBe("none");
    expect(publicClient.client.dynamicallyRegistered).toBe(true);
    expect(publicClient.client.grantTypes).toEqual(["authorization_code"]);
    expect(publicClient.client.responseTypes).toEqual(["code"]);
    expect(publicClient.registrationAccessToken).toBeTruthy();
    // Both one-time secrets are stored only as digests.
    expect(publicClient.client.registrationAccessTokenHash).toBe(
      hashOidcSecret(publicClient.registrationAccessToken),
    );

    // RFC 7591 §2: an omitted token_endpoint_auth_method means client_secret_basic.
    const confidential = await Effect.runPromise(
      service.registerDynamicClient({ redirectUris: ["https://rp.test/cb"] }),
    );
    expect(confidential.clientSecret).toBeTruthy();
    assert(confidential.clientSecret !== undefined);
    expect(confidential.client.type).toBe("web");
    expect(confidential.client.tokenEndpointAuthMethod).toBe("client_secret_basic");
    expect(confidential.client.clientSecretHash).toBe(hashOidcSecret(confidential.clientSecret));
    // The default scope is the provider's full allowed set.
    expect(confidential.client.scope).toBe("openid profile email offline_access");
  });

  // The OIDC layer built over the same stores, as an app builds it.
  const buildProvider = (dynamicRegistration?: OidcDynamicRegistrationConfig) => {
    const { layer } = setup();
    const config = {
      ...baseConfig,
      ...(dynamicRegistration !== undefined && { dynamicRegistration }),
    };
    return Effect.scoped(Layer.build(OidcProviderService.layer(config).pipe(Layer.provide(layer))));
  };

  it("builds with dynamic registration and no address source of its own (#398)", async () => {
    // The registration limit reads the address from the ClientIP that Http.make
    // provides, which checks the address source itself.
    await expect(Effect.runPromise(buildProvider({}))).resolves.toBeDefined();
  });

  it("builds without dynamic registration, which needs no address source", async () => {
    await expect(Effect.runPromise(buildProvider())).resolves.toBeDefined();
  });

  it("fails with access_denied when dynamic registration is not configured", async () => {
    const { service } = setup();
    expect(service.dynamicRegistration.enabled).toBe(false);
    const err = await Effect.runPromise(Effect.flip(service.registerDynamicClient(publicMetadata)));
    assert.instanceOf(err, OidcRegistrationError);
    expect(err.error).toBe("access_denied");
  });

  it("rejects redirect URIs that are not https, loopback, or a registered scheme", async () => {
    const { service } = setup({});
    const cases = [
      [],
      ["http://evil.test/cb"],
      ["javascript:alert(1)"],
      ["myapp://callback"],
      ["https://rp.test/cb#fragment"],
      ["not a url"],
    ];
    await Arr.reduce(cases, Promise.resolve(), async (previous, redirectUris) => {
      await previous;
      const err = await Effect.runPromise(
        Effect.flip(service.registerDynamicClient({ ...publicMetadata, redirectUris })),
      );
      assert.instanceOf(err, OidcRegistrationError);
      expect(err.error).toBe("invalid_redirect_uri");
    });

    // Private-use URI schemes (RFC 8252 §7.1) are opt-in per deployment.
    const withScheme = setup({ allowedRedirectUriSchemes: ["myapp"] });
    const ok = await Effect.runPromise(
      withScheme.service.registerDynamicClient({
        ...publicMetadata,
        redirectUris: ["myapp://callback"],
      }),
    );
    expect(ok.client.redirectUris).toEqual(["myapp://callback"]);
  });

  it("rejects metadata the provider cannot honour with invalid_client_metadata", async () => {
    const { service } = setup({});
    const cases: ReadonlyArray<Partial<OidcProvider.OidcClientMetadata>> = [
      { tokenEndpointAuthMethod: "private_key_jwt" },
      { grantTypes: ["client_credentials"] },
      { grantTypes: ["refresh_token"] },
      { responseTypes: ["token"] },
      { scope: "openid admin:everything" },
      { scope: "profile" },
      // refresh_token without offline_access can never mint a refresh token.
      { grantTypes: ["authorization_code", "refresh_token"], scope: "openid" },
    ];
    await Arr.reduce(cases, Promise.resolve(), async (previous, overrides) => {
      await previous;
      const err = await Effect.runPromise(
        Effect.flip(service.registerDynamicClient({ ...publicMetadata, ...overrides })),
      );
      assert.instanceOf(err, OidcRegistrationError);
      expect(err.error).toBe("invalid_client_metadata");
    });
  });

  it("honours the registration policy for denial, error code, and consent", async () => {
    const denyAll = setup({ policy: () => Effect.succeed(false) });
    const denied = await Effect.runPromise(
      Effect.flip(denyAll.service.registerDynamicClient(publicMetadata)),
    );
    assert.instanceOf(denied, OidcRegistrationError);
    expect(denied.error).toBe("invalid_client_metadata");

    const forbid = setup({
      policy: () =>
        Effect.succeed({ allow: false, error: "access_denied", errorDescription: "Closed" }),
    });
    const forbidden = await Effect.runPromise(
      Effect.flip(forbid.service.registerDynamicClient(publicMetadata)),
    );
    assert.instanceOf(forbidden, OidcRegistrationError);
    expect(forbidden.error).toBe("access_denied");
    expect(forbidden.description).toBe("Closed");

    // The policy sees the NORMALIZED metadata and may opt the client into
    // skipping the consent screen.
    let seen: string | undefined;
    const allow = setup({
      policy: (metadata) => {
        seen = metadata.tokenEndpointAuthMethod;
        return Effect.succeed({ allow: true, skipConsent: true });
      },
    });
    const registered = await Effect.runPromise(allow.service.registerDynamicClient(publicMetadata));
    expect(seen).toBe("none");
    expect(registered.client.skipConsent).toBe(true);
  });

  it("requires the initial access token when one is configured", async () => {
    const secret = setup({ initialAccessToken: Redacted.make("s3cret-iat") });

    const missing = await Effect.runPromise(
      Effect.flip(secret.service.registerDynamicClient(publicMetadata)),
    );
    assert.instanceOf(missing, OidcRegistrationError);
    expect(missing.error).toBe("invalid_token");

    const wrong = await Effect.runPromise(
      Effect.flip(
        secret.service.registerDynamicClient(publicMetadata, { initialAccessToken: "nope" }),
      ),
    );
    assert.instanceOf(wrong, OidcRegistrationError);
    expect(wrong.error).toBe("invalid_token");

    const ok = await Effect.runPromise(
      secret.service.registerDynamicClient(publicMetadata, {
        initialAccessToken: "s3cret-iat",
      }),
    );
    expect(ok.client.clientId).toBeTruthy();

    // The verifier-hook form receives the presented token.
    const seen: string[] = [];
    const hook = setup({
      initialAccessToken: (token) => {
        seen.push(token);
        return Effect.succeed(token.startsWith("tenant-"));
      },
    });
    const viaHook = await Effect.runPromise(
      hook.service.registerDynamicClient(publicMetadata, { initialAccessToken: "tenant-42" }),
    );
    expect(viaHook.client.clientId).toBeTruthy();
    expect(seen).toEqual(["tenant-42"]);
    const rejected = await Effect.runPromise(
      Effect.flip(
        hook.service.registerDynamicClient(publicMetadata, { initialAccessToken: "other" }),
      ),
    );
    assert.instanceOf(rejected, OidcRegistrationError);
    expect(rejected.error).toBe("invalid_token");
  });

  it("gates RFC 7592 management on the registration access token", async () => {
    const { service, stores } = setup({});
    const registered = await Effect.runPromise(service.registerDynamicClient(publicMetadata));
    const { clientId } = registered.client;
    const rat = registered.registrationAccessToken;

    const read = await Effect.runPromise(service.readDynamicClient(clientId, rat));
    expect(read.name).toBe("MCP Client");

    await Arr.reduce(
      [
        [clientId, "wrong-token"],
        ["unknown-client", rat],
      ] as const,
      Promise.resolve(),
      async (previous, [id, token]) => {
        await previous;
        const err = await Effect.runPromise(Effect.flip(service.readDynamicClient(id, token)));
        assert.instanceOf(err, OidcRegistrationError);
        expect(err.error).toBe("invalid_token");
      },
    );

    const updated = await Effect.runPromise(
      service.updateDynamicClient(clientId, rat, {
        ...publicMetadata,
        clientName: "Renamed",
        redirectUris: ["http://127.0.0.1:9876/callback", "https://rp.test/cb"],
      }),
    );
    expect(updated.name).toBe("Renamed");
    expect(updated.redirectUris).toEqual(["http://127.0.0.1:9876/callback", "https://rp.test/cb"]);
    // The secret and registration access token survive an update untouched.
    expect(updated.registrationAccessTokenHash).toBe(hashOidcSecret(rat));

    // A client cannot promote itself from public to confidential.
    const promote = await Effect.runPromise(
      Effect.flip(
        service.updateDynamicClient(clientId, rat, {
          ...publicMetadata,
          tokenEndpointAuthMethod: "client_secret_basic",
        }),
      ),
    );
    assert.instanceOf(promote, OidcRegistrationError);
    expect(promote.error).toBe("invalid_client_metadata");

    await Effect.runPromise(service.deleteDynamicClient(clientId, rat));
    expect(stores.clients.has(clientId)).toBe(false);
  });

  it("holds a dynamic client to the scopes and grants it registered for", async () => {
    const { service } = setup({ skipConsent: true });
    const registered = await Effect.runPromise(
      service.registerDynamicClient({
        redirectUris: ["https://rp.test/cb"],
        tokenEndpointAuthMethod: "none",
        scope: "openid profile",
      }),
    );
    const user = makeUser("u1");

    const tooWide = await Effect.runPromise(
      service.authorize(user, {
        responseType: "code",
        clientId: registered.client.clientId,
        redirectUri: "https://rp.test/cb",
        scope: "openid profile email",
        codeChallenge: "challenge",
      }),
    );
    expect(tooWide.type).toBe("error");
    expect(new URL(tooWide.redirectTo).searchParams.get("error")).toBe("invalid_scope");

    // The refresh_token grant was never registered for.
    const err = await Effect.runPromise(
      Effect.flip(
        service.token({
          grantType: "refresh_token",
          clientId: registered.client.clientId,
          refreshToken: "whatever",
        }),
      ),
    );
    expect(err).toMatchObject({ error: "unauthorized_client" });
  });

  it("mcpProviderPreset turns on PKCE and dynamic registration", () => {
    const preset = mcpProviderPreset(baseConfig);
    expect(preset.requirePKCE).toBe(true);
    expect(preset.dynamicRegistration?.management).toBe(true);
    expect(preset.dynamicRegistration?.skipConsent).toBe(false);

    // Caller overrides win, and merge into (rather than replace) the defaults.
    const policy = () => Effect.succeed(true);
    const custom = mcpProviderPreset({
      ...baseConfig,
      requirePKCE: false,
      dynamicRegistration: { policy, skipConsent: true },
    });
    expect(custom.requirePKCE).toBe(false);
    expect(custom.dynamicRegistration?.policy).toBe(policy);
    expect(custom.dynamicRegistration?.skipConsent).toBe(true);
    expect(custom.dynamicRegistration?.management).toBe(true);
  });

  it("mcpProviderPreset builds with no address source of its own (#398)", async () => {
    const { layer } = setup();
    const build = (config: OidcProviderConfig) =>
      Effect.scoped(Layer.build(OidcProviderService.layer(config).pipe(Layer.provide(layer))));

    await expect(Effect.runPromise(build(mcpProviderPreset(baseConfig)))).resolves.toBeDefined();
  });
});

// -----------------------------------------------------------------------------
// HTTP layer: full end-to-end flow
// -----------------------------------------------------------------------------

/** `Http.make`'s startup error for registration with no address source (#398). */
const REGISTRATION_ADDRESS_ERROR =
  /Dynamic client registration \(POST \/register\) is rate limited per client address/;

/**
 * A web handler wired with the OIDC provider endpoints over in-memory stores.
 * Pass `dynamicRegistration` to mount the RFC 7591/7592 endpoints.
 */
const makeHttpFixture = (
  options: {
    readonly dynamicRegistration?: OidcDynamicRegistrationConfig;
    /** Provide `RateLimiter`, so the per-IP registration limit runs. */
    readonly rateLimit?: boolean;
    readonly trustedProxy?: TrustedProxyConfig;
    /**
     * `false` passes `Http.make` neither `trustedProxy` nor
     * `allowMissingClientIp`, so a registration-enabled handler fails its
     * startup check.
     */
    readonly declareRegistrationAddress?: boolean;
    /** Pass `allowMissingClientIp: true` to `Http.make`. */
    readonly allowMissingClientIp?: boolean;
    /**
     * Add a build step that waits on a promise, as a database connection does,
     * so the services finish building only after `Http.make` returns.
     */
    readonly connectAsynchronously?: boolean;
  } = {},
) => {
  const usersById = new Map<string, Types.User>();
  const identifiers = new Map<string, Identifier>();
  const identifierStore = memoryIdentifierStore(identifiers);
  const sessions = new Map<string, Types.Session>();
  const oidc = makeOidcStores();
  let userSeq = 0;

  const seedUser = (email: string, attributes: Types.User["attributes"] = {}): string => {
    const id = `u${++userSeq}`;
    const now = DateTime.toDateUtc(DateTime.nowUnsafe());
    usersById.set(id, {
      id,
      name: `User ${id}`,
      createdAt: now,
      updatedAt: now,
      attributes,
    });
    const identifier = makeIdentifier({
      userId: id,
      type: "email",
      value: email,
      verified: true,
      verifiedAt: now,
    });
    identifiers.set(identifier.id, identifier);
    return id;
  };
  const makeSession = (userId: string): string => {
    const rawToken = Buffer.from(globalThis.crypto.getRandomValues(new Uint8Array(12))).toString(
      "hex",
    );
    const tokenHash = hashToken(rawToken);
    const now = DateTime.toDateUtc(DateTime.nowUnsafe());
    sessions.set(tokenHash, {
      id: tokenHash,
      userId,
      expiresAt: DateTime.toDateUtc(DateTime.add(DateTime.nowUnsafe(), { milliseconds: 3600_000 })),
      createdAt: now,
      lastActivityAt: now,
      attributes: {},
    });
    return rawToken;
  };

  const userStore: typeof UserStore.Service = {
    get: (userId) => Effect.sync(() => usersById.get(userId) ?? null),
  };
  const userServiceStore = {
    get: userStore.get,
    update: (user: Types.User) => Effect.sync(() => (usersById.set(user.id, user), user)),
    delete: () => Effect.void,
  };
  const sessionStore: typeof SessionStore.Service = {
    create: (s: Types.Session) => Effect.sync(() => (sessions.set(s.id, s), s)),
    get: (id: string) => Effect.sync(() => sessions.get(id) ?? null),
    update: (s: Types.Session) => Effect.sync(() => (sessions.set(s.id, s), s)),
    delete: (id: string) => Effect.sync(() => void sessions.delete(id)),
    deleteByUserId: (userId: string) =>
      Effect.sync(() => {
        sessions.forEach((s, id) => {
          if (s.userId === userId) sessions.delete(id);
        });
      }),
    listByUserId: (userId: string) =>
      Effect.sync(() => [...sessions.values()].filter((s) => s.userId === userId)),
  };

  const coreStoreLayer = Layer.mergeAll(
    Layer.succeed(SessionStore)(sessionStore),
    Layer.succeed(UserStore)(userStore),
  );

  const sessionServiceLayer = SessionService.layer({
    sessionExpiresIn: { activePeriod: 3600_000, idlePeriod: 3600_000 },
  }).pipe(Layer.provide(Layer.mergeAll(coreStoreLayer, Hooks.Default)));

  // SAFETY: the `undefined` services below complete `AuthServices` for
  // `HttpServer.make`; no OIDC route or flow these tests drive calls them.
  const base = Layer.mergeAll(
    sessionServiceLayer,
    UserService.layer().pipe(Layer.provide(Layer.succeed(UserServiceStore)(userServiceStore))),
    Layer.succeed(UserServiceStore)(userServiceStore),
    Hooks.Default,
    Layer.succeed(AuthLifecycleService)(undefined as never),
    Layer.succeed(IdentifierStore)(identifierStore),
    Layer.succeed(PasswordHasher)(undefined as never),
    Layer.succeed(EmailPasswordService)(undefined as never),
    Layer.succeed(EmailVerificationService)(undefined as never),
    Layer.succeed(EmailVerificationStore)(undefined as never),
    Layer.succeed(PasswordResetService)(undefined as never),
    Layer.succeed(PasswordResetStore)(undefined as never),
    Layer.succeed(PasswordResetUserStore)(undefined as never),
  );

  const jwtKeyStoreLayer = Layer.succeed(JwtKeyStore)(oidc.jwtKeyStore);
  const jwtServiceLayer = JwtService.layer({ issuer: ISSUER }).pipe(
    Layer.provide(jwtKeyStoreLayer),
  );

  // `OidcProviderService` resolves the OIDC stores, the core `UserStore`, and
  // `JwtService` at construction time, so all of them must already be built.
  const oidcDeps = Layer.mergeAll(
    Layer.succeed(OidcClientStore)(oidc.clientStore),
    Layer.succeed(OidcCodeStore)(oidc.codeStore),
    Layer.succeed(OidcTokenStore)(oidc.tokenStore),
    Layer.succeed(OidcConsentStore)(oidc.consentStore),
    jwtKeyStoreLayer,
    jwtServiceLayer,
    // resolveOidcProvider needs the core user store in the ambient context.
    Layer.succeed(UserStore)(userStore),
    Layer.succeed(IdentifierStore)(identifierStore),
  );

  // Registration is rate limited per client address and needs a RateLimiter (#389),
  // so a registration-enabled fixture gets Cloudflare's address source and a limiter
  // unless it says otherwise. The source is Http.make's own (#388, #398).
  const registrationEnabled = options.dynamicRegistration !== undefined;
  const addressSource: TrustedProxyConfig | undefined =
    options.declareRegistrationAddress === false
      ? undefined
      : (options.trustedProxy ?? (registrationEnabled ? ClientIP.cloudflare : undefined));
  const oidcServiceLayer = OidcProviderService.layer({
    issuer: ISSUER,
    loginPage: "http://idp.test/login",
    consentPage: "http://idp.test/consent",
    ...(options.dynamicRegistration !== undefined && {
      dynamicRegistration: options.dynamicRegistration,
    }),
  }).pipe(Layer.provide(oidcDeps));

  const oidcLayer = Layer.mergeAll(oidcDeps, oidcServiceLayer);

  // Every key the per-IP limiter touches, so a test can see its bucket (if any).
  const rateLimitKeys = new Set<string>();
  const rateLimitEntries = new Map<string, RateLimitEntry>();
  const rateLimitStore = {
    get: (key: string) =>
      Effect.sync(() => {
        rateLimitKeys.add(key);
        return rateLimitEntries.get(key) ?? null;
      }),
    set: (key: string, entry: RateLimitEntry, _ttl: number) =>
      Effect.sync(() => {
        rateLimitKeys.add(key);
        rateLimitEntries.set(key, entry);
      }),
    increment: (key: string, ttl: number) =>
      // Starts a new window when there is none or it has expired, as the
      // RateLimitStore contract requires (#455).
      Effect.flatMap(Clock.currentTimeMillis, (now) =>
        Effect.sync(() => {
          rateLimitKeys.add(key);
          const entry = rateLimitEntries.get(key);
          const next: RateLimitEntry =
            entry === undefined || now >= entry.resetAt
              ? { key, count: 1, resetAt: now + ttl * 1000 }
              : { ...entry, count: entry.count + 1 };
          rateLimitEntries.set(key, next);
          return next.count;
        }),
      ),
    delete: (key: string) => Effect.sync(() => void rateLimitEntries.delete(key)),
  };
  const limiterLayer = RateLimiter.layer().pipe(
    Layer.provide(Layer.succeed(RateLimitStore, rateLimitStore)),
  );

  const connection =
    options.connectAsynchronously === true
      ? Layer.effectDiscard(
          Effect.tryPromise({ try: () => Promise.resolve(), catch: () => "unreachable" }).pipe(
            Effect.orDie,
          ),
        )
      : Layer.empty;
  // The connection is built first, so the OIDC layer builds after it returns.
  const withOidc: Layer.Layer<AuthServices> = Layer.mergeAll(base, oidcLayer).pipe(
    Layer.provide(connection),
  );
  const withOidcLimiter: Layer.Layer<AuthServices> = Layer.merge(withOidc, limiterLayer);
  const limited =
    options.rateLimit === true || (registrationEnabled && options.rateLimit !== false);
  const withoutOidc: Layer.Layer<AuthServices> = base;

  return {
    seedUser,
    makeSession,
    oidcTokenStore: oidc.tokens,
    rateLimitKeys,
    /** The fixture's services with OIDC and no `RateLimiter`. */
    servicesWithoutRateLimiter: withOidc,
    /** The fixture's services with OIDC and its `RateLimiter`. */
    servicesWithRateLimiter: withOidcLimiter,
    handler: HttpServer.make({
      services: limited ? withOidcLimiter : withOidc,
      cookie: { secure: false },
      ...(addressSource !== undefined && { trustedProxy: addressSource }),
      ...(options.allowMissingClientIp === true && { allowMissingClientIp: true }),
    }).handler,
    handlerWithoutOidc: HttpServer.make({ services: withoutOidc, cookie: { secure: false } })
      .handler,
  };
};

/**
 * The auth API composed by hand from the exported group layers, outside
 * `Http.make`: no startup check and no `ClientIP` middleware (#389).
 */
const handBuiltHandler = (services: Layer.Layer<AuthServices>) => {
  const platform = Layer.mergeAll(Etag.layer, Path.layer, HttpPlatform.layer).pipe(
    Layer.provideMerge(FileSystem.layerNoop({})),
  );
  const api = HttpApiBuilder.layer(AuthApi).pipe(
    Layer.provide(HttpServer.authGroupLayer({ secure: false })),
    Layer.provide(HttpServer.scimGroupLayer()),
    Layer.provide(platform),
  );
  // SAFETY: the handlers' phantom requirements are satisfied by `services` at
  // runtime; `Http.make` narrows its handler the same way.
  return HttpRouter.toWebHandler(api.pipe(Layer.provideMerge(services)), {
    disableLogger: true,
  }).handler as (request: Request) => Promise<Response>;
};

/**
 * The address the fixture's Cloudflare source resolves, sent on every POST so the
 * registration limit has a key. Ignored where no source is declared.
 */
const FIXTURE_CLIENT_HEADERS = { "cf-connecting-ip": "203.0.113.10" };

const encodeJson = Schema.encodeSync(Schema.fromJsonString(Schema.Json));

/** A JSON response body, decoded against the shape the test reads from it. */
const jsonBody = async <S extends Schema.ConstraintDecoder<unknown>>(
  response: Response,
  schema: S,
): Promise<S["Type"]> => Schema.decodeUnknownSync(schema)(await response.json());

// The response bodies several tests read.
/** A JSON object's own fields, read one by one. */
const JsonFields = Schema.Record(Schema.String, Schema.Json);
const MessageBody = Schema.Struct({ message: Schema.String });
const ClientIdBody = Schema.Struct({ client: Schema.Struct({ clientId: Schema.String }) });
const CreatedClientBody = Schema.Struct({
  client: Schema.Struct({ clientId: Schema.String }),
  clientSecret: Schema.String,
});
const RefreshTokenBody = Schema.Struct({ refresh_token: Schema.String });

const post = (path: string, body: Schema.Json, sessionId?: string): Request =>
  new Request(`http://idp.test${path}`, {
    method: "POST",
    headers: {
      ...FIXTURE_CLIENT_HEADERS,
      "content-type": "application/json",
      ...(sessionId !== undefined ? { cookie: `conduit_session=${sessionId}` } : {}),
    },
    body: encodeJson(body),
  });

/** JSON request with an optional `Authorization: Bearer` (registration tokens). */
const jsonRequest = (
  method: string,
  path: string,
  body: Schema.Json | undefined,
  bearer?: string,
): Request =>
  new Request(`http://idp.test${path}`, {
    method,
    headers: {
      ...FIXTURE_CLIENT_HEADERS,
      "content-type": "application/json",
      ...(bearer !== undefined ? { authorization: `Bearer ${bearer}` } : {}),
    },
    // `JSON.stringify(undefined)` is `undefined`: no body at all.
    ...(body !== undefined && { body: encodeJson(body) }),
  });

const get = (
  path: string,
  query: Record<string, string> = {},
  options: { sessionId?: string; bearer?: string } = {},
): Request => {
  const url = new URL(`http://idp.test${path}`);
  Arr.forEach(Object.entries(query), ([k, v]) => {
    url.searchParams.set(k, v);
  });
  return new Request(url, {
    headers: {
      ...(options.sessionId !== undefined
        ? { cookie: `conduit_session=${options.sessionId}` }
        : {}),
      ...(options.bearer !== undefined ? { authorization: `Bearer ${options.bearer}` } : {}),
    },
  });
};

/** Swap `globalThis.fetch` for a canned JWKS response while `thunk` runs. */
// The redirect a response carries; a response without one fails the test.
const locationOf = (res: Response): URL => {
  const location = res.headers.get("location");
  assert(location !== null, `expected a redirect, got ${res.status}`);
  return new URL(location);
};

// A query parameter the redirect must carry.
const searchParam = (url: URL, name: string): string => {
  const value = url.searchParams.get(name);
  assert(value !== null, `the redirect carries no ${name}`);
  return value;
};

const withJwksFetch = async <A>(jwks: Schema.Json, thunk: () => Promise<A>): Promise<A> => {
  const original = globalThis.fetch;
  globalThis.fetch = () =>
    Promise.resolve(
      new Response(encodeJson(jwks), { headers: { "content-type": "application/json" } }),
    );
  return Promise.resolve()
    .then(thunk)
    .finally(() => {
      globalThis.fetch = original;
    });
};

describe("HTTP OIDC provider endpoints", () => {
  it("runs the full flow: register -> authorize -> token (PKCE) -> id_token/JWKS -> userinfo -> refresh", async () => {
    const fx = makeHttpFixture();
    const adminSid = fx.makeSession(fx.seedUser("admin@idp.test", { role: "admin" }));
    const userId = fx.seedUser("alice@idp.test");
    const userSid = fx.makeSession(userId);

    // 1. Register a client (admin-gated; non-admins are rejected).
    const denied = await fx.handler(
      post(
        "/oauth2/register",
        { name: "RP", redirectUris: ["https://rp.test/cb"] },
        fx.makeSession(fx.seedUser("pleb@idp.test")),
      ),
    );
    expect(denied.status).toBe(403);

    const registered = await fx.handler(
      post(
        "/oauth2/register",
        { name: "RP", redirectUris: ["https://rp.test/cb"], skipConsent: true },
        adminSid,
      ),
    );
    expect(registered.status).toBe(200);
    const { client, clientSecret } = await jsonBody(registered, CreatedClientBody);
    expect(clientSecret).toBeTruthy();

    // 2. Authorize with the user's session cookie (+ PKCE + nonce).
    const pkce = await Effect.runPromise(generatePKCE().pipe(Effect.provide(PlatformCrypto.layer)));
    const authorize = await fx.handler(
      get(
        "/oauth2/authorize",
        {
          response_type: "code",
          client_id: client.clientId,
          redirect_uri: "https://rp.test/cb",
          scope: "openid profile email offline_access",
          state: "st-1",
          code_challenge: pkce.codeChallenge,
          code_challenge_method: "S256",
          nonce: "n-1",
        },
        { sessionId: userSid },
      ),
    );
    expect(authorize.status).toBe(302);
    const location = locationOf(authorize);
    expect(location.origin + location.pathname).toBe("https://rp.test/cb");
    expect(location.searchParams.get("state")).toBe("st-1");
    const code = searchParam(location, "code");
    expect(code).toBeTruthy();

    // 3. Exchange the code (PKCE verifier + client secret).
    const tokenRes = await fx.handler(
      post("/oauth2/token", {
        grant_type: "authorization_code",
        code,
        redirect_uri: "https://rp.test/cb",
        code_verifier: pkce.codeVerifier,
        client_id: client.clientId,
        client_secret: clientSecret,
      }),
    );
    expect(tokenRes.status).toBe(200);
    const tokens = await jsonBody(
      tokenRes,
      Schema.Struct({
        access_token: Schema.String,
        token_type: Schema.String,
        expires_in: Schema.Number,
        refresh_token: Schema.String,
        id_token: Schema.String,
        scope: Schema.String,
      }),
    );
    expect(tokens.token_type).toBe("Bearer");
    expect(tokens.refresh_token).toBeTruthy();
    expect(tokens.scope).toBe("openid profile email offline_access");

    // A code is single use.
    const replay = await fx.handler(
      post("/oauth2/token", {
        grant_type: "authorization_code",
        code,
        redirect_uri: "https://rp.test/cb",
        code_verifier: pkce.codeVerifier,
        client_id: client.clientId,
        client_secret: clientSecret,
      }),
    );
    expect(replay.status).toBe(400);

    // 4. Verify the id_token against the published JWKS.
    const jwksRes = await fx.handler(get("/.well-known/jwks.json"));
    expect(jwksRes.status).toBe(200);
    const jwks = await jsonBody(jwksRes, Schema.Struct({ keys: Schema.Array(Schema.Json) }));
    expect(jwks.keys.length).toBeGreaterThan(0);

    const claims = await withJwksFetch(jwks, () =>
      Effect.runPromise(
        verifyIdToken(tokens.id_token, {
          provider: "test",
          jwksEndpoint: "http://idp.test/api/auth/.well-known/jwks.json",
          issuer: ISSUER,
          audience: client.clientId,
          nonce: "n-1",
        }),
      ),
    );
    expect(claims["sub"]).toBe(userId);
    expect(claims["email"]).toBe("alice@idp.test");
    expect(claims["email_verified"]).toBe(true);

    // 5. UserInfo with the bearer access token.
    const userinfo = await fx.handler(get("/oauth2/userinfo", {}, { bearer: tokens.access_token }));
    expect(userinfo.status).toBe(200);
    const info = await jsonBody(userinfo, JsonFields);
    expect(info["sub"]).toBe(userId);
    expect(info["email"]).toBe("alice@idp.test");
    expect(info["name"]).toBe(`User ${userId}`);

    const noToken = await fx.handler(get("/oauth2/userinfo"));
    expect(noToken.status).toBe(401);

    // 6. Refresh grant rotates tokens (client auth via Basic header).
    const basic = Buffer.from(`${client.clientId}:${clientSecret}`).toString("base64");
    const refreshRes = await fx.handler(
      new Request("http://idp.test/oauth2/token", {
        method: "POST",
        headers: { "content-type": "application/json", authorization: `Basic ${basic}` },
        body: encodeJson({ grant_type: "refresh_token", refresh_token: tokens.refresh_token }),
      }),
    );
    expect(refreshRes.status).toBe(200);
    const rotated = await jsonBody(
      refreshRes,
      Schema.Struct({
        access_token: Schema.String,
        refresh_token: Schema.String,
        id_token: Schema.String,
      }),
    );
    expect(rotated.access_token).not.toBe(tokens.access_token);
    expect(rotated.refresh_token).not.toBe(tokens.refresh_token);
    expect(rotated.id_token).toBeTruthy();

    // The old refresh token is burned; the rotated one still works.
    const reuse = await fx.handler(
      post("/oauth2/token", {
        grant_type: "refresh_token",
        refresh_token: tokens.refresh_token,
        client_id: client.clientId,
        client_secret: clientSecret,
      }),
    );
    expect(reuse.status).toBe(400);
    expect((await jsonBody(reuse, MessageBody)).message).toBe("invalid_grant");

    // The rotated access token is live.
    const userinfo2 = await fx.handler(
      get("/oauth2/userinfo", {}, { bearer: rotated.access_token }),
    );
    expect(userinfo2.status).toBe(200);
  });

  it("walks unauthenticated users through the login page and consent through the consent page", async () => {
    const fx = makeHttpFixture();
    const adminSid = fx.makeSession(fx.seedUser("admin@idp.test", { role: "admin" }));
    const userSid = fx.makeSession(fx.seedUser("bob@idp.test"));

    const registered = await fx.handler(
      post("/oauth2/register", { name: "RP", redirectUris: ["https://rp.test/cb"] }, adminSid),
    );
    const { client, clientSecret } = await jsonBody(registered, CreatedClientBody);

    const authorizeQuery = {
      response_type: "code",
      client_id: client.clientId,
      redirect_uri: "https://rp.test/cb",
      scope: "openid email",
      state: "st-2",
    };

    // No session: 302 to the login page with the original URL attached.
    const anonymous = await fx.handler(get("/oauth2/authorize", authorizeQuery));
    expect(anonymous.status).toBe(302);
    const loginUrl = locationOf(anonymous);
    expect(loginUrl.origin + loginUrl.pathname).toBe("http://idp.test/login");
    expect(loginUrl.searchParams.get("redirect_to")).toContain("/oauth2/authorize");

    // Signed in, consent not yet granted: 302 to the consent page.
    const needsConsent = await fx.handler(
      get("/oauth2/authorize", authorizeQuery, { sessionId: userSid }),
    );
    expect(needsConsent.status).toBe(302);
    const consentUrl = locationOf(needsConsent);
    expect(consentUrl.origin + consentUrl.pathname).toBe("http://idp.test/consent");
    expect(consentUrl.searchParams.get("client_id")).toBe(client.clientId);
    expect(consentUrl.searchParams.get("scope")).toBe("openid email");
    const consentCode = searchParam(consentUrl, "consent_code");

    // Denying redirects back with access_denied.
    const deniedConsent = await fx.handler(
      post("/oauth2/consent", { consentCode, accept: false }, userSid),
    );
    expect(deniedConsent.status).toBe(200);
    const deniedRedirect = new URL(
      (await jsonBody(deniedConsent, Schema.Struct({ redirectTo: Schema.String }))).redirectTo,
    );
    expect(deniedRedirect.searchParams.get("error")).toBe("access_denied");
    expect(deniedRedirect.searchParams.get("state")).toBe("st-2");

    // A consent code is single use.
    const reused = await fx.handler(
      post("/oauth2/consent", { consentCode, accept: true }, userSid),
    );
    expect(reused.status).toBe(400);

    // Run authorize again and accept this time.
    const again = await fx.handler(
      get("/oauth2/authorize", authorizeQuery, { sessionId: userSid }),
    );
    const consentCode2 = searchParam(locationOf(again), "consent_code");
    const accepted = await fx.handler(
      post("/oauth2/consent", { consentCode: consentCode2, accept: true }, userSid),
    );
    expect(accepted.status).toBe(200);
    const acceptedRedirect = new URL(
      (await jsonBody(accepted, Schema.Struct({ redirectTo: Schema.String }))).redirectTo,
    );
    const code = searchParam(acceptedRedirect, "code");
    expect(code).toBeTruthy();
    expect(acceptedRedirect.searchParams.get("state")).toBe("st-2");

    // The consent-issued code exchanges normally.
    const tokenRes = await fx.handler(
      post("/oauth2/token", {
        grant_type: "authorization_code",
        code,
        redirect_uri: "https://rp.test/cb",
        client_id: client.clientId,
        client_secret: clientSecret,
      }),
    );
    expect(tokenRes.status).toBe(200);

    // Consent is remembered: the next authorize goes straight to the client.
    const remembered = await fx.handler(
      get("/oauth2/authorize", authorizeQuery, { sessionId: userSid }),
    );
    const rememberedUrl = locationOf(remembered);
    expect(rememberedUrl.origin + rememberedUrl.pathname).toBe("https://rp.test/cb");
    expect(rememberedUrl.searchParams.get("code")).toBeTruthy();
  });

  it("rejects a token exchange with a wrong PKCE verifier or wrong secret", async () => {
    const fx = makeHttpFixture();
    const adminSid = fx.makeSession(fx.seedUser("admin@idp.test", { role: "admin" }));
    const userSid = fx.makeSession(fx.seedUser("carol@idp.test"));

    const registered = await fx.handler(
      post(
        "/oauth2/register",
        { name: "RP", redirectUris: ["https://rp.test/cb"], skipConsent: true },
        adminSid,
      ),
    );
    const { client, clientSecret } = await jsonBody(registered, CreatedClientBody);

    const pkce = await Effect.runPromise(generatePKCE().pipe(Effect.provide(PlatformCrypto.layer)));
    const authorizeOnce = async () => {
      const res = await fx.handler(
        get(
          "/oauth2/authorize",
          {
            response_type: "code",
            client_id: client.clientId,
            redirect_uri: "https://rp.test/cb",
            scope: "openid",
            code_challenge: pkce.codeChallenge,
            code_challenge_method: "S256",
          },
          { sessionId: userSid },
        ),
      );
      return searchParam(locationOf(res), "code");
    };

    // Wrong PKCE verifier -> invalid_grant.
    const badVerifier = await fx.handler(
      post("/oauth2/token", {
        grant_type: "authorization_code",
        code: await authorizeOnce(),
        redirect_uri: "https://rp.test/cb",
        code_verifier: "wrong-verifier",
        client_id: client.clientId,
        client_secret: clientSecret,
      }),
    );
    expect(badVerifier.status).toBe(400);
    expect((await jsonBody(badVerifier, MessageBody)).message).toBe("invalid_grant");

    // Wrong client secret -> 401 invalid_client.
    const badSecret = await fx.handler(
      post("/oauth2/token", {
        grant_type: "authorization_code",
        code: await authorizeOnce(),
        redirect_uri: "https://rp.test/cb",
        code_verifier: pkce.codeVerifier,
        client_id: client.clientId,
        client_secret: "wrong-secret",
      }),
    );
    expect(badSecret.status).toBe(401);
    expect((await jsonBody(badSecret, MessageBody)).message).toBe("invalid_client");

    // Unsupported grant type -> 400.
    const badGrant = await fx.handler(
      post("/oauth2/token", {
        grant_type: "password",
        client_id: client.clientId,
        client_secret: clientSecret,
      }),
    );
    expect(badGrant.status).toBe(400);
    expect((await jsonBody(badGrant, MessageBody)).message).toBe("unsupported_grant_type");
  });

  it("accepts a form-urlencoded token request", async () => {
    const fx = makeHttpFixture();
    const adminSid = fx.makeSession(fx.seedUser("admin@idp.test", { role: "admin" }));
    const userSid = fx.makeSession(fx.seedUser("dave@idp.test"));

    const registered = await fx.handler(
      post(
        "/oauth2/register",
        { name: "RP", redirectUris: ["https://rp.test/cb"], skipConsent: true },
        adminSid,
      ),
    );
    const { client, clientSecret } = await jsonBody(registered, CreatedClientBody);

    const authorize = await fx.handler(
      get(
        "/oauth2/authorize",
        {
          response_type: "code",
          client_id: client.clientId,
          redirect_uri: "https://rp.test/cb",
          scope: "openid",
        },
        { sessionId: userSid },
      ),
    );
    const code = searchParam(locationOf(authorize), "code");

    const tokenRes = await fx.handler(
      new Request("http://idp.test/oauth2/token", {
        method: "POST",
        headers: { "content-type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({
          grant_type: "authorization_code",
          code,
          redirect_uri: "https://rp.test/cb",
          client_id: client.clientId,
          client_secret: clientSecret,
        }).toString(),
      }),
    );
    expect(tokenRes.status).toBe(200);
    expect(
      (await jsonBody(tokenRes, Schema.Struct({ access_token: Schema.String }))).access_token,
    ).toBeTruthy();
  });

  it("serves the discovery document", async () => {
    const fx = makeHttpFixture();
    const res = await fx.handler(get("/.well-known/openid-configuration"));
    expect(res.status).toBe(200);
    const doc = await jsonBody(res, JsonFields);
    expect(doc["issuer"]).toBe(ISSUER);
    expect(doc["authorization_endpoint"]).toBe(`${ISSUER}/oauth2/authorize`);
    expect(doc["token_endpoint"]).toBe(`${ISSUER}/oauth2/token`);
    expect(doc["userinfo_endpoint"]).toBe(`${ISSUER}/oauth2/userinfo`);
    expect(doc["jwks_uri"]).toBe(`${ISSUER}/.well-known/jwks.json`);
    expect(doc["registration_endpoint"]).toBe(`${ISSUER}/oauth2/register`);
    expect(doc["end_session_endpoint"]).toBe(`${ISSUER}/oauth2/logout`);
    expect(doc["code_challenge_methods_supported"]).toEqual(["S256"]);
  });

  it("returns 404 when the OIDC provider is not configured", async () => {
    const fx = makeHttpFixture();
    const discovery = await fx.handlerWithoutOidc(get("/.well-known/openid-configuration"));
    expect(discovery.status).toBe(404);
    const token = await fx.handlerWithoutOidc(
      post("/oauth2/token", { grant_type: "authorization_code" }),
    );
    expect(token.status).toBe(404);
  });

  it("detects refresh-token reuse and rejects the replayed token", async () => {
    const fx = makeHttpFixture();
    const adminSid = fx.makeSession(fx.seedUser("admin@idp.test", { role: "admin" }));
    const userSid = fx.makeSession(fx.seedUser("reuse@idp.test"));

    const registered = await fx.handler(
      post(
        "/oauth2/register",
        { name: "RP", redirectUris: ["https://rp.test/cb"], skipConsent: true },
        adminSid,
      ),
    );
    const { client, clientSecret } = await jsonBody(registered, CreatedClientBody);

    const pkce = await Effect.runPromise(generatePKCE().pipe(Effect.provide(PlatformCrypto.layer)));
    const authorize = await fx.handler(
      get(
        "/oauth2/authorize",
        {
          response_type: "code",
          client_id: client.clientId,
          redirect_uri: "https://rp.test/cb",
          scope: "openid offline_access",
          code_challenge: pkce.codeChallenge,
          code_challenge_method: "S256",
        },
        { sessionId: userSid },
      ),
    );
    const code = searchParam(locationOf(authorize), "code");

    const tokenRes = await fx.handler(
      post("/oauth2/token", {
        grant_type: "authorization_code",
        code,
        redirect_uri: "https://rp.test/cb",
        code_verifier: pkce.codeVerifier,
        client_id: client.clientId,
        client_secret: clientSecret,
      }),
    );
    const { refresh_token: rt1 } = await jsonBody(tokenRes, RefreshTokenBody);

    // First rotation — consumes rt1, issues rt2.
    const rot1 = await fx.handler(
      post("/oauth2/token", {
        grant_type: "refresh_token",
        refresh_token: rt1,
        client_id: client.clientId,
        client_secret: clientSecret,
      }),
    );
    expect(rot1.status).toBe(200);
    const { refresh_token: rt2 } = await jsonBody(rot1, RefreshTokenBody);

    // Second rotation — consumes rt2, issues rt3.
    const rot2 = await fx.handler(
      post("/oauth2/token", {
        grant_type: "refresh_token",
        refresh_token: rt2,
        client_id: client.clientId,
        client_secret: clientSecret,
      }),
    );
    expect(rot2.status).toBe(200);
    const { refresh_token: rt3 } = await jsonBody(rot2, RefreshTokenBody);

    // Replay rt1 — already consumed → reuse detection fires, revokes family (rt3 should be gone).
    const replay = await fx.handler(
      post("/oauth2/token", {
        grant_type: "refresh_token",
        refresh_token: rt1,
        client_id: client.clientId,
        client_secret: clientSecret,
      }),
    );
    expect(replay.status).toBe(400);

    // rt3 must now be revoked too.
    const afterRevoke = await fx.handler(
      post("/oauth2/token", {
        grant_type: "refresh_token",
        refresh_token: rt3,
        client_id: client.clientId,
        client_secret: clientSecret,
      }),
    );
    expect(afterRevoke.status).toBe(400);
  });

  it("enforces absolute (non-sliding) refresh token lifetime", async () => {
    const fx = makeHttpFixture();
    const adminSid = fx.makeSession(fx.seedUser("admin@idp.test", { role: "admin" }));
    const userSid = fx.makeSession(fx.seedUser("expire@idp.test"));

    const registered = await fx.handler(
      post(
        "/oauth2/register",
        { name: "RP", redirectUris: ["https://rp.test/cb"], skipConsent: true },
        adminSid,
      ),
    );
    const { client, clientSecret } = await jsonBody(registered, CreatedClientBody);

    const pkce = await Effect.runPromise(generatePKCE().pipe(Effect.provide(PlatformCrypto.layer)));
    const authorize = await fx.handler(
      get(
        "/oauth2/authorize",
        {
          response_type: "code",
          client_id: client.clientId,
          redirect_uri: "https://rp.test/cb",
          scope: "openid offline_access",
          code_challenge: pkce.codeChallenge,
          code_challenge_method: "S256",
        },
        { sessionId: userSid },
      ),
    );
    const code = searchParam(locationOf(authorize), "code");

    const tokenRes = await fx.handler(
      post("/oauth2/token", {
        grant_type: "authorization_code",
        code,
        redirect_uri: "https://rp.test/cb",
        code_verifier: pkce.codeVerifier,
        client_id: client.clientId,
        client_secret: clientSecret,
      }),
    );
    const { refresh_token: rt } = await jsonBody(tokenRes, RefreshTokenBody);

    // Expire the token by mutating absoluteExpiresAt to the past.
    const hash = hashOidcSecret(rt);
    const stored = fx.oidcTokenStore.get(hash);
    assert(stored !== undefined, "the refresh token is stored");
    fx.oidcTokenStore.set(hash, {
      ...stored,
      absoluteExpiresAt: DateTime.toEpochMillis(DateTime.nowUnsafe()) - 1000,
      expiresAt: DateTime.toEpochMillis(DateTime.nowUnsafe()) - 1000,
    });

    const expired = await fx.handler(
      post("/oauth2/token", {
        grant_type: "refresh_token",
        refresh_token: rt,
        client_id: client.clientId,
        client_secret: clientSecret,
      }),
    );
    expect(expired.status).toBe(400);
    expect((await jsonBody(expired, MessageBody)).message).toBe("invalid_grant");
  });

  it("allows scope down-scoping on refresh token grant", async () => {
    const fx = makeHttpFixture();
    const adminSid = fx.makeSession(fx.seedUser("admin@idp.test", { role: "admin" }));
    const userSid = fx.makeSession(fx.seedUser("scope@idp.test"));

    const registered = await fx.handler(
      post(
        "/oauth2/register",
        { name: "RP", redirectUris: ["https://rp.test/cb"], skipConsent: true },
        adminSid,
      ),
    );
    const { client, clientSecret } = await jsonBody(registered, CreatedClientBody);

    const pkce = await Effect.runPromise(generatePKCE().pipe(Effect.provide(PlatformCrypto.layer)));
    const authorize = await fx.handler(
      get(
        "/oauth2/authorize",
        {
          response_type: "code",
          client_id: client.clientId,
          redirect_uri: "https://rp.test/cb",
          scope: "openid profile email offline_access",
          code_challenge: pkce.codeChallenge,
          code_challenge_method: "S256",
        },
        { sessionId: userSid },
      ),
    );
    const code = searchParam(locationOf(authorize), "code");

    const tokenRes = await fx.handler(
      post("/oauth2/token", {
        grant_type: "authorization_code",
        code,
        redirect_uri: "https://rp.test/cb",
        code_verifier: pkce.codeVerifier,
        client_id: client.clientId,
        client_secret: clientSecret,
      }),
    );
    const { refresh_token: rt } = await jsonBody(tokenRes, RefreshTokenBody);

    // Down-scope to a subset (keep offline_access for rotation) — should succeed.
    const downScoped = await fx.handler(
      post("/oauth2/token", {
        grant_type: "refresh_token",
        refresh_token: rt,
        client_id: client.clientId,
        client_secret: clientSecret,
        scope: "openid email offline_access",
      }),
    );
    expect(downScoped.status).toBe(200);
    const downScopedBody = await jsonBody(
      downScoped,
      Schema.Struct({ scope: Schema.String, refresh_token: Schema.String }),
    );
    expect(downScopedBody.scope).toBe("openid email offline_access");

    // Up-scope is forbidden: original grant had "profile"; re-requesting it via the narrower token fails.
    const rt2 = downScopedBody.refresh_token;
    const upScoped = await fx.handler(
      post("/oauth2/token", {
        grant_type: "refresh_token",
        refresh_token: rt2,
        client_id: client.clientId,
        client_secret: clientSecret,
        scope: "openid email profile offline_access",
      }),
    );
    expect(upScoped.status).toBe(400);
    expect((await jsonBody(upScoped, MessageBody)).message).toBe("invalid_scope");
  });

  it("prompt=none on authorize returns login_required for unauthenticated users", async () => {
    const fx = makeHttpFixture();
    const adminSid = fx.makeSession(fx.seedUser("admin@idp.test", { role: "admin" }));

    const registered = await fx.handler(
      post(
        "/oauth2/register",
        { name: "RP", redirectUris: ["https://rp.test/cb"], skipConsent: true },
        adminSid,
      ),
    );
    const { client } = await jsonBody(registered, ClientIdBody);

    const res = await fx.handler(
      get("/oauth2/authorize", {
        response_type: "code",
        client_id: client.clientId,
        redirect_uri: "https://rp.test/cb",
        scope: "openid",
        prompt: "none",
        state: "s1",
      }),
    );
    expect(res.status).toBe(302);
    const loc = locationOf(res);
    expect(loc.origin + loc.pathname).toBe("https://rp.test/cb");
    expect(loc.searchParams.get("error")).toBe("login_required");
    expect(loc.searchParams.get("state")).toBe("s1");
  });

  it("prompt=login forces re-authentication even when a session exists", async () => {
    const fx = makeHttpFixture();
    const adminSid = fx.makeSession(fx.seedUser("admin@idp.test", { role: "admin" }));
    const userSid = fx.makeSession(fx.seedUser("login@idp.test"));

    const registered = await fx.handler(
      post(
        "/oauth2/register",
        { name: "RP", redirectUris: ["https://rp.test/cb"], skipConsent: true },
        adminSid,
      ),
    );
    const { client } = await jsonBody(registered, ClientIdBody);

    const res = await fx.handler(
      get(
        "/oauth2/authorize",
        {
          response_type: "code",
          client_id: client.clientId,
          redirect_uri: "https://rp.test/cb",
          scope: "openid",
          prompt: "login",
        },
        { sessionId: userSid },
      ),
    );
    expect(res.status).toBe(302);
    const loc = locationOf(res);
    expect(loc.origin + loc.pathname).toBe("http://idp.test/login");
  });
});

// -----------------------------------------------------------------------------
// HTTP layer: RFC 7591 dynamic client registration + RFC 8414 metadata
// -----------------------------------------------------------------------------

const RegistrationResponse = Schema.Struct({
  client_id: Schema.String,
  client_id_issued_at: Schema.Number,
  client_secret: Schema.optional(Schema.String),
  client_secret_expires_at: Schema.optional(Schema.Number),
  client_name: Schema.String,
  redirect_uris: Schema.Array(Schema.String),
  grant_types: Schema.Array(Schema.String),
  response_types: Schema.Array(Schema.String),
  token_endpoint_auth_method: Schema.String,
  scope: Schema.String,
  registration_access_token: Schema.optional(Schema.String),
  registration_client_uri: Schema.optional(Schema.String),
});

describe("HTTP dynamic client registration (RFC 7591 / 7592)", () => {
  const MCP_REDIRECT = "http://127.0.0.1:33418/callback";

  it("registers an MCP client and runs authorization_code + PKCE S256 to a token", async () => {
    const fx = makeHttpFixture({ dynamicRegistration: { skipConsent: true } });
    const userId = fx.seedUser("mcp-user@idp.test");
    const userSid = fx.makeSession(userId);

    // 1. Dynamic registration: a public client, no credentials of any kind.
    //    Unknown members (client_uri, logo_uri, ...) are ignored, not rejected.
    const registered = await fx.handler(
      post("/register", {
        redirect_uris: [MCP_REDIRECT],
        token_endpoint_auth_method: "none",
        grant_types: ["authorization_code", "refresh_token"],
        response_types: ["code"],
        client_name: "Example MCP Client",
        scope: "openid profile email offline_access",
        client_uri: "https://mcp.example.com",
        logo_uri: "https://mcp.example.com/logo.png",
      }),
    );
    expect(registered.status).toBe(201);
    const client = await jsonBody(registered, RegistrationResponse);
    expect(client.client_id).toBeTruthy();
    expect(client.client_secret).toBeUndefined();
    expect(client.token_endpoint_auth_method).toBe("none");
    expect(client.client_name).toBe("Example MCP Client");
    expect(client.redirect_uris).toEqual([MCP_REDIRECT]);
    expect(client.grant_types).toEqual(["authorization_code", "refresh_token"]);
    expect(client.registration_access_token).toBeTruthy();
    expect(client.registration_client_uri).toBe(`${ISSUER}/register/${client.client_id}`);
    expect(client.client_id_issued_at).toBeGreaterThan(0);

    // 2. Authorization code with PKCE S256 — no client secret anywhere.
    const pkce = await Effect.runPromise(generatePKCE().pipe(Effect.provide(PlatformCrypto.layer)));
    const authorize = await fx.handler(
      get(
        "/oauth2/authorize",
        {
          response_type: "code",
          client_id: client.client_id,
          redirect_uri: MCP_REDIRECT,
          scope: "openid profile email offline_access",
          state: "mcp-state",
          code_challenge: pkce.codeChallenge,
          code_challenge_method: "S256",
        },
        { sessionId: userSid },
      ),
    );
    expect(authorize.status).toBe(302);
    const location = locationOf(authorize);
    expect(location.origin + location.pathname).toBe(MCP_REDIRECT);
    expect(location.searchParams.get("state")).toBe("mcp-state");
    const code = searchParam(location, "code");

    // 3. Token exchange: public client authenticates with the PKCE verifier.
    const tokenRes = await fx.handler(
      post("/oauth2/token", {
        grant_type: "authorization_code",
        code,
        redirect_uri: MCP_REDIRECT,
        code_verifier: pkce.codeVerifier,
        client_id: client.client_id,
      }),
    );
    expect(tokenRes.status).toBe(200);
    const tokens = await jsonBody(
      tokenRes,
      Schema.Struct({
        access_token: Schema.String,
        token_type: Schema.String,
        refresh_token: Schema.String,
        id_token: Schema.String,
        scope: Schema.String,
      }),
    );
    expect(tokens.token_type).toBe("Bearer");
    expect(tokens.id_token).toBeTruthy();
    expect(tokens.scope).toBe("openid profile email offline_access");

    // The access token resolves the user's claims.
    const userinfo = await fx.handler(get("/oauth2/userinfo", {}, { bearer: tokens.access_token }));
    expect(userinfo.status).toBe(200);
    expect((await jsonBody(userinfo, JsonFields))["sub"]).toBe(userId);

    // 4. The registered refresh_token grant works too.
    const refreshed = await fx.handler(
      post("/oauth2/token", {
        grant_type: "refresh_token",
        refresh_token: tokens.refresh_token,
        client_id: client.client_id,
      }),
    );
    expect(refreshed.status).toBe(200);
  });

  it("refuses a public client that omits PKCE", async () => {
    const fx = makeHttpFixture({ dynamicRegistration: { skipConsent: true } });
    const userSid = fx.makeSession(fx.seedUser("nopkce@idp.test"));

    const registered = await fx.handler(
      post("/register", {
        redirect_uris: [MCP_REDIRECT],
        token_endpoint_auth_method: "none",
      }),
    );
    const client = await jsonBody(registered, RegistrationResponse);

    const authorize = await fx.handler(
      get(
        "/oauth2/authorize",
        {
          response_type: "code",
          client_id: client.client_id,
          redirect_uri: MCP_REDIRECT,
          scope: "openid",
        },
        { sessionId: userSid },
      ),
    );
    expect(authorize.status).toBe(302);
    expect(locationOf(authorize).searchParams.get("error")).toBe("invalid_request");
  });

  it("answers metadata failures with an RFC 7591 error body", async () => {
    const fx = makeHttpFixture({ dynamicRegistration: {} });

    const badRedirect = await fx.handler(
      post("/register", { redirect_uris: ["http://evil.test/cb"] }),
    );
    expect(badRedirect.status).toBe(400);
    const body = await jsonBody(
      badRedirect,
      Schema.Struct({ error: Schema.String, error_description: Schema.String }),
    );
    expect(body.error).toBe("invalid_redirect_uri");
    expect(body.error_description).toContain("http://evil.test/cb");

    const badGrant = await fx.handler(
      post("/register", {
        redirect_uris: ["https://rp.test/cb"],
        grant_types: ["client_credentials"],
      }),
    );
    expect(badGrant.status).toBe(400);
    expect((await jsonBody(badGrant, Schema.Struct({ error: Schema.String }))).error).toBe(
      "invalid_client_metadata",
    );
  });

  it("requires the initial access token as a bearer credential when configured", async () => {
    const fx = makeHttpFixture({
      dynamicRegistration: { initialAccessToken: Redacted.make("iat-secret") },
    });
    const body = { redirect_uris: ["https://rp.test/cb"], token_endpoint_auth_method: "none" };

    const anonymous = await fx.handler(post("/register", body));
    expect(anonymous.status).toBe(401);
    expect((await jsonBody(anonymous, Schema.Struct({ code: Schema.String }))).code).toBe(
      "invalid_token",
    );

    const wrong = await fx.handler(jsonRequest("POST", "/register", body, "nope"));
    expect(wrong.status).toBe(401);

    const ok = await fx.handler(jsonRequest("POST", "/register", body, "iat-secret"));
    expect(ok.status).toBe(201);
  });

  it("answers 403 when the registration policy refuses the caller", async () => {
    const fx = makeHttpFixture({
      dynamicRegistration: {
        policy: (metadata) =>
          Effect.succeed(
            metadata.clientName === "Allowed"
              ? true
              : { allow: false, error: "access_denied", errorDescription: "Not on the allowlist" },
          ),
      },
    });

    const denied = await fx.handler(
      post("/register", { redirect_uris: ["https://rp.test/cb"], client_name: "Other" }),
    );
    expect(denied.status).toBe(403);
    expect((await jsonBody(denied, Schema.Struct({ code: Schema.String }))).code).toBe(
      "access_denied",
    );

    const allowed = await fx.handler(
      post("/register", { redirect_uris: ["https://rp.test/cb"], client_name: "Allowed" }),
    );
    expect(allowed.status).toBe(201);
  });

  it("serves the RFC 7592 management endpoints behind the registration access token", async () => {
    const fx = makeHttpFixture({ dynamicRegistration: {} });
    const registered = await fx.handler(
      post("/register", {
        redirect_uris: [MCP_REDIRECT],
        token_endpoint_auth_method: "none",
        client_name: "Managed",
      }),
    );
    const client = await jsonBody(registered, RegistrationResponse);
    const rat = client.registration_access_token;
    assert(rat !== undefined, "registration returns an access token");
    const path = `/register/${client.client_id}`;

    // Read.
    const read = await fx.handler(get(path, {}, { bearer: rat }));
    expect(read.status).toBe(200);
    const readBody = await jsonBody(read, RegistrationResponse);
    expect(readBody.client_name).toBe("Managed");
    // Neither one-time credential is recoverable after registration.
    expect(readBody.client_secret).toBeUndefined();
    expect(readBody.registration_access_token).toBeUndefined();

    // No token at all, and a wrong token.
    expect((await fx.handler(get(path))).status).toBe(401);
    expect((await fx.handler(get(path, {}, { bearer: "wrong" }))).status).toBe(401);
    // An unknown client is indistinguishable from a bad token.
    expect((await fx.handler(get("/register/nope", {}, { bearer: rat }))).status).toBe(401);

    // Update.
    const updated = await fx.handler(
      jsonRequest(
        "PUT",
        path,
        {
          redirect_uris: [MCP_REDIRECT, "https://rp.test/cb"],
          token_endpoint_auth_method: "none",
          client_name: "Managed v2",
        },
        rat,
      ),
    );
    expect(updated.status).toBe(200);
    const updatedBody = await jsonBody(updated, RegistrationResponse);
    expect(updatedBody.client_name).toBe("Managed v2");
    expect(updatedBody.redirect_uris).toEqual([MCP_REDIRECT, "https://rp.test/cb"]);

    // A rejected update keeps the RFC error shape.
    const badUpdate = await fx.handler(
      jsonRequest("PUT", path, { redirect_uris: ["http://evil.test/cb"] }, rat),
    );
    expect(badUpdate.status).toBe(400);
    expect((await jsonBody(badUpdate, Schema.Struct({ error: Schema.String }))).error).toBe(
      "invalid_redirect_uri",
    );

    // Delete, after which the registration is gone.
    const deleted = await fx.handler(jsonRequest("DELETE", path, undefined, rat));
    expect(deleted.status).toBe(204);
    expect((await fx.handler(get(path, {}, { bearer: rat }))).status).toBe(401);
  });

  it("404s the registration endpoints until dynamic registration is configured", async () => {
    const fx = makeHttpFixture();
    const register = await fx.handler(post("/register", { redirect_uris: ["https://rp.test/cb"] }));
    expect(register.status).toBe(404);

    // Management can be switched off on its own.
    const noManagement = makeHttpFixture({ dynamicRegistration: { management: false } });
    const registered = await noManagement.handler(
      post("/register", { redirect_uris: ["https://rp.test/cb"] }),
    );
    expect(registered.status).toBe(201);
    const client = await jsonBody(registered, RegistrationResponse);
    const rat = client.registration_access_token;
    assert(rat !== undefined, "registration returns an access token");
    const read = await noManagement.handler(
      get(`/register/${client.client_id}`, {}, { bearer: rat }),
    );
    expect(read.status).toBe(404);
  });

  it("serves RFC 8414 authorization server metadata pointing at the registration endpoint", async () => {
    const withoutDCR = makeHttpFixture();
    const base = await withoutDCR.handler(get("/.well-known/oauth-authorization-server"));
    expect(base.status).toBe(200);
    const baseDoc = await jsonBody(base, JsonFields);
    expect(baseDoc["issuer"]).toBe(ISSUER);
    expect(baseDoc["authorization_endpoint"]).toBe(`${ISSUER}/oauth2/authorize`);
    expect(baseDoc["token_endpoint"]).toBe(`${ISSUER}/oauth2/token`);
    expect(baseDoc["jwks_uri"]).toBe(`${ISSUER}/.well-known/jwks.json`);
    expect(baseDoc["code_challenge_methods_supported"]).toEqual(["S256"]);
    expect(baseDoc["grant_types_supported"]).toEqual(["authorization_code", "refresh_token"]);
    expect(baseDoc["response_types_supported"]).toEqual(["code"]);
    expect(baseDoc["token_endpoint_auth_methods_supported"]).toEqual([
      "client_secret_basic",
      "client_secret_post",
      "none",
    ]);
    // The OAuth document carries no OIDC-only members.
    expect(baseDoc["claims_supported"]).toBeUndefined();
    expect(baseDoc["registration_endpoint"]).toBe(`${ISSUER}/oauth2/register`);

    // With DCR on, both documents advertise the RFC 7591 endpoint.
    const withDCR = makeHttpFixture({ dynamicRegistration: {} });
    const doc = await jsonBody(
      await withDCR.handler(get("/.well-known/oauth-authorization-server")),
      JsonFields,
    );
    expect(doc["registration_endpoint"]).toBe(`${ISSUER}/register`);
    const oidcDoc = await jsonBody(
      await withDCR.handler(get("/.well-known/openid-configuration")),
      JsonFields,
    );
    expect(oidcDoc["registration_endpoint"]).toBe(`${ISSUER}/register`);
    expect(oidcDoc["userinfo_endpoint"]).toBe(`${ISSUER}/oauth2/userinfo`);
    expect(oidcDoc["claims_supported"]).toBeDefined();

    // 404 while the provider itself is absent.
    expect(
      (await withoutDCR.handlerWithoutOidc(get("/.well-known/oauth-authorization-server"))).status,
    ).toBe(404);
  });
});

describe("HTTP dynamic registration and the per-IP limit (#358)", () => {
  // An anonymous RFC 7591 registration: POST /register, no initial access token.
  const register = (headers: Record<string, string> = {}): Request =>
    new Request("http://idp.test/register", {
      method: "POST",
      headers: { "content-type": "application/json", ...headers },
      body: encodeJson({
        redirect_uris: ["http://127.0.0.1:9876/callback"],
        token_endpoint_auth_method: "none",
        client_name: "MCP Client",
      }),
    });

  it("throws from Http.make when registration is enabled with no RateLimiter in services", () => {
    // Registration needs its limit to run, so the app fails to start rather than
    // serve registrations with the limit silently off (#389).
    expect(() => makeHttpFixture({ dynamicRegistration: {}, rateLimit: false })).toThrow(
      RateLimiterConfigError,
    );
    expect(() => makeHttpFixture({ dynamicRegistration: {}, rateLimit: false })).toThrow(
      /the dynamic client registration limit \(POST \/register\) configured with no RateLimiter/,
    );
  });

  it("throws ClientAddressConfigError from Http.make when registration has no address source (#398)", () => {
    // The registration limit keys on the ClientIP that Http.make resolves from
    // its trustedProxy, so Http.make checks that source, and the app fails to
    // start rather than refuse every registration.
    const make = () =>
      makeHttpFixture({ dynamicRegistration: {}, declareRegistrationAddress: false });
    expect(make).toThrow(ClientAddressConfigError);
    expect(make).toThrow(REGISTRATION_ADDRESS_ERROR);
  });

  it("builds with Http.make's allowMissingClientIp opt-out, and refuses address-less registrations (#398)", async () => {
    const fx = makeHttpFixture({
      dynamicRegistration: {},
      declareRegistrationAddress: false,
      allowMissingClientIp: true,
    });

    const res = await fx.handler(register({ "cf-connecting-ip": "203.0.113.9" }));

    expect(res.status).toBe(429);
    expect([...fx.rateLimitKeys]).toEqual([]);
  });

  it("rejects Http.makeAsync with ClientAddressConfigError when registration has no address source and services build asynchronously (#400)", async () => {
    // With an asynchronous build step, the check runs only after Http.make
    // returns, so make cannot throw it: every request rejects with it.
    const fx = makeHttpFixture({
      dynamicRegistration: {},
      declareRegistrationAddress: false,
      connectAsynchronously: true,
    });
    await expect(fx.handler(new Request("http://localhost/session"))).rejects.toThrow(
      ClientAddressConfigError,
    );
    // makeAsync waits for the build, so the app fails to start instead.
    const constructed = HttpServer.makeAsync({
      services: fx.servicesWithRateLimiter,
      cookie: { secure: false },
    });
    await expect(constructed).rejects.toThrow(ClientAddressConfigError);
    await expect(constructed).rejects.toThrow(REGISTRATION_ADDRESS_ERROR);
  });

  it("refuses registrations with 429 outside Http.make when no RateLimiter is in scope", async () => {
    const fx = makeHttpFixture({ dynamicRegistration: {}, rateLimit: true });
    const handler = handBuiltHandler(fx.servicesWithoutRateLimiter);

    const res = await handler(register({ "cf-connecting-ip": "203.0.113.9" }));

    expect(res.status).toBe(429);
    expect(await res.json()).toMatchObject({
      message: "No RateLimiter in services; this request cannot be rate limited",
    });
  });

  it("refuses registrations with 429 outside Http.make when no ClientIP is in scope", async () => {
    const fx = makeHttpFixture({ dynamicRegistration: {}, rateLimit: true });
    const handler = handBuiltHandler(fx.servicesWithRateLimiter);

    const res = await handler(register({ "cf-connecting-ip": "203.0.113.9" }));

    expect(res.status).toBe(429);
    expect(await res.json()).toMatchObject({
      message: "Client address unavailable; this request cannot be rate limited",
    });
    expect([...fx.rateLimitKeys]).toEqual([]);
  });

  it("refuses a registration with no client address and never keys it under a shared bucket", async () => {
    const fx = makeHttpFixture({ dynamicRegistration: {}, rateLimit: true });

    const res = await fx.handler(register());

    expect(res.status).toBe(429);
    expect([...fx.rateLimitKeys]).toEqual([]);
  });

  it("keys the registration limit by the resolved client address", async () => {
    const fx = makeHttpFixture({
      dynamicRegistration: {},
      rateLimit: true,
      trustedProxy: ClientIP.cloudflare,
    });

    const res = await fx.handler(register({ "cf-connecting-ip": "203.0.113.9" }));

    expect(res.status).toBe(201);
    expect(fx.rateLimitKeys.has("oidc-register:203.0.113.9")).toBe(true);
    expect([...fx.rateLimitKeys].some((key) => key.includes("unknown"))).toBe(false);
  });

  it("refuses a registration whose forwarded address is unusable, without a shared bucket", async () => {
    const fx = makeHttpFixture({
      dynamicRegistration: {},
      rateLimit: true,
      trustedProxy: ClientIP.cloudflare,
    });

    const res = await fx.handler(register({ "cf-connecting-ip": "203.0.113.9, 198.51.100.1" }));

    expect(res.status).toBe(429);
    expect([...fx.rateLimitKeys]).toEqual([]);
  });
});
describe("HTTP OIDC client administration: PATCH /oauth2/clients/:clientId", () => {
  const patch = (path: string, body: Schema.Json, sessionId?: string): Request =>
    new Request(`http://idp.test${path}`, {
      method: "PATCH",
      headers: {
        ...FIXTURE_CLIENT_HEADERS,
        "content-type": "application/json",
        ...(sessionId !== undefined ? { cookie: `conduit_session=${sessionId}` } : {}),
      },
      body: encodeJson(body),
    });

  const registerClient = async (fx: ReturnType<typeof makeHttpFixture>, adminSid: string) => {
    const registered = await fx.handler(
      post("/oauth2/register", { name: "RP", redirectUris: ["https://rp.test/cb"] }, adminSid),
    );
    expect(registered.status).toBe(200);
    // SAFETY: a 200 from /oauth2/register carries the registered client.
    const { client } = await jsonBody(registered, ClientIdBody);
    return client.clientId;
  };

  it("lets an admin update every field of a registered client", async () => {
    const fx = makeHttpFixture();
    const adminSid = fx.makeSession(fx.seedUser("admin@idp.test", { role: "admin" }));
    const clientId = await registerClient(fx, adminSid);

    const res = await fx.handler(
      patch(
        `/oauth2/clients/${clientId}`,
        {
          name: "Renamed RP",
          redirectUris: ["https://rp.test/other"],
          skipConsent: true,
          disabled: true,
          metadata: { team: "core" },
        },
        adminSid,
      ),
    );
    expect(res.status).toBe(200);
    // SAFETY: a 200 from the update endpoint carries the client view.
    const body = await jsonBody(
      res,
      Schema.Struct({
        clientId: Schema.String,
        name: Schema.String,
        redirectUris: Schema.Array(Schema.String),
        skipConsent: Schema.Boolean,
        disabled: Schema.Boolean,
      }),
    );
    expect(body).toMatchObject({
      clientId,
      name: "Renamed RP",
      redirectUris: ["https://rp.test/other"],
      skipConsent: true,
      disabled: true,
    });
  });

  it("keeps the client's fields when the payload is empty", async () => {
    const fx = makeHttpFixture();
    const adminSid = fx.makeSession(fx.seedUser("admin@idp.test", { role: "admin" }));
    const clientId = await registerClient(fx, adminSid);

    const res = await fx.handler(patch(`/oauth2/clients/${clientId}`, {}, adminSid));
    expect(res.status).toBe(200);
    // SAFETY: a 200 from the update endpoint carries the client view.
    const body = await jsonBody(
      res,
      Schema.Struct({ name: Schema.String, redirectUris: Schema.Array(Schema.String) }),
    );
    expect(body).toMatchObject({ name: "RP", redirectUris: ["https://rp.test/cb"] });
  });

  it("answers 400 for an unknown client", async () => {
    const fx = makeHttpFixture();
    const adminSid = fx.makeSession(fx.seedUser("admin@idp.test", { role: "admin" }));
    const res = await fx.handler(patch("/oauth2/clients/nope", { name: "x" }, adminSid));
    expect(res.status).toBe(400);
  });

  it("refuses a non-admin with 403 and an anonymous caller with 401", async () => {
    const fx = makeHttpFixture();
    const adminSid = fx.makeSession(fx.seedUser("admin@idp.test", { role: "admin" }));
    const clientId = await registerClient(fx, adminSid);
    const userSid = fx.makeSession(fx.seedUser("pleb@idp.test"));

    const forbidden = await fx.handler(
      patch(`/oauth2/clients/${clientId}`, { name: "x" }, userSid),
    );
    expect(forbidden.status).toBe(403);
    const anonymous = await fx.handler(patch(`/oauth2/clients/${clientId}`, { name: "x" }));
    expect(anonymous.status).toBe(401);
  });
});
