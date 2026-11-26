import { sha256Hex } from "./testing/Sha256.ts";
import { assert, describe, it, expect } from "vite-plus/test";
import { enrolledGate, testChallenge } from "./testing/SecondFactor.ts";
import { memoryApiKeyStore, memoryEmailPasswordStore } from "./testing/MemoryStores.ts";
import { ApiKeyStore } from "./ApiKey.ts";
import { DateTime, Effect, Exit, Layer, MutableHashMap, Result, Struct } from "effect";
import * as Arr from "effect/Array";
import * as Option from "effect/Option";
import * as P from "effect/Predicate";
import * as Schema from "effect/Schema";
import { AuthError, UserNotFoundError } from "./Errors.ts";
import { Hooks } from "./Hooks.ts";
import { testCryptoLayer } from "./testing/TestCrypto.ts";
import { SessionService } from "./SessionService.ts";
import { SessionStore } from "./SessionStore.ts";
import { UserStore } from "./UserStore.ts";
import { UserServiceStore, UserService } from "./User.ts";
import { AuthLifecycleService } from "./AuthLifecycle.ts";
import {
  EmailPasswordService,
  EmailPasswordStore,
  exemptFromSecondFactor,
  type SecondFactorGate,
} from "./email/EmailPassword.ts";
import { PasswordHasher } from "./password/Password.ts";
import { EmailVerificationService } from "./email/EmailVerification.ts";
import { PasswordResetService } from "./password/PasswordReset.ts";
import { type AuthServices } from "./http/HttpServer.ts";
import * as HttpServer from "./http/HttpServer.ts";
import {
  IdentifierStore,
  makeIdentifier,
  memoryIdentifierStore,
  type Identifier,
} from "./Identifier.ts";
import {
  memoryOrganizationDomainStore,
  OrganizationDomainStore,
  OrganizationService,
  OrganizationStore,
  type Member,
  type Organization,
  type OrganizationDomain,
  type SsoProvider,
} from "./index.ts";
import { type OAuthCreateUserInput, OAuthStateStore, OAuthUserStore } from "./oauth/OAuth.ts";
import { oauthStateStoreKV } from "./KeyValueStores.ts";
import { KeyValueStore } from "effect/persistence";
import { SsoProviderStore, SsoError, SsoService } from "./Sso.ts";
import * as Sso from "./Sso.ts";
import * as ManagedUser from "./ManagedUser.ts";
import {
  memorySamlReplayStore,
  SamlReplayStore,
  SamlVerifier,
  type SamlAssertion,
  type SamlAuthnRequestInput,
  type SamlReplayRecord,
} from "./Saml.ts";
import type * as Types from "./Types.ts";
import { expectSpecJson, mediaTypeOf } from "./testing/WireFormat.ts";
import { memorySessionStore } from "./testing/MemoryStores.ts";
import type { SessionTouch } from "./SessionStore.ts";
import { globalFetchHttpClient, runPromiseHttp } from "./testing/HttpClient.ts";

const encodeJson = Schema.encodeSync(Schema.fromJsonString(Schema.Unknown));

/** A JSON response body, decoded against the shape the test reads from it. */
const jsonBody = async <S extends Schema.ConstraintDecoder<unknown>>(
  response: Response,
  schema: S,
): Promise<S["Type"]> => Schema.decodeUnknownSync(schema)(await response.json());

// The response bodies several tests read.
/** An `sso-providers` resource: its id, and its attributes field by field. */
const ProviderDocument = Schema.Struct({
  data: Schema.Struct({ id: Schema.String, attributes: Schema.JsonObject }),
});

/** The `organization` relationship of a registered connection: its linkage, or `null`. */
const providerOrganization = async (response: Response) =>
  (
    await jsonBody(
      response,
      Schema.Struct({
        data: Schema.Struct({
          relationships: Schema.Struct({
            organization: Schema.Struct({
              data: Schema.NullOr(Schema.Struct({ type: Schema.String, id: Schema.String })),
            }),
          }),
        }),
      }),
    )
  ).data.relationships.organization.data;

/** A registered connection's attributes. */
const providerAttributes = async (response: Response) =>
  (await jsonBody(response, ProviderDocument)).data.attributes;

/** A registered connection's id. */
const providerIdOf = async (response: Response) =>
  (await jsonBody(response, ProviderDocument)).data.id;

/** The IdP URL and round-trip state a started sign-in (`sso-authorizations`) answers. */
const signInUrl = async (response: Response) => {
  const { data } = await jsonBody(
    response,
    Schema.Struct({
      data: Schema.Struct({ id: Schema.String, attributes: Schema.Struct({ url: Schema.String }) }),
    }),
  );
  return { url: data.attributes.url, state: data.id };
};

const UserEmailBody = Schema.Struct({ user: Schema.Struct({ email: Schema.String }) });

/** Swap `globalThis.fetch` for a route handler while `thunk` runs. */
const withFetch = <A>(
  routes: Readonly<Record<string, Schema.Json>>,
  thunk: () => Promise<A>,
): Promise<A> => {
  const original = globalThis.fetch;
  globalThis.fetch = (input) => {
    const url = P.isString(input) ? input : input instanceof URL ? input.href : input.url;
    const key = Struct.keys(routes).find((k) => url.startsWith(k));
    const body = key ? routes[key] : { error: "no route" };
    return Promise.resolve(
      new Response(encodeJson(body), { headers: { "content-type": "application/json" } }),
    );
  };
  return new Promise<A>((resolve) => resolve(thunk())).finally(() => {
    globalThis.fetch = original;
  });
};

/**
 * The real `KeyValueStore`-backed state store over its own in-memory map,
 * built once so every run of a test's layer shares it.
 */
const kvStateStore = (): typeof OAuthStateStore.Service =>
  Effect.runSync(oauthStateStoreKV.pipe(Effect.provide(KeyValueStore.layerMemory)));

const makeStores = (
  overrides: {
    readonly domainStore?: typeof OrganizationDomainStore.Service;
    /** Seed org-1's verified acme.test claim. Default `true`. */
    readonly claimAcme?: boolean;
  } = {},
) => {
  const providers = MutableHashMap.empty<string, SsoProvider>();
  const users = MutableHashMap.empty<string, Types.User>();
  const identifierRecords = MutableHashMap.empty<string, Identifier>();
  const identifiers = memoryIdentifierStore(identifierRecords);
  const members: Member[] = [];
  const organizations = MutableHashMap.empty<string, Organization>();
  const domainRecords = MutableHashMap.empty<string, OrganizationDomain>();
  const domainStore = overrides.domainStore ?? memoryOrganizationDomainStore(domainRecords);
  let userSeq = 0;
  /** The `identifier` each `createUser` call was given. */
  const createdWith: Array<OAuthCreateUserInput["identifier"]> = [];

  const ssoStore: typeof SsoProviderStore.Service = {
    create: (p) => Effect.sync(() => (MutableHashMap.set(providers, p.id, p), p)),
    getById: (id) => Effect.succeed(Option.getOrNull(MutableHashMap.get(providers, id))),
    getByDomain: (domain) =>
      Effect.succeed(
        Arr.fromIterable(MutableHashMap.values(providers)).find((p) => p.domain === domain) ?? null,
      ),
    list: () => Effect.succeed(Arr.fromIterable(MutableHashMap.values(providers))),
  };

  const userStore = {
    getUser: (userId: string) => {
      const u = Option.getOrUndefined(MutableHashMap.get(users, userId));
      return u ? Effect.succeed(u) : Effect.fail(new UserNotFoundError({ message: "nf", userId }));
    },
    createUser: (input: OAuthCreateUserInput) =>
      Effect.sync(() => {
        createdWith.push(input.identifier);
        const now = DateTime.toDateUtc(DateTime.nowUnsafe());
        const user: Types.User = {
          id: `u${++userSeq}`,
          ...(input.name !== undefined && { name: input.name }),
          ...(input.image !== undefined && { image: input.image }),
          createdAt: now,
          updatedAt: now,
          attributes: input.attributes ?? {},
        };
        MutableHashMap.set(users, user.id, user);
        return { user, created: true };
      }),
  };

  const coreUserStore: typeof UserStore.Service = {
    get: (userId) => Effect.sync(() => Option.getOrNull(MutableHashMap.get(users, userId))),
  };

  const stateStore = kvStateStore();

  const passwordHashes = MutableHashMap.empty<string, string>();
  const sessionsCleared: Array<string> = [];
  const sessionManager: typeof SessionService.Service = {
    createSession: (userId) =>
      Effect.succeed({
        session: {
          id: `s-${userId}`,
          userId,
          expiresAt: DateTime.toDateUtc(
            DateTime.add(DateTime.nowUnsafe(), { milliseconds: 3600_000 }),
          ),
          createdAt: DateTime.toDateUtc(DateTime.nowUnsafe()),
          lastActivityAt: DateTime.toDateUtc(DateTime.nowUnsafe()),
          attributes: {},
        },
        token: `token-${userId}`,
      }),
    validateSession: () => Effect.die("unused"),
    invalidateSession: () => Effect.die("unused"),
    invalidateUserSessions: (userId) => Effect.sync(() => void sessionsCleared.push(userId)),
    listSessions: () => Effect.succeed([]),
    revokeSessionById: () => Effect.succeed(false),
    revokeOtherSessions: () => Effect.void,
    setSessionAttributes: () => Effect.die("unused"),
  };

  const orgStore: typeof OrganizationStore.Service = {
    createMember: (m: Member) => Effect.sync(() => (members.push(m), m)),
    getMember: (organizationId: string, userId: string) =>
      Effect.succeed(
        members.find((m) => m.organizationId === organizationId && m.userId === userId) ?? null,
      ),
    getMemberById: (memberId: string) =>
      Effect.succeed(members.find((m) => m.id === memberId) ?? null),
    // Read for the organization's `defaultRole`, and by JIT provisioning:
    getOrganizationById: (organizationId: string) =>
      Effect.succeed(Option.getOrNull(MutableHashMap.get(organizations, organizationId))),
    countMembersByOrganization: (organizationId: string) =>
      Effect.succeed(members.filter((m) => m.organizationId === organizationId).length),
    // Unused by SSO:
    createOrganization: () => Effect.die("unused"),
    getOrganizationBySlug: () => Effect.die("unused"),
    updateOrganization: () => Effect.die("unused"),
    deleteOrganization: () => Effect.die("unused"),
    updateMember: () => Effect.die("unused"),
    deleteMember: () => Effect.die("unused"),
    listMembersByOrganization: () => Effect.die("unused"),
    listMembersByUser: () => Effect.die("unused"),
    createInvitation: () => Effect.die("unused"),
    getInvitation: () => Effect.die("unused"),
    updateInvitation: () => Effect.die("unused"),
    listInvitationsByOrganization: () => Effect.die("unused"),
    listInvitationsByEmail: () => Effect.die("unused"),
    createTeam: () => Effect.die("unused"),
    getTeam: () => Effect.die("unused"),
    updateTeam: () => Effect.die("unused"),
    deleteTeam: () => Effect.die("unused"),
    listTeams: () => Effect.die("unused"),
    addTeamMember: () => Effect.die("unused"),
    getTeamMemberById: () => Effect.die("unused"),
    removeTeamMember: () => Effect.die("unused"),
    listTeamMembers: () => Effect.die("unused"),
    listTeamsForMember: () => Effect.die("unused"),
    upsertOrgRole: () => Effect.die("unused"),
    getOrgRole: () => Effect.die("unused"),
    getOrgRoleById: () => Effect.die("unused"),
    listOrgRoles: () => Effect.die("unused"),
    deleteOrgRole: () => Effect.die("unused"),
  };

  const emailPasswords = memoryEmailPasswordStore({
    users: MutableHashMap.empty(),
    passwordHashes,
  });

  const layer = Layer.mergeAll(
    Layer.succeed(SsoProviderStore)(ssoStore),
    Layer.succeed(OAuthStateStore)(stateStore),
    Layer.succeed(OAuthUserStore)(userStore),
    Layer.succeed(IdentifierStore)(identifiers),
    Layer.succeed(UserStore)(coreUserStore),
    Layer.succeed(SessionService)(sessionManager),
    Layer.succeed(EmailPasswordStore)(emailPasswords),
    Layer.succeed(OrganizationStore)(orgStore),
    Layer.succeed(OrganizationDomainStore)(domainStore),
    // The organization service is what SSO asks for JIT membership; wiring it
    // here means every sign-in test walks that path (and finds nothing to do
    // unless the test claimed a domain).
    OrganizationService.layer().pipe(
      Layer.provide(
        Layer.mergeAll(
          Layer.succeed(OrganizationStore)(orgStore),
          Layer.succeed(IdentifierStore)(identifiers),
          Layer.succeed(OrganizationDomainStore)(domainStore),
          Layer.succeed(SessionService)(sessionManager),
          Layer.succeed(EmailPasswordStore)(emailPasswords),
          Layer.succeed(UserStore)(coreUserStore),
        ),
      ),
    ),
    Hooks.Default,
    testCryptoLayer,
  );

  /** Register an organization row, with whatever JIT settings a test needs. */
  const seedOrganization = (
    organizationId: string,
    overrides: Partial<Organization> = {},
  ): Organization => {
    const organization: Organization = {
      id: organizationId,
      name: organizationId,
      slug: organizationId,
      metadata: {},
      createdAt: DateTime.toEpochMillis(DateTime.nowUnsafe()),
      ...overrides,
    };
    MutableHashMap.set(organizations, organization.id, organization);
    return organization;
  };

  /** Claim `domain` for `organizationId`, in the given verification state. */
  const seedDomain = (
    organizationId: string,
    domain: string,
    verificationState: OrganizationDomain["verificationState"] = "verified",
  ): OrganizationDomain => {
    const record: OrganizationDomain = {
      id: `dom-${MutableHashMap.size(domainRecords) + 1}`,
      organizationId,
      domain,
      verificationState,
      verificationStrategy: "manual",
      createdAt: DateTime.toEpochMillis(DateTime.nowUnsafe()),
      ...(verificationState === "verified" && {
        verifiedAt: DateTime.toEpochMillis(DateTime.nowUnsafe()),
      }),
    };
    MutableHashMap.set(domainRecords, record.id, record);
    return record;
  };

  // The ACME connections' organization holds acme.test, so they manage its
  // addresses; the managed-user cases below claim nothing else.
  if (overrides.claimAcme !== false) seedDomain("org-1", "acme.test");

  return {
    layer,
    providers,
    users,
    identifiers,
    createdWith,
    members,
    organizations,
    seedOrganization,
    seedDomain,
    passwordHashes,
    sessionsCleared,
  };
};

const ACME = {
  issuer: "https://idp.acme.test",
  domain: "acme.test",
  clientId: "client-1",
  clientSecret: "secret-1",
  redirectUri: "https://app/api/auth/sso/callback",
  authorizationEndpoint: "https://idp.acme.test/authorize",
  tokenEndpoint: "https://idp.acme.test/token",
  userInfoEndpoint: "https://idp.acme.test/userinfo",
  organizationId: "org-1",
};

describe("SsoService", () => {
  it("registers a provider and routes sign-in by email domain", async () => {
    const { layer } = makeStores();
    const sso = await runPromiseHttp(Sso.make().pipe(Effect.provide(layer)));

    const result = await Effect.runPromise(
      Effect.gen(function* () {
        const provider = yield* sso.registerProvider("admin", ACME);
        const resolved = yield* sso.resolveProviderForEmail("worker@ACME.test");
        const start = yield* sso.signIn({ email: "worker@acme.test" });
        return { provider, resolved, start };
      }).pipe(Effect.provide(layer)),
    );

    expect(result.provider.domain).toBe("acme.test");
    expect(result.resolved?.id).toBe(result.provider.id);
    const url = new URL(result.start.url);
    expect(url.origin + url.pathname).toBe("https://idp.acme.test/authorize");
    expect(url.searchParams.get("client_id")).toBe("client-1");
    expect(url.searchParams.get("state")).toBe(result.start.state);
  });

  it("provisions a user + org membership on first login and reuses on the second", async () => {
    const { layer, users, identifiers, createdWith, members } = makeStores();
    const sso = await runPromiseHttp(
      Sso.make({ defaultRole: "member" }).pipe(Effect.provide(layer)),
    );

    const idpRoutes = {
      "https://idp.acme.test/token": { access_token: "at", token_type: "bearer" },
      "https://idp.acme.test/userinfo": {
        sub: "idp-user-9",
        email: "worker@acme.test",
        email_verified: true,
        name: "Worker Bee",
      },
    };

    const signInFlow = () =>
      Effect.gen(function* () {
        const start = yield* sso.signIn({ email: "worker@acme.test" });
        return yield* sso.handleCallback(start.state, "auth-code");
      }).pipe(Effect.provide(layer));

    // Register once.
    await Effect.runPromise(sso.registerProvider("admin", ACME).pipe(Effect.provide(layer)));

    // First login: creates the user and the org membership.
    const first = await withFetch(idpRoutes, () => Effect.runPromise(signInFlow()));
    expect(first.isNewUser).toBe(true);
    const emailIdentifier = await Effect.runPromise(
      identifiers.getByValue("email", "worker@acme.test"),
    );
    expect(emailIdentifier?.userId).toBe(first.user.id);
    expect(emailIdentifier?.verified).toBe(true);
    // The store was handed the address to create the user with.
    expect(createdWith).toEqual([
      { type: "email", value: "worker@acme.test", verified: true, verifiedAt: expect.any(Date) },
    ]);
    expect(first.session?.userId).toBe(first.user.id);
    expect(members).toEqual([
      { ...members[0], organizationId: "org-1", userId: first.user.id, role: "member" },
    ]);
    expect(MutableHashMap.size(users)).toBe(1);

    // Second login: reuses the same user, no duplicate membership.
    const second = await withFetch(idpRoutes, () => Effect.runPromise(signInFlow()));
    expect(second.isNewUser).toBe(false);
    expect(second.user.id).toBe(first.user.id);
    expect(MutableHashMap.size(users)).toBe(1);
    expect(members.length).toBe(1);
  });

  /**
   * The same IdP round trip as above, but with the connection carrying no
   * organization: any membership that appears came from JIT provisioning.
   */
  const jitFixture = (
    overrides: { readonly domainStore?: typeof OrganizationDomainStore.Service } = {},
  ) => {
    const { organizationId: _connectionOrganization, ...withoutOrganization } = ACME;
    // An organization-less connection is bound to its own domain, so no claim.
    const stores = makeStores({ ...overrides, claimAcme: false });
    const idpRoutes = {
      "https://idp.acme.test/token": { access_token: "at", token_type: "bearer" },
      "https://idp.acme.test/userinfo": {
        sub: "idp-user-42",
        email: "worker@acme.test",
        email_verified: true,
      },
    };
    /** Sign in through the IdP; `extra` adds stores beside the fixture's. */
    const signIn = async <ROut = never>(extra?: Layer.Layer<ROut>) => {
      const layer = extra === undefined ? stores.layer : Layer.merge(stores.layer, extra);
      const sso = await runPromiseHttp(Sso.make().pipe(Effect.provide(layer)));
      await Effect.runPromise(
        sso.registerProvider("admin", withoutOrganization).pipe(Effect.provide(layer)),
      );
      return withFetch(idpRoutes, () =>
        Effect.runPromise(
          Effect.gen(function* () {
            const start = yield* sso.signIn({ email: "worker@acme.test" });
            return yield* sso.handleCallback(start.state, "auth-code");
          }).pipe(Effect.provide(layer)),
        ),
      );
    };
    return { ...stores, signIn };
  };

  it("clears a squatter's password, sessions and credentials when the IdP proves the address", async () => {
    const fx = jitFixture();
    // A squatter signed up with the address and a password they know; it was
    // never verified.
    const now = DateTime.toDateUtc(DateTime.nowUnsafe());
    MutableHashMap.set(fx.users, "user-squat", {
      id: "user-squat",
      createdAt: now,
      updatedAt: now,
      attributes: {},
    });
    await Effect.runPromise(
      fx.identifiers.create(
        makeIdentifier({
          userId: "user-squat",
          type: "email",
          value: "worker@acme.test",
          now: DateTime.toDateUtc(DateTime.nowUnsafe()),
        }),
      ),
    );
    MutableHashMap.set(fx.passwordHashes, "user-squat", "squatter-hash");

    // The squatter also minted an API key, which the first proof removes.
    const apiKeys = memoryApiKeyStore();
    await Effect.runPromise(
      apiKeys.create({
        id: "squatter-key",
        start: "abcdef",
        keyHash: "squatter-key-hash",
        userId: "user-squat",
        enabled: true,
        metadata: {},
        createdAt: 0,
        updatedAt: 0,
      }),
    );

    const result = await fx.signIn(Layer.succeed(ApiKeyStore, apiKeys));

    expect(result.isNewUser).toBe(false);
    expect(result.user.id).toBe("user-squat");
    expect(MutableHashMap.has(fx.passwordHashes, "user-squat")).toBe(false);
    expect(fx.sessionsCleared).toEqual(["user-squat"]);
    const identifier = await Effect.runPromise(
      fx.identifiers.getByValue("email", "worker@acme.test"),
    );
    expect(await Effect.runPromise(apiKeys.listByUserId("user-squat"))).toEqual([]);
    expect(identifier?.verified).toBe(true);
  });

  it("provisions JIT membership from a verified domain when the organization opts in", async () => {
    const fx = jitFixture();
    fx.seedOrganization("org-jit", { jitProvisioning: true, defaultRole: "admin" });
    fx.seedDomain("org-jit", "acme.test");

    const result = await fx.signIn();

    expect(result.isNewUser).toBe(true);
    expect(fx.members).toEqual([
      {
        ...fx.members[0],
        organizationId: "org-jit",
        userId: result.user.id,
        role: "admin",
        status: "active",
      },
    ]);
  });

  it("leaves JIT alone by default, and for an unverified domain claim", async () => {
    const optedOut = jitFixture();
    optedOut.seedOrganization("org-jit", {});
    optedOut.seedDomain("org-jit", "acme.test");
    await optedOut.signIn();
    expect(optedOut.members).toEqual([]);

    const unverified = jitFixture();
    unverified.seedOrganization("org-jit", { jitProvisioning: true });
    unverified.seedDomain("org-jit", "acme.test", "pending");
    await unverified.signIn();
    expect(unverified.members).toEqual([]);
  });

  it("still signs the user in when JIT provisioning fails", async () => {
    const fx = jitFixture({
      domainStore: {
        ...memoryOrganizationDomainStore(),
        getVerifiedByDomain: () => Effect.fail(new AuthError({ message: "domain store is down" })),
      },
    });
    fx.seedOrganization("org-jit", { jitProvisioning: true });

    const result = await fx.signIn();

    expect(result.user.id).toBeTypeOf("string");
    expect(result.session?.userId).toBe(result.user.id);
    expect(fx.members).toEqual([]);
  });

  it("answers a second-factor challenge, and no session, when the gate requires one", async () => {
    const challenged: Array<string> = [];
    const fx = jitFixture();

    const gated = await fx.signIn(enrolledGate(challenged));

    expect(gated.secondFactor).toEqual(testChallenge);
    expect(gated.session).toBeUndefined();
    expect(challenged).toEqual([gated.user.id]);
  });

  it("issues a session past the gate when SSO is exempt from it", async () => {
    const challenged: Array<string> = [];
    const fx = jitFixture();

    const exempt = await fx.signIn(
      Layer.merge(enrolledGate(challenged), exemptFromSecondFactor("sso")),
    );

    expect(exempt.secondFactor).toBeUndefined();
    expect(exempt.session?.userId).toBe(exempt.user.id);
    expect(challenged).toEqual([]);
  });

  it("populates endpoints from OIDC discovery", async () => {
    const { layer, providers } = makeStores();
    const sso = await runPromiseHttp(Sso.make().pipe(Effect.provide(layer)));

    const discovered = await withFetch(
      {
        "https://idp.acme.test/.well-known/openid-configuration": {
          issuer: "https://idp.acme.test",
          authorization_endpoint: "https://idp.acme.test/auth",
          token_endpoint: "https://idp.acme.test/tok",
          userinfo_endpoint: "https://idp.acme.test/ui",
          jwks_uri: "https://idp.acme.test/jwks",
        },
      },
      () =>
        Effect.runPromise(
          sso
            .registerProvider("admin", {
              issuer: "https://idp.acme.test",
              domain: "acme.test",
              clientId: "c",
              clientSecret: "s",
              redirectUri: "https://app/cb",
              discover: true,
            })
            .pipe(Effect.provide(layer)),
        ),
    );

    expect(discovered.authorizationEndpoint).toBe("https://idp.acme.test/auth");
    expect(discovered.tokenEndpoint).toBe("https://idp.acme.test/tok");
    expect(discovered.userInfoEndpoint).toBe("https://idp.acme.test/ui");
    expect(MutableHashMap.size(providers)).toBe(1);
  });

  it("refuses to register a connection whose endpoints name a private or plain-http host", async () => {
    const { layer, providers } = makeStores();
    const sso = await runPromiseHttp(Sso.make().pipe(Effect.provide(layer)));
    const register = (overrides: {
      readonly tokenEndpoint?: string;
      readonly jwksEndpoint?: string;
    }) =>
      Effect.runPromise(
        sso.registerProvider("admin", { ...ACME, ...overrides }).pipe(
          Effect.flip,
          Effect.map((e) => e.message),
          Effect.provide(layer),
        ),
      );

    const refused = await Promise.all(
      [
        "http://idp.acme.test/token",
        "https://127.0.0.1/token",
        "https://169.254.169.254/latest/meta-data",
        "https://[::1]/token",
        "https://10.0.0.5/token",
        "https://localhost/token",
        "https://idp.internal/token",
        "https://intranet/token",
        "https://user:pw@idp.acme.test/token",
      ].map((tokenEndpoint) => register({ tokenEndpoint })),
    );
    expect(refused).toHaveLength(9);
    expect(refused.filter((message) => !message.startsWith("IdP URL"))).toEqual([]);
    expect(await register({ jwksEndpoint: "https://192.168.1.1/jwks" })).toMatch(/^IdP URL/);
    expect(MutableHashMap.size(providers)).toBe(0);
  });

  it("checks discovery and the URLs it names before fetching them", async () => {
    const { layer, providers } = makeStores();
    const sso = await runPromiseHttp(Sso.make().pipe(Effect.provide(layer)));
    const requested: Array<string> = [];
    const original = globalThis.fetch;
    globalThis.fetch = (input) => {
      requested.push(P.isString(input) ? input : input instanceof URL ? input.href : input.url);
      return Promise.resolve(
        Response.json({
          issuer: "https://idp.acme.test",
          authorization_endpoint: "https://idp.acme.test/auth",
          token_endpoint: "https://10.1.2.3/token",
        }),
      );
    };
    const attempts = (async () => {
      const privateIssuer = await Effect.runPromiseExit(
        sso
          .registerProvider("admin", { ...ACME, issuer: "https://10.0.0.1", discover: true })
          .pipe(Effect.provide(layer)),
      );
      expect(Exit.isFailure(privateIssuer)).toBe(true);
      expect(requested).toEqual([]);

      const privateToken = await Effect.runPromiseExit(
        sso
          .registerProvider("admin", {
            issuer: ACME.issuer,
            domain: ACME.domain,
            clientId: ACME.clientId,
            clientSecret: ACME.clientSecret,
            redirectUri: ACME.redirectUri,
            discover: true,
          })
          .pipe(Effect.provide(layer)),
      );
      expect(Exit.isFailure(privateToken)).toBe(true);
      expect(MutableHashMap.size(providers)).toBe(0);
    })();
    await attempts.finally(() => {
      globalThis.fetch = original;
    });
  });

  it("accepts a private IdP with allowPrivateIdpUrls", async () => {
    const { layer, providers } = makeStores();
    const sso = await runPromiseHttp(
      Sso.make({ allowPrivateIdpUrls: true }).pipe(Effect.provide(layer)),
    );
    await Effect.runPromise(
      sso
        .registerProvider("admin", {
          ...ACME,
          tokenEndpoint: "http://10.0.0.5:8080/token",
          userInfoEndpoint: "http://localhost:8080/userinfo",
        })
        .pipe(Effect.provide(layer)),
    );
    expect(MutableHashMap.size(providers)).toBe(1);
  });

  it("fails sign-in for an unknown domain", async () => {
    const { layer } = makeStores();
    const sso = await runPromiseHttp(Sso.make().pipe(Effect.provide(layer)));
    const err = await Effect.runPromise(
      Effect.flip(sso.signIn({ email: "nobody@unknown.test" })).pipe(Effect.provide(layer)),
    );
    expect(err).toBeInstanceOf(SsoError);
  });

  it("rejects a callback whose profile email is unverified", async () => {
    const { layer } = makeStores();
    const sso = await runPromiseHttp(Sso.make().pipe(Effect.provide(layer)));
    await Effect.runPromise(sso.registerProvider("admin", ACME).pipe(Effect.provide(layer)));

    const err = await withFetch(
      {
        "https://idp.acme.test/token": { access_token: "at", token_type: "bearer" },
        "https://idp.acme.test/userinfo": {
          sub: "x",
          email: "worker@acme.test",
          email_verified: false,
        },
      },
      () =>
        Effect.runPromise(
          Effect.gen(function* () {
            const start = yield* sso.signIn({ email: "worker@acme.test" });
            return yield* Effect.flip(sso.handleCallback(start.state, "code"));
          }).pipe(Effect.provide(layer)),
        ),
    );
    expect(err).toBeInstanceOf(SsoError);
  });
});

// --- SAML --------------------------------------------------------------------
//
// The crypto lives in `@thomasfosterau/effect-auth/saml` and is exercised
// there, against hand-built XML fixtures. These tests are about the half core
// owns: protocol routing, one-time use of the AuthnRequest and the assertion,
// issuer pinning, and the fact that both protocols end in the *same*
// provisioning tail. So the verifier is stubbed, and the stub's "SAMLResponse"
// is just a JSON assertion — which lets each test state the exact assertion an
// IdP is pretending to send.

const SAML_IDP = "https://idp.acme.test/metadata";
const SAML_SP = "https://app.test/saml/metadata";
const SAML_ACS = "https://app.test/api/auth/sso/saml/acs";

const ACME_SAML = {
  protocol: "saml",
  domain: "acme.test",
  entityId: SAML_IDP,
  ssoUrl: "https://idp.acme.test/sso",
  idpCertificates: ["-----BEGIN CERTIFICATE-----\nZmFrZQ==\n-----END CERTIFICATE-----"],
  spEntityId: SAML_SP,
  acsUrl: SAML_ACS,
  organizationId: "org-1",
} as const satisfies Sso.RegisterSamlProviderInput;

/** Encode the assertion the stub verifier should "find" in this response. */
const samlResponse = (assertion: Partial<SamlAssertion>): string =>
  Buffer.from(encodeJson(assertion), "utf8").toString("base64");

/** The {@link SamlAssertion} fields a test overrides, read back out of the body. */
const decodeAssertionOverrides = Schema.decodeUnknownSync(
  Schema.fromJsonString(
    Schema.Struct({
      id: Schema.optionalKey(Schema.String),
      issuer: Schema.optionalKey(Schema.String),
      nameId: Schema.optionalKey(Schema.String),
      nameIdFormat: Schema.optionalKey(Schema.String),
      email: Schema.optionalKey(Schema.String),
      displayName: Schema.optionalKey(Schema.String),
      attributes: Schema.optionalKey(
        Schema.Record(Schema.String, Schema.Union([Schema.String, Schema.Array(Schema.String)])),
      ),
      sessionIndex: Schema.optionalKey(Schema.String),
      inResponseTo: Schema.optionalKey(Schema.String),
      notOnOrAfter: Schema.optionalKey(Schema.Number),
      relayState: Schema.optionalKey(Schema.String),
    }),
  ),
);

/**
 * A stub {@link SamlVerifier} standing in for the XML/crypto implementation:
 * it "signs" nothing and reads the assertion straight out of the base64 body,
 * recording every `AuthnRequest` it is asked to build so a test can find the
 * request id core minted.
 */
const stubSamlVerifier = (requests: SamlAuthnRequestInput[]): typeof SamlVerifier.Service => ({
  buildAuthnRequest: (input) => {
    requests.push(input);
    const url = new URL(input.ssoUrl);
    url.searchParams.set("SAMLRequest", `stub:${input.requestId}`);
    if (input.relayState !== undefined) url.searchParams.set("RelayState", input.relayState);
    return Effect.succeed({ url: url.toString(), requestId: input.requestId });
  },
  verify: (input) =>
    Effect.sync(() => {
      const decoded = Buffer.from(input.samlResponse, "base64").toString("utf8");
      const overrides = decodeAssertionOverrides(decoded);
      return {
        id: "_assertion-1",
        issuer: input.idpEntityId,
        nameId: "worker@acme.test",
        nameIdFormat: "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
        email: "worker@acme.test",
        displayName: "Worker Bee",
        attributes: {},
        ...overrides,
      } satisfies SamlAssertion;
    }),
  spMetadataXml: (input) => Effect.succeed(`<EntityDescriptor entityID="${input.spEntityId}"/>`),
});

const makeSamlFixture = () => {
  const base = makeStores();
  const replayRecords = MutableHashMap.empty<string, SamlReplayRecord>();
  const replay = memorySamlReplayStore(replayRecords);
  const requests: SamlAuthnRequestInput[] = [];

  const layer = Layer.mergeAll(
    base.layer,
    Layer.succeed(SamlVerifier)(stubSamlVerifier(requests)),
    Layer.succeed(SamlReplayStore)(replay),
  );

  return { ...base, layer, replay, replayRecords, requests };
};

describe("SsoService — SAML", () => {
  it("starts a SAML sign-in and records the request id one-time", async () => {
    const fx = makeSamlFixture();
    const sso = await runPromiseHttp(Sso.make().pipe(Effect.provide(fx.layer)));

    const { provider, start } = await Effect.runPromise(
      Effect.gen(function* () {
        const provider = yield* sso.registerSamlProvider("admin", ACME_SAML);
        const start = yield* sso.signIn({ email: "worker@ACME.test" });
        return { provider, start };
      }).pipe(Effect.provide(fx.layer)),
    );

    expect(provider.protocol).toBe("saml");
    expect(provider.idpCertificates).toEqual(ACME_SAML.idpCertificates);

    const url = new URL(start.url);
    expect(url.origin + url.pathname).toBe("https://idp.acme.test/sso");
    expect(url.searchParams.get("RelayState")).toBe(start.state);

    // The request id was minted by core and handed to the verifier, then
    // banked so the response can be matched against it exactly once.
    const requestId = fx.requests[0]?.requestId ?? "";
    expect(requestId).toMatch(/^_[0-9a-f]{32}$/);
    const banked = await Effect.runPromise(fx.replay.consume(requestId));
    expect(banked?.kind).toBe("authn-request");
    expect(banked?.relayState).toBe(start.state);
    expect(await Effect.runPromise(fx.replay.consume(requestId))).toBeNull();
  });

  it("provisions through the same tail as OIDC, then reuses the user", async () => {
    const fx = makeSamlFixture();
    const sso = await runPromiseHttp(Sso.make().pipe(Effect.provide(fx.layer)));

    const signIn = (assertionId: string) =>
      Effect.gen(function* () {
        const start = yield* sso.signIn({ email: "worker@acme.test" });
        const requestId = fx.requests[fx.requests.length - 1]?.requestId ?? "";
        return yield* sso.handleSamlCallback(
          providerId,
          samlResponse({ id: assertionId, inResponseTo: requestId }),
          start.state,
        );
      }).pipe(Effect.provide(fx.layer));

    const providerId = (
      await Effect.runPromise(
        sso.registerSamlProvider("admin", ACME_SAML).pipe(Effect.provide(fx.layer)),
      )
    ).id;

    const first = await Effect.runPromise(signIn("_a1"));
    expect(first.isNewUser).toBe(true);
    expect(first.provider.protocol).toBe("saml");
    expect(first.session?.userId).toBe(first.user.id);
    const identifier = await Effect.runPromise(
      fx.identifiers.getByValue("email", "worker@acme.test"),
    );
    expect(identifier?.userId).toBe(first.user.id);
    // The IdP attested the address inside a signed assertion, exactly as an
    // OIDC `email_verified` claim would.
    expect(identifier?.verified).toBe(true);
    expect(fx.members).toEqual([
      { ...fx.members[0], organizationId: "org-1", userId: first.user.id, role: "member" },
    ]);

    const second = await Effect.runPromise(signIn("_a2"));
    expect(second.isNewUser).toBe(false);
    expect(second.user.id).toBe(first.user.id);
    expect(MutableHashMap.size(fx.users)).toBe(1);
    expect(fx.members.length).toBe(1);
  });

  it("refuses to spend the same assertion twice", async () => {
    const fx = makeSamlFixture();
    const sso = await runPromiseHttp(Sso.make().pipe(Effect.provide(fx.layer)));

    const outcome = await Effect.runPromise(
      Effect.gen(function* () {
        const provider = yield* sso.registerSamlProvider("admin", ACME_SAML);
        const first = yield* sso.signIn({ email: "worker@acme.test" });
        const firstId = fx.requests[0]?.requestId ?? "";
        const response = samlResponse({ id: "_replayed", inResponseTo: firstId });
        const ok = yield* sso.handleSamlCallback(provider.id, response, first.state);

        // A captured response, replayed against a *fresh* request so the
        // AuthnRequest check cannot be what stops it.
        const second = yield* sso.signIn({ email: "worker@acme.test" });
        const secondId = fx.requests[1]?.requestId ?? "";
        const replayed = samlResponse({ id: "_replayed", inResponseTo: secondId });
        const err = yield* Effect.flip(sso.handleSamlCallback(provider.id, replayed, second.state));
        return { ok, err };
      }).pipe(Effect.provide(fx.layer)),
    );

    expect(outcome.ok.isNewUser).toBe(true);
    assert.instanceOf(outcome.err, SsoError);
    expect(outcome.err.message).toMatch(/already been used/);
  });

  it("remembers a spent assertion for as long as the clock skew still admits it", async () => {
    const fx = makeSamlFixture();
    const skew = 3 * 60 * 1000;
    const sso = await runPromiseHttp(
      Sso.make({ samlClockSkewMs: skew }).pipe(Effect.provide(fx.layer)),
    );

    // `NotOnOrAfter` has just passed, but within the skew the verifier still
    // accepts the assertion, so its record must outlive it by the skew too.
    const notOnOrAfter = DateTime.toEpochMillis(DateTime.nowUnsafe()) - 1000;
    const outcome = await Effect.runPromise(
      Effect.gen(function* () {
        const provider = yield* sso.registerSamlProvider("admin", ACME_SAML);
        const answer = (index: number) =>
          Effect.gen(function* () {
            const start = yield* sso.signIn({ email: "worker@acme.test" });
            const requestId = fx.requests[index]?.requestId ?? "";
            return yield* sso.handleSamlCallback(
              provider.id,
              samlResponse({ id: "_skewed", inResponseTo: requestId, notOnOrAfter }),
              start.state,
            );
          });
        const first = yield* answer(0);
        // The captured response, replayed against a fresh request inside the skew.
        const replayed = yield* Effect.flip(answer(1));
        return { first, replayed };
      }).pipe(Effect.provide(fx.layer)),
    );

    expect(outcome.first.isNewUser).toBe(true);
    assert.instanceOf(outcome.replayed, SsoError);
    expect(outcome.replayed.message).toMatch(/already been used/);
    const record = Option.getOrUndefined(MutableHashMap.get(fx.replayRecords, "_skewed"));
    expect(record?.expiresAt).toBe(notOnOrAfter + skew);
  });

  it("rejects a response answering an unknown or already-spent request", async () => {
    const fx = makeSamlFixture();
    const sso = await runPromiseHttp(Sso.make().pipe(Effect.provide(fx.layer)));

    const err = await Effect.runPromise(
      Effect.gen(function* () {
        const provider = yield* sso.registerSamlProvider("admin", ACME_SAML);
        const start = yield* sso.signIn({ email: "worker@acme.test" });
        return yield* Effect.flip(
          sso.handleSamlCallback(
            provider.id,
            samlResponse({ inResponseTo: "_never-issued" }),
            start.state,
          ),
        );
      }).pipe(Effect.provide(fx.layer)),
    );
    assert.instanceOf(err, SsoError);
    expect(err.message).toMatch(/unknown, expired, or already-used/);
  });

  it("rejects an assertion from a foreign issuer", async () => {
    const fx = makeSamlFixture();
    const sso = await runPromiseHttp(Sso.make().pipe(Effect.provide(fx.layer)));

    const err = await Effect.runPromise(
      Effect.gen(function* () {
        const provider = yield* sso.registerSamlProvider("admin", ACME_SAML);
        const start = yield* sso.signIn({ email: "worker@acme.test" });
        const requestId = fx.requests[0]?.requestId ?? "";
        return yield* Effect.flip(
          sso.handleSamlCallback(
            provider.id,
            samlResponse({ issuer: "https://evil.test/metadata", inResponseTo: requestId }),
            start.state,
          ),
        );
      }).pipe(Effect.provide(fx.layer)),
    );
    assert.instanceOf(err, SsoError);
    expect(err.message).toMatch(/does not match this connection/);
  });

  it("rejects a RelayState that does not match the one it minted", async () => {
    const fx = makeSamlFixture();
    const sso = await runPromiseHttp(Sso.make().pipe(Effect.provide(fx.layer)));

    const err = await Effect.runPromise(
      Effect.gen(function* () {
        const provider = yield* sso.registerSamlProvider("admin", ACME_SAML);
        yield* sso.signIn({ email: "worker@acme.test" });
        const requestId = fx.requests[0]?.requestId ?? "";
        return yield* Effect.flip(
          sso.handleSamlCallback(
            provider.id,
            samlResponse({ inResponseTo: requestId }),
            "not-the-relay-state",
          ),
        );
      }).pipe(Effect.provide(fx.layer)),
    );
    assert.instanceOf(err, SsoError);
    expect(err.message).toMatch(/RelayState/);
  });

  it("refuses an unsolicited (IdP-initiated) response unless configured for it", async () => {
    const fx = makeSamlFixture();
    const strict = await runPromiseHttp(Sso.make().pipe(Effect.provide(fx.layer)));
    const permissive = await runPromiseHttp(
      Sso.make({ allowIdpInitiated: true }).pipe(Effect.provide(fx.layer)),
    );

    const providerId = (
      await Effect.runPromise(
        strict.registerSamlProvider("admin", ACME_SAML).pipe(Effect.provide(fx.layer)),
      )
    ).id;

    const err = await Effect.runPromise(
      Effect.flip(strict.handleSamlCallback(providerId, samlResponse({ id: "_u1" }))).pipe(
        Effect.provide(fx.layer),
      ),
    );
    assert.instanceOf(err, SsoError);
    expect(err.message).toMatch(/IdP-initiated/);

    const ok = await Effect.runPromise(
      permissive
        .handleSamlCallback(providerId, samlResponse({ id: "_u2" }))
        .pipe(Effect.provide(fx.layer)),
    );
    expect(ok.isNewUser).toBe(true);
  });

  it("binds an SP-initiated response to the browser that started it", async () => {
    const fx = makeSamlFixture();
    const sso = await runPromiseHttp(
      Sso.make({ allowIdpInitiated: true }).pipe(Effect.provide(fx.layer)),
    );
    const providerId = (
      await Effect.runPromise(
        sso.registerSamlProvider("admin", ACME_SAML).pipe(Effect.provide(fx.layer)),
      )
    ).id;

    /** Start a sign-in, then post its response from a browser holding `browserState`. */
    const answer = (assertionId: string, browserState: (state: string) => string | undefined) =>
      Effect.gen(function* () {
        const start = yield* sso.signIn({ email: "worker@acme.test" });
        const requestId = fx.requests[fx.requests.length - 1]?.requestId ?? "";
        return yield* sso.handleSamlCallback(
          providerId,
          samlResponse({ id: assertionId, inResponseTo: requestId }),
          start.state,
          { browserState: browserState(start.state) },
        );
      }).pipe(Effect.provide(fx.layer));

    // The attacker started the sign-in; the victim's browser holds no state,
    // or the state of a sign-in of its own.
    const none = await Effect.runPromise(Effect.flip(answer("_b1", () => undefined)));
    assert.instanceOf(none, SsoError);
    expect(none.message).toMatch(/did not start/);
    const other = await Effect.runPromise(Effect.flip(answer("_b2", () => "another-state")));
    assert.instanceOf(other, SsoError);
    expect(other.message).toMatch(/did not start/);

    const ok = await Effect.runPromise(answer("_b3", (state) => state));
    expect(ok.user.id).toBeDefined();

    // An IdP-initiated response answers no request, so no browser holds a
    // state for it: `allowIdpInitiated` alone decides.
    const unsolicited = await Effect.runPromise(
      sso
        .handleSamlCallback(providerId, samlResponse({ id: "_b4" }), undefined, {
          browserState: undefined,
        })
        .pipe(Effect.provide(fx.layer)),
    );
    expect(unsolicited.user.id).toBe(ok.user.id);
  });

  it("keeps the two protocols' callbacks apart", async () => {
    const fx = makeSamlFixture();
    const sso = await runPromiseHttp(Sso.make().pipe(Effect.provide(fx.layer)));

    const errors = await Effect.runPromise(
      Effect.gen(function* () {
        const oidc = yield* sso.registerProvider("admin", { ...ACME, domain: "oidc.test" });
        const wrongProtocol = yield* Effect.flip(sso.handleSamlCallback(oidc.id, samlResponse({})));
        const unknown = yield* Effect.flip(sso.handleSamlCallback("nope", samlResponse({})));
        return { wrongProtocol, unknown };
      }).pipe(Effect.provide(fx.layer)),
    );

    assert.instanceOf(errors.wrongProtocol, SsoError);
    expect(errors.wrongProtocol.message).toMatch(/is an OIDC connection/);
    assert.instanceOf(errors.unknown, SsoError);
    expect(errors.unknown.message).toMatch(/not found/);
  });

  it("reports missing SAML support instead of half-working", async () => {
    // No SamlVerifier / SamlReplayStore in context: the OIDC half still works,
    // and the SAML half says exactly what is missing.
    const { layer } = makeStores();
    const sso = await runPromiseHttp(Sso.make().pipe(Effect.provide(layer)));

    const err = await Effect.runPromise(
      Effect.gen(function* () {
        const provider = yield* sso.registerSamlProvider("admin", ACME_SAML);
        return yield* Effect.flip(sso.signIn({ providerId: provider.id }));
      }).pipe(Effect.provide(layer)),
    );
    assert.instanceOf(err, SsoError);
    expect(err.message).toMatch(/SAML support is not installed/);
  });

  it("validates a SAML registration before storing it", async () => {
    const fx = makeSamlFixture();
    const sso = await runPromiseHttp(Sso.make().pipe(Effect.provide(fx.layer)));

    const errors = await Effect.runPromise(
      Effect.gen(function* () {
        const noCerts = yield* Effect.flip(
          sso.registerSamlProvider("admin", { ...ACME_SAML, idpCertificates: [] }),
        );
        const badUrl = yield* Effect.flip(
          sso.registerSamlProvider("admin", { ...ACME_SAML, acsUrl: "/relative" }),
        );
        return { noCerts, badUrl };
      }).pipe(Effect.provide(fx.layer)),
    );

    assert.instanceOf(errors.noCerts, SsoError);
    expect(errors.noCerts.message).toMatch(/idpCertificates must not be empty/);
    assert.instanceOf(errors.badUrl, SsoError);
    expect(errors.badUrl.message).toMatch(/acsUrl must be an absolute URL/);
    expect(MutableHashMap.size(fx.providers)).toBe(0);
  });

  it("renders SP metadata for a connection", async () => {
    const fx = makeSamlFixture();
    const sso = await runPromiseHttp(Sso.make().pipe(Effect.provide(fx.layer)));

    const xml = await Effect.runPromise(
      Effect.gen(function* () {
        const provider = yield* sso.registerSamlProvider("admin", ACME_SAML);
        return yield* sso.samlMetadata(provider.id);
      }).pipe(Effect.provide(fx.layer)),
    );
    expect(xml).toContain(SAML_SP);
  });
});

describe("memorySamlReplayStore", () => {
  const record = (id: string, expiresAt: number): SamlReplayRecord => ({
    id,
    kind: "assertion",
    providerId: "p1",
    createdAt: DateTime.toEpochMillis(DateTime.nowUnsafe()),
    expiresAt,
  });

  it("inserts if absent and reports a duplicate as null", async () => {
    const store = memorySamlReplayStore();
    expect(
      await Effect.runPromise(
        store.create(record("a", DateTime.toEpochMillis(DateTime.nowUnsafe()) + 60_000)),
      ),
    ).not.toBeNull();
    expect(
      await Effect.runPromise(
        store.create(record("a", DateTime.toEpochMillis(DateTime.nowUnsafe()) + 60_000)),
      ),
    ).toBeNull();
  });

  it("lets an expired id be re-used, since the window it guarded has passed", async () => {
    const store = memorySamlReplayStore();
    await Effect.runPromise(
      store.create(record("a", DateTime.toEpochMillis(DateTime.nowUnsafe()) - 1)),
    );
    expect(
      await Effect.runPromise(
        store.create(record("a", DateTime.toEpochMillis(DateTime.nowUnsafe()) + 60_000)),
      ),
    ).not.toBeNull();
  });

  it("consumes exactly once, and treats an expired record as absent", async () => {
    const store = memorySamlReplayStore();
    await Effect.runPromise(
      store.create(record("a", DateTime.toEpochMillis(DateTime.nowUnsafe()) + 60_000)),
    );
    expect(await Effect.runPromise(store.consume("a"))).not.toBeNull();
    expect(await Effect.runPromise(store.consume("a"))).toBeNull();

    await Effect.runPromise(
      store.create(record("b", DateTime.toEpochMillis(DateTime.nowUnsafe()) - 1)),
    );
    expect(await Effect.runPromise(store.consume("b"))).toBeNull();
    expect(await Effect.runPromise(store.consume("missing"))).toBeNull();
  });
});

// --- HTTP layer --------------------------------------------------------------

/** A web handler wired with the SSO endpoints over in-memory stores. */
const makeHttpFixture = (
  options: {
    readonly sso?: HttpServer.SsoRedirectConfig;
    readonly gate?: Layer.Layer<SecondFactorGate>;
  } = {},
) => {
  const usersById = MutableHashMap.empty<string, Types.User>();
  const identifierRecords = MutableHashMap.empty<string, Identifier>();
  const identifierStore = memoryIdentifierStore(identifierRecords);
  const sessions = MutableHashMap.empty<string, Types.Session>();
  const providers = MutableHashMap.empty<string, SsoProvider>();
  const members: Member[] = [];
  let userSeq = 0;

  const seedUser = (email: string, attributes: Types.Attributes = {}): string => {
    const id = `u${++userSeq}`;
    const now = DateTime.toDateUtc(DateTime.nowUnsafe());
    const user: Types.User = {
      id,
      createdAt: now,
      updatedAt: now,
      attributes,
    };
    MutableHashMap.set(usersById, id, user);
    const identifier = makeIdentifier({
      userId: id,
      type: "email",
      value: email,
      verified: true,
      verifiedAt: now,
      now,
    });
    MutableHashMap.set(identifierRecords, identifier.id, identifier);
    return id;
  };
  const makeSession = (userId: string): string => {
    const rawToken = Buffer.from(globalThis.crypto.getRandomValues(new Uint8Array(12))).toString(
      "hex",
    );
    const tokenHash = sha256Hex(rawToken);
    const now = DateTime.toDateUtc(DateTime.nowUnsafe());
    MutableHashMap.set(sessions, tokenHash, {
      id: tokenHash,
      userId,
      expiresAt: DateTime.toDateUtc(DateTime.add(DateTime.nowUnsafe(), { milliseconds: 3600_000 })),
      createdAt: now,
      lastActivityAt: now,
      attributes: {},
    });
    return rawToken;
  };

  const userStore = {
    get: (userId: string) =>
      Effect.sync(() => Option.getOrNull(MutableHashMap.get(usersById, userId))),
  };
  const userServiceStore = {
    get: userStore.get,
    update: (user: Types.User) =>
      Effect.sync(() => (MutableHashMap.set(usersById, user.id, user), user)),
    delete: () => Effect.void,
  };
  const sessionStore: typeof SessionStore.Service = {
    create: (s: Types.Session) => Effect.sync(() => (MutableHashMap.set(sessions, s.id, s), s)),
    get: (id: string) => Effect.sync(() => Option.getOrNull(MutableHashMap.get(sessions, id))),
    update: (s: Types.Session) => Effect.sync(() => (MutableHashMap.set(sessions, s.id, s), s)),
    touch: (sessionId: string, touch: SessionTouch) =>
      memorySessionStore(sessions).touch(sessionId, touch),
    delete: (id: string) => Effect.sync(() => void MutableHashMap.remove(sessions, id)),
    deleteByUserId: (userId: string) =>
      Effect.sync(() => {
        MutableHashMap.forEach(sessions, (s, id) => {
          if (s.userId === userId) MutableHashMap.remove(sessions, id);
        });
      }),
    listByUserId: (userId: string) =>
      Effect.sync(() =>
        Arr.fromIterable(MutableHashMap.values(sessions)).filter((s) => s.userId === userId),
      ),
  };
  const oauthUserStore = {
    getUser: (userId: string) => {
      const u = Option.getOrUndefined(MutableHashMap.get(usersById, userId));
      return u ? Effect.succeed(u) : Effect.fail(new UserNotFoundError({ message: "nf", userId }));
    },
    createUser: (input: { name?: string; image?: string }) =>
      Effect.sync(() => {
        const id = `u${++userSeq}`;
        const now = DateTime.toDateUtc(DateTime.nowUnsafe());
        const user: Types.User = {
          id,
          ...(input.name !== undefined && { name: input.name }),
          ...(input.image !== undefined && { image: input.image }),
          createdAt: now,
          updatedAt: now,
          attributes: {},
        };
        MutableHashMap.set(usersById, id, user);
        return { user, created: true };
      }),
  };
  const ssoStore: typeof SsoProviderStore.Service = {
    create: (p) => Effect.sync(() => (MutableHashMap.set(providers, p.id, p), p)),
    getById: (id) => Effect.succeed(Option.getOrNull(MutableHashMap.get(providers, id))),
    getByDomain: (domain) =>
      Effect.succeed(
        Arr.fromIterable(MutableHashMap.values(providers)).find((p) => p.domain === domain) ?? null,
      ),
    list: () => Effect.succeed(Arr.fromIterable(MutableHashMap.values(providers))),
  };
  const stateStore = kvStateStore();
  // SSO only ever calls getMember/createMember plus the organization read that
  // resolves the default role.
  const orgStore = {
    createMember: (m: Member) => Effect.sync(() => (members.push(m), m)),
    getMember: (organizationId: string, userId: string) =>
      Effect.succeed(
        members.find((m) => m.organizationId === organizationId && m.userId === userId) ?? null,
      ),
    getMemberById: (memberId: string) =>
      Effect.succeed(members.find((m) => m.id === memberId) ?? null),
    getOrganizationById: () => Effect.succeed(null),
  };

  const coreStoreLayer = Layer.mergeAll(
    Layer.succeed(SessionStore)(sessionStore),
    Layer.succeed(UserStore)(userStore),
  );

  const sessionServiceLayer = SessionService.layer({
    sessionExpiresIn: { activePeriod: 3600_000, idlePeriod: 3600_000 },
  }).pipe(Layer.provide(Layer.mergeAll(coreStoreLayer, Hooks.Default)));

  // SAFETY: the `undefined` services below complete `AuthServices` for
  // `HttpServer.make`; no SSO route these tests drive calls them.
  const base = Layer.mergeAll(
    sessionServiceLayer,
    UserService.layer().pipe(Layer.provide(Layer.succeed(UserServiceStore)(userServiceStore))),
    Layer.succeed(UserServiceStore)(userServiceStore),
    Layer.succeed(IdentifierStore)(identifierStore),
    Layer.succeed(EmailPasswordStore)(memoryEmailPasswordStore()),
    Hooks.Default,
    Layer.succeed(AuthLifecycleService)(undefined as never),
    Layer.succeed(EmailPasswordService)(undefined as never),
    Layer.succeed(PasswordHasher)(undefined as never),
    Layer.succeed(EmailVerificationService)(undefined as never),
    Layer.succeed(PasswordResetService)(undefined as never),
  );

  // `SsoService` only needs `SsoProviderStore` to construct; `OAuthStateStore`/
  // `OAuthUserStore`/`IdentifierStore`/`UserStore`/`SessionService`/
  // `SecureRandom.SecureRandom` are required dynamically by its `signIn`/`handleCallback`
  // methods, and `OrganizationStore` is resolved optionally at call time — all
  // are provided here as ambient context.
  // SAML is resolved optionally by `SsoService`, so the HTTP fixture installs
  // the same stub verifier the service-level tests use plus an in-memory
  // replay store — that is exactly what an app installing
  // `@thomasfosterau/effect-auth/saml` would provide.
  const samlRequests: SamlAuthnRequestInput[] = [];
  const ssoDeps = Layer.mergeAll(
    Layer.succeed(SsoProviderStore)(ssoStore),
    Layer.succeed(OAuthStateStore)(stateStore),
    Layer.succeed(OAuthUserStore)(oauthUserStore),
    Layer.succeed(IdentifierStore)(identifierStore),
    Layer.succeed(UserStore)(userStore),
    // SAFETY: SSO only ever calls the three `orgStore` methods; the HTTP flows
    // these tests drive reach no other `OrganizationStore` method.
    Layer.succeed(OrganizationStore)(orgStore as never),
    Layer.succeed(SamlVerifier)(stubSamlVerifier(samlRequests)),
    Layer.succeed(SamlReplayStore)(memorySamlReplayStore()),
    testCryptoLayer,
    options.gate ?? Layer.empty,
  );

  const ssoServiceLayer = SsoService.layer().pipe(Layer.provide([ssoDeps, globalFetchHttpClient]));

  const ssoLayer = Layer.mergeAll(ssoDeps, ssoServiceLayer);

  const withSso: Layer.Layer<AuthServices> = Layer.mergeAll(base, ssoLayer);
  const withoutSso: Layer.Layer<AuthServices> = base;

  return {
    seedUser,
    makeSession,
    handler: HttpServer.make({
      services: withSso,
      cookie: { secure: false },
      ipRateLimit: false,
      ...(options.sso !== undefined && { sso: options.sso }),
    }).handler,
    handlerWithoutSso: HttpServer.make({
      services: withoutSso,
      cookie: { secure: false },
      ipRateLimit: false,
    }).handler,
    providers,
    identifierRecords,
    samlRequests,
  };
};

/** Run `step` over `items` one after another. */
const inSequence = <A>(items: ReadonlyArray<A>, step: (item: A) => Promise<void>): Promise<void> =>
  Arr.reduce(items, Promise.resolve(), async (previous, item) => {
    await previous;
    await step(item);
  });

/** The pre-login cookie a started sign-in (`sso-authorizations`) sets, as a `Cookie` header. */
const ssoStateCookie = (response: Response): string => {
  const set = response.headers
    .getSetCookie()
    .find((cookie) => cookie.startsWith("conduit_session_sso_state="));
  return set?.split(";")[0] ?? "";
};

/** `POST /sso/callback` from a browser that holds `cookie`. */
const callbackPost = (body: Schema.Json, cookie: string): Request =>
  new Request("http://test/sso/callback", {
    method: "POST",
    headers: { "content-type": "application/json", cookie },
    body: encodeJson(body),
  });

/** A JSON:API create of a `type` resource with `attributes`, at `path`. */
const create =
  (path: string, type: string) =>
  (attributes: Schema.Json, sessionId?: string, relationships?: Schema.Json): Request =>
    new Request(`http://test${path}`, {
      method: "POST",
      headers: {
        "content-type": "application/vnd.api+json",
        ...(sessionId !== undefined ? { cookie: `conduit_session=${sessionId}` } : {}),
      },
      body: encodeJson({
        data: { type, attributes, ...(relationships !== undefined && { relationships }) },
      }),
    });

/** `POST /sso-providers`: register a connection. */
const registerProvider = create("/sso-providers", "sso-providers");

/** `POST /sso-authorizations`: start an SSO sign-in. */
const startSignIn = create("/sso-authorizations", "sso-authorizations");

const REGISTER_BODY = {
  issuer: "https://idp.acme.test",
  domain: "acme.test",
  clientId: "client-1",
  clientSecret: "secret-1",
  redirectUri: "https://app/api/auth/sso/callback",
  authorizationEndpoint: "https://idp.acme.test/authorize",
  tokenEndpoint: "https://idp.acme.test/token",
  userInfoEndpoint: "https://idp.acme.test/userinfo",
};

describe("HTTP SSO endpoints", () => {
  it("registers (admin only), signs in, and completes the callback", async () => {
    const fx = makeHttpFixture();
    const adminSid = fx.makeSession(fx.seedUser("admin@acme.test", { role: "admin" }));

    // Non-admin cannot register.
    const nonAdminSid = fx.makeSession(fx.seedUser("user@acme.test"));
    const denied = await fx.handler(registerProvider(REGISTER_BODY, nonAdminSid));
    expect(denied.status).toBe(403);

    // Admin registers the connection (secret is never echoed back).
    const registered = await fx.handler(registerProvider(REGISTER_BODY, adminSid));
    expect(registered.status).toBe(201);
    const provider = await providerAttributes(registered);
    expect(provider["domain"]).toBe("acme.test");
    expect(provider).not.toHaveProperty("clientSecret");

    // Anonymous sign-in resolves the IdP URL by email domain.
    const signIn = await fx.handler(startSignIn({ email: "worker@acme.test" }));
    expect(signIn.status).toBe(201);
    // The single-use state is this caller's alone.
    expect(signIn.headers.get("cache-control")).toBe("no-store");
    const { url, state } = await signInUrl(signIn);
    expect(new URL(url).origin).toBe("https://idp.acme.test");
    // The pre-login cookie binds the flow to this browser. The SAML ACS is a
    // cross-site POST, so it is `SameSite=None`, hence `Secure` even here.
    const preLogin = signIn.headers
      .getSetCookie()
      .find((cookie) => cookie.startsWith("conduit_session_sso_state="));
    expect(preLogin).toContain(`conduit_session_sso_state=${state}`);
    expect(preLogin).toMatch(/HttpOnly/i);
    expect(preLogin).toMatch(/SameSite=None/i);
    expect(preLogin).toMatch(/Secure/i);

    // Callback provisions the user and sets a session cookie.
    const callback = await withFetch(
      {
        "https://idp.acme.test/token": { access_token: "at", token_type: "bearer" },
        "https://idp.acme.test/userinfo": {
          sub: "idp-1",
          email: "worker@acme.test",
          email_verified: true,
          name: "Worker",
        },
      },
      () => fx.handler(callbackPost({ state, code: "auth-code" }, ssoStateCookie(signIn))),
    );
    expect(callback.status).toBe(200);
    expect(callback.headers.get("set-cookie")).toContain("conduit_session=");
    // A finished sign-in clears the pre-login cookie.
    expect(callback.headers.getSetCookie()).toContainEqual(
      expect.stringMatching(/^conduit_session_sso_state=;.*Max-Age=0/i),
    );
    // The callback keeps its own JSON answer, never a JSON:API document.
    const callbackBody = await expectSpecJson(callback, "application/json", ["user"]);
    expect(Schema.decodeUnknownSync(UserEmailBody)(callbackBody).user.email).toBe(
      "worker@acme.test",
    );
  });

  it("refuses a callback from a browser that did not start the sign-in", async () => {
    const fx = makeHttpFixture();
    const adminSid = fx.makeSession(fx.seedUser("admin@acme.test", { role: "admin" }));
    await fx.handler(registerProvider(REGISTER_BODY, adminSid));

    // The attacker starts a sign-in and completes the IdP leg as themselves;
    // the victim's browser holds no pre-login cookie, or one of its own.
    const attacker = await fx.handler(startSignIn({ email: "worker@acme.test" }));
    const { state } = await signInUrl(attacker);
    const victim = await fx.handler(startSignIn({ email: "worker@acme.test" }));

    await inSequence(["", ssoStateCookie(victim)], async (cookie) => {
      const res = await withFetch(ACME_IDP_ROUTES, () =>
        fx.handler(callbackPost({ state, code: "auth-code" }, cookie)),
      );
      expect(res.status).toBe(400);
      expect(res.headers.get("set-cookie")).toBeNull();
    });

    // The state was not spent by the refusals: its own browser still finishes.
    const own = await withFetch(ACME_IDP_ROUTES, () =>
      fx.handler(callbackPost({ state, code: "auth-code" }, ssoStateCookie(attacker))),
    );
    expect(own.status).toBe(200);
  });

  it("takes the organization as the relationship, and answers it the same way", async () => {
    const fx = makeHttpFixture();
    const adminSid = fx.makeSession(fx.seedUser("admin@acme.test", { role: "admin" }));

    const linked = await fx.handler(
      registerProvider(REGISTER_BODY, adminSid, {
        organization: { data: { type: "organizations", id: "org-1" } },
      }),
    );
    expect(linked.status).toBe(201);
    expect(await providerOrganization(linked)).toEqual({ type: "organizations", id: "org-1" });
    expect(
      Arr.fromIterable(MutableHashMap.values(fx.providers)).map((p) => p.organizationId),
    ).toEqual(["org-1"]);

    // `data: null` and an absent relationship both mean no organization.
    const none = await fx.handler(
      registerProvider({ ...REGISTER_BODY, domain: "b.test" }, adminSid, {
        organization: { data: null },
      }),
    );
    expect(none.status).toBe(201);
    expect(await providerOrganization(none)).toBeNull();

    // `organizationId` is no longer an attribute: sent as one, it is ignored.
    const attribute = await fx.handler(
      registerProvider({ ...REGISTER_BODY, domain: "c.test", organizationId: "org-1" }, adminSid),
    );
    expect(attribute.status).toBe(201);
    expect(await providerOrganization(attribute)).toBeNull();
  });

  it("returns 404 when SSO is not configured", async () => {
    const fx = makeHttpFixture();
    const res = await fx.handlerWithoutSso(startSignIn({ email: "a@b.test" }));
    expect(res.status).toBe(404);
  });
});

// --- HTTP: the SAML half -----------------------------------------------------

const SAML_REGISTER_BODY = {
  protocol: "saml",
  domain: "acme.test",
  entityId: SAML_IDP,
  ssoUrl: "https://idp.acme.test/sso",
  idpCertificates: ["-----BEGIN CERTIFICATE-----\nZmFrZQ==\n-----END CERTIFICATE-----"],
  spEntityId: SAML_SP,
  acsUrl: SAML_ACS,
};

/**
 * The IdP's ACS POST: an `application/x-www-form-urlencoded` browser form,
 * posted from the IdP's page (so `Origin` is the IdP's) by a browser holding
 * `cookie`.
 */
const acsPost = (providerId: string, fields: Record<string, string>, cookie = ""): Request =>
  new Request(`http://test/sso/saml/acs/${providerId}`, {
    method: "POST",
    headers: {
      "content-type": "application/x-www-form-urlencoded",
      origin: "https://idp.acme.test",
      ...(cookie !== "" && { cookie }),
    },
    body: new URLSearchParams(fields).toString(),
  });

describe("HTTP SSO endpoints — SAML", () => {
  it("registers a SAML connection through the same admin-gated endpoint", async () => {
    const fx = makeHttpFixture();
    const adminSid = fx.makeSession(fx.seedUser("admin@acme.test", { role: "admin" }));

    const registered = await fx.handler(registerProvider(SAML_REGISTER_BODY, adminSid));
    expect(registered.status).toBe(201);
    const provider = await providerAttributes(registered);
    expect(provider["protocol"]).toBe("saml");
    expect(provider["entityId"]).toBe(SAML_IDP);
    expect(provider["idpCertificates"]).toEqual(SAML_REGISTER_BODY.idpCertificates);
    // The SAML arm has no client secret to leak, and neither arm echoes the
    // registrar's user id.
    expect(provider).not.toHaveProperty("clientSecret");
    expect(provider).not.toHaveProperty("userId");
    expect(MutableHashMap.size(fx.providers)).toBe(1);
  });

  it("still registers an OIDC connection when the body carries no protocol", async () => {
    const fx = makeHttpFixture();
    const adminSid = fx.makeSession(fx.seedUser("admin@acme.test", { role: "admin" }));

    const registered = await fx.handler(registerProvider(REGISTER_BODY, adminSid));
    expect(registered.status).toBe(201);
    const provider = await providerAttributes(registered);
    expect(provider["protocol"]).toBe("oidc");
    expect(provider["issuer"]).toBe("https://idp.acme.test");
    expect(provider).not.toHaveProperty("clientSecret");
    // The OIDC arm of the view carries no SAML fields.
    expect(provider).not.toHaveProperty("idpCertificates");
  });

  it("rejects an invalid SAML registration with 400", async () => {
    const fx = makeHttpFixture();
    const adminSid = fx.makeSession(fx.seedUser("admin@acme.test", { role: "admin" }));

    const res = await fx.handler(
      registerProvider({ ...SAML_REGISTER_BODY, idpCertificates: [] }, adminSid),
    );
    expect(res.status).toBe(400);
    const { errors } = await jsonBody(
      res,
      Schema.Struct({ errors: Schema.Array(Schema.Struct({ detail: Schema.String })) }),
    );
    expect(errors[0]?.detail).toMatch(/idpCertificates/);
  });

  it("completes the cross-origin ACS form POST with a redirect and a session cookie", async () => {
    const fx = makeHttpFixture();
    const adminSid = fx.makeSession(fx.seedUser("admin@acme.test", { role: "admin" }));

    const registered = await fx.handler(registerProvider(SAML_REGISTER_BODY, adminSid));
    const providerId = await providerIdOf(registered);

    // Start the flow so the AuthnRequest id is banked, exactly as a browser
    // redirect would.
    const signIn = await fx.handler(startSignIn({ email: "worker@acme.test" }));
    expect(signIn.status).toBe(201);
    const { state } = await signInUrl(signIn);
    const requestId = fx.samlRequests[fx.samlRequests.length - 1]?.requestId ?? "";

    // The IdP's origin is in no `trustedOrigins`: the ACS is exempt from the
    // Origin gate and checks the pre-login cookie instead.
    const acs = await fx.handler(
      acsPost(
        providerId,
        {
          SAMLResponse: samlResponse({ id: "_http-a1", inResponseTo: requestId }),
          RelayState: state,
        },
        ssoStateCookie(signIn),
      ),
    );
    // A top-level form POST is answered with a redirect, never a body.
    expect(acs.status).toBe(303);
    expect(acs.headers.get("location")).toBe("/");
    expect(await acs.text()).toBe("");
    expect(acs.headers.get("cache-control")).toBe("no-store");
    const cookies = acs.headers.getSetCookie();
    expect(cookies).toContainEqual(expect.stringMatching(/^conduit_session=/));
    expect(cookies).toContainEqual(
      expect.stringMatching(/^conduit_session_sso_state=;.*Max-Age=0/i),
    );
  });

  it("redirects to the error page when the ACS response cannot be trusted", async () => {
    const fx = makeHttpFixture();
    const adminSid = fx.makeSession(fx.seedUser("admin@acme.test", { role: "admin" }));
    const registered = await fx.handler(registerProvider(SAML_REGISTER_BODY, adminSid));
    const providerId = await providerIdOf(registered);

    // No AuthnRequest was ever issued, so there is nothing to spend.
    const res = await fx.handler(
      acsPost(providerId, { SAMLResponse: samlResponse({ inResponseTo: "_never-issued" }) }),
    );
    expect(res.status).toBe(303);
    expect(res.headers.get("location")).toBe("/?error=access_denied");
    expect(res.headers.get("set-cookie")).toBeNull();
  });

  it("refuses an ACS POST from a browser that did not start the sign-in", async () => {
    const fx = makeHttpFixture({
      sso: { redirectTo: "https://app.test/home", errorRedirectTo: "/sign-in?next=%2Fhome" },
    });
    const adminSid = fx.makeSession(fx.seedUser("admin@acme.test", { role: "admin" }));
    const providerId = await providerIdOf(
      await fx.handler(registerProvider(SAML_REGISTER_BODY, adminSid)),
    );

    // The attacker starts the sign-in and has the IdP sign a response for
    // themselves; the victim's browser posts it holding no pre-login cookie,
    // or one of its own.
    const victim = await fx.handler(startSignIn({ email: "worker@acme.test" }));
    await inSequence(
      [
        ["_csrf-1", ""],
        ["_csrf-2", ssoStateCookie(victim)],
      ] as const,
      async ([id, cookie]) => {
        const { state } = await signInUrl(
          await fx.handler(startSignIn({ email: "worker@acme.test" })),
        );
        const requestId = fx.samlRequests[fx.samlRequests.length - 1]?.requestId ?? "";
        const res = await fx.handler(
          acsPost(
            providerId,
            { SAMLResponse: samlResponse({ id, inResponseTo: requestId }), RelayState: state },
            cookie,
          ),
        );
        expect(res.status).toBe(303);
        expect(res.headers.get("location")).toBe("/sign-in?next=%2Fhome&error=access_denied");
        expect(res.headers.get("set-cookie")).toBeNull();
      },
    );

    // The configured success target, for the browser that started it.
    const { state } = await signInUrl(victim);
    const requestId = fx.samlRequests[0]?.requestId ?? "";
    const own = await fx.handler(
      acsPost(
        providerId,
        { SAMLResponse: samlResponse({ id: "_own", inResponseTo: requestId }), RelayState: state },
        ssoStateCookie(victim),
      ),
    );
    expect(own.status).toBe(303);
    expect(own.headers.get("location")).toBe("https://app.test/home");
  });

  it("serves SP metadata as XML", async () => {
    const fx = makeHttpFixture();
    const adminSid = fx.makeSession(fx.seedUser("admin@acme.test", { role: "admin" }));
    const registered = await fx.handler(registerProvider(SAML_REGISTER_BODY, adminSid));
    const providerId = await providerIdOf(registered);

    const res = await fx.handler(
      new Request(`http://test/sso/saml/metadata/${providerId}`, { method: "GET" }),
    );
    expect(res.status).toBe(200);
    expect(mediaTypeOf(res)).toBe("application/samlmetadata+xml");
    const xml = await res.text();
    expect(xml.trimStart().startsWith("<")).toBe(true);
    expect(xml).toContain(SAML_SP);
  });

  it("answers 400 for metadata on an OIDC connection", async () => {
    const fx = makeHttpFixture();
    const adminSid = fx.makeSession(fx.seedUser("admin@acme.test", { role: "admin" }));
    const registered = await fx.handler(registerProvider(REGISTER_BODY, adminSid));
    const providerId = await providerIdOf(registered);

    const res = await fx.handler(
      new Request(`http://test/sso/saml/metadata/${providerId}`, { method: "GET" }),
    );
    expect(res.status).toBe(400);
  });

  it("returns 404 on the SAML routes when SSO is not configured", async () => {
    const fx = makeHttpFixture();
    const res = await fx.handlerWithoutSso(
      new Request("http://test/sso/saml/metadata/anything", { method: "GET" }),
    );
    expect(res.status).toBe(404);
  });
});

// --- Single-use callback state ----------------------------------------

/** The IdP answers every request (the token endpoint included) with `400`. */
const withFailingIdp = <A>(thunk: () => Promise<A>): Promise<A> => {
  const original = globalThis.fetch;
  globalThis.fetch = () =>
    Promise.resolve(
      new Response(encodeJson({ error: "invalid_grant" }), {
        status: 400,
        headers: { "content-type": "application/json" },
      }),
    );
  return new Promise<A>((resolve) => resolve(thunk())).finally(() => {
    globalThis.fetch = original;
  });
};

const ACME_IDP_ROUTES = {
  "https://idp.acme.test/token": { access_token: "at", token_type: "bearer" },
  "https://idp.acme.test/userinfo": {
    sub: "idp-user-9",
    email: "worker@acme.test",
    email_verified: true,
  },
};

/** A registered OIDC connection, and the callback of a started sign-in. */
const started = async () => {
  const stores = makeStores();
  const sso = await runPromiseHttp(Sso.make().pipe(Effect.provide(stores.layer)));
  const { state } = await Effect.runPromise(
    Effect.gen(function* () {
      yield* sso.registerProvider("admin", ACME);
      return yield* sso.signIn({ email: "worker@acme.test" });
    }).pipe(Effect.provide(stores.layer)),
  );
  return (code: string) => sso.handleCallback(state, code).pipe(Effect.provide(stores.layer));
};

describe("SSO callback state is single-use", () => {
  it("refuses a callback replayed after it signed the user in", async () => {
    const callback = await started();
    const first = await withFetch(ACME_IDP_ROUTES, () => Effect.runPromise(callback("code-1")));
    expect(first.session?.userId).toBe(first.user.id);

    const replay = await withFetch(ACME_IDP_ROUTES, () =>
      Effect.runPromise(Effect.flip(callback("code-1"))),
    );
    expect(replay).toBeInstanceOf(SsoError);
    expect(replay.message).toMatch(/already used/);
  });

  it("refuses a callback replayed after the first use failed at the IdP", async () => {
    const callback = await started();
    const failed = await withFailingIdp(() => Effect.runPromise(Effect.flip(callback("code-1"))));
    expect(failed).toBeInstanceOf(SsoError);

    // The failed attempt spent the state: a retry with a code the IdP would
    // accept is still refused.
    const replay = await withFetch(ACME_IDP_ROUTES, () =>
      Effect.runPromise(Effect.flip(callback("code-2"))),
    );
    expect(replay).toBeInstanceOf(SsoError);
    expect(replay.message).toMatch(/already used/);
  });

  it("admits only one of two concurrent callbacks carrying the same state", async () => {
    const callback = await started();
    const results = await withFetch(ACME_IDP_ROUTES, () =>
      Effect.runPromise(
        Effect.all([Effect.result(callback("code-1")), Effect.result(callback("code-1"))], {
          concurrency: "unbounded",
        }),
      ),
    );
    const refusals = Arr.filter(results, Result.isFailure).map((r) => r.failure);
    expect(Arr.filter(results, Result.isSuccess)).toHaveLength(1);
    expect(refusals).toHaveLength(1);
    expect(refusals[0]?.message).toMatch(/already used/);
  });

  it("answers 400 to a POST /sso/callback replayed after a failed exchange", async () => {
    const fx = makeHttpFixture();
    const adminSid = fx.makeSession(fx.seedUser("admin@acme.test", { role: "admin" }));
    await fx.handler(registerProvider(REGISTER_BODY, adminSid));
    const signIn = await fx.handler(startSignIn({ email: "worker@acme.test" }));
    const { state } = await signInUrl(signIn);
    const cookie = ssoStateCookie(signIn);

    const failed = await withFailingIdp(() =>
      fx.handler(callbackPost({ state, code: "code-1" }, cookie)),
    );
    expect(failed.status).toBe(400);

    const replay = await withFetch(ACME_IDP_ROUTES, () =>
      fx.handler(callbackPost({ state, code: "code-2" }, cookie)),
    );
    expect(replay.status).toBe(400);
    expect(replay.headers.get("set-cookie")).toBeNull();
  });

  it("answers 400 to a replayed SAML ACS POST, and to a fresh assertion for its RelayState", async () => {
    const fx = makeHttpFixture();
    const adminSid = fx.makeSession(fx.seedUser("admin@acme.test", { role: "admin" }));
    const providerId = await providerIdOf(
      await fx.handler(registerProvider(SAML_REGISTER_BODY, adminSid)),
    );
    const signIn = await fx.handler(startSignIn({ email: "worker@acme.test" }));
    const { state } = await signInUrl(signIn);
    const cookie = ssoStateCookie(signIn);
    const requestId = fx.samlRequests[fx.samlRequests.length - 1]?.requestId ?? "";
    const form = {
      SAMLResponse: samlResponse({ id: "_replayed", inResponseTo: requestId }),
      RelayState: state,
    };

    expect((await fx.handler(acsPost(providerId, form, cookie))).headers.get("location")).toBe("/");
    const replay = await fx.handler(acsPost(providerId, form, cookie));
    expect(replay.headers.get("location")).toBe("/?error=access_denied");
    expect(replay.headers.get("set-cookie")).toBeNull();

    // A new assertion answering the same, spent request with the same
    // RelayState is refused too: the RelayState lives and dies with it.
    const fresh = await fx.handler(
      acsPost(
        providerId,
        {
          SAMLResponse: samlResponse({ id: "_fresh", inResponseTo: requestId }),
          RelayState: state,
        },
        cookie,
      ),
    );
    expect(fresh.headers.get("location")).toBe("/?error=access_denied");
  });

  it("sends a browser that owes a second factor on with the challenge in the fragment", async () => {
    const challenged: Array<string> = [];
    const fx = makeHttpFixture({
      gate: enrolledGate(challenged),
      sso: { secondFactorRedirectTo: "/two-factor#stale" },
    });
    const adminSid = fx.makeSession(fx.seedUser("admin@acme.test", { role: "admin" }));
    const providerId = await providerIdOf(
      await fx.handler(registerProvider(SAML_REGISTER_BODY, adminSid)),
    );
    const signIn = await fx.handler(startSignIn({ email: "worker@acme.test" }));
    const { state } = await signInUrl(signIn);
    const requestId = fx.samlRequests[fx.samlRequests.length - 1]?.requestId ?? "";

    const res = await fx.handler(
      acsPost(
        providerId,
        { SAMLResponse: samlResponse({ inResponseTo: requestId }), RelayState: state },
        ssoStateCookie(signIn),
      ),
    );

    expect(res.status).toBe(303);
    expect(res.headers.get("location")).toBe(
      `/two-factor#second_factor=${testChallenge.token}&expires_at=${testChallenge.expiresAt}`,
    );
    expect(res.headers.get("cache-control")).toContain("no-store");
    // No session: only the pre-login cookie is cleared.
    const setCookie = res.headers.get("set-cookie") ?? "";
    expect(setCookie).toContain("_sso_state=;");
    expect(setCookie).not.toMatch(/(^|, )[a-z_]+_session=/);
    expect(challenged).toHaveLength(1);
  });
});

const userinfo = (claims: Record<string, Schema.Json>) => ({
  "https://idp.acme.test/token": { access_token: "at", token_type: "bearer" },
  "https://idp.acme.test/userinfo": { sub: "idp-user-1", ...claims },
});

/** Seed a user holding `email`, unverified, with a password. */
const seedUser = async (
  stores: ReturnType<typeof makeStores>,
  id: string,
  email: string,
  attributes: Types.Attributes = {},
) => {
  const now = DateTime.toDateUtc(DateTime.nowUnsafe());
  MutableHashMap.set(stores.users, id, { id, createdAt: now, updatedAt: now, attributes });
  MutableHashMap.set(stores.passwordHashes, id, "their-hash");
  await Effect.runPromise(
    stores.identifiers.create(makeIdentifier({ userId: id, type: "email", value: email, now })),
  );
};

const failureOf = <A, E>(result: Result.Result<A, E>): E => {
  assert(Result.isFailure(result));
  return result.failure;
};

describe("SSO signs in only managed users", () => {
  /** Register `provider` and run one OIDC round trip whose profile is `claims`. */
  const signInAs = async (
    stores: ReturnType<typeof makeStores>,
    claims: Record<string, Schema.Json>,
    provider: Sso.RegisterProviderInput = ACME,
  ) => {
    const sso = await runPromiseHttp(Sso.make().pipe(Effect.provide(stores.layer)));
    await Effect.runPromise(
      sso.registerProvider("admin", provider).pipe(Effect.provide(stores.layer)),
    );
    return withFetch(userinfo(claims), () =>
      Effect.runPromise(
        Effect.gen(function* () {
          const start = yield* sso.signIn({ email: "worker@acme.test" });
          return yield* Effect.result(sso.handleCallback(start.state, "code"));
        }).pipe(Effect.provide(stores.layer)),
      ),
    );
  };

  it("refuses an asserted address off the organization's verified domains, touching nothing", async () => {
    const stores = makeStores();
    await seedUser(stores, "victim", "ceo@b.test");

    const result = await signInAs(stores, { email: "ceo@b.test", email_verified: true });

    expect(failureOf(result).message).toMatch(/does not manage/);
    // The victim's unverified address was not proved: password and sessions stand.
    expect(MutableHashMap.get(stores.passwordHashes, "victim")).toEqual(Option.some("their-hash"));
    expect(stores.sessionsCleared).toEqual([]);
    // Nor was a user created for an unclaimed address.
    const fresh = await signInAs(makeStores(), { email: "new@b.test", email_verified: true });
    expect(failureOf(fresh).message).toMatch(/does not manage/);
  });

  it("refuses an address whose domain claim is still pending", async () => {
    const stores = makeStores({ claimAcme: false });
    stores.seedDomain("org-1", "acme.test", "pending");

    const result = await signInAs(stores, { email: "worker@acme.test", email_verified: true });

    expect(failureOf(result).message).toMatch(/does not manage/);
    expect(MutableHashMap.size(stores.users)).toBe(0);
  });

  it("refuses another organization's verified domain", async () => {
    const stores = makeStores();
    stores.seedDomain("org-2", "b.test");

    const result = await signInAs(stores, { email: "ceo@b.test", email_verified: true });

    expect(failureOf(result).message).toMatch(/does not manage/);
  });

  it("stamps a user it creates, and signs that user in off the verified domains", async () => {
    const stores = makeStores();
    const first = await signInAs(stores, { email: "worker@acme.test", email_verified: true });
    assert(Result.isSuccess(first));
    expect(ManagedUser.provisionedBy(first.success.user)).toEqual({
      kind: "sso",
      connectionId: first.success.provider.id,
      organizationId: "org-1",
    });

    // A user the organization provisioned keeps signing in under an address
    // it holds outside the claimed domains.
    await Effect.runPromise(
      stores.identifiers.create(
        makeIdentifier({
          userId: first.success.user.id,
          type: "email",
          value: "worker@personal.test",
          verified: true,
          now: DateTime.toDateUtc(DateTime.nowUnsafe()),
        }),
      ),
    );
    const again = await signInAs(stores, { email: "worker@personal.test", email_verified: true });
    assert(Result.isSuccess(again));
    expect(again.success.user.id).toBe(first.success.user.id);
  });

  it("signs in a user another organization provisioned only on this one's domains", async () => {
    const stores = makeStores();
    await seedUser(
      stores,
      "elsewhere",
      "worker@b.test",
      ManagedUser.provisionedByAttributes({
        kind: "scim",
        connectionId: "scim-2",
        organizationId: "org-2",
      }),
    );

    const result = await signInAs(stores, { email: "worker@b.test", email_verified: true });

    expect(failureOf(result).message).toMatch(/does not manage/);
  });

  it("binds a connection without an organization to its own domain and users", async () => {
    const { organizationId: _organizationId, ...withoutOrganization } = ACME;
    const stores = makeStores({ claimAcme: false });

    const offDomain = await signInAs(
      stores,
      { email: "ceo@b.test", email_verified: true },
      withoutOrganization,
    );
    expect(failureOf(offDomain).message).toMatch(/does not manage/);

    const onDomain = await signInAs(
      stores,
      { email: "worker@acme.test", email_verified: true },
      withoutOrganization,
    );
    assert(Result.isSuccess(onDomain));
    expect(ManagedUser.provisionedBy(onDomain.success.user)).toEqual({
      kind: "sso",
      connectionId: onDomain.success.provider.id,
    });
  });

  it("requires email_verified to be true unless the connection opts out", async () => {
    const missing = await signInAs(makeStores(), { email: "worker@acme.test" });
    expect(failureOf(missing).message).toMatch(/verified email/);

    const optedOut = await signInAs(
      makeStores(),
      { email: "worker@acme.test" },
      { ...ACME, requireEmailVerified: false },
    );
    assert(Result.isSuccess(optedOut));

    // Opting out never accepts an explicit `false`.
    const refused = await signInAs(
      makeStores(),
      { email: "worker@acme.test", email_verified: false },
      { ...ACME, requireEmailVerified: false },
    );
    expect(failureOf(refused).message).toMatch(/verified email/);
  });

  it("refuses a SAML assertion off the organization's verified domains", async () => {
    const fx = makeSamlFixture();
    const result = await runPromiseHttp(
      Effect.gen(function* () {
        const sso = yield* Sso.make();
        const provider = yield* sso.registerSamlProvider("admin", ACME_SAML);
        const start = yield* sso.signIn({ providerId: provider.id });
        const requestId = fx.requests[fx.requests.length - 1]?.requestId ?? "";
        return yield* Effect.result(
          sso.handleSamlCallback(
            provider.id,
            samlResponse({ email: "ceo@b.test", inResponseTo: requestId }),
            start.state,
          ),
        );
      }).pipe(Effect.provide(fx.layer)),
    );
    expect(failureOf(result).message).toMatch(/does not manage/);
  });
});
