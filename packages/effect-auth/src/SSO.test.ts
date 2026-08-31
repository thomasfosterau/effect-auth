import { describe, it, expect } from "vite-plus/test";
import { Effect, Layer } from "effect";
import { UserNotFoundError } from "./Errors.ts";
import { Hooks } from "./Hooks.ts";
import * as PlatformCrypto from "./PlatformCrypto.ts";
import { SessionService } from "./SessionService.ts";
import { SessionStore } from "./SessionStore.ts";
import { UserStore } from "./UserStore.ts";
import { hashToken } from "./TokenHash.ts";
import { UserServiceStore, UserService } from "./User.ts";
import { AuthLifecycleService } from "./AuthLifecycle.ts";
import { EmailPasswordService } from "./email/EmailPassword.ts";
import { PasswordHasher } from "./password/Password.ts";
import { EmailVerificationService } from "./email/EmailVerification.ts";
import { PasswordResetService } from "./password/PasswordReset.ts";
import { type AuthServices } from "./http/HttpServer.ts";
import * as HTTPServer from "./http/HttpServer.ts";
import {
  IdentifierStore,
  makeIdentifier,
  memoryIdentifierStore,
  type Identifier,
} from "./Identifier.ts";
import { OrganizationStore, type Member, type SSOProvider } from "./index.ts";
import { OAuthStateStore, OAuthUserStore, type OAuthState } from "./oauth/OAuth.ts";
import { SSOProviderStore, SSOError, SSOService } from "./SSO.ts";
import * as SSO from "./SSO.ts";
import {
  memorySAMLReplayStore,
  SAMLReplayStore,
  SAMLVerifier,
  type SAMLAssertion,
  type SAMLAuthnRequestInput,
  type SAMLReplayRecord,
} from "./SAML.ts";
import type * as Types from "./Types.ts";

/** Swap `globalThis.fetch` for a route handler while `thunk` runs. */
const withFetch = async <A>(
  routes: Record<string, unknown>,
  thunk: () => Promise<A>,
): Promise<A> => {
  const original = globalThis.fetch;
  globalThis.fetch = ((input: string | URL | Request) => {
    const url = typeof input === "string" ? input : input.toString();
    const key = Object.keys(routes).find((k) => url.startsWith(k));
    const body = key ? routes[key] : { error: "no route" };
    return Promise.resolve(
      new Response(JSON.stringify(body), { headers: { "content-type": "application/json" } }),
    );
  }) as typeof fetch;
  try {
    return await thunk();
  } finally {
    globalThis.fetch = original;
  }
};

const makeStores = () => {
  const providers = new Map<string, SSOProvider>();
  const users = new Map<string, Types.User>();
  const identifierRecords = new Map<string, Identifier>();
  const identifiers = memoryIdentifierStore(identifierRecords);
  const states = new Map<string, OAuthState>();
  const members: Member[] = [];
  let userSeq = 0;

  const ssoStore: typeof SSOProviderStore.Service = {
    create: (p) => Effect.sync(() => (providers.set(p.id, p), p)),
    getById: (id) => Effect.succeed(providers.get(id) ?? null),
    getByDomain: (domain) =>
      Effect.succeed([...providers.values()].find((p) => p.domain === domain) ?? null),
    list: () => Effect.succeed([...providers.values()]),
  };

  const userStore = {
    getUser: (userId: string) => {
      const u = users.get(userId);
      return u ? Effect.succeed(u) : Effect.fail(new UserNotFoundError({ message: "nf", userId }));
    },
    createUser: (input: { name?: string; image?: string }) =>
      Effect.sync(() => {
        const now = new Date();
        const user: Types.User = {
          id: `u${++userSeq}`,
          ...(input.name !== undefined && { name: input.name }),
          ...(input.image !== undefined && { image: input.image }),
          createdAt: now,
          updatedAt: now,
          attributes: {},
        };
        users.set(user.id, user);
        return user;
      }),
  };

  const coreUserStore: typeof UserStore.Service = {
    get: (userId) => Effect.sync(() => users.get(userId) ?? null),
    getCredentials: () => Effect.succeed(null),
  };

  const stateStore = {
    create: (s: OAuthState) => Effect.sync(() => (states.set(s.state, s), s)),
    get: (state: string) => Effect.succeed(states.get(state) ?? null),
    delete: (state: string) => Effect.sync(() => void states.delete(state)),
  };

  const sessionManager: typeof SessionService.Service = {
    createSession: (userId) =>
      Effect.succeed({
        id: `s-${userId}`,
        userId,
        expiresAt: new Date(Date.now() + 3600_000),
        createdAt: new Date(),
        lastActivityAt: new Date(),
        attributes: {},
      }),
    validateSession: () => Effect.die("unused"),
    invalidateSession: () => Effect.die("unused"),
    invalidateUserSessions: () => Effect.void,
    listSessions: () => Effect.succeed([]),
    revokeOtherSessions: () => Effect.void,
    setSessionAttributes: () => Effect.die("unused"),
  };

  const orgStore = {
    createMember: (m: Member) => Effect.sync(() => (members.push(m), m)),
    getMember: (organizationId: string, userId: string) =>
      Effect.succeed(
        members.find((m) => m.organizationId === organizationId && m.userId === userId) ?? null,
      ),
    // Unused by SSO:
    createOrganization: () => Effect.die("unused") as never,
    getOrganizationById: () => Effect.die("unused") as never,
    getOrganizationBySlug: () => Effect.die("unused") as never,
    updateOrganization: () => Effect.die("unused") as never,
    deleteOrganization: () => Effect.die("unused") as never,
    updateMember: () => Effect.die("unused") as never,
    deleteMember: () => Effect.die("unused") as never,
    listMembersByOrganization: () => Effect.die("unused") as never,
    listMembersByUser: () => Effect.die("unused") as never,
    countMembersByOrganization: () => Effect.die("unused") as never,
    createInvitation: () => Effect.die("unused") as never,
    getInvitation: () => Effect.die("unused") as never,
    updateInvitation: () => Effect.die("unused") as never,
    listInvitationsByOrganization: () => Effect.die("unused") as never,
    listInvitationsByEmail: () => Effect.die("unused") as never,
    createTeam: () => Effect.die("unused") as never,
    getTeam: () => Effect.die("unused") as never,
    updateTeam: () => Effect.die("unused") as never,
    deleteTeam: () => Effect.die("unused") as never,
    listTeams: () => Effect.die("unused") as never,
    addTeamMember: () => Effect.die("unused") as never,
    removeTeamMember: () => Effect.die("unused") as never,
    listTeamMembers: () => Effect.die("unused") as never,
    listTeamsForMember: () => Effect.die("unused") as never,
    upsertOrgRole: () => Effect.die("unused") as never,
    getOrgRole: () => Effect.die("unused") as never,
    listOrgRoles: () => Effect.die("unused") as never,
    deleteOrgRole: () => Effect.die("unused") as never,
  };

  const layer = Layer.mergeAll(
    Layer.succeed(SSOProviderStore)(ssoStore),
    Layer.succeed(OAuthStateStore)(stateStore),
    Layer.succeed(OAuthUserStore)(userStore),
    Layer.succeed(IdentifierStore)(identifiers),
    Layer.succeed(UserStore)(coreUserStore),
    Layer.succeed(SessionService)(sessionManager),
    Layer.succeed(OrganizationStore)(orgStore),
    Hooks.Default,
    PlatformCrypto.layer,
  );

  return { layer, providers, users, identifiers, members };
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

describe("SSOService", () => {
  it("registers a provider and routes sign-in by email domain", async () => {
    const { layer } = makeStores();
    const sso = await Effect.runPromise(SSO.make().pipe(Effect.provide(layer)));

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
    const { layer, users, identifiers, members } = makeStores();
    const sso = await Effect.runPromise(
      SSO.make({ defaultRole: "member" }).pipe(Effect.provide(layer)),
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
    expect(first.session.userId).toBe(first.user.id);
    expect(members).toEqual([
      { ...members[0], organizationId: "org-1", userId: first.user.id, role: "member" },
    ]);
    expect(users.size).toBe(1);

    // Second login: reuses the same user, no duplicate membership.
    const second = await withFetch(idpRoutes, () => Effect.runPromise(signInFlow()));
    expect(second.isNewUser).toBe(false);
    expect(second.user.id).toBe(first.user.id);
    expect(users.size).toBe(1);
    expect(members.length).toBe(1);
  });

  it("populates endpoints from OIDC discovery", async () => {
    const { layer, providers } = makeStores();
    const sso = await Effect.runPromise(SSO.make().pipe(Effect.provide(layer)));

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
    expect(providers.size).toBe(1);
  });

  it("fails sign-in for an unknown domain", async () => {
    const { layer } = makeStores();
    const sso = await Effect.runPromise(SSO.make().pipe(Effect.provide(layer)));
    const err = await Effect.runPromise(
      Effect.flip(sso.signIn({ email: "nobody@unknown.test" })).pipe(Effect.provide(layer)),
    );
    expect(err).toBeInstanceOf(SSOError);
  });

  it("rejects a callback whose profile email is unverified", async () => {
    const { layer } = makeStores();
    const sso = await Effect.runPromise(SSO.make().pipe(Effect.provide(layer)));
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
    expect(err).toBeInstanceOf(SSOError);
  });
});

// --- SAML --------------------------------------------------------------------
//
// The crypto lives in `@thomasfosterau/effect-auth-saml` and is exercised
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
} as const satisfies SSO.RegisterSAMLProviderInput;

/** Encode the assertion the stub verifier should "find" in this response. */
const samlResponse = (assertion: Partial<SAMLAssertion>): string =>
  Buffer.from(JSON.stringify(assertion), "utf8").toString("base64");

/**
 * A stub {@link SAMLVerifier} standing in for the XML/crypto implementation:
 * it "signs" nothing and reads the assertion straight out of the base64 body,
 * recording every `AuthnRequest` it is asked to build so a test can find the
 * request id core minted.
 */
const stubSAMLVerifier = (requests: SAMLAuthnRequestInput[]): typeof SAMLVerifier.Service => ({
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
      const overrides = JSON.parse(decoded) as Partial<SAMLAssertion>;
      return {
        id: "_assertion-1",
        issuer: input.idpEntityId,
        nameId: "worker@acme.test",
        nameIdFormat: "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
        email: "worker@acme.test",
        displayName: "Worker Bee",
        attributes: {},
        ...overrides,
      } satisfies SAMLAssertion;
    }),
  spMetadataXml: (input) => Effect.succeed(`<EntityDescriptor entityID="${input.spEntityId}"/>`),
});

const makeSAMLFixture = () => {
  const base = makeStores();
  const replayRecords = new Map<string, SAMLReplayRecord>();
  const replay = memorySAMLReplayStore(replayRecords);
  const requests: SAMLAuthnRequestInput[] = [];

  const layer = Layer.mergeAll(
    base.layer,
    Layer.succeed(SAMLVerifier)(stubSAMLVerifier(requests)),
    Layer.succeed(SAMLReplayStore)(replay),
  );

  return { ...base, layer, replay, replayRecords, requests };
};

describe("SSOService — SAML", () => {
  it("starts a SAML sign-in and records the request id one-time", async () => {
    const fx = makeSAMLFixture();
    const sso = await Effect.runPromise(SSO.make().pipe(Effect.provide(fx.layer)));

    const { provider, start } = await Effect.runPromise(
      Effect.gen(function* () {
        const provider = yield* sso.registerSAMLProvider("admin", ACME_SAML);
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
    const fx = makeSAMLFixture();
    const sso = await Effect.runPromise(SSO.make().pipe(Effect.provide(fx.layer)));

    const signIn = (assertionId: string) =>
      Effect.gen(function* () {
        const start = yield* sso.signIn({ email: "worker@acme.test" });
        const requestId = fx.requests[fx.requests.length - 1]?.requestId ?? "";
        return yield* sso.handleSAMLCallback(
          providerId,
          samlResponse({ id: assertionId, inResponseTo: requestId }),
          start.state,
        );
      }).pipe(Effect.provide(fx.layer));

    const providerId = (
      await Effect.runPromise(
        sso.registerSAMLProvider("admin", ACME_SAML).pipe(Effect.provide(fx.layer)),
      )
    ).id;

    const first = await Effect.runPromise(signIn("_a1"));
    expect(first.isNewUser).toBe(true);
    expect(first.provider.protocol).toBe("saml");
    expect(first.session.userId).toBe(first.user.id);
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
    expect(fx.users.size).toBe(1);
    expect(fx.members.length).toBe(1);
  });

  it("refuses to spend the same assertion twice", async () => {
    const fx = makeSAMLFixture();
    const sso = await Effect.runPromise(SSO.make().pipe(Effect.provide(fx.layer)));

    const outcome = await Effect.runPromise(
      Effect.gen(function* () {
        const provider = yield* sso.registerSAMLProvider("admin", ACME_SAML);
        const first = yield* sso.signIn({ email: "worker@acme.test" });
        const firstId = fx.requests[0]?.requestId ?? "";
        const response = samlResponse({ id: "_replayed", inResponseTo: firstId });
        const ok = yield* sso.handleSAMLCallback(provider.id, response, first.state);

        // A captured response, replayed against a *fresh* request so the
        // AuthnRequest check cannot be what stops it.
        const second = yield* sso.signIn({ email: "worker@acme.test" });
        const secondId = fx.requests[1]?.requestId ?? "";
        const replayed = samlResponse({ id: "_replayed", inResponseTo: secondId });
        const err = yield* Effect.flip(sso.handleSAMLCallback(provider.id, replayed, second.state));
        return { ok, err };
      }).pipe(Effect.provide(fx.layer)),
    );

    expect(outcome.ok.isNewUser).toBe(true);
    expect(outcome.err).toBeInstanceOf(SSOError);
    expect((outcome.err as SSOError).message).toMatch(/already been used/);
  });

  it("rejects a response answering an unknown or already-spent request", async () => {
    const fx = makeSAMLFixture();
    const sso = await Effect.runPromise(SSO.make().pipe(Effect.provide(fx.layer)));

    const err = await Effect.runPromise(
      Effect.gen(function* () {
        const provider = yield* sso.registerSAMLProvider("admin", ACME_SAML);
        const start = yield* sso.signIn({ email: "worker@acme.test" });
        return yield* Effect.flip(
          sso.handleSAMLCallback(
            provider.id,
            samlResponse({ inResponseTo: "_never-issued" }),
            start.state,
          ),
        );
      }).pipe(Effect.provide(fx.layer)),
    );
    expect((err as SSOError).message).toMatch(/unknown, expired, or already-used/);
  });

  it("rejects an assertion from a foreign issuer", async () => {
    const fx = makeSAMLFixture();
    const sso = await Effect.runPromise(SSO.make().pipe(Effect.provide(fx.layer)));

    const err = await Effect.runPromise(
      Effect.gen(function* () {
        const provider = yield* sso.registerSAMLProvider("admin", ACME_SAML);
        const start = yield* sso.signIn({ email: "worker@acme.test" });
        const requestId = fx.requests[0]?.requestId ?? "";
        return yield* Effect.flip(
          sso.handleSAMLCallback(
            provider.id,
            samlResponse({ issuer: "https://evil.test/metadata", inResponseTo: requestId }),
            start.state,
          ),
        );
      }).pipe(Effect.provide(fx.layer)),
    );
    expect((err as SSOError).message).toMatch(/does not match this connection/);
  });

  it("rejects a RelayState that does not match the one it minted", async () => {
    const fx = makeSAMLFixture();
    const sso = await Effect.runPromise(SSO.make().pipe(Effect.provide(fx.layer)));

    const err = await Effect.runPromise(
      Effect.gen(function* () {
        const provider = yield* sso.registerSAMLProvider("admin", ACME_SAML);
        yield* sso.signIn({ email: "worker@acme.test" });
        const requestId = fx.requests[0]?.requestId ?? "";
        return yield* Effect.flip(
          sso.handleSAMLCallback(
            provider.id,
            samlResponse({ inResponseTo: requestId }),
            "not-the-relay-state",
          ),
        );
      }).pipe(Effect.provide(fx.layer)),
    );
    expect((err as SSOError).message).toMatch(/RelayState/);
  });

  it("refuses an unsolicited (IdP-initiated) response unless configured for it", async () => {
    const fx = makeSAMLFixture();
    const strict = await Effect.runPromise(SSO.make().pipe(Effect.provide(fx.layer)));
    const permissive = await Effect.runPromise(
      SSO.make({ allowIdpInitiated: true }).pipe(Effect.provide(fx.layer)),
    );

    const providerId = (
      await Effect.runPromise(
        strict.registerSAMLProvider("admin", ACME_SAML).pipe(Effect.provide(fx.layer)),
      )
    ).id;

    const err = await Effect.runPromise(
      Effect.flip(strict.handleSAMLCallback(providerId, samlResponse({ id: "_u1" }))).pipe(
        Effect.provide(fx.layer),
      ),
    );
    expect((err as SSOError).message).toMatch(/IdP-initiated/);

    const ok = await Effect.runPromise(
      permissive
        .handleSAMLCallback(providerId, samlResponse({ id: "_u2" }))
        .pipe(Effect.provide(fx.layer)),
    );
    expect(ok.isNewUser).toBe(true);
  });

  it("keeps the two protocols' callbacks apart", async () => {
    const fx = makeSAMLFixture();
    const sso = await Effect.runPromise(SSO.make().pipe(Effect.provide(fx.layer)));

    const errors = await Effect.runPromise(
      Effect.gen(function* () {
        const oidc = yield* sso.registerProvider("admin", { ...ACME, domain: "oidc.test" });
        const wrongProtocol = yield* Effect.flip(sso.handleSAMLCallback(oidc.id, samlResponse({})));
        const unknown = yield* Effect.flip(sso.handleSAMLCallback("nope", samlResponse({})));
        return { wrongProtocol, unknown };
      }).pipe(Effect.provide(fx.layer)),
    );

    expect((errors.wrongProtocol as SSOError).message).toMatch(/is an OIDC connection/);
    expect((errors.unknown as SSOError).message).toMatch(/not found/);
  });

  it("reports missing SAML support instead of half-working", async () => {
    // No SAMLVerifier / SAMLReplayStore in context: the OIDC half still works,
    // and the SAML half says exactly what is missing.
    const { layer } = makeStores();
    const sso = await Effect.runPromise(SSO.make().pipe(Effect.provide(layer)));

    const err = await Effect.runPromise(
      Effect.gen(function* () {
        const provider = yield* sso.registerSAMLProvider("admin", ACME_SAML);
        return yield* Effect.flip(sso.signIn({ providerId: provider.id }));
      }).pipe(Effect.provide(layer)),
    );
    expect((err as SSOError).message).toMatch(/SAML support is not installed/);
  });

  it("validates a SAML registration before storing it", async () => {
    const fx = makeSAMLFixture();
    const sso = await Effect.runPromise(SSO.make().pipe(Effect.provide(fx.layer)));

    const errors = await Effect.runPromise(
      Effect.gen(function* () {
        const noCerts = yield* Effect.flip(
          sso.registerSAMLProvider("admin", { ...ACME_SAML, idpCertificates: [] }),
        );
        const badUrl = yield* Effect.flip(
          sso.registerSAMLProvider("admin", { ...ACME_SAML, acsUrl: "/relative" }),
        );
        return { noCerts, badUrl };
      }).pipe(Effect.provide(fx.layer)),
    );

    expect((errors.noCerts as SSOError).message).toMatch(/idpCertificates must not be empty/);
    expect((errors.badUrl as SSOError).message).toMatch(/acsUrl must be an absolute URL/);
    expect(fx.providers.size).toBe(0);
  });

  it("renders SP metadata for a connection", async () => {
    const fx = makeSAMLFixture();
    const sso = await Effect.runPromise(SSO.make().pipe(Effect.provide(fx.layer)));

    const xml = await Effect.runPromise(
      Effect.gen(function* () {
        const provider = yield* sso.registerSAMLProvider("admin", ACME_SAML);
        return yield* sso.samlMetadata(provider.id);
      }).pipe(Effect.provide(fx.layer)),
    );
    expect(xml).toContain(SAML_SP);
  });
});

describe("memorySAMLReplayStore", () => {
  const record = (id: string, expiresAt: number): SAMLReplayRecord => ({
    id,
    kind: "assertion",
    providerId: "p1",
    createdAt: Date.now(),
    expiresAt,
  });

  it("inserts if absent and reports a duplicate as null", async () => {
    const store = memorySAMLReplayStore();
    expect(await Effect.runPromise(store.create(record("a", Date.now() + 60_000)))).not.toBeNull();
    expect(await Effect.runPromise(store.create(record("a", Date.now() + 60_000)))).toBeNull();
  });

  it("lets an expired id be re-used, since the window it guarded has passed", async () => {
    const store = memorySAMLReplayStore();
    await Effect.runPromise(store.create(record("a", Date.now() - 1)));
    expect(await Effect.runPromise(store.create(record("a", Date.now() + 60_000)))).not.toBeNull();
  });

  it("consumes exactly once, and treats an expired record as absent", async () => {
    const store = memorySAMLReplayStore();
    await Effect.runPromise(store.create(record("a", Date.now() + 60_000)));
    expect(await Effect.runPromise(store.consume("a"))).not.toBeNull();
    expect(await Effect.runPromise(store.consume("a"))).toBeNull();

    await Effect.runPromise(store.create(record("b", Date.now() - 1)));
    expect(await Effect.runPromise(store.consume("b"))).toBeNull();
    expect(await Effect.runPromise(store.consume("missing"))).toBeNull();
  });
});

// --- HTTP layer --------------------------------------------------------------

/** A web handler wired with the SSO endpoints over in-memory stores. */
const makeHttpFixture = () => {
  const usersById = new Map<string, Types.User>();
  const identifierRecords = new Map<string, Identifier>();
  const identifierStore = memoryIdentifierStore(identifierRecords);
  const sessions = new Map<string, Types.Session>();
  const providers = new Map<string, SSOProvider>();
  const states = new Map<string, OAuthState>();
  const members: Member[] = [];
  let userSeq = 0;

  const seedUser = (email: string, attributes: Record<string, unknown> = {}): string => {
    const id = `u${++userSeq}`;
    const now = new Date();
    const user: Types.User = {
      id,
      createdAt: now,
      updatedAt: now,
      attributes,
    };
    usersById.set(id, user);
    const identifier = makeIdentifier({
      userId: id,
      type: "email",
      value: email,
      verified: true,
      verifiedAt: now,
    });
    identifierRecords.set(identifier.id, identifier);
    return id;
  };
  const makeSession = (userId: string): string => {
    const rawToken = Buffer.from(globalThis.crypto.getRandomValues(new Uint8Array(12))).toString(
      "hex",
    );
    const tokenHash = hashToken(rawToken);
    const now = new Date();
    sessions.set(tokenHash, {
      id: tokenHash,
      userId,
      expiresAt: new Date(Date.now() + 3600_000),
      createdAt: now,
      lastActivityAt: now,
      attributes: {},
    });
    return rawToken;
  };

  const userStore = {
    get: (userId: string) => Effect.sync(() => usersById.get(userId) ?? null),
    getCredentials: (_userId: string) => Effect.succeed(null),
  };
  const userServiceStore = {
    get: userStore.get,
    update: (user: Types.User) => Effect.sync(() => (usersById.set(user.id, user), user)),
    delete: () => Effect.void,
  };
  const sessionStore = {
    create: (s: Types.Session) => Effect.sync(() => (sessions.set(s.id, s), s)),
    get: (id: string) => Effect.sync(() => sessions.get(id) ?? null),
    update: (s: Types.Session) => Effect.sync(() => (sessions.set(s.id, s), s)),
    delete: (id: string) => Effect.sync(() => void sessions.delete(id)),
    deleteByUserId: (userId: string) =>
      Effect.sync(() => {
        for (const [id, s] of sessions) if (s.userId === userId) sessions.delete(id);
      }),
    listByUserId: (userId: string) =>
      Effect.sync(() => [...sessions.values()].filter((s) => s.userId === userId)),
  };
  const oauthUserStore = {
    getUser: (userId: string) => {
      const u = usersById.get(userId);
      return u ? Effect.succeed(u) : Effect.fail(new UserNotFoundError({ message: "nf", userId }));
    },
    createUser: (input: { name?: string; image?: string }) =>
      Effect.sync(() => {
        const id = `u${++userSeq}`;
        const now = new Date();
        const user: Types.User = {
          id,
          ...(input.name !== undefined && { name: input.name }),
          ...(input.image !== undefined && { image: input.image }),
          createdAt: now,
          updatedAt: now,
          attributes: {},
        };
        usersById.set(id, user);
        return user;
      }),
  };
  const ssoStore: typeof SSOProviderStore.Service = {
    create: (p) => Effect.sync(() => (providers.set(p.id, p), p)),
    getById: (id) => Effect.succeed(providers.get(id) ?? null),
    getByDomain: (domain) =>
      Effect.succeed([...providers.values()].find((p) => p.domain === domain) ?? null),
    list: () => Effect.succeed([...providers.values()]),
  };
  const stateStore = {
    create: (s: OAuthState) => Effect.sync(() => (states.set(s.state, s), s)),
    get: (state: string) => Effect.succeed(states.get(state) ?? null),
    delete: (state: string) => Effect.sync(() => void states.delete(state)),
  };
  // SSO only ever calls getMember/createMember; the rest are unused stubs.
  const orgStore = {
    createMember: (m: Member) => Effect.sync(() => (members.push(m), m)),
    getMember: (organizationId: string, userId: string) =>
      Effect.succeed(
        members.find((m) => m.organizationId === organizationId && m.userId === userId) ?? null,
      ),
  };

  const coreStoreLayer = Layer.mergeAll(
    Layer.succeed(SessionStore)(sessionStore as never),
    Layer.succeed(UserStore)(userStore),
  );

  const sessionServiceLayer = SessionService.layer({
    sessionExpiresIn: { activePeriod: 3600_000, idlePeriod: 3600_000 },
  }).pipe(Layer.provide(Layer.mergeAll(coreStoreLayer, Hooks.Default)));

  const base = Layer.mergeAll(
    sessionServiceLayer,
    UserService.layer().pipe(Layer.provide(Layer.succeed(UserServiceStore)(userServiceStore))),
    Layer.succeed(UserServiceStore)(userServiceStore),
    Layer.succeed(IdentifierStore)(identifierStore),
    Hooks.Default,
    Layer.succeed(AuthLifecycleService)(undefined as never),
    Layer.succeed(EmailPasswordService)(undefined as never),
    Layer.succeed(PasswordHasher)(undefined as never),
    Layer.succeed(EmailVerificationService)(undefined as never),
    Layer.succeed(PasswordResetService)(undefined as never),
  );

  // `SSOService` only needs `SSOProviderStore` to construct; `OAuthStateStore`/
  // `OAuthUserStore`/`IdentifierStore`/`UserStore`/`SessionService`/
  // `Crypto.Crypto` are required dynamically by its `signIn`/`handleCallback`
  // methods, and `OrganizationStore` is resolved optionally at call time — all
  // are provided here as ambient context.
  // SAML is resolved optionally by `SSOService`, so the HTTP fixture installs
  // the same stub verifier the service-level tests use plus an in-memory
  // replay store — that is exactly what an app installing
  // `@thomasfosterau/effect-auth-saml` would provide.
  const samlRequests: SAMLAuthnRequestInput[] = [];
  const ssoDeps = Layer.mergeAll(
    Layer.succeed(SSOProviderStore)(ssoStore),
    Layer.succeed(OAuthStateStore)(stateStore),
    Layer.succeed(OAuthUserStore)(oauthUserStore),
    Layer.succeed(IdentifierStore)(identifierStore),
    Layer.succeed(UserStore)(userStore),
    Layer.succeed(OrganizationStore)(orgStore as never),
    Layer.succeed(SAMLVerifier)(stubSAMLVerifier(samlRequests)),
    Layer.succeed(SAMLReplayStore)(memorySAMLReplayStore()),
    PlatformCrypto.layer,
  );

  const ssoServiceLayer = SSOService.layer().pipe(Layer.provide(ssoDeps));

  const ssoLayer = Layer.mergeAll(ssoDeps, ssoServiceLayer);

  const withSSO = Layer.mergeAll(base, ssoLayer) as Layer.Layer<AuthServices>;
  const withoutSSO = base as Layer.Layer<AuthServices>;

  return {
    seedUser,
    makeSession,
    handler: HTTPServer.make({ services: withSSO, cookie: { secure: false } }).handler,
    handlerWithoutSSO: HTTPServer.make({ services: withoutSSO, cookie: { secure: false } }).handler,
    providers,
    identifierRecords,
    samlRequests,
  };
};

const post = (path: string, body: unknown, sessionId?: string): Request =>
  new Request(`http://test${path}`, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      ...(sessionId !== undefined ? { cookie: `conduit_session=${sessionId}` } : {}),
    },
    body: JSON.stringify(body),
  });

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
    const denied = await fx.handler(post("/sso/register", REGISTER_BODY, nonAdminSid));
    expect(denied.status).toBe(403);

    // Admin registers the connection (secret is never echoed back).
    const registered = await fx.handler(post("/sso/register", REGISTER_BODY, adminSid));
    expect(registered.status).toBe(200);
    const provider = (await registered.json()) as Record<string, unknown>;
    expect(provider["domain"]).toBe("acme.test");
    expect(provider).not.toHaveProperty("clientSecret");

    // Anonymous sign-in resolves the IdP URL by email domain.
    const signIn = await fx.handler(post("/sign-in/sso", { email: "worker@acme.test" }));
    expect(signIn.status).toBe(200);
    const { url, state } = (await signIn.json()) as { url: string; state: string };
    expect(new URL(url).origin).toBe("https://idp.acme.test");

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
      () => fx.handler(post("/sso/callback", { state, code: "auth-code" })),
    );
    expect(callback.status).toBe(200);
    expect(callback.headers.get("set-cookie")).toContain("conduit_session=");
    expect(((await callback.json()) as { user: { email: string } }).user.email).toBe(
      "worker@acme.test",
    );
  });

  it("returns 404 when SSO is not configured", async () => {
    const fx = makeHttpFixture();
    const res = await fx.handlerWithoutSSO(post("/sign-in/sso", { email: "a@b.test" }));
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

/** The IdP's ACS POST: an `application/x-www-form-urlencoded` browser form. */
const acsPost = (providerId: string, fields: Record<string, string>): Request =>
  new Request(`http://test/sso/saml/acs/${providerId}`, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams(fields).toString(),
  });

describe("HTTP SSO endpoints — SAML", () => {
  it("registers a SAML connection through the same admin-gated endpoint", async () => {
    const fx = makeHttpFixture();
    const adminSid = fx.makeSession(fx.seedUser("admin@acme.test", { role: "admin" }));

    const registered = await fx.handler(post("/sso/register", SAML_REGISTER_BODY, adminSid));
    expect(registered.status).toBe(200);
    const provider = (await registered.json()) as Record<string, unknown>;
    expect(provider["protocol"]).toBe("saml");
    expect(provider["entityId"]).toBe(SAML_IDP);
    expect(provider["idpCertificates"]).toEqual(SAML_REGISTER_BODY.idpCertificates);
    // The SAML arm has no client secret to leak, and neither arm echoes the
    // registrar's user id.
    expect(provider).not.toHaveProperty("clientSecret");
    expect(provider).not.toHaveProperty("userId");
    expect(fx.providers.size).toBe(1);
  });

  it("still registers an OIDC connection when the body carries no protocol", async () => {
    const fx = makeHttpFixture();
    const adminSid = fx.makeSession(fx.seedUser("admin@acme.test", { role: "admin" }));

    const registered = await fx.handler(post("/sso/register", REGISTER_BODY, adminSid));
    expect(registered.status).toBe(200);
    const provider = (await registered.json()) as Record<string, unknown>;
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
      post("/sso/register", { ...SAML_REGISTER_BODY, idpCertificates: [] }, adminSid),
    );
    expect(res.status).toBe(400);
    expect(((await res.json()) as { message: string }).message).toMatch(/idpCertificates/);
  });

  it("completes the ACS form POST and issues a session cookie", async () => {
    const fx = makeHttpFixture();
    const adminSid = fx.makeSession(fx.seedUser("admin@acme.test", { role: "admin" }));

    const registered = await fx.handler(post("/sso/register", SAML_REGISTER_BODY, adminSid));
    const { id: providerId } = (await registered.json()) as { id: string };

    // Start the flow so the AuthnRequest id is banked, exactly as a browser
    // redirect would.
    const signIn = await fx.handler(post("/sign-in/sso", { email: "worker@acme.test" }));
    expect(signIn.status).toBe(200);
    const { state } = (await signIn.json()) as { url: string; state: string };
    const requestId = fx.samlRequests[fx.samlRequests.length - 1]?.requestId ?? "";

    const acs = await fx.handler(
      acsPost(providerId, {
        SAMLResponse: samlResponse({ id: "_http-a1", inResponseTo: requestId }),
        RelayState: state,
      }),
    );
    expect(acs.status).toBe(200);
    expect(acs.headers.get("set-cookie")).toContain("conduit_session=");
    expect(((await acs.json()) as { user: { email: string } }).user.email).toBe("worker@acme.test");
  });

  it("answers 400 when the ACS response cannot be trusted", async () => {
    const fx = makeHttpFixture();
    const adminSid = fx.makeSession(fx.seedUser("admin@acme.test", { role: "admin" }));
    const registered = await fx.handler(post("/sso/register", SAML_REGISTER_BODY, adminSid));
    const { id: providerId } = (await registered.json()) as { id: string };

    // No AuthnRequest was ever issued, so there is nothing to spend.
    const res = await fx.handler(
      acsPost(providerId, { SAMLResponse: samlResponse({ inResponseTo: "_never-issued" }) }),
    );
    expect(res.status).toBe(400);
    expect(res.headers.get("set-cookie")).toBeNull();
  });

  it("serves SP metadata as XML", async () => {
    const fx = makeHttpFixture();
    const adminSid = fx.makeSession(fx.seedUser("admin@acme.test", { role: "admin" }));
    const registered = await fx.handler(post("/sso/register", SAML_REGISTER_BODY, adminSid));
    const { id: providerId } = (await registered.json()) as { id: string };

    const res = await fx.handler(
      new Request(`http://test/sso/saml/metadata/${providerId}`, { method: "GET" }),
    );
    expect(res.status).toBe(200);
    expect(res.headers.get("content-type")).toContain("application/samlmetadata+xml");
    expect(await res.text()).toContain(SAML_SP);
  });

  it("answers 400 for metadata on an OIDC connection", async () => {
    const fx = makeHttpFixture();
    const adminSid = fx.makeSession(fx.seedUser("admin@acme.test", { role: "admin" }));
    const registered = await fx.handler(post("/sso/register", REGISTER_BODY, adminSid));
    const { id: providerId } = (await registered.json()) as { id: string };

    const res = await fx.handler(
      new Request(`http://test/sso/saml/metadata/${providerId}`, { method: "GET" }),
    );
    expect(res.status).toBe(400);
  });

  it("returns 404 on the SAML routes when SSO is not configured", async () => {
    const fx = makeHttpFixture();
    const res = await fx.handlerWithoutSSO(
      new Request("http://test/sso/saml/metadata/anything", { method: "GET" }),
    );
    expect(res.status).toBe(404);
  });
});
