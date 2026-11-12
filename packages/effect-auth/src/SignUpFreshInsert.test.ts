/**
 * Every flow that creates a user through {@link createUserWithIdentifier}
 * refuses a store whose `createUser` returns a user that already existed
 * (`created: false`), and writes nothing to that user (#406).
 *
 * Each case drives one flow to its create seam with the same writer: it
 * returns the existing owner of the address, whose unverified identifier lands
 * between the flow's own lookup and its insert, and reports `created: false`.
 * Each flow must then fail, leave the owner's identifier as it was, and mint no
 * session.
 */
import { describe, expect, it } from "vite-plus/test";
import { EmailPasswordStore } from "./email/EmailPassword.ts";
import { memoryEmailPasswordStore, memoryOtpFailures } from "./testing/MemoryStores.ts";
import { Clock, DateTime, Effect, Layer, MutableHashMap } from "effect";
import * as Arr from "effect/Array";
import * as Option from "effect/Option";
import * as Schema from "effect/Schema";
import * as Cipher from "./Cipher.ts";
import { UserNotFoundError } from "./Errors.ts";
import { Hooks } from "./Hooks.ts";
import {
  type Identifier,
  IdentifierStore,
  type IdentifierType,
  makeIdentifier,
  memoryIdentifierStore,
} from "./Identifier.ts";
import * as PlatformCrypto from "./PlatformCrypto.ts";
import { SessionService } from "./SessionService.ts";
import { hashToken } from "./TokenHash.ts";
import { type CreateUserResult, UserStore } from "./UserStore.ts";
import * as MagicLink from "./MagicLink.ts";
import * as EmailOtp from "./email/EmailOtp.ts";
import * as PhoneOtp from "./PhoneOtp.ts";
import * as GoogleOneTap from "./GoogleOneTap.ts";
import * as Sso from "./Sso.ts";
import * as Scim from "./Scim.ts";
import { OAuthStateStore, type OAuthState, OAuthUserStore } from "./oauth/OAuth.ts";
import {
  memorySamlReplayStore,
  SamlReplayStore,
  SamlVerifier,
  type SamlAssertion,
  type SamlAuthnRequestInput,
} from "./Saml.ts";
import { type Member, OrganizationStore } from "./Organization.ts";
import type * as Types from "./Types.ts";

const EMAIL = "owner@acme.test";
const PHONE = "+15555550123";

/** What every case shares: the owner, the identifier store and the recorders. */
const makeWorld = (type: IdentifierType, value: string) => {
  const owner: Types.User = {
    id: "owner",
    createdAt: DateTime.toDateUtc(DateTime.nowUnsafe()),
    updatedAt: DateTime.toDateUtc(DateTime.nowUnsafe()),
    attributes: {},
  };
  const users = MutableHashMap.fromIterable<string, Types.User>([[owner.id, owner]]);
  const identifierRecords = MutableHashMap.empty<string, Identifier>();
  const identifiers = memoryIdentifierStore(identifierRecords);
  const sessionsFor: string[] = [];
  /** Memberships a flow writes after its create (SCIM), recorded per world. */
  const members: Member[] = [];
  let writes = 0;

  /**
   * A writer that finds or creates on the address: the owner's row (and its
   * unverified identifier) appears after the flow's lookup, and the writer
   * hands that row back as an existing user.
   */
  const createUser = (): Effect.Effect<CreateUserResult> =>
    Effect.sync(() => {
      writes++;
      const held = makeIdentifier({
        userId: owner.id,
        type,
        value,
        verified: false,
        now: DateTime.toDateUtc(DateTime.nowUnsafe()),
      });
      MutableHashMap.set(identifierRecords, held.id, held);
      return { user: owner, created: false };
    });

  const sessionManager: typeof SessionService.Service = {
    createSession: (userId) =>
      Effect.sync(() => {
        sessionsFor.push(userId);
        return {
          id: `s-${userId}`,
          userId,
          expiresAt: DateTime.toDateUtc(
            DateTime.add(DateTime.nowUnsafe(), { milliseconds: 3600_000 }),
          ),
          createdAt: DateTime.toDateUtc(DateTime.nowUnsafe()),
          lastActivityAt: DateTime.toDateUtc(DateTime.nowUnsafe()),
          attributes: {},
        };
      }),
    validateSession: () => Effect.die("unused"),
    invalidateSession: () => Effect.die("unused"),
    invalidateUserSessions: () => Effect.void,
    listSessions: () => Effect.succeed([]),
    revokeSessionById: () => Effect.succeed(false),
    revokeOtherSessions: () => Effect.void,
    setSessionAttributes: () => Effect.die("unused"),
  };

  const base = Layer.mergeAll(
    Layer.succeed(IdentifierStore)(identifiers),
    Layer.succeed(UserStore)({
      get: (userId) => Effect.sync(() => Option.getOrNull(MutableHashMap.get(users, userId))),
    }),
    Layer.succeed(SessionService)(sessionManager),
    Layer.succeed(EmailPasswordStore)(memoryEmailPasswordStore()),
    Hooks.Default,
    PlatformCrypto.layer,
  );

  return {
    owner,
    base,
    createUser,
    identifierRecords,
    members,
    sessionsFor,
    writes: () => writes,
  };
};

type World = ReturnType<typeof makeWorld>;

/** A one-time-code store keyed by the address and purpose, as both OTP flows use. */
const memoryOtpStore = <R extends { readonly purpose: string; readonly attempts: number }>(
  keyOf: (record: R) => string,
) => {
  const records = MutableHashMap.empty<string, R>();
  const key = (address: string, purpose: string) => `${address}:${purpose}`;
  return {
    upsert: (record: R) =>
      Effect.sync(
        () => (MutableHashMap.set(records, key(keyOf(record), record.purpose), record), record),
      ),
    get: (address: string, purpose: string) =>
      Effect.sync(() => Option.getOrNull(MutableHashMap.get(records, key(address, purpose)))),
    delete: (address: string, purpose: string) =>
      Effect.sync(() => void MutableHashMap.remove(records, key(address, purpose))),
    incrementAttempts: (address: string, purpose: string) =>
      Effect.sync(() => {
        const record = Option.getOrUndefined(MutableHashMap.get(records, key(address, purpose)));
        if (record === undefined) return 0;
        const attempts = record.attempts + 1;
        MutableHashMap.set(records, key(address, purpose), { ...record, attempts });
        return attempts;
      }),
    ...memoryOtpFailures<string>(),
  };
};

const encodeJson = Schema.encodeSync(Schema.fromJsonString(Schema.Unknown));

// --- Google One Tap: a fake Google signing the credential --------------------

const ONE_TAP_CLIENT = "client-1.apps.googleusercontent.com";
const ONE_TAP_JWKS = "https://fake-google.test/fresh-insert/certs";
const oneTapKeys = Cipher.generateJwsKeyPair("ES256");

const b64 = (value: Schema.Json): string =>
  Buffer.from(encodeJson(value), "utf8").toString("base64url");

const signGoogleCredential = (nonce: string): string => {
  const header = { alg: "ES256", kid: "k1", typ: "JWT" };
  const claims = {
    iss: "https://accounts.google.com",
    aud: ONE_TAP_CLIENT,
    sub: "google-owner",
    email: EMAIL,
    email_verified: true,
    nonce: hashToken(nonce),
    exp: Math.floor(DateTime.toEpochMillis(DateTime.nowUnsafe()) / 1000) + 300,
    iat: Math.floor(DateTime.toEpochMillis(DateTime.nowUnsafe()) / 1000),
  };
  const signingInput = `${b64(header)}.${b64(claims)}`;
  const signature = Cipher.signJws(
    "ES256",
    Buffer.from(signingInput, "utf8"),
    oneTapKeys.privateKeyPem,
  );
  return `${signingInput}.${Buffer.from(signature).toString("base64url")}`;
};

/** Answer the JWKS request with the fake Google's key while `thunk` runs. */
const withGoogleJwks = <A>(thunk: () => Promise<A>): Promise<A> => {
  const original = globalThis.fetch;
  const jwks = { keys: [{ ...oneTapKeys.publicKeyJwk, kid: "k1", alg: "ES256" }] };
  globalThis.fetch = () =>
    Promise.resolve(
      new Response(encodeJson(jwks), { headers: { "content-type": "application/json" } }),
    );
  return new Promise<A>((resolve) => resolve(thunk())).finally(() => {
    globalThis.fetch = original;
  });
};

// --- SSO: a SAML connection with a stub verifier ------------------------------

/** The assertion fields a case overrides, as the stub reads them from the body. */
const decodeAssertionOverrides = Schema.decodeUnknownSync(
  Schema.fromJsonString(Schema.Struct({ inResponseTo: Schema.optionalKey(Schema.String) })),
);

/** Reads the assertion straight out of the base64 body (no XML, no crypto). */
const stubSamlVerifier = (requests: SamlAuthnRequestInput[]): typeof SamlVerifier.Service => ({
  buildAuthnRequest: (input) => {
    requests.push(input);
    return Effect.succeed({ url: input.ssoUrl, requestId: input.requestId });
  },
  verify: (input) =>
    Effect.sync(() => {
      const overrides = decodeAssertionOverrides(
        Buffer.from(input.samlResponse, "base64").toString("utf8"),
      );
      return {
        id: "_assertion-1",
        issuer: input.idpEntityId,
        nameId: EMAIL,
        nameIdFormat: "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
        email: EMAIL,
        attributes: {},
        ...overrides,
      } satisfies SamlAssertion;
    }),
  spMetadataXml: () => Effect.succeed("<EntityDescriptor/>"),
});

const oauthUserStore = (world: World): typeof OAuthUserStore.Service => ({
  getUser: (userId) =>
    userId === world.owner.id
      ? Effect.succeed(world.owner)
      : Effect.fail(new UserNotFoundError({ message: "nf", userId })),
  createUser: world.createUser,
});

interface Case {
  readonly flow: string;
  readonly type: IdentifierType;
  readonly value: string;
  /** Drive the flow to its create seam and return its failure's `_tag`. */
  readonly run: (world: World) => Promise<string>;
  /** Writes the flow makes after a create, beyond the identifier and session. */
  readonly extraWrites?: (world: World) => ReadonlyArray<unknown>;
}

const cases: ReadonlyArray<Case> = [
  {
    flow: "MagicLink.verify",
    type: "email",
    value: EMAIL,
    run: (world) => {
      const sent: string[] = [];
      const tokens = MutableHashMap.empty<string, MagicLink.MagicLinkToken>();
      const layer = Layer.mergeAll(
        world.base,
        Layer.succeed(MagicLink.MagicLinkStore)({
          create: (token) =>
            Effect.sync(() => (MutableHashMap.set(tokens, token.token, token), token)),
          get: (token) => Effect.sync(() => Option.getOrNull(MutableHashMap.get(tokens, token))),
          getByEmail: () => Effect.succeed(null),
          delete: (token) => Effect.sync(() => void MutableHashMap.remove(tokens, token)),
          deleteByEmail: () => Effect.void,
        }),
        Layer.succeed(MagicLink.MagicLinkUserStore)({ createUser: world.createUser }),
      );
      return Effect.runPromise(
        Effect.gen(function* () {
          const service = yield* MagicLink.make({
            sendMagicLink: (_email, token) => Effect.sync(() => void sent.push(token)),
          });
          yield* service.send(EMAIL);
          const error = yield* Effect.flip(service.verify(sent[0] ?? ""));
          return error._tag;
        }).pipe(Effect.provide(layer)),
      );
    },
  },
  {
    flow: "EmailOtp.signIn",
    type: "email",
    value: EMAIL,
    run: (world) => {
      const sent: string[] = [];
      const layer = Layer.mergeAll(
        world.base,
        Layer.succeed(EmailOtp.EmailOtpStore)(
          memoryOtpStore<EmailOtp.EmailOtpRecord>((record) => record.email),
        ),
        Layer.succeed(EmailOtp.EmailOtpUserStore)({ createUser: world.createUser }),
      );
      return Effect.runPromise(
        Effect.gen(function* () {
          const service = yield* EmailOtp.make({
            sendVerificationOtp: (_email, otp) => Effect.sync(() => void sent.push(otp)),
          });
          yield* service.send(EMAIL, "sign-in");
          const error = yield* Effect.flip(service.signIn(EMAIL, sent[0] ?? ""));
          return error._tag;
        }).pipe(Effect.provide(layer)),
      );
    },
  },
  {
    flow: "PhoneOtp.signIn",
    type: "phone",
    value: PHONE,
    run: (world) => {
      const sent: string[] = [];
      const layer = Layer.mergeAll(
        world.base,
        Layer.succeed(PhoneOtp.PhoneOtpStore)(
          memoryOtpStore<PhoneOtp.PhoneOtpRecord>((record) => record.phoneNumber),
        ),
        Layer.succeed(PhoneOtp.PhoneOtpUserStore)({ createUser: world.createUser }),
      );
      return Effect.runPromise(
        Effect.gen(function* () {
          const service = yield* PhoneOtp.make({
            sendOtp: (_phone, otp) => Effect.sync(() => void sent.push(otp)),
          });
          yield* service.send(PHONE, "sign-in");
          const error = yield* Effect.flip(service.signIn(PHONE, sent[0] ?? ""));
          return error._tag;
        }).pipe(Effect.provide(layer)),
      );
    },
  },
  {
    flow: "GoogleOneTap.signIn",
    type: "email",
    value: EMAIL,
    run: (world) => {
      const nonces = MutableHashMap.empty<string, number>();
      const layer = Layer.mergeAll(
        world.base,
        Layer.succeed(GoogleOneTap.GoogleOneTapNonceStore)({
          create: (nonce, expiresAt) =>
            Effect.sync(() => void MutableHashMap.set(nonces, nonce, expiresAt)),
          get: (nonce) =>
            Effect.sync(() => {
              const expiresAt = Option.getOrUndefined(MutableHashMap.get(nonces, nonce));
              return expiresAt === undefined ? null : { expiresAt };
            }),
          delete: (nonce) => Effect.sync(() => void MutableHashMap.remove(nonces, nonce)),
        }),
        Layer.succeed(OAuthUserStore)(oauthUserStore(world)),
      );
      return withGoogleJwks(() =>
        Effect.runPromise(
          Effect.gen(function* () {
            const service = yield* GoogleOneTap.make({
              clientId: ONE_TAP_CLIENT,
              jwksEndpoint: ONE_TAP_JWKS,
            });
            const nonce = yield* service.createNonce();
            const error = yield* Effect.flip(service.signIn(signGoogleCredential(nonce), nonce));
            return error._tag;
          }).pipe(Effect.provide(layer)),
        ),
      );
    },
  },
  {
    flow: "Sso.handleSamlCallback",
    type: "email",
    value: EMAIL,
    run: (world) => {
      const providers = MutableHashMap.empty<string, Sso.SsoProvider>();
      const states = MutableHashMap.empty<string, OAuthState>();
      const requests: SamlAuthnRequestInput[] = [];
      const layer = Layer.mergeAll(
        world.base,
        Layer.succeed(Sso.SsoProviderStore)({
          create: (provider) =>
            Effect.sync(() => (MutableHashMap.set(providers, provider.id, provider), provider)),
          getById: (id) => Effect.succeed(Option.getOrNull(MutableHashMap.get(providers, id))),
          getByDomain: (domain) =>
            Effect.succeed(
              Arr.fromIterable(MutableHashMap.values(providers)).find((p) => p.domain === domain) ??
                null,
            ),
          list: () => Effect.succeed(Arr.fromIterable(MutableHashMap.values(providers))),
        }),
        Layer.succeed(OAuthStateStore)({
          create: (state) =>
            Effect.sync(() => (MutableHashMap.set(states, state.state, state), state)),
          get: (state) => Effect.succeed(Option.getOrNull(MutableHashMap.get(states, state))),
          delete: (state) => Effect.sync(() => void MutableHashMap.remove(states, state)),
        }),
        Layer.succeed(OAuthUserStore)(oauthUserStore(world)),
        Layer.succeed(SamlVerifier)(stubSamlVerifier(requests)),
        Layer.succeed(SamlReplayStore)(memorySamlReplayStore()),
      );
      return Effect.runPromise(
        Effect.gen(function* () {
          const sso = yield* Sso.make();
          const provider = yield* sso.registerSamlProvider("admin", {
            protocol: "saml",
            domain: "acme.test",
            entityId: "https://idp.acme.test/metadata",
            ssoUrl: "https://idp.acme.test/sso",
            idpCertificates: ["-----BEGIN CERTIFICATE-----\nZmFrZQ==\n-----END CERTIFICATE-----"],
            spEntityId: "https://app.test/saml/metadata",
            acsUrl: "https://app.test/api/auth/sso/saml/acs",
          });
          const start = yield* sso.signIn({ email: EMAIL });
          const inResponseTo = requests[0]?.requestId ?? "";
          const response = Buffer.from(encodeJson({ inResponseTo }), "utf8").toString("base64");
          const error = yield* Effect.flip(
            sso.handleSamlCallback(provider.id, response, start.state),
          );
          return error._tag;
        }).pipe(Effect.provide(layer)),
      );
    },
  },
  {
    flow: "Scim.createUser",
    type: "email",
    value: EMAIL,
    run: (world) => {
      // SCIM reads and writes memberships after the create; any other
      // organization call dies.
      const unused = (name: string) => () => Effect.die(`unused: ${name}`);
      const orgs: typeof OrganizationStore.Service = {
        getMember: () => Effect.succeed(null),
        getMemberById: () => Effect.succeed(null),
        createMember: (member: Member) => Effect.sync(() => (world.members.push(member), member)),
        createOrganization: unused("createOrganization"),
        getOrganizationById: unused("getOrganizationById"),
        getOrganizationBySlug: unused("getOrganizationBySlug"),
        updateOrganization: unused("updateOrganization"),
        deleteOrganization: unused("deleteOrganization"),
        updateMember: unused("updateMember"),
        deleteMember: unused("deleteMember"),
        listMembersByOrganization: unused("listMembersByOrganization"),
        listMembersByUser: unused("listMembersByUser"),
        countMembersByOrganization: unused("countMembersByOrganization"),
        createInvitation: unused("createInvitation"),
        getInvitation: unused("getInvitation"),
        updateInvitation: unused("updateInvitation"),
        listInvitationsByOrganization: unused("listInvitationsByOrganization"),
        listInvitationsByEmail: unused("listInvitationsByEmail"),
        createTeam: unused("createTeam"),
        getTeam: unused("getTeam"),
        updateTeam: unused("updateTeam"),
        deleteTeam: unused("deleteTeam"),
        listTeams: unused("listTeams"),
        addTeamMember: unused("addTeamMember"),
        getTeamMemberById: unused("getTeamMemberById"),
        removeTeamMember: unused("removeTeamMember"),
        listTeamMembers: unused("listTeamMembers"),
        listTeamsForMember: unused("listTeamsForMember"),
        upsertOrgRole: unused("upsertOrgRole"),
        getOrgRole: unused("getOrgRole"),
        getOrgRoleById: unused("getOrgRoleById"),
        listOrgRoles: unused("listOrgRoles"),
        deleteOrgRole: unused("deleteOrgRole"),
      };
      const layer = Layer.mergeAll(
        world.base,
        Layer.succeed(Scim.ScimConnectionStore)(Scim.memoryScimConnectionStore()),
        Layer.succeed(Scim.ScimUserStore)({
          create: world.createUser,
          get: (userId) => Effect.succeed(userId === world.owner.id ? world.owner : null),
          update: (user) => Effect.die(`unexpected update of ${user.id}`),
        }),
        Layer.succeed(OrganizationStore)(orgs),
      );
      return Effect.runPromise(
        Effect.gen(function* () {
          const scim = yield* Scim.make();
          const connection: Scim.ScimConnection = {
            id: "conn-1",
            organizationId: "org-1",
            tokenHash: hashToken("token"),
            createdAt: yield* Clock.currentTimeMillis,
          };
          const error = yield* Effect.flip(scim.createUser(connection, { userName: EMAIL }));
          return error._tag;
        }).pipe(Effect.provide(layer)),
      );
    },
    extraWrites: (world) => world.members,
  },
];

describe("a store whose createUser reports created: false", () => {
  it.each(cases)(
    "$flow fails and writes nothing to the existing user",
    async ({ flow, type, value, run, extraWrites }) => {
      const world = makeWorld(type, value);

      const tag = await run(world);

      // The flow reached its create seam, then refused the user it returned.
      expect(world.writes()).toBe(1);
      // Each flow answers with its own error (`MagicLink` → `MagicLinkError`).
      expect(tag).toBe(`${flow.split(".")[0]}Error`);
      // The owner's identifier is as the writer left it: not re-claimed, not
      // verified. No session, and nothing else written.
      expect(
        Arr.fromIterable(MutableHashMap.values(world.identifierRecords)).map(
          ({ userId, verified }) => ({ userId, verified }),
        ),
      ).toEqual([{ userId: world.owner.id, verified: false }]);
      expect(world.sessionsFor).toEqual([]);
      expect(extraWrites?.(world) ?? []).toEqual([]);
    },
  );
});
