/**
 * Deleting a user deletes what they hold, end to end: every API and
 * HTTP route that deletes a user, over the in-memory stores holding one
 * credential of every kind (and a pending magic link and one-time codes for
 * its addresses) for the user being deleted and for a bystander.
 */
import { sha256Hex } from "./testing/Sha256.ts";
import { describe, expect, it } from "vite-plus/test";
import * as Arr from "effect/Array";
import * as Clock from "effect/Clock";
import * as DateTime from "effect/DateTime";
import * as Effect from "effect/Effect";
import * as Layer from "effect/Layer";
import * as MutableHashMap from "effect/MutableHashMap";
import * as Result from "effect/Result";
import * as Option from "effect/Option";
import * as Schema from "effect/Schema";
import { AccountDeletion } from "./AccountDeletion.ts";
import {
  accountDeletionLayer,
  AccountManagementService,
  AccountManagementStore,
} from "./AccountManagement.ts";
import { AdminService, AdminUserStore } from "./Admin.ts";
import { AnonymousService, AnonymousUserStore } from "./Anonymous.ts";
import { ApiKeyService, ApiKeyStore } from "./ApiKey.ts";
import { AuthLifecycleService } from "./AuthLifecycle.ts";
import { EmailOtpService, EmailOtpStore, EmailOtpUserStore } from "./email/EmailOtp.ts";
import { EmailPasswordService, EmailPasswordStore } from "./email/EmailPassword.ts";
import { EmailVerificationService, EmailVerificationStore } from "./email/EmailVerification.ts";
import { AuthError, LastOrganizationOwnerError } from "./Errors.ts";
import { Hooks } from "./Hooks.ts";
import * as HttpServer from "./http/HttpServer.ts";
import { IdentifierStore, lookupIdentifier, makeIdentifier } from "./Identifier.ts";
import { MagicLinkService, MagicLinkStore, MagicLinkUserStore } from "./MagicLink.ts";
import { MultiFactorStore } from "./multifactor/MultiFactor.ts";
import { CredentialStore } from "./multifactor/WebAuthn.ts";
import { OAuthAccountStore } from "./oauth/OAuthAccount.ts";
import { OidcConsentStore, OidcTokenStore } from "./OidcProvider.ts";
import {
  type Member,
  type Organization,
  OrganizationStore,
  type Team,
  type TeamMember,
} from "./Organization.ts";
import { PasswordHasher } from "./password/Password.ts";
import {
  PasswordResetService,
  PasswordResetStore,
  PasswordResetUserStore,
} from "./password/PasswordReset.ts";
import { PhoneOtpStore } from "./PhoneOtp.ts";
import { RateLimiter } from "./RateLimit.ts";
import { SessionService } from "./SessionService.ts";
import { SessionStore } from "./SessionStore.ts";
import { TrustedDeviceStore } from "./TrustedDevice.ts";
import type * as Types from "./Types.ts";
import { UserService, UserServiceStore } from "./User.ts";
import { inlineDeliveryScheduler } from "./testing/Delivery.ts";
import * as Testing from "./testing/index.ts";
import { definedKeys } from "./DefinedKeys.ts";

const notUsed = () => Effect.fail(new AuthError({ message: "not used by these tests" }));

/**
 * An `OrganizationStore` over plain arrays, with the organization, membership
 * and team calls the purge makes; the rest are not used here.
 */
const memoryOrganizations = (): typeof OrganizationStore.Service => {
  const organizations = MutableHashMap.empty<string, Organization>();
  let members: ReadonlyArray<Member> = [];
  const teams = MutableHashMap.empty<string, Team>();
  let teamMembers: ReadonlyArray<TeamMember> = [];
  return {
    createOrganization: (organization) =>
      Effect.sync(
        () => (MutableHashMap.set(organizations, organization.id, organization), organization),
      ),
    getOrganizationById: (id) =>
      Effect.sync(() => Option.getOrNull(MutableHashMap.get(organizations, id))),
    getOrganizationBySlug: notUsed,
    updateOrganization: notUsed,
    deleteOrganization: notUsed,
    createMember: (member) => Effect.sync(() => ((members = [...members, member]), member)),
    getMember: (organizationId, userId) =>
      Effect.sync(() =>
        Arr.findFirst(
          members,
          (m) => m.organizationId === organizationId && m.userId === userId,
        ).pipe(Option.getOrNull),
      ),
    getMemberById: notUsed,
    updateMember: notUsed,
    deleteMember: (id) => Effect.sync(() => void (members = members.filter((m) => m.id !== id))),
    listMembersByOrganization: (organizationId) =>
      Effect.sync(() => members.filter((m) => m.organizationId === organizationId)),
    listMembersByUser: (userId) => Effect.sync(() => members.filter((m) => m.userId === userId)),
    countMembersByOrganization: notUsed,
    createInvitation: notUsed,
    getInvitation: notUsed,
    updateInvitation: notUsed,
    listInvitationsByOrganization: notUsed,
    listInvitationsByEmail: notUsed,
    createTeam: (team) => Effect.sync(() => (MutableHashMap.set(teams, team.id, team), team)),
    getTeam: notUsed,
    updateTeam: notUsed,
    deleteTeam: notUsed,
    listTeams: notUsed,
    addTeamMember: (teamMember) =>
      Effect.sync(() => ((teamMembers = [...teamMembers, teamMember]), teamMember)),
    getTeamMemberById: notUsed,
    removeTeamMember: (teamId, userId) =>
      Effect.sync(
        () =>
          void (teamMembers = teamMembers.filter(
            (m) => !(m.teamId === teamId && m.userId === userId),
          )),
      ),
    listTeamMembers: notUsed,
    listTeamsForMember: (organizationId, userId) =>
      Effect.sync(() =>
        Arr.filterMap(teamMembers, (m) => {
          const team = Option.getOrUndefined(MutableHashMap.get(teams, m.teamId));
          return m.userId === userId && team?.organizationId === organizationId
            ? Result.succeed(team)
            : Result.failVoid;
        }),
      ),
    upsertOrgRole: notUsed,
    getOrgRole: notUsed,
    getOrgRoleById: notUsed,
    listOrgRoles: notUsed,
    deleteOrgRole: notUsed,
  };
};

/** The messages the services sent: the latest token or code per address (or user). */
interface Outbox {
  readonly magicLinks: MutableHashMap.MutableHashMap<string, string>;
  readonly emailOtps: MutableHashMap.MutableHashMap<string, string>;
  readonly resets: MutableHashMap.MutableHashMap<string, string>;
  readonly deletions: MutableHashMap.MutableHashMap<string, string>;
}

const makeOutbox = (): Outbox => ({
  magicLinks: MutableHashMap.empty(),
  emailOtps: MutableHashMap.empty(),
  resets: MutableHashMap.empty(),
  deletions: MutableHashMap.empty(),
});

const sent = (box: MutableHashMap.MutableHashMap<string, string>, key: string): string =>
  Option.getOrElse(MutableHashMap.get(box, key), () => `nothing sent to ${key}`);

/** `AnonymousUserStore` over the memory `UserServiceStore`. */
const anonymousUsers = Layer.effect(
  AnonymousUserStore,
  Effect.map(UserServiceStore, (users) => ({
    createAnonymousUser: Effect.flatMap(DateTime.nowAsDate, (now) =>
      users.update({
        id: globalThis.crypto.randomUUID(),
        createdAt: now,
        updatedAt: now,
        attributes: { isAnonymous: true },
      }),
    ),
    deleteUser: users.delete,
  })),
);

/** The passwordless and reset flows' user stores, over the memory `EmailPasswordStore`. */
const flowUserStores = Layer.mergeAll(
  Layer.effect(
    MagicLinkUserStore,
    Effect.map(EmailPasswordStore, (store) => ({ createUser: store.createUser })),
  ),
  Layer.effect(
    EmailOtpUserStore,
    Effect.map(EmailPasswordStore, (store) => ({ createUser: store.createUser })),
  ),
  Layer.effect(
    PasswordResetUserStore,
    Effect.map(EmailPasswordStore, (store) => ({ setPasswordHash: store.setPasswordHash })),
  ),
);

const stores = Layer.mergeAll(
  Testing.memoryStores,
  Hooks.Default,
  PasswordHasher.layer({ iterations: 1 }),
  inlineDeliveryScheduler,
  Layer.succeed(PhoneOtpStore, Testing.memoryPhoneOtpStore()),
  Layer.effect(OrganizationStore, Effect.sync(memoryOrganizations)),
  Layer.succeed(AdminUserStore, {
    listUsers: notUsed,
    createUser: notUsed,
    setPasswordHash: notUsed,
  }),
);

const sessions = SessionService.layer(Testing.defaultSessionConfig).pipe(
  Layer.provideMerge(Layer.merge(stores, flowUserStores.pipe(Layer.provide(stores)))),
);

/**
 * `UserServiceStore` over the memory one, whose `delete` fails while
 * `failing()` holds.
 */
const failingUserDelete = (failing: () => boolean) =>
  Layer.effect(
    UserServiceStore,
    Effect.map(UserServiceStore, (inner) => ({
      ...inner,
      delete: (userId: string) =>
        failing()
          ? Effect.fail(new AuthError({ message: "user delete failed" }))
          : inner.delete(userId),
    })),
  ).pipe(Layer.provide(sessions));

/**
 * Every deleting service, and the sign-in flows whose tokens a deletion must
 * void, over one set of memory stores; each build starts empty. With
 * `failing`, the user row's delete fails while it holds.
 */
const world = (outbox: Outbox, failing?: () => boolean) =>
  Layer.mergeAll(
    AdminService.layer(),
    AccountManagementService.layer({
      sendChangeEmailVerification: () => Effect.void,
      sendEmailChangeNotice: () => Effect.void,
      sendDeleteAccountVerification: ({ user, token }) =>
        Effect.sync(() => void MutableHashMap.set(outbox.deletions, user.id, token)),
    }),
    ApiKeyService.layer().pipe(Layer.provideMerge(RateLimiter.layer())),
    AnonymousService.layer().pipe(Layer.provideMerge(anonymousUsers)),
    MagicLinkService.layer({
      sendMagicLink: (email, token) =>
        Effect.sync(() => void MutableHashMap.set(outbox.magicLinks, email, token)),
    }),
    EmailOtpService.layer({
      sendVerificationOtp: (email, otp) =>
        Effect.sync(() => void MutableHashMap.set(outbox.emailOtps, email, otp)),
    }),
    PasswordResetService.layer({
      sendResetPassword: (email, token) =>
        Effect.sync(() => void MutableHashMap.set(outbox.resets, email, token)),
    }),
    AuthLifecycleService.layer().pipe(
      Layer.provideMerge(
        Layer.mergeAll(
          EmailPasswordService.layer(),
          EmailVerificationService.layer({ sendEmail: () => Effect.void }),
          UserService.layer(),
        ),
      ),
    ),
  ).pipe(
    Layer.provideMerge(accountDeletionLayer),
    Layer.provideMerge(
      failing === undefined ? sessions : Layer.merge(sessions, failingUserDelete(failing)),
    ),
  );

type World = Layer.Success<ReturnType<typeof world>>;

/**
 * One built world, shared by the test's own effects and the HTTP handler
 * mounted over it, with the messages it sent.
 */
const harness = async (failing?: () => boolean) => {
  const outbox = makeOutbox();
  const context = await Effect.runPromise(Effect.scoped(Layer.build(world(outbox, failing))));
  const { handler } = HttpServer.make({
    services: Layer.succeedContext(context),
    cookie: { secure: false },
    ipRateLimit: false,
  });
  const run = <A, E>(effect: Effect.Effect<A, E, World>): Promise<A> =>
    Effect.runPromise(Effect.provide(effect, context));
  return { run, handler, outbox };
};

/** A new organization with no members; answers its id. */
const createOrganization = (name: string) =>
  Effect.gen(function* () {
    const id = globalThis.crypto.randomUUID();
    yield* (yield* OrganizationStore).createOrganization({
      id,
      name,
      slug: id,
      metadata: {},
      createdAt: yield* Clock.currentTimeMillis,
    });
    return id;
  });

const addMember = (
  organizationId: string,
  userId: string,
  role: string,
  status?: Member["status"],
) =>
  Effect.gen(function* () {
    return yield* (yield* OrganizationStore).createMember({
      id: globalThis.crypto.randomUUID(),
      organizationId,
      userId,
      role,
      ...(status === undefined ? {} : { status }),
      createdAt: yield* Clock.currentTimeMillis,
    });
  });

/** One credential of every kind for `user`, and how to find each again. */
const seed = (user: Types.User, email: string, outbox: Outbox) =>
  Effect.gen(function* () {
    const now = yield* DateTime.nowAsDate;
    const at = now.getTime();
    const phone = `+1555${String(at).slice(-7)}${email.length}`;
    yield* (yield* UserServiceStore).update(user);
    const identifiers = yield* IdentifierStore;
    yield* identifiers.create(
      makeIdentifier({ userId: user.id, type: "email", value: email, now }),
    );
    yield* identifiers.create(
      makeIdentifier({ userId: user.id, type: "phone", value: phone, now }),
    );
    const { token: sessionToken } = yield* (yield* SessionService).createSession(user.id);
    const apiKey = yield* (yield* ApiKeyService).create(user.id, { name: "CI" });
    yield* (yield* OAuthAccountStore).create({
      id: globalThis.crypto.randomUUID(),
      userId: user.id,
      provider: "github",
      providerId: globalThis.crypto.randomUUID(),
      accessToken: "provider-access-token",
      refreshToken: "provider-refresh-token",
      createdAt: at,
      updatedAt: at,
    });
    yield* (yield* CredentialStore).create({
      id: globalThis.crypto.randomUUID(),
      userId: user.id,
      publicKey: new Uint8Array([1, 2, 3]),
      algorithm: -7,
      counter: 0,
      createdAt: at,
    });
    yield* (yield* MultiFactorStore).upsert({
      userId: user.id,
      secret: "JBSWY3DPEHPK3PXP",
      backupCodes: ["backup-code-hash"],
      verified: true,
      createdAt: at,
    });
    const deviceHash = `device-${user.id}`;
    yield* (yield* TrustedDeviceStore).upsert({
      tokenHash: deviceHash,
      userId: user.id,
      createdAt: at,
      expiresAt: at + 60_000,
    });
    const oidcTokenHash = `oidc-${user.id}`;
    yield* (yield* OidcTokenStore).create({
      tokenHash: oidcTokenHash,
      kind: "refresh",
      clientId: "client",
      userId: user.id,
      scopes: ["openid"],
      expiresAt: at + 60_000,
      createdAt: at,
    });
    yield* (yield* OidcConsentStore).upsert({
      userId: user.id,
      clientId: "client",
      scopes: ["openid"],
      createdAt: at,
      updatedAt: at,
    });
    yield* (yield* AccountManagementStore).create({
      token: `change-email-${user.id}`,
      userId: user.id,
      purpose: "change-email",
      newEmail: `new-${email}`,
      createdAt: at,
      expiresAt: at + 60_000,
    });
    // The pending proofs the flows themselves issue, by user and by address.
    const verification = yield* (yield* EmailVerificationService).createVerification(
      user.id,
      email,
    );
    yield* (yield* PasswordResetService).requestPasswordReset(email);
    yield* (yield* MagicLinkService).send(email);
    yield* (yield* EmailOtpService).send(email, "sign-in");
    yield* (yield* PhoneOtpStore).upsert({
      phoneNumber: phone,
      otpHash: "otp-hash",
      purpose: "sign-in",
      attempts: 0,
      createdAt: at,
      expiresAt: at + 60_000,
    });
    // An organization of their own, with a team: the only member, so the
    // purge removes the membership without refusing.
    const organizationId = yield* createOrganization(`${email}'s organization`);
    yield* addMember(organizationId, user.id, "owner");
    const teamId = globalThis.crypto.randomUUID();
    const organizations = yield* OrganizationStore;
    yield* organizations.createTeam({
      id: teamId,
      organizationId,
      name: "Team",
      createdAt: at,
      updatedAt: at,
    });
    yield* organizations.addTeamMember({
      id: globalThis.crypto.randomUUID(),
      teamId,
      userId: user.id,
      createdAt: at,
    });
    return {
      organizationId,
      user,
      email,
      phone,
      sessionToken,
      apiKey: apiKey.key,
      deviceHash,
      oidcTokenHash,
      verificationToken: verification.token,
      resetToken: sent(outbox.resets, email),
      magicLink: sent(outbox.magicLinks, email),
      emailOtp: sent(outbox.emailOtps, email),
    };
  });

type Seeded = Effect.Success<ReturnType<typeof seed>>;

const count = (found: Option.Option<unknown>) => (Option.isSome(found) ? 1 : 0);

/** How many of each credential kind `seeded.user` still holds. */
const inventory = (seeded: Seeded) =>
  Effect.gen(function* () {
    const id = seeded.user.id;
    return {
      user: count(yield* (yield* UserServiceStore).get(id)),
      identifiers: (yield* (yield* IdentifierStore).listByUser(id)).length,
      email: count(yield* lookupIdentifier(yield* IdentifierStore, "email", seeded.email)),
      sessions: (yield* (yield* SessionStore).listByUserId(id)).length,
      apiKeys: (yield* (yield* ApiKeyStore).listByUserId(id)).length,
      oauthAccounts: (yield* (yield* OAuthAccountStore).getByUserId(id)).length,
      passkeys: (yield* (yield* CredentialStore).listByUserId(id)).length,
      multiFactor: count(yield* (yield* MultiFactorStore).get(id)),
      trustedDevices: count(yield* (yield* TrustedDeviceStore).getByTokenHash(seeded.deviceHash)),
      oidcTokens: count(yield* (yield* OidcTokenStore).get(seeded.oidcTokenHash)),
      oidcConsents: count(yield* (yield* OidcConsentStore).get(id, "client")),
      passwordResets: count(yield* (yield* PasswordResetStore).get(sha256Hex(seeded.resetToken))),
      emailVerifications: count(yield* (yield* EmailVerificationStore).getLatestByUserId(id)),
      accountTokens: count(yield* (yield* AccountManagementStore).get(`change-email-${id}`)),
      magicLinks: count(yield* (yield* MagicLinkStore).getByEmail(seeded.email)),
      emailOtps: count(yield* (yield* EmailOtpStore).get(seeded.email, "sign-in")),
      phoneOtps: count(yield* (yield* PhoneOtpStore).get(seeded.phone, "sign-in")),
      memberships: (yield* (yield* OrganizationStore).listMembersByUser(id)).length,
      teamMemberships: (yield* (yield* OrganizationStore).listTeamsForMember(
        seeded.organizationId,
        id,
      )).length,
      apiKeyValid: (yield* (yield* ApiKeyService).verify(seeded.apiKey)).valid,
    };
  });

const held = {
  user: 1,
  identifiers: 2,
  email: 1,
  sessions: 1,
  apiKeys: 1,
  oauthAccounts: 1,
  passkeys: 1,
  multiFactor: 1,
  trustedDevices: 1,
  oidcTokens: 1,
  oidcConsents: 1,
  passwordResets: 1,
  emailVerifications: 1,
  accountTokens: 1,
  magicLinks: 1,
  emailOtps: 1,
  phoneOtps: 1,
  memberships: 1,
  teamMemberships: 1,
  apiKeyValid: true,
};

const nothing = {
  user: 0,
  identifiers: 0,
  email: 0,
  sessions: 0,
  apiKeys: 0,
  oauthAccounts: 0,
  passkeys: 0,
  multiFactor: 0,
  trustedDevices: 0,
  oidcTokens: 0,
  oidcConsents: 0,
  passwordResets: 0,
  emailVerifications: 0,
  accountTokens: 0,
  magicLinks: 0,
  emailOtps: 0,
  phoneOtps: 0,
  memberships: 0,
  teamMemberships: 0,
  apiKeyValid: false,
};

const fixtureUser = (attributes: Types.Attributes = {}): Types.User => ({
  ...Testing.fixtureUser(),
  id: globalThis.crypto.randomUUID(),
  attributes,
});

/** The doomed account and a bystander, both holding one of everything. */
const seedAccounts = Effect.fn("seedAccounts")(function* (outbox: Outbox) {
  const doomed = yield* seed(fixtureUser(), "doomed@example.com", outbox);
  const bystander = yield* seed(fixtureUser(), "bystander@example.com", outbox);
  return { doomed, bystander, before: yield* inventory(doomed) };
});

/** A platform administrator with a session, for the admin routes. */
const seedAdmin = Effect.fn("seedAdmin")(function* () {
  const admin = fixtureUser({ role: "admin" });
  yield* (yield* UserServiceStore).update(admin);
  const { token } = yield* (yield* SessionService).createSession(admin.id);
  return { admin, token };
});

/** A JSON request body, as the wire carries it. */
const toJson = Schema.encodeSync(Schema.fromJsonString(Schema.Json));

const request = (method: string, path: string, sessionToken: string, body?: Schema.Json) =>
  new Request(`http://test${path}`, {
    method,
    headers: {
      cookie: `conduit_session=${sessionToken}`,
      ...definedKeys({
        "content-type": body !== undefined ? "application/vnd.api+json" : undefined,
      }),
    },
    ...definedKeys({ body: body !== undefined ? toJson(body) : undefined }),
  });

describe("every path that deletes a user deletes everything the account holds", () => {
  it("AdminService.removeUser", async () => {
    const { run, outbox } = await harness();
    await run(
      Effect.gen(function* () {
        const { doomed, bystander, before } = yield* seedAccounts(outbox);
        expect(before).toEqual(held);
        const { admin } = yield* seedAdmin();
        yield* (yield* AdminService).removeUser(admin, doomed.user.id);
        expect(yield* inventory(doomed)).toEqual(nothing);
        expect(yield* inventory(bystander)).toEqual(held);
      }),
    );
  });

  it("HTTP DELETE /admin/users/:id", async () => {
    const { run, handler, outbox } = await harness();
    const { doomed, bystander, before, adminToken } = await run(
      Effect.gen(function* () {
        const seeded = yield* seedAccounts(outbox);
        const { token } = yield* seedAdmin();
        return { ...seeded, adminToken: token };
      }),
    );
    expect(before).toEqual(held);
    const response = await handler(request("DELETE", `/admin/users/${doomed.user.id}`, adminToken));
    expect(response.status).toBe(204);
    expect(await run(inventory(doomed))).toEqual(nothing);
    expect(await run(inventory(bystander))).toEqual(held);
  });

  it("AccountManagementService.confirmAccountDeletion", async () => {
    const { run, outbox } = await harness();
    await run(
      Effect.gen(function* () {
        const { doomed, bystander, before } = yield* seedAccounts(outbox);
        expect(before).toEqual(held);
        const accounts = yield* AccountManagementService;
        const { token } = yield* accounts.requestAccountDeletion(doomed.user.id);
        expect(yield* accounts.confirmAccountDeletion(token)).toEqual({
          userId: doomed.user.id,
        });
        expect(yield* inventory(doomed)).toEqual(nothing);
        expect(yield* inventory(bystander)).toEqual(held);
        // The token was spent with the rest.
        expect(Option.isNone(yield* (yield* AccountManagementStore).get(token))).toBe(true);
      }),
    );
  });

  it("HTTP POST /account-deletions, then POST /account-deletions/redemptions", async () => {
    const { run, handler, outbox } = await harness();
    const { doomed, bystander, before } = await run(seedAccounts(outbox));
    expect(before).toEqual(held);
    const requested = await handler(
      request("POST", "/account-deletions", doomed.sessionToken, {
        data: { type: "account-deletions" },
      }),
    );
    expect(requested.status).toBe(202);
    const redeemed = await handler(
      request("POST", "/account-deletions/redemptions", doomed.sessionToken, {
        data: {
          type: "account-deletion-redemptions",
          attributes: { token: sent(outbox.deletions, doomed.user.id) },
        },
      }),
    );
    expect(redeemed.status).toBe(204);
    expect(await run(inventory(doomed))).toEqual(nothing);
    expect(await run(inventory(bystander))).toEqual(held);
  });

  it("AnonymousService.linkAccount deletes the anonymous user and what it holds", async () => {
    const { run, outbox } = await harness();
    await run(
      Effect.gen(function* () {
        const { bystander } = yield* seedAccounts(outbox);
        const anonymous = yield* AnonymousService;
        const { user } = yield* anonymous.signInAnonymous();
        const guest = yield* seed(user, "guest@example.com", outbox);
        yield* anonymous.linkAccount(user, bystander.user);
        expect(yield* inventory(guest)).toEqual(nothing);
        expect(yield* inventory(bystander)).toEqual(held);
      }),
    );
  });

  it("UserService.deleteUser, through AccountDeletion", async () => {
    const { run, outbox } = await harness();
    await run(
      Effect.gen(function* () {
        const { doomed, bystander, before } = yield* seedAccounts(outbox);
        expect(before).toEqual(held);
        yield* (yield* UserService).deleteUser(doomed.user.id);
        expect(yield* inventory(doomed)).toEqual(nothing);
        expect(yield* inventory(bystander)).toEqual(held);
      }),
    );
  });

  it("AccountDeletion.deleteUser", async () => {
    const { run, outbox } = await harness();
    await run(
      Effect.gen(function* () {
        const { doomed, bystander, before } = yield* seedAccounts(outbox);
        expect(before).toEqual(held);
        yield* (yield* AccountDeletion).deleteUser(doomed.user.id);
        expect(yield* inventory(doomed)).toEqual(nothing);
        expect(yield* inventory(bystander)).toEqual(held);
      }),
    );
  });

  it("the user row goes last: a failing delete leaves the user, and a retry finishes", async () => {
    let failDelete = true;
    const { run, outbox } = await harness(() => failDelete);
    await run(
      Effect.gen(function* () {
        const { doomed, before } = yield* seedAccounts(outbox);
        expect(before).toEqual(held);
        const { admin } = yield* seedAdmin();
        const removal = (yield* AdminService).removeUser(admin, doomed.user.id);
        const failure = yield* Effect.flip(removal);
        expect(failure.message).toBe("user delete failed");
        // Everything but the row is gone; no row names a missing user.
        expect(yield* inventory(doomed)).toEqual({ ...nothing, user: 1 });
        failDelete = false;
        yield* removal;
        expect(yield* inventory(doomed)).toEqual(nothing);
      }),
    );
  });
});

describe("a deleted user's address can be claimed again, and nothing sent before reaches the new account", () => {
  it("the email signs up again; the old reset, verification, magic link and code all fail", async () => {
    const { run, outbox } = await harness();
    await run(
      Effect.gen(function* () {
        const { doomed } = yield* seedAccounts(outbox);
        const { admin } = yield* seedAdmin();
        yield* (yield* AdminService).removeUser(admin, doomed.user.id);

        // A new account claims the address.
        const signedUp = yield* (yield* EmailPasswordService).signUp({
          email: doomed.email,
          password: "a new and different passphrase",
        });
        expect(signedUp.user.id).not.toBe(doomed.user.id);
        const holder = yield* lookupIdentifier(yield* IdentifierStore, "email", doomed.email);
        expect(Option.getOrUndefined(holder)?.userId).toBe(signedUp.user.id);

        // Nothing sent to the old account works, for it or for the new one.
        const reset = yield* Effect.flip(
          (yield* PasswordResetService).resetPassword(doomed.resetToken, "taken over at last"),
        );
        expect(reset._tag).toBe("PasswordResetError");
        const verified = yield* Effect.flip(
          (yield* EmailVerificationService).verifyToken(doomed.verificationToken),
        );
        expect(verified._tag).toBe("EmailVerificationError");
        const link = yield* Effect.flip((yield* MagicLinkService).verify(doomed.magicLink));
        expect(link._tag).toBe("MagicLinkError");
        const code = yield* Effect.flip(
          (yield* EmailOtpService).signIn(doomed.email, doomed.emailOtp),
        );
        expect(code._tag).toBe("EmailOtpError");

        // No session was minted for the new account by any of them.
        expect(yield* (yield* SessionStore).listByUserId(signedUp.user.id)).toHaveLength(
          signedUp.session === undefined ? 0 : 1,
        );
      }),
    );
  });
});

describe("the last owner of an organization that has other members is not deleted", () => {
  /** The doomed user owns "Acme" alone; the bystander is a plain member of it. */
  const seedSharedOrganization = Effect.fn("seedSharedOrganization")(function* (outbox: Outbox) {
    const seeded = yield* seedAccounts(outbox);
    const acme = yield* createOrganization("Acme");
    yield* addMember(acme, seeded.doomed.user.id, "owner");
    yield* addMember(acme, seeded.bystander.user.id, "member");
    return { ...seeded, acme, before: yield* inventory(seeded.doomed) };
  });

  /** The doomed account still holds everything, and Acme keeps both members. */
  const untouched = (seeded: Effect.Success<ReturnType<typeof seedSharedOrganization>>) =>
    Effect.gen(function* () {
      expect(yield* inventory(seeded.doomed)).toEqual(seeded.before);
      expect(seeded.before).toEqual({ ...held, memberships: 2 });
      expect(
        (yield* (yield* OrganizationStore).listMembersByOrganization(seeded.acme)).length,
      ).toBe(2);
    });

  const expectLastOwner = (error: { readonly _tag: string }, acme: string) => {
    expect(error).toBeInstanceOf(LastOrganizationOwnerError);
    expect(error).toMatchObject({
      organizationId: acme,
      message: expect.stringContaining("'Acme'"),
    });
  };

  const servicePaths: ReadonlyArray<
    readonly [string, (userId: string) => Effect.Effect<unknown, { readonly _tag: string }, World>]
  > = [
    [
      "AdminService.removeUser",
      (userId) =>
        Effect.gen(function* () {
          const { admin } = yield* seedAdmin();
          return yield* (yield* AdminService).removeUser(admin, userId);
        }),
    ],
    [
      "AccountManagementService.confirmAccountDeletion",
      (userId) =>
        Effect.gen(function* () {
          const accounts = yield* AccountManagementService;
          const { token } = yield* accounts.requestAccountDeletion(userId);
          return yield* accounts.confirmAccountDeletion(token).pipe(
            // The token is kept, so the user can confirm once ownership moves.
            Effect.tapError(() =>
              Effect.gen(function* () {
                const kept = yield* (yield* AccountManagementStore).get(sha256Hex(token));
                expect(kept).not.toBeNull();
              }),
            ),
          );
        }),
    ],
    [
      "UserService.deleteUser",
      (userId) => Effect.flatMap(UserService, (s) => s.deleteUser(userId)),
    ],
    [
      "AccountDeletion.deleteUser",
      (userId) => Effect.flatMap(AccountDeletion, (s) => s.deleteUser(userId)),
    ],
  ];

  it.each(servicePaths)("%s refuses with an error naming the organization", async (_, remove) => {
    const { run, outbox } = await harness();
    await run(
      Effect.gen(function* () {
        const seeded = yield* seedSharedOrganization(outbox);
        expectLastOwner(yield* Effect.flip(remove(seeded.doomed.user.id)), seeded.acme);
        yield* untouched(seeded);
      }),
    );
  });

  it("AnonymousService.linkAccount refuses before its callback, and keeps the guest", async () => {
    const { run, outbox } = await harness();
    await run(
      Effect.gen(function* () {
        const { bystander } = yield* seedAccounts(outbox);
        const anonymous = yield* AnonymousService;
        const { user } = yield* anonymous.signInAnonymous();
        const guest = yield* seed(user, "guest@example.com", outbox);
        const acme = yield* createOrganization("Acme");
        yield* addMember(acme, user.id, "owner");
        yield* addMember(acme, bystander.user.id, "member");
        const before = yield* inventory(guest);
        expectLastOwner(yield* Effect.flip(anonymous.linkAccount(user, bystander.user)), acme);
        expect(yield* inventory(guest)).toEqual(before);
      }),
    );
  });

  it("HTTP DELETE /admin/users/:id answers 409", async () => {
    const { run, handler, outbox } = await harness();
    const { seeded, adminToken } = await run(
      Effect.gen(function* () {
        const seeded = yield* seedSharedOrganization(outbox);
        const { token } = yield* seedAdmin();
        return { seeded, adminToken: token };
      }),
    );
    const response = await handler(
      request("DELETE", `/admin/users/${seeded.doomed.user.id}`, adminToken),
    );
    expect(response.status).toBe(409);
    expect(await response.text()).toContain("Acme");
    await run(untouched(seeded));
  });

  it("HTTP POST /account-deletions/redemptions answers 409", async () => {
    const { run, handler, outbox } = await harness();
    const seeded = await run(seedSharedOrganization(outbox));
    await handler(
      request("POST", "/account-deletions", seeded.doomed.sessionToken, {
        data: { type: "account-deletions" },
      }),
    );
    const redeemed = await handler(
      request("POST", "/account-deletions/redemptions", seeded.doomed.sessionToken, {
        data: {
          type: "account-deletion-redemptions",
          attributes: { token: sent(outbox.deletions, seeded.doomed.user.id) },
        },
      }),
    );
    expect(redeemed.status).toBe(409);
    await run(untouched(seeded));
  });

  it("another active owner lets the user go, and the organization keeps its members", async () => {
    const { run, outbox } = await harness();
    await run(
      Effect.gen(function* () {
        const seeded = yield* seedSharedOrganization(outbox);
        yield* addMember(seeded.acme, globalThis.crypto.randomUUID(), "owner");
        yield* (yield* AccountDeletion).deleteUser(seeded.doomed.user.id);
        expect(yield* inventory(seeded.doomed)).toEqual(nothing);
        const left = yield* (yield* OrganizationStore).listMembersByOrganization(seeded.acme);
        expect(left.map((m) => m.role).toSorted()).toEqual(["member", "owner"]);
      }),
    );
  });

  it("a deactivated owner does not count as another owner", async () => {
    const { run, outbox } = await harness();
    await run(
      Effect.gen(function* () {
        const seeded = yield* seedSharedOrganization(outbox);
        yield* addMember(seeded.acme, globalThis.crypto.randomUUID(), "owner", "inactive");
        expectLastOwner(
          yield* Effect.flip((yield* AccountDeletion).deleteUser(seeded.doomed.user.id)),
          seeded.acme,
        );
      }),
    );
  });

  it("a deactivated owner's own membership does not hold the deletion back", async () => {
    const { run, outbox } = await harness();
    await run(
      Effect.gen(function* () {
        const { doomed, bystander } = yield* seedAccounts(outbox);
        const acme = yield* createOrganization("Acme");
        yield* addMember(acme, doomed.user.id, "owner", "inactive");
        yield* addMember(acme, bystander.user.id, "member");
        yield* (yield* AccountDeletion).deleteUser(doomed.user.id);
        expect(yield* inventory(doomed)).toEqual(nothing);
      }),
    );
  });
});
