/**
 * Deleting a user deletes what they hold (#601), end to end: every deletion
 * path, over the in-memory stores holding one credential of every kind for
 * the user being deleted and for a bystander.
 */
import { describe, expect, it } from "vite-plus/test";
import { DateTime, Effect, Layer } from "effect";
import { AccountManagementService, AccountManagementStore } from "./AccountManagement.ts";
import { AdminService, AdminUserStore } from "./Admin.ts";
import { AnonymousService, AnonymousUserStore } from "./Anonymous.ts";
import { ApiKeyService, ApiKeyStore } from "./ApiKey.ts";
import { EmailVerificationStore } from "./email/EmailVerification.ts";
import { AuthError } from "./Errors.ts";
import { Hooks } from "./Hooks.ts";
import { IdentifierStore, lookupIdentifier, makeIdentifier } from "./Identifier.ts";
import { MultiFactorStore } from "./multifactor/MultiFactor.ts";
import { CredentialStore } from "./multifactor/WebAuthn.ts";
import { OAuthAccountStore } from "./oauth/OAuthAccount.ts";
import { OidcConsentStore, OidcTokenStore } from "./OidcProvider.ts";
import { PasswordHasher } from "./password/Password.ts";
import { PasswordResetStore } from "./password/PasswordReset.ts";
import { RateLimiter } from "./RateLimit.ts";
import { SessionService } from "./SessionService.ts";
import { SessionStore } from "./SessionStore.ts";
import { TrustedDeviceStore } from "./TrustedDevice.ts";
import type * as Types from "./Types.ts";
import { UserService, UserServiceStore } from "./User.ts";
import * as Testing from "./testing/index.ts";

const notUsed = () => Effect.fail(new AuthError({ message: "not used by these tests" }));

/** `AnonymousUserStore` over the memory `UserServiceStore`. */
const anonymousUsers = Layer.effect(
  AnonymousUserStore,
  Effect.map(UserServiceStore, (users) => ({
    createAnonymousUser: () =>
      Effect.flatMap(DateTime.nowAsDate, (now) =>
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

const stores = Layer.mergeAll(
  Testing.memoryStores,
  Hooks.Default,
  PasswordHasher.layer({ iterations: 1 }),
  Layer.succeed(AdminUserStore, {
    listUsers: notUsed,
    createUser: notUsed,
    setPasswordHash: notUsed,
  }),
);

const sessions = SessionService.layer(Testing.defaultSessionConfig).pipe(
  Layer.provideMerge(stores),
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
 * Every deleting service, over one set of memory stores; each build starts
 * empty. With `failing`, the user row's delete fails while it holds.
 */
const world = (failing?: () => boolean) =>
  Layer.mergeAll(
    AdminService.layer(),
    AccountManagementService.layer({
      sendChangeEmailVerification: () => Effect.void,
      sendDeleteAccountVerification: () => Effect.void,
    }),
    ApiKeyService.layer().pipe(Layer.provideMerge(RateLimiter.layer())),
    AnonymousService.layer().pipe(Layer.provideMerge(anonymousUsers)),
    UserService.layer(),
  ).pipe(
    Layer.provideMerge(
      failing === undefined ? sessions : Layer.merge(sessions, failingUserDelete(failing)),
    ),
  );

/** One credential of every kind for `user`, and how to find each again. */
const seed = (user: Types.User, email: string) =>
  Effect.gen(function* () {
    const now = yield* DateTime.nowAsDate;
    const at = now.getTime();
    yield* (yield* UserServiceStore).update(user);
    const identifiers = yield* IdentifierStore;
    yield* identifiers.create(
      makeIdentifier({ userId: user.id, type: "email", value: email, now }),
    );
    yield* (yield* SessionService).createSession(user.id);
    const apiKey = yield* (yield* ApiKeyService).create(user.id, { name: "CI" });
    const oauth = {
      id: globalThis.crypto.randomUUID(),
      userId: user.id,
      provider: "github",
      providerId: globalThis.crypto.randomUUID(),
      accessToken: "provider-access-token",
      refreshToken: "provider-refresh-token",
      createdAt: at,
      updatedAt: at,
    };
    yield* (yield* OAuthAccountStore).create(oauth);
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
    const token = (kind: string) => ({
      token: `${kind}-${user.id}`,
      userId: user.id,
      email,
      createdAt: at,
      expiresAt: at + 60_000,
    });
    yield* (yield* PasswordResetStore).create(token("reset"));
    yield* (yield* EmailVerificationStore).create(token("verification"));
    yield* (yield* AccountManagementStore).create({
      token: `change-email-${user.id}`,
      userId: user.id,
      purpose: "change-email",
      newEmail: `new-${email}`,
      createdAt: at,
      expiresAt: at + 60_000,
    });
    return { user, email, apiKey: apiKey.key, oauth, deviceHash, oidcTokenHash };
  });

type Seeded = Effect.Success<ReturnType<typeof seed>>;

const count = (found: object | null) => (found === null ? 0 : 1);

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
      passwordResets: count(yield* (yield* PasswordResetStore).get(`reset-${id}`)),
      emailVerifications: count(yield* (yield* EmailVerificationStore).get(`verification-${id}`)),
      accountTokens: count(yield* (yield* AccountManagementStore).get(`change-email-${id}`)),
      apiKeyValid: (yield* (yield* ApiKeyService).verify(seeded.apiKey)).valid,
    };
  });

const held = {
  user: 1,
  identifiers: 1,
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
  apiKeyValid: false,
};

const fixtureUser = (attributes: Types.Attributes = {}): Types.User => ({
  ...Testing.fixtureUser(),
  id: globalThis.crypto.randomUUID(),
  attributes,
});

/** The doomed account and a bystander, both holding one of everything. */
const seedAccounts = Effect.fn("seedAccounts")(function* () {
  const doomed = yield* seed(fixtureUser(), "doomed@example.com");
  const bystander = yield* seed(fixtureUser(), "bystander@example.com");
  return { doomed, bystander, before: yield* inventory(doomed) };
});

const run = <A, E>(
  effect: Effect.Effect<A, E, Layer.Success<ReturnType<typeof world>>>,
  layer = world(),
): Promise<A> => Effect.runPromise(effect.pipe(Effect.provide(layer)));

describe("deleting a user deletes every credential the account holds (#601)", () => {
  it("AdminService.removeUser", async () => {
    await run(
      Effect.gen(function* () {
        const { doomed, bystander, before } = yield* seedAccounts();
        expect(before).toEqual(held);
        const admin = fixtureUser({ role: "admin" });
        yield* (yield* AdminService).removeUser(admin, doomed.user.id);
        expect(yield* inventory(doomed)).toEqual(nothing);
        expect(yield* inventory(bystander)).toEqual(held);
      }),
    );
  });

  it("AccountManagementService.confirmAccountDeletion", async () => {
    await run(
      Effect.gen(function* () {
        const { doomed, bystander, before } = yield* seedAccounts();
        expect(before).toEqual(held);
        const accounts_ = yield* AccountManagementService;
        const { token } = yield* accounts_.requestAccountDeletion(doomed.user.id);
        expect(yield* accounts_.confirmAccountDeletion(token)).toEqual({
          userId: doomed.user.id,
        });
        expect(yield* inventory(doomed)).toEqual(nothing);
        expect(yield* inventory(bystander)).toEqual(held);
        // The token was spent with the rest.
        expect(yield* (yield* AccountManagementStore).get(token)).toBeNull();
      }),
    );
  });

  it("AnonymousService.linkAccount deletes the anonymous user's credentials too", async () => {
    await run(
      Effect.gen(function* () {
        const { bystander } = yield* seedAccounts();
        const anonymous = yield* AnonymousService;
        const { user } = yield* anonymous.signInAnonymous();
        const guest = yield* seed(user, "guest@example.com");
        yield* anonymous.linkAccount(user, bystander.user);
        expect(yield* inventory(guest)).toEqual(nothing);
        expect(yield* inventory(bystander)).toEqual(held);
      }),
    );
  });

  it("the user row goes last: a failing delete leaves the user, and a retry finishes", async () => {
    let failDelete = true;
    await run(
      Effect.gen(function* () {
        const { doomed, before } = yield* seedAccounts();
        expect(before).toEqual(held);
        const admin = fixtureUser({ role: "admin" });
        const removal = (yield* AdminService).removeUser(admin, doomed.user.id);
        const failure = yield* Effect.flip(removal);
        expect(failure.message).toBe("user delete failed");
        // Everything but the row is gone; no row names a missing user.
        expect(yield* inventory(doomed)).toEqual({ ...nothing, user: 1 });
        failDelete = false;
        yield* removal;
        expect(yield* inventory(doomed)).toEqual(nothing);
      }),
      world(() => failDelete),
    );
  });

  it("UserService.deleteUser deletes the row only, and the orphaned API key no longer verifies", async () => {
    await run(
      Effect.gen(function* () {
        const { doomed, before } = yield* seedAccounts();
        expect(before).toEqual(held);
        yield* (yield* UserService).deleteUser(doomed.user.id);
        const after = yield* inventory(doomed);
        expect(after.user).toBe(0);
        expect(after.apiKeys).toBe(1);
        expect(after.apiKeyValid).toBe(false);
      }),
    );
  });
});
