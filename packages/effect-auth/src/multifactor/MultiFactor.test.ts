import { sha256Hex } from "../testing/Sha256.ts";
import { assert, describe, it, expect, beforeEach } from "vite-plus/test";
import { Clock, Context, DateTime, Effect, MutableHashMap, Redacted, Result } from "effect";
import * as Arr from "effect/Array";
import * as Option from "effect/Option";
import { Hooks } from "../Hooks.ts";
import { testCryptoContext, testPepper } from "../testing/TestCrypto.ts";
import { SessionService, make as makeSessionService } from "../SessionService.ts";
import { SessionStore } from "../SessionStore.ts";
import { UserStore } from "../UserStore.ts";
import {
  type PendingMultiFactor,
  type MultiFactorRecord,
  MultiFactorStore,
  PendingMultiFactorStore,
} from "./MultiFactor.ts";
import * as MultiFactor from "./MultiFactor.ts";
import { memoryMultiFactorStore } from "../testing/MemoryStores.ts";
import * as Cipher from "../Cipher.ts";
import { type CreateUserInput, EmailPasswordStore } from "../email/EmailPassword.ts";
import {
  IdentifierStore,
  makeIdentifier,
  memoryIdentifierStore,
  type Identifier,
} from "../Identifier.ts";
import { generateHotp, generateTotp } from "./Otp.ts";
import { PasswordHasher } from "../password/Password.ts";
import * as Password from "../password/Password.ts";
import { scryptHasher } from "../password/Scrypt.ts";
import type { Session, User, SessionConfig } from "../Types.ts";
import { memorySessionStore } from "../testing/MemoryStores.ts";
import type { SessionTouch } from "../SessionStore.ts";
import { TrustedDeviceStore } from "../TrustedDevice.ts";

const users = MutableHashMap.empty<string, User>();
const identifiers = MutableHashMap.empty<string, Identifier>();
const passwordHashes = MutableHashMap.empty<string, string>();
const multiFactorRecords = MutableHashMap.empty<string, MultiFactorRecord>();
const pendingChallenges = MutableHashMap.empty<string, PendingMultiFactor>();
const pendingAttempts = MutableHashMap.empty<string, number>();
const sessions = MutableHashMap.empty<string, Session>();

const sessionStore = {
  create: (session: Session) =>
    Effect.sync(() => {
      MutableHashMap.set(sessions, session.id, session);
      return session;
    }),

  get: (sessionId: string) =>
    Effect.sync(() => Option.getOrNull(MutableHashMap.get(sessions, sessionId))),

  update: (session: Session) =>
    Effect.sync(() => {
      MutableHashMap.set(sessions, session.id, session);
      return session;
    }),

  touch: (sessionId: string, touch: SessionTouch) =>
    memorySessionStore(sessions).touch(sessionId, touch),
  delete: (sessionId: string) =>
    Effect.sync(() => {
      MutableHashMap.remove(sessions, sessionId);
    }),

  deleteByUserId: (userId: string) =>
    Effect.sync(() => {
      MutableHashMap.forEach(sessions, (session, id) => {
        if (session.userId === userId) {
          MutableHashMap.remove(sessions, id);
        }
      });
    }),

  listByUserId: (userId: string) =>
    Effect.sync(() =>
      Array.from(MutableHashMap.values(sessions)).filter((session) => session.userId === userId),
    ),
};

const userStore = {
  get: (userId: string) => Effect.sync(() => Option.getOrNull(MutableHashMap.get(users, userId))),
};

const emailPasswordStore = {
  createUser: (input: CreateUserInput) =>
    Effect.sync(() => {
      const user: User = {
        id: `user-${MutableHashMap.size(users) + 1}`,
        ...(input.name !== undefined && { name: input.name }),
        createdAt: DateTime.toDateUtc(DateTime.nowUnsafe()),
        updatedAt: DateTime.toDateUtc(DateTime.nowUnsafe()),
        attributes: input.attributes ?? {},
      };
      MutableHashMap.set(users, user.id, user);
      return { user, created: true };
    }),

  getPasswordHash: (userId: string) =>
    Effect.sync(() => Option.getOrNull(MutableHashMap.get(passwordHashes, userId))),

  clearPasswordHash: (userId: string) =>
    Effect.sync(() => void MutableHashMap.remove(passwordHashes, userId)),
  setPasswordHash: (userId: string, hash: string) =>
    Effect.sync(() => {
      MutableHashMap.set(passwordHashes, userId, hash);
    }),
};

// Every read yields the fiber, as a database round trip would, so concurrent
// redemptions interleave between a read and the write that follows.
const memoryMultiFactor = memoryMultiFactorStore(multiFactorRecords);
const multiFactorStore: typeof MultiFactorStore.Service = {
  ...memoryMultiFactor,
  get: (userId) => Effect.tap(memoryMultiFactor.get(userId), () => Effect.yieldNow),
};

const pendingMultiFactorStore = {
  create: (pending: PendingMultiFactor) =>
    Effect.sync(() => {
      MutableHashMap.set(pendingChallenges, pending.token, pending);
      return pending;
    }),

  get: (token: string) =>
    Effect.sync(() => Option.getOrNull(MutableHashMap.get(pendingChallenges, token))).pipe(
      Effect.tap(() => Effect.yieldNow),
    ),

  consume: (token: string) =>
    Effect.sync(() => {
      MutableHashMap.remove(pendingAttempts, token);
      const found = Option.getOrNull(MutableHashMap.get(pendingChallenges, token));
      MutableHashMap.remove(pendingChallenges, token);
      return found;
    }),

  recordFailedAttempt: (token: string) =>
    Effect.sync(() => {
      const attempts = Option.getOrElse(MutableHashMap.get(pendingAttempts, token), () => 0) + 1;
      MutableHashMap.set(pendingAttempts, token, attempts);
      return attempts;
    }),

  delete: (token: string) =>
    Effect.sync(() => {
      MutableHashMap.remove(pendingChallenges, token);
      MutableHashMap.remove(pendingAttempts, token);
    }),
};

const sessionConfig: SessionConfig = {
  sessionExpiresIn: {
    activePeriod: 1000 * 60 * 60 * 24,
    idlePeriod: 1000 * 60 * 60 * 12,
  },
};

const makeTestContext = async () => {
  const sessionManager = await Effect.runPromise(
    Effect.provide(
      makeSessionService(sessionConfig),
      Context.merge(
        Context.merge(Context.make(SessionStore, sessionStore), Context.make(UserStore, userStore)),
        testCryptoContext(),
      ),
    ).pipe(Effect.provide(Hooks.Default)),
  );

  return Context.merge(
    Context.make(SessionService, sessionManager),
    Context.merge(
      Context.make(SessionStore, sessionStore),
      Context.merge(
        Context.make(UserStore, userStore),
        Context.merge(
          Context.merge(
            Context.make(EmailPasswordStore, emailPasswordStore),
            Context.make(IdentifierStore, memoryIdentifierStore(identifiers)),
          ),
          Context.merge(
            Context.make(MultiFactorStore, multiFactorStore),
            Context.merge(
              Context.merge(
                Context.make(PendingMultiFactorStore, pendingMultiFactorStore),
                Context.make(PasswordHasher, Password.pbkdf2Hasher({ iterations: 1000 })),
              ),
              testCryptoContext(),
            ),
          ),
        ),
      ),
    ),
  );
};

const seedUser = async (id: string, email: string, password: string): Promise<User> => {
  const user: User = {
    id,
    createdAt: DateTime.toDateUtc(DateTime.nowUnsafe()),
    updatedAt: DateTime.toDateUtc(DateTime.nowUnsafe()),
    attributes: {},
  };
  MutableHashMap.set(users, id, user);
  const identifier = makeIdentifier({
    userId: id,
    type: "email",
    value: email,
    verified: true,
    verifiedAt: DateTime.toDateUtc(DateTime.nowUnsafe()),
    now: DateTime.toDateUtc(DateTime.nowUnsafe()),
  });
  MutableHashMap.set(identifiers, identifier.id, identifier);

  const hasher = Password.pbkdf2Hasher({ iterations: 1000 });
  const hashed = await Effect.runPromise(hasher.hash(password));
  MutableHashMap.set(passwordHashes, id, hashed.hash);

  return user;
};

describe("MultiFactorService", () => {
  beforeEach(() => {
    MutableHashMap.clear(users);
    MutableHashMap.clear(identifiers);
    MutableHashMap.clear(passwordHashes);
    MutableHashMap.clear(multiFactorRecords);
    MutableHashMap.clear(pendingChallenges);
    MutableHashMap.clear(pendingAttempts);
    MutableHashMap.clear(sessions);
  });

  it("should enable, confirm with a TOTP code, and report multi-factor as enabled", async () => {
    const testContext = await makeTestContext();
    await seedUser("user-2fa-1", "totp@example.com", "correct-password");

    const { enableResult, enabledBeforeConfirm, enabledAfterConfirm } = await Effect.runPromise(
      Effect.provide(
        Effect.gen(function* () {
          const service = yield* MultiFactor.make({ issuer: "TestApp" });

          const enableResult = yield* service.enable("user-2fa-1", "correct-password");
          const enabledBeforeConfirm = yield* service.isEnabled("user-2fa-1");

          const code = yield* generateTotp(enableResult.secret);
          yield* service.confirmEnable("user-2fa-1", code);

          const enabledAfterConfirm = yield* service.isEnabled("user-2fa-1");

          return { enableResult, enabledBeforeConfirm, enabledAfterConfirm };
        }),
        testContext,
      ).pipe(Effect.provide(Hooks.Default)),
    );

    expect(enableResult.secret.length).toBeGreaterThan(0);
    expect(enableResult.totpUri).toContain("otpauth://totp/");
    expect(enableResult.totpUri).toContain("TestApp");
    expect(enableResult.totpUri).toContain(encodeURIComponent("totp@example.com"));
    expect(enableResult.backupCodes).toHaveLength(10);
    Arr.forEach(enableResult.backupCodes, (code) => {
      expect(code).toMatch(/^[0-9a-f]{5}-[0-9a-f]{5}$/);
    });

    // Backup codes are stored hashed, never in plaintext
    const record = Option.getOrUndefined(MutableHashMap.get(multiFactorRecords, "user-2fa-1"));
    expect(record?.verified).toBe(true);
    Arr.forEach(enableResult.backupCodes, (plaintext) => {
      expect(record?.backupCodes).not.toContain(plaintext);
    });
    // Each is peppered under the root secret, and the TOTP secret is sealed.
    expect(record?.backupCodes).toEqual(
      enableResult.backupCodes.map((code) => testPepper(code.replace("-", ""))),
    );
    expect(record?.secret.startsWith(Cipher.SEALED_PREFIX)).toBe(true);

    expect(enabledBeforeConfirm).toBe(false);
    expect(enabledAfterConfirm).toBe(true);
  });

  it("should reject confirmEnable with an invalid code", async () => {
    const testContext = await makeTestContext();
    await seedUser("user-2fa-2", "badcode@example.com", "correct-password");

    const result = await Effect.runPromise(
      Effect.provide(
        Effect.gen(function* () {
          const service = yield* MultiFactor.make({ issuer: "TestApp" });
          yield* service.enable("user-2fa-2", "correct-password");
          return yield* Effect.result(service.confirmEnable("user-2fa-2", "000000"));
        }),
        testContext,
      ).pipe(Effect.provide(Hooks.Default)),
    );

    expect(result._tag).toBe("Failure");
    assert(Result.isFailure(result));
    expect(result.failure._tag).toBe("MultiFactorError");
    expect(
      Option.getOrUndefined(MutableHashMap.get(multiFactorRecords, "user-2fa-2"))?.verified,
    ).toBe(false);
  });

  it("refuses to re-enrol a confirmed enrolment and keeps it in force", async () => {
    const testContext = await makeTestContext();
    await seedUser("user-2fa-reenrol", "reenrol@example.com", "correct-password");

    const { sealedBefore, result, enabledAfter } = await Effect.runPromise(
      Effect.provide(
        Effect.gen(function* () {
          const service = yield* MultiFactor.make({ issuer: "TestApp" });
          const first = yield* service.enable("user-2fa-reenrol", "correct-password");
          yield* service.confirmEnable("user-2fa-reenrol", yield* generateTotp(first.secret));
          const sealedBefore = Option.getOrUndefined(
            MutableHashMap.get(multiFactorRecords, "user-2fa-reenrol"),
          )?.secret;
          const result = yield* Effect.result(
            service.enable("user-2fa-reenrol", "correct-password"),
          );
          const enabledAfter = yield* service.isEnabled("user-2fa-reenrol");
          return { sealedBefore, result, enabledAfter };
        }),
        testContext,
      ).pipe(Effect.provide(Hooks.Default)),
    );

    assert(Result.isFailure(result));
    expect(result.failure._tag).toBe("MultiFactorAlreadyEnabledError");
    expect(enabledAfter).toBe(true);
    const record = Option.getOrUndefined(
      MutableHashMap.get(multiFactorRecords, "user-2fa-reenrol"),
    );
    expect(record?.verified).toBe(true);
    expect(sealedBefore).toBeDefined();
    expect(record?.secret).toBe(sealedBefore);
  });

  it("replaces an enrolment that was never confirmed", async () => {
    const testContext = await makeTestContext();
    await seedUser("user-2fa-restart", "restart@example.com", "correct-password");

    const { first, firstSealed, second, stale } = await Effect.runPromise(
      Effect.provide(
        Effect.gen(function* () {
          const service = yield* MultiFactor.make({ issuer: "TestApp" });
          const first = yield* service.enable("user-2fa-restart", "correct-password");
          const firstSealed = Option.getOrUndefined(
            MutableHashMap.get(multiFactorRecords, "user-2fa-restart"),
          )?.secret;
          const second = yield* service.enable("user-2fa-restart", "correct-password");
          const stale = yield* Effect.result(
            service.confirmEnable("user-2fa-restart", yield* generateTotp(first.secret)),
          );
          yield* service.confirmEnable("user-2fa-restart", yield* generateTotp(second.secret));
          return { first, firstSealed, second, stale };
        }),
        testContext,
      ).pipe(Effect.provide(Hooks.Default)),
    );

    expect(second.secret).not.toBe(first.secret);
    const record = Option.getOrUndefined(
      MutableHashMap.get(multiFactorRecords, "user-2fa-restart"),
    );
    expect(Result.isFailure(stale)).toBe(true);
    expect(record?.verified).toBe(true);
    expect(record?.secret).toBeDefined();
    expect(record?.secret).not.toBe(firstSealed);
  });

  it("should fail to enable with a wrong password", async () => {
    const testContext = await makeTestContext();
    await seedUser("user-2fa-3", "wrongpw@example.com", "correct-password");

    const result = await Effect.runPromise(
      Effect.provide(
        Effect.gen(function* () {
          const service = yield* MultiFactor.make({ issuer: "TestApp" });
          return yield* Effect.result(service.enable("user-2fa-3", "wrong-password"));
        }),
        testContext,
      ).pipe(Effect.provide(Hooks.Default)),
    );

    expect(result._tag).toBe("Failure");
    assert(Result.isFailure(result));
    expect(result.failure._tag).toBe("InvalidCredentialsError");
    expect(MutableHashMap.size(multiFactorRecords)).toBe(0);
  });

  it("should fail to disable with a wrong password and remove the record on success", async () => {
    // Trusted devices are revoked by the successful disable only.
    const revokedDevices: string[] = [];
    const devices: typeof TrustedDeviceStore.Service = {
      upsert: (record) => Effect.succeed(record),
      getByTokenHash: () => Effect.succeed(null),
      delete: () => Effect.void,
      deleteByUserId: (userId) => Effect.sync(() => void revokedDevices.push(userId)),
    };
    const testContext = Context.add(await makeTestContext(), TrustedDeviceStore, devices);
    await seedUser("user-2fa-4", "disable@example.com", "correct-password");

    const { wrongPassword, stillEnabled, enabledAfterDisable } = await Effect.runPromise(
      Effect.provide(
        Effect.gen(function* () {
          const service = yield* MultiFactor.make({
            issuer: "TestApp",
            skipVerificationOnEnable: true,
          });

          yield* service.enable("user-2fa-4", "correct-password");

          const wrongPassword = yield* Effect.result(
            service.disable("user-2fa-4", "wrong-password"),
          );
          const stillEnabled = yield* service.isEnabled("user-2fa-4");

          yield* service.disable("user-2fa-4", "correct-password");
          const enabledAfterDisable = yield* service.isEnabled("user-2fa-4");

          return { wrongPassword, stillEnabled, enabledAfterDisable };
        }),
        testContext,
      ).pipe(Effect.provide(Hooks.Default)),
    );

    expect(wrongPassword._tag).toBe("Failure");
    assert(Result.isFailure(wrongPassword));
    expect(wrongPassword.failure._tag).toBe("InvalidCredentialsError");
    expect(stillEnabled).toBe(true);
    expect(enabledAfterDisable).toBe(false);
    expect(MutableHashMap.size(multiFactorRecords)).toBe(0);
    expect(revokedDevices).toEqual(["user-2fa-4"]);
  });

  it("verifies a password hashed by a previous hasher through MultiAlgorithmVerifier", async () => {
    // Seeded with PBKDF2; the configured hasher is now scrypt.
    await seedUser("user-2fa-legacy", "legacy@example.com", "correct-password");
    const current = scryptHasher({ cost: 16384 });
    const testContext = Context.add(
      Context.add(await makeTestContext(), PasswordHasher, current),
      Password.MultiAlgorithmVerifier,
      Password.multiAlgorithmVerifier([Password.pbkdf2Hasher({ iterations: 1000 }), current]),
    );

    const enabledAfterDisable = await Effect.runPromise(
      Effect.provide(
        Effect.gen(function* () {
          const service = yield* MultiFactor.make({
            issuer: "TestApp",
            skipVerificationOnEnable: true,
          });
          yield* service.enable("user-2fa-legacy", "correct-password");
          yield* service.regenerateBackupCodes("user-2fa-legacy", "correct-password");
          yield* service.disable("user-2fa-legacy", "correct-password");
          return yield* service.isEnabled("user-2fa-legacy");
        }),
        testContext,
      ).pipe(Effect.provide(Hooks.Default)),
    );
    expect(enabledAfterDisable).toBe(false);
  });

  it("should create a session on the challenge + verifyTotp happy path", async () => {
    const testContext = await makeTestContext();
    await seedUser("user-2fa-5", "challenge@example.com", "correct-password");

    const result = await Effect.runPromise(
      Effect.provide(
        Effect.gen(function* () {
          const service = yield* MultiFactor.make({
            issuer: "TestApp",
            skipVerificationOnEnable: true,
          });

          const { secret } = yield* service.enable("user-2fa-5", "correct-password");
          const challenge = yield* service.beginChallenge("user-2fa-5");

          const code = yield* generateTotp(secret);
          return yield* service.verifyTotp(challenge.token, code, {
            sessionAttributes: { device: "test" },
          });
        }),
        testContext,
      ).pipe(Effect.provide(Hooks.Default)),
    );

    expect(result.userId).toBe("user-2fa-5");
    expect(result.session.userId).toBe("user-2fa-5");
    expect(result.session.attributes).toEqual({ device: "test" });
    expect(MutableHashMap.size(sessions)).toBe(1);
    // Pending token is consumed on success
    expect(MutableHashMap.size(pendingChallenges)).toBe(0);
  });

  it("should reject an expired pending token", async () => {
    const testContext = await makeTestContext();
    await seedUser("user-2fa-6", "expired@example.com", "correct-password");

    const result = await Effect.runPromise(
      Effect.provide(
        Effect.gen(function* () {
          const service = yield* MultiFactor.make({
            issuer: "TestApp",
            skipVerificationOnEnable: true,
            pendingExpiresIn: -1000, // Already expired on creation
          });

          const { secret } = yield* service.enable("user-2fa-6", "correct-password");
          const challenge = yield* service.beginChallenge("user-2fa-6");

          const code = yield* generateTotp(secret);
          return yield* Effect.result(service.verifyTotp(challenge.token, code));
        }),
        testContext,
      ).pipe(Effect.provide(Hooks.Default)),
    );

    expect(result._tag).toBe("Failure");
    assert(Result.isFailure(result));
    expect(result.failure._tag).toBe("MultiFactorError");
    expect(MutableHashMap.size(sessions)).toBe(0);
    // Expired tokens are deleted eagerly
    expect(MutableHashMap.size(pendingChallenges)).toBe(0);
  });

  it("should reject a replayed pending token", async () => {
    const testContext = await makeTestContext();
    await seedUser("user-2fa-7", "replay@example.com", "correct-password");

    const result = await Effect.runPromise(
      Effect.provide(
        Effect.gen(function* () {
          const service = yield* MultiFactor.make({
            issuer: "TestApp",
            skipVerificationOnEnable: true,
          });

          const { secret } = yield* service.enable("user-2fa-7", "correct-password");
          const challenge = yield* service.beginChallenge("user-2fa-7");

          const code = yield* generateTotp(secret);
          yield* service.verifyTotp(challenge.token, code);

          const replayCode = yield* generateTotp(secret);
          return yield* Effect.result(service.verifyTotp(challenge.token, replayCode));
        }),
        testContext,
      ).pipe(Effect.provide(Hooks.Default)),
    );

    expect(result._tag).toBe("Failure");
    assert(Result.isFailure(result));
    expect(result.failure._tag).toBe("MultiFactorError");
    // Only the first verification created a session
    expect(MutableHashMap.size(sessions)).toBe(1);
  });

  it("should reject a replayed TOTP code on a fresh challenge", async () => {
    const testContext = await makeTestContext();
    await seedUser("user-2fa-7b", "replay2@example.com", "correct-password");

    const result = await Effect.runPromise(
      Effect.provide(
        Effect.gen(function* () {
          const service = yield* MultiFactor.make({
            issuer: "TestApp",
            skipVerificationOnEnable: true,
          });

          const { secret } = yield* service.enable("user-2fa-7b", "correct-password");

          // First challenge: verify with code C1 → success
          const challenge1 = yield* service.beginChallenge("user-2fa-7b");
          const code = yield* generateTotp(secret);
          yield* service.verifyTotp(challenge1.token, code);

          // Second challenge: a fresh pending token, but same code C1 within window
          const challenge2 = yield* service.beginChallenge("user-2fa-7b");
          return yield* Effect.result(service.verifyTotp(challenge2.token, code));
        }),
        testContext,
      ).pipe(Effect.provide(Hooks.Default)),
    );

    expect(result._tag).toBe("Failure");
    assert(Result.isFailure(result));
    expect(result.failure._tag).toBe("MultiFactorError");
    // Only the first challenge produced a session
    expect(MutableHashMap.size(sessions)).toBe(1);
  });

  it("caps wrong codes per challenge, and answers a capped challenge as a wrong code", async () => {
    const testContext = await makeTestContext();
    await seedUser("user-2fa-cap", "cap@example.com", "correct-password");

    const { wrong, rightAfterCap, pendingAfterFour } = await Effect.runPromise(
      Effect.provide(
        Effect.gen(function* () {
          const service = yield* MultiFactor.make({
            issuer: "TestApp",
            skipVerificationOnEnable: true,
          });
          const { secret } = yield* service.enable("user-2fa-cap", "correct-password");
          const challenge = yield* service.beginChallenge("user-2fa-cap");

          const wrongCode = () => Effect.flip(service.verifyTotp(challenge.token, "not-a-code"));
          const errors = [yield* wrongCode(), yield* wrongCode(), yield* wrongCode()];
          errors.push(yield* wrongCode());
          const pendingAfter4 = MutableHashMap.has(pendingChallenges, sha256Hex(challenge.token));
          // The fifth wrong code (the default cap) deletes the challenge.
          errors.push(yield* wrongCode());

          // From then on even the right code answers exactly as a wrong one.
          const code = yield* generateTotp(secret);
          const afterCap = yield* Effect.flip(service.verifyTotp(challenge.token, code));
          return { wrong: errors, rightAfterCap: afterCap, pendingAfterFour: pendingAfter4 };
        }),
        testContext,
      ).pipe(Effect.provide(Hooks.Default)),
    );

    expect(pendingAfterFour).toBe(true);
    expect(wrong.map((error) => [error._tag, error.message])).toEqual(
      Arr.replicate(["MultiFactorError", "Invalid multi-factor code"], 5),
    );
    expect([rightAfterCap._tag, rightAfterCap.message]).toEqual([
      "MultiFactorError",
      "Invalid multi-factor code",
    ]);
    expect(MutableHashMap.size(pendingChallenges)).toBe(0);
    expect(MutableHashMap.size(pendingAttempts)).toBe(0);
    expect(MutableHashMap.size(sessions)).toBe(0);
  });

  it("compares at most maxFailedAttempts of a concurrent burst of codes", async () => {
    const testContext = await makeTestContext();
    await seedUser("user-2fa-burst", "burst@example.com", "correct-password");
    // Reads that yield, as a database round trip does: every code of the
    // burst reads the challenge before any of them is counted.
    const slowPending: typeof PendingMultiFactorStore.Service = {
      ...pendingMultiFactorStore,
      get: (token) =>
        Effect.flatMap(pendingMultiFactorStore.get(token), (r) => Effect.as(Effect.yieldNow, r)),
    };

    const outcomes = await Effect.runPromise(
      Effect.provide(
        Effect.gen(function* () {
          const service = yield* MultiFactor.make({
            issuer: "TestApp",
            skipVerificationOnEnable: true,
          }).pipe(Effect.provideService(PendingMultiFactorStore, slowPending));
          const { backupCodes } = yield* service.enable("user-2fa-burst", "correct-password");
          const challenge = yield* service.beginChallenge("user-2fa-burst");
          // Nine wrong codes, then a right one, past the default cap of 5.
          const codes = [...Arr.replicate("wrong-backup", 9), backupCodes[0] ?? ""];
          return yield* Effect.all(
            codes.map((code) => Effect.result(service.verifyBackupCode(challenge.token, code))),
            { concurrency: "unbounded" },
          );
        }),
        testContext,
      ).pipe(Effect.provide(Hooks.Default)),
    );

    expect(outcomes.filter(Result.isSuccess)).toHaveLength(0);
    expect(MutableHashMap.size(sessions)).toBe(0);
    expect(MutableHashMap.size(pendingChallenges)).toBe(0);
  });

  it("counts TOTP and backup codes against one cap, configurable per service", async () => {
    const testContext = await makeTestContext();
    await seedUser("user-2fa-cap2", "cap2@example.com", "correct-password");

    const { underCap, capped } = await Effect.runPromise(
      Effect.provide(
        Effect.gen(function* () {
          const service = yield* MultiFactor.make({
            issuer: "TestApp",
            skipVerificationOnEnable: true,
            maxFailedAttempts: 2,
          });
          const { backupCodes } = yield* service.enable("user-2fa-cap2", "correct-password");

          // One wrong code leaves the challenge redeemable.
          const first = yield* service.beginChallenge("user-2fa-cap2");
          yield* Effect.flip(service.verifyTotp(first.token, "not-a-code"));
          const redeemed = yield* service.verifyBackupCode(first.token, backupCodes[0] ?? "");

          // A wrong TOTP code and a wrong backup code reach the cap of 2.
          const second = yield* service.beginChallenge("user-2fa-cap2");
          yield* Effect.flip(service.verifyTotp(second.token, "not-a-code"));
          yield* Effect.flip(service.verifyBackupCode(second.token, "wrong-backup"));
          const refused = yield* Effect.flip(
            service.verifyBackupCode(second.token, backupCodes[1] ?? ""),
          );
          return { underCap: redeemed, capped: refused };
        }),
        testContext,
      ).pipe(Effect.provide(Hooks.Default)),
    );

    expect(underCap.userId).toBe("user-2fa-cap2");
    expect([capped._tag, capped.message]).toEqual(["MultiFactorError", "Invalid backup code"]);
    expect(MutableHashMap.size(sessions)).toBe(1);
    // The unused backup code survives the capped challenge.
    expect(
      Option.getOrUndefined(MutableHashMap.get(multiFactorRecords, "user-2fa-cap2"))?.backupCodes,
    ).toHaveLength(9);
  });

  it("should accept a backup code only once", async () => {
    const testContext = await makeTestContext();
    await seedUser("user-2fa-8", "backup@example.com", "correct-password");

    const { firstUse, reuse, secondUse } = await Effect.runPromise(
      Effect.provide(
        Effect.gen(function* () {
          const service = yield* MultiFactor.make({
            issuer: "TestApp",
            skipVerificationOnEnable: true,
          });

          const { backupCodes } = yield* service.enable("user-2fa-8", "correct-password");

          const firstChallenge = yield* service.beginChallenge("user-2fa-8");
          const firstUse = yield* service.verifyBackupCode(firstChallenge.token, backupCodes[0]);

          const secondChallenge = yield* service.beginChallenge("user-2fa-8");
          const reuse = yield* Effect.result(
            service.verifyBackupCode(secondChallenge.token, backupCodes[0]),
          );

          // A failed attempt does not consume the pending token; another code works
          const secondUse = yield* service.verifyBackupCode(secondChallenge.token, backupCodes[1]);

          return { firstUse, reuse, secondUse };
        }),
        testContext,
      ).pipe(Effect.provide(Hooks.Default)),
    );

    expect(firstUse.userId).toBe("user-2fa-8");
    expect(reuse._tag).toBe("Failure");
    assert(Result.isFailure(reuse));
    expect(reuse.failure._tag).toBe("MultiFactorError");
    expect(secondUse.userId).toBe("user-2fa-8");
    expect(MutableHashMap.size(sessions)).toBe(2);
    expect(
      Option.getOrUndefined(MutableHashMap.get(multiFactorRecords, "user-2fa-8"))?.backupCodes,
    ).toHaveLength(8);
  });

  it("still redeems a backup code stored under its unpeppered digest", async () => {
    const testContext = await makeTestContext();
    await seedUser("user-2fa-legacy", "legacy@example.com", "correct-password");

    const redeemed = await Effect.runPromise(
      Effect.provide(
        Effect.gen(function* () {
          const service = yield* MultiFactor.make({
            issuer: "TestApp",
            skipVerificationOnEnable: true,
          });
          const { backupCodes } = yield* service.enable("user-2fa-legacy", "correct-password");
          const code = backupCodes[0] ?? "";
          // Rewrite the record as a deployment before the pepper stored it.
          const record = Option.getOrUndefined(
            MutableHashMap.get(multiFactorRecords, "user-2fa-legacy"),
          );
          assert(record !== undefined, "the enrolment is stored");
          MutableHashMap.set(multiFactorRecords, "user-2fa-legacy", {
            ...record,
            backupCodes: [sha256Hex(code.replace("-", "")), ...record.backupCodes.slice(1)],
          });
          const challenge = yield* service.beginChallenge("user-2fa-legacy");
          return yield* service.verifyBackupCode(challenge.token, code);
        }),
        testContext,
      ).pipe(Effect.provide(Hooks.Default)),
    );

    expect(redeemed.userId).toBe("user-2fa-legacy");
    expect(
      Option.getOrUndefined(MutableHashMap.get(multiFactorRecords, "user-2fa-legacy"))?.backupCodes,
    ).toHaveLength(9);
  });

  describe("concurrent redemptions", () => {
    const race = async <A, E>(
      userId: string,
      redeem: (
        service: Effect.Success<ReturnType<typeof MultiFactor.make>>,
        enabled: { readonly secret: string; readonly backupCodes: ReadonlyArray<string> },
      ) => Effect.Effect<ReadonlyArray<Effect.Effect<A, E>>, unknown>,
    ) => {
      const testContext = await makeTestContext();
      await seedUser(userId, `${userId}@example.com`, "correct-password");
      return Effect.runPromise(
        Effect.provide(
          Effect.gen(function* () {
            const service = yield* MultiFactor.make({
              issuer: "TestApp",
              skipVerificationOnEnable: true,
            });
            const enabled = yield* service.enable(userId, "correct-password");
            const attempts = yield* redeem(service, enabled);
            return yield* Effect.all(attempts.map(Effect.result), { concurrency: "unbounded" });
          }),
          testContext,
        ).pipe(Effect.provide(Hooks.Default)),
      );
    };

    it("accepts one TOTP code once across concurrent challenges", async () => {
      const results = await race("user-2fa-race-totp", (service, { secret }) =>
        Effect.gen(function* () {
          const code = yield* generateTotp(secret);
          const first = yield* service.beginChallenge("user-2fa-race-totp");
          const second = yield* service.beginChallenge("user-2fa-race-totp");
          return [service.verifyTotp(first.token, code), service.verifyTotp(second.token, code)];
        }),
      );
      expect(results.filter(Result.isSuccess)).toHaveLength(1);
      expect(MutableHashMap.size(sessions)).toBe(1);
    });

    it("accepts one backup code once across concurrent challenges", async () => {
      const results = await race("user-2fa-race-backup", (service, { backupCodes }) =>
        Effect.gen(function* () {
          const first = yield* service.beginChallenge("user-2fa-race-backup");
          const second = yield* service.beginChallenge("user-2fa-race-backup");
          return [
            service.verifyBackupCode(first.token, backupCodes[0] ?? ""),
            service.verifyBackupCode(second.token, backupCodes[0] ?? ""),
          ];
        }),
      );
      expect(results.filter(Result.isSuccess)).toHaveLength(1);
      expect(MutableHashMap.size(sessions)).toBe(1);
      expect(
        Option.getOrUndefined(MutableHashMap.get(multiFactorRecords, "user-2fa-race-backup"))
          ?.backupCodes,
      ).toHaveLength(9);
    });

    it("creates one session from one challenge redeemed concurrently with two codes", async () => {
      const results = await race("user-2fa-race-pending", (service, { backupCodes }) =>
        Effect.gen(function* () {
          const challenge = yield* service.beginChallenge("user-2fa-race-pending");
          return [
            service.verifyBackupCode(challenge.token, backupCodes[0] ?? ""),
            service.verifyBackupCode(challenge.token, backupCodes[1] ?? ""),
          ];
        }),
      );
      expect(results.filter(Result.isSuccess)).toHaveLength(1);
      expect(MutableHashMap.size(sessions)).toBe(1);
    });
  });

  it("should invalidate old backup codes on regeneration", async () => {
    const testContext = await makeTestContext();
    await seedUser("user-2fa-9", "regen@example.com", "correct-password");

    const { wrongPassword, oldCodes, newCodes, oldCodeResult, newCodeResult } =
      await Effect.runPromise(
        Effect.provide(
          Effect.gen(function* () {
            const service = yield* MultiFactor.make({
              issuer: "TestApp",
              skipVerificationOnEnable: true,
              backupCodeCount: 4,
            });

            const { backupCodes: oldCodes } = yield* service.enable(
              "user-2fa-9",
              "correct-password",
            );

            const wrongPassword = yield* Effect.result(
              service.regenerateBackupCodes("user-2fa-9", "wrong-password"),
            );

            const newCodes = yield* service.regenerateBackupCodes("user-2fa-9", "correct-password");

            const challenge = yield* service.beginChallenge("user-2fa-9");
            const oldCodeResult = yield* Effect.result(
              service.verifyBackupCode(challenge.token, oldCodes[0]),
            );
            const newCodeResult = yield* service.verifyBackupCode(challenge.token, newCodes[0]);

            return { wrongPassword, oldCodes, newCodes, oldCodeResult, newCodeResult };
          }),
          testContext,
        ).pipe(Effect.provide(Hooks.Default)),
      );

    expect(wrongPassword._tag).toBe("Failure");
    assert(Result.isFailure(wrongPassword));
    expect(wrongPassword.failure._tag).toBe("InvalidCredentialsError");
    expect(newCodes).toHaveLength(4);
    expect(newCodes).not.toEqual(oldCodes);
    expect(oldCodeResult._tag).toBe("Failure");
    expect(newCodeResult.userId).toBe("user-2fa-9");
  });

  it("should not begin a challenge for a user without verified multi-factor", async () => {
    const testContext = await makeTestContext();
    await seedUser("user-2fa-10", "nochallenge@example.com", "correct-password");

    const { withoutRecord, unverified } = await Effect.runPromise(
      Effect.provide(
        Effect.gen(function* () {
          const service = yield* MultiFactor.make({ issuer: "TestApp" });

          const withoutRecord = yield* Effect.result(service.beginChallenge("user-2fa-10"));

          // Enabled but not yet confirmed: still not challengeable
          yield* service.enable("user-2fa-10", "correct-password");
          const unverified = yield* Effect.result(service.beginChallenge("user-2fa-10"));

          return { withoutRecord, unverified };
        }),
        testContext,
      ).pipe(Effect.provide(Hooks.Default)),
    );

    expect(withoutRecord._tag).toBe("Failure");
    assert(Result.isFailure(withoutRecord));
    expect(withoutRecord.failure._tag).toBe("MultiFactorError");
    expect(unverified._tag).toBe("Failure");
    assert(Result.isFailure(unverified));
    expect(unverified.failure._tag).toBe("MultiFactorError");
    expect(MutableHashMap.size(pendingChallenges)).toBe(0);
  });
});

describe("MultiFactorService with TOTP secret encryption", () => {
  beforeEach(() => {
    MutableHashMap.clear(users);
    MutableHashMap.clear(identifiers);
    MutableHashMap.clear(passwordHashes);
    MutableHashMap.clear(multiFactorRecords);
    MutableHashMap.clear(pendingChallenges);
    MutableHashMap.clear(pendingAttempts);
    MutableHashMap.clear(sessions);
  });

  it("should enroll and verify TOTP with { secret } encryption", async () => {
    const testContext = await makeTestContext();
    await seedUser("user-enc-1", "enc-totp@example.com", "correct-password");

    const { enableResult, enabled, verifyResult } = await Effect.runPromise(
      Effect.provide(
        Effect.gen(function* () {
          const service = yield* MultiFactor.make({
            issuer: "TestApp",
            skipVerificationOnEnable: false,
            encryptSecret: { secret: Redacted.make("totp-encryption-secret-32-bytes!!") },
          });

          const enableResult = yield* service.enable("user-enc-1", "correct-password");

          // Confirm with the previous time step's code (within the default ±1
          // window) so the challenge verification below can use the current
          // step's code without tripping the replay guard.
          const currentCounter = Math.floor((yield* Clock.currentTimeMillis) / 1000 / 30);
          const confirmCode = yield* generateHotp(enableResult.secret, currentCounter - 1);
          yield* service.confirmEnable("user-enc-1", confirmCode);

          const enabled = yield* service.isEnabled("user-enc-1");

          const challenge = yield* service.beginChallenge("user-enc-1");
          const verifyCode = yield* generateTotp(enableResult.secret);
          const verifyResult = yield* service.verifyTotp(challenge.token, verifyCode);

          return { enableResult, enabled, verifyResult };
        }),
        testContext,
      ).pipe(Effect.provide(Hooks.Default)),
    );

    expect(enabled).toBe(true);
    expect(verifyResult.userId).toBe("user-enc-1");
    expect(MutableHashMap.size(sessions)).toBe(1);

    // The stored secret must be ciphertext, not the plaintext base32 secret
    const record = Option.getOrUndefined(MutableHashMap.get(multiFactorRecords, "user-enc-1"));
    expect(record?.secret).toBeDefined();
    expect(record?.secret).not.toBe(enableResult.secret);
    expect(record?.secret).not.toMatch(/^[A-Z2-7]+=*$/);
  });

  it("should enroll and verify TOTP with a custom { cipher }", async () => {
    const testContext = await makeTestContext();
    await seedUser("user-enc-2", "enc-cipher@example.com", "correct-password");

    const { enableResult, verifyResult } = await Effect.runPromise(
      Effect.provide(
        Effect.gen(function* () {
          const cipher = yield* Effect.orDie(Cipher.aes256GcmCipher("custom-cipher-secret"));
          const service = yield* MultiFactor.make({
            issuer: "TestApp",
            skipVerificationOnEnable: true,
            encryptSecret: { cipher },
          });

          const enableResult = yield* service.enable("user-enc-2", "correct-password");

          const challenge = yield* service.beginChallenge("user-enc-2");
          const code = yield* generateTotp(enableResult.secret);
          const verifyResult = yield* service.verifyTotp(challenge.token, code);

          return { enableResult, verifyResult };
        }),
        testContext,
      ).pipe(Effect.provide(Hooks.Default)),
    );

    expect(verifyResult.userId).toBe("user-enc-2");

    // Stored secret is ciphertext
    const record = Option.getOrUndefined(MutableHashMap.get(multiFactorRecords, "user-enc-2"));
    expect(record?.secret).not.toBe(enableResult.secret);
  });

  it("should return plaintext secret and valid totpUri from enable even with encryption", async () => {
    const testContext = await makeTestContext();
    await seedUser("user-enc-3", "enc-uri@example.com", "correct-password");

    const result = await Effect.runPromise(
      Effect.provide(
        Effect.gen(function* () {
          const service = yield* MultiFactor.make({
            issuer: "TestApp",
            encryptSecret: { secret: Redacted.make("totp-encryption-secret-32-bytes!!") },
          });
          return yield* service.enable("user-enc-3", "correct-password");
        }),
        testContext,
      ).pipe(Effect.provide(Hooks.Default)),
    );

    // The returned secret is plaintext base32 (for QR code display)
    expect(result.secret).toMatch(/^[A-Z2-7]+=*$/);
    // The totpUri uses the plaintext secret
    expect(result.totpUri).toContain(result.secret);
    expect(result.totpUri).toContain("otpauth://totp/");
  });

  it("should accept backup code redemption when secret is encrypted", async () => {
    const testContext = await makeTestContext();
    await seedUser("user-enc-4", "enc-backup@example.com", "correct-password");

    const result = await Effect.runPromise(
      Effect.provide(
        Effect.gen(function* () {
          const service = yield* MultiFactor.make({
            issuer: "TestApp",
            skipVerificationOnEnable: true,
            encryptSecret: { secret: Redacted.make("totp-encryption-secret-32-bytes!!") },
          });

          const { backupCodes } = yield* service.enable("user-enc-4", "correct-password");

          const challenge = yield* service.beginChallenge("user-enc-4");
          return yield* service.verifyBackupCode(challenge.token, backupCodes[0]);
        }),
        testContext,
      ).pipe(Effect.provide(Hooks.Default)),
    );

    expect(result.userId).toBe("user-enc-4");
    expect(MutableHashMap.size(sessions)).toBe(1);
  });
});
