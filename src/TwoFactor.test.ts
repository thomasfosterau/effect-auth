import { describe, it, expect, beforeEach } from "vite-plus/test";
import { Context, Effect, Redacted } from "effect";
import { Hooks } from "./Hooks.js";
import { SessionStore } from "./SessionStore.js";
import { UserStore } from "./UserStore.js";
import { SessionService } from "./SessionService.js";
import {
  makeTwoFactorService,
  type PendingTwoFactor,
  type TwoFactorRecord,
  TwoFactorStore,
  PendingTwoFactorStore,
} from "./TwoFactor.js";
import { makeAes256GcmCipher } from "./Cipher.js";
import { type CreateUserInput, EmailPasswordStore } from "./EmailPassword.js";
import { generateTOTP } from "./Otp.js";
import { PasswordHasher, makePBKDF2Hasher } from "./Password.js";
import type { Session, User, SessionConfig } from "./Types.js";

const users = new Map<string, User>();
const usersByEmail = new Map<string, string>();
const passwordHashes = new Map<string, string>();
const twoFactorRecords = new Map<string, TwoFactorRecord>();
const pendingChallenges = new Map<string, PendingTwoFactor>();
const sessions = new Map<string, Session>();

const sessionStore = {
  create: (session: Session) =>
    Effect.sync(() => {
      sessions.set(session.id, session);
      return session;
    }),

  get: (sessionId: string) => Effect.sync(() => sessions.get(sessionId) ?? null),

  update: (session: Session) =>
    Effect.sync(() => {
      sessions.set(session.id, session);
      return session;
    }),

  delete: (sessionId: string) =>
    Effect.sync(() => {
      sessions.delete(sessionId);
    }),

  deleteByUserId: (userId: string) =>
    Effect.sync(() => {
      for (const [id, session] of sessions.entries()) {
        if (session.userId === userId) {
          sessions.delete(id);
        }
      }
    }),

  listByUserId: (userId: string) =>
    Effect.sync(() => Array.from(sessions.values()).filter((session) => session.userId === userId)),
};

const userStore = {
  get: (userId: string) => Effect.sync(() => users.get(userId) ?? null),

  getCredentials: (userId: string) => Effect.sync(() => passwordHashes.get(userId) ?? null),
};

const emailPasswordStore = {
  getUserByEmail: (email: string) =>
    Effect.sync(() => {
      const userId = usersByEmail.get(email);
      return userId ? (users.get(userId) ?? null) : null;
    }),

  createUser: (input: CreateUserInput) =>
    Effect.sync(() => {
      const user: User = {
        id: `user-${users.size + 1}`,
        email: input.email,
        emailVerified: false,
        ...(input.name !== undefined && { name: input.name }),
        createdAt: new Date(),
        updatedAt: new Date(),
        attributes: input.attributes ?? {},
      };
      users.set(user.id, user);
      usersByEmail.set(user.email, user.id);
      return user;
    }),

  getPasswordHash: (userId: string) => Effect.sync(() => passwordHashes.get(userId) ?? null),

  setPasswordHash: (userId: string, hash: string) =>
    Effect.sync(() => {
      passwordHashes.set(userId, hash);
    }),
};

const twoFactorStore = {
  get: (userId: string) => Effect.sync(() => twoFactorRecords.get(userId) ?? null),

  upsert: (record: TwoFactorRecord) =>
    Effect.sync(() => {
      twoFactorRecords.set(record.userId, record);
      return record;
    }),

  delete: (userId: string) =>
    Effect.sync(() => {
      twoFactorRecords.delete(userId);
    }),
};

const pendingTwoFactorStore = {
  create: (pending: PendingTwoFactor) =>
    Effect.sync(() => {
      pendingChallenges.set(pending.token, pending);
      return pending;
    }),

  get: (token: string) => Effect.sync(() => pendingChallenges.get(token) ?? null),

  delete: (token: string) =>
    Effect.sync(() => {
      pendingChallenges.delete(token);
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
      SessionService.make(sessionConfig),
      Context.merge(Context.make(SessionStore, sessionStore), Context.make(UserStore, userStore)),
    ),
  );

  return Context.merge(
    Context.make(SessionService, sessionManager),
    Context.merge(
      Context.make(SessionStore, sessionStore),
      Context.merge(
        Context.make(UserStore, userStore),
        Context.merge(
          Context.make(EmailPasswordStore, emailPasswordStore),
          Context.merge(
            Context.make(TwoFactorStore, twoFactorStore),
            Context.merge(
              Context.make(PendingTwoFactorStore, pendingTwoFactorStore),
              Context.make(PasswordHasher, makePBKDF2Hasher()),
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
    email,
    emailVerified: true,
    createdAt: new Date(),
    updatedAt: new Date(),
    attributes: {},
  };
  users.set(id, user);
  usersByEmail.set(email, id);

  const hasher = makePBKDF2Hasher();
  const hashed = await Effect.runPromise(hasher.hash(password));
  passwordHashes.set(id, hashed.hash);

  return user;
};

describe("TwoFactorService", () => {
  beforeEach(() => {
    users.clear();
    usersByEmail.clear();
    passwordHashes.clear();
    twoFactorRecords.clear();
    pendingChallenges.clear();
    sessions.clear();
  });

  it("should enable, confirm with a TOTP code, and report two-factor as enabled", async () => {
    const testContext = await makeTestContext();
    await seedUser("user-2fa-1", "totp@example.com", "correct-password");

    const program = Effect.gen(function* () {
      const service = yield* makeTwoFactorService({ issuer: "TestApp" });

      const enableResult = yield* service.enable("user-2fa-1", "correct-password");
      const enabledBeforeConfirm = yield* service.isEnabled("user-2fa-1");

      const code = yield* generateTOTP(enableResult.secret);
      yield* service.confirmEnable("user-2fa-1", code);

      const enabledAfterConfirm = yield* service.isEnabled("user-2fa-1");

      return { enableResult, enabledBeforeConfirm, enabledAfterConfirm };
    });

    const { enableResult, enabledBeforeConfirm, enabledAfterConfirm } = await Effect.runPromise(
      Effect.provide(program, testContext).pipe(Effect.provide(Hooks.Default)),
    );

    expect(enableResult.secret.length).toBeGreaterThan(0);
    expect(enableResult.totpUri).toContain("otpauth://totp/");
    expect(enableResult.totpUri).toContain("TestApp");
    expect(enableResult.totpUri).toContain(encodeURIComponent("totp@example.com"));
    expect(enableResult.backupCodes).toHaveLength(10);
    for (const code of enableResult.backupCodes) {
      expect(code).toMatch(/^[0-9a-f]{5}-[0-9a-f]{5}$/);
    }

    // Backup codes are stored hashed, never in plaintext
    const record = twoFactorRecords.get("user-2fa-1");
    expect(record?.verified).toBe(true);
    for (const plaintext of enableResult.backupCodes) {
      expect(record?.backupCodes).not.toContain(plaintext);
    }

    expect(enabledBeforeConfirm).toBe(false);
    expect(enabledAfterConfirm).toBe(true);
  });

  it("should reject confirmEnable with an invalid code", async () => {
    const testContext = await makeTestContext();
    await seedUser("user-2fa-2", "badcode@example.com", "correct-password");

    const program = Effect.gen(function* () {
      const service = yield* makeTwoFactorService({ issuer: "TestApp" });
      yield* service.enable("user-2fa-2", "correct-password");
      return yield* Effect.result(service.confirmEnable("user-2fa-2", "000000"));
    });

    const result = await Effect.runPromise(
      Effect.provide(program, testContext).pipe(Effect.provide(Hooks.Default)),
    );

    expect(result._tag).toBe("Failure");
    if (result._tag === "Failure") {
      expect(result.failure._tag).toBe("TwoFactorError");
    }
    expect(twoFactorRecords.get("user-2fa-2")?.verified).toBe(false);
  });

  it("should fail to enable with a wrong password", async () => {
    const testContext = await makeTestContext();
    await seedUser("user-2fa-3", "wrongpw@example.com", "correct-password");

    const program = Effect.gen(function* () {
      const service = yield* makeTwoFactorService({ issuer: "TestApp" });
      return yield* Effect.result(service.enable("user-2fa-3", "wrong-password"));
    });

    const result = await Effect.runPromise(
      Effect.provide(program, testContext).pipe(Effect.provide(Hooks.Default)),
    );

    expect(result._tag).toBe("Failure");
    if (result._tag === "Failure") {
      expect(result.failure._tag).toBe("InvalidCredentialsError");
    }
    expect(twoFactorRecords.size).toBe(0);
  });

  it("should fail to disable with a wrong password and remove the record on success", async () => {
    const testContext = await makeTestContext();
    await seedUser("user-2fa-4", "disable@example.com", "correct-password");

    const program = Effect.gen(function* () {
      const service = yield* makeTwoFactorService({
        issuer: "TestApp",
        skipVerificationOnEnable: true,
      });

      yield* service.enable("user-2fa-4", "correct-password");

      const wrongPassword = yield* Effect.result(service.disable("user-2fa-4", "wrong-password"));
      const stillEnabled = yield* service.isEnabled("user-2fa-4");

      yield* service.disable("user-2fa-4", "correct-password");
      const enabledAfterDisable = yield* service.isEnabled("user-2fa-4");

      return { wrongPassword, stillEnabled, enabledAfterDisable };
    });

    const { wrongPassword, stillEnabled, enabledAfterDisable } = await Effect.runPromise(
      Effect.provide(program, testContext).pipe(Effect.provide(Hooks.Default)),
    );

    expect(wrongPassword._tag).toBe("Failure");
    if (wrongPassword._tag === "Failure") {
      expect(wrongPassword.failure._tag).toBe("InvalidCredentialsError");
    }
    expect(stillEnabled).toBe(true);
    expect(enabledAfterDisable).toBe(false);
    expect(twoFactorRecords.size).toBe(0);
  });

  it("should create a session on the challenge + verifyTotp happy path", async () => {
    const testContext = await makeTestContext();
    await seedUser("user-2fa-5", "challenge@example.com", "correct-password");

    const program = Effect.gen(function* () {
      const service = yield* makeTwoFactorService({
        issuer: "TestApp",
        skipVerificationOnEnable: true,
      });

      const { secret } = yield* service.enable("user-2fa-5", "correct-password");
      const challenge = yield* service.beginChallenge("user-2fa-5");

      const code = yield* generateTOTP(secret);
      return yield* service.verifyTotp(challenge.token, code, {
        sessionAttributes: { device: "test" },
      });
    });

    const result = await Effect.runPromise(
      Effect.provide(program, testContext).pipe(Effect.provide(Hooks.Default)),
    );

    expect(result.userId).toBe("user-2fa-5");
    expect(result.session.userId).toBe("user-2fa-5");
    expect(result.session.attributes).toEqual({ device: "test" });
    expect(sessions.size).toBe(1);
    // Pending token is consumed on success
    expect(pendingChallenges.size).toBe(0);
  });

  it("should reject an expired pending token", async () => {
    const testContext = await makeTestContext();
    await seedUser("user-2fa-6", "expired@example.com", "correct-password");

    const program = Effect.gen(function* () {
      const service = yield* makeTwoFactorService({
        issuer: "TestApp",
        skipVerificationOnEnable: true,
        pendingExpiresIn: -1000, // Already expired on creation
      });

      const { secret } = yield* service.enable("user-2fa-6", "correct-password");
      const challenge = yield* service.beginChallenge("user-2fa-6");

      const code = yield* generateTOTP(secret);
      return yield* Effect.result(service.verifyTotp(challenge.token, code));
    });

    const result = await Effect.runPromise(
      Effect.provide(program, testContext).pipe(Effect.provide(Hooks.Default)),
    );

    expect(result._tag).toBe("Failure");
    if (result._tag === "Failure") {
      expect(result.failure._tag).toBe("TwoFactorError");
    }
    expect(sessions.size).toBe(0);
    // Expired tokens are deleted eagerly
    expect(pendingChallenges.size).toBe(0);
  });

  it("should reject a replayed pending token", async () => {
    const testContext = await makeTestContext();
    await seedUser("user-2fa-7", "replay@example.com", "correct-password");

    const program = Effect.gen(function* () {
      const service = yield* makeTwoFactorService({
        issuer: "TestApp",
        skipVerificationOnEnable: true,
      });

      const { secret } = yield* service.enable("user-2fa-7", "correct-password");
      const challenge = yield* service.beginChallenge("user-2fa-7");

      const code = yield* generateTOTP(secret);
      yield* service.verifyTotp(challenge.token, code);

      const replayCode = yield* generateTOTP(secret);
      return yield* Effect.result(service.verifyTotp(challenge.token, replayCode));
    });

    const result = await Effect.runPromise(
      Effect.provide(program, testContext).pipe(Effect.provide(Hooks.Default)),
    );

    expect(result._tag).toBe("Failure");
    if (result._tag === "Failure") {
      expect(result.failure._tag).toBe("TwoFactorError");
    }
    // Only the first verification created a session
    expect(sessions.size).toBe(1);
  });

  it("should accept a backup code only once", async () => {
    const testContext = await makeTestContext();
    await seedUser("user-2fa-8", "backup@example.com", "correct-password");

    const program = Effect.gen(function* () {
      const service = yield* makeTwoFactorService({
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
    });

    const { firstUse, reuse, secondUse } = await Effect.runPromise(
      Effect.provide(program, testContext).pipe(Effect.provide(Hooks.Default)),
    );

    expect(firstUse.userId).toBe("user-2fa-8");
    expect(reuse._tag).toBe("Failure");
    if (reuse._tag === "Failure") {
      expect(reuse.failure._tag).toBe("TwoFactorError");
    }
    expect(secondUse.userId).toBe("user-2fa-8");
    expect(sessions.size).toBe(2);
    expect(twoFactorRecords.get("user-2fa-8")?.backupCodes).toHaveLength(8);
  });

  it("should invalidate old backup codes on regeneration", async () => {
    const testContext = await makeTestContext();
    await seedUser("user-2fa-9", "regen@example.com", "correct-password");

    const program = Effect.gen(function* () {
      const service = yield* makeTwoFactorService({
        issuer: "TestApp",
        skipVerificationOnEnable: true,
        backupCodeCount: 4,
      });

      const { backupCodes: oldCodes } = yield* service.enable("user-2fa-9", "correct-password");

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
    });

    const { wrongPassword, oldCodes, newCodes, oldCodeResult, newCodeResult } =
      await Effect.runPromise(
        Effect.provide(program, testContext).pipe(Effect.provide(Hooks.Default)),
      );

    expect(wrongPassword._tag).toBe("Failure");
    if (wrongPassword._tag === "Failure") {
      expect(wrongPassword.failure._tag).toBe("InvalidCredentialsError");
    }
    expect(newCodes).toHaveLength(4);
    expect(newCodes).not.toEqual(oldCodes);
    expect(oldCodeResult._tag).toBe("Failure");
    expect(newCodeResult.userId).toBe("user-2fa-9");
  });

  it("should not begin a challenge for a user without verified two-factor", async () => {
    const testContext = await makeTestContext();
    await seedUser("user-2fa-10", "nochallenge@example.com", "correct-password");

    const program = Effect.gen(function* () {
      const service = yield* makeTwoFactorService({ issuer: "TestApp" });

      const withoutRecord = yield* Effect.result(service.beginChallenge("user-2fa-10"));

      // Enabled but not yet confirmed: still not challengeable
      yield* service.enable("user-2fa-10", "correct-password");
      const unverified = yield* Effect.result(service.beginChallenge("user-2fa-10"));

      return { withoutRecord, unverified };
    });

    const { withoutRecord, unverified } = await Effect.runPromise(
      Effect.provide(program, testContext).pipe(Effect.provide(Hooks.Default)),
    );

    expect(withoutRecord._tag).toBe("Failure");
    if (withoutRecord._tag === "Failure") {
      expect(withoutRecord.failure._tag).toBe("TwoFactorError");
    }
    expect(unverified._tag).toBe("Failure");
    if (unverified._tag === "Failure") {
      expect(unverified.failure._tag).toBe("TwoFactorError");
    }
    expect(pendingChallenges.size).toBe(0);
  });
});

describe("TwoFactorService with TOTP secret encryption", () => {
  beforeEach(() => {
    users.clear();
    usersByEmail.clear();
    passwordHashes.clear();
    twoFactorRecords.clear();
    pendingChallenges.clear();
    sessions.clear();
  });

  it("should enroll and verify TOTP with { secret } encryption", async () => {
    const testContext = await makeTestContext();
    await seedUser("user-enc-1", "enc-totp@example.com", "correct-password");

    const program = Effect.gen(function* () {
      const service = yield* makeTwoFactorService({
        issuer: "TestApp",
        skipVerificationOnEnable: false,
        encryptSecret: { secret: Redacted.make("totp-encryption-secret-32-bytes!!") },
      });

      const enableResult = yield* service.enable("user-enc-1", "correct-password");

      const code = yield* generateTOTP(enableResult.secret);
      yield* service.confirmEnable("user-enc-1", code);

      const enabled = yield* service.isEnabled("user-enc-1");

      const challenge = yield* service.beginChallenge("user-enc-1");
      const verifyCode = yield* generateTOTP(enableResult.secret);
      const verifyResult = yield* service.verifyTotp(challenge.token, verifyCode);

      return { enableResult, enabled, verifyResult };
    });

    const { enableResult, enabled, verifyResult } = await Effect.runPromise(
      Effect.provide(program, testContext).pipe(Effect.provide(Hooks.Default)),
    );

    expect(enabled).toBe(true);
    expect(verifyResult.userId).toBe("user-enc-1");
    expect(sessions.size).toBe(1);

    // The stored secret must be ciphertext, not the plaintext base32 secret
    const record = twoFactorRecords.get("user-enc-1");
    expect(record?.secret).toBeDefined();
    expect(record?.secret).not.toBe(enableResult.secret);
    expect(record?.secret).not.toMatch(/^[A-Z2-7]+=*$/);
  });

  it("should enroll and verify TOTP with a custom { cipher }", async () => {
    const testContext = await makeTestContext();
    await seedUser("user-enc-2", "enc-cipher@example.com", "correct-password");

    const cipher = makeAes256GcmCipher("custom-cipher-secret");

    const program = Effect.gen(function* () {
      const service = yield* makeTwoFactorService({
        issuer: "TestApp",
        skipVerificationOnEnable: true,
        encryptSecret: { cipher },
      });

      const enableResult = yield* service.enable("user-enc-2", "correct-password");

      const challenge = yield* service.beginChallenge("user-enc-2");
      const code = yield* generateTOTP(enableResult.secret);
      const verifyResult = yield* service.verifyTotp(challenge.token, code);

      return { enableResult, verifyResult };
    });

    const { enableResult, verifyResult } = await Effect.runPromise(
      Effect.provide(program, testContext).pipe(Effect.provide(Hooks.Default)),
    );

    expect(verifyResult.userId).toBe("user-enc-2");

    // Stored secret is ciphertext
    const record = twoFactorRecords.get("user-enc-2");
    expect(record?.secret).not.toBe(enableResult.secret);
  });

  it("should return plaintext secret and valid totpUri from enable even with encryption", async () => {
    const testContext = await makeTestContext();
    await seedUser("user-enc-3", "enc-uri@example.com", "correct-password");

    const program = Effect.gen(function* () {
      const service = yield* makeTwoFactorService({
        issuer: "TestApp",
        encryptSecret: { secret: Redacted.make("totp-encryption-secret-32-bytes!!") },
      });
      return yield* service.enable("user-enc-3", "correct-password");
    });

    const result = await Effect.runPromise(
      Effect.provide(program, testContext).pipe(Effect.provide(Hooks.Default)),
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

    const program = Effect.gen(function* () {
      const service = yield* makeTwoFactorService({
        issuer: "TestApp",
        skipVerificationOnEnable: true,
        encryptSecret: { secret: Redacted.make("totp-encryption-secret-32-bytes!!") },
      });

      const { backupCodes } = yield* service.enable("user-enc-4", "correct-password");

      const challenge = yield* service.beginChallenge("user-enc-4");
      return yield* service.verifyBackupCode(challenge.token, backupCodes[0]);
    });

    const result = await Effect.runPromise(
      Effect.provide(program, testContext).pipe(Effect.provide(Hooks.Default)),
    );

    expect(result.userId).toBe("user-enc-4");
    expect(sessions.size).toBe(1);
  });
});
