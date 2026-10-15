import { describe, it, expect, beforeEach } from "vite-plus/test";
import { Context, Crypto, Effect, Redacted } from "effect";
import { Hooks } from "../Hooks.ts";
import * as PlatformCrypto from "../PlatformCrypto.ts";
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
import type { Session, User, SessionConfig } from "../Types.ts";

const users = new Map<string, User>();
const identifiers = new Map<string, Identifier>();
const passwordHashes = new Map<string, string>();
const multiFactorRecords = new Map<string, MultiFactorRecord>();
const pendingChallenges = new Map<string, PendingMultiFactor>();
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
};

const emailPasswordStore = {
  createUser: (input: CreateUserInput) =>
    Effect.sync(() => {
      const user: User = {
        id: `user-${users.size + 1}`,
        ...(input.name !== undefined && { name: input.name }),
        createdAt: new Date(),
        updatedAt: new Date(),
        attributes: input.attributes ?? {},
      };
      users.set(user.id, user);
      return { user, created: true };
    }),

  getPasswordHash: (userId: string) => Effect.sync(() => passwordHashes.get(userId) ?? null),

  setPasswordHash: (userId: string, hash: string) =>
    Effect.sync(() => {
      passwordHashes.set(userId, hash);
    }),
};

const multiFactorStore = {
  get: (userId: string) => Effect.sync(() => multiFactorRecords.get(userId) ?? null),

  upsert: (record: MultiFactorRecord) =>
    Effect.sync(() => {
      multiFactorRecords.set(record.userId, record);
      return record;
    }),

  delete: (userId: string) =>
    Effect.sync(() => {
      multiFactorRecords.delete(userId);
    }),
};

const pendingMultiFactorStore = {
  create: (pending: PendingMultiFactor) =>
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
      makeSessionService(sessionConfig),
      Context.merge(
        Context.merge(Context.make(SessionStore, sessionStore), Context.make(UserStore, userStore)),
        Context.make(Crypto.Crypto, PlatformCrypto.instance),
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
              Context.make(Crypto.Crypto, PlatformCrypto.instance),
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
    createdAt: new Date(),
    updatedAt: new Date(),
    attributes: {},
  };
  users.set(id, user);
  const identifier = makeIdentifier({
    userId: id,
    type: "email",
    value: email,
    verified: true,
    verifiedAt: new Date(),
  });
  identifiers.set(identifier.id, identifier);

  const hasher = Password.pbkdf2Hasher({ iterations: 1000 });
  const hashed = await Effect.runPromise(hasher.hash(password));
  passwordHashes.set(id, hashed.hash);

  return user;
};

describe("MultiFactorService", () => {
  beforeEach(() => {
    users.clear();
    identifiers.clear();
    passwordHashes.clear();
    multiFactorRecords.clear();
    pendingChallenges.clear();
    sessions.clear();
  });

  it("should enable, confirm with a TOTP code, and report multi-factor as enabled", async () => {
    const testContext = await makeTestContext();
    await seedUser("user-2fa-1", "totp@example.com", "correct-password");

    const program = Effect.gen(function* () {
      const service = yield* MultiFactor.make({ issuer: "TestApp" });

      const enableResult = yield* service.enable("user-2fa-1", "correct-password");
      const enabledBeforeConfirm = yield* service.isEnabled("user-2fa-1");

      const code = yield* generateTotp(enableResult.secret);
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
    const record = multiFactorRecords.get("user-2fa-1");
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
      const service = yield* MultiFactor.make({ issuer: "TestApp" });
      yield* service.enable("user-2fa-2", "correct-password");
      return yield* Effect.result(service.confirmEnable("user-2fa-2", "000000"));
    });

    const result = await Effect.runPromise(
      Effect.provide(program, testContext).pipe(Effect.provide(Hooks.Default)),
    );

    expect(result._tag).toBe("Failure");
    if (result._tag === "Failure") {
      expect(result.failure._tag).toBe("MultiFactorError");
    }
    expect(multiFactorRecords.get("user-2fa-2")?.verified).toBe(false);
  });

  it("should fail to enable with a wrong password", async () => {
    const testContext = await makeTestContext();
    await seedUser("user-2fa-3", "wrongpw@example.com", "correct-password");

    const program = Effect.gen(function* () {
      const service = yield* MultiFactor.make({ issuer: "TestApp" });
      return yield* Effect.result(service.enable("user-2fa-3", "wrong-password"));
    });

    const result = await Effect.runPromise(
      Effect.provide(program, testContext).pipe(Effect.provide(Hooks.Default)),
    );

    expect(result._tag).toBe("Failure");
    if (result._tag === "Failure") {
      expect(result.failure._tag).toBe("InvalidCredentialsError");
    }
    expect(multiFactorRecords.size).toBe(0);
  });

  it("should fail to disable with a wrong password and remove the record on success", async () => {
    const testContext = await makeTestContext();
    await seedUser("user-2fa-4", "disable@example.com", "correct-password");

    const program = Effect.gen(function* () {
      const service = yield* MultiFactor.make({
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
    expect(multiFactorRecords.size).toBe(0);
  });

  it("should create a session on the challenge + verifyTotp happy path", async () => {
    const testContext = await makeTestContext();
    await seedUser("user-2fa-5", "challenge@example.com", "correct-password");

    const program = Effect.gen(function* () {
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
      const service = yield* MultiFactor.make({
        issuer: "TestApp",
        skipVerificationOnEnable: true,
        pendingExpiresIn: -1000, // Already expired on creation
      });

      const { secret } = yield* service.enable("user-2fa-6", "correct-password");
      const challenge = yield* service.beginChallenge("user-2fa-6");

      const code = yield* generateTotp(secret);
      return yield* Effect.result(service.verifyTotp(challenge.token, code));
    });

    const result = await Effect.runPromise(
      Effect.provide(program, testContext).pipe(Effect.provide(Hooks.Default)),
    );

    expect(result._tag).toBe("Failure");
    if (result._tag === "Failure") {
      expect(result.failure._tag).toBe("MultiFactorError");
    }
    expect(sessions.size).toBe(0);
    // Expired tokens are deleted eagerly
    expect(pendingChallenges.size).toBe(0);
  });

  it("should reject a replayed pending token", async () => {
    const testContext = await makeTestContext();
    await seedUser("user-2fa-7", "replay@example.com", "correct-password");

    const program = Effect.gen(function* () {
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
    });

    const result = await Effect.runPromise(
      Effect.provide(program, testContext).pipe(Effect.provide(Hooks.Default)),
    );

    expect(result._tag).toBe("Failure");
    if (result._tag === "Failure") {
      expect(result.failure._tag).toBe("MultiFactorError");
    }
    // Only the first verification created a session
    expect(sessions.size).toBe(1);
  });

  it("should reject a replayed TOTP code on a fresh challenge", async () => {
    const testContext = await makeTestContext();
    await seedUser("user-2fa-7b", "replay2@example.com", "correct-password");

    const program = Effect.gen(function* () {
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
    });

    const result = await Effect.runPromise(
      Effect.provide(program, testContext).pipe(Effect.provide(Hooks.Default)),
    );

    expect(result._tag).toBe("Failure");
    if (result._tag === "Failure") {
      expect(result.failure._tag).toBe("MultiFactorError");
    }
    // Only the first challenge produced a session
    expect(sessions.size).toBe(1);
  });

  it("should accept a backup code only once", async () => {
    const testContext = await makeTestContext();
    await seedUser("user-2fa-8", "backup@example.com", "correct-password");

    const program = Effect.gen(function* () {
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
    });

    const { firstUse, reuse, secondUse } = await Effect.runPromise(
      Effect.provide(program, testContext).pipe(Effect.provide(Hooks.Default)),
    );

    expect(firstUse.userId).toBe("user-2fa-8");
    expect(reuse._tag).toBe("Failure");
    if (reuse._tag === "Failure") {
      expect(reuse.failure._tag).toBe("MultiFactorError");
    }
    expect(secondUse.userId).toBe("user-2fa-8");
    expect(sessions.size).toBe(2);
    expect(multiFactorRecords.get("user-2fa-8")?.backupCodes).toHaveLength(8);
  });

  it("should invalidate old backup codes on regeneration", async () => {
    const testContext = await makeTestContext();
    await seedUser("user-2fa-9", "regen@example.com", "correct-password");

    const program = Effect.gen(function* () {
      const service = yield* MultiFactor.make({
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

  it("should not begin a challenge for a user without verified multi-factor", async () => {
    const testContext = await makeTestContext();
    await seedUser("user-2fa-10", "nochallenge@example.com", "correct-password");

    const program = Effect.gen(function* () {
      const service = yield* MultiFactor.make({ issuer: "TestApp" });

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
      expect(withoutRecord.failure._tag).toBe("MultiFactorError");
    }
    expect(unverified._tag).toBe("Failure");
    if (unverified._tag === "Failure") {
      expect(unverified.failure._tag).toBe("MultiFactorError");
    }
    expect(pendingChallenges.size).toBe(0);
  });
});

describe("MultiFactorService with TOTP secret encryption", () => {
  beforeEach(() => {
    users.clear();
    identifiers.clear();
    passwordHashes.clear();
    multiFactorRecords.clear();
    pendingChallenges.clear();
    sessions.clear();
  });

  it("should enroll and verify TOTP with { secret } encryption", async () => {
    const testContext = await makeTestContext();
    await seedUser("user-enc-1", "enc-totp@example.com", "correct-password");

    const program = Effect.gen(function* () {
      const service = yield* MultiFactor.make({
        issuer: "TestApp",
        skipVerificationOnEnable: false,
        encryptSecret: { secret: Redacted.make("totp-encryption-secret-32-bytes!!") },
      });

      const enableResult = yield* service.enable("user-enc-1", "correct-password");

      // Confirm with the previous time step's code (within the default ±1
      // window) so the challenge verification below can use the current
      // step's code without tripping the replay guard.
      const currentCounter = Math.floor(Date.now() / 1000 / 30);
      const confirmCode = yield* generateHotp(enableResult.secret, currentCounter - 1);
      yield* service.confirmEnable("user-enc-1", confirmCode);

      const enabled = yield* service.isEnabled("user-enc-1");

      const challenge = yield* service.beginChallenge("user-enc-1");
      const verifyCode = yield* generateTotp(enableResult.secret);
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
    const record = multiFactorRecords.get("user-enc-1");
    expect(record?.secret).toBeDefined();
    expect(record?.secret).not.toBe(enableResult.secret);
    expect(record?.secret).not.toMatch(/^[A-Z2-7]+=*$/);
  });

  it("should enroll and verify TOTP with a custom { cipher }", async () => {
    const testContext = await makeTestContext();
    await seedUser("user-enc-2", "enc-cipher@example.com", "correct-password");

    const cipher = Cipher.aes256GcmCipher("custom-cipher-secret");

    const program = Effect.gen(function* () {
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
    });

    const { enableResult, verifyResult } = await Effect.runPromise(
      Effect.provide(program, testContext).pipe(Effect.provide(Hooks.Default)),
    );

    expect(verifyResult.userId).toBe("user-enc-2");

    // Stored secret is ciphertext
    const record = multiFactorRecords.get("user-enc-2");
    expect(record?.secret).not.toBe(enableResult.secret);
  });

  it("should return plaintext secret and valid totpUri from enable even with encryption", async () => {
    const testContext = await makeTestContext();
    await seedUser("user-enc-3", "enc-uri@example.com", "correct-password");

    const program = Effect.gen(function* () {
      const service = yield* MultiFactor.make({
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
      const service = yield* MultiFactor.make({
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
