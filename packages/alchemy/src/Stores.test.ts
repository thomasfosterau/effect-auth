import { describe, it, expect } from "vite-plus/test";
import { Effect, Result } from "effect";
import * as Auth from "effect-auth";
import { migrate, schemaStatements } from "./Schema.js";
import {
  layer,
  makeChallengeStore,
  makeCredentialStore,
  makeEmailOtpStore,
  makeEmailOtpUserStore,
  makeEmailPasswordStore,
  makeEmailVerificationStore,
  makeMagicLinkStore,
  makeMagicLinkUserStore,
  makeOAuthAccountStore,
  makeOAuthStateStore,
  makeOAuthUserStore,
  makePasswordResetStore,
  makePendingTwoFactorStore,
  makeRateLimitStore,
  makeRoleStore,
  makeSessionStore,
  makeTwoFactorStore,
  makeUserServiceStore,
  makeUserStore,
} from "./Stores.js";
import type { D1Database, D1PreparedStatement, D1Result } from "./D1.js";

type SqlValue = null | number | bigint | string | Uint8Array;

interface SqliteStatement {
  all(...params: SqlValue[]): unknown[];
  get(...params: SqlValue[]): unknown;
  run(...params: SqlValue[]): unknown;
}
interface SqliteDatabase {
  prepare(sql: string): SqliteStatement;
}

/**
 * Load whichever embedded SQLite engine is available — Node's built-in
 * `node:sqlite` (Node >= 22.13) or `better-sqlite3`. Both are real SQLite
 * engines, like D1. The suite skips if neither can be loaded.
 */
const loadSqlite = async (): Promise<(() => SqliteDatabase) | null> => {
  try {
    const { DatabaseSync } = await import("node:sqlite");
    return () => new DatabaseSync(":memory:") as unknown as SqliteDatabase;
  } catch {
    // node:sqlite unavailable or requires --experimental-sqlite
  }
  try {
    const { default: Database } = await import("better-sqlite3");
    return () => new Database(":memory:") as unknown as SqliteDatabase;
  } catch {
    // better-sqlite3 not installed
  }
  return null;
};

const newSqlite = await loadSqlite();

/**
 * Wraps the embedded SQLite engine in the minimal async D1 client shape these
 * stores expect.
 */
const makeTestDb = (): { db: D1Database; sqlite: SqliteDatabase } => {
  const sqlite = newSqlite!();
  const db: D1Database = {
    prepare(sql: string): D1PreparedStatement {
      let bound: SqlValue[] = [];
      const statement: D1PreparedStatement = {
        bind(...values: readonly unknown[]): D1PreparedStatement {
          bound = values as SqlValue[];
          return statement;
        },
        first<T>(): Promise<T | null> {
          const row = sqlite.prepare(sql).get(...bound) as T | undefined;
          return Promise.resolve(row ?? null);
        },
        all<T>(): Promise<D1Result<T>> {
          const results = sqlite.prepare(sql).all(...bound) as T[];
          return Promise.resolve({ results, success: true, meta: {} });
        },
        run<T>(): Promise<D1Result<T>> {
          sqlite.prepare(sql).run(...bound);
          return Promise.resolve({ results: [] as T[], success: true, meta: {} });
        },
      };
      return statement;
    },
  };
  return { db, sqlite };
};

const setup = async (): Promise<{ db: D1Database; sqlite: SqliteDatabase }> => {
  const handles = makeTestDb();
  await Effect.runPromise(migrate(handles.db));
  return handles;
};

describe("@effect-auth/alchemy package", () => {
  it("exposes schema statements and a layer factory", () => {
    expect(schemaStatements.length).toBeGreaterThan(0);
    expect(typeof layer).toBe("function");
  });
});

const suite = newSqlite ? describe : describe.skip;

suite("@effect-auth/alchemy stores", () => {
  it("session store: create / get / update / delete by user", async () => {
    const { db } = await setup();
    const store = makeSessionStore(db);
    const now = new Date();
    const session: Auth.Session = {
      id: "s1",
      userId: "u1",
      expiresAt: new Date(now.getTime() + 60_000),
      createdAt: now,
      lastActivityAt: now,
      attributes: { ip: "127.0.0.1" },
    };

    await Effect.runPromise(store.create(session));

    const fetched = await Effect.runPromise(store.get("s1"));
    expect(fetched?.userId).toBe("u1");
    expect(fetched?.attributes).toEqual({ ip: "127.0.0.1" });
    expect(fetched?.expiresAt.getTime()).toBe(session.expiresAt.getTime());

    await Effect.runPromise(store.update({ ...session, attributes: { ip: "10.0.0.1" } }));
    const updated = await Effect.runPromise(store.get("s1"));
    expect(updated?.attributes).toEqual({ ip: "10.0.0.1" });

    const listed = await Effect.runPromise(store.listByUserId("u1"));
    expect(listed.map((entry) => entry.id)).toEqual(["s1"]);
    expect(await Effect.runPromise(store.listByUserId("nobody"))).toEqual([]);

    expect(await Effect.runPromise(store.get("nope"))).toBe(null);

    await Effect.runPromise(store.deleteByUserId("u1"));
    expect(await Effect.runPromise(store.get("s1"))).toBe(null);
    expect(await Effect.runPromise(store.listByUserId("u1"))).toEqual([]);
  });

  it("user + email-password stores share auth_users", async () => {
    const { db } = await setup();
    const emailPassword = makeEmailPasswordStore(db);
    const users = makeUserStore(db);

    const created = await Effect.runPromise(
      emailPassword.createUser({ email: "a@b.com", name: "Ada", attributes: { plan: "pro" } }),
    );
    expect(created.email).toBe("a@b.com");
    expect(created.emailVerified).toBe(false);
    expect(created.name).toBe("Ada");
    expect(created.attributes).toEqual({ plan: "pro" });

    const byEmail = await Effect.runPromise(emailPassword.getUserByEmail("a@b.com"));
    expect(byEmail?.id).toBe(created.id);

    expect(await Effect.runPromise(emailPassword.getPasswordHash(created.id))).toBe(null);
    expect(await Effect.runPromise(users.getCredentials(created.id))).toBe(null);

    await Effect.runPromise(emailPassword.setPasswordHash(created.id, "hash:123"));
    expect(await Effect.runPromise(emailPassword.getPasswordHash(created.id))).toBe("hash:123");
    expect(await Effect.runPromise(users.getCredentials(created.id))).toBe("hash:123");

    const user = await Effect.runPromise(users.get(created.id));
    expect(user?.email).toBe("a@b.com");
    expect(user?.name).toBe("Ada");
    expect(user?.attributes).toEqual({ plan: "pro" });
    expect(user?.createdAt.getTime()).toBe(created.createdAt.getTime());
    expect(user?.updatedAt.getTime()).toBe(created.updatedAt.getTime());

    expect(await Effect.runPromise(users.get("nope"))).toBe(null);
  });

  it("user service store: getByEmail / update / delete", async () => {
    const { db } = await setup();
    const emailPassword = makeEmailPasswordStore(db);
    const service = makeUserServiceStore(db);

    const user = await Effect.runPromise(emailPassword.createUser({ email: "c@d.com" }));
    expect((await Effect.runPromise(service.getByEmail("c@d.com")))?.id).toBe(user.id);

    await Effect.runPromise(
      service.update({
        ...user,
        email: "new@d.com",
        emailVerified: true,
        attributes: { role: "x" },
      }),
    );
    const updated = await Effect.runPromise(service.get(user.id));
    expect(updated?.email).toBe("new@d.com");
    expect(updated?.emailVerified).toBe(true);
    expect(updated?.attributes["role"]).toBe("x");
    expect(await Effect.runPromise(service.getByEmail("new@d.com"))).not.toBe(null);

    await Effect.runPromise(service.delete(user.id));
    expect(await Effect.runPromise(service.get(user.id))).toBe(null);
  });

  it("rate limit store: increment, set, get, delete", async () => {
    const { db } = await setup();
    const store = makeRateLimitStore(db);

    expect(await Effect.runPromise(store.get("k"))).toBe(null);
    expect(await Effect.runPromise(store.increment("k", 60))).toBe(1);
    expect(await Effect.runPromise(store.increment("k", 60))).toBe(2);
    expect((await Effect.runPromise(store.get("k")))?.count).toBe(2);

    const blockedUntil = Date.now() + 5_000;
    await Effect.runPromise(
      store.set("k", { key: "k", count: 5, resetAt: Date.now() + 1_000, blockedUntil }, 5),
    );
    expect((await Effect.runPromise(store.get("k")))?.blockedUntil).toBe(blockedUntil);

    await Effect.runPromise(store.delete("k"));
    expect(await Effect.runPromise(store.get("k"))).toBe(null);
  });

  it("email verification store: create / get / deleteByUserId", async () => {
    const { db } = await setup();
    const store = makeEmailVerificationStore(db);
    const verification: Auth.EmailVerification = {
      token: "t1",
      userId: "u1",
      email: "e@e.com",
      createdAt: Date.now(),
      expiresAt: Date.now() + 1_000,
    };

    await Effect.runPromise(store.create(verification));
    expect((await Effect.runPromise(store.get("t1")))?.email).toBe("e@e.com");
    await Effect.runPromise(store.deleteByUserId("u1"));
    expect(await Effect.runPromise(store.get("t1"))).toBe(null);
  });

  it("webauthn stores round-trip binary data", async () => {
    const { db } = await setup();
    const challenges = makeChallengeStore(db);
    const credentials = makeCredentialStore(db);

    const challengeBytes = new Uint8Array([1, 2, 3, 250, 255]);
    await Effect.runPromise(
      challenges.create({ challenge: challengeBytes, expiresAt: Date.now() + 1_000, userId: "u1" }),
    );
    const fetched = await Effect.runPromise(challenges.get(challengeBytes));
    expect(Array.from(fetched?.challenge ?? [])).toEqual([1, 2, 3, 250, 255]);
    expect(fetched?.userId).toBe("u1");

    await Effect.runPromise(challenges.delete(challengeBytes));
    expect(await Effect.runPromise(challenges.get(challengeBytes))).toBe(null);

    const credential: Auth.WebAuthnCredential = {
      id: "c1",
      userId: "u1",
      publicKey: new Uint8Array([9, 8, 7]),
      algorithm: -7,
      counter: 0,
      createdAt: Date.now(),
      transports: ["usb"],
    };
    await Effect.runPromise(credentials.create(credential));
    const gotCred = await Effect.runPromise(credentials.get("c1"));
    expect(Array.from(gotCred?.publicKey ?? [])).toEqual([9, 8, 7]);
    expect(gotCred?.transports).toEqual(["usb"]);

    await Effect.runPromise(credentials.update({ ...credential, counter: 5 }));
    expect((await Effect.runPromise(credentials.get("c1")))?.counter).toBe(5);
    expect((await Effect.runPromise(credentials.listByUserId("u1"))).length).toBe(1);
  });

  it("oauth account store: create / link / getByUserId / delete", async () => {
    const { db } = await setup();
    const store = makeOAuthAccountStore(db);
    const account: Auth.OAuthAccount = {
      id: "oa1",
      userId: "u1",
      provider: "github",
      providerId: "gh-1",
      accessToken: "tok",
      createdAt: Date.now(),
      updatedAt: Date.now(),
      email: "g@g.com",
    };

    await Effect.runPromise(store.create(account));
    expect((await Effect.runPromise(store.get("github", "gh-1")))?.email).toBe("g@g.com");

    await Effect.runPromise(store.linkToUser("u2", account));
    expect((await Effect.runPromise(store.get("github", "gh-1")))?.userId).toBe("u2");
    expect((await Effect.runPromise(store.getByUserId("u2"))).length).toBe(1);

    await Effect.runPromise(store.delete("github", "gh-1"));
    expect(await Effect.runPromise(store.get("github", "gh-1"))).toBe(null);
  });

  it("oauth user store: createUser / getUser / getUserByEmail", async () => {
    const { db } = await setup();
    const store = makeOAuthUserStore(db);

    const created = await Effect.runPromise(
      store.createUser({
        email: "o@o.com",
        emailVerified: true,
        name: "Oda",
        image: "https://img.example/o.png",
      }),
    );
    expect(created.email).toBe("o@o.com");
    expect(created.emailVerified).toBe(true);
    expect(created.name).toBe("Oda");
    expect(created.image).toBe("https://img.example/o.png");
    expect(created.attributes).toEqual({});

    const fetched = await Effect.runPromise(store.getUser(created.id));
    expect(fetched.email).toBe("o@o.com");
    expect(fetched.emailVerified).toBe(true);
    expect(fetched.createdAt.getTime()).toBe(created.createdAt.getTime());

    expect((await Effect.runPromise(store.getUserByEmail("o@o.com")))?.id).toBe(created.id);
    expect(await Effect.runPromise(store.getUserByEmail("nobody@o.com"))).toBe(null);

    const missing = await Effect.runPromise(Effect.result(store.getUser("nope")));
    expect(Result.isFailure(missing) && missing.failure._tag).toBe("UserNotFoundError");
  });

  it("oauth state store: create / get / not-found", async () => {
    const { db } = await setup();
    const store = makeOAuthStateStore(db);
    const state: Auth.OAuthState = {
      state: "st1",
      provider: "google",
      codeVerifier: "v",
      createdAt: Date.now(),
      expiresAt: Date.now() + 1_000,
    };

    await Effect.runPromise(store.create(state));
    expect((await Effect.runPromise(store.get("st1")))?.codeVerifier).toBe("v");

    expect(await Effect.runPromise(store.get("nope"))).toBe(null);
  });

  it("password reset store: create / get / deleteByUserId", async () => {
    const { db } = await setup();
    const store = makePasswordResetStore(db);
    const token: Auth.PasswordResetToken = {
      token: "r1",
      userId: "u1",
      email: "e@e.com",
      createdAt: Date.now(),
      expiresAt: Date.now() + 1_000,
    };

    await Effect.runPromise(store.create(token));
    expect((await Effect.runPromise(store.get("r1")))?.userId).toBe("u1");
    await Effect.runPromise(store.deleteByUserId("u1"));
    expect(await Effect.runPromise(store.get("r1"))).toBe(null);
  });

  it("magic link store: roundtrip, delete by email, user store", async () => {
    const { db } = await setup();
    const store = makeMagicLinkStore(db);
    const users = makeMagicLinkUserStore(db);
    const link = (token: string, email: string): Auth.MagicLinkToken => ({
      token,
      email,
      createdAt: Date.now(),
      expiresAt: Date.now() + 300_000,
    });

    await Effect.runPromise(store.create(link("ml-1", "a@example.com")));
    await Effect.runPromise(store.create(link("ml-2", "a@example.com")));
    await Effect.runPromise(store.create(link("ml-3", "b@example.com")));

    expect((await Effect.runPromise(store.get("ml-1")))?.email).toBe("a@example.com");
    expect(await Effect.runPromise(store.get("nope"))).toBe(null);

    await Effect.runPromise(store.delete("ml-1"));
    await Effect.runPromise(store.deleteByEmail("a@example.com"));
    expect(await Effect.runPromise(store.get("ml-2"))).toBe(null);
    expect((await Effect.runPromise(store.get("ml-3")))?.email).toBe("b@example.com");

    const user = await Effect.runPromise(
      users.createUser({ email: "ml@example.com", emailVerified: true, name: "Mel" }),
    );
    expect(user.emailVerified).toBe(true);
    expect(user.name).toBe("Mel");
    const byEmail = await Effect.runPromise(users.getUserByEmail("ml@example.com"));
    expect(byEmail?.id).toBe(user.id);
    expect(byEmail?.emailVerified).toBe(true);
    expect(await Effect.runPromise(users.getUserByEmail("nobody@example.com"))).toBe(null);
  });

  it("email otp store: upserts per email+purpose and increments attempts", async () => {
    const { db } = await setup();
    const store = makeEmailOtpStore(db);
    const users = makeEmailOtpUserStore(db);
    const record: Auth.EmailOtpRecord = {
      email: "otp@example.com",
      otpHash: "hash",
      purpose: "sign-in",
      attempts: 0,
      createdAt: Date.now(),
      expiresAt: Date.now() + 300_000,
    };

    await Effect.runPromise(store.upsert(record));
    await Effect.runPromise(
      store.upsert({ ...record, purpose: "forget-password", otpHash: "other" }),
    );

    expect(await Effect.runPromise(store.incrementAttempts("otp@example.com", "sign-in"))).toBe(1);
    expect(await Effect.runPromise(store.incrementAttempts("otp@example.com", "sign-in"))).toBe(2);

    await Effect.runPromise(store.upsert({ ...record, otpHash: "new-hash" }));
    const replaced = await Effect.runPromise(store.get("otp@example.com", "sign-in"));
    expect(replaced?.otpHash).toBe("new-hash");
    expect(replaced?.attempts).toBe(0);
    expect(
      (await Effect.runPromise(store.get("otp@example.com", "forget-password")))?.otpHash,
    ).toBe("other");

    await Effect.runPromise(store.delete("otp@example.com", "sign-in"));
    expect(await Effect.runPromise(store.get("otp@example.com", "sign-in"))).toBe(null);

    const missing = await Effect.runPromise(
      Effect.result(store.incrementAttempts("otp@example.com", "sign-in")),
    );
    expect(Result.isFailure(missing) && missing.failure._tag).toBe("AuthError");

    const user = await Effect.runPromise(
      users.createUser({ email: "otp@example.com", emailVerified: true }),
    );
    expect((await Effect.runPromise(users.getUserByEmail("otp@example.com")))?.id).toBe(user.id);
  });

  it("two factor + pending two factor stores roundtrip", async () => {
    const { db } = await setup();
    const store = makeTwoFactorStore(db);
    const pendingStore = makePendingTwoFactorStore(db);
    const record: Auth.TwoFactorRecord = {
      userId: "user-1",
      secret: "JBSWY3DPEHPK3PXP",
      backupCodes: ["h1", "h2", "h3"],
      verified: false,
      createdAt: Date.now(),
    };

    expect(await Effect.runPromise(store.get("user-1"))).toBe(null);

    await Effect.runPromise(store.upsert(record));
    const created = await Effect.runPromise(store.get("user-1"));
    expect(created?.verified).toBe(false);
    expect(created?.backupCodes).toEqual(["h1", "h2", "h3"]);

    await Effect.runPromise(store.upsert({ ...record, verified: true, backupCodes: ["h2", "h3"] }));
    const updated = await Effect.runPromise(store.get("user-1"));
    expect(updated?.verified).toBe(true);
    expect(updated?.backupCodes).toEqual(["h2", "h3"]);

    await Effect.runPromise(store.delete("user-1"));
    expect(await Effect.runPromise(store.get("user-1"))).toBe(null);

    const pending: Auth.PendingTwoFactor = {
      token: "p2f-1",
      userId: "user-1",
      expiresAt: Date.now() + 300_000,
      createdAt: Date.now(),
    };
    await Effect.runPromise(pendingStore.create(pending));
    expect(await Effect.runPromise(pendingStore.get("p2f-1"))).toEqual(pending);
    await Effect.runPromise(pendingStore.delete("p2f-1"));
    expect(await Effect.runPromise(pendingStore.get("p2f-1"))).toBe(null);
  });

  it("role store reads roles and permissions", async () => {
    const { db, sqlite } = await setup();
    sqlite.prepare("INSERT INTO auth_user_roles (user_id, role) VALUES (?, ?)").run("u1", "admin");
    sqlite
      .prepare("INSERT INTO auth_role_permissions (role, resource, action) VALUES (?, ?, ?)")
      .run("admin", "post", "delete");

    const store = makeRoleStore(db);
    expect(await Effect.runPromise(store.getUserRoles("u1"))).toEqual(["admin"]);
    expect(await Effect.runPromise(store.getRolePermissions("admin"))).toEqual([
      { resource: "post", action: "delete" },
    ]);
  });

  it("combined layer provides every store tag", async () => {
    const { db } = await setup();
    const program = Effect.gen(function* () {
      const sessions = yield* Auth.SessionStore;
      const now = new Date();
      yield* sessions.create({
        id: "s9",
        userId: "u9",
        expiresAt: new Date(now.getTime() + 60_000),
        createdAt: now,
        lastActivityAt: now,
        attributes: {},
      });
      const session = yield* sessions.get("s9");
      const rateLimit = yield* Auth.RateLimitStore;
      const count = yield* rateLimit.increment("layer-key", 60);
      const oauthUsers = yield* Auth.OAuthUserStore;
      const user = yield* oauthUsers.createUser({ email: "layer@l.com", emailVerified: false });
      const magicLinks = yield* Auth.MagicLinkStore;
      yield* magicLinks.create({
        token: "ml-layer",
        email: "layer@l.com",
        createdAt: now.getTime(),
        expiresAt: now.getTime() + 60_000,
      });
      const magicLink = yield* magicLinks.get("ml-layer");
      const emailOtps = yield* Auth.EmailOtpStore;
      const twoFactor = yield* Auth.TwoFactorStore;
      const pendingTwoFactor = yield* Auth.PendingTwoFactorStore;
      const magicLinkUsers = yield* Auth.MagicLinkUserStore;
      const emailOtpUsers = yield* Auth.EmailOtpUserStore;
      return {
        session,
        count,
        user,
        magicLink,
        stores: [emailOtps, twoFactor, pendingTwoFactor, magicLinkUsers, emailOtpUsers],
      };
    });

    const result = await Effect.runPromise(program.pipe(Effect.provide(layer(db))));
    expect(result.session?.userId).toBe("u9");
    expect(result.count).toBe(1);
    expect(result.user.email).toBe("layer@l.com");
    expect(result.magicLink?.email).toBe("layer@l.com");
    for (const store of result.stores) {
      expect(store).toBeDefined();
    }
  });

  it("rateLimit.increment resets count when window expires", async () => {
    const { db } = await setup();
    const store = makeRateLimitStore(db);
    await Effect.runPromise(store.increment("k-reset", 1));
    await Effect.runPromise(store.increment("k-reset", 1));
    await Effect.runPromise(
      store.set("k-reset", { key: "k-reset", count: 99, resetAt: Date.now() - 1 }, 1),
    );
    expect(await Effect.runPromise(store.increment("k-reset", 60))).toBe(1);
  });

  it("rateLimit.get / credential.get surface AuthError with cause when D1 fails", async () => {
    const stmt: D1PreparedStatement = {
      bind(): D1PreparedStatement {
        return stmt;
      },
      first: () => Promise.reject(new Error("simulated D1 failure")),
      all: () => Promise.reject(new Error("simulated D1 failure")),
      run: () => Promise.reject(new Error("simulated D1 failure")),
    };
    const brokenDb: D1Database = { prepare: () => stmt };

    const rateLimits = makeRateLimitStore(brokenDb);
    const credentials = makeCredentialStore(brokenDb);

    const e1 = await Effect.runPromise(Effect.flip(rateLimits.get("key")));
    const e2 = await Effect.runPromise(Effect.flip(credentials.get("cred-id")));

    expect(e1._tag).toBe("AuthError");
    expect(e1.cause).toBeDefined();
    expect(e2._tag).toBe("AuthError");
    expect(e2.cause).toBeDefined();
  });
});
