/**
 * The contracts of the stores beyond sign-in — `EmailPasswordStore`,
 * `UserServiceStore`, `ApiKeyStore`, `RateLimitStore` and the two token stores —
 * as one suite each dialect's file runs against a real engine (#675, #728).
 *
 * `ApiKeyStore` runs the core's published conformance suite. The others have
 * none, so their cases here are written from the contracts' documented
 * semantics (`EmailPasswordStore`, `UserServiceStore` as core's `/sql` store
 * implements it, `RateLimitStore.increment`, `EmailVerificationStore`,
 * `PasswordResetStore`); the email-password cases end with a real sign-up and
 * sign-in through `EmailPasswordService`, the user-service cases with a round
 * trip through `UserService`.
 *
 * Never published (`tsconfig.json` excludes `src/testing/`).
 */

import { Context, DateTime, Effect, Layer } from "effect";
import * as Arr from "effect/Array";
import { TestClock } from "effect/testing";
import { describe, expect, it } from "vite-plus/test";
import * as Auth from "@thomasfosterau/effect-auth";
import * as Testing from "@thomasfosterau/effect-auth/testing";
import * as ApiKeyStore from "../ApiKeyStore.ts";
import type { DrizzleDatabase } from "../Database.ts";
import * as EmailPasswordStore from "../EmailPasswordStore.ts";
import * as IdentifierStore from "../IdentifierStore.ts";
import * as RateLimitStore from "../RateLimitStore.ts";
import type { Tables } from "../Schema.ts";
import * as SessionStore from "../SessionStore.ts";
import * as TokenStore from "../TokenStore.ts";
import * as UserServiceStore from "../UserServiceStore.ts";
import * as UserStore from "../UserStore.ts";
import { conformance } from "./Conformance.ts";

/**
 * `RateLimitStore.purgeExpired` over the same database and tables as the
 * stores, so a case can run it without knowing the dialect.
 */
class PurgeRateLimits extends Context.Service<
  PurgeRateLimits,
  Effect.Effect<void, Auth.AuthError>
>()("@thomasfosterau/effect-auth-drizzle/testing/AuthStoresContract/PurgeRateLimits") {}

/** Every store the suite exercises. */
export type AuthStores =
  | PurgeRateLimits
  | Auth.ApiKeyStore
  | Auth.Email.EmailPasswordStore
  | Auth.Password.PasswordResetUserStore
  | Auth.RateLimitStore
  | Auth.Email.EmailVerificationStore
  | Auth.Password.PasswordResetStore
  | Auth.SessionStore
  | Auth.UserStore
  | Auth.UserServiceStore
  | Auth.IdentifierStore;

/** The stores over one dialect's tables, still needing the database. */
export const authStoresLayer = (tables: Tables): Layer.Layer<AuthStores, never, DrizzleDatabase> =>
  Layer.mergeAll(
    ApiKeyStore.layer(tables),
    EmailPasswordStore.layer(tables),
    EmailPasswordStore.passwordResetUserLayer(tables),
    RateLimitStore.layer(tables),
    TokenStore.layer(tables),
    SessionStore.layer(tables),
    UserStore.layer(tables),
    UserServiceStore.layer(tables),
    IdentifierStore.layer(tables),
    Layer.effect(
      PurgeRateLimits,
      Effect.map(Effect.context<DrizzleDatabase>(), (context) =>
        RateLimitStore.purgeExpired(tables).pipe(Effect.provide(context)),
      ),
    ),
  );

/** Runs a case against the file's database, with {@link authStoresLayer} provided. */
export type Run = <A, E>(effect: Effect.Effect<A, E, AuthStores>) => Promise<A>;

const millis = (offset: number): number =>
  DateTime.toEpochMillis(
    DateTime.add(DateTime.makeUnsafe("2026-01-01T00:00:00.000Z"), { milliseconds: offset }),
  );

const dateAt = (offset: number): Date => DateTime.toDateUtc(DateTime.makeUnsafe(millis(offset)));

const uuid = (): string => globalThis.crypto.randomUUID();

const tokenRecord = (userId: string) => ({
  token: Auth.hashToken(uuid()),
  userId,
  email: `${userId}@example.com`,
  createdAt: millis(0),
  expiresAt: millis(60_000),
});

const emailPasswordCases = (label: string, run: Run): void => {
  describe(`${label}: EmailPasswordStore`, () => {
    it("creates a new user that UserStore reads back, with no password yet", async () => {
      const result = await run(
        Effect.gen(function* () {
          const store = yield* Auth.Email.EmailPasswordStore;
          const users = yield* Auth.UserStore;
          const created = yield* store.createUser({ name: "Ada", attributes: { team: "core" } });
          return {
            created,
            read: yield* users.get(created.user.id),
            hash: yield* store.getPasswordHash(created.user.id),
          };
        }),
      );
      expect(result.created.created).toBe(true);
      expect(result.created.user.name).toBe("Ada");
      expect(result.created.user.attributes).toEqual({ team: "core" });
      expect(result.read).toEqual(result.created.user);
      expect(result.hash).toBeNull();
    });

    it("sets, reads and clears the password hash; a missing user reads null", async () => {
      const result = await run(
        Effect.gen(function* () {
          const store = yield* Auth.Email.EmailPasswordStore;
          const resets = yield* Auth.Password.PasswordResetUserStore;
          const { user } = yield* store.createUser({});
          yield* store.setPasswordHash(user.id, "hash-1");
          const first = yield* store.getPasswordHash(user.id);
          yield* resets.setPasswordHash(user.id, "hash-2");
          const second = yield* store.getPasswordHash(user.id);
          yield* store.clearPasswordHash(user.id);
          // Writes to a missing user are no-ops.
          yield* store.setPasswordHash(uuid(), "hash-3");
          return {
            first,
            second,
            cleared: yield* store.getPasswordHash(user.id),
            missing: yield* store.getPasswordHash(uuid()),
          };
        }),
      );
      expect(result).toEqual({ first: "hash-1", second: "hash-2", cleared: null, missing: null });
    });

    it("signs up and signs in through EmailPasswordService", async () => {
      const service = Auth.Email.EmailPasswordService.layer().pipe(
        Layer.provideMerge(
          Auth.SessionService.layer({
            sessionExpiresIn: { activePeriod: 86_400_000, idlePeriod: 3_600_000 },
          }),
        ),
        Layer.provideMerge(Auth.Password.PasswordHasher.layer()),
        Layer.provideMerge(Auth.Hooks.Default),
      );
      const result = await run(
        Effect.gen(function* () {
          const auth = yield* Auth.Email.EmailPasswordService;
          const sessions = yield* Auth.SessionService;
          const email = `${uuid()}@example.com`;
          const signedUp = yield* auth.signUp({ email, password: "correct horse battery" });
          const signedIn = yield* auth.signIn({ email, password: "correct horse battery" });
          const wrong = yield* Effect.flip(auth.signIn({ email, password: "wrong horse battery" }));
          // The raw token is the credential; the session (and its row) holds its digest.
          const token = signedIn.token ?? "";
          const validated = yield* sessions.validateSession(token);
          const stored = yield* Auth.SessionStore.use((store) =>
            store.get(signedIn.session?.id ?? ""),
          );
          return {
            signedUp: signedUp.user.id,
            validated: validated.user.id,
            digest: Auth.hashToken(token),
            sessionId: signedIn.session?.id,
            storedId: stored?.id,
            wrong: wrong._tag,
          };
        }).pipe(Effect.provide(service)),
      );
      expect(result.validated).toBe(result.signedUp);
      expect(result.sessionId).toBe(result.digest);
      expect(result.storedId).toBe(result.digest);
      expect(result.wrong).toBe("InvalidCredentialsError");
    });
  });
};

const userServiceCases = (label: string, run: Run): void => {
  describe(`${label}: UserServiceStore`, () => {
    it("get reads the user UserStore reads, and null on a miss", async () => {
      const result = await run(
        Effect.gen(function* () {
          const { user } = yield* Auth.Email.EmailPasswordStore.use((store) =>
            store.createUser({ name: "Ada", attributes: { team: "core" } }),
          );
          const store = yield* Auth.UserServiceStore;
          return {
            user,
            read: yield* store.get(user.id),
            viaUserStore: yield* Auth.UserStore.use((users) => users.get(user.id)),
            missing: yield* store.get(uuid()),
          };
        }),
      );
      expect(result.read).toEqual(result.user);
      expect(result.read).toEqual(result.viaUserStore);
      expect(result.missing).toBeNull();
    });

    it("update writes name, image, updatedAt and the attributes, and returns the user", async () => {
      const updatedAt = dateAt(90_000);
      const result = await run(
        Effect.gen(function* () {
          const { user } = yield* Auth.Email.EmailPasswordStore.use((store) =>
            store.createUser({ name: "Ada", image: "a.png", attributes: { team: "core" } }),
          );
          const store = yield* Auth.UserServiceStore;
          const renamed = yield* store.update({
            ...user,
            name: "Grace",
            image: "g.png",
            updatedAt,
            attributes: { plan: "pro", nested: { seats: 3 } },
          });
          const first = yield* store.get(user.id);
          // Absent fields are cleared, not kept.
          const { name: _name, image: _image, ...bare } = renamed;
          yield* store.update({ ...bare, attributes: {} });
          return { renamed, first, cleared: yield* store.get(user.id) };
        }),
      );
      expect(result.first).toEqual(result.renamed);
      expect(result.first?.name).toBe("Grace");
      expect(result.first?.image).toBe("g.png");
      expect(result.first?.updatedAt).toEqual(updatedAt);
      expect(result.first?.attributes).toEqual({ plan: "pro", nested: { seats: 3 } });
      expect(result.cleared?.name).toBeUndefined();
      expect(result.cleared?.image).toBeUndefined();
      expect(result.cleared?.attributes).toEqual({});
    });

    it("update of a missing user writes nothing and returns the user given", async () => {
      const ghost: Auth.User = {
        id: uuid(),
        name: "Nobody",
        createdAt: dateAt(0),
        updatedAt: dateAt(0),
        attributes: {},
      };
      const result = await run(
        Effect.gen(function* () {
          const store = yield* Auth.UserServiceStore;
          return { returned: yield* store.update(ghost), read: yield* store.get(ghost.id) };
        }),
      );
      expect(result).toEqual({ returned: ghost, read: null });
    });

    it("delete removes the user; a delete of a missing user is a no-op", async () => {
      const result = await run(
        Effect.gen(function* () {
          const { user } = yield* Auth.Email.EmailPasswordStore.use((store) =>
            store.createUser({}),
          );
          const { user: other } = yield* Auth.Email.EmailPasswordStore.use((store) =>
            store.createUser({}),
          );
          const store = yield* Auth.UserServiceStore;
          yield* store.delete(user.id);
          yield* store.delete(uuid());
          return { deleted: yield* store.get(user.id), other: yield* store.get(other.id) };
        }),
      );
      expect(result.deleted).toBeNull();
      expect(result.other).not.toBeNull();
    });

    it("UserService round-trips over the store", async () => {
      const result = await run(
        Effect.gen(function* () {
          const { user } = yield* Auth.Email.EmailPasswordStore.use((store) =>
            store.createUser({ name: "Ada" }),
          );
          const service = yield* Auth.UserService;
          const renamed = yield* service.updateUser(user.id, { name: "Grace" });
          const tagged = yield* service.updateUserAttributes(user.id, { theme: "dark" });
          const read = yield* service.getUser(user.id);
          yield* service.deleteUser(user.id);
          const gone = yield* Effect.flip(service.getUser(user.id));
          return { renamed, tagged, read, gone: gone._tag };
        }).pipe(Effect.provide(Auth.UserService.layer())),
      );
      expect(result.renamed.name).toBe("Grace");
      expect(result.read).toEqual(result.tagged);
      expect(result.read.name).toBe("Grace");
      expect(result.read.attributes).toEqual({ theme: "dark" });
      expect(result.gone).toBe("UserNotFoundError");
    });
  });
};

const rateLimitCases = (label: string, run: Run): void => {
  describe(`${label}: RateLimitStore`, () => {
    it("counts from 1 in a new window, and get reads the entry", async () => {
      const key = `ip:${uuid()}`;
      const result = await run(
        Effect.gen(function* () {
          const store = yield* Auth.RateLimitStore;
          const missing = yield* store.get(key);
          const counts = [
            yield* store.increment(key, 60),
            yield* store.increment(key, 60),
            yield* store.increment(key, 60),
          ];
          return { missing, counts, entry: yield* store.get(key) };
        }),
      );
      expect(result.missing).toBeNull();
      expect(result.counts).toEqual([1, 2, 3]);
      expect(result.entry?.count).toBe(3);
      expect(result.entry?.resetAt).toBeGreaterThan(millis(0));
      expect(result.entry && "blockedUntil" in result.entry).toBe(false);
    });

    it("gives concurrent increments distinct counts", async () => {
      const key = `ip:${uuid()}`;
      const counts = await run(
        Effect.gen(function* () {
          const store = yield* Auth.RateLimitStore;
          return yield* Effect.all(
            Arr.makeBy(8, () => store.increment(key, 60)),
            { concurrency: "unbounded" },
          );
        }),
      );
      expect(Arr.sort(counts, (a: number, b: number) => (a < b ? -1 : a > b ? 1 : 0))).toEqual([
        1, 2, 3, 4, 5, 6, 7, 8,
      ]);
    });

    it("re-opens an expired window at 1 and drops its block; set round-trips", async () => {
      const expired = `ip:${uuid()}`;
      const open = `ip:${uuid()}`;
      const result = await run(
        Effect.gen(function* () {
          const store = yield* Auth.RateLimitStore;
          yield* store.set(
            expired,
            { key: expired, count: 9, resetAt: millis(0), blockedUntil: millis(1) },
            60,
          );
          const blocked = {
            key: open,
            count: 4,
            resetAt: millis(10 ** 12),
            blockedUntil: millis(10 ** 12),
          };
          yield* store.set(open, { key: open, count: 2, resetAt: millis(10 ** 12) }, 60);
          yield* store.set(open, blocked, 60);
          return {
            reopened: yield* store.increment(expired, 60),
            after: yield* store.get(expired),
            open: yield* store.get(open),
            blocked,
          };
        }),
      );
      expect(result.reopened).toBe(1);
      expect(result.after?.count).toBe(1);
      expect(result.after && "blockedUntil" in result.after).toBe(false);
      expect(result.open).toEqual(result.blocked);
    });

    it("delete removes the entry and is a no-op for an unknown key", async () => {
      const key = `ip:${uuid()}`;
      const result = await run(
        Effect.gen(function* () {
          const store = yield* Auth.RateLimitStore;
          yield* store.increment(key, 60);
          yield* store.delete(key);
          yield* store.delete(uuid());
          return { gone: yield* store.get(key), restarted: yield* store.increment(key, 60) };
        }),
      );
      expect(result).toEqual({ gone: null, restarted: 1 });
    });

    it("purgeExpired deletes rows whose window and block have both passed, keeps open or blocked ones, and is idempotent (#686)", async () => {
      // A fixed instant before the real clock: the other cases' rows all reset
      // after it, so the purge leaves them alone.
      const now = millis(0);
      const entries: ReadonlyArray<Auth.RateLimitEntry> = [
        // Window and block both passed, or the block never set: purged.
        { key: `ip:${uuid()}`, count: 3, resetAt: now - 60_000 },
        { key: `ip:${uuid()}`, count: 9, resetAt: now - 60_000, blockedUntil: now - 60_000 },
        // Both end exactly now, which the limiter already treats as over: purged.
        { key: `ip:${uuid()}`, count: 1, resetAt: now, blockedUntil: now },
        // Inside its window, and past its window but still blocked: kept.
        { key: `ip:${uuid()}`, count: 2, resetAt: now + 60_000 },
        { key: `ip:${uuid()}`, count: 9, resetAt: now - 60_000, blockedUntil: now + 60_000 },
      ];
      const result = await run(
        Effect.gen(function* () {
          yield* TestClock.setTime(now);
          const store = yield* Auth.RateLimitStore;
          yield* Effect.forEach(entries, (entry) => store.set(entry.key, entry, 60), {
            concurrency: 1,
            discard: true,
          });
          const read = Effect.forEach(entries, (entry) => store.get(entry.key), {
            concurrency: 1,
          });
          yield* yield* PurgeRateLimits;
          const first = yield* read;
          yield* yield* PurgeRateLimits;
          return { first, second: yield* read };
        }).pipe(Effect.provide(TestClock.layer())),
      );
      expect(result.first).toEqual([null, null, null, entries[3], entries[4]]);
      expect(result.second).toEqual(result.first);
    });
  });
};

const tokenCases = (label: string, run: Run): void => {
  describe(`${label}: EmailVerificationStore and PasswordResetStore`, () => {
    it("round-trip a record by its digest, and a miss is null", async () => {
      const verification = tokenRecord(uuid());
      const reset = tokenRecord(uuid());
      const result = await run(
        Effect.gen(function* () {
          const verifications = yield* Auth.Email.EmailVerificationStore;
          const resets = yield* Auth.Password.PasswordResetStore;
          return {
            created: yield* verifications.create(verification),
            verification: yield* verifications.get(verification.token),
            reset: yield* Effect.andThen(resets.create(reset), resets.get(reset.token)),
            missing: yield* verifications.get(Auth.hashToken(uuid())),
          };
        }),
      );
      expect(result.created).toEqual(verification);
      expect(result.verification).toEqual(verification);
      expect(result.reset).toEqual(reset);
      expect(result.missing).toBeNull();
    });

    it("keep the two purposes apart in one table", async () => {
      const userId = uuid();
      const verification = tokenRecord(userId);
      const reset = tokenRecord(userId);
      const result = await run(
        Effect.gen(function* () {
          const verifications = yield* Auth.Email.EmailVerificationStore;
          const resets = yield* Auth.Password.PasswordResetStore;
          yield* verifications.create(verification);
          yield* resets.create(reset);
          const crossed = {
            verificationAsReset: yield* resets.get(verification.token),
            resetAsVerification: yield* verifications.get(reset.token),
          };
          // A reset request clears the user's pending resets, never their verification.
          yield* resets.delete(verification.token);
          yield* resets.deleteByUserId(userId);
          return {
            ...crossed,
            verification: yield* verifications.get(verification.token),
            reset: yield* resets.get(reset.token),
          };
        }),
      );
      expect(result).toEqual({
        verificationAsReset: null,
        resetAsVerification: null,
        verification,
        reset: null,
      });
    });

    it("delete and deleteByUserId remove only their rows, and are no-ops on a miss", async () => {
      const userId = uuid();
      const first = tokenRecord(userId);
      const second = tokenRecord(userId);
      const other = tokenRecord(uuid());
      const result = await run(
        Effect.gen(function* () {
          const store = yield* Auth.Email.EmailVerificationStore;
          yield* Effect.forEach([first, second, other], store.create, {
            concurrency: 1,
            discard: true,
          });
          yield* store.delete(first.token);
          yield* store.delete(Auth.hashToken(uuid()));
          const afterDelete = yield* store.get(second.token);
          yield* store.deleteByUserId(userId);
          yield* store.deleteByUserId(uuid());
          return {
            afterDelete,
            first: yield* store.get(first.token),
            second: yield* store.get(second.token),
            other: yield* store.get(other.token),
          };
        }),
      );
      expect(result).toEqual({ afterDelete: second, first: null, second: null, other });
    });

    it("getLatestByUserId reads the user's newest record of its own purpose, and null for none (#682)", async () => {
      const userId = uuid();
      const older = tokenRecord(userId);
      const newer = { ...tokenRecord(userId), createdAt: millis(2_000) };
      const middle = { ...tokenRecord(userId), createdAt: millis(1_000) };
      // A newer reset for the same user is the other purpose's.
      const reset = { ...tokenRecord(userId), createdAt: millis(5_000) };
      const result = await run(
        Effect.gen(function* () {
          const store = yield* Auth.Email.EmailVerificationStore;
          const resets = yield* Auth.Password.PasswordResetStore;
          yield* Effect.forEach([older, newer, middle], store.create, {
            concurrency: 1,
            discard: true,
          });
          yield* resets.create(reset);
          return {
            latest: yield* store.getLatestByUserId(userId),
            none: yield* store.getLatestByUserId(uuid()),
          };
        }),
      );
      expect(result).toEqual({ latest: newer, none: null });
    });
  });
};

/** Register every case, `label` naming the engine and driver. */
export const authStoresContract = (label: string, run: Run): void => {
  conformance(`${label}: ApiKeyStore`, Testing.apiKeyStoreConformance(), run);
  emailPasswordCases(label, run);
  userServiceCases(label, run);
  rateLimitCases(label, run);
  tokenCases(label, run);
};
