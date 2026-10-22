/**
 * Core sign-up over the single-table `IdentifierStore` (#380), written once and
 * run against each dialect that has an engine in the test run.
 *
 * Core passes the address a user signs up with to the store's `createUser` (as
 * `CreateUserInput.identifier`). The application's user writer inserts the row
 * with it, and the claim that follows finds the address already on the row. On a
 * `NOT NULL` `email` column that is the only way the row can be inserted; on a
 * nullable one a writer may also leave the address out, and the claim writes it.
 *
 * The suite drives `EmailPasswordService` end to end: sign-up, then sign-in with
 * the same address. Everything but the users table is in memory. Never published
 * (`tsconfig.json` excludes `src/testing/`).
 */

import { Effect, Layer } from "effect";
import { beforeEach, describe, expect, it } from "vite-plus/test";
import * as Auth from "@thomasfosterau/effect-auth";
import * as Email from "@thomasfosterau/effect-auth/email";
import * as Password from "@thomasfosterau/effect-auth/password";

/** A user row's email columns as the application writes them. */
export interface UserRowInsert {
  readonly id: string;
  /** `null` leaves the address out of the insert. */
  readonly email: string | null;
  readonly emailVerified: boolean;
  readonly createdAt: Date;
}

/** The database the sign-up suite runs against. */
export interface SignUpHarness {
  /** Run `build`'s program against the single-table store on the file's database. */
  readonly run: <A, E>(build: () => Effect.Effect<A, E, Auth.IdentifierStore>) => Promise<A>;
  /** Insert a user row, as the application's own user writer does. */
  readonly insertUser: (row: UserRowInsert) => Promise<void>;
  /** The email columns of a user row as stored, or `null` when there is no row. */
  readonly readUserRow: (
    userId: string,
  ) => Promise<{ readonly email: string | null; readonly emailVerified: boolean } | null>;
  /** How many user rows the table holds. */
  readonly countUserRows: () => Promise<number>;
}

/**
 * Whether the application's writer puts `CreateUserInput.identifier` on the row
 * (`"writes"`), leaves the address for the claim to write (`"omits"`), or finds
 * or creates on the address (`"findsOrCreates"`): it puts the address on the row
 * of a new user, and returns the user who already holds it with
 * `created: false`.
 */
export type WriterMode = "writes" | "omits" | "findsOrCreates";

/** Fast test-only password hasher (not cryptographically secure). */
const testHasher: typeof Password.PasswordHasher.Service = {
  algorithm: "test",
  hash: (password) => Effect.succeed({ hash: `test$${password}`, algorithm: "test" }),
  verify: (password, hash) => Effect.succeed(hash === `test$${password}`),
};

/** A `SessionService` that issues a session and does nothing else. */
const sessions: typeof Auth.SessionService.Service = {
  createSession: (userId) =>
    Effect.sync(() => {
      const now = new Date();
      return {
        id: `s-${userId}`,
        userId,
        expiresAt: new Date(now.getTime() + 3_600_000),
        createdAt: now,
        lastActivityAt: now,
        attributes: {},
      };
    }),
  validateSession: () => Effect.die("unused"),
  invalidateSession: () => Effect.die("unused"),
  invalidateUserSessions: () => Effect.void,
  listSessions: () => Effect.succeed([]),
  revokeOtherSessions: () => Effect.void,
  setSessionAttributes: () => Effect.die("unused"),
};

/**
 * The application's side of sign-up: an `EmailPasswordStore` whose `createUser`
 * inserts the row through `insertUser`, and a `UserStore` over the users it
 * created. Password hashes stay in memory.
 */
export const makeAppWriter = (
  insertUser: (row: UserRowInsert) => Promise<void>,
  mode: WriterMode,
) => {
  const users = new Map<string, Auth.User>();
  const hashes = new Map<string, string>();
  /** The `identifier` each `createUser` call was given. */
  const createdWith: Array<Auth.NewUserIdentifier | undefined> = [];

  const toRow = (
    id: string,
    createdAt: Date,
    identifier: Auth.NewUserIdentifier | undefined,
  ): UserRowInsert =>
    mode !== "omits" && identifier?.type === "email"
      ? { id, email: identifier.value, emailVerified: identifier.verified, createdAt }
      : { id, email: null, emailVerified: false, createdAt };

  /** Insert a new user; in `"findsOrCreates"` mode, first look the address up through `lookup`. */
  const createUserWith = (
    input: Email.CreateUserInput,
    lookup?: typeof Auth.IdentifierStore.Service,
  ): Effect.Effect<Auth.CreateUserResult, Auth.AuthError> =>
    Effect.gen(function* () {
      createdWith.push(input.identifier);
      if (mode === "findsOrCreates" && lookup !== undefined && input.identifier !== undefined) {
        const held = yield* lookup.getByValue(input.identifier.type, input.identifier.value);
        const existing = held === null ? undefined : users.get(held.userId);
        if (existing !== undefined) return { user: existing, created: false };
      }
      const id = globalThis.crypto.randomUUID();
      const now = new Date();
      yield* Effect.tryPromise({
        try: () => insertUser(toRow(id, now, input.identifier)),
        catch: (cause) => new Auth.AuthError({ message: "insert into users failed", cause }),
      });
      const user: Auth.User = { id, createdAt: now, updatedAt: now, attributes: {} };
      users.set(id, user);
      return { user, created: true };
    });

  const createUser = (input: Email.CreateUserInput) => createUserWith(input);

  const emailPasswordStore: typeof Email.EmailPasswordStore.Service = {
    createUser,
    getPasswordHash: (userId) => Effect.sync(() => hashes.get(userId) ?? null),
    clearPasswordHash: (userId: string) => Effect.sync(() => void hashes.delete(userId)),
    setPasswordHash: (userId, hash) => Effect.sync(() => void hashes.set(userId, hash)),
  };

  const userStore: typeof Auth.UserStore.Service = {
    get: (userId) => Effect.sync(() => users.get(userId) ?? null),
  };

  /**
   * Run `f` against an `EmailPasswordService` over the ambient identifier store,
   * passed through `wrap` when given (to stage a concurrent sign-up).
   */
  const withService = <A, E>(
    f: (service: typeof Email.EmailPasswordService.Service) => Effect.Effect<A, E>,
    wrap?: (store: typeof Auth.IdentifierStore.Service) => typeof Auth.IdentifierStore.Service,
  ): Effect.Effect<A, E, Auth.IdentifierStore> =>
    Effect.gen(function* () {
      const store = yield* Auth.IdentifierStore;
      const layer = Email.EmailPasswordService.layer().pipe(
        Layer.provide(
          Layer.mergeAll(
            Layer.succeed(Email.EmailPasswordStore)({
              ...emailPasswordStore,
              createUser: (input) => createUserWith(input, store),
            }),
            Layer.succeed(Auth.IdentifierStore)(wrap === undefined ? store : wrap(store)),
            Layer.succeed(Auth.UserStore)(userStore),
            Layer.succeed(Password.PasswordHasher)(testHasher),
            Layer.succeed(Auth.SessionService)(sessions),
            Auth.Hooks.Default,
          ),
        ),
      );
      return yield* Effect.gen(function* () {
        return yield* f(yield* Email.EmailPasswordService);
      }).pipe(Effect.provide(layer));
    });

  return { createdWith, createUser, withService };
};

const ADA = "ada@example.com";
const PASSWORD = "correct horse battery staple";

/**
 * The sign-up suite. `nullable` says which shape the harness's table has; the
 * suite runs the writer that puts the address on the row against both, and the
 * writer that leaves it out against each with its own expectation.
 */
export const signUpContract = (label: string, nullable: boolean, harness: SignUpHarness) =>
  describe(`${label}: core sign-up (${nullable ? "nullable" : "NOT NULL"} email)`, () => {
    beforeEach(async () => {
      expect(await harness.countUserRows()).toBe(0);
    });

    it("inserts the row holding the address, unverified, and the user signs in with it", async () => {
      const writer = makeAppWriter(harness.insertUser, "writes");

      const { signedUp, signedIn } = await harness.run(() =>
        writer.withService((service) =>
          Effect.gen(function* () {
            const signedUp = yield* service.signUp({ email: ADA, password: PASSWORD });
            const signedIn = yield* service.signIn({ email: ADA, password: PASSWORD });
            return { signedUp, signedIn };
          }),
        ),
      );

      expect(writer.createdWith).toEqual([{ type: "email", value: ADA, verified: false }]);
      expect(signedUp.identifier).toEqual({ type: "email", value: ADA });
      expect(await harness.readUserRow(signedUp.user.id)).toEqual({
        email: ADA,
        emailVerified: false,
      });
      expect(await harness.countUserRows()).toBe(1);
      expect(signedIn.user.id).toBe(signedUp.user.id);
      expect(signedIn.session?.userId).toBe(signedUp.user.id);
    });

    it("a second sign-up with the address fails with EmailInUseError and inserts no row", async () => {
      const writer = makeAppWriter(harness.insertUser, "writes");

      const error = await harness.run(() =>
        writer.withService((service) =>
          Effect.gen(function* () {
            yield* service.signUp({ email: ADA, password: PASSWORD });
            return yield* Effect.flip(service.signUp({ email: ADA, password: "another password" }));
          }),
        ),
      );

      expect(error).toBeInstanceOf(Auth.EmailInUseError);
      expect(await harness.countUserRows()).toBe(1);
    });

    it("a sign-up that loses the race at the insert fails with EmailInUseError, not AuthError", async () => {
      const writer = makeAppWriter(harness.insertUser, "writes");
      await harness.run(() =>
        writer.withService((service) => service.signUp({ email: ADA, password: PASSWORD })),
      );

      // The second sign-up's pre-check misses Ada (as if it ran before her row
      // committed), so the users table's unique index is what refuses it.
      let missed = false;
      const error = await harness.run(() =>
        writer.withService(
          (service) => Effect.flip(service.signUp({ email: ADA, password: "another password" })),
          (store) => ({
            ...store,
            getByValue: (type, value) => {
              if (missed) return store.getByValue(type, value);
              missed = true;
              return Effect.succeed(null);
            },
          }),
        ),
      );

      expect(missed).toBe(true);
      expect(error).toBeInstanceOf(Auth.EmailInUseError);
      expect(await harness.countUserRows()).toBe(1);
    });

    it("a writer that returns the address's existing owner fails sign-up with EmailInUseError, and the owner keeps their password", async () => {
      const writer = makeAppWriter(harness.insertUser, "findsOrCreates");
      const ada = await harness.run(() =>
        writer.withService((service) => service.signUp({ email: ADA, password: PASSWORD })),
      );

      // The second sign-up's pre-check misses Ada, so it reaches the writer,
      // which finds Ada's row and returns her with `created: false`.
      let missed = false;
      const error = await harness.run(() =>
        writer.withService(
          (service) => Effect.flip(service.signUp({ email: ADA, password: "attacker password" })),
          (store) => ({
            ...store,
            getByValue: (type, value) => {
              if (missed) return store.getByValue(type, value);
              missed = true;
              return Effect.succeed(null);
            },
          }),
        ),
      );

      expect(missed).toBe(true);
      expect(error).toBeInstanceOf(Auth.EmailInUseError);
      expect(writer.createdWith).toHaveLength(2);
      expect(await harness.countUserRows()).toBe(1);
      expect(await harness.readUserRow(ada.user.id)).toEqual({ email: ADA, emailVerified: false });
      // Ada's own password still signs her in, and the attacker's does not.
      const signIns = await harness.run(() =>
        writer.withService((service) =>
          Effect.gen(function* () {
            const own = yield* service.signIn({ email: ADA, password: PASSWORD });
            const attacker = yield* Effect.flip(
              service.signIn({ email: ADA, password: "attacker password" }),
            );
            return { own, attacker };
          }),
        ),
      );
      expect(signIns.own.user.id).toBe(ada.user.id);
      expect(signIns.attacker).toBeInstanceOf(Auth.InvalidCredentialsError);
    });

    it("a verified address is held verified, whether the writer stores the flag or not", async () => {
      const writer = makeAppWriter(harness.insertUser, "writes");
      // A writer that stores the address but drops its verification.
      const unflagged = makeAppWriter(
        (row) => harness.insertUser({ ...row, emailVerified: false }),
        "writes",
      );
      const verifiedAt = new Date(Date.UTC(2026, 9, 15));

      const { flagged, dropped } = await harness.run(() =>
        Effect.gen(function* () {
          const store = yield* Auth.IdentifierStore;
          const verified = { type: "email", verified: true, verifiedAt } as const;
          return {
            flagged: yield* Auth.createUserWithIdentifier(
              store,
              { ...verified, value: ADA },
              (identifier) => writer.createUser({ identifier }),
            ),
            dropped: yield* Auth.createUserWithIdentifier(
              store,
              { ...verified, value: "grace@example.com" },
              (identifier) => unflagged.createUser({ identifier }),
            ),
          };
        }),
      );

      expect(flagged.identifier).toMatchObject({ id: flagged.user.id, value: ADA, verified: true });
      expect(await harness.readUserRow(flagged.user.id)).toEqual({
        email: ADA,
        emailVerified: true,
      });
      expect(dropped.identifier).toMatchObject({ value: "grace@example.com", verified: true });
      expect(await harness.readUserRow(dropped.user.id)).toEqual({
        email: "grace@example.com",
        emailVerified: true,
      });
    });

    it.runIf(nullable)(
      "a writer that leaves the address out still signs up: the claim writes it",
      async () => {
        const writer = makeAppWriter(harness.insertUser, "omits");

        const { signedUp, signedIn } = await harness.run(() =>
          writer.withService((service) =>
            Effect.gen(function* () {
              const signedUp = yield* service.signUp({ email: ADA, password: PASSWORD });
              const signedIn = yield* service.signIn({ email: ADA, password: PASSWORD });
              return { signedUp, signedIn };
            }),
          ),
        );

        expect(await harness.readUserRow(signedUp.user.id)).toEqual({
          email: ADA,
          emailVerified: false,
        });
        expect(signedIn.user.id).toBe(signedUp.user.id);
      },
    );
    it.skipIf(nullable)(
      "a writer that leaves the address out cannot insert the row: sign-up fails and nothing is written",
      async () => {
        const writer = makeAppWriter(harness.insertUser, "omits");

        const error = await harness.run(() =>
          writer.withService((service) =>
            Effect.flip(service.signUp({ email: ADA, password: PASSWORD })),
          ),
        );

        expect(error).toBeInstanceOf(Auth.AuthError);
        expect(await harness.countUserRows()).toBe(0);
      },
    );
  });
