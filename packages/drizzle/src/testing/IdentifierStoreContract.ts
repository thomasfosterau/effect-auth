/**
 * The `IdentifierStore` contract, written once and run against every drizzle
 * store that claims it (#182).
 *
 * The suites:
 *
 * - {@link identifierStoreContract} — the semantics the core contract states for
 *   any store, restricted to email identifiers so the multi-identifier store and
 *   the single-table store both qualify. It runs against each of them.
 * - {@link singleTableContract} — what only the single-table store does: one
 *   email per user, the user row as the identifier, refusals for other types.
 * - {@link notNullContract} — a `NOT NULL` email column: a targeted delete is
 *   refused, `deleteByUser` leaves the row for account deletion to remove, and
 *   `replace` rewrites the address without ever writing `NULL`.
 * - {@link verifiedAtContract} — a mapped `emailVerifiedAt` column stores and
 *   reports the verification time.
 *
 * A harness supplies the database and the user rows; everything else is the
 * assertion. Never published (`tsconfig.json` excludes `src/testing/`).
 */

import { Effect } from "effect";
import { assert, beforeEach, describe, expect, it } from "vite-plus/test";
import * as Auth from "@thomasfosterau/effect-auth";

/**
 * Three user ids in the shape the applications use: `uuid` keys. The
 * multi-identifier store keys on text, so the same ids serve both.
 */
export const USER = {
  ada: "5e1f0c3a-7b1d-4a53-9c0e-00000000000a",
  grace: "5e1f0c3a-7b1d-4a53-9c0e-00000000000b",
  /** Never seeded: a user id that exists nowhere. */
  ghost: "5e1f0c3a-7b1d-4a53-9c0e-0000000000ff",
} as const;

/** The `created_at` every seeded user row carries. */
export const USER_CREATED_AT = new Date(Date.UTC(2026, 0, 1));

/** The database a suite runs against. */
export interface StoreHarness {
  /** Run `build`'s program against the store under test on the file's database. */
  readonly run: <A, E>(build: () => Effect.Effect<A, E, Auth.IdentifierStore>) => Promise<A>;
  /**
   * Insert {@link USER}'s `ada` and `grace` rows, as the application's own user
   * writer would, with no login handle. A store that keeps identifiers in its
   * own table has nothing to seed.
   */
  readonly seedUsers: () => Promise<void>;
}

/** The single-table suite also looks at the user row itself. */
export interface SingleTableHarness extends StoreHarness {
  /**
   * The email columns of a user row as they are stored, or `null` when the row
   * is gone. Read straight from the table, not through the store.
   */
  readonly readUserRow: (
    userId: string,
  ) => Promise<{ readonly email: string | null; readonly emailVerified: boolean } | null>;
}

const emailFor = (userId: string, value: string, verified = false): Auth.Identifier =>
  Auth.makeIdentifier({ userId, type: "email", value, verified });

/** The semantics every `IdentifierStore` states, over email identifiers. */
export const identifierStoreContract = (label: string, harness: StoreHarness) =>
  describe(`${label}: IdentifierStore contract`, () => {
    beforeEach(() => harness.seedUsers());

    it("resolves an email by its value, and misses with null", async () => {
      const result = await harness.run(() =>
        Effect.gen(function* () {
          const store = yield* Auth.IdentifierStore;
          const created = yield* store.create(emailFor(USER.ada, "ada@example.com"));
          return {
            created,
            byValue: yield* store.getByValue("email", "ada@example.com"),
            missing: yield* store.getByValue("email", "nobody@example.com"),
            // The same value under another type is a different key.
            crossType: yield* store.getByValue("phone", "ada@example.com"),
          };
        }),
      );

      expect(result.created.userId).toBe(USER.ada);
      expect(result.created.verified).toBe(false);
      expect(result.byValue?.id).toBe(result.created.id);
      expect(result.byValue?.userId).toBe(USER.ada);
      expect(result.byValue?.value).toBe("ada@example.com");
      expect(result.missing).toBeNull();
      expect(result.crossType).toBeNull();
    });

    it("refuses a claimed (type, value) with AuthError, which claimIdentifier reports as taken", async () => {
      const result = await harness.run(() =>
        Effect.gen(function* () {
          const store = yield* Auth.IdentifierStore;
          yield* store.create(emailFor(USER.ada, "ada@example.com"));

          const duplicate = yield* Effect.flip(
            store.create(emailFor(USER.grace, "ada@example.com")),
          );
          const claim = yield* Effect.flip(
            Auth.claimIdentifier(store, emailFor(USER.grace, "ada@example.com")),
          );
          const free = yield* Auth.claimIdentifier(
            store,
            emailFor(USER.grace, "grace@example.com"),
          );

          return {
            duplicate,
            claim,
            free,
            owner: yield* store.getByValue("email", "ada@example.com"),
          };
        }),
      );

      expect(result.duplicate._tag).toBe("AuthError");
      expect(result.duplicate.cause).toBeDefined();

      expect(result.claim._tag).toBe("IdentifierTakenError");
      assert.instanceOf(result.claim, Auth.IdentifierTakenError);
      expect(result.claim.identifierType).toBe("email");

      expect(result.free.userId).toBe(USER.grace);
      // The loser never took the address from its owner.
      expect(result.owner?.userId).toBe(USER.ada);
    });

    it("lists a user's identifiers, and [] for a user with none", async () => {
      const result = await harness.run(() =>
        Effect.gen(function* () {
          const store = yield* Auth.IdentifierStore;
          yield* store.create(emailFor(USER.ada, "ada@example.com"));
          return {
            listed: yield* store.listByUser(USER.ada),
            graceNone: yield* store.listByUser(USER.grace),
            ghost: yield* store.listByUser(USER.ghost),
          };
        }),
      );

      expect(result.listed.map((identifier) => identifier.value)).toEqual(["ada@example.com"]);
      expect(result.listed[0]?.type).toBe("email");
      expect(result.graceNone).toEqual([]);
      expect(result.ghost).toEqual([]);
    });

    it("setVerified marks the identifier verified, and returns null for an unknown id", async () => {
      const result = await harness.run(() =>
        Effect.gen(function* () {
          const store = yield* Auth.IdentifierStore;
          const created = yield* store.create(emailFor(USER.ada, "ada@example.com"));
          return {
            verified: yield* store.setVerified(created.id, new Date(Date.UTC(2026, 0, 2))),
            reloaded: yield* store.getByValue("email", "ada@example.com"),
            unknown: yield* store.setVerified(USER.ghost, new Date(Date.UTC(2026, 0, 2))),
          };
        }),
      );

      expect(result.verified?.verified).toBe(true);
      expect(result.reloaded?.verified).toBe(true);
      expect(result.unknown).toBeNull();
    });

    it("delete removes one identifier, and is a no-op when it is absent", async () => {
      const result = await harness.run(() =>
        Effect.gen(function* () {
          const store = yield* Auth.IdentifierStore;
          const ada = yield* store.create(emailFor(USER.ada, "ada@example.com"));
          yield* store.create(emailFor(USER.grace, "grace@example.com"));

          yield* store.delete(ada.id);
          yield* store.delete(USER.ghost);

          return {
            gone: yield* store.getByValue("email", "ada@example.com"),
            adaListed: yield* store.listByUser(USER.ada),
            kept: yield* store.getByValue("email", "grace@example.com"),
          };
        }),
      );

      expect(result.gone).toBeNull();
      expect(result.adaListed).toEqual([]);
      expect(result.kept?.userId).toBe(USER.grace);
    });

    it("deleteByUser removes that user's identifiers, and is a no-op for a user with none", async () => {
      const result = await harness.run(() =>
        Effect.gen(function* () {
          const store = yield* Auth.IdentifierStore;
          yield* store.create(emailFor(USER.ada, "ada@example.com"));
          yield* store.create(emailFor(USER.grace, "grace@example.com"));

          yield* store.deleteByUser(USER.ada);
          yield* store.deleteByUser(USER.ghost);

          return {
            adaListed: yield* store.listByUser(USER.ada),
            graceListed: yield* store.listByUser(USER.grace),
          };
        }),
      );

      expect(result.adaListed).toEqual([]);
      expect(result.graceListed.map((identifier) => identifier.value)).toEqual([
        "grace@example.com",
      ]);
    });

    it("replace swaps the user's email for a new one, and the old one resolves to nothing", async () => {
      const result = await harness.run(() =>
        Effect.gen(function* () {
          const store = yield* Auth.IdentifierStore;
          const ada = yield* store.create(emailFor(USER.ada, "ada@example.com"));
          const replaced = yield* store.replace(
            ada,
            emailFor(USER.ada, "ada-new@example.com", true),
          );
          return {
            replaced,
            listed: yield* store.listByUser(USER.ada),
            old: yield* store.getByValue("email", "ada@example.com"),
            current: yield* store.getByValue("email", "ada-new@example.com"),
            // Free again once released: another user can claim it.
            moved: yield* Auth.claimIdentifier(store, emailFor(USER.grace, "ada@example.com")),
          };
        }),
      );

      expect(result.replaced?.userId).toBe(USER.ada);
      expect(result.replaced?.value).toBe("ada-new@example.com");
      expect(result.replaced?.verified).toBe(true);
      expect(result.listed.map((identifier) => [identifier.value, identifier.verified])).toEqual([
        ["ada-new@example.com", true],
      ]);
      expect(result.old).toBeNull();
      expect(result.current?.userId).toBe(USER.ada);
      expect(result.moved.userId).toBe(USER.grace);
    });

    it("replace refuses an address another user holds with AuthError, which replaceIdentifier reports as taken, and keeps the old one", async () => {
      const result = await harness.run(() =>
        Effect.gen(function* () {
          const store = yield* Auth.IdentifierStore;
          const ada = yield* store.create(emailFor(USER.ada, "ada@example.com", true));
          yield* store.create(emailFor(USER.grace, "grace@example.com"));

          // The store call alone: the unique index refuses the write.
          const refused = yield* Effect.flip(
            store.replace(ada, emailFor(USER.ada, "grace@example.com")),
          );
          const taken = yield* Effect.flip(
            Auth.replaceIdentifier(store, ada, emailFor(USER.ada, "grace@example.com")),
          );
          return {
            refused,
            taken,
            adaListed: yield* store.listByUser(USER.ada),
            owner: yield* store.getByValue("email", "grace@example.com"),
          };
        }),
      );

      expect(result.refused._tag).toBe("AuthError");
      expect(result.taken._tag).toBe("IdentifierTakenError");
      assert.instanceOf(result.taken, Auth.IdentifierTakenError);
      expect(result.taken.identifierType).toBe("email");
      expect(result.adaListed.map((identifier) => [identifier.value, identifier.verified])).toEqual(
        [["ada@example.com", true]],
      );
      expect(result.owner?.userId).toBe(USER.grace);
    });

    it("replace of an identifier the user no longer holds resolves to null and writes nothing", async () => {
      const result = await harness.run(() =>
        Effect.gen(function* () {
          const store = yield* Auth.IdentifierStore;
          const ada = yield* store.create(emailFor(USER.ada, "ada@example.com"));
          // The same record with an address the user does not hold: a stale read.
          const stale: Auth.Identifier = { ...ada, value: "ada-old@example.com" };
          return {
            replaced: yield* store.replace(stale, emailFor(USER.ada, "ada-new@example.com")),
            notFound: yield* Effect.flip(
              Auth.replaceIdentifier(store, stale, emailFor(USER.ada, "ada-new@example.com")),
            ),
            listed: yield* store.listByUser(USER.ada),
            newAddress: yield* store.getByValue("email", "ada-new@example.com"),
          };
        }),
      );

      expect(result.replaced).toBeNull();
      expect(result.notFound._tag).toBe("IdentifierNotFoundError");
      expect(result.listed.map((identifier) => identifier.value)).toEqual(["ada@example.com"]);
      expect(result.newAddress).toBeNull();
    });

    it("replace refuses a replacement for another user, of another type, with the same id, or of the same value", async () => {
      const result = await harness.run(() =>
        Effect.gen(function* () {
          const store = yield* Auth.IdentifierStore;
          const ada = yield* store.create(emailFor(USER.ada, "ada@example.com"));
          return {
            otherUser: yield* Effect.flip(
              store.replace(ada, emailFor(USER.grace, "grace@example.com")),
            ),
            otherType: yield* Effect.flip(
              store.replace(
                ada,
                Auth.makeIdentifier({ userId: USER.ada, type: "username", value: "ada" }),
              ),
            ),
            sameId: yield* Effect.flip(
              store.replace(ada, { ...emailFor(USER.ada, "ada-new@example.com"), id: ada.id }),
            ),
            sameValue: yield* Effect.flip(
              store.replace(ada, emailFor(USER.ada, "ada@example.com", true)),
            ),
            adaListed: yield* store.listByUser(USER.ada),
            graceListed: yield* store.listByUser(USER.grace),
            newAddress: yield* store.getByValue("email", "ada-new@example.com"),
          };
        }),
      );

      expect(result.otherUser._tag).toBe("AuthError");
      expect(result.otherType._tag).toBe("AuthError");
      expect(result.sameId._tag).toBe("AuthError");
      expect(result.sameValue._tag).toBe("AuthError");
      expect(result.newAddress).toBeNull();
      expect(result.adaListed.map((identifier) => [identifier.value, identifier.verified])).toEqual(
        [["ada@example.com", false]],
      );
      expect(result.graceListed).toEqual([]);
    });
  });

/** What only the single-table store does, over the same database harness. */
export const singleTableContract = (label: string, harness: SingleTableHarness) =>
  describe(`${label}: single-table semantics`, () => {
    beforeEach(() => harness.seedUsers());

    it("uses the user's id as the identifier's id and the user's created_at as its createdAt", async () => {
      const result = await harness.run(() =>
        Effect.gen(function* () {
          const store = yield* Auth.IdentifierStore;
          const created = yield* store.create(emailFor(USER.ada, "ada@example.com"));
          return {
            created,
            listed: yield* store.listByUser(USER.ada),
          };
        }),
      );

      expect(result.created.id).toBe(USER.ada);
      expect(result.created.userId).toBe(USER.ada);
      expect(result.created.createdAt).toEqual(USER_CREATED_AT);
      expect(result.listed).toEqual([result.created]);
    });

    it("never reports a verifiedAt, since the table has no column for one", async () => {
      const result = await harness.run(() =>
        Effect.gen(function* () {
          const store = yield* Auth.IdentifierStore;
          const created = yield* store.create(
            Auth.makeIdentifier({
              userId: USER.ada,
              type: "email",
              value: "ada@example.com",
              verified: true,
              verifiedAt: new Date(Date.UTC(2026, 0, 2)),
            }),
          );
          return {
            created,
            reloaded: yield* store.getByValue("email", "ada@example.com"),
          };
        }),
      );

      expect(result.created.verified).toBe(true);
      expect("verifiedAt" in result.created).toBe(false);
      expect(result.reloaded?.verified).toBe(true);
      expect(result.reloaded && "verifiedAt" in result.reloaded).toBe(false);
    });

    it("holds only email: other types never resolve and cannot be created", async () => {
      const result = await harness.run(() =>
        Effect.gen(function* () {
          const store = yield* Auth.IdentifierStore;
          yield* store.create(emailFor(USER.ada, "ada@example.com"));
          const username = yield* Effect.flip(
            store.create(Auth.makeIdentifier({ userId: USER.ada, type: "username", value: "ada" })),
          );
          const phone = yield* Effect.flip(
            store.create(
              Auth.makeIdentifier({ userId: USER.grace, type: "phone", value: "+61400000000" }),
            ),
          );
          return {
            username,
            phone,
            usernameLookup: yield* store.getByValue("username", "ada"),
            phoneLookup: yield* store.getByValue("phone", "+61400000000"),
            listed: yield* store.listByUser(USER.ada),
            graceListed: yield* store.listByUser(USER.grace),
          };
        }),
      );

      expect(result.username._tag).toBe("IdentifierRefusedError");
      expect(result.username.message).toContain("email identifiers only");
      expect(result.phone._tag).toBe("IdentifierRefusedError");
      expect(result.usernameLookup).toBeNull();
      expect(result.phoneLookup).toBeNull();
      expect(result.listed.map((identifier) => identifier.type)).toEqual(["email"]);
      expect(result.graceListed).toEqual([]);
    });

    it("allows one email per user: a second address is refused and the first is kept", async () => {
      const result = await harness.run(() =>
        Effect.gen(function* () {
          const store = yield* Auth.IdentifierStore;
          yield* store.create(emailFor(USER.ada, "ada@example.com"));
          const second = yield* Effect.flip(
            store.create(emailFor(USER.ada, "ada@work.example.com")),
          );
          // claimIdentifier only reports IdentifierTakenError for an address
          // another user holds; this refusal passes through as it is.
          const claim = yield* Effect.flip(
            Auth.claimIdentifier(store, emailFor(USER.ada, "ada@work.example.com")),
          );
          return {
            second,
            claim,
            listed: yield* store.listByUser(USER.ada),
            secondLookup: yield* store.getByValue("email", "ada@work.example.com"),
          };
        }),
      );

      expect(result.second._tag).toBe("IdentifierRefusedError");
      expect(result.second.message).toContain("one email identifier per user");
      expect(result.claim._tag).toBe("IdentifierRefusedError");
      expect(result.listed.map((identifier) => identifier.value)).toEqual(["ada@example.com"]);
      expect(result.secondLookup).toBeNull();
    });

    it("refuses an email for a user with no row, and writes nothing", async () => {
      const result = await harness.run(() =>
        Effect.gen(function* () {
          const store = yield* Auth.IdentifierStore;
          const error = yield* Effect.flip(store.create(emailFor(USER.ghost, "ghost@example.com")));
          return {
            error,
            lookup: yield* store.getByValue("email", "ghost@example.com"),
            ghostListed: yield* store.listByUser(USER.ghost),
          };
        }),
      );

      expect(result.error._tag).toBe("AuthError");
      expect(result.error.message).toContain("no user row");
      expect(result.lookup).toBeNull();
      expect(result.ghostListed).toEqual([]);
    });

    it("replace rewrites the row's address in place, keeping the user's id and created_at", async () => {
      const result = await harness.run(() =>
        Effect.gen(function* () {
          const store = yield* Auth.IdentifierStore;
          const ada = yield* store.create(emailFor(USER.ada, "ada@example.com"));
          return yield* store.replace(ada, emailFor(USER.ada, "ada-new@example.com", true));
        }),
      );

      expect(result?.id).toBe(USER.ada);
      expect(result?.createdAt).toEqual(USER_CREATED_AT);
      expect(await harness.readUserRow(USER.ada)).toEqual({
        email: "ada-new@example.com",
        emailVerified: true,
      });
    });

    it("a user whose email is NULL holds no identifier, and setVerified finds none", async () => {
      const result = await harness.run(() =>
        Effect.gen(function* () {
          const store = yield* Auth.IdentifierStore;
          return {
            listed: yield* store.listByUser(USER.grace),
            verified: yield* store.setVerified(USER.grace, new Date(Date.UTC(2026, 0, 2))),
          };
        }),
      );

      expect(result.listed).toEqual([]);
      expect(result.verified).toBeNull();
    });

    it("delete clears the address and keeps the user row, so the address can be claimed again", async () => {
      const result = await harness.run(() =>
        Effect.gen(function* () {
          const store = yield* Auth.IdentifierStore;
          yield* store.create(emailFor(USER.ada, "ada@example.com", true));
          yield* store.delete(USER.ada);
          const cleared = yield* Effect.orDie(
            Effect.tryPromise(() => harness.readUserRow(USER.ada)),
          );
          const afterDelete = yield* store.getByValue("email", "ada@example.com");
          const adaListed = yield* store.listByUser(USER.ada);
          // Once cleared, the address is free for another user to claim.
          const moved = yield* Auth.claimIdentifier(
            store,
            emailFor(USER.grace, "ada@example.com", true),
          );
          return {
            cleared,
            afterDelete,
            adaListed,
            moved,
          };
        }),
      );

      // The row survives the delete; only its email columns are cleared.
      expect(result.cleared).toEqual({ email: null, emailVerified: false });
      expect(result.afterDelete).toBeNull();
      expect(result.adaListed).toEqual([]);
      expect(result.moved.userId).toBe(USER.grace);
      expect(result.moved.verified).toBe(true);
    });
  });

/**
 * The NOT NULL `email` suite: the store's behaviour when the column cannot hold
 * `NULL`. The harness seeds {@link USER}'s `ada` and `grace` with addresses, since
 * a NOT NULL row always holds one.
 */
export interface NotNullHarness extends SingleTableHarness {
  /** Delete the user row itself, as account deletion does after the identifier store. */
  readonly deleteUserRow: (userId: string) => Promise<void>;
}

/** The NOT NULL suite; see {@link NotNullHarness}. */
export const notNullContract = (label: string, harness: NotNullHarness) =>
  describe(`${label}: NOT NULL email`, () => {
    beforeEach(() => harness.seedUsers());

    it("reads the seeded addresses as identifiers", async () => {
      const result = await harness.run(() =>
        Effect.gen(function* () {
          const store = yield* Auth.IdentifierStore;
          return {
            ada: yield* store.getByValue("email", "ada@example.com"),
            adaListed: yield* store.listByUser(USER.ada),
          };
        }),
      );

      expect(result.ada?.userId).toBe(USER.ada);
      expect(result.adaListed.map((identifier) => identifier.value)).toEqual(["ada@example.com"]);
    });

    it("refuses a targeted delete with AuthError while the row holds the address, and keeps it", async () => {
      const result = await harness.run(() =>
        Effect.gen(function* () {
          const store = yield* Auth.IdentifierStore;
          return {
            refused: yield* Effect.flip(store.delete(USER.ada)),
            still: yield* store.getByValue("email", "ada@example.com"),
          };
        }),
      );

      expect(result.refused._tag).toBe("AuthError");
      expect(result.refused.message).toContain("NOT NULL");
      expect(result.still?.userId).toBe(USER.ada);
      expect(await harness.readUserRow(USER.ada)).toEqual({
        email: "ada@example.com",
        emailVerified: false,
      });
    });

    it("a targeted delete of a user with no row is still a no-op", async () => {
      const result = await harness.run(() =>
        Effect.gen(function* () {
          const store = yield* Auth.IdentifierStore;
          yield* store.delete(USER.ghost);
          return "ok" as const;
        }),
      );

      expect(result).toBe("ok");
    });

    it("replace rewrites a NOT NULL address in place: the row is never NULL", async () => {
      const result = await harness.run(() =>
        Effect.gen(function* () {
          const store = yield* Auth.IdentifierStore;
          const ada = yield* store.getByValue("email", "ada@example.com");
          assert(ada !== null, "ada's email is seeded");
          return {
            replaced: yield* store.replace(ada, emailFor(USER.ada, "ada-new@example.com", true)),
            old: yield* store.getByValue("email", "ada@example.com"),
            listed: yield* store.listByUser(USER.ada),
          };
        }),
      );

      expect(result.replaced?.value).toBe("ada-new@example.com");
      expect(result.old).toBeNull();
      expect(result.listed.map((identifier) => identifier.value)).toEqual(["ada-new@example.com"]);
      expect(await harness.readUserRow(USER.ada)).toEqual({
        email: "ada-new@example.com",
        emailVerified: true,
      });
    });

    it("replace with an address another user holds is refused, and the NOT NULL row keeps its address", async () => {
      const result = await harness.run(() =>
        Effect.gen(function* () {
          const store = yield* Auth.IdentifierStore;
          const ada = yield* store.getByValue("email", "ada@example.com");
          assert(ada !== null, "ada's email is seeded");
          return yield* Effect.flip(
            Auth.replaceIdentifier(store, ada, emailFor(USER.ada, "grace@example.com")),
          );
        }),
      );

      expect(result._tag).toBe("IdentifierTakenError");
      expect(await harness.readUserRow(USER.ada)).toEqual({
        email: "ada@example.com",
        emailVerified: false,
      });
    });

    it("account deletion: deleteByUser leaves the address for the row delete, which removes it", async () => {
      const result = await harness.run(() =>
        Effect.gen(function* () {
          const store = yield* Auth.IdentifierStore;
          yield* store.deleteByUser(USER.ada);
          return {
            // Still held: deleteByUser does not write NULL.
            held: yield* store.getByValue("email", "ada@example.com"),
          };
        }),
      );

      expect(result.held?.userId).toBe(USER.ada);
      expect(await harness.readUserRow(USER.ada)).toEqual({
        email: "ada@example.com",
        emailVerified: false,
      });

      // The application's account deletion deletes the row next.
      await harness.deleteUserRow(USER.ada);

      const after = await harness.run(() =>
        Effect.gen(function* () {
          const store = yield* Auth.IdentifierStore;
          return {
            gone: yield* store.getByValue("email", "ada@example.com"),
            listed: yield* store.listByUser(USER.ada),
          };
        }),
      );

      expect(await harness.readUserRow(USER.ada)).toBeNull();
      expect(after.gone).toBeNull();
      expect(after.listed).toEqual([]);
    });

    it("refuses a second address for a user who already holds one", async () => {
      const result = await harness.run(() =>
        Effect.gen(function* () {
          const store = yield* Auth.IdentifierStore;
          return yield* Effect.flip(store.create(emailFor(USER.ada, "ada-work@example.com")));
        }),
      );

      expect(result._tag).toBe("IdentifierRefusedError");
      expect(await harness.readUserRow(USER.ada)).toEqual({
        email: "ada@example.com",
        emailVerified: false,
      });
    });

    it("setVerified works on a NOT NULL row", async () => {
      const result = await harness.run(() =>
        Effect.gen(function* () {
          const store = yield* Auth.IdentifierStore;
          return yield* store.setVerified(USER.ada, new Date(Date.UTC(2026, 0, 2)));
        }),
      );

      expect(result?.verified).toBe(true);
      expect(await harness.readUserRow(USER.ada)).toEqual({
        email: "ada@example.com",
        emailVerified: true,
      });
    });
  });

/** The mapped `emailVerifiedAt` suite's harness: the single-table one plus a read of the column. */
export interface VerifiedAtHarness extends SingleTableHarness {
  /** The raw `email_verified_at` column of a user row, or `null`. */
  readonly readVerifiedAt: (userId: string) => Promise<Date | null>;
}

/**
 * The suite for a store that maps `emailVerifiedAt`: the timestamp is stored and
 * reported. The unmapped case is {@link singleTableContract}'s
 * "never reports a verifiedAt".
 */
export const verifiedAtContract = (label: string, harness: VerifiedAtHarness) =>
  describe(`${label}: mapped emailVerifiedAt`, () => {
    beforeEach(() => harness.seedUsers());

    it("stores the verification time on setVerified and reports it", async () => {
      const verifiedAt = new Date(Date.UTC(2026, 0, 2, 9, 30));
      const result = await harness.run(() =>
        Effect.gen(function* () {
          const store = yield* Auth.IdentifierStore;
          yield* store.create(emailFor(USER.ada, "ada@example.com"));
          return {
            verified: yield* store.setVerified(USER.ada, verifiedAt),
            reloaded: yield* store.getByValue("email", "ada@example.com"),
          };
        }),
      );

      expect(result.verified?.verifiedAt).toEqual(verifiedAt);
      expect(result.reloaded?.verifiedAt).toEqual(verifiedAt);
      expect(await harness.readVerifiedAt(USER.ada)).toEqual(verifiedAt);
    });

    it("stores and reports a verifiedAt given at claim", async () => {
      const verifiedAt = new Date(Date.UTC(2026, 0, 3));
      const result = await harness.run(() =>
        Effect.gen(function* () {
          const store = yield* Auth.IdentifierStore;
          return yield* store.create(
            Auth.makeIdentifier({
              userId: USER.ada,
              type: "email",
              value: "ada@example.com",
              verified: true,
              verifiedAt,
            }),
          );
        }),
      );

      expect(result.verifiedAt).toEqual(verifiedAt);
      expect(await harness.readVerifiedAt(USER.ada)).toEqual(verifiedAt);
    });

    it("reports no verifiedAt for an identifier that was never verified", async () => {
      const result = await harness.run(() =>
        Effect.gen(function* () {
          const store = yield* Auth.IdentifierStore;
          return yield* store.create(emailFor(USER.ada, "ada@example.com"));
        }),
      );

      expect("verifiedAt" in result).toBe(false);
      expect(await harness.readVerifiedAt(USER.ada)).toBeNull();
    });

    it("replace writes the replacement's verification time, and clears it for an unverified one", async () => {
      const verifiedAt = new Date(Date.UTC(2026, 0, 4));
      const result = await harness.run(() =>
        Effect.gen(function* () {
          const store = yield* Auth.IdentifierStore;
          const ada = yield* store.create(emailFor(USER.ada, "ada@example.com"));
          const verified = yield* store.replace(
            ada,
            Auth.makeIdentifier({
              userId: USER.ada,
              type: "email",
              value: "ada-new@example.com",
              verified: true,
              verifiedAt,
            }),
          );
          const storedVerifiedAt = yield* Effect.orDie(
            Effect.tryPromise(() => harness.readVerifiedAt(USER.ada)),
          );
          assert(verified !== null, "the verified replace succeeds");
          const unverified = yield* store.replace(
            verified,

            emailFor(USER.ada, "ada-other@example.com"),
          );
          return { verified, storedVerifiedAt, unverified };
        }),
      );

      expect(result.verified?.verifiedAt).toEqual(verifiedAt);
      expect(result.storedVerifiedAt).toEqual(verifiedAt);
      expect(result.unverified && "verifiedAt" in result.unverified).toBe(false);
      expect(await harness.readVerifiedAt(USER.ada)).toBeNull();
    });

    it("delete clears the verification time with the address", async () => {
      const verifiedAt = new Date(Date.UTC(2026, 0, 2));
      const result = await harness.run(() =>
        Effect.gen(function* () {
          const store = yield* Auth.IdentifierStore;
          yield* store.create(emailFor(USER.ada, "ada@example.com"));
          yield* store.setVerified(USER.ada, verifiedAt);
          yield* store.delete(USER.ada);
          return { listed: yield* store.listByUser(USER.ada) };
        }),
      );

      expect(result.listed).toEqual([]);
      expect(await harness.readVerifiedAt(USER.ada)).toBeNull();
    });
  });
