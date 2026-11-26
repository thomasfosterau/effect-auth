import { assert, beforeEach, describe, expect, it } from "vite-plus/test";
import * as Context from "effect/Context";
import * as DateTime from "effect/DateTime";
import * as Effect from "effect/Effect";
import * as MutableHashMap from "effect/MutableHashMap";
import * as Result from "effect/Result";
import * as Option from "effect/Option";
import { AccountDeletion } from "./AccountDeletion.ts";
import { UserServiceStore } from "./User.ts";
import * as User from "./User.ts";
import {
  IdentifierStore,
  makeIdentifier,
  memoryIdentifierStore,
  resolveUserByIdentifier,
  type Identifier,
} from "./Identifier.ts";
import { normalizeEmail } from "./Normalize.ts";
import type { User as UserRecord } from "./Types.ts";

const users = MutableHashMap.empty<string, UserRecord>();
const identifierRecords = MutableHashMap.empty<string, Identifier>();
const identifiers = memoryIdentifierStore(identifierRecords);

const userStore = {
  get: (userId: string) => Effect.sync(() => MutableHashMap.get(users, userId)),

  update: (user: UserRecord) =>
    Effect.sync(() => {
      MutableHashMap.set(users, user.id, user);
      return user;
    }),

  delete: (userId: string) =>
    Effect.sync(() => {
      MutableHashMap.remove(users, userId);
    }),
};

const makeTestContext = () => Context.make(UserServiceStore, userStore);

describe("UserService", () => {
  beforeEach(() => {
    MutableHashMap.clear(users);
    MutableHashMap.clear(identifierRecords);

    const seeded: UserRecord = {
      id: "user-1",
      name: "User One",
      createdAt: DateTime.toDateUtc(DateTime.nowUnsafe()),
      updatedAt: DateTime.toDateUtc(DateTime.nowUnsafe()),
      attributes: {
        role: "member",
      },
    };

    MutableHashMap.set(users, seeded.id, seeded);
    // The login handle lives in the identifier store now, not on the user.
    const emailIdentifier = makeIdentifier({
      userId: seeded.id,
      type: "email",
      value: "user@example.com",
      now: DateTime.toDateUtc(DateTime.nowUnsafe()),
    });
    MutableHashMap.set(identifierRecords, emailIdentifier.id, emailIdentifier);
  });

  it("should get user by id", async () => {
    const result = await Effect.runPromise(
      Effect.provide(
        Effect.gen(function* () {
          const service = yield* User.make();
          return yield* service.getUser("user-1");
        }),
        makeTestContext(),
      ),
    );

    expect(result.id).toBe("user-1");
    expect(result.name).toBe("User One");
  });

  it("should resolve a user by normalized email identifier", async () => {
    const result = await Effect.runPromise(
      Effect.provide(
        Effect.gen(function* () {
          const store = yield* IdentifierStore;
          return yield* resolveUserByIdentifier(
            store,
            userStore.get,
            "email",
            normalizeEmail("  USER@EXAMPLE.COM  "),
          );
        }),
        Context.make(IdentifierStore, identifiers),
      ),
    );

    assert(Option.isSome(result), "the identifier resolves to its user");
    expect(Option.getOrUndefined(result)?.user.id).toBe("user-1");
    expect(Option.getOrUndefined(result)?.identifier.value).toBe("user@example.com");
  });

  it("should merge attributes when updating user", async () => {
    const result = await Effect.runPromise(
      Effect.provide(
        Effect.gen(function* () {
          const service = yield* User.make();
          return yield* service.updateUserAttributes("user-1", {
            theme: "dark",
            displayName: "Updated User",
          });
        }),
        makeTestContext(),
      ),
    );

    expect(result.attributes.theme).toBe("dark");
    expect(result.attributes.displayName).toBe("Updated User");
    expect(result.attributes.role).toBe("member");
  });

  it("refuses a role in a profile update — the rung is server-only by default", async () => {
    const error = await Effect.runPromise(
      Effect.provide(
        Effect.gen(function* () {
          const service = yield* User.make();
          return yield* Effect.flip(
            service.updateUserAttributes("user-1", { displayName: "Sneaky", role: "admin" }),
          );
        }),
        makeTestContext(),
      ),
    );

    expect(error._tag).toBe("InvalidInputError");
    expect(error).toMatchObject({ field: "role" });
    // Nothing was written — not even the harmless half of the update.
    expect(Option.getOrUndefined(MutableHashMap.get(users, "user-1"))?.attributes).toEqual({
      role: "member",
    });
  });

  it("refuses every configured server-only attribute, and can be opted out of", async () => {
    const refused = await Effect.runPromise(
      Effect.provide(
        Effect.gen(function* () {
          const service = yield* User.make({ serverOnlyAttributes: ["role", "plan"] });
          return yield* Effect.flip(service.updateUserAttributes("user-1", { plan: "pro" }));
        }),
        makeTestContext(),
      ),
    );
    expect(refused).toMatchObject({ _tag: "InvalidInputError", field: "plan" });

    const allowed = await Effect.runPromise(
      Effect.provide(
        Effect.gen(function* () {
          const service = yield* User.make({ serverOnlyAttributes: [] });
          return yield* service.updateUserAttributes("user-1", { role: "admin" });
        }),
        makeTestContext(),
      ),
    );
    expect(allowed.attributes.role).toBe("admin");
  });

  it.each([
    "banned",
    "banReason",
    "banExpires",
    "scimDeactivated",
    "scimUserName",
    "scimExternalId",
    "isAnonymous",
  ])(
    "refuses %s, which its own service writes, even with no server-only attributes",
    async (key) => {
      const error = await Effect.runPromise(
        Effect.provide(
          Effect.gen(function* () {
            const service = yield* User.make({ serverOnlyAttributes: [] });
            return yield* Effect.flip(service.updateUserAttributes("user-1", { [key]: false }));
          }),
          makeTestContext(),
        ),
      );
      expect(error).toMatchObject({ _tag: "InvalidInputError", field: key });
      expect(Option.getOrUndefined(MutableHashMap.get(users, "user-1"))?.attributes).toEqual({
        role: "member",
      });
    },
  );

  it("should mark the user's email identifier as verified", async () => {
    const result = await Effect.runPromise(
      Effect.provide(
        Effect.gen(function* () {
          const store = yield* IdentifierStore;
          const identifier = yield* store.getByValue("email", "user@example.com");
          assert(Option.isSome(identifier), "the email identifier exists");
          yield* store.setVerified(identifier.value.id, yield* DateTime.nowAsDate);
          return yield* store.getByValue("email", "user@example.com");
        }),
        Context.make(IdentifierStore, identifiers),
      ),
    );

    expect(Option.getOrUndefined(result)?.verified).toBe(true);
    expect(Option.getOrUndefined(result)?.verifiedAt).toBeInstanceOf(Date);
  });

  it("deleteUser deletes the account through AccountDeletion", async () => {
    const deleted: Array<string> = [];
    const deletion = Context.make(AccountDeletion, {
      deleteUser: (userId) =>
        Effect.sync(() => {
          deleted.push(userId);
          MutableHashMap.remove(users, userId);
        }),
    });
    const result = await Effect.runPromise(
      Effect.provide(
        Effect.gen(function* () {
          const service = yield* User.make();
          yield* service.deleteUser("user-1");
          return yield* Effect.result(service.getUser("user-1"));
        }),
        Context.merge(makeTestContext(), deletion),
      ),
    );

    expect(deleted).toEqual(["user-1"]);
    assert(Result.isFailure(result));
    expect(result.failure._tag).toBe("UserNotFoundError");
  });

  it("deleteUser without AccountDeletion fails and deletes nothing, not even the row", async () => {
    const result = await Effect.runPromise(
      Effect.provide(
        Effect.gen(function* () {
          const service = yield* User.make();
          const failure = yield* Effect.flip(service.deleteUser("user-1"));
          return { failure, user: yield* service.getUser("user-1") };
        }),
        makeTestContext(),
      ),
    );

    expect(result.failure._tag).toBe("AuthError");
    expect(result.failure.message).toContain("accountDeletionLayer");
    expect(result.user.id).toBe("user-1");
  });
});
