import { assert, beforeEach, describe, expect, it } from "vite-plus/test";
import { Context, Effect, Result } from "effect";
import { UserServiceStore } from "./User.ts";
import * as User from "./User.ts";
import {
  IdentifierStore,
  makeIdentifier,
  memoryIdentifierStore,
  resolveUserByIdentifier,
  type Identifier,
} from "./Identifier.ts";
import { normalizeEmail } from "./utils.ts";
import type { User as UserRecord } from "./Types.ts";

const users = new Map<string, UserRecord>();
const identifierRecords = new Map<string, Identifier>();
const identifiers = memoryIdentifierStore(identifierRecords);

const userStore = {
  get: (userId: string) => Effect.sync(() => users.get(userId) ?? null),

  update: (user: UserRecord) =>
    Effect.sync(() => {
      users.set(user.id, user);
      return user;
    }),

  delete: (userId: string) =>
    Effect.sync(() => {
      users.delete(userId);
    }),
};

const makeTestContext = () => Context.make(UserServiceStore, userStore);

describe("UserService", () => {
  beforeEach(() => {
    users.clear();
    identifierRecords.clear();

    const seeded: UserRecord = {
      id: "user-1",
      name: "User One",
      createdAt: new Date(),
      updatedAt: new Date(),
      attributes: {
        role: "member",
      },
    };

    users.set(seeded.id, seeded);
    // The login handle lives in the identifier store now, not on the user.
    const emailIdentifier = makeIdentifier({
      userId: seeded.id,
      type: "email",
      value: "user@example.com",
    });
    identifierRecords.set(emailIdentifier.id, emailIdentifier);
  });

  it("should get user by id", async () => {
    const program = Effect.gen(function* () {
      const service = yield* User.make();
      return yield* service.getUser("user-1");
    });

    const result = await Effect.runPromise(Effect.provide(program, makeTestContext()));

    expect(result.id).toBe("user-1");
    expect(result.name).toBe("User One");
  });

  it("should resolve a user by normalized email identifier", async () => {
    const program = Effect.gen(function* () {
      const store = yield* IdentifierStore;
      return yield* resolveUserByIdentifier(
        store,
        userStore.get,
        "email",
        normalizeEmail("  USER@EXAMPLE.COM  "),
      );
    });

    const result = await Effect.runPromise(
      Effect.provide(program, Context.make(IdentifierStore, identifiers)),
    );

    assert(result !== null, "the identifier resolves to its user");
    expect(result.user.id).toBe("user-1");
    expect(result.identifier.value).toBe("user@example.com");
  });

  it("should merge attributes when updating user", async () => {
    const program = Effect.gen(function* () {
      const service = yield* User.make();
      return yield* service.updateUserAttributes("user-1", {
        theme: "dark",
        displayName: "Updated User",
      });
    });

    const result = await Effect.runPromise(Effect.provide(program, makeTestContext()));

    expect(result.attributes.theme).toBe("dark");
    expect(result.attributes.displayName).toBe("Updated User");
    expect(result.attributes.role).toBe("member");
  });

  it("refuses a role in a profile update — the rung is server-only by default (#193)", async () => {
    const program = Effect.gen(function* () {
      const service = yield* User.make();
      return yield* Effect.flip(
        service.updateUserAttributes("user-1", { displayName: "Sneaky", role: "admin" }),
      );
    });

    const error = await Effect.runPromise(Effect.provide(program, makeTestContext()));

    expect(error._tag).toBe("InvalidInputError");
    expect(error).toMatchObject({ field: "role" });
    // Nothing was written — not even the harmless half of the update.
    expect(users.get("user-1")?.attributes).toEqual({ role: "member" });
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

  it("should mark the user's email identifier as verified", async () => {
    const program = Effect.gen(function* () {
      const store = yield* IdentifierStore;
      const identifier = yield* store.getByValue("email", "user@example.com");
      assert(identifier !== null, "the email identifier exists");
      yield* store.setVerified(identifier.id, new Date());
      return yield* store.getByValue("email", "user@example.com");
    });

    const result = await Effect.runPromise(
      Effect.provide(program, Context.make(IdentifierStore, identifiers)),
    );

    expect(result?.verified).toBe(true);
    expect(result?.verifiedAt).toBeInstanceOf(Date);
  });

  it("should delete user", async () => {
    const program = Effect.gen(function* () {
      const service = yield* User.make();
      yield* service.deleteUser("user-1");
      return yield* Effect.result(service.getUser("user-1"));
    });

    const result = await Effect.runPromise(Effect.provide(program, makeTestContext()));

    expect(result._tag).toBe("Failure");

    assert(Result.isFailure(result));

    expect(result.failure._tag).toBe("UserNotFoundError");
  });
});
