import { beforeEach, describe, expect, it } from "vite-plus/test";
import { Context, Effect } from "effect";
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

    expect(result).not.toBeNull();
    expect(result!.user.id).toBe("user-1");
    expect(result!.identifier.value).toBe("user@example.com");
  });

  it("should merge attributes when updating user", async () => {
    const program = Effect.gen(function* () {
      const service = yield* User.make();
      return yield* service.updateUserAttributes("user-1", {
        role: "admin",
        displayName: "Updated User",
      });
    });

    const result = await Effect.runPromise(Effect.provide(program, makeTestContext()));

    expect(result.attributes.role).toBe("admin");
    expect(result.attributes.displayName).toBe("Updated User");
  });

  it("should mark the user's email identifier as verified", async () => {
    const program = Effect.gen(function* () {
      const store = yield* IdentifierStore;
      const identifier = yield* store.getByValue("email", "user@example.com");
      yield* store.setVerified(identifier!.id, new Date());
      return yield* store.getByValue("email", "user@example.com");
    });

    const result = await Effect.runPromise(
      Effect.provide(program, Context.make(IdentifierStore, identifiers)),
    );

    expect(result!.verified).toBe(true);
    expect(result!.verifiedAt).toBeInstanceOf(Date);
  });

  it("should delete user", async () => {
    const program = Effect.gen(function* () {
      const service = yield* User.make();
      yield* service.deleteUser("user-1");
      return yield* Effect.result(service.getUser("user-1"));
    });

    const result = await Effect.runPromise(Effect.provide(program, makeTestContext()));

    expect(result._tag).toBe("Failure");
    if (result._tag === "Failure") {
      expect(result.failure._tag).toBe("UserNotFoundError");
    }
  });
});
