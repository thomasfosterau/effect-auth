import { beforeEach, describe, expect, it } from "vite-plus/test";
import { Context, Effect } from "effect";
import { makeUserService, UserServiceStore } from "./User.js";
import type { User } from "./Types.js";

const users = new Map<string, User>();
const usersByEmail = new Map<string, string>();

const userStore = {
  get: (userId: string) => Effect.sync(() => users.get(userId) ?? null),

  getByEmail: (email: string) =>
    Effect.sync(() => {
      const userId = usersByEmail.get(email);
      return userId ? (users.get(userId) ?? null) : null;
    }),

  update: (user: User) =>
    Effect.sync(() => {
      users.set(user.id, user);
      usersByEmail.set(user.email.toLowerCase(), user.id);
      return user;
    }),

  delete: (userId: string) =>
    Effect.sync(() => {
      const existing = users.get(userId);
      if (existing) {
        usersByEmail.delete(existing.email.toLowerCase());
      }
      users.delete(userId);
    }),
};

const makeTestContext = () => Context.make(UserServiceStore, userStore);

describe("UserService", () => {
  beforeEach(() => {
    users.clear();
    usersByEmail.clear();

    const seeded: User = {
      id: "user-1",
      email: "user@example.com",
      emailVerified: false,
      name: "User One",
      createdAt: new Date(),
      updatedAt: new Date(),
      attributes: {
        role: "member",
      },
    };

    users.set(seeded.id, seeded);
    usersByEmail.set("user@example.com", seeded.id);
  });

  it("should get user by id", async () => {
    const program = Effect.gen(function* () {
      const service = yield* makeUserService();
      return yield* service.getUser("user-1");
    });

    const result = await Effect.runPromise(Effect.provide(program, makeTestContext()));

    expect(result.id).toBe("user-1");
    expect(result.email).toBe("user@example.com");
  });

  it("should get user by normalized email", async () => {
    const program = Effect.gen(function* () {
      const service = yield* makeUserService();
      return yield* service.getUserByEmail("  USER@EXAMPLE.COM  ");
    });

    const result = await Effect.runPromise(Effect.provide(program, makeTestContext()));

    expect(result.id).toBe("user-1");
  });

  it("should merge attributes when updating user", async () => {
    const program = Effect.gen(function* () {
      const service = yield* makeUserService();
      return yield* service.updateUserAttributes("user-1", {
        role: "admin",
        displayName: "Updated User",
      });
    });

    const result = await Effect.runPromise(Effect.provide(program, makeTestContext()));

    expect(result.email).toBe("user@example.com");
    expect(result.attributes.role).toBe("admin");
    expect(result.attributes.displayName).toBe("Updated User");
  });

  it("should mark user email as verified", async () => {
    const program = Effect.gen(function* () {
      const service = yield* makeUserService();
      return yield* service.markEmailVerified("user-1");
    });

    const result = await Effect.runPromise(Effect.provide(program, makeTestContext()));

    expect(result.emailVerified).toBe(true);
  });

  it("should delete user", async () => {
    const program = Effect.gen(function* () {
      const service = yield* makeUserService();
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
