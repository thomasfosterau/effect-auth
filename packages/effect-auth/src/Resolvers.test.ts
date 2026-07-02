import { describe, it, expect, beforeEach } from "vite-plus/test";
import { Effect, Context } from "effect";
import * as Requests from "./Requests.js";
import * as Resolvers from "./Resolvers.js";
import { type UserStore } from "./Session.js";
import { UserStore as UserStoreTag } from "./Session.js";
import { PasswordHasherLive, makePasswordHasher } from "./Password.js";
import type { User } from "./Types.js";
import { UserNotFoundError } from "./Errors.js";
import { makeUserService, UserService, UserServiceStore } from "./User.js";

// Mock stores for testing
const users = new Map<string, User>([
  ["user1", { id: "user1", attributes: { name: "Test User" } }],
]);
const credentials = new Map<string, string>();

const mockUserStore: UserStore = {
  get: (userId) =>
    Effect.gen(function* () {
      const user = users.get(userId);
      if (!user) {
        return yield* Effect.fail(new UserNotFoundError({ message: "Not found", userId }));
      }
      return user;
    }),
  getCredentials: (userId) =>
    Effect.gen(function* () {
      const hash = credentials.get(userId);
      if (!hash) {
        return yield* Effect.fail(new UserNotFoundError({ message: "Not found", userId }));
      }
      return hash;
    }),
};

describe("Resolvers", () => {
  beforeEach(() => {
    credentials.clear();
  });

  it("should hash a password using the resolver", async () => {
    const request = Requests.HashPasswordRequest({ password: "testPassword123" });
    const program = Effect.request(request, Resolvers.makeHashPasswordResolver);

    const result = await Effect.runPromise(Effect.provide(program, PasswordHasherLive));

    expect(result.hash).toBeDefined();
    expect(result.algorithm).toBe("pbkdf2-sha256");
  });

  describe("VerifyPasswordResolver", () => {
    it("should verify a password using the resolver", async () => {
      const program = Effect.gen(function* () {
        // First hash a password
        const hashRequest = Requests.HashPasswordRequest({ password: "testPassword123" });
        const hashed = yield* Effect.request(hashRequest, Resolvers.makeHashPasswordResolver);

        // Then verify it
        const verifyRequest = Requests.VerifyPasswordRequest({
          password: "testPassword123",
          hash: hashed.hash,
        });
        return yield* Effect.request(verifyRequest, Resolvers.makeVerifyPasswordResolver);
      });

      const isValid = await Effect.runPromise(Effect.provide(program, PasswordHasherLive));

      expect(isValid).toBe(true);
    });

    it("should reject incorrect password using the resolver", async () => {
      const program = Effect.gen(function* () {
        // First hash a password
        const hashRequest = Requests.HashPasswordRequest({ password: "correctPassword" });
        const hashed = yield* Effect.request(hashRequest, Resolvers.makeHashPasswordResolver);

        // Then verify with wrong password
        const verifyRequest = Requests.VerifyPasswordRequest({
          password: "wrongPassword",
          hash: hashed.hash,
        });
        return yield* Effect.request(verifyRequest, Resolvers.makeVerifyPasswordResolver);
      });

      const isValid = await Effect.runPromise(Effect.provide(program, PasswordHasherLive));

      expect(isValid).toBe(false);
    });
  });

  describe("VerifyCredentialsResolver", () => {
    it("should verify valid credentials", async () => {
      const program = Effect.gen(function* () {
        const hasher = makePasswordHasher();

        // Setup: hash a password and store it
        const hashed = yield* hasher.hash("userPassword123");
        credentials.set("user1", hashed.hash);

        // Verify credentials
        const request = Requests.VerifyCredentialsRequest({
          userId: "user1",
          password: "userPassword123",
        });
        return yield* Effect.request(request, Resolvers.makeVerifyCredentialsResolver);
      });

      const testContext = Context.merge(
        Context.make(UserStoreTag, mockUserStore),
        PasswordHasherLive,
      );

      const user = await Effect.runPromise(Effect.provide(program, testContext));

      expect(user.id).toBe("user1");
    });

    it("should fail with invalid credentials", async () => {
      const program = Effect.gen(function* () {
        const hasher = makePasswordHasher();

        // Setup: hash a password and store it
        const hashed = yield* hasher.hash("correctPassword");
        credentials.set("user1", hashed.hash);

        // Try to verify with wrong password
        const request = Requests.VerifyCredentialsRequest({
          userId: "user1",
          password: "wrongPassword",
        });
        return yield* Effect.request(request, Resolvers.makeVerifyCredentialsResolver);
      });

      const testContext = Context.merge(
        Context.make(UserStoreTag, mockUserStore),
        PasswordHasherLive,
      );

      const result = await Effect.runPromise(Effect.result(Effect.provide(program, testContext)));

      expect(result._tag).toBe("Failure");
      if (result._tag === "Failure") {
        expect(result.failure._tag).toBe("InvalidCredentialsError");
      }
    });
  });

  describe("User resolvers", () => {
    const userRecords = new Map<string, User>();
    const usersByEmail = new Map<string, string>();

    const userServiceStore = {
      get: (userId: string) =>
        Effect.gen(function* () {
          const user = userRecords.get(userId);
          if (!user) {
            return yield* Effect.fail(new UserNotFoundError({ message: "Not found", userId }));
          }
          return user;
        }),

      getByEmail: (email: string) =>
        Effect.sync(() => {
          const id = usersByEmail.get(email);
          return id ? (userRecords.get(id) ?? null) : null;
        }),

      update: (user: User) =>
        Effect.sync(() => {
          userRecords.set(user.id, user);
          const email = user.attributes.email;
          if (typeof email === "string") {
            usersByEmail.set(email.toLowerCase(), user.id);
          }
          return user;
        }),

      delete: (userId: string) =>
        Effect.sync(() => {
          const existing = userRecords.get(userId);
          if (existing) {
            const email = existing.attributes.email;
            if (typeof email === "string") {
              usersByEmail.delete(email.toLowerCase());
            }
          }
          userRecords.delete(userId);
        }),
    };

    beforeEach(() => {
      const seeded: User = {
        id: "resolver-user-1",
        attributes: {
          email: "resolver@example.com",
          name: "Resolver User",
          emailVerified: false,
        },
      };

      userRecords.clear();
      usersByEmail.clear();
      userRecords.set(seeded.id, seeded);
      usersByEmail.set("resolver@example.com", seeded.id);
    });

    const makeUserTestContext = async () => {
      const service = await Effect.runPromise(makeUserService());
      return Context.merge(
        Context.make(UserServiceStore, userServiceStore),
        Context.make(UserService, service),
      );
    };

    it("should get a user via resolver", async () => {
      const request = Requests.GetUserRequest({ userId: "resolver-user-1" });
      const program = Effect.request(request, Resolvers.makeGetUserResolver);

      const result = await Effect.runPromise(Effect.provide(program, await makeUserTestContext()));

      expect(result.id).toBe("resolver-user-1");
    });

    it("should get a user by email via resolver", async () => {
      const request = Requests.GetUserByEmailRequest({ email: "RESOLVER@EXAMPLE.COM" });
      const program = Effect.request(request, Resolvers.makeGetUserByEmailResolver);

      const result = await Effect.runPromise(Effect.provide(program, await makeUserTestContext()));

      expect(result.id).toBe("resolver-user-1");
    });

    it("should update user attributes via resolver", async () => {
      const request = Requests.UpdateUserAttributesRequest({
        userId: "resolver-user-1",
        attributes: { role: "admin" },
      });
      const program = Effect.request(request, Resolvers.makeUpdateUserAttributesResolver);

      const result = await Effect.runPromise(Effect.provide(program, await makeUserTestContext()));

      expect(result.attributes.role).toBe("admin");
      expect(result.attributes.email).toBe("resolver@example.com");
    });

    it("should mark email verified via resolver", async () => {
      const request = Requests.MarkEmailVerifiedRequest({ userId: "resolver-user-1" });
      const program = Effect.request(request, Resolvers.makeMarkEmailVerifiedResolver);

      const result = await Effect.runPromise(Effect.provide(program, await makeUserTestContext()));

      expect(result.attributes.emailVerified).toBe(true);
    });

    it("should delete user via resolver", async () => {
      const request = Requests.DeleteUserRequest({ userId: "resolver-user-1" });
      const program = Effect.request(request, Resolvers.makeDeleteUserResolver);

      await Effect.runPromise(Effect.provide(program, await makeUserTestContext()));

      expect(userRecords.has("resolver-user-1")).toBe(false);
      expect(usersByEmail.has("resolver@example.com")).toBe(false);
    });
  });
});
