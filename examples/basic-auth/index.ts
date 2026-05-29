/**
 * Complete example showing authentication flow with effect-auth
 *
 * This example demonstrates:
 * - Setting up storage adapters
 * - Password hashing and verification
 * - Session creation and validation
 * - User authentication flow
 */

import { Effect, Context } from "effect";
import * as Auth from "effect-auth";

// In-memory storage for demonstration
// In production, use Redis, PostgreSQL, etc.
const sessions = new Map<string, Auth.Session>();
const users = new Map<string, Auth.User>();
const passwords = new Map<string, string>();

// Initialize with a test user
users.set("user-1", {
  id: "user-1",
  attributes: {
    email: "test@example.com",
    name: "Test User",
  },
});

/**
 * Implement SessionStore using in-memory Map
 */
const sessionStore: Auth.SessionStore = {
  create: (session) =>
    Effect.sync(() => {
      sessions.set(session.id, session);
      return session;
    }),

  get: (sessionId) =>
    Effect.gen(function* () {
      const session = sessions.get(sessionId);
      if (!session) {
        return yield* Effect.fail(
          new Auth.SessionNotFoundError({
            message: "Session not found",
            sessionId,
          }),
        );
      }
      return session;
    }),

  update: (session) =>
    Effect.sync(() => {
      sessions.set(session.id, session);
      return session;
    }),

  delete: (sessionId) =>
    Effect.sync(() => {
      sessions.delete(sessionId);
    }),

  deleteByUserId: (userId) =>
    Effect.sync(() => {
      for (const [id, session] of sessions.entries()) {
        if (session.userId === userId) {
          sessions.delete(id);
        }
      }
    }),
};

/**
 * Implement UserStore using in-memory Map
 */
const userStore: Auth.UserStore = {
  get: (userId) =>
    Effect.gen(function* () {
      const user = users.get(userId);
      if (!user) {
        return yield* Effect.fail(
          new Auth.UserNotFoundError({
            message: "User not found",
            userId,
          }),
        );
      }
      return user;
    }),

  getCredentials: (userId) =>
    Effect.gen(function* () {
      const password = passwords.get(userId);
      if (!password) {
        return yield* Effect.fail(
          new Auth.UserNotFoundError({
            message: "User not found",
            userId,
          }),
        );
      }
      return password;
    }),
};

/**
 * Session configuration
 */
const sessionConfig: Auth.SessionConfig = {
  sessionExpiresIn: {
    activePeriod: 1000 * 60 * 60 * 24 * 30, // 30 days
    idlePeriod: 1000 * 60 * 60 * 24 * 14, // 14 days
  },
};

/**
 * Complete authentication flow example
 */
const authenticationFlow = Effect.gen(function* () {
  console.log("🔐 Starting authentication flow example...\n");

  // Get services
  const hasher = yield* Auth.PasswordHasher;
  const sessionManager = yield* Auth.makeSessionManager(sessionConfig);

  // 1. Hash a password for our test user
  console.log("1️⃣ Hashing password...");
  const hashedPassword = yield* hasher.hash("mySecurePassword123");
  passwords.set("user-1", hashedPassword.hash);
  console.log("   ✅ Password hashed successfully");
  console.log(`   Algorithm: ${hashedPassword.algorithm}\n`);

  // 2. Verify credentials (simulate login)
  console.log("2️⃣ Verifying credentials...");
  const isValid = yield* hasher.verify("mySecurePassword123", hashedPassword.hash);
  if (!isValid) {
    return yield* Effect.fail(
      new Auth.InvalidCredentialsError({
        message: "Invalid credentials",
      }),
    );
  }
  console.log("   ✅ Credentials verified\n");

  // 3. Create a session after successful authentication
  console.log("3️⃣ Creating session...");
  const session = yield* sessionManager.createSession("user-1", {
    ip: "192.168.1.1",
    userAgent: "Mozilla/5.0",
  });
  console.log(`   ✅ Session created with ID: ${session.id}`);
  console.log(`   User ID: ${session.userId}`);
  console.log(`   Expires: ${session.expiresAt.toISOString()}\n`);

  // 4. Validate the session (simulate subsequent request)
  console.log("4️⃣ Validating session...");
  const { session: validSession, user } = yield* sessionManager.validateSession(session.id);
  console.log("   ✅ Session validated successfully");
  console.log(`   User: ${user.attributes.name} (${user.attributes.email})`);
  console.log(`   Session ID: ${validSession.id}\n`);

  // 5. Test invalid password
  console.log("5️⃣ Testing invalid password...");
  const isInvalid = yield* hasher.verify("wrongPassword", hashedPassword.hash);
  console.log(`   ✅ Invalid password correctly rejected: ${!isInvalid}\n`);

  // 6. Create multiple sessions for the same user
  console.log("6️⃣ Creating additional sessions...");
  const session2 = yield* sessionManager.createSession("user-1");
  const session3 = yield* sessionManager.createSession("user-1");
  console.log(`   ✅ Created sessions: ${session2.id}, ${session3.id}\n`);

  // 7. Invalidate all user sessions
  console.log("7️⃣ Invalidating all user sessions...");
  yield* sessionManager.invalidateUserSessions("user-1");
  const result = yield* Effect.either(sessionManager.validateSession(session.id));
  if (result._tag === "Left") {
    console.log("   ✅ All sessions invalidated successfully\n");
  }

  // 8. Create a new session after invalidation
  console.log("8️⃣ Creating new session after invalidation...");
  const newSession = yield* sessionManager.createSession("user-1");
  const { user: newUser } = yield* sessionManager.validateSession(newSession.id);
  console.log(`   ✅ New session created: ${newSession.id}`);
  console.log(`   User: ${newUser.attributes.name}\n`);

  console.log("✨ Authentication flow completed successfully!");

  return {
    user: newUser,
    session: newSession,
  };
});

/**
 * Run the example
 */
const runExample = async () => {
  try {
    const result = await Effect.runPromise(
      Effect.provide(
        authenticationFlow,
        Context.merge(
          Context.make(Auth.SessionStore, sessionStore),
          Context.merge(Context.make(Auth.UserStore, userStore), Auth.PasswordHasherLive),
        ),
      ).pipe(Effect.provide(Auth.Hooks.Default)),
    );

    console.log("\n📊 Final Result:");
    console.log(JSON.stringify(result, null, 2));
  } catch (error) {
    console.error("❌ Error:", error);
    process.exit(1);
  }
};

// Run if this file is executed directly
if (import.meta.url === `file://${process.argv[1]}`) {
  runExample();
}

export { authenticationFlow, sessionStore, userStore, sessionConfig };
