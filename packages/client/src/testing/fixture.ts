/**
 * Test-only fixture: a fully functional in-memory effect-auth server (the
 * real `makeAuthWebHandler` over in-memory stores) plus a cookie-jar `fetch`
 * so the browser-oriented client can be exercised end to end in-process.
 *
 * Excluded from the published build (see `tsconfig.json`).
 */
import * as Auth from "effect-auth";
import { Effect, Layer } from "effect";

const HOUR = 60 * 60 * 1000;

// Low scrypt cost keeps the suite fast while exercising real hashing.
const hasher = Auth.makeScryptHasher({ cost: 16384 });

export const makeServerFixture = () => {
  const usersById = new Map<string, Auth.User>();
  const userIdByEmail = new Map<string, string>();
  const passwordHashes = new Map<string, string>();
  const sessions = new Map<string, Auth.Session>();
  const verifications = new Map<string, Auth.EmailVerification>();
  const resets = new Map<string, Auth.PasswordResetToken>();
  let userSeq = 0;

  const createUser = (input: {
    readonly email: string;
    readonly emailVerified?: boolean;
    readonly name?: string;
    readonly attributes?: Record<string, unknown>;
  }): Auth.User => {
    const now = new Date();
    const user: Auth.User = {
      id: `user-${++userSeq}`,
      email: input.email,
      emailVerified: input.emailVerified ?? false,
      ...(input.name !== undefined && { name: input.name }),
      createdAt: now,
      updatedAt: now,
      attributes: input.attributes ?? {},
    };
    usersById.set(user.id, user);
    userIdByEmail.set(user.email, user.id);
    return user;
  };

  const userByEmail = (email: string): Auth.User | null => {
    const id = userIdByEmail.get(email);
    return id === undefined ? null : (usersById.get(id) ?? null);
  };

  const getUserById = (userId: string) => Effect.sync(() => usersById.get(userId) ?? null);

  const sessionStore: Auth.SessionStoreShape = {
    create: (session) => Effect.sync(() => (sessions.set(session.id, session), session)),
    get: (sessionId) => Effect.sync(() => sessions.get(sessionId) ?? null),
    update: (session) => Effect.sync(() => (sessions.set(session.id, session), session)),
    delete: (sessionId) => Effect.sync(() => void sessions.delete(sessionId)),
    deleteByUserId: (userId) =>
      Effect.sync(() => {
        for (const [id, session] of sessions) if (session.userId === userId) sessions.delete(id);
      }),
    listByUserId: (userId) =>
      Effect.sync(() => [...sessions.values()].filter((session) => session.userId === userId)),
  };

  const userStore: Auth.UserStoreShape = {
    get: getUserById,
    getCredentials: (userId) => Effect.sync(() => passwordHashes.get(userId) ?? null),
  };

  const emailPasswordStore: Auth.EmailPasswordStoreShape = {
    getUserByEmail: (email) => Effect.sync(() => userByEmail(email)),
    createUser: (input) => Effect.sync(() => createUser(input)),
    getPasswordHash: (userId) => Effect.sync(() => passwordHashes.get(userId) ?? null),
    setPasswordHash: (userId, hash) => Effect.sync(() => void passwordHashes.set(userId, hash)),
  };

  const userServiceStore: Auth.UserServiceStoreShape = {
    get: getUserById,
    getByEmail: (email) => Effect.sync(() => userByEmail(email)),
    update: (user) =>
      Effect.sync(() => {
        usersById.set(user.id, user);
        userIdByEmail.set(user.email, user.id);
        return user;
      }),
    delete: (userId) =>
      Effect.sync(() => {
        const user = usersById.get(userId);
        if (user !== undefined) {
          userIdByEmail.delete(user.email);
          usersById.delete(userId);
        }
      }),
  };

  const emailVerificationStore: Auth.EmailVerificationStoreShape = {
    create: (v) => Effect.sync(() => (verifications.set(v.token, v), v)),
    get: (token) => Effect.sync(() => verifications.get(token) ?? null),
    delete: (token) => Effect.sync(() => void verifications.delete(token)),
    deleteByUserId: (userId) =>
      Effect.sync(() => {
        for (const [token, v] of verifications)
          if (v.userId === userId) verifications.delete(token);
      }),
  };

  const passwordResetStore: Auth.PasswordResetStoreShape = {
    create: (reset) => Effect.sync(() => (resets.set(reset.token, reset), reset)),
    get: (token) => Effect.sync(() => resets.get(token) ?? null),
    delete: (token) => Effect.sync(() => void resets.delete(token)),
    deleteByUserId: (userId) =>
      Effect.sync(() => {
        for (const [token, reset] of resets) if (reset.userId === userId) resets.delete(token);
      }),
  };

  const passwordResetUserStore: Auth.PasswordResetUserStoreShape = {
    getUserByEmail: (email) => Effect.sync(() => userByEmail(email)),
    setPasswordHash: (userId, hash) => Effect.sync(() => void passwordHashes.set(userId, hash)),
  };

  const storeLayer = Layer.mergeAll(
    Layer.succeed(Auth.SessionStore)(sessionStore),
    Layer.succeed(Auth.UserStore)(userStore),
    Layer.succeed(Auth.EmailPasswordStore)(emailPasswordStore),
    Layer.succeed(Auth.PasswordHasher)(hasher),
    Layer.succeed(Auth.EmailVerificationStore)(emailVerificationStore),
    Layer.succeed(Auth.PasswordResetStore)(passwordResetStore),
    Layer.succeed(Auth.PasswordResetUserStore)(passwordResetUserStore),
    Layer.succeed(Auth.UserServiceStore)(userServiceStore),
    Auth.Hooks.Default,
  );

  const services: Layer.Layer<Auth.Http.AuthServices> = Layer.mergeAll(
    storeLayer,
    Auth.SessionManager.layer({
      sessionExpiresIn: { activePeriod: HOUR, idlePeriod: HOUR },
    }).pipe(Layer.provide(storeLayer)),
    Auth.AuthLifecycleService.layer(),
    Auth.EmailVerificationService.layer({ sendEmail: () => Effect.void }),
    Auth.PasswordResetService.layer({ sendResetPassword: () => Effect.void }),
    Auth.UserService.layer(),
  );

  const { handler } = Auth.Http.makeAuthWebHandler({
    services,
    cookie: { secure: false },
  });

  return { handler, sessions };
};

/**
 * A `fetch` that dispatches to an in-process handler and emulates the
 * browser's cookie jar (the client relies on `credentials: "include"`).
 */
export const makeCookieJarFetch = (
  handler: (request: Request) => Promise<Response>,
): typeof globalThis.fetch => {
  const jar = new Map<string, string>();

  return (async (input: RequestInfo | URL, init?: RequestInit) => {
    const request = new Request(input, init);
    if (jar.size > 0) {
      request.headers.set(
        "cookie",
        [...jar.entries()].map(([name, value]) => `${name}=${value}`).join("; "),
      );
    }
    const response = await handler(request);
    for (const setCookie of response.headers.getSetCookie()) {
      const [pair] = setCookie.split(";");
      const eq = (pair ?? "").indexOf("=");
      if (eq <= 0) continue;
      const name = pair!.slice(0, eq).trim();
      const value = pair!.slice(eq + 1).trim();
      if (value === "" || setCookie.toLowerCase().includes("max-age=0")) {
        jar.delete(name);
      } else {
        jar.set(name, value);
      }
    }
    return response;
  }) as typeof globalThis.fetch;
};
