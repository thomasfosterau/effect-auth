import { describe, it, expect } from "vite-plus/test";
import { Effect, Exit, Layer, Option } from "effect";
import type * as Types from "./Types.ts";
import * as SessionContext from "./SessionContext.ts";
import {
  CurrentSession,
  CurrentUser,
  MaybeCurrentSession,
  requireCurrentUser,
} from "./SessionContext.ts";
import * as Entity from "./Entity.ts";
import * as Policy from "./Policy.ts";
import { Authorizer, CurrentCredential, CurrentPrincipal } from "./Authorizer.ts";

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

const USER_ID = "user-42";
const now = new Date();

const testUser: Types.User = {
  id: USER_ID,
  createdAt: now,
  updatedAt: now,
  attributes: { role: "admin" },
};

const testSession: Types.Session = {
  id: "session-1",
  userId: USER_ID,
  expiresAt: new Date(now.getTime() + 60 * 60 * 1000),
  createdAt: now,
  lastActivityAt: now,
  attributes: {},
};

const resolved: Types.SessionWithUser = { session: testSession, user: testUser };

/**
 * One read-path effect, written the way an app's zero-IO guard is: it must
 * answer for an anonymous caller *without* failing. Every context below runs
 * this exact value — that is the property #185 is about.
 */
const canViewDeleted = Effect.map(
  SessionContext.currentUserOption,
  Option.match({
    onNone: () => false,
    onSome: (user) => user.attributes.role === "admin",
  }),
);

// ---------------------------------------------------------------------------
// Providing a resolved session outside HTTP
// ---------------------------------------------------------------------------

describe("SessionContext.authenticatedLayer", () => {
  it("runs gated code in a runtime that never saw an HTTP request", async () => {
    const program = Effect.gen(function* () {
      const session = yield* CurrentSession;
      const user = yield* CurrentUser;
      const maybe = yield* MaybeCurrentSession;
      return { sessionId: session.id, userId: user.id, maybe };
    });

    const result = await Effect.runPromise(
      program.pipe(Effect.provide(SessionContext.authenticatedLayer(resolved))),
    );

    expect(result.sessionId).toBe("session-1");
    expect(result.userId).toBe(USER_ID);
    expect(result.maybe).toStrictEqual(Option.some(resolved));
  });

  it('derives CurrentPrincipal as User::"<user.id>"', async () => {
    const principal = await Effect.runPromise(
      CurrentPrincipal.pipe(Effect.provide(SessionContext.authenticatedLayer(resolved))),
    );
    expect(principal).toStrictEqual(Entity.ref("User", USER_ID));
  });

  it("the derived principal drives an end-to-end Authorizer.check", async () => {
    const authorizerLayer = Authorizer.layer({
      policies: [
        Policy.permit({
          id: "self-read",
          action: Policy.eq(Entity.ref("Action", "profile:read")),
          resource: Policy.eq(Entity.ref("User", USER_ID)),
        }),
      ],
    });

    const program = Effect.gen(function* () {
      const authorizer = yield* Authorizer;
      return {
        allowed: yield* authorizer.check({
          action: "profile:read",
          resource: Entity.ref("User", USER_ID),
        }),
        denied: yield* authorizer.check({
          action: "profile:read",
          resource: Entity.ref("User", "someone-else"),
        }),
      };
    });

    const result = await Effect.runPromise(
      program.pipe(
        Effect.provide(
          Layer.mergeAll(authorizerLayer, SessionContext.authenticatedLayer(resolved)),
        ),
      ),
    );

    expect(result.allowed).toBe(true);
    expect(result.denied).toBe(false);
  });

  it("provides CurrentCredential, defaulting to interactive", async () => {
    const credential = await Effect.runPromise(
      CurrentCredential.pipe(Effect.provide(SessionContext.authenticatedLayer(resolved))),
    );
    expect(credential).toBe("interactive");
  });

  it("a machine caller's credential class is carried, not assumed", async () => {
    // The middleware derives this from the Authorization header; an app edge
    // that provides the context by hand has to be able to say the same thing,
    // or an API key silently reads as an interactive session.
    const credential = await Effect.runPromise(
      CurrentCredential.pipe(
        Effect.provide(SessionContext.authenticatedLayer(resolved, { credentialClass: "machine" })),
      ),
    );
    expect(credential).toBe("machine");
  });

  it("the read-path effect sees the resolved user", async () => {
    const allowed = await Effect.runPromise(
      canViewDeleted.pipe(Effect.provide(SessionContext.authenticatedLayer(resolved))),
    );
    expect(allowed).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// The anonymous case is a value, not the absence of a service
// ---------------------------------------------------------------------------

describe("SessionContext.anonymousLayer", () => {
  it("the same read-path effect answers false instead of failing", async () => {
    const exit = await Effect.runPromiseExit(
      canViewDeleted.pipe(Effect.provide(SessionContext.anonymousLayer)),
    );
    expect(exit).toStrictEqual(Exit.succeed(false));
  });

  it("currentUserOption is None and isAuthenticated is false", async () => {
    const program = Effect.all([SessionContext.currentUserOption, SessionContext.isAuthenticated]);
    const [user, authenticated] = await Effect.runPromise(
      program.pipe(Effect.provide(SessionContext.anonymousLayer)),
    );
    expect(user).toStrictEqual(Option.none());
    expect(authenticated).toBe(false);
  });

  it("requireCurrentUser turns the anonymous branch into NotAuthenticatedError", async () => {
    const exit = await Effect.runPromiseExit(
      requireCurrentUser.pipe(Effect.provide(SessionContext.anonymousLayer)),
    );
    expect(Exit.isFailure(exit)).toBe(true);
    const error = await Effect.runPromise(
      requireCurrentUser.pipe(Effect.provide(SessionContext.anonymousLayer), Effect.flip),
    );
    expect(error._tag).toBe("NotAuthenticatedError");
    expect(error.code).toBe("NOT_AUTHENTICATED");
  });

  it("requireCurrentSession likewise", async () => {
    const error = await Effect.runPromise(
      SessionContext.requireCurrentSession.pipe(
        Effect.provide(SessionContext.anonymousLayer),
        Effect.flip,
      ),
    );
    expect(error._tag).toBe("NotAuthenticatedError");
  });
});

// ---------------------------------------------------------------------------
// The "whatever my edge produced" constructor
// ---------------------------------------------------------------------------

describe("SessionContext.layer", () => {
  it.each([
    ["a resolved session", resolved as Parameters<typeof SessionContext.layer>[0], true],
    ["an Option.some", Option.some(resolved), true],
    ["an Option.none", Option.none<Types.SessionWithUser>(), false],
    ["null", null, false],
    ["undefined", undefined, false],
  ])("normalizes %s", async (_label, input, expected) => {
    const authenticated = await Effect.runPromise(
      SessionContext.isAuthenticated.pipe(Effect.provide(SessionContext.layer(input))),
    );
    expect(authenticated).toBe(expected);
  });

  it("toOption is the same normalization, exposed", () => {
    expect(SessionContext.toOption(resolved)).toStrictEqual(Option.some(resolved));
    expect(SessionContext.toOption(null)).toStrictEqual(Option.none());
    expect(SessionContext.toOption(Option.none())).toStrictEqual(Option.none());
  });
});

// ---------------------------------------------------------------------------
// A user with no session record
// ---------------------------------------------------------------------------

describe("SessionContext.userLayer", () => {
  it("provides CurrentUser and CurrentPrincipal without inventing a session", async () => {
    const program = Effect.gen(function* () {
      const user = yield* CurrentUser;
      const principal = yield* CurrentPrincipal;
      return { user, principal };
    });

    const result = await Effect.runPromise(
      program.pipe(Effect.provide(SessionContext.userLayer(testUser))),
    );

    expect(result.user.id).toBe(USER_ID);
    expect(result.principal).toStrictEqual(Entity.ref("User", USER_ID));
  });
});

describe("SessionContext.userSessionLayer", () => {
  it("is authenticatedLayer from the two halves an edge carries apart", async () => {
    const result = await Effect.runPromise(
      MaybeCurrentSession.pipe(
        Effect.provide(SessionContext.userSessionLayer(testSession, testUser)),
      ),
    );
    expect(result).toStrictEqual(Option.some(resolved));
  });
});
