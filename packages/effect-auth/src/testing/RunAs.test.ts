import { describe, expect, expectTypeOf, it } from "vite-plus/test";
import { Context, Effect, Exit, Option } from "effect";
import { TestClock } from "effect/testing";
import * as Authorizer from "../Authorizer.ts";
import * as Condition from "../Condition.ts";
import * as Entity from "../Entity.ts";
import * as Guard from "../Guard.ts";
import * as Ladder from "../Ladder.ts";
import * as Policy from "../Policy.ts";
import * as SessionContext from "../SessionContext.ts";
import type * as Types from "../Types.ts";
import * as Testing from "./index.ts";

const createdAt = new Date("2026-01-01T00:00:00.000Z");
const ada: Types.User = { id: "u-ada", createdAt, updatedAt: createdAt, attributes: {} };

const whoAmI = Effect.all(
  {
    principal: Effect.service(Authorizer.CurrentPrincipal),
    credential: Effect.service(Authorizer.CurrentCredential),
    user: Effect.service(SessionContext.CurrentUser),
    session: Effect.service(SessionContext.CurrentSession),
    maybe: Effect.service(SessionContext.MaybeCurrentSession),
  },
  { concurrency: 1 },
);

describe("runAs", () => {
  it("runs an effect as a signed-in fixture user with the middleware's full context", async () => {
    const seen = await Effect.runPromise(whoAmI.pipe(Testing.runAs(ada)));

    expect(seen.principal).toEqual(Entity.ref("User", "u-ada"));
    expect(seen.credential).toBe("interactive");
    expect(seen.user).toBe(ada);
    expect(seen.session.userId).toBe("u-ada");
    expect(seen.session.expiresAt.getTime()).toBeGreaterThan(seen.session.createdAt.getTime());
    expect(seen.maybe).toEqual(Option.some({ session: seen.session, user: ada }));
  });

  it("runs an effect anonymously for null", async () => {
    const seen = await Effect.runPromise(
      Effect.gen(function* () {
        return {
          authenticated: yield* SessionContext.isAuthenticated,
          user: yield* Effect.exit(SessionContext.requireCurrentUser),
        };
      }).pipe(Testing.runAs(null)),
    );

    expect(seen.authenticated).toBe(false);
    expect(Exit.isFailure(seen.user)).toBe(true);
  });

  it("does not provide a principal to an anonymous run", () => {
    const needsPrincipal = Effect.service(Authorizer.CurrentPrincipal).pipe(Testing.runAs(null));
    expectTypeOf(needsPrincipal).toEqualTypeOf<
      Effect.Effect<Entity.EntityRef, never, Authorizer.CurrentPrincipal>
    >();
    expect(Effect.runSync(Effect.succeed(1).pipe(Testing.runAs(undefined)))).toBe(1);
  });

  it("takes the credential class and session overrides", async () => {
    const seen = await Effect.runPromise(
      whoAmI.pipe(
        Testing.runAs(ada, {
          credentialClass: "machine",
          session: { id: "s-1", attributes: { device: "ci" } },
        }),
      ),
    );

    expect(seen.credential).toBe("machine");
    expect(seen.session.id).toBe("s-1");
    expect(seen.session.attributes).toEqual({ device: "ci" });
    expect(seen.session.userId).toBe("u-ada");
  });

  it("mints the session from the Clock", async () => {
    const at = Date.parse("2030-06-01T00:00:00.000Z");
    const session = await Effect.runPromise(
      Effect.gen(function* () {
        yield* TestClock.setTime(at);
        return yield* Effect.service(SessionContext.CurrentSession).pipe(Testing.runAs(ada));
      }).pipe(Effect.provide(TestClock.layer())),
    );

    expect(session.createdAt.getTime()).toBe(at);
    expect(session.lastActivityAt.getTime()).toBe(at);
    expect(session.expiresAt.getTime()).toBe(at + 24 * 60 * 60 * 1000);
  });

  it("drives the policy kernel as the fixture principal", async () => {
    const mintKey = Entity.ref("Action", "mintApiKey");
    const interactiveOnly = Policy.permit({
      id: "mint-key-requires-interactive-session",
      action: Policy.eq(mintKey),
      when: Condition.eq(
        Condition.attr("context", "credentialClass"),
        Condition.lit("interactive"),
      ),
    });
    const mayMint = Authorizer.Authorizer.pipe(
      Effect.flatMap((authorizer) =>
        authorizer.check({ action: mintKey, resource: Entity.ref("ApiKey", "any") }),
      ),
      Effect.provide(Authorizer.Authorizer.layer({ policies: [interactiveOnly] })),
    );

    expect(await Effect.runPromise(mayMint.pipe(Testing.runAs(ada)))).toBe(true);
    expect(
      await Effect.runPromise(mayMint.pipe(Testing.runAs(ada, { credentialClass: "machine" }))),
    ).toBe(false);
  });
});

interface AppUser {
  readonly id: string;
  readonly role: string;
}

class CurrentViewer extends Context.Service<CurrentViewer, Option.Option<AppUser>>()(
  "@test/CurrentViewer",
) {}

const Roles = Ladder.make(["user", "moderator", "admin"]);
const guards = Guard.make({ ladder: Roles, viewer: CurrentViewer });
const requireModerator = guards.requireRoleAtLeast("moderator");

const moderator: AppUser = { id: "u-mod", role: "moderator" };
const member: AppUser = { id: "u-member", role: "user" };

describe("runAsViewer", () => {
  it("runs a guard as the app's viewer, signed in or anonymous", async () => {
    const asModerator = await Effect.runPromiseExit(
      requireModerator.pipe(Testing.runAsViewer(CurrentViewer, moderator)),
    );
    const asMember = await Effect.runPromiseExit(
      requireModerator.pipe(Testing.runAsViewer(CurrentViewer, member)),
    );
    const asNobody = await Effect.runPromiseExit(
      requireModerator.pipe(Testing.runAsViewer(CurrentViewer, null)),
    );

    expect(asModerator).toEqual(Exit.succeed(moderator));
    expect(Exit.isFailure(asMember)).toBe(true);
    expect(Exit.isFailure(asNobody)).toBe(true);
  });

  it("gives the viewer, the session context and the principal one identity", async () => {
    const seen = await Effect.runPromise(
      Effect.gen(function* () {
        const viewer = yield* CurrentViewer;
        const principal = yield* Authorizer.CurrentPrincipal;
        const resolved = yield* SessionContext.MaybeCurrentSession;
        return { viewer, principal, resolved };
      }).pipe(Testing.runAsViewer(CurrentViewer, moderator)),
    );

    expect(seen.viewer).toEqual(Option.some(moderator));
    expect(seen.principal).toEqual(Entity.ref("User", "u-mod"));
    // The default projection keeps the viewer's other fields as attributes,
    // so the library's own role projection agrees with the app's viewer.
    expect(Option.flatMap(seen.resolved, SessionContext.withRole())).toEqual(
      Option.some(expect.objectContaining({ id: "u-mod", role: "moderator" })),
    );
  });

  it("runs anonymously with the viewer and the session context both empty", async () => {
    const seen = await Effect.runPromise(
      Effect.gen(function* () {
        return {
          viewer: yield* CurrentViewer,
          authenticated: yield* SessionContext.isAuthenticated,
        };
      }).pipe(Testing.runAsViewer(CurrentViewer, null)),
    );

    expect(seen).toEqual({ viewer: Option.none(), authenticated: false });
  });

  it("projects the viewer through toUser when given", async () => {
    const user = await Effect.runPromise(
      Effect.service(SessionContext.CurrentUser).pipe(
        Testing.runAsViewer(CurrentViewer, moderator, {
          toUser: (viewer, now) => ({
            id: `app-${viewer.id}`,
            name: viewer.role,
            createdAt: now,
            updatedAt: now,
            attributes: {},
          }),
        }),
      ),
    );

    expect(user.id).toBe("app-u-mod");
    expect(user.name).toBe("moderator");
  });
});
