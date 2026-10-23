/**
 * The zero-IO guards (#189), ported from the applications' guard suite
 * (gardeneria `packages/database/tests/guards.test.ts`, website's equivalent):
 * `requireRoleAtLeast` and the named gates built on it, `requireUser`,
 * `requireOwnerOrRole`, the read-path predicates, and the capability hooks
 * (gardeneria `apps/api/src/document.ts`'s `roleCapabilities` /
 * `ownedCapabilities`).
 *
 * Every rung is driven through every gate. The library-side additions: the
 * gates run with no `EntityResolver` (or `Authorizer`) in context, and a gate,
 * its predicate, and an `Authorizer` handed the kit's own policies agree on
 * every viewer.
 */
import { describe, expect, it } from "vite-plus/test";
import {
  Array as Arr,
  Context,
  DateTime,
  Effect,
  Exit,
  Layer,
  Logger,
  Option,
  Schema,
} from "effect";
import * as Authorizer from "./Authorizer.ts";
import * as Entity from "./Entity.ts";
import * as Guard from "./Guard.ts";
import * as Ladder from "./Ladder.ts";
import * as Policy from "./Policy.ts";
import * as System from "./System.ts";
import * as SessionContext from "./SessionContext.ts";
import type * as Types from "./Types.ts";

interface AppUser {
  readonly id: string;
  readonly role: string;
  readonly email: string;
}

class CurrentViewer extends Context.Service<CurrentViewer, Option.Option<AppUser>>()(
  "@test/CurrentViewer",
) {}

const Roles = Ladder.make(["user", "contributor", "moderator", "admin"]);
const Axes = Roles.axes({
  corpusWrite: "contributor",
  moderate: "moderator",
  viewPrivate: "moderator",
  viewDeleted: "moderator",
});
const guards = Guard.make({ ladder: Roles, viewer: CurrentViewer });

// The applications' named gates, bound once.
const requireContributor = guards.requireRoleAtLeast(Axes.corpusWrite);
const requireModerator = guards.requireRoleAtLeast(Axes.moderate);
const requireAdmin = guards.requireRoleAtLeast("admin");

const user = (role: string, id = `u-${role}`): AppUser => ({ id, role, email: `${id}@b.test` });
const admin = user("admin");
const moderator = user("moderator");
const contributor = user("contributor");
const member = user("user", "u-member");
const otherMember = user("user", "u-other");

const as = (viewer: AppUser | null) => SessionContext.viewerLayer(CurrentViewer, viewer);

const run = <A>(effect: Effect.Effect<A, never, CurrentViewer>, viewer: AppUser | null): A =>
  Effect.runSync(effect.pipe(Effect.provide(as(viewer))));

const runGate = <A, E>(gate: Effect.Effect<A, E, CurrentViewer>, viewer: AppUser | null) =>
  Effect.runSyncExit(gate.pipe(Effect.provide(as(viewer))));

/** A failure's `_tag`; a failure without one fails the test. */
const decodeTagged = Schema.decodeUnknownSync(Schema.Struct({ _tag: Schema.String }));

const tagOf = (exit: Exit.Exit<unknown, unknown>): string | undefined =>
  Exit.isFailure(exit)
    ? Option.getOrUndefined(
        Option.map(Exit.findErrorOption(exit), (error) => decodeTagged(error)._tag),
      )
    : undefined;

describe("requireRoleAtLeast", () => {
  it("admits every rung at or above the minimum and refuses the rest", () => {
    Arr.forEach(Roles.rungs, (min, minIndex) => {
      Arr.forEach(Roles.rungs, (held, heldIndex) => {
        const exit = runGate(guards.requireRoleAtLeast(min), user(held));
        // At or above the minimum succeeds; below it fails with `Forbidden`.
        const admitted = heldIndex >= minIndex;
        expect(
          admitted ? Exit.isSuccess(exit) : tagOf(exit),
          admitted ? `${held} ≥ ${min}` : `${held} < ${min}`,
        ).toBe(admitted ? true : "Forbidden");
      });
    });
  });

  it("yields the viewer itself — the application's own type — on success", () => {
    const exit = runGate(guards.requireRoleAtLeast("contributor"), moderator);
    expect(Exit.isSuccess(exit) && exit.value).toBe(moderator);
  });

  it("fails Unauthorized (not Forbidden) for an anonymous request, at every rung", () => {
    Arr.forEach(Roles.rungs, (min) => {
      expect(tagOf(runGate(guards.requireRoleAtLeast(min), null))).toBe("Unauthorized");
    });
  });

  it("refuses a role string that is not on the ladder even at the lowest rung", () => {
    expect(tagOf(runGate(guards.requireRoleAtLeast("user"), user("not-a-rung")))).toBe("Forbidden");
  });
});

describe("the named gates", () => {
  const cases = [
    ["requireContributor", requireContributor, ["contributor", "moderator", "admin"]],
    ["requireModerator", requireModerator, ["moderator", "admin"]],
    ["requireAdmin", requireAdmin, ["admin"]],
  ] as const;

  Arr.forEach(cases, ([name, gate, admitted]) => {
    it(`${name} admits exactly ${admitted.join(" / ")}`, () => {
      Arr.forEach(Roles.rungs, (held) => {
        expect(Exit.isSuccess(runGate(gate, user(held))), `${name} for ${held}`).toBe(
          admitted.some((rung) => rung === held),
        );
      });
      expect(tagOf(runGate(gate, null))).toBe("Unauthorized");
      expect(tagOf(runGate(gate, user("superadmin")))).toBe("Forbidden");
    });
  });
});

describe("requireUser", () => {
  it("returns the viewer for every rung — no ladder comparison", () => {
    Arr.forEach(Roles.rungs, (role) => {
      const viewer = user(role);
      const exit = runGate(guards.requireUser, viewer);
      expect(Exit.isSuccess(exit) && exit.value).toBe(viewer);
    });
  });

  it("admits a signed-in viewer whose role is off the ladder: signed in is not a rung", () => {
    expect(Exit.isSuccess(runGate(guards.requireUser, user("")))).toBe(true);
  });

  it("fails Unauthorized when no viewer is on the request", () => {
    expect(tagOf(runGate(guards.requireUser, null))).toBe("Unauthorized");
  });
});

describe("requireOwnerOrRole (the owned-material write gate)", () => {
  const gate = guards.requireOwnerOrRole(member.id, Axes.moderate);

  it("admits the owner whatever their rung", () => {
    const exit = runGate(gate, member);
    expect(Exit.isSuccess(exit) && exit.value).toBe(member);
    // …even an owner whose role has fallen off the ladder.
    expect(Exit.isSuccess(runGate(gate, { ...member, role: "retired-rung" }))).toBe(true);
  });

  it("admits the named rung and above acting on someone else's row", () => {
    expect(Exit.isSuccess(runGate(gate, moderator))).toBe(true);
    expect(Exit.isSuccess(runGate(gate, admin))).toBe(true);
  });

  it("refuses another member below the rung — Forbidden, not NotFound", () => {
    expect(tagOf(runGate(gate, otherMember))).toBe("Forbidden");
    expect(tagOf(runGate(gate, contributor))).toBe("Forbidden");
  });

  it("fails Unauthorized for an anonymous request", () => {
    expect(tagOf(runGate(gate, null))).toBe("Unauthorized");
  });
});

describe("the read-path predicates", () => {
  it("hasRoleAtLeast answers each axis, and false for anonymous (never fails)", () => {
    // canViewDeletedE / canViewPrivateE in the applications: moderator and above.
    Arr.forEach([Axes.viewDeleted, Axes.viewPrivate], (axis) => {
      expect(run(guards.hasRoleAtLeast(axis), admin)).toBe(true);
      expect(run(guards.hasRoleAtLeast(axis), moderator)).toBe(true);
      expect(run(guards.hasRoleAtLeast(axis), contributor)).toBe(false);
      expect(run(guards.hasRoleAtLeast(axis), member)).toBe(false);
      expect(run(guards.hasRoleAtLeast(axis), null)).toBe(false);
    });
  });

  it("isAdminViewer asks for the admin rung literally — no lower rung satisfies it", () => {
    const isAdminViewer = guards.hasRoleAtLeast("admin");
    expect(run(isAdminViewer, admin)).toBe(true);
    Arr.forEach([moderator, contributor, member, null], (viewer) => {
      expect(run(isAdminViewer, viewer)).toBe(false);
    });
  });

  it("isOwnerOrRole mirrors requireOwnerOrRole without failing", () => {
    const predicate = guards.isOwnerOrRole(member.id, Axes.moderate);
    expect(run(predicate, member)).toBe(true);
    expect(run(predicate, moderator)).toBe(true);
    expect(run(predicate, otherMember)).toBe(false);
    expect(run(predicate, null)).toBe(false);
  });

  it("isSignedIn and viewer read the viewer, anonymous as a value", () => {
    expect(run(guards.isSignedIn, member)).toBe(true);
    expect(run(guards.isSignedIn, null)).toBe(false);
    expect(run(guards.viewer, member)).toEqual(Option.some(member));
    expect(run(guards.viewer, null)).toEqual(Option.none());
  });
});

describe("guards and the policy kernel", () => {
  const viewers = [admin, moderator, contributor, member, user("superadmin"), null];

  it("run with no EntityResolver, Authorizer or PolicyStore in context", () => {
    // The gate's only requirement is the viewer service: the type says so,
    // and running it with nothing else provided proves it.
    const exit = Effect.runSyncExit(
      Effect.provide(requireContributor, SessionContext.viewerLayer(CurrentViewer, contributor)),
    );
    expect(Exit.isSuccess(exit)).toBe(true);
  });

  it("each gate and its predicate agree on every viewer and every axis", () => {
    Arr.forEach(Object.values(Axes), (axis) => {
      Arr.forEach(viewers, (viewer) => {
        const gateAdmits = Exit.isSuccess(runGate(guards.requireRoleAtLeast(axis), viewer));
        expect(run(guards.hasRoleAtLeast(axis), viewer)).toBe(gateAdmits);
        expect(guards.decideRole(viewer, axis)).toBe(gateAdmits);
      });
      Arr.forEach(viewers, (viewer) => {
        const gateAdmits = Exit.isSuccess(
          runGate(guards.requireOwnerOrRole(member.id, axis), viewer),
        );
        expect(run(guards.isOwnerOrRole(member.id, axis), viewer)).toBe(gateAdmits);
      });
    });
  });

  it("an Authorizer handed the kit's own policies decides exactly as the gates do", () => {
    const decideWithAuthorizer = (
      viewer: AppUser,
      policies: ReadonlyArray<Policy.DeclarativePolicy>,
      resource: Entity.Entity,
    ) =>
      Effect.runSync(
        Effect.gen(function* () {
          const authorizer = yield* Authorizer.Authorizer;
          return yield* authorizer.check({ action: "write", resource: resource.ref });
        }).pipe(
          Authorizer.CurrentPrincipal.provide(Entity.ref("User", viewer.id)),
          Effect.provide(Authorizer.Authorizer.layer({ policies })),
          Effect.provideService(
            Authorizer.EntityResolver,
            Authorizer.memoryEntityResolver([
              Entity.entity(Entity.ref("User", viewer.id), { attributes: { role: viewer.role } }),
              resource,
            ]),
          ),
        ),
      );

    const doc = Entity.entity(Entity.ref("Owned", "doc-1"), {
      attributes: { owner: Entity.entityValue(Entity.ref("User", member.id)) },
    });
    Arr.forEach(Object.values(Axes), (axis) => {
      Arr.forEach(viewers, (viewer) => {
        if (viewer === null) return;
        expect(decideWithAuthorizer(viewer, guards.policies.roleAtLeast(axis), doc)).toBe(
          guards.decideRole(viewer, axis),
        );
        expect(decideWithAuthorizer(viewer, guards.policies.ownerOrRole(axis), doc)).toBe(
          guards.decideOwnerOrRole(viewer, member.id, axis),
        );
      });
    });
  });
});

describe("the capability hooks", () => {
  it("roleCapabilities advertises exactly what the rung gate admits", () => {
    const hook = guards.roleCapabilities(Axes.corpusWrite);
    expect(hook(contributor)).toEqual({ canEdit: true, canDelete: true });
    expect(hook(member)).toEqual({ canEdit: false, canDelete: false });
    expect(hook(null)).toEqual({ canEdit: false, canDelete: false });
    expect(hook(undefined)).toEqual({ canEdit: false, canDelete: false });
  });

  it("roleCapabilities follows its axis: a family gated above corpus-write says so", () => {
    // gardeneria #1123 — `pages` gates on moderate; inheriting the corpus-write
    // default advertised canEdit to a contributor the operation refused.
    expect(guards.roleCapabilities(Axes.moderate)(contributor).canEdit).toBe(false);
    expect(Exit.isFailure(runGate(requireModerator, contributor))).toBe(true);
  });

  it("ownedCapabilities is requireOwnerOrRole restated as meta", () => {
    const hook = guards.ownedCapabilities(
      Axes.moderate,
      (resource: { readonly owner?: string }) => resource.owner,
    );
    const mine = { owner: member.id };
    expect(hook(mine, member)).toEqual({ canEdit: true, canDelete: true });
    expect(hook(mine, moderator)).toEqual({ canEdit: true, canDelete: true });
    expect(hook(mine, otherMember)).toEqual({ canEdit: false, canDelete: false });
    expect(hook(mine, null)).toEqual({ canEdit: false, canDelete: false });
    // No owner on the representation: nothing for a stranger, still the rung.
    expect(hook({}, otherMember)).toEqual({ canEdit: false, canDelete: false });
    expect(hook({}, moderator)).toEqual({ canEdit: true, canDelete: true });
  });
});

describe("the viewer seam (SessionContext)", () => {
  const libraryUser = (attributes: Types.User["attributes"]): Types.SessionWithUser => ({
    session: {
      id: "s1",
      userId: "u1",
      expiresAt: DateTime.toDateUtc(DateTime.makeUnsafe(0)),
      createdAt: DateTime.toDateUtc(DateTime.makeUnsafe(0)),
      lastActivityAt: DateTime.toDateUtc(DateTime.makeUnsafe(0)),
      attributes: {},
    },
    user: {
      id: "u1",
      createdAt: DateTime.toDateUtc(DateTime.makeUnsafe(0)),
      updatedAt: DateTime.toDateUtc(DateTime.makeUnsafe(0)),
      attributes,
    },
  });

  class LibraryViewer extends Context.Service<
    LibraryViewer,
    Option.Option<SessionContext.UserWithRole>
  >()("@test/LibraryViewer") {}
  const libraryGuards = Guard.make({ ladder: Roles, viewer: LibraryViewer });

  const fromSession = (resolved: Types.SessionWithUser | null) =>
    SessionContext.viewerFromSession(LibraryViewer, SessionContext.withRole()).pipe(
      Layer.provide(SessionContext.layer(resolved)),
    );

  it("lifts the rung out of the library user's attributes", () => {
    const exit = Effect.runSyncExit(
      libraryGuards
        .requireRoleAtLeast(Axes.moderate)
        .pipe(Effect.provide(fromSession(libraryUser({ role: "moderator" })))),
    );
    expect(Exit.isSuccess(exit) && exit.value.role).toBe("moderator");
  });

  it("a user with no role attribute is signed in but holds no rung", () => {
    const layer = fromSession(libraryUser({}));
    expect(
      Exit.isSuccess(Effect.runSyncExit(Effect.provide(libraryGuards.requireUser, layer))),
    ).toBe(true);
    expect(
      tagOf(Effect.runSyncExit(Effect.provide(libraryGuards.requireRoleAtLeast("user"), layer))),
    ).toBe("Forbidden");
  });

  it("an anonymous session is an anonymous viewer", () => {
    expect(
      tagOf(Effect.runSyncExit(Effect.provide(libraryGuards.requireUser, fromSession(null)))),
    ).toBe("Unauthorized");
  });

  it("viewerLayer accepts the app's user, an Option of one, or null", () => {
    Arr.forEach([member, Option.some(member)], (given) => {
      const layer = SessionContext.viewerLayer(CurrentViewer, given);
      expect(Effect.runSync(Effect.provide(guards.viewer, layer))).toEqual(Option.some(member));
    });
    Arr.forEach([null, undefined, Option.none<AppUser>()], (given) => {
      const layer = SessionContext.viewerLayer(CurrentViewer, given);
      expect(Effect.runSync(Effect.provide(guards.viewer, layer))).toEqual(Option.none());
    });
  });
});

describe("the errors", () => {
  it("are the HTTP tier's own classes, so a guard failure encodes at the edge untranslated", async () => {
    const Http = await import("./http/HttpApiSchema.ts");
    expect(Http.Unauthorized).toBe(Guard.Unauthorized);
    expect(Http.Forbidden).toBe(Guard.Forbidden);
  });
});

describe("requireSystem (#362)", () => {
  const page = Entity.ref("Page", "p-1");
  const policies = [
    System.grant("translation-pipeline", {
      id: "translation-pipeline:write-pages",
      action: "page:write",
      resource: Policy.isType("Page"),
    }),
    // An unscoped permit never reaches a system principal.
    Policy.permit({ id: "everyone:read", action: Policy.eq(Entity.ref("Action", "page:read")) }),
  ];
  const authorizer = Authorizer.Authorizer.layer({ policies });
  const gate = (action: string) => Guard.requireSystem({ action, resource: page });

  const run = <A, E>(effect: Effect.Effect<A, E, Authorizer.Authorizer>) =>
    Effect.runPromiseExit(effect.pipe(Effect.provide(authorizer)));

  it("admits a granted system principal and yields its ref", async () => {
    const exit = await run(gate("page:write").pipe(System.provide("translation-pipeline")));
    expect(exit).toEqual(Exit.succeed(System.ref("translation-pipeline")));
  });

  it("refuses a system principal no policy grants the action with Forbidden", async () => {
    expect(tagOf(await run(gate("page:write").pipe(System.provide("billing-cron"))))).toBe(
      "Forbidden",
    );
    expect(tagOf(await run(gate("page:read").pipe(System.provide("translation-pipeline"))))).toBe(
      "Forbidden",
    );
  });

  it("refuses a missing principal, and a user principal, with Unauthorized", async () => {
    expect(tagOf(await run(gate("page:write")))).toBe("Unauthorized");
    expect(
      tagOf(
        await run(
          gate("page:read").pipe(Authorizer.CurrentPrincipal.provide(Entity.ref("User", "u-1"))),
        ),
      ),
    ).toBe("Unauthorized");
  });

  it("logs the decision with the system principal's name", async () => {
    const records: Array<string> = [];
    const encodeJson = Schema.encodeUnknownSync(Schema.fromJsonString(Schema.Unknown));
    const collector = Logger.make((options) => void records.push(encodeJson(options.message)));
    await Effect.runPromise(
      gate("page:write").pipe(
        System.provide("translation-pipeline"),
        Effect.provide(Layer.merge(authorizer, Logger.layer([collector]))),
      ),
    );
    expect(records.some((record) => record.includes("authorization.decision"))).toBe(true);
    expect(records.some((record) => record.includes("translation-pipeline"))).toBe(true);
  });
});
