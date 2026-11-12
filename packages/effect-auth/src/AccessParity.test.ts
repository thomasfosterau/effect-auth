/**
 * The parity matrices of #637: `OwnedAccess` and `ReferenceAccess` against
 * the read rules a content kernel (pulpit) enforces today, written down here
 * from the issue's rules, not from the implementation.
 *
 * - **Owned rows**: visibility × draft × unapproved × owner × group × viewer
 *   × follower seam × member seam.
 * - **Reference rows**: visibility (absent included) × followers-of × group
 *   × viewer × both seams.
 * - **Read scope**: both `readScope`s, for every viewer and seam presence.
 * - **Serveability**: `Cacheability.publiclyServeable(OwnedAccess.serveableAxes)`.
 * - **Policies**: `ReadScope.compile` over each `policies` and `binding`
 *   admits exactly the rows `canView` does, on the same matrices.
 *
 * Every seam is a spy: a call with a subject that is not a string, or for a
 * row or viewer the rules say must not ask, is collected and fails the test.
 */
import { describe, expect, it } from "vite-plus/test";
import { Context, Effect, Exit, Layer } from "effect";
import * as Arr from "effect/Array";
import * as Option from "effect/Option";
import * as P from "effect/Predicate";
import * as R from "effect/Record";
import * as Cacheability from "./Cacheability.ts";
import * as Entity from "./Entity.ts";
import * as Guard from "./Guard.ts";
import * as Ladder from "./Ladder.ts";
import * as OwnedAccess from "./OwnedAccess.ts";
import * as Policy from "./Policy.ts";
import * as ReadScope from "./ReadScope.ts";
import * as ReferenceAccess from "./ReferenceAccess.ts";
import * as SessionContext from "./SessionContext.ts";

interface AppUser {
  readonly id: string;
  readonly role: string;
}
class CurrentViewer extends Context.Service<CurrentViewer, Option.Option<AppUser>>()(
  "@test/AccessParity/CurrentViewer",
) {}

const Roles = Ladder.make(["user", "contributor", "moderator", "admin"]);
/** The four role axes a content application asks (see the `OwnedAccess` module docs). */
const Axes = Roles.axes({
  viewPrivate: "moderator",
  viewDeleted: "moderator",
  moderate: "moderator",
  writeCorpus: "contributor",
});
const guards = Guard.make({ ladder: Roles, viewer: CurrentViewer });
const owned = OwnedAccess.make({ guards, viewPrivate: Axes.viewPrivate });
const reference = ReferenceAccess.make({ guards, viewPrivate: Axes.viewPrivate });

const OWNER = "u-owner";
const GROUP = "g-club";
/** An account the follower follows, for reference rows. */
const FOLLOWED = "u-followed";

const VIEWERS: ReadonlyArray<readonly [string, AppUser | null]> = [
  ["anonymous", null],
  ["owner", { id: OWNER, role: "user" }],
  ["stranger", { id: "u-stranger", role: "user" }],
  ["follower", { id: "u-follower", role: "user" }],
  ["group member", { id: "u-member", role: "user" }],
  ["contributor", { id: "u-contributor", role: "contributor" }],
  ["moderator", { id: "u-moderator", role: "moderator" }],
  ["off-ladder", { id: "u-odd", role: "superadmin" }],
];

/** The relation graph the `graph` seams answer from. */
const graphFollows = (followerId: string, ownerId: string): boolean =>
  followerId === "u-follower" && (ownerId === OWNER || ownerId === FOLLOWED);
const graphMember = (accountId: string, groupId: string): boolean =>
  accountId === "u-member" && groupId === GROUP;

/** How a seam answers: not provided, always false, always true, or from the graph. */
type SeamMode = "absent" | "never" | "always" | "graph";
const SEAM_MODES: ReadonlyArray<SeamMode> = ["absent", "never", "always", "graph"];
const answer = (mode: SeamMode, graph: boolean): boolean =>
  mode === "always" || (mode === "graph" && graph);

/** The view-private rung, written from the ladder: moderator and above. */
const atViewPrivate = (viewer: AppUser): boolean =>
  viewer.role === "moderator" || viewer.role === "admin";

const label = (parts: Readonly<Record<string, string | boolean | null | undefined>>): string =>
  Arr.map(R.toEntries(parts), ([key, value]) => `${key}=${String(value)}`).join(" ");

// ---------------------------------------------------------------------------
// Spy seams
// ---------------------------------------------------------------------------

interface SeamCall {
  readonly seam: "follower" | "member";
  readonly account: unknown;
  readonly subject: unknown;
}

const spySeams = (
  follower: SeamMode,
  member: SeamMode,
  calls: Array<SeamCall>,
): ReadonlyArray<Layer.Layer<OwnedAccess.IsFollower> | Layer.Layer<OwnedAccess.IsMember>> => [
  ...(follower === "absent"
    ? []
    : [
        Layer.succeed(OwnedAccess.IsFollower, {
          isFollower: (account: string, subject: string) => {
            calls.push({ seam: "follower", account, subject });
            return Effect.succeed(
              answer(follower, P.isString(subject) && graphFollows(account, subject)),
            );
          },
          following: (account: string) => OwnedAccess.subquery(`following(${account})`),
        }),
      ]),
  ...(member === "absent"
    ? []
    : [
        Layer.succeed(OwnedAccess.IsMember, {
          isMember: (account: string, subject: string) => {
            calls.push({ seam: "member", account, subject });
            return Effect.succeed(
              answer(member, P.isString(subject) && graphMember(account, subject)),
            );
          },
          groupsOf: (account: string) => OwnedAccess.subquery(`groups(${account})`),
        }),
      ]),
];

const runAs = <A>(
  effect: Effect.Effect<A, never, CurrentViewer>,
  viewer: AppUser | null,
  follower: SeamMode,
  member: SeamMode,
  calls: Array<SeamCall> = [],
): A =>
  Effect.runSync(
    Effect.provide(
      effect,
      Layer.mergeAll(
        SessionContext.viewerLayer(CurrentViewer, viewer),
        ...spySeams(follower, member, calls),
      ),
    ),
  );

/** A seam call the rules forbid, described; `[]` when every call was allowed. */
const forbiddenCalls = (
  calls: ReadonlyArray<SeamCall>,
  viewer: AppUser | null,
  allowed: { readonly follower: string | undefined; readonly member: string | undefined },
): ReadonlyArray<string> =>
  Arr.flatMap(calls, (call) => {
    const expected = call.seam === "follower" ? allowed.follower : allowed.member;
    const ok =
      viewer !== null &&
      P.isString(call.account) &&
      P.isString(call.subject) &&
      call.account === viewer.id &&
      expected !== undefined &&
      call.subject === expected;
    return ok ? [] : [`${call.seam}(${String(call.account)}, ${String(call.subject)})`];
  });

/** A compiled scope's single-row answer, with each set answered by the seam modes. */
const compiledAdmits = (
  compiled: ReadScope.Compiled,
  columns: ReadScope.Row,
  viewer: AppUser | null,
  follower: SeamMode,
  member: SeamMode,
): boolean | "inexact" => {
  if (P.isTagged(compiled, "Inexact")) return "inexact";
  return ReadScope.matches(
    compiled.scope,
    columns,
    (set, value) =>
      viewer !== null &&
      P.isString(value) &&
      (set === "following"
        ? answer(follower, graphFollows(viewer.id, value))
        : set === "groups" && answer(member, graphMember(viewer.id, value))),
  );
};

const compileFor = (
  policies: ReadonlyArray<Policy.DeclarativePolicy>,
  binding: ReadScope.Binding,
  viewer: AppUser | null,
  context: Readonly<Record<string, Entity.AttributeValue>> = {},
): ReadScope.Compiled => {
  const principal =
    viewer === null
      ? Entity.entity(Entity.ref("Anonymous", "anonymous"))
      : guards.principal(viewer);
  return ReadScope.compile(policies, binding, {
    principal: principal.ref,
    action: Entity.ref("Action", "read"),
    context,
    slice: Entity.slice([principal]),
  });
};

/** Whether a set from a read scope contains `value`, answered by the seam mode. */
const inScopeSet = (set: OwnedAccess.FollowingSet, mode: SeamMode, graph: boolean): boolean =>
  P.isTagged(set, "Subquery") && answer(mode, graph);

// ---------------------------------------------------------------------------
// Owned rows
// ---------------------------------------------------------------------------

const VISIBILITIES: ReadonlyArray<OwnedAccess.Visibility> = [
  "public",
  "followers",
  "group",
  "private",
];

const ownedRows: ReadonlyArray<OwnedAccess.OwnedRow> = Arr.flatMap(VISIBILITIES, (visibility) =>
  Arr.flatMap([false, true], (draft) =>
    Arr.flatMap([false, true], (unapproved) =>
      Arr.flatMap([OWNER, undefined], (ownerId) =>
        Arr.map([GROUP, undefined], (groupId) => ({
          ownerId,
          visibility,
          draft,
          unapproved,
          groupId,
        })),
      ),
    ),
  ),
);

/** What a signed-in viewer's relations answer: whom they follow, which groups they are in. */
interface Relations {
  readonly follows: (account: string) => boolean;
  readonly member: (group: string) => boolean;
}

/** The relations the seam modes give `viewerId` (the row predicate's facts). */
const seamRelations = (viewerId: string, follower: SeamMode, member: SeamMode): Relations => ({
  follows: (account) => answer(follower, graphFollows(viewerId, account)),
  member: (group) => answer(member, graphMember(viewerId, group)),
});

/** The relations a `member` read scope's sets give (the list filter's facts). */
const scopeRelations = (
  scope: Extract<OwnedAccess.OwnedReadScope, { readonly kind: "member" }>,
  follower: SeamMode,
  member: SeamMode,
): Relations => ({
  follows: (account) => inScopeSet(scope.following, follower, graphFollows(scope.userId, account)),
  member: (group) => inScopeSet(scope.groups, member, graphMember(scope.userId, group)),
});

/** Published: neither a draft nor unapproved (#637 section 1). */
const isPublished = (row: OwnedAccess.OwnedRow): boolean =>
  row.draft !== true && row.unapproved !== true;

/** The one owned rule anonymous gets: public and published. */
const ownedPublic = (row: OwnedAccess.OwnedRow): boolean =>
  row.visibility === "public" && isPublished(row);

/** An owner arm that never matches a row with no owner (section 2). */
const ownedBy = (row: OwnedAccess.OwnedRow, accountId: string): boolean =>
  row.ownerId !== undefined && row.ownerId === accountId;

/** Who else reads a published owned row, by visibility (section 3: no group reads as private). */
const ownedAudience: Readonly<
  Record<OwnedAccess.Visibility, (row: OwnedAccess.OwnedRow, relations: Relations) => boolean>
> = {
  public: () => true,
  followers: (row, relations) => row.ownerId !== undefined && relations.follows(row.ownerId),
  group: (row, relations) => row.groupId !== undefined && relations.member(row.groupId),
  private: () => false,
};

/** A signed-in viewer's owned read: the rung, the owner, or the published audience. */
const ownedForAccount = (
  row: OwnedAccess.OwnedRow,
  accountId: string,
  relations: Relations,
): boolean =>
  ownedBy(row, accountId) || (isPublished(row) && ownedAudience[row.visibility](row, relations));

/** The owned read rule, from #637's sections 1–3. */
const expectedOwned = (
  row: OwnedAccess.OwnedRow,
  viewer: AppUser | null,
  follower: SeamMode,
  member: SeamMode,
): boolean =>
  viewer === null
    ? ownedPublic(row)
    : atViewPrivate(viewer) ||
      ownedForAccount(row, viewer.id, seamRelations(viewer.id, follower, member));

/** The only seam questions the rules allow for an owned row. */
const ownedAllowedQuestions = (row: OwnedAccess.OwnedRow) => ({
  follower: isPublished(row) && row.visibility === "followers" ? row.ownerId : undefined,
  member: isPublished(row) && row.visibility === "group" ? row.groupId : undefined,
});

const ownedColumns = (row: OwnedAccess.OwnedRow): ReadScope.Row => ({
  owner: row.ownerId ?? null,
  visibility: row.visibility,
  draft: row.draft ?? null,
  unapproved: row.unapproved ?? null,
  group: row.groupId ?? null,
});

/** The documented meaning of an `OwnedReadScope` for owned rows, as a renderer applies it. */
const ownedScopeAdmits = (
  scope: OwnedAccess.OwnedReadScope,
  row: OwnedAccess.OwnedRow,
  follower: SeamMode,
  member: SeamMode,
): boolean =>
  scope.kind === "all" ||
  (scope.kind === "public"
    ? ownedPublic(row)
    : ownedForAccount(row, scope.userId, scopeRelations(scope, follower, member)));

describe("owned rows: canView matches the read rule on every cell", () => {
  const cells = Arr.flatMap(ownedRows, (row) =>
    Arr.flatMap(VIEWERS, ([name, viewer]) =>
      Arr.flatMap(SEAM_MODES, (follower) =>
        Arr.map(SEAM_MODES, (member) => ({ row, name, viewer, follower, member })),
      ),
    ),
  );

  it("covers the full matrix", () => {
    expect(ownedRows).toHaveLength(64);
    expect(cells).toHaveLength(64 * 8 * 4 * 4);
  });

  it("agrees with the rule, and asks a seam only what the rule allows", () => {
    const failures = Arr.flatMap(cells, ({ row, name, viewer, follower, member }) => {
      const calls: Array<SeamCall> = [];
      const actual = runAs(owned.canView(row), viewer, follower, member, calls);
      const expected = expectedOwned(row, viewer, follower, member);
      const bad = forbiddenCalls(calls, viewer, ownedAllowedQuestions(row));
      const where = label({ viewer: name, ...row, follower, member });
      return [
        ...(actual === expected ? [] : [`${where}: canView ${actual}, rule ${expected}`]),
        ...Arr.map(bad, (call) => `${where}: forbidden seam call ${call}`),
      ];
    });
    expect(failures).toEqual([]);
  });

  it("never asks either seam about a row with no owner or no group", () => {
    const calls: Array<SeamCall> = [];
    Arr.forEach(cells, ({ row, viewer, follower, member }) => {
      if (row.ownerId === undefined || row.groupId === undefined) {
        runAs(owned.canView(row), viewer, follower, member, calls);
      }
    });
    expect(Arr.filter(calls, (call) => !P.isString(call.subject))).toEqual([]);
    expect(Arr.filter(calls, (call) => call.seam === "follower" && call.subject !== OWNER)).toEqual(
      [],
    );
    expect(Arr.filter(calls, (call) => call.seam === "member" && call.subject !== GROUP)).toEqual(
      [],
    );
  });

  it("reads an omitted unapproved exactly as false", () => {
    Arr.forEach(ownedRows, (row) => {
      if (row.unapproved === true) return;
      const { unapproved: _, ...without } = row;
      Arr.forEach(VIEWERS, ([, viewer]) => {
        expect(runAs(owned.canView(without), viewer, "graph", "graph")).toBe(
          runAs(owned.canView(row), viewer, "graph", "graph"),
        );
      });
    });
  });

  it("does not turn a missing owner into an id the anonymous principal or an empty id matches", () => {
    const noOwner = { ownerId: undefined, visibility: "private" } as const;
    expect(runAs(owned.canView(noOwner), null, "always", "always")).toBe(false);
    expect(runAs(owned.canView(noOwner), { id: "", role: "user" }, "always", "always")).toBe(false);
    expect(
      runAs(owned.canView(noOwner), { id: "anonymous", role: "user" }, "always", "always"),
    ).toBe(false);
  });

  it("ReadScope.compile over policies admits exactly the rows canView does", () => {
    const failures = Arr.flatMap(VIEWERS, ([name, viewer]) => {
      const compiled = compileFor(owned.policies, owned.binding, viewer);
      return Arr.flatMap(ownedRows, (row) =>
        Arr.flatMap(SEAM_MODES, (follower) =>
          Arr.flatMap(SEAM_MODES, (member) => {
            const actual = compiledAdmits(compiled, ownedColumns(row), viewer, follower, member);
            const expected = expectedOwned(row, viewer, follower, member);
            return actual === expected
              ? []
              : [`${label({ viewer: name, ...row, follower, member })}: compiled ${actual}`];
          }),
        ),
      );
    });
    expect(failures).toEqual([]);
  });

  it("the read scope, rendered as documented, admits exactly the rows canView does", () => {
    const failures = Arr.flatMap(VIEWERS, ([name, viewer]) =>
      Arr.flatMap(SEAM_MODES, (follower) =>
        Arr.flatMap(SEAM_MODES, (member) => {
          const scope = runAs(owned.readScope, viewer, follower, member);
          return Arr.flatMap(ownedRows, (row) =>
            ownedScopeAdmits(scope, row, follower, member) ===
            expectedOwned(row, viewer, follower, member)
              ? []
              : [label({ viewer: name, ...row, follower, member })],
          );
        }),
      ),
    );
    expect(failures).toEqual([]);
  });
});

// ---------------------------------------------------------------------------
// Reference rows
// ---------------------------------------------------------------------------

/** The followers-of cases, relative to the viewer: itself, an account it follows, another, none. */
const followersOfCases = (viewer: AppUser | null): ReadonlyArray<string | undefined> => [
  // Anonymous has no id: use the anonymous sentinel, which must name nobody.
  viewer?.id ?? "anonymous",
  FOLLOWED,
  "u-elsewhere",
  undefined,
];

const referenceRowsFor = (viewer: AppUser | null): ReadonlyArray<ReferenceAccess.ReferenceRow> =>
  Arr.flatMap([undefined, ...VISIBILITIES], (visibility) =>
    Arr.flatMap(followersOfCases(viewer), (followersOf) =>
      Arr.map([GROUP, "g-other", undefined], (groupId) => ({
        ...(visibility === undefined ? {} : { visibility }),
        followersOf,
        groupId,
      })),
    ),
  );

/** Who reads a reference row with an axis, by visibility (section 4); `public` is everyone's. */
const referenceAudience: Readonly<
  Record<
    OwnedAccess.Visibility,
    (row: ReferenceAccess.ReferenceRow, accountId: string, relations: Relations) => boolean
  >
> = {
  public: () => true,
  followers: (row, accountId, relations) =>
    row.followersOf !== undefined &&
    (row.followersOf === accountId || relations.follows(row.followersOf)),
  group: (row, _, relations) => row.groupId !== undefined && relations.member(row.groupId),
  private: () => false,
};

/** Visible to anyone: no axis on the view, or public. */
const referenceOpen = (row: ReferenceAccess.ReferenceRow): boolean =>
  row.visibility === undefined || row.visibility === "public";

/** The reference read rule, from #637's section 4. */
const expectedReference = (
  row: ReferenceAccess.ReferenceRow,
  viewer: AppUser | null,
  follower: SeamMode,
  member: SeamMode,
): boolean =>
  referenceOpen(row) ||
  (viewer !== null &&
    (atViewPrivate(viewer) ||
      referenceAudience[row.visibility ?? "private"](
        row,
        viewer.id,
        seamRelations(viewer.id, follower, member),
      )));

const referenceAllowedQuestions = (row: ReferenceAccess.ReferenceRow) => ({
  follower: row.visibility === "followers" ? row.followersOf : undefined,
  member: row.visibility === "group" ? row.groupId : undefined,
});

const referenceColumns = (row: ReferenceAccess.ReferenceRow): ReadScope.Row => ({
  visibility: row.visibility ?? null,
  followersOf: row.followersOf ?? null,
  group: row.groupId ?? null,
});

/** The documented meaning of an `OwnedReadScope` for reference rows (no axis: no filter). */
const referenceScopeAdmits = (
  scope: OwnedAccess.OwnedReadScope,
  row: ReferenceAccess.ReferenceRow,
  follower: SeamMode,
  member: SeamMode,
): boolean =>
  referenceOpen(row) ||
  scope.kind === "all" ||
  (scope.kind === "member" &&
    referenceAudience[row.visibility ?? "private"](
      row,
      scope.userId,
      scopeRelations(scope, follower, member),
    ));

describe("reference rows: canView matches the read rule on every cell", () => {
  const cells = Arr.flatMap(VIEWERS, ([name, viewer]) =>
    Arr.flatMap(referenceRowsFor(viewer), (row) =>
      Arr.flatMap(SEAM_MODES, (follower) =>
        Arr.map(SEAM_MODES, (member) => ({ row, name, viewer, follower, member })),
      ),
    ),
  );

  it("covers the full matrix", () => {
    expect(referenceRowsFor(null)).toHaveLength(5 * 4 * 3);
    expect(cells).toHaveLength(60 * 8 * 4 * 4);
  });

  it("agrees with the rule, and asks a seam only what the rule allows", () => {
    const failures = Arr.flatMap(cells, ({ row, name, viewer, follower, member }) => {
      const calls: Array<SeamCall> = [];
      const actual = runAs(reference.canView(row), viewer, follower, member, calls);
      const expected = expectedReference(row, viewer, follower, member);
      const bad = forbiddenCalls(calls, viewer, referenceAllowedQuestions(row));
      const where = label({ viewer: name, ...row, follower, member });
      return [
        ...(actual === expected ? [] : [`${where}: canView ${actual}, rule ${expected}`]),
        ...Arr.map(bad, (call) => `${where}: forbidden seam call ${call}`),
      ];
    });
    expect(failures).toEqual([]);
  });

  it("the followers-of account reads its followers rows and not its private rows", () => {
    const account = { id: "u-corpus", role: "user" };
    const row = (visibility: OwnedAccess.Visibility) => ({ visibility, followersOf: account.id });
    expect(runAs(reference.canView(row("followers")), account, "never", "never")).toBe(true);
    expect(runAs(reference.canView(row("private")), account, "always", "always")).toBe(false);
    expect(runAs(reference.canView(row("group")), account, "always", "never")).toBe(false);
  });

  it("ReadScope.compile over policies admits exactly the rows canView does", () => {
    const failures = Arr.flatMap(VIEWERS, ([name, viewer]) => {
      const scoped = compileFor(reference.policies, reference.binding, viewer, {
        unscoped: false,
      });
      const unscoped = compileFor(reference.policies, reference.binding, viewer, {
        unscoped: true,
      });
      return Arr.flatMap(referenceRowsFor(viewer), (row) =>
        Arr.flatMap(SEAM_MODES, (follower) =>
          Arr.flatMap(SEAM_MODES, (member) => {
            const compiled = row.visibility === undefined ? unscoped : scoped;
            const actual = compiledAdmits(
              compiled,
              referenceColumns(row),
              viewer,
              follower,
              member,
            );
            const expected = expectedReference(row, viewer, follower, member);
            return actual === expected
              ? []
              : [`${label({ viewer: name, ...row, follower, member })}: compiled ${actual}`];
          }),
        ),
      );
    });
    expect(failures).toEqual([]);
  });

  it("a compiled scope reads a NULL visibility column as private, and fails closed without the unscoped fact", () => {
    const columns = { visibility: null, followersOf: null, group: null };
    const stranger = { id: "u-stranger", role: "user" };
    expect(
      compiledAdmits(
        compileFor(reference.policies, reference.binding, stranger, { unscoped: false }),
        columns,
        stranger,
        "always",
        "always",
      ),
    ).toBe(false);
    expect(
      compiledAdmits(
        compileFor(reference.policies, reference.binding, null),
        { visibility: "private", followersOf: null, group: null },
        null,
        "absent",
        "absent",
      ),
    ).toBe(false);
  });

  it("the read scope, rendered as documented, admits exactly the rows canView does", () => {
    const failures = Arr.flatMap(VIEWERS, ([name, viewer]) =>
      Arr.flatMap(SEAM_MODES, (follower) =>
        Arr.flatMap(SEAM_MODES, (member) => {
          const scope = runAs(reference.readScope, viewer, follower, member);
          return Arr.flatMap(referenceRowsFor(viewer), (row) =>
            referenceScopeAdmits(scope, row, follower, member) ===
            expectedReference(row, viewer, follower, member)
              ? []
              : [label({ viewer: name, ...row, follower, member })],
          );
        }),
      ),
    );
    expect(failures).toEqual([]);
  });
});

// ---------------------------------------------------------------------------
// Read scope
// ---------------------------------------------------------------------------

/** The read scope the rule gives a viewer, with or without each seam. */
const expectedScope = (
  viewer: AppUser | null,
  follower: boolean,
  member: boolean,
): OwnedAccess.OwnedReadScope => {
  if (viewer === null) return { kind: "public" };
  if (atViewPrivate(viewer)) return { kind: "all" };
  return {
    kind: "member",
    userId: viewer.id,
    following: follower ? OwnedAccess.subquery(`following(${viewer.id})`) : OwnedAccess.nobody,
    groups: member ? OwnedAccess.subquery(`groups(${viewer.id})`) : OwnedAccess.nobody,
  };
};

describe("read scope: both readScopes for every viewer and seam presence", () => {
  const cells = Arr.flatMap(VIEWERS, ([name, viewer]) =>
    Arr.flatMap([false, true], (follower) =>
      Arr.map([false, true], (member) => ({ name, viewer, follower, member })),
    ),
  );

  it("is all for the rung, public for anonymous, member otherwise, nobody sets without a seam", () => {
    expect(cells).toHaveLength(8 * 2 * 2);
    Arr.forEach(cells, ({ name, viewer, follower, member }) => {
      const modes = [follower ? "graph" : "absent", member ? "graph" : "absent"] as const;
      const expected = expectedScope(viewer, follower, member);
      const where = label({ viewer: name, follower, member });
      expect(runAs(owned.readScope, viewer, ...modes), `owned ${where}`).toEqual(expected);
      expect(runAs(reference.readScope, viewer, ...modes), `reference ${where}`).toEqual(expected);
    });
  });

  it("the explicit never layers are the same fail-closed sets", () => {
    const viewer = { id: "u-stranger", role: "user" };
    const scope = Effect.runSync(
      owned.readScope.pipe(
        Effect.provide(
          Layer.mergeAll(
            SessionContext.viewerLayer(CurrentViewer, viewer),
            OwnedAccess.isFollowerNever,
            OwnedAccess.isMemberNever,
          ),
        ),
      ),
    );
    expect(scope).toEqual(expectedScope(viewer, false, false));
    const shared = { ownerId: OWNER, visibility: "group", groupId: GROUP } as const;
    expect(
      Effect.runSync(
        owned
          .canView(shared)
          .pipe(
            Effect.provide(
              Layer.merge(
                SessionContext.viewerLayer(CurrentViewer, { id: "u-member", role: "user" }),
                OwnedAccess.isMemberNever,
              ),
            ),
          ),
      ),
    ).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// Serveability
// ---------------------------------------------------------------------------

describe("serveability: publiclyServeable(OwnedAccess.serveableAxes)", () => {
  /** The attribute is left out of the representation (no wire value is this string). */
  const ABSENT = "<absent>";
  type Value = string | boolean | null | undefined;
  const visibilities: ReadonlyArray<Value> = [
    ABSENT,
    undefined,
    null,
    "public",
    "followers",
    "group",
    "private",
  ];
  const drafts: ReadonlyArray<Value> = [ABSENT, undefined, false, true, null];
  const moderationStates: ReadonlyArray<Value> = [ABSENT, "approved", "pending", null];
  const deletedAts: ReadonlyArray<Value> = [ABSENT, null, "2026-11-11T00:00:00Z"];

  /** Serveable, per CACHE-AUTH-005 without the publish stamp. */
  const expected = (
    visibility: Value,
    draft: Value,
    moderationState: Value,
    deletedAt: Value,
  ): boolean =>
    visibility === "public" &&
    (draft === ABSENT || draft === undefined || draft === false) &&
    (moderationState === ABSENT || moderationState === "approved") &&
    deletedAt === ABSENT;

  const serveable = Cacheability.publiclyServeable(OwnedAccess.serveableAxes);
  const field = (name: string, value: Value) => (value === ABSENT ? {} : { [name]: value });

  it("matches the rule on every cell", () => {
    const cells = Arr.flatMap(visibilities, (visibility) =>
      Arr.flatMap(drafts, (draft) =>
        Arr.flatMap(moderationStates, (moderationState) =>
          Arr.map(deletedAts, (deletedAt) => ({ visibility, draft, moderationState, deletedAt })),
        ),
      ),
    );
    expect(cells).toHaveLength(7 * 5 * 4 * 3);
    const failures = Arr.flatMap(cells, ({ visibility, draft, moderationState, deletedAt }) => {
      const attributes = {
        ...field("visibility", visibility),
        ...field("draft", draft),
        ...field("moderationState", moderationState),
        ...field("deletedAt", deletedAt),
      };
      return serveable(attributes) === expected(visibility, draft, moderationState, deletedAt)
        ? []
        : [label({ visibility, draft, moderationState, deletedAt })];
    });
    expect(failures).toEqual([]);
  });

  it("refuses an unapproved representation, and admits only rows every viewer may read", () => {
    expect(serveable({ visibility: "public", unapproved: true })).toBe(false);
    expect(serveable({ visibility: "public", unapproved: false })).toBe(true);
    // Every owned row whose wire attributes are serveable is visible to every
    // viewer, under every seam.
    Arr.forEach(ownedRows, (row) => {
      const attributes = {
        visibility: row.visibility,
        draft: row.draft,
        unapproved: row.unapproved,
      };
      if (!serveable(attributes)) return;
      Arr.forEach(VIEWERS, ([name, viewer]) => {
        expect(runAs(owned.canView(row), viewer, "absent", "absent"), name).toBe(true);
      });
    });
  });
});

// ---------------------------------------------------------------------------
// The four role axes
// ---------------------------------------------------------------------------

describe("the four role axes fail closed on a role outside the ladder", () => {
  const offLadder = ["superadmin", "", "ADMIN", "owner", "root"];

  it("decideRole and the gates refuse it at every axis", () => {
    Arr.forEach(R.values(Axes), (axis) => {
      Arr.forEach(offLadder, (role) => {
        const viewer = { id: "u-odd", role };
        expect(guards.decideRole(viewer, axis), `${role} @ ${axis.name}`).toBe(false);
        expect(guards.decideOwnerOrRole(viewer, OWNER, axis)).toBe(false);
        const gate = Effect.runSyncExit(
          guards
            .requireOwnerOrRole(OWNER, axis)
            .pipe(Effect.provide(SessionContext.viewerLayer(CurrentViewer, viewer))),
        );
        expect(Exit.isFailure(gate)).toBe(true);
      });
    });
  });

  it("and the rungs on the ladder answer as declared", () => {
    expect(guards.decideRole({ id: "m", role: "moderator" }, Axes.moderate)).toBe(true);
    expect(guards.decideRole({ id: "c", role: "contributor" }, Axes.writeCorpus)).toBe(true);
    expect(guards.decideRole({ id: "c", role: "contributor" }, Axes.viewDeleted)).toBe(false);
  });
});
// ---------------------------------------------------------------------------
// The policies, handed facts by a caller
// ---------------------------------------------------------------------------

/** Decide one read with the policies alone, the caller asserting the relation facts. */
const decideWithFacts = (
  policies: ReadonlyArray<Policy.DeclarativePolicy>,
  resource: Entity.Entity,
): boolean => {
  const principal = guards.principal({ id: "u-stranger", role: "user" });
  return Policy.decidePure(
    policies,
    Policy.request({
      principal: principal.ref,
      action: Entity.ref("Action", "read"),
      resource: resource.ref,
      context: { follows: true, member: true, unscoped: false },
    }),
    Entity.slice([principal, resource]),
  ).allowed;
};
const entityRow = (
  type: string,
  attributes: Readonly<Record<string, Entity.AttributeValue>>,
): Entity.Entity => Entity.entity(Entity.ref(type, "row"), { attributes });
describe("the policies refuse a relation fact about a missing owner, followers-of or group", () => {
  const published = { draft: false, unapproved: false };

  it("owned rows: follows with no owner, member with no group", () => {
    expect(
      decideWithFacts(
        owned.policies,
        entityRow("Owned", { visibility: "followers", ...published }),
      ),
    ).toBe(false);
    expect(
      decideWithFacts(owned.policies, entityRow("Owned", { visibility: "group", ...published })),
    ).toBe(false);
    // The same facts with the subject present are what the permits admit.
    const owner = Entity.entityValue(Entity.ref("User", OWNER));
    expect(
      decideWithFacts(
        owned.policies,
        entityRow("Owned", { visibility: "followers", ...published, owner }),
      ),
    ).toBe(true);
    expect(
      decideWithFacts(
        owned.policies,
        entityRow("Owned", { visibility: "group", ...published, group: GROUP }),
      ),
    ).toBe(true);
  });

  it("reference rows: follows with no followers-of, member with no group", () => {
    expect(
      decideWithFacts(reference.policies, entityRow("Reference", { visibility: "followers" })),
    ).toBe(false);
    expect(
      decideWithFacts(reference.policies, entityRow("Reference", { visibility: "group" })),
    ).toBe(false);
    expect(
      decideWithFacts(
        reference.policies,
        entityRow("Reference", { visibility: "group", group: GROUP }),
      ),
    ).toBe(true);
  });
});
