/**
 * The read scope (#190, #203): a policy set compiled over an unbound row.
 *
 * The kernel (`Policy.decidePure`) is the specification. Every test here
 * compiles a policy set once per viewer and requires the compiled scope's
 * single-row form (`ReadScope.matches`) to agree with the kernel's decision on
 * every row of a corpus that includes absent attributes. The SQL projection
 * is held to the same corpus in effect-auth-sql's `ReadScope.test.ts`.
 */
import { assert, describe, expect, it } from "vite-plus/test";
import { Array as Arr, Context, Match, Option, Predicate } from "effect";
import * as Condition from "./Condition.ts";
import * as Entity from "./Entity.ts";
import * as Guard from "./Guard.ts";
import * as Ladder from "./Ladder.ts";
import * as OwnedAccess from "./OwnedAccess.ts";
import * as Policy from "./Policy.ts";
import * as ReadScope from "./ReadScope.ts";

interface AppUser {
  readonly id: string;
  readonly role: string;
}
class CurrentViewer extends Context.Service<CurrentViewer, Option.Option<AppUser>>()(
  "@test/ReadScope/CurrentViewer",
) {}

const Roles = Ladder.make(["user", "contributor", "moderator", "admin"]);
const Axes = Roles.axes({ viewPrivate: "moderator" });
const guards = Guard.make({ ladder: Roles, viewer: CurrentViewer });
const owned = OwnedAccess.make({ guards, viewPrivate: Axes.viewPrivate });

const read = Entity.ref("Action", "read");
const anonymous = Entity.entity(Entity.ref("Anonymous", "anonymous"));

const binding: ReadScope.Binding = {
  resourceType: "Owned",
  attributes: {
    owner: { entity: guards.principalType },
    visibility: "Text",
    draft: "Boolean",
  },
  setFacts: { follows: { attribute: "owner", set: "following" } },
};

/** A row of the corpus, as a database holds it: `null` is a NULL column. */
type CorpusRow = {
  readonly id: string;
  readonly owner: string | null;
  readonly visibility: string | null;
  readonly draft: boolean | null;
};

const users = ["u-admin", "u-moderator", "u-member", "u-other", "u-stranger"] as const;
const corpus: ReadonlyArray<CorpusRow> = Arr.flatMap([...users, null], (owner) =>
  Arr.flatMap(["public", "followers", "private", "unknown", null], (visibility) =>
    Arr.map([false, true, null], (draft) => ({
      id: `${owner ?? "none"}/${visibility ?? "none"}/${String(draft)}`,
      owner,
      visibility,
      draft,
    })),
  ),
);

const viewers: ReadonlyArray<AppUser | null> = [
  null,
  { id: "u-admin", role: "admin" },
  { id: "u-moderator", role: "moderator" },
  { id: "u-member", role: "user" },
  { id: "u-other", role: "contributor" },
  // A role off the ladder: the role policy errors for this principal.
  { id: "u-stranger", role: "guest" },
];

/** Who follows whom: `u-other` follows `u-member` and `u-admin`. */
const followsEdge = (follower: string, owner: string): boolean =>
  follower === "u-other" && (owner === "u-member" || owner === "u-admin");

const principalOf = (viewer: AppUser | null): Entity.Entity =>
  viewer === null ? anonymous : guards.principal(viewer);

/** The kernel's decision for one row: the specification. */
const kernelAllows = (
  policies: ReadonlyArray<Policy.DeclarativePolicy>,
  viewer: AppUser | null,
  row: CorpusRow,
): boolean => {
  const principal = principalOf(viewer);
  const resource = Entity.entity(Entity.ref("Owned", row.id), {
    attributes: {
      ...(row.owner === null
        ? {}
        : { owner: Entity.entityValue(Entity.ref(guards.principalType, row.owner)) }),
      ...(row.visibility === null ? {} : { visibility: row.visibility }),
      ...(row.draft === null ? {} : { draft: row.draft }),
    },
  });
  const follows = viewer !== null && row.owner !== null && followsEdge(viewer.id, row.owner);
  return Policy.decidePure(
    policies,
    Policy.request({
      principal: principal.ref,
      action: read,
      resource: resource.ref,
      context: { follows },
    }),
    Entity.slice([principal, resource]),
  ).allowed;
};

const compileFor = (
  policies: ReadonlyArray<Policy.DeclarativePolicy>,
  viewer: AppUser | null,
): ReadScope.Compiled => {
  const principal = principalOf(viewer);
  return ReadScope.compile(policies, binding, {
    principal: principal.ref,
    action: read,
    slice: Entity.slice([principal]),
  });
};

const exact = (compiled: ReadScope.Compiled): ReadScope.ReadScope => {
  assert(
    Predicate.isTagged(compiled, "Exact"),
    `inexact: ${Predicate.isTagged(compiled, "Inexact") ? compiled.reasons.join("; ") : ""}`,
  );
  return compiled.scope;
};

const scopeAllows = (scope: ReadScope.ReadScope, viewer: AppUser | null, row: CorpusRow): boolean =>
  ReadScope.matches(
    scope,
    { owner: row.owner, visibility: row.visibility, draft: row.draft },
    (set, value) =>
      set === "following" &&
      viewer !== null &&
      Predicate.isString(value) &&
      followsEdge(viewer.id, value),
  );

/** Require the compiled scope and the kernel to agree on every row, for every viewer. */
const expectAgreement = (policies: ReadonlyArray<Policy.DeclarativePolicy>): void => {
  const disagreements = Arr.flatMap(viewers, (viewer) => {
    const scope = exact(compileFor(policies, viewer));
    return Arr.flatMap(corpus, (row) => {
      const kernel = kernelAllows(policies, viewer, row);
      return scopeAllows(scope, viewer, row) === kernel
        ? []
        : [{ viewer: viewer?.id ?? "anonymous", row: row.id, kernel }];
    });
  });
  expect(disagreements).toEqual([]);
};

/** Every text literal a predicate compares with. */
const literalTexts = (predicate: ReadScope.Predicate): ReadonlyArray<string> =>
  Match.valueTags(predicate, {
    And: ({ predicates }) => Arr.flatMap(predicates, literalTexts),
    Or: ({ predicates }) => Arr.flatMap(predicates, literalTexts),
    Not: ({ predicate: inner }) => literalTexts(inner),
    Eq: ({ value }) => (Predicate.isString(value.value) ? [value.value] : []),
    Compare: ({ value }) => (Predicate.isString(value.value) ? [value.value] : []),
    IsNull: () => [],
    InSet: () => [],
  });

describe("ReadScope.compile", () => {
  it("agrees with the kernel on the owned-material policies, absent attributes included", () => {
    expectAgreement(owned.policies);
  });

  it("returns AllowAll for the viewPrivate axis, with no disjunction to render", () => {
    expect(exact(compileFor(owned.policies, { id: "u-moderator", role: "moderator" }))).toEqual(
      ReadScope.allowAll,
    );
  });

  it("returns Deny when no permit applies", () => {
    const policies = [
      Policy.permit({
        id: "admins",
        principal: Policy.isType("Nobody"),
        resource: Policy.isType("Owned"),
      }),
    ];
    expect(exact(compileFor(policies, { id: "u-member", role: "user" }))).toEqual(ReadScope.deny);
  });

  it("compiles the follower arm to a named set, never to members", () => {
    const scope = exact(compileFor(owned.policies, { id: "u-other", role: "contributor" }));
    assert(Predicate.isTagged(scope, "Filter"));
    expect(scope.sets).toEqual(["following"]);
    expect(ReadScope.attributes(scope.predicate)).toEqual(["draft", "owner", "visibility"]);
    // The follow set travels by name; no member id is inlined as a literal.
    expect(literalTexts(scope.predicate)).not.toContain("u-member");
  });

  it("agrees with the kernel when a forbid reads an absent attribute", () => {
    expectAgreement([
      ...owned.policies,
      Policy.forbid({
        id: "no-unknown",
        resource: Policy.isType("Owned"),
        when: Condition.not(
          Condition.or(
            Condition.eq(Condition.attr("resource", "visibility"), Condition.lit("public")),
            Condition.eq(Condition.attr("resource", "visibility"), Condition.lit("followers")),
            Condition.eq(Condition.attr("resource", "visibility"), Condition.lit("private")),
          ),
        ),
      }),
    ]);
  });

  it("agrees with the kernel on Has and on a forbid over a set fact", () => {
    expectAgreement([
      Policy.permit({
        id: "drafts-known",
        resource: Policy.isType("Owned"),
        when: Condition.has("resource", "draft"),
      }),
      Policy.forbid({
        id: "not-followed",
        resource: Policy.isType("Owned"),
        when: Condition.eq(Condition.attr("context", "follows"), Condition.lit(true)),
      }),
    ]);
  });

  it("flags a policy it can't express as Inexact, with the reason", () => {
    const compiled = compileFor(
      [
        Policy.permit({
          id: "tagged",
          resource: Policy.isType("Owned"),
          when: Condition.contains(Condition.attr("resource", "tags"), Condition.lit("x")),
        }),
      ],
      { id: "u-member", role: "user" },
    );
    assert(Predicate.isTagged(compiled, "Inexact"));
    expect(compiled.reasons.join("\n")).toContain("tagged");
  });

  it("ignores an inexpressible policy whose scopes never apply", () => {
    const compiled = compileFor(
      [
        ...owned.policies,
        Policy.permit({
          id: "elsewhere",
          resource: Policy.isType("Document"),
          when: Condition.contains(Condition.attr("resource", "tags"), Condition.lit("x")),
        }),
      ],
      { id: "u-member", role: "user" },
    );
    expect(compiled._tag).toBe("Exact");
  });
});

describe("ReadScope.withoutSets", () => {
  it("narrows a positive set reference to nothing", () => {
    const scope = exact(compileFor(owned.policies, { id: "u-other", role: "contributor" }));
    const narrowed = ReadScope.withoutSets(scope, () => false);
    expect(narrowed._tag).toBe("Filter");
    // Every row the narrowed scope admits, the original admits with the set full.
    const widened = Arr.filter(
      corpus,
      (row) =>
        ReadScope.matches(narrowed, row, () => true) && !ReadScope.matches(scope, row, () => true),
    );
    expect(widened).toEqual([]);
    expect(
      ReadScope.matches(
        narrowed,
        { owner: "u-member", visibility: "followers", draft: false },
        () => true,
      ),
    ).toBe(false);
  });

  it("narrows a set under a forbid to Deny rather than dropping the forbid", () => {
    const scope = exact(
      compileFor(
        [
          Policy.permit({ id: "all", resource: Policy.isType("Owned") }),
          Policy.forbid({
            id: "followed",
            resource: Policy.isType("Owned"),
            when: Condition.eq(Condition.attr("context", "follows"), Condition.lit(true)),
          }),
        ],
        { id: "u-member", role: "user" },
      ),
    );
    expect(ReadScope.withoutSets(scope, () => false)).toEqual(ReadScope.deny);
  });
});
