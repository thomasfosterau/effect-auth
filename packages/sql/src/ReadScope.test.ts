/**
 * The SQL projection of a read scope, against a real Postgres (PGlite): the
 * rows `readScopeWhere` lists must be exactly the rows the core's
 * `ReadScope.matches` admits, which the core's own suite holds to the kernel's
 * `Policy.decidePure`. The corpus includes NULL columns, so the projection's
 * NULL handling is checked against the kernel's absent-attribute rule rather
 * than against SQL's three-valued logic.
 */

import type { PGlite } from "@electric-sql/pglite";
import * as PgliteClient from "@effect/sql-pglite/PgliteClient";
import { Array as Arr, Effect, Order, Predicate } from "effect";
import { SqlClient } from "effect/sql";
import { afterAll, assert, beforeAll, describe, expect, it } from "vite-plus/test";
import { Condition, Entity, Policy, ReadScope } from "@thomasfosterau/effect-auth";
import { readScopeWhere } from "./ReadScope.ts";
import { migratedPglite } from "./testing/PgliteTemplate.ts";

let database: PGlite;

beforeAll(async () => {
  database = await migratedPglite();
  await database.exec(`
    CREATE TABLE owned (id TEXT PRIMARY KEY, owner_id TEXT, visibility TEXT, draft BOOLEAN, score INTEGER);
    CREATE TABLE follows (follower TEXT NOT NULL, followee TEXT NOT NULL);
    INSERT INTO follows VALUES ('u-other', 'u-member'), ('u-other', 'u-admin');
  `);
  const values = Arr.map(corpus, (row) => [
    row.id,
    row.owner,
    row.visibility,
    row.draft,
    row.score,
  ]);
  await Promise.all(
    Arr.map(values, (params) =>
      database.query(`INSERT INTO owned VALUES ($1, $2, $3, $4, $5)`, params),
    ),
  );
});

afterAll(async () => {
  await database?.close();
});

interface CorpusRow {
  readonly id: string;
  readonly owner: string | null;
  readonly visibility: string | null;
  readonly draft: boolean | null;
  readonly score: number | null;
}

const corpus: ReadonlyArray<CorpusRow> = Arr.flatMap(
  ["u-admin", "u-member", "u-other", null],
  (owner) =>
    Arr.flatMap(["public", "followers", "private", null], (visibility) =>
      Arr.flatMap([false, true, null], (draft) =>
        Arr.map([0, 10, null], (score) => ({
          id: `${owner ?? "none"}/${visibility ?? "none"}/${String(draft)}/${String(score)}`,
          owner,
          visibility,
          draft,
          score,
        })),
      ),
    ),
);

const followsEdge = (follower: string, owner: string): boolean =>
  follower === "u-other" && (owner === "u-member" || owner === "u-admin");

const binding: ReadScope.Binding = {
  resourceType: "Owned",
  attributes: { owner: { entity: "User" }, visibility: "Text", draft: "Boolean", score: "Integer" },
  setFacts: { follows: { attribute: "owner", set: "following" } },
};

const attr = (name: string) => Condition.attr("resource", name);
const policies: ReadonlyArray<Policy.DeclarativePolicy> = [
  Policy.permit({
    id: "public",
    resource: Policy.isType("Owned"),
    when: Condition.and(
      Condition.eq(attr("visibility"), Condition.lit("public")),
      Condition.eq(attr("draft"), Condition.lit(false)),
    ),
  }),
  Policy.permit({
    id: "owner",
    resource: Policy.isType("Owned"),
    when: Condition.eq(Condition.principal, attr("owner")),
  }),
  Policy.permit({
    id: "follower",
    resource: Policy.isType("Owned"),
    when: Condition.and(
      Condition.eq(attr("visibility"), Condition.lit("followers")),
      Condition.not(Condition.eq(attr("draft"), Condition.lit(true))),
      Condition.eq(Condition.attr("context", "follows"), Condition.lit(true)),
    ),
  }),
  Policy.permit({
    id: "moderator",
    resource: Policy.isType("Owned"),
    when: Condition.contains(Condition.lit(["moderator"]), Condition.attr("principal", "role")),
  }),
  Policy.forbid({
    id: "low-score",
    resource: Policy.isType("Owned"),
    when: Condition.lt(attr("score"), Condition.lit(5)),
  }),
];

/** Anonymous, two signed-in members, a follower, and a moderator. */
const viewers = [null, "u-admin", "u-member", "u-other", "u-moderator"] as const;

const principalOf = (viewer: string | null): Entity.Entity =>
  viewer === null
    ? Entity.entity(Entity.ref("Anonymous", "anonymous"))
    : Entity.entity(Entity.ref("User", viewer), {
        attributes: { role: viewer === "u-moderator" ? "moderator" : "member" },
      });

const compiled = (viewer: string | null): ReadScope.ReadScope => {
  const principal = principalOf(viewer);
  const result = ReadScope.compile(policies, binding, {
    principal: principal.ref,
    action: Entity.ref("Action", "read"),
    slice: Entity.slice([principal]),
  });
  assert(Predicate.isTagged(result, "Exact"));
  return result.scope;
};

/** The kernel's own decision on every corpus row: the specification. */
const kernel = (viewer: string | null) => {
  const principal = principalOf(viewer);
  return Arr.sort(
    Arr.map(
      Arr.filter(corpus, (row) => {
        const resource = Entity.entity(Entity.ref("Owned", row.id), {
          attributes: {
            ...(row.owner === null
              ? {}
              : { owner: Entity.entityValue(Entity.ref("User", row.owner)) }),
            ...(row.visibility === null ? {} : { visibility: row.visibility }),
            ...(row.draft === null ? {} : { draft: row.draft }),
            ...(row.score === null ? {} : { score: row.score }),
          },
        });
        return Policy.decidePure(
          policies,
          Policy.request({
            principal: principal.ref,
            action: Entity.ref("Action", "read"),
            resource: resource.ref,
            context: {
              follows: viewer !== null && row.owner !== null && followsEdge(viewer, row.owner),
            },
          }),
          Entity.slice([principal, resource]),
        ).allowed;
      }),
      (row) => row.id,
    ),
    Order.String,
  );
};

const listed = (scope: ReadScope.ReadScope, viewer: string | null, withSets: boolean) =>
  Effect.runPromise(
    Effect.gen(function* () {
      const sql = yield* SqlClient.SqlClient;
      const where = yield* readScopeWhere(scope, {
        columns: {
          owner: sql("owner_id"),
          visibility: sql("visibility"),
          draft: sql("draft"),
          score: sql("score"),
        },
        ...(withSets
          ? {
              sets: {
                following: sql`SELECT followee FROM follows WHERE follower = ${viewer ?? ""}`,
              },
            }
          : {}),
      });
      const rows = yield* sql<{ readonly id: string }>`SELECT id FROM owned WHERE ${where}`;
      return Arr.sort(
        Arr.map(rows, (row) => row.id),
        Order.String,
      );
    }).pipe(Effect.provide(PgliteClient.layer({ liveClient: database }))),
  );

const expected = (scope: ReadScope.ReadScope, viewer: string | null, withSets: boolean) =>
  Arr.sort(
    Arr.map(
      Arr.filter(corpus, (row) =>
        ReadScope.matches(
          withSets ? scope : ReadScope.withoutSets(scope, () => false),
          { owner: row.owner, visibility: row.visibility, draft: row.draft, score: row.score },
          (_set, value) =>
            viewer !== null && Predicate.isString(value) && followsEdge(viewer, value),
        ),
      ),
      (row) => row.id,
    ),
    Order.String,
  );

describe("readScopeWhere over PostgreSQL (PGlite)", () => {
  it.each(viewers)("lists exactly the rows the kernel allows, for viewer %s", async (viewer) => {
    const scope = compiled(viewer);
    const rows = await listed(scope, viewer, true);
    expect(rows).toEqual(kernel(viewer));
    expect(rows).toEqual(expected(scope, viewer, true));
  });

  it("is AllowAll-with-forbids for the moderator and a bounded filter for everyone else", () => {
    // The moderator's permit is unconditional, so only the forbid remains.
    const moderator = compiled("u-moderator");
    assert(Predicate.isTagged(moderator, "Filter"));
    expect(ReadScope.attributes(moderator.predicate)).toEqual(["score"]);
    const member = compiled("u-member");
    assert(Predicate.isTagged(member, "Filter"));
    expect(member.sets).toEqual(["following"]);
  });

  it.each(viewers)("narrows when the follow set is not provided, for viewer %s", async (viewer) => {
    const scope = compiled(viewer);
    const narrowed = await listed(scope, viewer, false);
    expect(narrowed).toEqual(expected(scope, viewer, false));
    const full = await listed(scope, viewer, true);
    expect(Arr.difference(narrowed, full)).toEqual([]);
  });

  it("renders a column the binding lacks as deny-all", async () => {
    const scope = compiled("u-member");
    const rows = await Effect.runPromise(
      Effect.gen(function* () {
        const sql = yield* SqlClient.SqlClient;
        const where = yield* readScopeWhere(scope, { columns: { owner: sql("owner_id") } });
        return yield* sql`SELECT id FROM owned WHERE ${where}`;
      }).pipe(Effect.provide(PgliteClient.layer({ liveClient: database }))),
    );
    expect(rows).toEqual([]);
  });
});
