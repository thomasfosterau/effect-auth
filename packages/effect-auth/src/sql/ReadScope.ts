/**
 * Renders a core `ReadScope` as a SQL `WHERE` fragment over a relation's
 * columns. Every comparison is guarded by `IS NOT NULL`, so the fragment stays
 * two-valued. It fails closed: a scope attribute with no column renders `1 =
 * 0`, and a set with no fragment is dropped through `withoutSets`.
 *
 * @module read-scope
 */

import { Effect, Match } from "effect";
import * as Arr from "effect/Array";
import { SqlClient, type Statement } from "effect/sql";
import { ReadScope } from "../index.ts";

/**
 * Where each scope attribute and named set lives in the relation being read.
 *
 * @since 0.1.0
 * @category models
 */
export interface ReadScopeBinding {
  /** Each attribute's column: an identifier (`sql("owner_id")`) or a fragment (`sql.literal("s.owner_id")`). */
  readonly columns: Readonly<Record<string, Statement.Fragment | Statement.Identifier>>;
  /** Each named set as a subquery selecting one column (`sql\`SELECT followee FROM follows WHERE …\``). */
  readonly sets?: Readonly<Record<string, Statement.Fragment>> | undefined;
}

/**
 * Render a read scope as a `WHERE` fragment.
 *
 * `AllowAll` renders `1 = 1` and `Deny` renders `1 = 0`, so the result can
 * always be spliced into `WHERE ${fragment}`.
 *
 * @since 0.1.0
 * @category read scope
 */
export const readScopeWhere = (
  scope: ReadScope.ReadScope,
  binding: ReadScopeBinding,
): Effect.Effect<Statement.Fragment, never, SqlClient.SqlClient> =>
  Effect.map(SqlClient.SqlClient, (sql) => {
    const sets = binding.sets ?? {};
    const narrowed = ReadScope.withoutSets(scope, (set) => sets[set] !== undefined);
    const allow = sql.literal("1 = 1");
    const none = sql.literal("1 = 0");

    const column = (name: string): Statement.Fragment | Statement.Identifier =>
      binding.columns[name] ?? none;
    const render = (predicate: ReadScope.Predicate): Statement.Fragment =>
      Match.valueTags(predicate, {
        And: ({ predicates }): Statement.Fragment => sql.and(Arr.map(predicates, render)),
        Or: ({ predicates }): Statement.Fragment => sql.or(Arr.map(predicates, render)),
        Not: ({ predicate: inner }): Statement.Fragment => sql`NOT (${render(inner)})`,
        IsNull: ({ attribute }): Statement.Fragment => sql`${column(attribute)} IS NULL`,
        Eq: ({ attribute, value }): Statement.Fragment =>
          sql`(${column(attribute)} IS NOT NULL AND ${column(attribute)} = ${value.value})`,
        Compare: ({ op, attribute, value }): Statement.Fragment =>
          sql`(${column(attribute)} IS NOT NULL AND ${column(attribute)} ${sql.literal(operators[op])} ${value.value})`,
        InSet: ({ attribute, set }): Statement.Fragment =>
          sql`(${column(attribute)} IS NOT NULL AND ${column(attribute)} IN (${sets[set] ?? none}))`,
      });
    // A predicate reading a column the binding lacks lists nothing.
    const filter = (predicate: ReadScope.Predicate): Statement.Fragment =>
      Arr.some(ReadScope.attributes(predicate), (name) => binding.columns[name] === undefined)
        ? none
        : render(predicate);
    return Match.valueTags(narrowed, {
      AllowAll: () => allow,
      Deny: () => none,
      Filter: ({ predicate }) => filter(predicate),
    });
  });

const operators = { lt: "<", lte: "<=", gt: ">", gte: ">=" } as const;
