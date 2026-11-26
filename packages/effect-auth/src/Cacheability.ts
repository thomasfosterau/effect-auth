/**
 * What a shared, viewer-less cache asks of authorization, kept apart: may a
 * representation be served to any viewer ({@link publiclyServeable}), and must
 * this viewer bypass the cache ({@link bypassesForFreshness})? {@link
 * publicReach} derives the public types from the policies. A response rendered
 * for a resolved principal is `private, no-store`.
 *
 * @module cacheability
 */
import * as Effect from "effect/Effect";
import * as Arr from "effect/Array";
import * as Option from "effect/Option";
import * as P from "effect/Predicate";
import * as R from "effect/Record";
import * as Entity from "./Entity.ts";
import type * as Guard from "./Guard.ts";
import type * as Ladder from "./Ladder.ts";
import type * as Policy from "./Policy.ts";
import * as ReadScope from "./ReadScope.ts";

/**
 * One attribute a representation must carry for it to be served from a
 * viewer-less cache.
 *
 * - `{ attribute, equals }` — the attribute must equal `equals` exactly. When
 *   absent, the representation is not serveable unless `optional` is `true`
 *   (use `optional` only for an axis a family genuinely may not ride, never to
 *   paper over a projection that might drop it).
 * - `{ attribute, absent: true }` — the attribute must not be present at all
 *   (a tombstone's `deletedAt`: any value, `null` included, means not
 *   serveable).
 *
 * @since 0.1.0
 * @category models
 */
export type ServeableAxis =
  | {
      readonly attribute: string;
      readonly equals: string | number | boolean;
      readonly optional?: boolean;
    }
  | { readonly attribute: string; readonly absent: true };

/**
 * Whether a representation's attributes may be stored in, and served from, a
 * cache with no viewer in its key. Fails closed on every axis: a present
 * attribute must hold exactly the serveable literal, and a required one must be
 * present. A non-object representation is never serveable.
 *
 * @since 0.1.0
 * @category predicates
 */
export const publiclyServeable =
  (axes: ReadonlyArray<ServeableAxis>) =>
  (attributes: unknown): boolean => {
    if (!P.isObject(attributes)) {
      return false;
    }
    const record = attributes;
    return axes.every((axis) => {
      const present = Object.prototype.hasOwnProperty.call(record, axis.attribute);
      const value = record[axis.attribute];
      if ("absent" in axis) return !present;
      if (!present || value === undefined) return axis.optional === true;
      return value === axis.equals;
    });
  };

/**
 * Whether the current viewer must bypass a public-only cache to see fresh
 * data: true when they hold **any** of `axes` (typically the axes that see
 * private and soft-deleted material). Never fails; `false` for anonymous.
 *
 * Not an authorization gate: it only decides whom a public-only cache cannot
 * serve fresh.
 *
 * @since 0.1.0
 * @category predicates
 */
export const bypassesForFreshness = <Id, User extends Guard.ViewerShape, Rung extends string>(
  guards: Guard.Guards<Id, User, Rung>,
  axes: ReadonlyArray<NoInfer<Rung> | Ladder.Axis<NoInfer<Rung>>>,
): Effect.Effect<boolean, never, Id> =>
  Effect.map(guards.viewer, (viewer) =>
    axes.some((axis) => guards.decideRole(Option.getOrNull(viewer), axis)),
  );

/**
 * Whether a list should include soft-deleted rows: only when the request opts
 * in (`includeDeleted: true`) **and** the viewer holds `viewDeleted`. Asking
 * without the rung changes nothing, so no caller can page tombstones by
 * setting a flag.
 *
 * @since 0.1.0
 * @category predicates
 */
export const shouldIncludeDeleted =
  <Id, User extends Guard.ViewerShape, Rung extends string>(
    guards: Guard.Guards<Id, User, Rung>,
    viewDeleted: NoInfer<Rung> | Ladder.Axis<NoInfer<Rung>>,
  ) =>
  (input: { readonly includeDeleted?: boolean | undefined }): Effect.Effect<boolean, never, Id> =>
    input.includeDeleted === true ? guards.hasRoleAtLeast(viewDeleted) : Effect.succeed(false);

/**
 * How much of one resource type the anonymous principal may read, compiled
 * from the policies, so a model change that narrows a type fails a pinned
 * test. Only `All` lets a cache admit a
 * type wholesale; `Undecided` is never public.
 *
 * @since 0.2.0
 * @category models
 */
export type PublicReach =
  | { readonly _tag: "All" }
  | { readonly _tag: "Some"; readonly scope: ReadScope.ReadScope }
  | { readonly _tag: "None" }
  | { readonly _tag: "Undecided"; readonly reasons: ReadonlyArray<string> };

/**
 * Options for {@link publicReach}: the action decided (default
 * `Action::"read"`) and the principal standing for "any viewer" (default
 * `Anonymous::"anonymous"`, with no attributes and no parents, so a policy
 * that reads the principal's attributes cannot match it).
 *
 * @since 0.2.0
 * @category models
 */
export interface PublicReachOptions {
  readonly action?: Entity.EntityRef;
  readonly principal?: Entity.EntityRef;
}

/**
 * Compile one resource type's read scope for the anonymous principal and say
 * how much of the type it admits.
 *
 * @example
 * ```ts
 * import assert from "node:assert/strict"
 * import * as Auth from "@thomasfosterau/effect-auth"
 *
 * const { Cacheability, Condition, Policy } = Auth
 * const policies = [
 *   // Reference data: every row is public.
 *   Policy.permit({ id: "species", resource: Policy.isType("Species") }),
 *   // Owned material: only published public rows are.
 *   Policy.permit({
 *     id: "garden:public",
 *     resource: Policy.isType("Garden"),
 *     when: Condition.eq(Condition.attr("resource", "visibility"), Condition.lit("public")),
 *   }),
 * ]
 * const bindings = [
 *   { resourceType: "Species", attributes: {} },
 *   { resourceType: "Garden", attributes: { visibility: "Text" } },
 *   { resourceType: "Journal", attributes: {} },
 * ] as const
 *
 * // A test pins this: moving `Species` behind a role fails the build.
 * assert.deepEqual(Cacheability.publicReachByType(policies, bindings), {
 *   Species: "All",
 *   Garden: "Some",
 *   Journal: "None",
 * })
 * ```
 *
 * @since 0.2.0
 * @category drift guard
 */
export const publicReach = (
  policies: ReadonlyArray<Policy.DeclarativePolicy>,
  binding: ReadScope.Binding,
  options: PublicReachOptions = {},
): PublicReach => {
  const principal = Entity.entity(options.principal ?? Entity.ref("Anonymous", "anonymous"));
  const compiled = ReadScope.compile(policies, binding, {
    principal: principal.ref,
    action: options.action ?? Entity.ref("Action", "read"),
    slice: Entity.slice([principal]),
  });
  if (P.isTagged(compiled, "Inexact")) {
    return { _tag: "Undecided", reasons: compiled.reasons };
  }
  const { scope } = compiled;
  if (P.isTagged(scope, "AllowAll")) return { _tag: "All" };
  if (P.isTagged(scope, "Deny")) return { _tag: "None" };
  return { _tag: "Some", scope };
};

/**
 * {@link publicReach} for each binding, keyed by resource type, as just the
 * tag: the shape a drift-guard test pins.
 *
 * @since 0.2.0
 * @category drift guard
 */
export const publicReachByType = (
  policies: ReadonlyArray<Policy.DeclarativePolicy>,
  bindings: ReadonlyArray<ReadScope.Binding>,
  options: PublicReachOptions = {},
): Readonly<Record<string, PublicReach["_tag"]>> =>
  R.fromEntries(
    Arr.map(bindings, (binding) => [
      binding.resourceType,
      publicReach(policies, binding, options)._tag,
    ]),
  );
