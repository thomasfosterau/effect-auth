/**
 * Two questions a shared, viewer-less cache (a KV read-through cache, a CDN,
 * a service-worker cache keyed by URL) asks of authorization — kept apart,
 * because collapsing them is how a private row ends up in the cache.
 *
 * 1. **May this representation be stored where any viewer can be served it?**
 *    ({@link publiclyServeable}) A property of the *representation*: is it
 *    identical for every possible viewer, anonymous included? Checked on the
 *    write path and again on every hit, whoever the viewer is.
 * 2. **May this viewer be served from that cache?** ({@link bypassesForFreshness})
 *    A property of the *viewer*: a hit is a public-only snapshot, so a viewer
 *    entitled to more (private or deleted material) must be routed around the
 *    cache to the database. This is not an authorization gate and not the
 *    cache's safety property — it only decides who a cache cannot be fresh for.
 *
 * ### Conservative by construction
 *
 * {@link publiclyServeable} answers from a declared list of axes, and every
 * axis fails closed: an axis whose attribute is present must hold **exactly**
 * the serveable literal — `null`, `""`, or a state a later schema change
 * introduces are all "not serveable" — and a required axis whose attribute is
 * *absent* is not serveable either, because a projection that dropped the one
 * attribute deciding who may see the row must not read as public.
 * {@link OwnedAccess.serveableAxes} are the axes derived from the owned-read
 * policy (visibility required; draft optional, since a leaf without the axis
 * never emits it), and the tests pin that a representation they admit is
 * visible to every viewer, anonymous included.
 *
 * ### The `Cache-Control` corollary
 *
 * A response rendered after a principal was resolved is `private, no-store`,
 * unconditionally — whatever {@link publiclyServeable} says about the resource
 * inside it, because the rendering (per-viewer `meta.canEdit`, a private field
 * the viewer may see) is the viewer's. The ordering is what makes that
 * enforceable: decide cacheability *before* resolving the viewer, or mark the
 * response `private, no-store` the moment one is resolved. Marking an
 * admin-rendered response cacheable would let the platform serve it to
 * anonymous visitors on a later hit — a hit the Worker, and its auth check,
 * never runs for.
 *
 * ### A drift guard instead of an allow-list
 *
 * A client-side cache that admits whole resource types (a service worker's
 * list of "public" types) restates the read policy as a string array, and a
 * type that moves from public to owned silently stays on it.
 * {@link publicReach} derives the list from the policies instead. It compiles
 * each type's read scope for the anonymous principal: `All` when every row is
 * public, `Some` when only the rows a filter admits are (check each
 * representation with {@link publiclyServeable}), `None` when no row is, and
 * `Undecided` when the policies read rows in a way a scope can't express,
 * which a cache treats as `None`. Pin the result in a test, and a model change
 * that narrows a type fails the build.
 *
 * @module cacheability
 */
import { Array as Arr, Effect, Option, Predicate, Record as Rec } from "effect";
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
 * cache with no viewer in its key. Fails closed on every axis — see the
 * module docs. A non-object representation is never serveable.
 *
 * @since 0.1.0
 * @category predicates
 */
export const publiclyServeable =
  (axes: ReadonlyArray<ServeableAxis>) =>
  (attributes: unknown): boolean => {
    if (!Predicate.isObject(attributes)) {
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
 * Not an authorization gate — see the module docs.
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
 * from the policies (see the module docs). Only `All` lets a cache admit a
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
  readonly action?: Entity.EntityRef | undefined;
  readonly principal?: Entity.EntityRef | undefined;
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
  if (Predicate.isTagged(compiled, "Inexact")) {
    return { _tag: "Undecided", reasons: compiled.reasons };
  }
  const { scope } = compiled;
  if (Predicate.isTagged(scope, "AllowAll")) return { _tag: "All" };
  if (Predicate.isTagged(scope, "Deny")) return { _tag: "None" };
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
  Rec.fromEntries(
    Arr.map(bindings, (binding) => [
      binding.resourceType,
      publicReach(policies, binding, options)._tag,
    ]),
  );
