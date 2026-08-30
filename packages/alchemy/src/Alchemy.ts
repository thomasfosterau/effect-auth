/**
 * A minimal, structural model of the slice of Alchemy v2's resource API that
 * the providers in this package target.
 *
 * Alchemy v2 (https://v2.alchemy.run) is the Effect-based, TypeScript-native
 * Infrastructure-as-Code toolkit. In its model a *resource* is a typed Effect
 * described by three things — a string `type` tag, an input `Props` shape and
 * an output `Attributes` shape — and a *provider* drives that resource's
 * lifecycle through four operations:
 *
 * - {@link Provider.read} — look up the resource's live state and report what
 *   currently exists, or `undefined` when it does not.
 * - {@link Provider.diff} — compare the desired props against the previous ones
 *   and decide whether the change is a no-op, an in-place update, or a full
 *   replacement.
 * - {@link Provider.reconcile} — make the world match the desired state through
 *   a single observe-ensure-sync flow that covers first-time creation, updates
 *   and adoption, then returns the output attributes.
 * - {@link Provider.delete} — remove the resource; it must be idempotent, so
 *   "already gone" counts as success.
 *
 * This module does **not** import `alchemy`. Just as this package models the
 * Cloudflare D1 client with a small structural interface (see `./D1.ts`) rather
 * than depending on `@cloudflare/workers-types`, these types capture the
 * lifecycle *contract* so the providers stay dependency-free and fully
 * testable. In a real Alchemy v2 program you mount a provider with
 * `Layer.effect(Provider, ...)`; see the package README. The
 * {@link provision} / {@link deprovision} helpers run the same contract outside
 * the engine, which is handy for tests and one-off migrations.
 */

import { Effect } from "effect";

/**
 * Identity assigned to a resource instance by the Alchemy engine. The
 * `logicalId` is the stable name a resource is declared with in a program.
 */
export interface ResourceId {
  readonly logicalId: string;
}

/**
 * Outcome of {@link Provider.diff}.
 *
 * - `"noop"` — desired props match the previous ones; nothing to do.
 * - `"update"` — apply the change in place by running {@link Provider.reconcile}.
 * - `"replace"` — the change is immutable; delete and recreate the resource.
 */
export type DiffResult = "noop" | "update" | "replace";

/** Arguments passed to {@link Provider.read}. */
export interface ReadArgs<Props, Attributes> {
  readonly id: ResourceId;
  /** The desired props, which carry any bound dependencies (e.g. a database). */
  readonly props: Props;
  /** The last attributes the engine cached for this resource, if any. */
  readonly output: Attributes | undefined;
}

/** Arguments passed to {@link Provider.diff}. */
export interface DiffArgs<Props> {
  readonly id: ResourceId;
  /** The desired props. */
  readonly news: Props;
  /** The previously applied props. */
  readonly olds: Props;
}

/** Arguments passed to {@link Provider.reconcile}. */
export interface ReconcileArgs<Props, Attributes> {
  readonly id: ResourceId;
  /** The desired props. */
  readonly news: Props;
  /** The previously applied props, or `undefined` on first creation. */
  readonly olds: Props | undefined;
  /** Cached stable attributes from a previous apply, never assumed to exist. */
  readonly output: Attributes | undefined;
}

/** Arguments passed to {@link Provider.delete}. */
export interface DeleteArgs<Props, Attributes> {
  readonly id: ResourceId;
  /** The last applied props, which carry any bound dependencies. */
  readonly props: Props;
  /** The last attributes the engine cached for this resource, if any. */
  readonly output: Attributes | undefined;
}

/**
 * The lifecycle a provider implements for a resource. `Props` is the input
 * shape, `Attributes` the output shape, `E` the error channel and `R` the
 * Effect requirements (usually `never` here, since the bound dependencies are
 * carried in `Props`).
 */
export interface Provider<Props, Attributes, E = never, R = never> {
  /**
   * Look up the resource's live state. Returns the observed attributes, or
   * `undefined` when the resource does not exist.
   */
  readonly read: (args: ReadArgs<Props, Attributes>) => Effect.Effect<Attributes | undefined, E, R>;

  /**
   * Decide how a props change should be applied. Pure — it inspects only the
   * desired and previous props, never live state.
   */
  readonly diff: (args: DiffArgs<Props>) => DiffResult;

  /**
   * Make the world match the desired state and return the fresh attributes.
   * Must be idempotent: running it twice converges to the same result.
   */
  readonly reconcile: (args: ReconcileArgs<Props, Attributes>) => Effect.Effect<Attributes, E, R>;

  /**
   * Remove the resource. Must be idempotent — deleting something that is
   * already gone succeeds.
   */
  readonly delete: (args: DeleteArgs<Props, Attributes>) => Effect.Effect<void, E, R>;
}

/**
 * A declared resource: the `type` tag plus phantom `Props`/`Attributes` types
 * that flow through to its {@link Provider}. Created with {@link Resource}.
 */
export interface Resource<Type extends string, Props, Attributes> {
  readonly type: Type;
  /** Phantom marker for the input props shape — not present at runtime. */
  readonly _props?: Props;
  /** Phantom marker for the output attributes shape — not present at runtime. */
  readonly _attributes?: Attributes;
}

/**
 * Declare a resource type. The string tag should be globally unique and
 * namespaced, e.g. `"effect-auth::AuthSchema"`.
 */
export const Resource = <Type extends string, Props, Attributes>(
  type: Type,
): Resource<Type, Props, Attributes> => ({ type });

/**
 * The state the engine carries between applies for a single resource: the props
 * it was last reconciled with and the attributes it returned.
 */
export interface ResourceState<Props, Attributes> {
  readonly props: Props;
  readonly output: Attributes;
}

/**
 * Run a provider's create/update lifecycle outside the Alchemy engine.
 *
 * Pass `prior` to model a subsequent apply (update/replace); omit it for a
 * first-time create. This mirrors what the engine does — read live state, diff
 * against the previous props, replace if required, then reconcile — and is the
 * entry point used by the standalone helpers and the test-suite. Inside a real
 * Alchemy program the engine performs these steps for you.
 */
export const provision = <Props, Attributes, E, R>(
  provider: Provider<Props, Attributes, E, R>,
  id: ResourceId,
  props: Props,
  prior?: ResourceState<Props, Attributes>,
): Effect.Effect<Attributes, E, R> =>
  Effect.gen(function* () {
    if (prior !== undefined) {
      const live = yield* provider.read({ id, props, output: prior.output });
      if (
        live !== undefined &&
        provider.diff({ id, news: props, olds: prior.props }) === "replace"
      ) {
        yield* provider.delete({ id, props: prior.props, output: prior.output });
      }
    }
    return yield* provider.reconcile({
      id,
      news: props,
      olds: prior?.props,
      output: prior?.output,
    });
  });

/**
 * Run a provider's delete lifecycle outside the Alchemy engine — the teardown
 * counterpart to {@link provision}.
 */
export const deprovision = <Props, Attributes, E, R>(
  provider: Provider<Props, Attributes, E, R>,
  id: ResourceId,
  state: ResourceState<Props, Attributes>,
): Effect.Effect<void, E, R> => provider.delete({ id, props: state.props, output: state.output });
