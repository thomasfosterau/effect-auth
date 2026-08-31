/**
 * Thin helpers for driving a **real** Alchemy v2 provider outside the engine.
 *
 * Everything describing Alchemy's resource model — `Resource`, `Provider`,
 * `ProviderService`, `Diff`, `ResourceLike` — comes from the `alchemy` package
 * itself; this module deliberately declares none of it. The resource in
 * `./AuthSchema.ts` is a genuine `Alchemy.Resource` and its provider is built
 * with `Provider.succeed`, so it mounts in an Alchemy program exactly like
 * `Cloudflare.D1.Database` or `Alchemy.Random` do.
 *
 * What Alchemy has no equivalent for is running *one* provider's lifecycle
 * against *one* set of props without standing up the engine. The real
 * equivalent of "apply this resource" is a full stack —
 * `Alchemy.Stack(name, { providers, state }, program)` driven by `deploy` /
 * `destroy` (see `alchemy/Deploy`, `alchemy/Destroy`, or the `alchemy/Test`
 * harness) — which brings a state store, a plan, a CLI session, platform
 * services and credential resolution with it. That is the right tool for a
 * deployment and the wrong tool for a migration script or a unit test that
 * only wants to know whether the schema DDL converges against one database.
 *
 * So {@link provision} and {@link deprovision} stay as package-local helpers.
 * They are *not* a model of Alchemy: every type below is derived from the real
 * {@link ProviderService} signatures, they call the provider's actual
 * lifecycle operations, and all they add is the engine-supplied bookkeeping
 * those operations require (`fqn`, `instanceId`, `bindings`, and a status
 * session).
 */

import { Effect } from "effect";
import type { Diff } from "alchemy/Diff";
import type { ProviderService } from "alchemy/Provider";
import type { ResourceLike } from "alchemy/Resource";
import type { ScopedPlanStatusSession } from "alchemy/Cli/Cli";

/**
 * The props shape a provider's lifecycle operations receive, derived from
 * `ProviderService<R>` itself rather than restated.
 */
export type ProviderProps<R extends ResourceLike> = Parameters<
  ProviderService<R>["reconcile"]
>[0]["news"];

/**
 * A do-nothing {@link ScopedPlanStatusSession}.
 *
 * The engine hands providers a live session so `reconcile` / `delete` can
 * report progress to the CLI. Outside the engine there is nothing to report
 * to, so every call is discarded.
 */
export const silentSession: ScopedPlanStatusSession = {
  emit: () => Effect.void,
  done: () => Effect.void,
  note: () => Effect.void,
};

/**
 * The state the engine carries between applies for a single resource: the
 * props it was last reconciled with and the attributes it returned. Pass one
 * to {@link provision} to model a subsequent apply, or to {@link deprovision}
 * to tear the resource down.
 */
export interface ResourceState<R extends ResourceLike> {
  readonly props: ProviderProps<R>;
  readonly output: R["Attributes"];
}

/** Identity the engine would otherwise assign to a resource instance. */
export interface ResourceIdentity {
  /** The logical id the resource is declared with, e.g. `"auth-schema"`. */
  readonly id: string;
  /**
   * Fully-qualified name (namespace path + logical id). Defaults to
   * {@link ResourceIdentity.id} when the resource is not namespaced.
   */
  readonly fqn?: string;
  /** Physical instance id. Defaults to {@link ResourceIdentity.id}. */
  readonly instanceId?: string;
}

/**
 * The engine collects a resource's bindings while planning and hands them to
 * each lifecycle operation. A standalone run has none. `BindingData<R>` stays
 * deferred for a generic `R`, so the empty array is cast to whatever the
 * operation being called expects.
 */
const noBindings = <T>(): T => [] as unknown as T;

const identity = (ref: ResourceIdentity): { id: string; fqn: string; instanceId: string } => ({
  id: ref.id,
  fqn: ref.fqn ?? ref.id,
  instanceId: ref.instanceId ?? ref.id,
});

/**
 * Run a provider's create/update lifecycle outside the Alchemy engine.
 *
 * Pass `prior` to model a subsequent apply (update/replace); omit it for a
 * first-time create. This mirrors what the engine does — read live state, diff
 * against the previous props, replace if the diff demands it, then reconcile —
 * and returns the fresh attributes. Inside a real Alchemy program the engine
 * performs these steps for you.
 */
export const provision = <R extends ResourceLike>(
  provider: ProviderService<R>,
  ref: ResourceIdentity,
  props: ProviderProps<R>,
  prior?: ResourceState<R>,
): Effect.Effect<R["Attributes"], unknown> =>
  Effect.gen(function* () {
    const self = identity(ref);
    if (prior !== undefined) {
      const read = provider.read;
      const live =
        read === undefined
          ? undefined
          : yield* read({ ...self, olds: props, output: prior.output });

      const diff = provider.diff;
      const decision =
        diff === undefined
          ? undefined
          : ((yield* diff({
              ...self,
              olds: prior.props,
              news: props,
              oldBindings: noBindings(),
              newBindings: noBindings(),
              output: prior.output,
            })) as Diff | undefined);

      if (live !== undefined && decision?.action === "replace") {
        yield* provider.delete({
          ...self,
          olds: prior.props,
          output: prior.output,
          session: silentSession,
          bindings: noBindings(),
        });
      }
    }
    return yield* provider.reconcile({
      ...self,
      news: props,
      olds: prior?.props,
      output: prior?.output,
      session: silentSession,
      bindings: noBindings(),
    });
  });

/**
 * Run a provider's delete lifecycle outside the Alchemy engine — the teardown
 * counterpart to {@link provision}.
 */
export const deprovision = <R extends ResourceLike>(
  provider: ProviderService<R>,
  ref: ResourceIdentity,
  state: ResourceState<R>,
): Effect.Effect<void, unknown> =>
  provider.delete({
    ...identity(ref),
    olds: state.props,
    output: state.output,
    session: silentSession,
    bindings: noBindings(),
  });
