/**
 * A cached remote key set: a JWKS fetched once per `ttlMs`, refetched early
 * for a `kid` it does not hold at most once per `minRefreshIntervalMs`, and
 * kept when a refetch fails, so neither forged `kid`s nor a stalled endpoint
 * turn every verification into a fetch. Refetches are serialised.
 */
import * as Clock from "effect/Clock";
import * as Context from "effect/Context";
import * as Effect from "effect/Effect";
import * as SynchronizedRef from "effect/SynchronizedRef";
import * as HashMap from "effect/HashMap";
import * as Option from "effect/Option";
import * as Result from "effect/Result";
import type * as Types from "./Types.ts";

/** How long keys are fresh, and the least time between two fetches. */
export interface KeySetTiming {
  readonly ttlMs: number;
  readonly minRefreshIntervalMs: number;
}

/** Five minutes fresh; a forced refetch at most every 30 seconds. */
const defaultTiming: KeySetTiming = { ttlMs: 5 * 60_000, minRefreshIntervalMs: 30_000 };

/** The keys a key set holds, and when it last fetched and tried to. */
interface State {
  readonly keys: ReadonlyArray<Types.JsonObject>;
  readonly fetchedAt: number;
  readonly attemptedAt: number;
}

/** The key the lookup picks from a set, or `undefined`. */
export type Pick = (keys: ReadonlyArray<Types.JsonObject>) => Types.JsonObject | undefined;

/** A cached key set over one JWKS endpoint. */
export interface KeySet<E> {
  /**
   * The key `pick` chooses, refetching when the keys are stale or hold no
   * such key (within the refetch interval). `undefined` when none matches.
   * Fails only when no key matches and the fetch failed.
   */
  readonly key: (pick: Pick) => Effect.Effect<Types.JsonObject | undefined, E>;
}

const emptyState: Effect.Effect<SynchronizedRef.SynchronizedRef<State>> =
  SynchronizedRef.make<State>({
    keys: [],
    fetchedAt: Number.NEGATIVE_INFINITY,
    attemptedAt: Number.NEGATIVE_INFINITY,
  });

/** A key set over `fetch` that keeps its keys in `ref`. */
const over = <E>(
  ref: SynchronizedRef.SynchronizedRef<State>,
  fetch: Effect.Effect<ReadonlyArray<Types.JsonObject>, E>,
  timing: KeySetTiming,
): KeySet<E> => {
  const key = (pick: Pick): Effect.Effect<Types.JsonObject | undefined, E> =>
    Effect.gen(function* () {
      const now = yield* Clock.currentTimeMillis;
      const current = yield* SynchronizedRef.get(ref);
      const cached = pick(current.keys);
      if (cached !== undefined && now - current.fetchedAt < timing.ttlMs) return cached;

      return yield* SynchronizedRef.modifyEffect(ref, (state) =>
        Effect.gen(function* () {
          const known = pick(state.keys);
          // Another fiber may have refetched while this one waited.
          if (known !== undefined && now - state.fetchedAt < timing.ttlMs) {
            return [known, state] as const;
          }
          if (now - state.attemptedAt < timing.minRefreshIntervalMs) {
            return [known, state] as const;
          }
          const fetched = yield* Effect.result(fetch);
          if (Result.isFailure(fetched)) {
            // Keep serving keys fetched before: a fetch fault must not
            // fail every token the old keys still verify.
            const next = { ...state, attemptedAt: now };
            if (known !== undefined) return [known, next] as const;
            return yield* Effect.fail(fetched.failure);
          }
          const next = { keys: fetched.success, fetchedAt: now, attemptedAt: now };
          return [pick(next.keys), next] as const;
        }),
      );
    });

  return { key };
};

/** A key set over `fetch`, empty until the first lookup. */
export const make = <E>(
  fetch: Effect.Effect<ReadonlyArray<Types.JsonObject>, E>,
  timing: KeySetTiming = defaultTiming,
): Effect.Effect<KeySet<E>> => Effect.map(emptyState, (ref) => over(ref, fetch, timing));

/**
 * Key sets by JWKS URL, built on first use. For verifiers whose endpoints are
 * configured per provider (OAuth, SSO connections, Google One Tap).
 */
export class KeySets extends Context.Service<
  KeySets,
  {
    readonly forUrl: <E>(
      url: string,
      fetch: Effect.Effect<ReadonlyArray<Types.JsonObject>, E>,
    ) => Effect.Effect<KeySet<E>>;
  }
>()("@effect-auth/RemoteJwks/KeySets") {}

/** A {@link KeySets} with `timing` for every URL. */
export const makeKeySets = (
  timing: KeySetTiming = defaultTiming,
): Effect.Effect<typeof KeySets.Service> =>
  Effect.gen(function* () {
    const sets = yield* SynchronizedRef.make(
      HashMap.empty<string, SynchronizedRef.SynchronizedRef<State>>(),
    );
    return {
      // Callers share a URL's keys; each lookup refetches through its own
      // caller's `fetch`, so its failure keeps that caller's error type.
      forUrl: <E>(url: string, fetch: Effect.Effect<ReadonlyArray<Types.JsonObject>, E>) =>
        SynchronizedRef.modifyEffect(sets, (map) =>
          Option.match(HashMap.get(map, url), {
            onSome: (existing) => Effect.succeed([existing, map] as const),
            onNone: () =>
              Effect.map(emptyState, (ref) => [ref, HashMap.set(map, url, ref)] as const),
          }),
        ).pipe(Effect.map((ref) => over(ref, fetch, timing))),
    };
  });
