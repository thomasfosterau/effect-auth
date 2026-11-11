/**
 * The client session as an `effect/reactivity` Atom graph
 * (`@thomasfosterau/effect-auth/client/atoms`).
 *
 * {@link makeSessionAtoms} turns an {@link AuthClient} into Atoms: the session
 * read (`GET /sessions/current?include=user`) as an `AsyncResult`, the states
 * derived from it (signed in, pending, last error), and the signed-in user's
 * session list. An application reads them through its own `AtomRegistry`, the
 * one its other Atoms live in, so auth and data share one graph and one
 * runtime: an Atom that reads `isSignedIn` or `data` recomputes when the user
 * signs in or out, with no invalidation list.
 *
 * Commands stay plain calls on the client (`client.signIn(...)`, ...). The
 * Atoms observe them through `client.onSessionChange`: each session-changing
 * call refetches the session while it is observed, and resolves once that
 * refetch has settled.
 *
 * This is a subpath of its own, apart from `./client`, because it imports
 * `effect` at runtime and `./client` stays free of it.
 *
 * @example
 * ```ts
 * import assert from "node:assert";
 * import { AtomRegistry } from "effect/reactivity";
 * import { createAuthClient } from "@thomasfosterau/effect-auth/client";
 * import { makeSessionAtoms } from "@thomasfosterau/effect-auth/client/atoms";
 * import { makeCookieJarFetch, makeServerFixture } from "@thomasfosterau/effect-auth/client/testing";
 *
 * const server = makeServerFixture();
 * const client = createAuthClient({
 *   baseUrl: "http://app.test",
 *   fetch: makeCookieJarFetch(server.handler),
 * });
 * const registry = AtomRegistry.make();
 * const session = makeSessionAtoms(client);
 *
 * // Observing the session starts its first read; it is pending until then.
 * const seen: Array<boolean> = [];
 * const unsubscribe = registry.subscribe(session.isSignedIn, (signedIn) => seen.push(signedIn), {
 *   immediate: true,
 * });
 * assert.strictEqual(registry.get(session.isPending), true);
 *
 * // A command resolves once the observed session has refetched.
 * await client.signUp({ email: "ada@app.test", password: "correct horse battery" });
 * assert.strictEqual(registry.get(session.isSignedIn), true);
 * assert.strictEqual(registry.get(session.data)?.user.email, "ada@app.test");
 *
 * await client.signOut();
 * assert.strictEqual(registry.get(session.isSignedIn), false);
 * assert.deepStrictEqual(seen, [false, true, false]);
 *
 * unsubscribe();
 * registry.dispose();
 * ```
 *
 * @module client/atoms
 */
import { Effect, Option, Predicate } from "effect";
import { AsyncResult, Atom, type AtomRegistry } from "effect/reactivity";
import type * as Http from "../http/index.ts";
import { type AuthClient, AuthClientError } from "./Client.ts";

/** The session read: the session and its user, or `null` when signed out. */
export type SessionResult = AsyncResult.AsyncResult<
  Http.SessionWithUserView | null,
  AuthClientError
>;

/** The signed-in user's sessions (`GET /sessions`). */
export type SessionListResult = AsyncResult.AsyncResult<
  readonly Http.SessionView[],
  AuthClientError
>;

/** A snapshot of the session read, for templates that want plain fields. */
export interface SessionState {
  /** The authenticated session + user, or `null` when signed out (or not read yet). */
  readonly data: Http.SessionWithUserView | null;
  /** `true` from the first read until it settles, and while a refetch is in flight. */
  readonly isPending: boolean;
  /** The last unexpected error (a `401` is `data: null`, not an error). */
  readonly error: AuthClientError | null;
}

/** A snapshot of the session list, shaped like {@link SessionState}. */
export interface SessionListState {
  /** The sessions, or `null` before the first list arrives. */
  readonly data: readonly Http.SessionView[] | null;
  /** `true` while the list is being read. */
  readonly isPending: boolean;
  /** The last error reading the list. */
  readonly error: AuthClientError | null;
}

/** Options for opt-in background session refresh. Every feature is off by default. */
export interface RefreshOptions {
  /**
   * Refetch the session every `intervalMs` milliseconds while it is observed:
   * the interval starts with the first subscriber and stops with the last.
   */
  readonly intervalMs?: number | undefined;
  /**
   * Refetch when the window gains focus or the tab becomes visible. A no-op
   * outside a browser.
   */
  readonly onFocus?: boolean | undefined;
  /**
   * Mirror session changes across browser tabs via `BroadcastChannel`: `true`
   * for the default channel name (`"effect-auth-session"`), or a string for a
   * custom one (when several auth clients share a page). A tab that receives a
   * session takes it as is, without a request, and does not echo it. A no-op
   * where `BroadcastChannel` is unavailable.
   */
  readonly crossTab?: boolean | string | undefined;
}

/** Options for {@link makeSessionAtoms}. */
export interface SessionAtomsOptions {
  /** Opt-in background refresh while the session is observed. */
  readonly refresh?: RefreshOptions | undefined;
}

/**
 * The session Atoms over one client. Every Atom is lazy: nothing is fetched
 * until a registry reads or mounts one. Refreshing any session Atom
 * (`registry.refresh(atoms.isSignedIn)`, say) refetches the session read;
 * `registry.refresh(atoms.sessions)` refetches the list.
 */
export interface SessionAtoms {
  /**
   * The session read. It starts waiting (`Initial`); a `401` is
   * `Success(null)`; a failure keeps the last session as its previous success;
   * a refetch keeps the current value, marked waiting; and a refetch
   * superseded by a later one is interrupted, so its answer never lands.
   */
  readonly result: Atom.Atom<SessionResult>;
  /** {@link result} as `{ data, isPending, error }`. */
  readonly state: Atom.Atom<SessionState>;
  /** The current session and user (kept through a failed refetch), or `null`. */
  readonly data: Atom.Atom<Http.SessionWithUserView | null>;
  /** Whether {@link data} holds a session. `false` while the first read is pending. */
  readonly isSignedIn: Atom.Atom<boolean>;
  /** Whether the session read is in flight. */
  readonly isPending: Atom.Atom<boolean>;
  /** The last unexpected error reading the session, or `null`. */
  readonly error: Atom.Atom<AuthClientError | null>;
  /**
   * The signed-in user's sessions. It depends on the session's id, so a
   * sign-in, sign-out or switch of account refetches it through the graph;
   * signed out, it is empty without a request.
   */
  readonly sessions: Atom.Atom<SessionListResult>;
  /** {@link sessions} as `{ data, isPending, error }`. */
  readonly sessionsState: Atom.Atom<SessionListState>;
}

const DEFAULT_CHANNEL = "effect-auth-session";

/** What a tab posts on the cross-tab channel. */
interface SessionMessage {
  readonly data: Http.SessionWithUserView | null;
}

/** Any rejection as an {@link AuthClientError}; status `0` for one that never reached the server. */
const toClientError = (cause: unknown): AuthClientError =>
  cause instanceof AuthClientError
    ? cause
    : new AuthClientError(
        0,
        Predicate.hasProperty(cause, "message") && Predicate.isString(cause.message)
          ? cause.message
          : String(cause),
      );

/**
 * Lay the read's next value over the one on show, which a cross-tab message
 * may have replaced: a waiting value keeps what is shown, and a failure keeps
 * the latest session shown as its previous success.
 */
const merge = (shown: Option.Option<SessionResult>, next: SessionResult): SessionResult => {
  if (next.waiting) return Option.isSome(shown) ? AsyncResult.waitingFrom(shown) : next;
  if (AsyncResult.isFailure(next)) {
    return AsyncResult.failureWithPrevious(next.cause, {
      previous: Option.orElse(shown, () => Option.some(next)),
    });
  }
  return next;
};

/** Resolve once `atom`'s result in `registry` is no longer waiting. */
const settled = <A, E>(
  registry: AtomRegistry.AtomRegistry,
  atom: Atom.Atom<AsyncResult.AsyncResult<A, E>>,
): Promise<void> =>
  new Promise((resolve) => {
    if (!registry.get(atom).waiting) {
      resolve();
      return;
    }
    const unsubscribe = registry.subscribe(atom, (result) => {
      if (result.waiting) return;
      unsubscribe();
      resolve();
    });
  });

const stateOf = <A>(
  result: AsyncResult.AsyncResult<A, AuthClientError>,
): {
  readonly data: A | null;
  readonly isPending: boolean;
  readonly error: AuthClientError | null;
} => ({
  data: Option.getOrNull(AsyncResult.value(result)),
  isPending: result.waiting,
  error: Option.getOrNull(AsyncResult.error(result)),
});

/**
 * Build the session Atoms over `client`. Make them once per client (at module
 * scope, or once per app) and read them through the application's registry:
 * two calls give two independent graphs, each with its own session read.
 *
 * While {@link SessionAtoms.result} (or any Atom derived from it) is mounted,
 * the graph listens to `client.onSessionChange`, refetching the session on
 * each session-changing call, and runs the opt-in `refresh` features; it
 * stops when the last subscriber leaves. The last session read is kept for
 * the next subscriber, so remounting does not refetch: a sign-in made while
 * nothing observed the session shows on the next refresh or session-changing
 * call.
 */
export const makeSessionAtoms = (
  client: AuthClient,
  options: SessionAtomsOptions = {},
): SessionAtoms => {
  const refresh = options.refresh ?? {};

  // The read itself, kept alive so a later subscriber starts from the last
  // session rather than a fresh pending read. Refreshing it interrupts a read
  // still in flight, which is what drops an out-of-order answer.
  const read = Atom.keepAlive(
    Atom.make(Effect.tryPromise({ try: () => client.getSession(), catch: toClientError })),
  );

  // The observed session: the read, plus everything that lives only while
  // something observes the session (the session-change listener and the
  // refresh features). Refreshing it refreshes `read`.
  const result: Atom.Atom<SessionResult> = Atom.transform(read, (get) => {
    const registry = get.registry;
    const refetch = (): Promise<void> => {
      registry.refresh(read);
      return settled(registry, read);
    };
    let channel: BroadcastChannel | undefined;

    get.subscribe(read, (next) => {
      get.setSelf(merge(get.self<SessionResult>(), next));
      if (channel !== undefined && AsyncResult.isSuccess(next) && !next.waiting) {
        const message: SessionMessage = { data: next.value };
        channel.postMessage(message);
      }
    });
    get.addFinalizer(client.onSessionChange(refetch));

    if (refresh.intervalMs !== undefined && refresh.intervalMs > 0) {
      const interval = setInterval(() => void refetch(), refresh.intervalMs);
      get.addFinalizer(() => clearInterval(interval));
    }

    if (refresh.onFocus === true) {
      const onFocus = (): void => void refetch();
      const onVisibilityChange = (): void => {
        if (globalThis.document.visibilityState === "visible") void refetch();
      };
      if (globalThis.window !== undefined) {
        globalThis.window.addEventListener("focus", onFocus);
        get.addFinalizer(() => globalThis.window.removeEventListener("focus", onFocus));
      }
      if (globalThis.document !== undefined) {
        globalThis.document.addEventListener("visibilitychange", onVisibilityChange);
        get.addFinalizer(() =>
          globalThis.document.removeEventListener("visibilitychange", onVisibilityChange),
        );
      }
    }

    if (
      refresh.crossTab !== undefined &&
      refresh.crossTab !== false &&
      globalThis.BroadcastChannel !== undefined
    ) {
      const opened = new BroadcastChannel(
        refresh.crossTab === true ? DEFAULT_CHANNEL : refresh.crossTab,
      );
      opened.addEventListener("message", (event: MessageEvent<SessionMessage>) => {
        get.setSelf(AsyncResult.success(event.data.data));
      });
      channel = opened;
      get.addFinalizer(() => opened.close());
    }

    return get.once(read);
  });

  const state = Atom.map(result, stateOf);
  const data = Atom.map(result, (current) => Option.getOrNull(AsyncResult.value(current)));
  const isSignedIn = Atom.map(data, (current) => current !== null);
  const isPending = Atom.map(result, (current) => current.waiting);
  const error = Atom.map(result, (current) => Option.getOrNull(AsyncResult.error(current)));

  // The session's identity: `undefined` until the first read settles, then
  // the session id or `null`. A string compares by value, so a refetch that
  // returns the same session does not reach the list.
  const sessionId = Atom.make((get): string | null | undefined => {
    const current = get(result);
    if (AsyncResult.isInitial(current)) return undefined;
    return Option.getOrNull(AsyncResult.value(current))?.session.id ?? null;
  });

  const sessions: Atom.Atom<SessionListResult> = Atom.make(
    (get): Effect.Effect<readonly Http.SessionView[], AuthClientError> => {
      const id = get(sessionId);
      if (id === undefined) return Effect.never;
      if (id === null) return Effect.succeed<readonly Http.SessionView[]>([]);
      return Effect.tryPromise({ try: () => client.listSessions(), catch: toClientError });
    },
  );
  const sessionsState = Atom.map(sessions, stateOf);

  return { result, state, data, isSignedIn, isPending, error, sessions, sessionsState };
};
