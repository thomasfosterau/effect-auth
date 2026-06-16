/**
 * The {@link WorkOS} Effect service: an Effect-native facade over the WorkOS
 * Node SDK that exposes the *entire* WorkOS feature set.
 *
 * Every WorkOS module (`sso`, `userManagement`, `directorySync`,
 * `organizations`, `multiFactorAuth`, `auditLogs`, `events`, `webhooks`,
 * `authorization` (FGA), `vault`, `widgets`, `adminPortal`, `passwordless`,
 * `organizationDomains`, `actions`, `apiKeys`, `connect`, `featureFlags`,
 * `groups`, `pipes`, `radar`, ...) is re-exposed with the exact same method
 * signatures, except that every method now returns an
 * `Effect<Result, WorkOSError>` instead of a `Promise<Result>`.
 *
 * Because the wrappers are derived from the SDK's own types via the
 * {@link Effectified} mapped type, the surface stays in lock-step with the
 * installed `@workos-inc/node` version — new endpoints become available
 * automatically with no extra code here.
 *
 * @example
 * import { Effect } from "effect"
 * import { WorkOS } from "@effect-auth/workos"
 *
 * const program = Effect.gen(function* () {
 *   const workos = yield* WorkOS
 *   const org = yield* workos.organizations.createOrganization({ name: "Acme" })
 *   return org
 * })
 *
 * program.pipe(Effect.provide(WorkOS.layer))
 */

import { Config, Context, Effect, Layer, Option, Redacted } from "effect";
import { WorkOS as WorkOSSDK } from "@workos-inc/node";
import type { WorkOSOptions } from "@workos-inc/node";
import { toWorkOSError, WorkOSError } from "./Errors.js";

/** The underlying WorkOS Node SDK client instance type. */
export type WorkOSClient = WorkOSSDK;

/**
 * The set of WorkOS SDK modules exposed by the service. Listing them as a
 * `satisfies ReadonlyArray<keyof WorkOSClient>` keeps the runtime iteration and
 * the static types in sync, and makes the compiler reject typos.
 */
const MODULE_KEYS = [
  "actions",
  "apiKeys",
  "auditLogs",
  "authorization",
  "connect",
  "directorySync",
  "events",
  "featureFlags",
  "groups",
  "multiFactorAuth",
  "organizations",
  "organizationDomains",
  "passwordless",
  "pipes",
  "radar",
  "adminPortal",
  "sso",
  "userManagement",
  "vault",
  "webhooks",
  "widgets",
] as const satisfies ReadonlyArray<keyof WorkOSClient>;

/** A WorkOS SDK module name, e.g. `"sso"` or `"userManagement"`. */
export type WorkOSModuleKey = (typeof MODULE_KEYS)[number];

/**
 * Maps a WorkOS SDK module type to its Effect-returning equivalent: every method
 * `(...args) => Promise<R>` (or `(...args) => R`) becomes
 * `(...args) => Effect<R, WorkOSError>`. Non-method properties are preserved.
 */
export type Effectified<T> = {
  readonly [K in keyof T]: T[K] extends (...args: infer Args) => infer R
    ? (...args: Args) => Effect.Effect<Awaited<R>, WorkOSError>
    : T[K];
};

/** The effectified WorkOS modules, keyed by module name. */
export type WorkOSModules = {
  readonly [K in WorkOSModuleKey]: Effectified<WorkOSClient[K]>;
};

/**
 * The shape of the {@link WorkOS} service.
 *
 * In addition to every effectified module it exposes:
 * - `client`: the raw WorkOS SDK instance, an escape hatch for anything not yet
 *   surfaced (e.g. the low-level `get`/`post` helpers).
 * - `use`: run an arbitrary call against the raw client as an Effect.
 */
export interface WorkOSService extends WorkOSModules {
  /** The underlying WorkOS Node SDK client. */
  readonly client: WorkOSClient;
  /**
   * Run an arbitrary operation against the raw WorkOS client as an Effect,
   * mapping any thrown SDK exception into a {@link WorkOSError}.
   *
   * @example
   * yield* workos.use((client) => client.get("/some/new/endpoint"))
   */
  readonly use: <A>(f: (client: WorkOSClient) => A | Promise<A>) => Effect.Effect<A, WorkOSError>;
}

const isPromiseLike = (u: unknown): u is PromiseLike<unknown> =>
  typeof u === "object" && u !== null && typeof (u as { then?: unknown }).then === "function";

/**
 * Invoke `f`, which may return either a value or a Promise, and lift the result
 * into an Effect, mapping any synchronous throw or rejected promise into a
 * {@link WorkOSError} tagged with `operation`.
 */
const runCall = <A>(f: () => A | Promise<A>, operation: string): Effect.Effect<A, WorkOSError> =>
  Effect.flatMap(
    Effect.try({ try: f, catch: (cause) => toWorkOSError(cause, operation) }),
    (result) =>
      isPromiseLike(result)
        ? Effect.tryPromise({
            try: () => result as Promise<A>,
            catch: (cause) => toWorkOSError(cause, operation),
          })
        : Effect.succeed(result as A),
  );

/**
 * Wrap a single WorkOS SDK module in a Proxy that returns Effects from every
 * method while leaving non-method properties untouched.
 */
const effectifyModule = <T extends object>(target: T, moduleName: string): Effectified<T> =>
  new Proxy(target, {
    get(obj, prop) {
      const value = Reflect.get(obj, prop, obj);
      if (typeof value !== "function") return value;
      const fn = value as (...args: ReadonlyArray<unknown>) => unknown;
      const operation = `${moduleName}.${String(prop)}`;
      return (...args: ReadonlyArray<unknown>) =>
        runCall(() => Reflect.apply(fn, obj, args), operation);
    },
  }) as unknown as Effectified<T>;

/**
 * Build a {@link WorkOSService} from an already-constructed WorkOS SDK client.
 * Useful when you manage client construction yourself or in tests.
 */
export const makeFromClient = (client: WorkOSClient): WorkOSService => {
  const modules: Record<string, unknown> = {};
  for (const key of MODULE_KEYS) {
    modules[key] = effectifyModule(client[key] as object, key);
  }

  const use = <A>(f: (client: WorkOSClient) => A | Promise<A>): Effect.Effect<A, WorkOSError> =>
    runCall(() => f(client), "use");

  return { ...(modules as WorkOSModules), client, use };
};

/**
 * Options for constructing the WorkOS client. Mirrors `WorkOSOptions` from the
 * SDK, but additionally accepts a `Redacted` API key so secrets stay redacted in
 * logs and traces.
 */
export interface WorkOSClientOptions {
  /** WorkOS API key (`sk_...`). Required for server-side (confidential) usage. */
  readonly apiKey?: string | Redacted.Redacted<string>;
  /** WorkOS Client ID (`client_...`). Required for AuthKit / PKCE flows. */
  readonly clientId?: string;
  /** Override the API hostname (defaults to `api.workos.com`). */
  readonly apiHostname?: string;
  /** Whether to use HTTPS (defaults to `true`). */
  readonly https?: boolean;
  /** Override the API port. */
  readonly port?: number;
  /** Per-request timeout in milliseconds. */
  readonly timeout?: number;
  /** Application metadata sent in the User-Agent header. */
  readonly appInfo?: WorkOSOptions["appInfo"];
  /** Extra `fetch` request init merged into every request. */
  readonly config?: WorkOSOptions["config"];
  /** Custom `fetch` implementation. */
  readonly fetchFn?: WorkOSOptions["fetchFn"];
}

const resolveApiKey = (
  apiKey: string | Redacted.Redacted<string> | undefined,
): string | undefined =>
  apiKey === undefined ? undefined : typeof apiKey === "string" ? apiKey : Redacted.value(apiKey);

/**
 * Construct a raw WorkOS SDK client from {@link WorkOSClientOptions}.
 */
export const makeClient = (options: WorkOSClientOptions = {}): WorkOSClient => {
  const { apiKey, ...rest } = options;
  // Copy only defined entries so we don't trip `exactOptionalPropertyTypes`.
  const workosOptions: WorkOSOptions = {};
  for (const [k, v] of Object.entries(rest)) {
    if (v !== undefined) (workosOptions as Record<string, unknown>)[k] = v;
  }
  const key = resolveApiKey(apiKey);
  if (key !== undefined) workosOptions.apiKey = key;
  return new WorkOSSDK(workosOptions);
};

/**
 * Read {@link WorkOSClientOptions} from the environment via Effect `Config`.
 *
 * - `WORKOS_API_KEY` (redacted, required)
 * - `WORKOS_CLIENT_ID` (optional)
 * - `WORKOS_API_HOSTNAME` (optional)
 * - `WORKOS_HTTPS` (optional boolean)
 * - `WORKOS_PORT` (optional integer)
 */
export const configOptions: Effect.Effect<WorkOSClientOptions, Config.ConfigError> = Effect.gen(
  function* () {
    const apiKey = yield* Config.redacted("WORKOS_API_KEY");
    const clientId = Option.getOrUndefined(yield* Config.option(Config.string("WORKOS_CLIENT_ID")));
    const apiHostname = Option.getOrUndefined(
      yield* Config.option(Config.string("WORKOS_API_HOSTNAME")),
    );
    const https = Option.getOrUndefined(yield* Config.option(Config.boolean("WORKOS_HTTPS")));
    const port = Option.getOrUndefined(yield* Config.option(Config.int("WORKOS_PORT")));

    const options: {
      apiKey: Redacted.Redacted<string>;
      clientId?: string;
      apiHostname?: string;
      https?: boolean;
      port?: number;
    } = { apiKey };
    if (clientId !== undefined) options.clientId = clientId;
    if (apiHostname !== undefined) options.apiHostname = apiHostname;
    if (https !== undefined) options.https = https;
    if (port !== undefined) options.port = port;
    return options;
  },
);

/**
 * The WorkOS Effect service.
 *
 * Provide one of its layers and then `yield* WorkOS` anywhere to access the full
 * WorkOS feature set as Effects.
 */
export class WorkOS extends Context.Service<WorkOS, WorkOSService>()("@effect-auth/workos/WorkOS") {
  /**
   * Layer that reads credentials from the environment via Effect `Config`
   * (`WORKOS_API_KEY`, `WORKOS_CLIENT_ID`, ...). This is the recommended layer
   * for most applications.
   */
  static readonly layer: Layer.Layer<WorkOS, Config.ConfigError> = Layer.effect(
    WorkOS,
    Effect.map(configOptions, (options) => makeFromClient(makeClient(options))),
  );

  /**
   * Layer built from explicit {@link WorkOSClientOptions}. Handy when you load
   * configuration yourself or want a public (PKCE) client with only a
   * `clientId`.
   */
  static readonly layerOptions = (options: WorkOSClientOptions): Layer.Layer<WorkOS> =>
    Layer.sync(WorkOS, () => makeFromClient(makeClient(options)));

  /**
   * Layer built from an already-constructed WorkOS SDK client. Useful in tests
   * or when sharing a client across libraries.
   */
  static readonly layerClient = (client: WorkOSClient): Layer.Layer<WorkOS> =>
    Layer.succeed(WorkOS, makeFromClient(client));
}
