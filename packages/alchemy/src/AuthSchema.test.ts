import { describe, it, expect } from "vite-plus/test";
import { Effect, FileSystem, Layer, Path, PlatformError } from "effect";
import { SqlClient } from "effect/unstable/sql";
import * as FetchHttpClient from "effect/unstable/http/FetchHttpClient";
import { AdoptPolicy } from "alchemy/AdoptPolicy";
import { AlchemyContextLive } from "alchemy/AlchemyContext";
import { apply } from "alchemy/Apply";
import { provideFreshArtifactStore } from "alchemy/Artifacts";
import { AuthProviders } from "alchemy/Auth/AuthProvider";
import { CredentialsStoreLive } from "alchemy/Auth/Credentials";
import { ProfileLive } from "alchemy/Auth/Profile";
import { LoggingCli } from "alchemy/Cli/LoggingCli";
import * as Plan from "alchemy/Plan";
import { Stack } from "alchemy/Stack";
import { make as makeStack } from "alchemy/Stack";
import { Stage } from "alchemy/Stage";
import * as State from "alchemy/State";
import { AuthSchema, AuthSchemaProvider, authTableNames } from "./AuthSchema.ts";
import * as D1Client from "./D1Client.ts";
import { makeTestD1 } from "./testShim.ts";

/**
 * The lifecycle below is driven by the **real** Alchemy engine — `Stack` +
 * `Plan.make` + `apply`, the same path `alchemy deploy` takes — against an
 * in-memory state store. This mirrors `alchemy/Test`'s own `scratchStack`.
 *
 * `alchemy/Test` itself can't be used here: its runtime always builds
 * `PlatformServices`, which imports `@effect/platform-node`, an unmet peer
 * dependency of `alchemy` in this repo (the import dies with
 * `ERR_MODULE_NOT_FOUND`). The only substitution below is that platform layer:
 * `Path` is real, and the filesystem is Effect's own testing stub reporting an
 * empty disk, which is all the engine needs to conclude there is no Alchemy
 * profile or credentials file to read.
 */
const notFound = (path: string) =>
  PlatformError.systemError({
    _tag: "NotFound",
    module: "FileSystem",
    method: "readFileString",
    description: "no such file",
    pathOrDescriptor: path,
  });

const platform = Layer.mergeAll(
  FileSystem.layerNoop({
    readFileString: (path: string) => Effect.fail(notFound(path)),
    readFile: (path: string) => Effect.fail(notFound(path)),
    exists: () => Effect.succeed(false),
    makeDirectory: () => Effect.void,
    writeFileString: () => Effect.void,
  } as never),
  Path.layer,
  FetchHttpClient.layer,
);

const STACK = "effect-auth-alchemy-test";
const STAGE = "test";

/** A stack with its own in-memory state, deployable more than once. */
const makeEngine = () => {
  const store: Record<string, never> = {};
  const state = Layer.succeed(State.State, State.InMemoryService(store));
  const providers = AuthSchemaProvider();

  const withRuntime = <A>(effect: Effect.Effect<A, unknown, never>): Promise<A> =>
    Effect.runPromise(
      effect.pipe(
        Effect.provide(Layer.succeed(Stage, STAGE)),
        provideFreshArtifactStore,
        Effect.provideService(AdoptPolicy, false),
        Effect.provideService(AuthProviders, {}),
        // The order of the provides below is load-bearing — each one supplies
        // requirements of the layers provided before it, mirroring alchemy's
        // own runtime layering — so they cannot collapse into a single merged
        // provide.
        // @effect-diagnostics-next-line effect/multipleEffectProvide:off
        Effect.provide(Layer.mergeAll(LoggingCli, AlchemyContextLive)),
        Effect.provide(Layer.provide(ProfileLive, platform)),
        Effect.provide(Layer.provide(CredentialsStoreLive, platform)),
        Effect.provide(platform),
        Effect.scoped,
      ) as Effect.Effect<A>,
    );

  return {
    /** `alchemy deploy` for one program. */
    deploy: <A>(program: Effect.Effect<A, never, never>): Promise<unknown> =>
      withRuntime(
        program.pipe(
          makeStack({ name: STACK, providers, state } as never) as never,
          Effect.flatMap((compiled: { services: Layer.Layer<never> }) =>
            Plan.make(compiled as never).pipe(
              Effect.flatMap(apply),
              Effect.provide(compiled.services),
            ),
          ),
        ) as unknown as Effect.Effect<unknown, unknown, never>,
      ),
    /** `alchemy destroy`: apply an empty plan, so every resource is deleted. */
    destroy: (): Promise<unknown> =>
      withRuntime(
        Plan.make({
          name: STACK,
          stage: STAGE,
          resources: {},
          bindings: {},
          actions: {},
          output: {},
        } as never).pipe(
          Effect.flatMap(apply),
          Effect.asVoid,
          // Ordered provides again: `providers` and the `Stack` layer are
          // resolved against the state layer provided first.
          // @effect-diagnostics-next-line effect/multipleEffectProvide:off
          Effect.provide(state),
          Effect.provide(providers as Layer.Layer<never>),
          Effect.provide(
            Layer.succeed(Stack, {
              name: STACK,
              stage: STAGE,
              resources: {},
              bindings: {},
              actions: {},
            } as never),
          ),
        ) as Effect.Effect<unknown, unknown, never>,
      ),
  };
};

const tablesIn = (database: D1Client.D1Database): Promise<readonly string[]> =>
  Effect.runPromise(
    Effect.gen(function* () {
      const sql = yield* SqlClient.SqlClient;
      const rows = yield* sql<{
        readonly name: string;
      }>`SELECT name FROM sqlite_master WHERE type = 'table' AND name LIKE 'auth_%' ORDER BY name`;
      return rows.map((row) => row.name);
    }).pipe(Effect.provide(D1Client.layer({ db: database }))),
  );

const countUsers = (database: D1Client.D1Database): Promise<number> =>
  Effect.runPromise(
    Effect.gen(function* () {
      const sql = yield* SqlClient.SqlClient;
      const rows = yield* sql<{ readonly n: number }>`SELECT count(*) AS n FROM auth_users`;
      return rows[0]?.n ?? 0;
    }).pipe(Effect.provide(D1Client.layer({ db: database }))) as Effect.Effect<number>,
  );

const insertUser = (database: D1Client.D1Database): Promise<void> =>
  Effect.runPromise(
    Effect.gen(function* () {
      const sql = yield* SqlClient.SqlClient;
      yield* sql`INSERT INTO auth_users (id, created_at, updated_at) VALUES ('u1', 1, 1)`;
    }).pipe(Effect.provide(D1Client.layer({ db: database }))) as Effect.Effect<void>,
  );

describe("AuthSchema resource", () => {
  it("is a real Alchemy resource whose provider mounts on Alchemy's own tag", async () => {
    const provider = await Effect.runPromise(
      AuthSchema.Provider.pipe(Effect.provide(AuthSchemaProvider())),
    );
    expect(typeof provider.reconcile).toBe("function");
    expect(typeof provider.delete).toBe("function");
    expect(await Effect.runPromise(provider.list())).toEqual([]);
  });

  it("derives its table list from the shared SQL schema", () => {
    expect(authTableNames).toContain("auth_users");
    expect(authTableNames).toContain("auth_sessions");
    expect(authTableNames).toContain("auth_identifiers");
    expect(authTableNames.every((name) => name.startsWith("auth_"))).toBe(true);
  });

  it("deploys the schema, converges on a redeploy, and keeps data by default", async () => {
    const database = makeTestD1();
    const engine = makeEngine();
    const program = Effect.gen(function* () {
      return yield* AuthSchema("auth-schema", { database });
    });

    const created = (await engine.deploy(program as never)) as {
      tables: readonly string[];
      statements: number;
      appliedAt: number;
    };
    expect(created.tables).toEqual([...authTableNames].sort());
    expect(created.statements).toBeGreaterThan(0);
    expect(created.appliedAt).toBeGreaterThan(0);

    // Data written between deploys must survive the next reconcile.
    await insertUser(database);
    await engine.deploy(program as never);
    expect(await countUsers(database)).toBe(1);
    expect(await tablesIn(database)).toEqual([...authTableNames].sort());

    // Teardown leaves the tables alone unless `dropOnDelete` is set.
    await engine.destroy();
    expect(await tablesIn(database)).toEqual([...authTableNames].sort());
    expect(await countUsers(database)).toBe(1);
  });

  it("drops every auth table on destroy when dropOnDelete is set", async () => {
    const database = makeTestD1();
    const engine = makeEngine();
    const program = Effect.gen(function* () {
      return yield* AuthSchema("auth-schema", { database, dropOnDelete: true });
    });

    await engine.deploy(program as never);
    expect(await tablesIn(database)).toEqual([...authTableNames].sort());

    await engine.destroy();
    expect(await tablesIn(database)).toEqual([]);
  });
});
