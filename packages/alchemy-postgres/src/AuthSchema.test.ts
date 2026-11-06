import { assert, describe, it, expect, onTestFinished } from "vite-plus/test";
import {
  Array as Arr,
  Config,
  Effect,
  FileSystem,
  Layer,
  Option,
  Order,
  Path,
  PlatformError,
  Redacted,
  Schema,
} from "effect";
import { PGlite } from "@electric-sql/pglite";
import * as PgliteClient from "@effect/sql-pglite/PgliteClient";
import { SqlClient } from "effect/sql";
import * as FetchHttpClient from "effect/http/FetchHttpClient";
import { AdoptPolicy } from "alchemy/AdoptPolicy";
import { AlchemyContextLive } from "alchemy/AlchemyContext";
import { apply } from "alchemy/Apply";
import { provideFreshArtifactStore } from "alchemy/Artifacts";
import { AuthProviders } from "alchemy/Auth/AuthProvider";
import { CredentialsStoreLive } from "alchemy/Auth/Credentials";
import { ProfileStoreLive } from "alchemy/Auth/Profile";
import { LoggingCli } from "alchemy/Cli/LoggingCli";
import * as Plan from "alchemy/Plan";
import { Stack } from "alchemy/Stack";
import { make as makeStack, type StackServices } from "alchemy/Stack";
import { Stage } from "alchemy/Stage";
import * as State from "alchemy/State";
import {
  AuthSchema,
  AuthSchemaProvider,
  authTableNames,
  type PostgresDatabase,
  postgresDatabase,
} from "./AuthSchema.ts";
import * as Postgres from "./Postgres.ts";

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
    chmod: () => Effect.void,
    writeFileString: () => Effect.void,
  }),
  Path.layer,
  FetchHttpClient.layer,
);

const STACK = "effect-auth-alchemy-postgres-test";

/** Every auth table, sorted by name. */
const sortedTableNames = Arr.sort(authTableNames, Order.String);

/** What a deploy resolves to: the `AuthSchema` attributes, or nothing. */
const DeployOutput = Schema.UndefinedOr(
  Schema.Struct({
    tables: Schema.Array(Schema.String),
    statements: Schema.Number,
    appliedAt: Schema.Number,
  }),
);
const STAGE = "test";

/**
 * A stack with its own in-memory state, deployable more than once. Pass an
 * existing `store` to drive the same state with a differently-built provider,
 * the way a later `alchemy destroy` runs against state an earlier deploy left
 * behind.
 */
const makeEngine = (
  options: Parameters<typeof AuthSchemaProvider>[0],
  store: Record<string, never> = {},
) => {
  const state = Layer.succeed(State.State, State.InMemoryService(store));
  const providers = AuthSchemaProvider(options);

  const withRuntime = <A>(effect: Effect.Effect<A, unknown, Stage>): Promise<A> =>
    Effect.runPromise(
      // SAFETY: `LoggingCli` asks for a `Terminal` only to prompt in `approvePlan`;
      // these deploys call `apply` directly and never ask for approval.
      effect.pipe(
        Effect.provide(Layer.succeed(Stage, STAGE)),
        provideFreshArtifactStore,
        Effect.provideService(AdoptPolicy, false),
        Effect.provideService(AuthProviders, {}),
        // The order of the provides below is load-bearing — each one supplies
        // requirements of the layers provided before it, mirroring alchemy's
        // own runtime layering — so they cannot collapse into a single merged
        // provide.
        // layerMergeAllWithDependencies: this layering predates the rc.118 move and
        // is only newly flagged by @effect/language-service 0.87.3; left as is.
        // @effect-diagnostics-next-line multipleEffectProvide:off layerMergeAllWithDependencies:off
        Effect.provide(Layer.mergeAll(LoggingCli, AlchemyContextLive)),
        Effect.provide(Layer.provide(ProfileStoreLive, platform)),
        Effect.provide(Layer.provide(CredentialsStoreLive, platform)),
        Effect.provide(platform),
        Effect.scoped,
      ) as Effect.Effect<A>,
    );

  return {
    /** The engine's persisted state, so another engine can pick it up. */
    store,
    /** `alchemy deploy` for one program. */
    deploy: <A, E, R extends Layer.Success<typeof providers> | StackServices>(
      program: Effect.Effect<A, E, R>,
    ): Promise<typeof DeployOutput.Type> =>
      withRuntime(
        // SAFETY: `withRuntime` provides the engine services a deploy uses, and
        // `compiled.services` is the whole context the stack was built in, its
        // `State` and providers among it. `Stack.make` also declares
        // `ChildProcessSpawner`, `Digest`, `SecureRandom` and `Interaction`, which an `AuthSchema`
        // deploy never reaches: one that did would fail with a missing-service defect.
        program.pipe(
          makeStack({ name: STACK, providers, state }),
          Effect.flatMap((compiled) =>
            Plan.make(compiled).pipe(Effect.flatMap(apply), Effect.provide(compiled.services)),
          ),
          Effect.flatMap(Schema.decodeUnknownEffect(DeployOutput)),
        ) as Effect.Effect<typeof DeployOutput.Type, unknown, never>,
      ),
    /** `alchemy destroy`: apply an empty plan, so every resource is deleted. */
    destroy: (): Promise<void> =>
      withRuntime(
        Plan.make({
          name: STACK,
          stage: STAGE,
          resources: {},
          bindings: {},
          actions: {},
          output: {},
        }).pipe(
          Effect.flatMap(apply),
          Effect.asVoid,
          // Ordered provides again: `providers` and the `Stack` layer are
          // resolved against the state layer provided first.
          // @effect-diagnostics-next-line multipleEffectProvide:off
          Effect.provide(state),
          Effect.provide(providers),
          Effect.provide(
            Layer.succeed(Stack, {
              name: STACK,
              stage: STAGE,
              resources: {},
              bindings: {},
              actions: {},
            }),
          ),
        ),
      ),
  };
};

/**
 * The lifecycle against a PGlite database, held open across every operation
 * so a later deploy sees what an earlier one created.
 */
const tablesInPostgres = (database: PostgresDatabase): Promise<readonly string[]> =>
  Effect.runPromise(
    Effect.gen(function* () {
      const sql = yield* SqlClient.SqlClient;
      const rows = yield* sql<{ readonly name: string }>`
        SELECT table_name AS name FROM information_schema.tables
        WHERE table_schema = current_schema() AND table_name LIKE 'auth\\_%' ESCAPE '\\'
        ORDER BY table_name`;
      return rows.map((row) => row.name);
    }).pipe(Effect.provide(database.client)),
  );

/** The real Postgres server CI's alchemy job runs, if this environment names one. */
const databaseUrl = Option.getOrUndefined(
  Effect.runSync(Config.option(Config.Redacted("DATABASE_URL"))),
);

const pglite = async (): Promise<{
  readonly database: PostgresDatabase;
  readonly close: () => Promise<void>;
}> => {
  const client = await PGlite.create();
  return {
    database: postgresDatabase(PgliteClient.layer({ liveClient: client })),
    close: () => client.close(),
  };
};

// `PGlite.create()` runs `initdb` inside its WASM module, which takes seconds on
// a loaded machine, so the PGlite cases get more than the default 5 s.
const PGLITE_TIMEOUT = 60_000;

describe("AuthSchema resource on Postgres", () => {
  it("is a real Alchemy resource whose provider mounts on Alchemy's own tag", async () => {
    // Building the provider connects to nothing: the layer is built per operation.
    const database = Postgres.database(Redacted.make("postgres://unused@localhost/unused"));
    const provider = await Effect.runPromise(
      AuthSchema.Provider.pipe(Effect.provide(AuthSchemaProvider({ database }))),
    );
    expect(provider).toHaveProperty("reconcile", expect.any(Function));
    expect(provider).toHaveProperty("delete", expect.any(Function));
    expect(await Effect.runPromise(provider.list())).toEqual([]);
  });

  it(
    "deploys the schema into Postgres, converges, and drops it only when asked",
    async () => {
      const { database, close } = await pglite();
      onTestFinished(close);
      const engine = makeEngine({ database });
      const created = await engine.deploy(AuthSchema("auth-schema", { dropOnDelete: true }));
      assert(created !== undefined);
      expect(created.tables).toEqual(sortedTableNames);
      await engine.deploy(AuthSchema("auth-schema", { dropOnDelete: true }));
      expect(await tablesInPostgres(database)).toEqual(sortedTableNames);
      await engine.destroy();
      expect(await tablesInPostgres(database)).toEqual([]);
    },
    PGLITE_TIMEOUT,
  );

  // A real server, over `@effect/sql-pg` — CI's alchemy job runs one and sets
  // DATABASE_URL; without it the case is skipped.
  it.skipIf(databaseUrl === undefined)(
    "deploys through @effect/sql-pg against a real Postgres server",
    async () => {
      assert(databaseUrl !== undefined);
      const database = Postgres.database(databaseUrl);
      const engine = makeEngine({ database });
      await engine.deploy(AuthSchema("auth-schema", { dropOnDelete: true }));
      expect(await tablesInPostgres(database)).toEqual(sortedTableNames);
      await engine.destroy();
      expect(await tablesInPostgres(database)).toEqual([]);
    },
  );
});
