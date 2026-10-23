import { assert, describe, it, expect } from "vite-plus/test";
import {
  Array as Arr,
  Effect,
  FileSystem,
  Layer,
  Order,
  Path,
  PlatformError,
  Predicate,
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
import * as D1Client from "./D1Client.ts";
import * as Postgres from "./Postgres.ts";
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
    chmod: () => Effect.void,
    writeFileString: () => Effect.void,
  }),
  Path.layer,
  FetchHttpClient.layer,
);

const STACK = "effect-auth-alchemy-test";

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
        // `ChildProcessSpawner`, `Crypto` and `Interaction`, which an `AuthSchema`
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
    }).pipe(Effect.provide(D1Client.layer({ db: database }))),
  );

const insertUser = (database: D1Client.D1Database): Promise<void> =>
  Effect.runPromise(
    Effect.gen(function* () {
      const sql = yield* SqlClient.SqlClient;
      yield* sql`INSERT INTO auth_users (id, created_at, updated_at) VALUES ('u1', 1, 1)`;
    }).pipe(Effect.provide(D1Client.layer({ db: database }))),
  );

describe("AuthSchema resource", () => {
  it("is a real Alchemy resource whose provider mounts on Alchemy's own tag", async () => {
    const provider = await Effect.runPromise(
      AuthSchema.Provider.pipe(Effect.provide(AuthSchemaProvider({ database: makeTestD1() }))),
    );
    expect(Predicate.isFunction(provider.reconcile)).toBe(true);
    expect(Predicate.isFunction(provider.delete)).toBe(true);
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
    const engine = makeEngine({ database });
    const program = AuthSchema("auth-schema");

    const created = await engine.deploy(program);
    assert(created !== undefined);
    expect(created.tables).toEqual(sortedTableNames);
    expect(created.statements).toBeGreaterThan(0);
    expect(created.appliedAt).toBeGreaterThan(0);

    // Data written between deploys must survive the next reconcile.
    await insertUser(database);
    await engine.deploy(program);
    expect(await countUsers(database)).toBe(1);
    expect(await tablesIn(database)).toEqual(sortedTableNames);

    // Teardown leaves the tables alone unless `dropOnDelete` is set.
    await engine.destroy();
    expect(await tablesIn(database)).toEqual(sortedTableNames);
    expect(await countUsers(database)).toBe(1);
  });

  it("drops every auth table on destroy when dropOnDelete is set", async () => {
    const database = makeTestD1();
    const engine = makeEngine({ database });
    const program = AuthSchema("auth-schema", { dropOnDelete: true });

    await engine.deploy(program);
    expect(await tablesIn(database)).toEqual(sortedTableNames);

    await engine.destroy();
    expect(await tablesIn(database)).toEqual([]);
  });

  it("reconciles and drops the database each resource names", async () => {
    const primary = makeTestD1();
    const tenants = makeTestD1();
    const engine = makeEngine({ databases: { primary, tenants } });

    await engine.deploy(
      Effect.gen(function* () {
        yield* AuthSchema("primary-auth", { database: "primary" });
        yield* AuthSchema("tenant-auth", { database: "tenants", dropOnDelete: true });
      }),
    );
    expect(await tablesIn(primary)).toEqual(sortedTableNames);
    expect(await tablesIn(tenants)).toEqual(sortedTableNames);

    // Only the resource that opted in loses its tables.
    await engine.destroy();
    expect(await tablesIn(primary)).toEqual(sortedTableNames);
    expect(await tablesIn(tenants)).toEqual([]);
  });

  it("fails the destroy rather than silently skipping an unregistered database", async () => {
    const database = makeTestD1();
    const engine = makeEngine({ databases: { primary: database } });
    await engine.deploy(AuthSchema("auth-schema", { database: "primary", dropOnDelete: true }));

    // The stack is torn down by a provider that no longer holds the binding:
    // dropping is impossible, so the destroy must fail loudly and leave the
    // tables (and the state row) alone.
    const detached = makeEngine({ databases: {} }, engine.store);
    await expect(detached.destroy()).rejects.toThrow(/UnknownDatabaseError/);
    expect(await tablesIn(database)).toEqual(sortedTableNames);
  });
});

/**
 * The Postgres path: the same lifecycle against a PGlite database, held open
 * across every operation so a later deploy sees what an earlier one created.
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

const pglite = async (): Promise<{ readonly database: PostgresDatabase; readonly close: () => Promise<void> }> => {
  const client = await PGlite.create();
  return {
    database: postgresDatabase(PgliteClient.layer({ liveClient: client })),
    close: () => client.close(),
  };
};

describe("AuthSchema resource on Postgres", () => {
  it("deploys the schema into Postgres, converges, and drops it only when asked", async () => {
    const { database, close } = await pglite();
    try {
      const engine = makeEngine({ database });
      const created = await engine.deploy(AuthSchema("auth-schema", { dropOnDelete: true }));
      assert(created !== undefined);
      expect(created.tables).toEqual(sortedTableNames);
      await engine.deploy(AuthSchema("auth-schema", { dropOnDelete: true }));
      expect(await tablesInPostgres(database)).toEqual(sortedTableNames);
      await engine.destroy();
      expect(await tablesInPostgres(database)).toEqual([]);
    } finally {
      await close();
    }
  });

  it("reconciles a D1 binding and a Postgres database in one stack", async () => {
    const d1 = makeTestD1();
    const { database: pg, close } = await pglite();
    try {
      const engine = makeEngine({ databases: { edge: d1, origin: pg } });
      await engine.deploy(
        Effect.gen(function* () {
          yield* AuthSchema("edge-auth", { database: "edge" });
          yield* AuthSchema("origin-auth", { database: "origin" });
        }),
      );
      expect(await tablesIn(d1)).toEqual(sortedTableNames);
      expect(await tablesInPostgres(pg)).toEqual(sortedTableNames);
    } finally {
      await close();
    }
  });

  // A real server, over `@effect/sql-pg` — CI's alchemy job runs one and sets
  // DATABASE_URL; without it the case is skipped.
  const databaseUrl = process.env["DATABASE_URL"];
  it.skipIf(databaseUrl === undefined)(
    "deploys through @effect/sql-pg against a real Postgres server",
    async () => {
      assert(databaseUrl !== undefined);
      const database = Postgres.database(Redacted.make(databaseUrl));
      const engine = makeEngine({ database });
      await engine.deploy(AuthSchema("auth-schema", { dropOnDelete: true }));
      expect(await tablesInPostgres(database)).toEqual(sortedTableNames);
      await engine.destroy();
      expect(await tablesInPostgres(database)).toEqual([]);
    },
  );
});
