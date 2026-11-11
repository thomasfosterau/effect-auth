import { assert, describe, it, expect } from "vite-plus/test";
import { Effect, FileSystem, Layer, Order, Path, PlatformError } from "effect";
import * as Arr from "effect/Array";
import * as Schema from "effect/Schema";
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
import { Database } from "@alchemy.run/cloudflare/D1/Database";
import { QueryDatabase } from "@alchemy.run/cloudflare/D1/QueryDatabase";
import { Providers } from "@alchemy.run/cloudflare/Providers";
import * as Provider from "alchemy/Provider";
import { AuthSchema, authTableNames } from "./AuthSchema.ts";
import * as D1Client from "./D1Client.ts";
import { clientOver, makeRawD1, type RawD1, runtimeContext } from "./testShim.ts";

/**
 * The Action below is driven by the **real** Alchemy engine — `Stack` +
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

const STACK = "effect-auth-alchemy-cloudflare-test";

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

/** The attributes the stub `Database` provider reports for a logical id. */
const attributes = (id: string) => ({
  databaseId: `db-${id}`,
  databaseName: id,
  jurisdiction: "default" as const,
  readReplication: undefined,
  accountId: "account",
  migrationsDir: undefined,
  migrationsTable: undefined,
  migrationsHashes: {},
  importHashes: {},
});

/**
 * The Cloudflare side, stubbed at the provider's seams: a `Cloudflare.D1.Database`
 * provider that "creates" a database by minting an id, and a `QueryDatabase`
 * that binds a database the way `Cloudflare.D1.QueryDatabaseLocal` does —
 * resolving its `databaseId` at apply time — but over an in-memory SQLite
 * database per id instead of the D1 HTTP API.
 */
const makeCloudflare = () => {
  const databases: Record<string, RawD1> = {};
  const rawFor = (id: string): RawD1 => (databases[id] ??= makeRawD1());
  const databaseProvider = Provider.succeed(Database, {
    read: ({ id, output }) =>
      Effect.succeed(output ?? (`db-${id}` in databases ? attributes(id) : undefined)),
    diff: () => Effect.void,
    reconcile: ({ id }) => Effect.succeed(attributes(id)),
    delete: () => Effect.void,
    list: () => Effect.succeed([]),
  });
  const queryDatabase = Layer.succeed(
    QueryDatabase,
    Effect.fn("QueryDatabase")(function* (database: Database) {
      // As `QueryDatabaseLocal` does: a deferred accessor, resolved at apply.
      const databaseId = yield* database.databaseId;
      return clientOver(Effect.map(databaseId, (id) => rawFor(id)));
    }),
  );
  /** The SQLite database behind the D1 database with this logical id. */
  const client = (id: string) => clientOver(Effect.sync(() => rawFor(`db-${id}`)));
  // The provider collection a `Cloudflare.D1.Database` is deployed by
  // (`Cloudflare.providers()`), holding only the stubbed `Database` provider.
  const providers = Layer.effect(Providers, Provider.collection([Database])).pipe(
    Layer.provideMerge(databaseProvider),
  );
  return { providers, queryDatabase, client };
};
const STAGE = "test";

/**
 * A stack with its own in-memory state, deployable more than once. Pass an
 * existing `store` to drive the same state with a differently-built provider,
 * the way a later `alchemy destroy` runs against state an earlier deploy left
 * behind.
 */
const makeEngine = (cloudflare: ReturnType<typeof makeCloudflare>) => {
  const store: Record<string, never> = {};
  const state = Layer.succeed(State.State, State.InMemoryService(store));
  const providers = cloudflare.providers;

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
    /** `alchemy deploy` for one program. */
    deploy: <A, E, R extends Layer.Success<typeof providers> | StackServices | QueryDatabase>(
      program: Effect.Effect<A, E, R>,
    ): Promise<typeof DeployOutput.Type> =>
      withRuntime(
        // SAFETY: `withRuntime` provides the engine services a deploy uses, and
        // `compiled.services` is the whole context the stack was built in, its
        // `State` and providers among it. `Stack.make` also declares
        // `ChildProcessSpawner`, `Digest`, `SecureRandom` and `Interaction`, which an `AuthSchema`
        // deploy never reaches: one that did would fail with a missing-service defect.
        program.pipe(
          // What an application provides around `AuthSchema` on deploy
          // (`Cloudflare.D1.QueryDatabaseLocal`), stubbed.
          Effect.provide(cloudflare.queryDatabase),
          makeStack({ name: STACK, providers, state }),
          Effect.flatMap((compiled) =>
            Plan.make(compiled).pipe(Effect.flatMap(apply), Effect.provide(compiled.services)),
          ),
          Effect.flatMap(Schema.decodeUnknownEffect(DeployOutput)),
        ) as Effect.Effect<typeof DeployOutput.Type, unknown>,
      ),
    /** `alchemy destroy`: apply an empty plan, so every resource and action is removed. */
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

const query = <A, E>(
  cloudflare: ReturnType<typeof makeCloudflare>,
  id: string,
  effect: Effect.Effect<A, E, SqlClient.SqlClient>,
): Promise<A> =>
  Effect.runPromise(
    effect.pipe(
      Effect.provide(
        D1Client.layer({ db: cloudflare.client(id) }).pipe(Layer.provide(runtimeContext)),
      ),
    ),
  );

const tablesIn = (cloudflare: ReturnType<typeof makeCloudflare>, id: string) =>
  query(
    cloudflare,
    id,
    Effect.gen(function* () {
      const sql = yield* SqlClient.SqlClient;
      const rows = yield* sql<{
        readonly name: string;
      }>`SELECT name FROM sqlite_master WHERE type = 'table' AND name LIKE 'auth_%' ORDER BY name`;
      return rows.map((row) => row.name);
    }),
  );

const countUsers = (cloudflare: ReturnType<typeof makeCloudflare>, id: string) =>
  query(
    cloudflare,
    id,
    Effect.gen(function* () {
      const sql = yield* SqlClient.SqlClient;
      const rows = yield* sql<{ readonly n: number }>`SELECT count(*) AS n FROM auth_users`;
      return rows[0]?.n ?? 0;
    }),
  );

const insertUser = (cloudflare: ReturnType<typeof makeCloudflare>, id: string) =>
  query(
    cloudflare,
    id,
    Effect.gen(function* () {
      const sql = yield* SqlClient.SqlClient;
      yield* sql`INSERT INTO auth_users (id, created_at, updated_at) VALUES ('u1', 1, 1)`;
    }),
  );

describe("AuthSchema action", () => {
  it("derives its table list from the shared SQL schema", () => {
    expect(authTableNames).toContain("auth_users");
    expect(authTableNames).toContain("auth_sessions");
    expect(authTableNames).toContain("auth_identifiers");
    expect(authTableNames.every((name) => name.startsWith("auth_"))).toBe(true);
  });

  it("applies the schema to a database created in the same deploy, and keeps data", async () => {
    const cloudflare = makeCloudflare();
    const engine = makeEngine(cloudflare);
    const program = Effect.fn("program")(function* () {
      const database = yield* Database("auth-db");
      return yield* AuthSchema("auth-schema", database);
    });

    const created = await engine.deploy(program());
    assert(created !== undefined);
    expect(created.tables).toEqual(sortedTableNames);
    expect(created.statements).toBeGreaterThan(0);
    expect(created.appliedAt).toBeGreaterThan(0);

    // Data written between deploys survives the next one; the unchanged
    // input leaves the action's last run standing.
    await insertUser(cloudflare, "auth-db");
    const redeployed = await engine.deploy(program());
    expect(redeployed).toEqual(created);
    expect(await countUsers(cloudflare, "auth-db")).toBe(1);

    // An action has no delete: a teardown leaves the tables alone.
    await engine.destroy();
    expect(await tablesIn(cloudflare, "auth-db")).toEqual(sortedTableNames);
    expect(await countUsers(cloudflare, "auth-db")).toBe(1);
  });

  it("applies the schema to the database each action names", async () => {
    const cloudflare = makeCloudflare();
    const engine = makeEngine(cloudflare);

    await engine.deploy(
      Effect.gen(function* () {
        const primary = yield* Database("primary");
        const tenants = yield* Database("tenants");
        yield* AuthSchema("primary-auth", primary);
        yield* AuthSchema("tenant-auth", tenants);
        return undefined;
      }),
    );
    expect(await tablesIn(cloudflare, "primary")).toEqual(sortedTableNames);
    expect(await tablesIn(cloudflare, "tenants")).toEqual(sortedTableNames);
  });
});
