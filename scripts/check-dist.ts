/**
 * Dist-level import smoke test for each package's published Effect floor.
 *
 * Packs every package under `packages/*`, checks each packed manifest's
 * `repository` (below), and reads the `effect` peer range from each package
 * that imports Effect at module load. By default each package is
 * installed beside exactly the lowest `effect` its own range admits (its
 * floor): packages that share a floor share one scratch project, and a
 * package with a higher floor (effect-auth-alchemy's `>=4.0.0`, above the
 * programme's `>=4.0.0-rc.118`) gets a project of its own. Each project
 * imports every `exports` entry of its packages from the packed `dist/`, and
 * the project holding `@thomasfosterau/effect-auth` runs a behaviour phase.
 * A stale `dist/`, or source that calls an API the floor does not have, fails
 * here instead of in a consumer. rc.113 renamed the `Config` constructors, and
 * the published range once claimed rc.112 while the code crashed at import on
 * every later rc: the unit suite only ever runs the catalog version, so this
 * is the check that proves each lower bound.
 *
 * Every package under `packages/*` is packed, the framework bindings included,
 * and each packed manifest must set `repository.url` and `repository.directory`
 * to `packages/<dir>`. npm resolves a README's relative links against that
 * directory, so a missing or wrong value breaks them on the npm page. Every
 * offender is reported together. The bindings are packed for this check only:
 * nothing imports them here.
 *
 * Run `vp run build` first (the packed tarballs contain `dist/`), then:
 *
 *   vp run check:dist [-- --effect <version> | catalog] [--keep]
 *
 * Third-party peers are installed the same way. `alchemy` and `@effect/sql-pg`
 * (beside effect-auth-alchemy; the latter is its `./postgres` entry's optional
 * peer) and `drizzle-orm` (beside effect-auth-drizzle) go in at
 * `semver.minVersion` of the range the packed manifest declares for them, so a
 * default run proves each peer floor the way it proves `effect`. The floor must
 * be a version npm publishes: a strict bound such as `>X` can name one that was
 * never released, and the check fails then, naming the package, peer, range
 * and computed version, rather than letting the install fail with an unclear error. When
 * several packages in one project declare the same peer, the highest floor is
 * installed, and the post-install check proves every declared range holds.
 * The log prints each peer version it installs and why.
 *
 * `--effect catalog` installs every package beside the version the workspace
 * builds against, and every peer at its catalog version (the newest leg). It
 * fails if that `effect` is outside any package's peer range (the workspace
 * would be building a package against an `effect` it does not support).
 * `--effect <version>` installs every package whose peer range admits that
 * version beside it, skips (and names) each package whose range does not: a
 * version below a package's floor is a combination that package does not
 * support. Its peers are installed at their floors, as in a default run.
 * `--keep` leaves the scratch projects on disk (the path is printed) instead of
 * deleting them, for debugging a failure.
 *
 * Each scratch project is installed with pnpm, as a pnpm consumer would
 * install it, and is its own pnpm workspace: its `package.json` carries the
 * workspace's `packageManager` (so a global pnpm of another major switches to
 * the pinned one rather than installing with its own defaults) and its
 * `pnpm-workspace.yaml` holds the settings the check relies on (see
 * `workspaceYaml`). It installs with `autoInstallPeers: false` and
 * `strictPeerDependencies: false`, which installs an `effect` that a peer
 * range rejects without complaint, so after each install the check reads
 * the `effect` range every one of our packages and every peer installed
 * beside them (such as `alchemy`) declares, and fails if the installed
 * `effect` misses one. It also checks each installed peer against the range
 * our packed manifests declare for it.
 *
 * Importing is not enough: the Effect API also moved *inside* the supported
 * range in places that only bite when a function is called (rc.116 replaced
 * `SchemaGetter.onSome`, which `protectedField` builds on), so the behaviour
 * phase builds the env-backed layers and exercises `protectedField` on the
 * packed dist.
 *
 * The query operators are the same kind of gap: the drizzle stores run
 * `eq`, `inArray`, `and`, `or` and `asc` only in the catalog-version tests. So
 * the project holding effect-auth-drizzle also runs a drizzle query smoke
 * (`drizzleSmoke`) against the drizzle-orm installed beside it, which builds
 * queries over the packed tables and the package's identifier store and batched
 * request read, and asserts the SQL and parameters they generate. No connection
 * is opened.
 *
 * Not covered: the react / solid / svelte / vue bindings, which import Effect
 * only through `effect-auth-client`.
 */
import { execFileSync } from "node:child_process";
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  rmSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { basename, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import semver from "semver";

const root = resolve(import.meta.dirname, "..");

/**
 * `semver` is CommonJS, so its default import is whatever `module.exports`
 * held when Node read `node_modules/semver/index.js`. If that object lacks the
 * functions this script calls, the import still succeeds and the first call
 * fails later as `semver.minVersion is not a function` (#331). Fail here
 * instead, naming the file and its size. One known way to get there is an empty
 * or truncated read of the file; the root cause of #331 is not confirmed.
 */
if (typeof semver.minVersion !== "function" || typeof semver.satisfies !== "function") {
  // Resolved only on this path, so a healthy run never depends on
  // `import.meta.resolve`.
  const semverFile = fileURLToPath(import.meta.resolve("semver"));
  throw new Error(
    `semver loaded without its exports from ${semverFile} (${statSync(semverFile).size} bytes now). ` +
      "The module exported nothing; an empty or truncated read of the file is one known cause. " +
      "Rerun, and if it recurs, record the run on #331.",
  );
}

/** Workspace directories smoke-tested here, with any peer to install beside them. */
interface Target {
  readonly dir: string;
  /**
   * Third-party peers to install beside it: at the floor of the range the
   * packed manifest declares (the catalog version under `--effect catalog`).
   */
  readonly peers?: ReadonlyArray<string>;
}

const allTargets: ReadonlyArray<Target> = [
  // effect-jsonapi is the optional peer of the `./http` entry (#205), and of
  // the client's `./testing` entry through it: installed at its floor so those
  // entries import like the rest.
  { dir: "effect-auth", peers: ["@thomasfosterau/effect-jsonapi"] },
  { dir: "client", peers: ["@thomasfosterau/effect-jsonapi"] },
  { dir: "sql" },
  { dir: "argon2" },
  { dir: "resend" },
  { dir: "twilio" },
  { dir: "saml" },
  { dir: "sveltekit" },
  { dir: "drizzle", peers: ["drizzle-orm"] },
  // `@effect/sql-pg` is the optional peer of the `./postgres` entry: installed
  // at its floor so that entry imports like the rest.
  { dir: "alchemy", peers: ["alchemy", "@effect/sql-pg"] },
];

const arg = (flag: string): string | undefined => {
  const index = process.argv.indexOf(flag);
  return index === -1 ? undefined : process.argv[index + 1];
};

/** The version the default `catalog:` of pnpm-workspace.yaml pins for `name`. */
const catalogEntry = (name: string): string => {
  const workspace = readFileSync(join(root, "pnpm-workspace.yaml"), "utf8");
  const escaped = name.replace(/[.*+?^${}()|[\]\\/@]/g, "\\$&");
  const match = new RegExp(`^ {2}"?${escaped}"?: (\\S+)$`, "m").exec(workspace);
  if (!match?.[1]) throw new Error(`no \`${name}\` entry in the pnpm-workspace.yaml catalog`);
  return match[1];
};

/**
 * `undefined`: each package at its own floor. `"catalog"`: every package at
 * the catalog version. Anything else: every package whose range admits it.
 */
const requested = arg("--effect");
const keep = process.argv.includes("--keep");

const run = (cmd: string, args: ReadonlyArray<string>, cwd: string): string =>
  execFileSync(cmd, args, { cwd, encoding: "utf8", stdio: ["ignore", "pipe", "inherit"] });

/** The workspace's `packageManager` (`pnpm@<version>`), given to every scratch project. */
const packageManager = (() => {
  // SAFETY: the root manifest is this repository's own `package.json`.
  const value = (
    JSON.parse(readFileSync(join(root, "package.json"), "utf8")) as {
      packageManager?: string;
    }
  ).packageManager;
  if (!value?.startsWith("pnpm@"))
    throw new Error("the root package.json pins no pnpm packageManager");
  return value;
})();

/**
 * The `pnpm-workspace.yaml` of a scratch project, as JSON (a YAML subset).
 * `overrides` resolves every sibling, wherever it is depended on, to its
 * tarball; with `autoInstallPeers: false` and `strictPeerDependencies: false`
 * pnpm installs exactly the `effect` and peers the manifest names, in range or
 * not (npm's `--legacy-peer-deps`), and the checks after the install judge it.
 */
const workspaceYaml = (overrides: Record<string, string>): string =>
  JSON.stringify(
    { packages: ["."], autoInstallPeers: false, strictPeerDependencies: false, overrides },
    null,
    2,
  );

const publishedCache = new Map<string, ReadonlyArray<string>>();

/** Every version of `name` the registry publishes, read once per package. */
const publishedVersions = (name: string): ReadonlyArray<string> => {
  let versions = publishedCache.get(name);
  if (!versions) {
    const parsed: unknown = JSON.parse(run("pnpm", ["view", name, "versions", "--json"], root));
    // A lone version prints as a string and several as an array.
    versions = [parsed].flat().map(String);
    publishedCache.set(name, versions);
  }
  return versions;
};

/**
 * The lowest version `range` admits, which must be one npm publishes. A strict
 * lower bound such as `>X` can name a version that was never released
 * (`>2.0.0-beta.79` gives `2.0.0-beta.79.0`), and an install at that version
 * fails with an unclear error, so it is refused here, naming the package, the
 * peer, the range and the computed version.
 */
const floorOf = (owner: string, peer: string, range: string): string => {
  const version = semver.minVersion(range)?.version;
  if (!version) throw new Error(`${owner}: ${peer} peer range ${range} has no lowest version`);
  if (!publishedVersions(peer).includes(version)) {
    throw new Error(
      `${owner}: ${peer} peer range ${range} has the lowest version ${version}, which npm does not publish (a strict lower bound such as \`>X\` can name a version that was never released; use \`>=\`)`,
    );
  }
  return version;
};

/**
 * Every installed copy of `effect`, as the real path of each directory pnpm
 * linked it from (`node_modules/.pnpm/effect@<version>/node_modules/effect`),
 * so one copy reached along several paths is listed once per path but under
 * one name. Should `pnpm list` exit non-zero (over the tree's peers, say), its
 * output is still the answer, so only that is used.
 */
const listEffectCopies = (cwd: string): ReadonlyArray<string> => {
  let out: string;
  try {
    out = run("pnpm", ["list", "effect", "--depth", "Infinity", "--parseable"], cwd);
  } catch (error) {
    // `execFileSync` attaches the child's captured output to the error it
    // throws for a failed child.
    out = error instanceof Error && "stdout" in error ? String(error.stdout) : "";
  }
  return out.split("\n").filter((line) => line.endsWith("/node_modules/effect"));
};

/**
 * Each `effect` range that one of `names` (our packages, and the peers
 * installed beside them) declares and the installed `effect` misses, read from
 * the installed manifests. Ranges stated deeper in the tree are not checked:
 * they belong to a third party's own dependency choices, not to a floor this
 * repo claims (on 2026-10-04 alchemy's `@effect/sql-d1 ^4.0.0` resolved to
 * 4.0.1, which peers `effect ^4.0.1`, before any `effect` 4.0.1 existed).
 */
const unmetEffectRanges = (
  project: string,
  installed: string,
  names: ReadonlyArray<string>,
): ReadonlyArray<string> =>
  names.flatMap((name) => {
    const path = join(project, "node_modules", name, "package.json");
    if (!existsSync(path)) return [];
    // SAFETY: an installed package's `package.json` is a manifest: `name` is
    // always present and every other field `Manifest` reads is optional.
    const manifest = JSON.parse(readFileSync(path, "utf8")) as Manifest;
    return [manifest.peerDependencies?.effect, manifest.dependencies?.effect]
      .filter((range): range is string => range !== undefined)
      .filter((range) => !semver.satisfies(installed, range))
      .map((range) => `${name} wants effect ${range}`);
  });

interface Manifest {
  readonly name: string;
  readonly repository?: { readonly url?: string; readonly directory?: string };
  readonly exports?: Record<string, { readonly import?: string } | string>;
  readonly dependencies?: Record<string, string>;
  readonly peerDependencies?: Record<string, string>;
}

/** A target after `pnpm pack`, with the manifest exactly as it will publish. */
interface Packed {
  readonly target: Target;
  readonly manifest: Manifest;
  /** The tarball's file name inside the scratch directory. */
  readonly file: string;
  /** The packed `peerDependencies.effect` (`catalog:*` already replaced). */
  readonly range: string;
}

/**
 * The `effect` version to install `packed` beside, or `undefined` to skip it
 * (an explicit `--effect` outside its range).
 */
const effectFor = ({ manifest: { name }, range }: Packed): string | undefined => {
  if (requested === undefined) return floorOf(name, "effect", range);
  const version = requested === "catalog" ? catalogEntry("effect") : requested;
  if (semver.satisfies(version, range)) return version;
  if (requested === "catalog") {
    throw new Error(`${name} peers effect ${range}, which the catalog's effect ${version} misses`);
  }
  console.log(`skip ${name}: effect ${version} is outside its peer range ${range}`);
  return undefined;
};

/**
 * The version of third-party `peer` to install beside `group`, and why. By
 * default the highest floor among the ranges the group's packed manifests
 * declare for it, so one install satisfies every declared range; under
 * `--effect catalog` the catalog version, as for `effect`.
 */
const peerVersionFor = (
  group: ReadonlyArray<Packed>,
  peer: string,
): { readonly version: string; readonly why: string } => {
  if (requested === "catalog") return { version: catalogEntry(peer), why: "catalog" };
  const floors = group.flatMap(({ manifest }) => {
    const range = manifest.peerDependencies?.[peer];
    if (range === undefined) return [];
    return [{ version: floorOf(manifest.name, peer, range), why: `floor of ${range}` }];
  });
  if (floors.length === 0) {
    throw new Error(
      `no package in ${group.map(({ manifest }) => manifest.name).join(", ")} declares a ${peer} peer`,
    );
  }
  return floors.reduce((highest, next) =>
    semver.gt(next.version, highest.version) ? next : highest,
  );
};

/**
 * Each range that one of `group`'s packed manifests declares for `peer` and the
 * installed copy misses. The highest floor is installed, so this fails only
 * when two packages in the group declare ranges no single version satisfies.
 */
const unmetPeerRanges = (
  peer: string,
  installed: string,
  group: ReadonlyArray<Packed>,
): ReadonlyArray<string> =>
  group.flatMap(({ manifest }) => {
    const range = manifest.peerDependencies?.[peer];
    return range !== undefined && !semver.satisfies(installed, range)
      ? [`${manifest.name} wants ${peer} ${range}, installed ${installed}`]
      : [];
  });

/** Runs inside the scratch project, against the packed `dist/` only. */
const behaviour = `
import { ConfigProvider, Effect, Layer, Redacted, Result, Schema } from "effect";
import * as Auth from "@thomasfosterau/effect-auth";

const check = (name, ok) => {
  if (!ok) throw new Error("behaviour check failed: " + name);
  console.log("ok   " + name);
};

// Env-backed Configs (renamed in rc.113).
const env = ConfigProvider.layer(
  ConfigProvider.fromEnv({
    env: { JWT_ISSUER: "https://issuer.test", JWT_ENCRYPT_PRIVATE_KEY_SECRET: "s3cret" },
  }),
);
const jwt = await Effect.runPromise(Auth.jwtServiceConfig.pipe(Effect.provide(env)));
check("jwtServiceConfig reads the environment", jwt.issuer === "https://issuer.test");
check(
  "jwtServiceConfig redacts the secret",
  Redacted.value(jwt.encryptPrivateKey.secret) === "s3cret",
);

// protectedField (built on SchemaGetter.transformOptionalEffect).
const alice = Auth.Entity.ref("User", "alice");
const bob = Auth.Entity.ref("User", "bob");
const resolver = Layer.succeed(
  Auth.EntityResolver,
  Auth.memoryEntityResolver([
    Auth.Entity.entity(alice, { parents: [Auth.Entity.ref("Role", "admin")] }),
  ]),
);
const View = Schema.Struct({
  id: Schema.String,
  email: Auth.protectedField(Schema.String, {
    policies: Auth.Policy.role("admin", {
      action: Auth.Policy.eq(Auth.Entity.ref("Action", "user:read-email")),
    }),
    action: "user:read-email",
  }),
});
const as = (principal, effect) =>
  effect.pipe(Auth.CurrentPrincipal.provide(principal), Effect.provide(resolver));
const encode = (principal, value) =>
  Effect.runPromise(as(principal, Schema.encodeEffect(View)(value)));
const decode = (principal, input) =>
  Effect.runPromise(Effect.result(as(principal, Schema.decodeUnknownEffect(View)(input))));

const full = { id: "u-1", email: "a@example.com" };
check("protectedField keeps the field for an admin", (await encode(alice, full)).email === "a@example.com");
check("protectedField drops the key for a non-admin", !("email" in (await encode(bob, full))));
check("protectedField passes an absent value through", !("email" in (await encode(bob, { id: "u-1" }))));
check("protectedField decodes for an admin", Result.isSuccess(await decode(alice, full)));
check("protectedField rejects a non-admin write", Result.isFailure(await decode(bob, full)));
`;

/**
 * Runs inside the project that holds effect-auth-drizzle, against the packed
 * `dist/` and the drizzle-orm installed beside it (its floor by default, the
 * catalog version under `--effect catalog`). Nothing here opens a connection:
 * `drizzle-orm/pg-proxy` takes a callback in place of a driver, which records
 * each statement and returns no rows, so `.toSQL()` and `.execute()` build the
 * SQL a store sends. The direct query uses `eq`, `inArray` and
 * `orderBy(asc(...))` over the package's own tables; the store and request
 * reads are the package's code paths, asserted the same way. Every drizzle
 * import is made inside the check, so a missing operator reports as a
 * `FAIL drizzle query smoke` line naming the drizzle-orm version.
 */
const drizzleSmoke = `
import { readFileSync } from "node:fs";

const drizzleVersion = JSON.parse(
  readFileSync(new URL("./node_modules/drizzle-orm/package.json", import.meta.url), "utf8"),
).version;

const failure = (message) =>
  "FAIL drizzle query smoke: " + message + " (drizzle-orm " + drizzleVersion + ")";

const expectSql = (name, actual, expected) => {
  if (actual.sql !== expected.sql) {
    throw new Error(name + " SQL is\\n  " + actual.sql + "\\nexpected\\n  " + expected.sql);
  }
  if (JSON.stringify(actual.params) !== JSON.stringify(expected.params)) {
    throw new Error(
      name + " params are " + JSON.stringify(actual.params) +
        ", expected " + JSON.stringify(expected.params),
    );
  }
  console.log("ok   " + name);
};

const main = async () => {
  const { and, asc, eq, inArray } = await import("drizzle-orm");
  const { drizzle } = await import("drizzle-orm/pg-proxy");
  const { Effect, Layer } = await import("effect");
  const Drizzle = await import("@thomasfosterau/effect-auth-drizzle");

  const sent = [];
  const db = drizzle(async (sql, params) => {
    sent.push({ sql, params });
    return { rows: [] };
  });
  const { identifiers } = Drizzle.Pg.tables;
  const table = '"effect_auth_identifiers"';
  const cols = ["id", "user_id", "type", "value", "verified", "verified_at", "created_at"];
  const select = "select " + cols.map((name) => '"' + name + '"').join(", ") + " from " + table;

  // The operators the stores use, built directly over the packed table.
  const direct = db
    .select()
    .from(identifiers)
    .where(
      and(
        eq(identifiers.type, "email"),
        inArray(identifiers.value, ["a@example.test", "b@example.test"]),
      ),
    )
    .orderBy(asc(identifiers.createdAt))
    .toSQL();
  expectSql("eq, inArray and orderBy(asc) build", direct, {
    sql:
      select +
      " where (" + table + '."type" = $1 and ' + table + '."value" in ($2, $3)) order by ' +
      table + '."created_at" asc',
    params: ["email", "a@example.test", "b@example.test"],
  });

  // The identifier store's list read: eq + orderBy(asc), run through the store.
  const store = await Effect.runPromise(
    Drizzle.IdentifierStore.make().pipe(Effect.provide(Drizzle.databaseLayer(db))),
  );
  const listed = await Effect.runPromise(store.listByUser("user-1"));
  if (listed.length !== 0) throw new Error("store read returned rows from an empty database");
  expectSql("IdentifierStore.listByUser builds", sent.pop(), {
    sql: select + " where " + table + '."user_id" = $1 order by ' + table + '."created_at" asc',
    params: ["user-1"],
  });

  // The batched request read: two lookups, one WHERE ... IN (...) statement.
  const requests = Drizzle.Requests.layer().pipe(Layer.provide(Drizzle.databaseLayer(db)));
  const batched = await Effect.runPromise(
    Effect.all(
      [
        Drizzle.Requests.listIdentifiersByUser("user-1"),
        Drizzle.Requests.listIdentifiersByUser("user-2"),
      ],
      { concurrency: "unbounded" },
    ).pipe(Effect.provide(requests)),
  );
  if (batched.length !== 2) throw new Error("the batched read did not resolve both lookups");
  if (sent.length !== 1) {
    throw new Error("two lookups sent " + sent.length + " statements, expected one batched query");
  }
  expectSql("Requests.listIdentifiersByUser batches", sent.pop(), {
    sql:
      select + " where " + table + '."user_id" in ($1, $2) order by ' + table + '."created_at" asc',
    params: ["user-1", "user-2"],
  });
};

main().catch((error) => {
  console.error(failure(error instanceof Error ? error.message : String(error)));
  process.exit(1);
});
`;

const scratch = mkdtempSync(join(tmpdir(), "effect-auth-dist-"));
try {
  // Every package, the bindings too: their manifests are checked below even
  // though nothing imports them.
  const dirs = readdirSync(join(root, "packages"), { withFileTypes: true })
    .filter((entry) => entry.isDirectory())
    .map((entry) => entry.name)
    .sort();
  const directoryErrors: Array<string> = [];
  const packed: Array<Packed> = [];
  for (const dir of dirs) {
    const cwd = join(root, "packages", dir);
    const dist = join(cwd, "dist");
    if (!existsSync(dist) || !readdirSync(dist, { withFileTypes: true }).length) {
      throw new Error(`${dir}: dist/ is missing or empty; run \`vp run build\` first`);
    }
    // `pnpm pack` rewrites `catalog:` / `workspace:*` exactly as publishing does.
    // pnpm prints the tarball path last, so there is no filename to guess at.
    const printed = run("pnpm", ["pack", "--pack-destination", scratch], cwd)
      .trim()
      .split("\n")
      .pop();
    const file = printed ? basename(printed.trim()) : undefined;
    if (!file?.endsWith(".tgz")) throw new Error(`${dir}: pnpm pack printed no tarball`);
    // The floor comes from the manifest a consumer will see, not a constant
    // here, so a peer range and the version it is checked at cannot drift.
    // SAFETY: a packed `package.json` is a manifest: `name` is always present and
    // every other field `Manifest` reads is optional (and checked below).
    const manifest = JSON.parse(
      run("tar", ["-xzOf", file, "package/package.json"], scratch),
    ) as Manifest;
    const expectedDirectory = `packages/${dir}`;
    if (!manifest.repository?.url) {
      directoryErrors.push(`${manifest.name}: repository.url is missing`);
    }
    if (manifest.repository?.directory !== expectedDirectory) {
      const found = manifest.repository?.directory;
      directoryErrors.push(
        `${manifest.name}: repository.directory is ${found === undefined ? "missing" : JSON.stringify(found)}, expected "${expectedDirectory}"`,
      );
    }
    const target = allTargets.find((candidate) => candidate.dir === dir);
    if (!target) continue;
    const range = manifest.peerDependencies?.effect;
    if (!range) throw new Error(`${manifest.name}: the packed manifest has no effect peer`);
    packed.push({ target, manifest, file, range });
  }
  if (directoryErrors.length > 0) {
    throw new Error(
      `packed manifests must set repository.url and repository.directory (their own packages/<dir>):\n${directoryErrors.join("\n")}`,
    );
  }

  // The packed manifests depend on siblings by their real version, which is
  // not on npm yet; resolve every sibling to its tarball in every project.
  const siblings = Object.fromEntries(
    packed.map(({ manifest, file }) => [manifest.name, `file:../${file}`]),
  );

  const groups = new Map<string, Array<Packed>>();
  for (const p of packed) {
    const version = effectFor(p);
    if (version !== undefined) groups.set(version, [...(groups.get(version) ?? []), p]);
  }
  if (groups.size === 0) throw new Error(`no package's effect peer range admits ${requested}`);

  for (const [effectVersion, group] of [...groups].sort(([a], [b]) => semver.compare(a, b))) {
    const names = group.map(({ manifest }) => manifest.name);
    console.log(`effect ${effectVersion}: ${names.join(", ")}`);
    const project = join(scratch, `project-${effectVersion}`);
    mkdirSync(project);
    const peers = new Set(group.flatMap(({ target }) => target.peers ?? []));
    const peerVersions = new Map([...peers].map((peer) => [peer, peerVersionFor(group, peer)]));
    for (const [peer, { version, why }] of peerVersions) {
      console.log(`  peer ${peer} ${version} (${why})`);
    }
    writeFileSync(
      join(project, "package.json"),
      JSON.stringify(
        {
          name: "effect-auth-dist-smoke",
          private: true,
          type: "module",
          dependencies: {
            effect: effectVersion,
            ...Object.fromEntries([...peerVersions].map(([peer, { version }]) => [peer, version])),
            ...Object.fromEntries(names.map((name) => [name, siblings[name]])),
          },
          packageManager,
        },
        null,
        2,
      ),
    );
    writeFileSync(join(project, "pnpm-workspace.yaml"), workspaceYaml(siblings));
    // No lockfile exists to freeze (pnpm freezes by default under CI).
    run(
      "pnpm",
      ["install", "--no-frozen-lockfile", "--ignore-scripts", "--reporter=append-only"],
      project,
    );

    // SAFETY: an installed package's manifest always carries its `version`.
    const installed = (
      JSON.parse(readFileSync(join(project, "node_modules", "effect", "package.json"), "utf8")) as {
        version: string;
      }
    ).version;
    if (installed !== effectVersion) {
      throw new Error(`expected effect ${effectVersion}, installed ${installed}`);
    }
    const copies = listEffectCopies(project);
    if (new Set(copies).size !== 1) {
      throw new Error(`expected one copy of effect, found:\n${copies.join("\n")}`);
    }
    // pnpm installed whatever `effect` was asked for (no peer is enforced), in
    // range or not, so prove the installed one is in every range that counts.
    const unmet = unmetEffectRanges(project, installed, [...Object.keys(siblings), ...peers]);
    if (unmet.length > 0) {
      throw new Error(`effect ${installed} is outside a declared range:\n${unmet.join("\n")}`);
    }
    for (const [peer, { version }] of peerVersions) {
      // SAFETY: an installed package's manifest always carries its `version`.
      const peerManifest = JSON.parse(
        readFileSync(join(project, "node_modules", peer, "package.json"), "utf8"),
      ) as { version: string };
      const installedPeer = peerManifest.version;
      if (!semver.satisfies(installedPeer, version)) {
        throw new Error(`expected ${peer} ${version}, installed ${installedPeer}`);
      }
      const unmetPeer = unmetPeerRanges(peer, installedPeer, group);
      if (unmetPeer.length > 0) {
        throw new Error(
          `peer ${peer} ${installedPeer} is outside a declared range:\n${unmetPeer.join("\n")}`,
        );
      }
      console.log(`  peer ${peer}: installed ${installedPeer}`);
    }

    const specifiers = group.flatMap(({ manifest }) =>
      Object.keys(manifest.exports ?? {}).map((key) =>
        key === "." ? manifest.name : `${manifest.name}/${key.slice(2)}`,
      ),
    );
    writeFileSync(
      join(project, "smoke.mjs"),
      `const specifiers = ${JSON.stringify(specifiers)};
let failed = 0;
for (const specifier of specifiers) {
  try {
    const mod = await import(specifier);
    if (Object.keys(mod).length === 0) throw new Error("no exports");
    console.log("ok   " + specifier);
  } catch (error) {
    failed++;
    console.error("FAIL " + specifier + ": " + (error instanceof Error ? error.message : error));
  }
}
process.exit(failed === 0 ? 0 : 1);
`,
    );
    console.log(
      `effect ${installed}: importing ${specifiers.length} entry points from packed dist`,
    );
    console.log(run("node", ["smoke.mjs"], project));
    if (names.includes("@thomasfosterau/effect-auth")) {
      writeFileSync(join(project, "behaviour.mjs"), behaviour);
      console.log(`effect ${installed}: exercising config layers and protectedField`);
      console.log(run("node", ["behaviour.mjs"], project));
    }
    if (names.includes("@thomasfosterau/effect-auth-drizzle")) {
      writeFileSync(join(project, "drizzle.mjs"), drizzleSmoke);
      console.log(`effect ${installed}: drizzle query smoke over the installed drizzle-orm`);
      console.log(run("node", ["drizzle.mjs"], project));
    }
  }
} finally {
  if (keep) console.log(`kept ${scratch}`);
  else rmSync(scratch, { recursive: true, force: true });
}
