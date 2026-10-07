/**
 * Dist-level import smoke test for each package's published Effect floor.
 *
 * Packs every package that imports Effect at module load and reads the
 * `effect` peer range from each packed manifest. By default each package is
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
 * `--effect catalog` installs every package beside the version the workspace
 * builds against, and fails if that version is outside any package's peer
 * range (the workspace would be building a package against an `effect` it
 * does not support). `--effect <version>` installs every package whose peer
 * range admits that version beside it, and skips (and names) each package
 * whose range does not: a version below a package's floor is a combination
 * that package does not support. `--keep` leaves the scratch projects on disk
 * (the path is printed) instead of deleting them, for debugging a failure.
 *
 * The install uses `--legacy-peer-deps`, which installs an `effect` that a
 * peer range rejects without complaint, so after each install the check reads
 * the `effect` range every one of our packages and every peer installed
 * beside them (such as `alchemy`) declares, and fails if the installed
 * `effect` misses one.
 *
 * Importing is not enough: the Effect API also moved *inside* the supported
 * range in places that only bite when a function is called (rc.116 replaced
 * `SchemaGetter.onSome`, which `protectedField` builds on), so the behaviour
 * phase builds the env-backed layers and exercises `protectedField` on the
 * packed dist.
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
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { basename, join, resolve } from "node:path";
import semver from "semver";

const root = resolve(import.meta.dirname, "..");

/** Workspace directories smoke-tested here, with any peer to install beside them. */
interface Target {
  readonly dir: string;
  /** Peers to install beside it, at the version the workspace catalog pins. */
  readonly peers?: ReadonlyArray<string>;
}

const allTargets: ReadonlyArray<Target> = [
  { dir: "effect-auth" },
  { dir: "client" },
  { dir: "sql" },
  { dir: "argon2" },
  { dir: "resend" },
  { dir: "twilio" },
  { dir: "saml" },
  { dir: "drizzle", peers: ["drizzle-orm"] },
  { dir: "alchemy", peers: ["alchemy"] },
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

/**
 * Every installed copy of `effect`. `npm ls` exits non-zero for any unmet
 * peer in the tree (a transitive dependency wanting a newer `effect`, say),
 * which is not what is being asked here, so only its output is used.
 */
const listEffectCopies = (cwd: string): ReadonlyArray<string> => {
  let out: string;
  try {
    out = run("npm", ["ls", "effect", "--all", "--parseable"], cwd);
  } catch (error) {
    out = String((error as { stdout?: unknown }).stdout ?? "");
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
  if (requested === undefined) {
    const floor = semver.minVersion(range)?.version;
    if (!floor) throw new Error(`${name}: effect peer range ${range} has no lowest version`);
    return floor;
  }
  const version = requested === "catalog" ? catalogEntry("effect") : requested;
  if (semver.satisfies(version, range)) return version;
  if (requested === "catalog") {
    throw new Error(`${name} peers effect ${range}, which the catalog's effect ${version} misses`);
  }
  console.log(`skip ${name}: effect ${version} is outside its peer range ${range}`);
  return undefined;
};

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
    if (!readdirSync(dist, { withFileTypes: true }).length) {
      throw new Error(`${dir}: dist/ is empty; run \`vp run build\` first`);
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
      `packed manifests must set repository.directory to their own packages/<dir>:\n${directoryErrors.join("\n")}`,
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
    writeFileSync(
      join(project, "package.json"),
      JSON.stringify(
        {
          name: "effect-auth-dist-smoke",
          private: true,
          type: "module",
          dependencies: {
            effect: effectVersion,
            ...Object.fromEntries([...peers].map((peer) => [peer, catalogEntry(peer)])),
            ...Object.fromEntries(names.map((name) => [name, siblings[name]])),
          },
          overrides: siblings,
        },
        null,
        2,
      ),
    );
    run(
      "npm",
      [
        "install",
        "--no-audit",
        "--no-fund",
        "--ignore-scripts",
        "--legacy-peer-deps",
        "--loglevel=error",
      ],
      project,
    );

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
    // `--legacy-peer-deps` installed whatever `effect` was asked for, in
    // range or not, so prove the installed one is in every range that counts.
    const unmet = unmetEffectRanges(project, installed, [...Object.keys(siblings), ...peers]);
    if (unmet.length > 0) {
      throw new Error(`effect ${installed} is outside a declared range:\n${unmet.join("\n")}`);
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
  }
} finally {
  if (keep) console.log(`kept ${scratch}`);
  else rmSync(scratch, { recursive: true, force: true });
}
