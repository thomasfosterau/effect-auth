/**
 * Dist-level import smoke test for the published Effect floor.
 *
 * Packs every package that imports Effect at module load, installs the
 * tarballs into a scratch project next to ONE exact `effect` version (by
 * default the published peer floor), and imports every `exports` entry from
 * the packed `dist/`, then runs `behaviour.mjs` against it. A stale `dist/`, or source that calls an API the floor
 * does not have, fails here instead of in a consumer. rc.113 renamed the
 * `Config` constructors, and the published range once claimed rc.112 while the
 * code crashed at import on every later rc: the unit suite only ever runs the
 * catalog version, so this is the check that proves the lower bound.
 *
 * Run `vp run build` first (the packed tarballs contain `dist/`), then:
 *
 *   vp run check:dist [-- --effect <version> | catalog]
 *
 * Importing is not enough: the Effect API also moved *inside* the supported
 * range in places that only bite when a function is called (rc.116 replaced
 * `SchemaGetter.onSome`, which `protectedField` builds on), so the behaviour
 * phase builds the env-backed layers and exercises `protectedField` on the
 * packed dist.
 *
 * Not covered: `@thomasfosterau/effect-auth-alchemy` (its `alchemy` peer needs
 * effect >=rc.115, so it cannot be installed on the floor; its unit suite
 * covers it against the catalog version) and the react / solid / svelte / vue
 * bindings, which import Effect only through `effect-auth-client`.
 */
import { execFileSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";

const root = resolve(import.meta.dirname, "..");
const DEFAULT_FLOOR = "4.0.0-rc.113";

/** Workspace directories smoke-tested here, with any peer to install beside them. */
const packages: ReadonlyArray<{ readonly dir: string; readonly peers?: ReadonlyArray<string> }> = [
  { dir: "effect-auth" },
  { dir: "client" },
  { dir: "sql" },
  { dir: "argon2" },
  { dir: "resend" },
  { dir: "twilio" },
  { dir: "saml" },
  { dir: "drizzle", peers: ["drizzle-orm"] },
];

const arg = (flag: string): string | undefined => {
  const index = process.argv.indexOf(flag);
  return index === -1 ? undefined : process.argv[index + 1];
};

/** `--effect catalog` tests the version the workspace itself builds against. */
const catalogEffect = (): string => {
  const workspace = readFileSync(join(root, "pnpm-workspace.yaml"), "utf8");
  const match = /^ {2}effect: (\S+)$/m.exec(workspace);
  if (!match?.[1]) throw new Error("no `effect` entry in the pnpm-workspace.yaml catalog");
  return match[1];
};

const requested = arg("--effect") ?? DEFAULT_FLOOR;
const effectVersion = requested === "catalog" ? catalogEffect() : requested;
const keep = process.argv.includes("--keep");

const run = (cmd: string, args: ReadonlyArray<string>, cwd: string): string =>
  execFileSync(cmd, args, { cwd, encoding: "utf8", stdio: ["ignore", "pipe", "inherit"] });

interface Manifest {
  readonly name: string;
  readonly exports?: Record<string, { readonly import?: string } | string>;
  readonly peerDependencies?: Record<string, string>;
}

const readManifest = (dir: string): Manifest =>
  JSON.parse(readFileSync(join(root, "packages", dir, "package.json"), "utf8")) as Manifest;

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

// protectedField (rc.113-rc.115 have SchemaGetter.onSome; rc.116+ have transformOptionalEffect).
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
  const tarballs = new Map<string, string>();
  for (const { dir } of packages) {
    const manifest = readManifest(dir);
    const dist = join(root, "packages", dir, "dist");
    if (!readdirSync(dist, { withFileTypes: true }).length) {
      throw new Error(`${manifest.name}: dist/ is empty; run \`vp run build\` first`);
    }
    // `pnpm pack` rewrites `catalog:` / `workspace:*` exactly as publishing does.
    run("pnpm", ["pack", "--pack-destination", scratch], join(root, "packages", dir));
    const file = readdirSync(scratch).find(
      (f) => f.endsWith(".tgz") && f.startsWith(manifest.name.replace("@", "").replace("/", "-")),
    );
    if (!file) throw new Error(`${manifest.name}: pnpm pack produced no tarball`);
    tarballs.set(manifest.name, `file:./${file}`);
  }

  const peers = new Set(packages.flatMap((p) => p.peers ?? []));
  const project = join(scratch, "project");
  mkdirSync(project);
  writeFileSync(
    join(project, "package.json"),
    JSON.stringify(
      {
        name: "effect-auth-dist-smoke",
        private: true,
        type: "module",
        dependencies: {
          effect: effectVersion,
          ...Object.fromEntries([...peers].map((peer) => [peer, "*"])),
          ...Object.fromEntries(
            [...tarballs].map(([name, spec]) => [name, `file:../${spec.slice(7)}`]),
          ),
        },
        // The packed manifests depend on siblings by their real version, which
        // is not on npm yet; resolve them to the tarballs instead.
        overrides: Object.fromEntries(
          [...tarballs].map(([name, spec]) => [name, `file:../${spec.slice(7)}`]),
        ),
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
  const copies = run("npm", ["ls", "effect", "--all", "--parseable"], project)
    .split("\n")
    .filter((line) => line.endsWith("/node_modules/effect"));
  if (new Set(copies).size !== 1) {
    throw new Error(`expected one copy of effect, found:\n${copies.join("\n")}`);
  }

  const specifiers = packages.flatMap(({ dir }) => {
    const manifest = readManifest(dir);
    return Object.keys(manifest.exports ?? {}).map((key) =>
      key === "." ? manifest.name : `${manifest.name}/${key.slice(2)}`,
    );
  });
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
  writeFileSync(join(project, "behaviour.mjs"), behaviour);
  console.log(`effect ${installed}: importing ${specifiers.length} entry points from packed dist`);
  console.log(run("node", ["smoke.mjs"], project));
  console.log(`effect ${installed}: exercising config layers and protectedField`);
  console.log(run("node", ["behaviour.mjs"], project));
} finally {
  if (keep) console.log(`kept ${scratch}`);
  else rmSync(scratch, { recursive: true, force: true });
}
