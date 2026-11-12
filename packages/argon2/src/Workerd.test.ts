/**
 * The hasher inside a real workerd (#744), the runtime the package claims.
 *
 * workerd refuses to generate wasm code while it serves a request
 * (`CompileError: WebAssembly.compile(): Wasm code generation disallowed by
 * embedder`). A backend that compiles its wasm lazily, on the first hash, as
 * hash-wasm did through 0.1.x, therefore fails every sign-up and sign-in on a
 * deployed Worker while passing every Node test. The kernel compiles at
 * module scope instead, which workerd allows from compatibility date
 * 2025-06-01 (`allow_eval_during_startup`) and refuses before it.
 *
 * This suite bundles a worker around the hasher, as an app's bundler would,
 * serves it from the `workerd` binary at workerd's newest compatibility date
 * and at 2023-01-01 with `allow_eval_during_startup`, and hashes and verifies
 * inside `fetch`; it also pins that the 2023 date without the flag refuses
 * the worker at startup.
 */
import { spawn } from "node:child_process";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { createRequire } from "node:module";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createInterface } from "node:readline";
import { Readable } from "node:stream";
import { fileURLToPath } from "node:url";
import { rolldown, type Plugin } from "vite/rolldown";
import { afterAll, assert, beforeAll, describe, expect, it } from "vite-plus/test";
import { Data } from "effect";
import * as Option from "effect/Option";
import * as R from "effect/Record";
import * as Schema from "effect/Schema";
import { hashWasmFixtures } from "./HashWasm.fixtures.ts";

/** The `workerd` package's entry: the platform binary's path and its newest compatibility date. */
const Workerd = Schema.Struct({ default: Schema.String, compatibilityDate: Schema.String });
const workerd = Schema.decodeUnknownSync(Workerd)(createRequire(import.meta.url)("workerd"));

/** A worker service: its compatibility date and flags. */
interface WorkerConfig {
  readonly date: string;
  readonly flags: ReadonlyArray<string>;
}

const LEGACY_DATE = "2023-01-01";

/**
 * The workers served for the whole suite. Before 2026-08-04 the core's
 * `node:crypto` import needs `nodejs_compat`; before 2025-06-01 the kernel's
 * module-scope compile needs `allow_eval_during_startup`.
 */
const SERVED = {
  current: { date: workerd.compatibilityDate, flags: [] },
  legacy: { date: LEGACY_DATE, flags: ["nodejs_compat", "allow_eval_during_startup"] },
} as const satisfies Record<string, WorkerConfig>;
type ServedName = keyof typeof SERVED;
const SERVED_NAMES = ["current", "legacy"] as const satisfies ReadonlyArray<ServedName>;

/** workerd stopped before every socket listened. */
class WorkerdExited extends Data.TaggedError("WorkerdExited")<{
  readonly code: number | null;
  readonly stderr: string;
}> {}

const srcDir = fileURLToPath(new URL(".", import.meta.url));
// A path beside the sources, so the entry's bare imports resolve from this package.
const ENTRY = join(srcDir, "__workerd_entry__.ts");

const WORKER_SOURCE = `
import { Effect } from "effect";
import { argon2Hasher } from "./index.ts";

// The smallest valid wasm module: the magic number and version 1.
const EMPTY_MODULE = new Uint8Array([0, 97, 115, 109, 1, 0, 0, 0]);
const PRECOMPILED = new WebAssembly.Module(EMPTY_MODULE);

const attempt = async (thunk) => {
  try {
    await thunk();
    return { ok: true };
  } catch (error) {
    return { ok: false, threw: String(error) };
  }
};

const run = (effect) =>
  Effect.runPromise(
    Effect.match(effect, {
      onSuccess: (value) => ({ ok: true, value }),
      onFailure: (error) => ({ ok: false, tag: error._tag, message: error.message, cause: String(error.cause) }),
    }),
  );

const hasher = argon2Hasher();

export default {
  async fetch(request) {
    const url = new URL(request.url);
    if (url.pathname === "/probe") {
      return Response.json({
        compile: await attempt(() => WebAssembly.compile(EMPTY_MODULE)),
        module: await attempt(() => new WebAssembly.Module(EMPTY_MODULE)),
        instance: await attempt(() => new WebAssembly.Instance(PRECOMPILED, {})),
      });
    }
    if (url.pathname === "/roundtrip") {
      const password = "correct horse battery staple";
      const hashed = await run(hasher.hash(password));
      if (!hashed.ok) return Response.json({ hashed });
      return Response.json({
        hashed,
        verified: await run(hasher.verify(password, hashed.value.hash)),
        rejected: await run(hasher.verify("not the password", hashed.value.hash)),
      });
    }
    const { password, hash } = await request.json();
    return Response.json(await run(hasher.verify(password, hash)));
  },
};
`;

const entryPlugin: Plugin = {
  name: "workerd-entry",
  resolveId: (id) => (id === ENTRY ? ENTRY : undefined),
  load: (id) => (id === ENTRY ? { code: WORKER_SOURCE, moduleType: "js" } : undefined),
};

/** Bundle the worker into one ES module; `node:*` stays external for `nodejs_compat`. */
const bundleWorker = async (): Promise<string> => {
  const bundle = await rolldown({
    input: ENTRY,
    platform: "browser",
    external: [/^node:/],
    plugins: [entryPlugin],
    logLevel: "silent",
  });
  const { output } = await bundle.generate({ format: "esm", codeSplitting: false });
  await bundle.close();
  const [chunk] = output;
  assert(chunk.type === "chunk", "the bundle is one chunk");
  return chunk.code;
};

const serviceConfig = ([name, { date, flags }]: readonly [string, WorkerConfig]): string => {
  const flagList = flags.map((flag) => `"${flag}"`).join(", ");
  return `(name = "${name}", worker = (modules = [(name = "worker.js", esModule = embed "worker.js")], compatibilityDate = "${date}", compatibilityFlags = [${flagList}]))`;
};

const socketConfig = (name: string): string =>
  `(name = "${name}", address = "127.0.0.1:0", http = (), service = "${name}")`;

const configFor = (workers: Readonly<Record<string, WorkerConfig>>): string =>
  `using Workerd = import "/workerd/workerd.capnp";
const config :Workerd.Config = (
  services = [${R.toEntries(workers).map(serviceConfig).join(", ")}],
  sockets = [${R.keys(workers).map(socketConfig).join(", ")}],
);
`;

/** One line workerd writes to its control fd once a socket listens. */
const ListenEvent = Schema.fromJsonString(
  Schema.Struct({ event: Schema.Literal("listen"), socket: Schema.String, port: Schema.Finite }),
);
const decodeListen = Schema.decodeUnknownOption(ListenEvent);

interface Runtime {
  readonly ports: Readonly<Record<string, number>>;
  readonly stderr: () => string;
  readonly stop: () => Promise<void>;
}

let bundled: Promise<string> | undefined;

/** Serve the bundled worker under each of `workers`, resolving once every socket listens. */
const serve = async (workers: Readonly<Record<string, WorkerConfig>>): Promise<Runtime> => {
  bundled ??= bundleWorker();
  const workDir = await mkdtemp(join(tmpdir(), "effect-auth-argon2-workerd-"));
  await writeFile(join(workDir, "worker.js"), await bundled);
  await writeFile(join(workDir, "config.capnp"), configFor(workers));

  const child = spawn(workerd.default, ["serve", "config.capnp", "--control-fd=3"], {
    cwd: workDir,
    stdio: ["ignore", "ignore", "pipe", "pipe"],
  });
  let stderr = "";
  child.stderr?.on("data", (chunk: Buffer) => {
    stderr += chunk.toString();
  });
  const stop = async () => {
    child.kill();
    await rm(workDir, { recursive: true, force: true });
  };
  const control = child.stdio[3];
  assert(control instanceof Readable, "workerd's control fd is readable");
  const lines = createInterface({ input: control });
  const ports: Record<string, number> = {};
  const listening = new Promise<void>((resolve, reject) => {
    child.once("exit", (code) => reject(new WorkerdExited({ code, stderr })));
    lines.on("line", (line) => {
      const event = decodeListen(line);
      if (Option.isSome(event)) ports[event.value.socket] = event.value.port;
      if (R.size(ports) === R.size(workers)) resolve();
    });
  });
  await listening.catch(async (exited: WorkerdExited) => {
    await stop();
    throw exited;
  });
  return { ports, stderr: () => stderr, stop };
};

let runtime: Runtime | undefined;

beforeAll(async () => {
  runtime = await serve(SERVED);
}, 120_000);

afterAll(async () => {
  await runtime?.stop();
});

/** What `/verify` takes. */
const VerifyRequest = Schema.Struct({ password: Schema.String, hash: Schema.String });
const encodeVerifyRequest = Schema.encodeSync(Schema.fromJsonString(VerifyRequest));

/** Call the worker `name`, decoding its JSON answer; a `body` is POSTed to `/verify`. */
const callWorker = async <S extends Schema.ConstraintDecoder<unknown>>(
  schema: S,
  name: ServedName,
  path: string,
  body?: typeof VerifyRequest.Type,
): Promise<S["Type"]> => {
  const port = runtime?.ports[name];
  assert(port !== undefined, `workerd serves the ${name} worker`);
  const response = await fetch(
    `http://127.0.0.1:${port}${path}`,
    body === undefined ? {} : { method: "POST", body: encodeVerifyRequest(body) },
  );
  expect(response.status, runtime?.stderr()).toBe(200);
  return Schema.decodeSync(Schema.fromJsonString(schema))(await response.text());
};

const Attempt = Schema.Struct({ ok: Schema.Boolean, threw: Schema.optional(Schema.String) });
const Probe = Schema.Struct({ compile: Attempt, module: Attempt, instance: Attempt });

/** An effect's outcome, as the worker reports it. */
const Outcome = <A extends Schema.Top>(value: A) =>
  Schema.Union([
    Schema.Struct({ ok: Schema.Literal(true), value }),
    Schema.Struct({
      ok: Schema.Literal(false),
      tag: Schema.String,
      message: Schema.String,
      cause: Schema.String,
    }),
  ]);

const Verified = Outcome(Schema.Boolean);

const Roundtrip = Schema.Struct({
  hashed: Outcome(Schema.Struct({ hash: Schema.String, algorithm: Schema.String })),
  verified: Schema.optional(Verified),
  rejected: Schema.optional(Verified),
});

const DISALLOWED = "Wasm code generation disallowed by embedder";

describe.each(SERVED_NAMES)("workerd, the %s worker", (name) => {
  it("refuses to compile wasm inside a request, but instantiates a compiled module", async () => {
    const probe = await callWorker(Probe, name, "/probe");

    expect(probe.compile.threw).toContain(DISALLOWED);
    expect(probe.module.threw).toContain(DISALLOWED);
    expect(probe.instance).toEqual({ ok: true });
  });

  it("hashes and verifies inside fetch", async () => {
    const result = await callWorker(Roundtrip, name, "/roundtrip");

    expect(result.hashed).toMatchObject({ ok: true, value: { algorithm: "argon2id" } });
    assert(result.hashed.ok, "the hash succeeds");
    expect(result.hashed.value.hash).toMatch(
      /^\$argon2id\$v=19\$m=19456,t=2,p=1\$[^$]{22}\$[^$]{43}$/,
    );
    expect(result.verified).toEqual({ ok: true, value: true });
    expect(result.rejected).toEqual({ ok: true, value: false });
  });

  it.each(hashWasmFixtures)("verifies a hash-wasm hash inside fetch: $label", async (fixture) => {
    const { password, hash } = fixture;
    expect(await callWorker(Verified, name, "/verify", { password, hash })).toEqual({
      ok: true,
      value: true,
    });
    expect(await callWorker(Verified, name, "/verify", { password: "wrong", hash })).toEqual({
      ok: true,
      value: false,
    });
  });
});

describe("workerd before 2025-06-01 without allow_eval_during_startup", () => {
  it("refuses the worker at startup", async () => {
    await expect(
      serve({ legacy: { date: LEGACY_DATE, flags: ["nodejs_compat"] } }),
    ).rejects.toMatchObject({
      _tag: "WorkerdExited",
      stderr: expect.stringContaining(`WebAssembly.Module(): ${DISALLOWED}`),
    });
  }, 120_000);
});
