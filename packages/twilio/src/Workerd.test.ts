/**
 * The sender inside a real workerd (#606), the runtime the package claims.
 *
 * workerd's `fetch` rejects `redirect: "error"` outright (a `TypeError` on
 * every request, a 200 included), so the sender sends `redirect: "manual"`
 * and fails any 3xx itself. This suite bundles a worker around the sender,
 * serves it from the `workerd` binary at two compatibility dates, and points
 * it at a local origin that counts the requests it receives.
 */
import { spawn } from "node:child_process";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { createServer, type Server } from "node:http";
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
import * as P from "effect/Predicate";
import * as Schema from "effect/Schema";

/** The `workerd` package's entry: the platform binary's path and its newest compatibility date. */
const Workerd = Schema.Struct({ default: Schema.String, compatibilityDate: Schema.String });
const workerd = Schema.decodeUnknownSync(Workerd)(createRequire(import.meta.url)("workerd"));

/** The compatibility dates the worker runs at: workerd's newest, and one from before 2024. */
const DATE_NAMES = ["current", "legacy"] as const;
type DateName = (typeof DATE_NAMES)[number];
const DATES: Readonly<Record<DateName, string>> = {
  current: workerd.compatibilityDate,
  legacy: "2023-01-01",
};

/** workerd stopped before every socket listened. */
class WorkerdExited extends Data.TaggedError("WorkerdExited")<{
  readonly code: number | null;
  readonly stderr: string;
}> {}

const ACCOUNT_SID = "ACworkerd000000000000000000000000";
/** The path the sender posts to under its `baseUrl`. */
const MESSAGES_PATH = `/2010-04-01/Accounts/${ACCOUNT_SID}/Messages.json`;

const srcDir = fileURLToPath(new URL(".", import.meta.url));
// A path beside the sources, so the entry's bare imports resolve from this package.
const ENTRY = join(srcDir, "__workerd_entry__.ts");

const WORKER_SOURCE = `
import { Effect, Redacted } from "effect";
import { twilioSmsSender } from "./index.ts";

const probe = async (url, redirect) => {
  try {
    const response = await fetch(url, { method: "POST", body: "{}", redirect });
    return { status: response.status, type: response.type, redirected: response.redirected };
  } catch (error) {
    return { threw: String(error) };
  }
};

export default {
  async fetch(request) {
    const url = new URL(request.url);
    const origin = url.searchParams.get("origin");
    if (url.pathname === "/probe") {
      return Response.json({
        error: await probe(origin + "/s200/x", "error"),
        manual: await probe(origin + "/s302/x", "manual"),
        follow: await probe(origin + "/s302/x", "follow"),
      });
    }
    const sender = twilioSmsSender({
      accountSid: "${ACCOUNT_SID}",
      authToken: Redacted.make("workerd-auth-token"),
      from: "+15551234567",
      baseUrl: origin,
    });
    const result = await Effect.runPromise(
      Effect.match(sender.send({ to: "+15559876543", purpose: "second-factor-otp", params: { otp: "1" } }), {
        onSuccess: () => ({ ok: true }),
        onFailure: (error) => ({ ok: false, tag: error._tag, message: error.message, cause: error.cause }),
      }),
    );
    return Response.json(result);
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

const workerService = (name: DateName): string =>
  `(name = "${name}", worker = (modules = [(name = "worker.js", esModule = embed "worker.js")], compatibilityDate = "${DATES[name]}", compatibilityFlags = ["nodejs_compat"], globalOutbound = "net"))`;

const CONFIG = `using Workerd = import "/workerd/workerd.capnp";
const config :Workerd.Config = (
  services = [
    ${DATE_NAMES.map(workerService).join(",\n    ")},
    (name = "net", network = (allow = ["public", "private", "local"])),
  ],
  sockets = [
    ${DATE_NAMES.map((name) => `(name = "${name}", address = "127.0.0.1:0", http = (), service = "${name}")`).join(",\n    ")},
  ],
);
`;

/** One line workerd writes to its control fd once a socket listens. */
const ListenEvent = Schema.fromJsonString(
  Schema.Struct({
    event: Schema.Literal("listen"),
    socket: Schema.Literals(DATE_NAMES),
    port: Schema.Finite,
  }),
);
const decodeListen = Schema.decodeUnknownOption(ListenEvent);

/**
 * The origin: `/<test>/s<status>/…` answers that status, a 3xx pointing at
 * `/<test>/landed`, which answers 200. It records every path it receives.
 */
const paths: string[] = [];
const origin: Server = createServer((request, response) => {
  const path = request.url ?? "/";
  paths.push(path);
  const [, test, step] = path.split("/");
  const status = Number(step?.slice(1));
  if (step === "landed" || !(status >= 300 && status <= 399)) {
    response.writeHead(step === "landed" ? 200 : status).end("{}");
  } else {
    response.writeHead(status, { Location: `/${test}/landed` }).end();
  }
});

let originUrl = "";
const ports: Partial<Record<DateName, number>> = {};
let stopRuntime = (): void => {};
let workDir = "";
let stderr = "";

beforeAll(async () => {
  await new Promise<void>((resolve) => origin.listen(0, "127.0.0.1", () => resolve()));
  const address = origin.address();
  assert(P.isNotNull(address) && !P.isString(address), "the origin listens on a port");
  originUrl = `http://127.0.0.1:${address.port}`;

  workDir = await mkdtemp(join(tmpdir(), "effect-auth-twilio-workerd-"));
  await writeFile(join(workDir, "worker.js"), await bundleWorker());
  await writeFile(join(workDir, "config.capnp"), CONFIG);

  const child = spawn(workerd.default, ["serve", "config.capnp", "--control-fd=3"], {
    cwd: workDir,
    stdio: ["ignore", "ignore", "pipe", "pipe"],
  });
  stopRuntime = () => void child.kill();
  child.stderr?.on("data", (chunk: Buffer) => {
    stderr += chunk.toString();
  });
  const control = child.stdio[3];
  assert(control instanceof Readable, "workerd's control fd is readable");
  const lines = createInterface({ input: control });
  let listening = 0;
  await new Promise<void>((resolve, reject) => {
    child.once("exit", (code) => reject(new WorkerdExited({ code, stderr })));
    lines.on("line", (line) => {
      const event = decodeListen(line);
      if (Option.isSome(event)) {
        ports[event.value.socket] = event.value.port;
        listening += 1;
      }
      if (listening === DATE_NAMES.length) resolve();
    });
  });
}, 120_000);

afterAll(async () => {
  stopRuntime();
  await new Promise<void>((resolve) => origin.close(() => resolve()));
  if (workDir !== "") await rm(workDir, { recursive: true, force: true });
});

/** Ask the worker at `date` to run `path` against the origin's `originPath`, decoding its JSON. */
const callWorker = async <S extends Schema.ConstraintDecoder<unknown>>(
  schema: S,
  date: DateName,
  path: string,
  originPath: string,
): Promise<S["Type"]> => {
  const port = ports[date];
  assert(port !== undefined, `workerd serves the ${date} worker`);
  const target = encodeURIComponent(`${originUrl}${originPath}`);
  const response = await fetch(`http://127.0.0.1:${port}${path}?origin=${target}`);
  expect(response.status, stderr).toBe(200);
  return Schema.decodeSync(Schema.fromJsonString(schema))(await response.text());
};

/** The paths the origin received for one test's prefix. */
const pathsFor = (test: string): string[] => paths.filter((path) => path.startsWith(`/${test}/`));

const Probe = Schema.Struct({
  error: Schema.Struct({ threw: Schema.String }),
  manual: Schema.Struct({ status: Schema.Finite, type: Schema.String, redirected: Schema.Boolean }),
  follow: Schema.Struct({ status: Schema.Finite, redirected: Schema.Boolean }),
});

const SendResult = Schema.Union([
  Schema.Struct({ ok: Schema.Literal(true) }),
  Schema.Struct({
    ok: Schema.Literal(false),
    tag: Schema.String,
    message: Schema.String,
    cause: Schema.Unknown,
  }),
]);

describe.each(DATE_NAMES)("workerd at its %s compatibility date", (date) => {
  it("rejects redirect: 'error' on every fetch, returns the real 3xx under 'manual', and follows under 'follow'", async () => {
    const probe = await callWorker(Probe, date, "/probe", `/probe-${date}`);

    expect(probe.error.threw).toContain(
      'Invalid redirect value, must be one of "follow" or "manual"',
    );
    expect(probe.manual).toEqual({ status: 302, type: "default", redirected: false });
    expect(probe.follow).toEqual({ status: 200, redirected: true });
  });

  it("sends on a 200 with one request", async () => {
    const test = `ok-${date}`;
    const result = await callWorker(SendResult, date, "/send", `/${test}/s200`);

    expect(result).toEqual({ ok: true });
    expect(pathsFor(test)).toEqual([`/${test}/s200${MESSAGES_PATH}`]);
  });

  it.each([301, 302, 307, 308])(
    "fails a %i as an AuthError after exactly one request",
    async (status) => {
      const test = `redirect-${status}-${date}`;
      const result = await callWorker(SendResult, date, "/send", `/${test}/s${status}`);

      assert(!result.ok, "the send fails");
      expect(result.tag).toBe("AuthError");
      expect(result.cause).toEqual({ status });
      expect(result.message).not.toContain("landed");
      expect(pathsFor(test)).toEqual([`/${test}/s${status}${MESSAGES_PATH}`]);
    },
  );
});
