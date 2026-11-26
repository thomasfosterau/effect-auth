/**
 * The core's crypto inside a real workerd, the runtime the getting-started guide claims
 * for everything but `./saml`: JWS through `effect/jose`, JWT, passwords,
 * AES-GCM and the `node:crypto` corral. `nodejs_compat` sets no `Buffer`
 * global on a Worker dated before 2024-09-23, so the corral imports `Buffer`
 * from `node:buffer`. This suite bundles a worker around those callers,
 * serves it from the `workerd` binary at workerd's newest compatibility date
 * and at the core's supported minimum, and checks every primitive inside a
 * `fetch` handler. The tokens the worker signs are verified here with Node's
 * own `KeyObject` verifier, and the worker verifies tokens Node
 * signed, so the two runtimes agree byte for byte where the algorithm is
 * deterministic. The worker's global outbound is a network service that
 * allows nothing, so no step can reach the internet.
 */
import { spawn } from "node:child_process";
import * as crypto from "node:crypto";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { createRequire } from "node:module";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createInterface } from "node:readline";
import { Readable } from "node:stream";
import { fileURLToPath } from "node:url";
import { rolldown, type Plugin } from "vite/rolldown";
import { afterAll, assert, beforeAll, describe, expect, it } from "vite-plus/test";
import * as Effect from "effect/Effect";
import { Base64Url } from "effect/encoding";
import * as Option from "effect/Option";
import * as Result from "effect/Result";
import * as Schema from "effect/Schema";
import { aes256GcmCipher } from "./index.ts";
import * as PlatformCrypto from "./PlatformCrypto.ts";
import { sha256Hex } from "./testing/Sha256.ts";
import { pbkdf2Hasher } from "./password/index.ts";
import * as Rfc7515 from "./testing/Rfc7515.ts";

/** The `workerd` package's entry: the platform binary's path and its newest compatibility date. */
const Workerd = Schema.Struct({ default: Schema.String, compatibilityDate: Schema.String });
const workerd = Schema.decodeUnknownSync(Workerd)(createRequire(import.meta.url)("workerd"));

/**
 * The compatibility dates the worker runs at: workerd's newest, and the
 * oldest the core supports (`nodejs_compat` on, no Node globals), which the
 * getting-started guide states.
 */
const DATE_NAMES = ["current", "minimum"] as const;
type DateName = (typeof DATE_NAMES)[number];
const DATES: Readonly<Record<DateName, string>> = {
  current: workerd.compatibilityDate,
  minimum: "2023-01-01",
};

/** workerd stopped before every socket listened. */
class WorkerdExited extends Schema.TaggedError<WorkerdExited, { readonly brand: unique symbol }>()(
  "WorkerdExited",
  {
    code: Schema.NullOr(Schema.Finite),
    stderr: Schema.String,
  },
) {}

const srcDir = fileURLToPath(new URL(".", import.meta.url));
// A path beside the sources, so the entry's relative imports resolve here.
const ENTRY = join(srcDir, "__workerd_entry__.ts");

const WORKER_SOURCE = `
import * as crypto from "node:crypto";
import { Effect, Layer, Redacted } from "effect";
import { Base64Url } from "effect/encoding";
import * as Option from "effect/Option";
import {
  aes256GcmCipher,
  aes256GcmOpen,
  aes256GcmSeal,
  constantTimeHashEqual,
  hashToken,
  hmac,
  JwtKeyStore,
  JwtService,
  jwkToSpkiDer,
  RootSecret,
  sha256,
  verifySpkiSignature,
} from "./index.ts";
import { signWithPkcs8, verifiesWithJwk } from "./JwsSignature.ts";
import * as PlatformCrypto from "./PlatformCrypto.ts";
import { appleClientSecret } from "./oauth/index.ts";
import { pbkdf2Hasher } from "./password/index.ts";
import { scryptHasher } from "./password/Scrypt.ts";
import { memoryJwtKeyStore } from "./testing/index.ts";

const enc = (text) => new TextEncoder().encode(text);
const runCrypto = (effect) => Effect.runPromise(PlatformCrypto.provide(effect));
const b64 = (bytes) => Base64Url.encode(new Uint8Array(bytes));
const unb64 = (text) => {
  const decoded = Base64Url.decode(text);
  if (decoded._tag !== "Success") throw new Error("not base64url: " + text);
  return decoded.success;
};
const attempt = async (f) => {
  try {
    return { ok: true, value: await f() };
  } catch (error) {
    return { ok: false, error: String(error) };
  }
};
// Swap the first character of a token's last segment: unlike the last
// character, it carries six bits of the bytes and never padding.
const tamper = (token) => {
  const at = token.lastIndexOf(".") + 1;
  return token.slice(0, at) + (token[at] === "A" ? "B" : "A") + token.slice(at + 1);
};

// workerd from 2025-12-03 exports every absent JWK member as undefined.
const definedMembers = (jwk) => Object.fromEntries(Object.entries(jwk).filter(([, v]) => v !== undefined));

const keyPair = (algorithm) => {
  const { publicKey, privateKey } =
    algorithm === "ES256"
      ? crypto.generateKeyPairSync("ec", { namedCurve: "P-256" })
      : algorithm === "EdDSA"
        ? crypto.generateKeyPairSync("ed25519")
        : crypto.generateKeyPairSync("rsa", { modulusLength: 2048 });
  return {
    jwk: definedMembers(publicKey.export({ format: "jwk" })),
    privateKeyPem: privateKey.export({ type: "pkcs8", format: "pem" }),
  };
};

const signCompact = (algorithm, payload, privateKeyPem) =>
  runCrypto(signWithPkcs8(enc(payload), Redacted.make(privateKeyPem), algorithm, { typ: "JWT" }));
const verifiesCompact = (algorithm, token, jwk) =>
  Effect.runPromise(verifiesWithJwk(token, jwk, algorithm));

const jws = async (algorithm) => {
  const { jwk, privateKeyPem } = keyPair(algorithm);
  const token = await signCompact(algorithm, "payload-" + algorithm, privateKeyPem);
  return {
    jwk,
    privateKeyPem,
    token,
    verifies: await verifiesCompact(algorithm, token, jwk),
    rejectsTampered: !(await verifiesCompact(algorithm, tamper(token), jwk)),
  };
};

const jwtService = (algorithm) =>
  Effect.runPromise(
    Effect.gen(function* () {
      const jwt = yield* JwtService;
      const now = new Date();
      const { token } = yield* jwt.sign({ id: "u-1", createdAt: now, updatedAt: now, attributes: {} });
      const claims = yield* jwt.verify(token);
      const tampered = yield* Effect.result(jwt.verify(tamper(token)));
      return { token, sub: claims.sub, rejectsTampered: tampered._tag === "Failure", jwks: yield* jwt.getJwks };
    }).pipe(
      Effect.provide(
        JwtService.layer({ issuer: "https://app.example.com", algorithm }).pipe(
          Layer.provide(
            Layer.merge(
              Layer.succeed(JwtKeyStore, memoryJwtKeyStore()),
              Layer.orDie(RootSecret.RootSecret.layer("0123456789abcdef".repeat(4))),
            ),
          ),
        ),
      ),
    ),
  );

const apple = async () => {
  const { jwk, privateKeyPem } = keyPair("ES256");
  const token = await Effect.runPromise(
    appleClientSecret({
      teamId: "TEAM",
      clientId: "com.example.app",
      keyId: "KEY",
      privateKey: Redacted.make(privateKeyPem),
      now: 1_700_000_000_000,
    }),
  );
  return { token, jwk, verifies: await verifiesCompact("ES256", token, jwk) };
};

const password = (hasher) =>
  Effect.runPromise(
    Effect.gen(function* () {
      const { hash } = yield* hasher.hash("correct horse battery staple");
      return {
        hash,
        verifies: yield* hasher.verify("correct horse battery staple", hash),
        rejectsWrong: !(yield* hasher.verify("wrong password", hash)),
      };
    }),
  );

const aes = () =>
  runCrypto(
    Effect.gen(function* () {
      const cipher = yield* aes256GcmCipher("workerd-secret");
      const sealed = yield* cipher.encrypt("refresh-token-123");
      const opened = yield* cipher.decrypt(sealed);
      const tampered = yield* Effect.result(cipher.decrypt(tamper(sealed)));
      const key = yield* sha256("cookie-key");
      const cookie = yield* aes256GcmSeal(key, "cached-session");
      return {
        sealed,
        opened,
        rejectsTampered: tampered._tag === "Failure",
        cookieOpened: Option.getOrNull(yield* aes256GcmOpen(key, cookie)),
        cookieRejectsWrongKey: Option.isNone(yield* aes256GcmOpen(yield* sha256("other"), cookie)),
      };
    }),
  );

const der = async () => {
  const { publicKey, privateKey } = crypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
  const spki = await runCrypto(jwkToSpkiDer("ES256", publicKey.export({ format: "jwk" })));
  const message = enc("authenticator-data");
  const signature = new Uint8Array(crypto.sign("sha256", message, privateKey));
  const ed = crypto.generateKeyPairSync("ed25519");
  const edSpki = await runCrypto(jwkToSpkiDer("EdDSA", ed.publicKey.export({ format: "jwk" })));
  const edSignature = new Uint8Array(crypto.sign(null, message, ed.privateKey));
  return {
    es256: await runCrypto(verifySpkiSignature("ES256", spki, message, signature)),
    eddsa: await runCrypto(verifySpkiSignature("EdDSA", edSpki, message, edSignature)),
  };
};

// ES256 signatures a JOSE verifier must refuse: DER (crypto.sign's default
// encoding), and r || s one byte short or long.
const es256Malformed = async () => {
  const { jwk, privateKeyPem } = keyPair("ES256");
  const token = await signCompact("ES256", "payload-malformed", privateKeyPem);
  const input = token.slice(0, token.lastIndexOf("."));
  const signature = unb64(token.slice(token.lastIndexOf(".") + 1));
  const withSignature = (bytes) => verifiesCompact("ES256", input + "." + b64(bytes), jwk);
  return {
    der: await withSignature(crypto.sign("sha256", enc(input), privateKeyPem)),
    short: await withSignature(signature.subarray(0, 63)),
    long: await withSignature(new Uint8Array([...signature, 0])),
  };
};

// A compact JWS Node sends, verified against its public JWK: RFC 7515
// Appendix A.3, a signature neither runtime produced.
const verifyCompact = ({ jws, jwk }) => verifiesCompact("ES256", jws, jwk);

// globalOutbound is a network service that allows nothing, so even the
// worker's own listener, which answers /ping, is out of reach.
const offline = async (probe) => {
  const response = await fetch(probe + "/ping");
  return response.status;
};

const run = async (probe) => ({
  bufferGlobal: typeof globalThis.Buffer,
  es256: await attempt(() => jws("ES256")),
  eddsa: await attempt(() => jws("EdDSA")),
  rs256: await attempt(() => jws("RS256")),
  jwtES256: await attempt(() => jwtService("ES256")),
  jwtEdDSA: await attempt(() => jwtService("EdDSA")),
  apple: await attempt(apple),
  pbkdf2: await attempt(() => password(pbkdf2Hasher())),
  scrypt: await attempt(() => password(scryptHasher({ cost: 16384 }))),
  tokenHash: await attempt(async () => {
    const [raw, a, b] = await runCrypto(Effect.forEach(["raw-token", "a", "b"], hashToken));
    return { digest: raw, equal: constantTimeHashEqual(a, a), unequal: !constantTimeHashEqual(a, b) };
  }),
  hmac: await attempt(async () => ({
    sha1: b64(await runCrypto(hmac("sha1", "key", "data"))),
    sha256: b64(await runCrypto(sha256("data"))),
  })),
  aes: await attempt(aes),
  der: await attempt(der),
  es256Malformed: await attempt(es256Malformed),
  offline: await attempt(() => offline(probe)),
});

/** Verify what Node made: JWS signatures, an AES-GCM ciphertext and a PBKDF2 hash. */
const check = async (input) => ({
  jws: await Promise.all(input.jws.map(({ algorithm, jwk, token }) => verifiesCompact(algorithm, token, jwk))),
  eddsaToken: await signCompact("EdDSA", "node.signed-EdDSA", input.eddsa.privateKeyPem),
  decrypted: await runCrypto(Effect.flatMap(aes256GcmCipher(input.aes.secret), (cipher) => cipher.decrypt(input.aes.sealed))),
  pbkdf2: await Effect.runPromise(pbkdf2Hasher().verify(input.pbkdf2.password, input.pbkdf2.hash)),
});

export default {
  async fetch(request) {
    const url = new URL(request.url);
    if (url.pathname === "/ping") return new Response("pong");
    if (url.pathname === "/verify") return Response.json(await verifyCompact(await request.json()));
    if (url.pathname === "/pbkdf2") return Response.json(await password(pbkdf2Hasher()));
    const body =
      url.pathname === "/check"
        ? await check(await request.json())
        : await run(url.searchParams.get("probe"));
    return Response.json(body);
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
  `(name = "${name}", worker = (modules = [(name = "worker.js", esModule = embed "worker.js")], compatibilityDate = "${DATES[name]}", compatibilityFlags = ["nodejs_compat"], globalOutbound = "offline"))`;

const CONFIG = `using Workerd = import "/workerd/workerd.capnp";
const config :Workerd.Config = (
  services = [
    ${DATE_NAMES.map(workerService).join(",\n    ")},
    (name = "offline", network = (allow = [])),
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

const ports: Partial<Record<DateName, number>> = {};
let stopRuntime = (): void => {};
let workDir = "";
let stderr = "";

beforeAll(async () => {
  workDir = await mkdtemp(join(tmpdir(), "effect-auth-core-workerd-"));
  await writeFile(join(workDir, "worker.js"), await bundleWorker());
  await writeFile(join(workDir, "config.capnp"), CONFIG);

  const child = spawn(workerd.default, ["serve", "config.capnp", "--control-fd=3"], {
    cwd: workDir,
    stdio: ["ignore", "ignore", "pipe", "pipe"],
  });
  stopRuntime = () => void child.kill();
  child.stderr?.on("data", (chunk: Uint8Array) => {
    stderr += new TextDecoder().decode(chunk);
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
  if (workDir !== "") await rm(workDir, { recursive: true, force: true });
});

/** Ask the worker at `date` for `path` (a POST of the JSON `body` when given), decoding its JSON. */
const callWorker = async <S extends Schema.ConstraintDecoder<unknown>>(
  schema: S,
  date: DateName,
  path: string,
  body?: string,
): Promise<S["Type"]> => {
  const port = ports[date];
  assert(port !== undefined, `workerd serves the ${date} worker`);
  const response = await fetch(
    `http://127.0.0.1:${port}${path}`,
    body === undefined ? {} : { method: "POST", body },
  );
  const text = await response.text();
  expect(response.status, `${text}\n${stderr}`).toBe(200);
  return Schema.decodeSync(Schema.fromJsonString(schema))(text);
};

/** A worker step's outcome: its value, or the error it threw (shown when the test fails). */
const Attempt = <A extends Schema.Top>(value: A) =>
  Schema.Union([
    Schema.Struct({ ok: Schema.Literal(true), value }),
    Schema.Struct({ ok: Schema.Literal(false), error: Schema.String }),
  ]);

const Jwk = Schema.Record(Schema.String, Schema.Json);

const SignedJws = Schema.Struct({
  jwk: Jwk,
  privateKeyPem: Schema.String,
  token: Schema.String,
  verifies: Schema.Boolean,
  rejectsTampered: Schema.Boolean,
});

const JwtRun = Schema.Struct({
  token: Schema.String,
  sub: Schema.String,
  rejectsTampered: Schema.Boolean,
  jwks: Schema.Struct({ keys: Schema.Array(Jwk) }),
});

const PasswordRun = Schema.Struct({
  hash: Schema.String,
  verifies: Schema.Boolean,
  rejectsWrong: Schema.Boolean,
});

const Run = Schema.Struct({
  bufferGlobal: Schema.String,
  es256: Attempt(SignedJws),
  eddsa: Attempt(SignedJws),
  rs256: Attempt(SignedJws),
  jwtES256: Attempt(JwtRun),
  jwtEdDSA: Attempt(JwtRun),
  apple: Attempt(Schema.Struct({ token: Schema.String, jwk: Jwk, verifies: Schema.Boolean })),
  pbkdf2: Attempt(PasswordRun),
  scrypt: Attempt(PasswordRun),
  tokenHash: Attempt(
    Schema.Struct({ digest: Schema.String, equal: Schema.Boolean, unequal: Schema.Boolean }),
  ),
  hmac: Attempt(Schema.Struct({ sha1: Schema.String, sha256: Schema.String })),
  aes: Attempt(
    Schema.Struct({
      sealed: Schema.String,
      opened: Schema.String,
      rejectsTampered: Schema.Boolean,
      cookieOpened: Schema.NullOr(Schema.String),
      cookieRejectsWrongKey: Schema.Boolean,
    }),
  ),
  der: Attempt(Schema.Struct({ es256: Schema.Boolean, eddsa: Schema.Boolean })),
  es256Malformed: Attempt(
    Schema.Struct({ der: Schema.Boolean, short: Schema.Boolean, long: Schema.Boolean }),
  ),
  offline: Attempt(Schema.Finite),
});

/** A JWS Node signed, as the worker's `/check` reads it. */
const NodeSigned = Schema.Struct({
  algorithm: Schema.Literals(["ES256", "EdDSA", "RS256"]),
  jwk: Jwk,
  privateKeyPem: Schema.String,
  token: Schema.String,
});

const encodeCheckInput = Schema.encodeSync(
  Schema.fromJsonString(
    Schema.Struct({
      jws: Schema.Array(NodeSigned),
      eddsa: NodeSigned,
      aes: Schema.Struct({ secret: Schema.String, sealed: Schema.String }),
      pbkdf2: Schema.Struct({ password: Schema.String, hash: Schema.String }),
    }),
  ),
);

const decodeJwk = Schema.decodeUnknownSync(Jwk);

const encodeCompactJws = Schema.encodeSync(
  Schema.fromJsonString(Schema.Struct({ jws: Schema.String, jwk: Jwk })),
);

const Check = Schema.Struct({
  jws: Schema.Array(Schema.Boolean),
  eddsaToken: Schema.String,
  decrypted: Schema.String,
  pbkdf2: Schema.Boolean,
});

/** The value of a worker step, failing with the error it threw. */
const valueOf = <A>(
  step: { readonly ok: true; readonly value: A } | { readonly ok: false; readonly error: string },
): A => {
  assert(step.ok, step.ok ? "" : `the worker step threw: ${step.error}`);
  return step.value;
};

/** The bytes of a base64url string; anything else decodes to none, which verifies nothing. */
const bytes = (text: string): Uint8Array =>
  Result.getOrElse(Base64Url.decode(text), () => new Uint8Array(0));

type JwsAlgorithm = "ES256" | "EdDSA" | "RS256";

/** Node's own verifier, over a `KeyObject`: the signing input and signature of a compact JWS. */
const keyObjectVerifies = (
  algorithm: JwsAlgorithm,
  token: string,
  jwk: crypto.JsonWebKeyInput["key"],
): boolean => {
  const at = token.lastIndexOf(".");
  const data = new TextEncoder().encode(token.slice(0, at));
  const signature = bytes(token.slice(at + 1));
  const key = crypto.createPublicKey({ key: jwk, format: "jwk" });
  if (algorithm === "ES256")
    return crypto.verify("sha256", data, { key, dsaEncoding: "ieee-p1363" }, signature);
  return crypto.verify(algorithm === "RS256" ? "sha256" : null, data, key, signature);
};

/** The signature segment Node's Ed25519 signer gives `token`'s signing input. */
const nodeEd25519Signature = (token: string, privateKeyPem: string): string =>
  Base64Url.encode(
    new Uint8Array(
      crypto.sign(
        null,
        new TextEncoder().encode(token.slice(0, token.lastIndexOf("."))),
        privateKeyPem,
      ),
    ),
  );

/** A compact JWS signed in Node with a `KeyObject`. */
const nodeSigned = (algorithm: JwsAlgorithm) => {
  const { publicKey, privateKey } =
    algorithm === "ES256"
      ? crypto.generateKeyPairSync("ec", { namedCurve: "P-256" })
      : algorithm === "EdDSA"
        ? crypto.generateKeyPairSync("ed25519")
        : crypto.generateKeyPairSync("rsa", { modulusLength: 2048 });
  const encode = (text: string) => Base64Url.encode(new TextEncoder().encode(text));
  const input = `${encode(`{"alg":"${algorithm}"}`)}.${encode(`node.signed-${algorithm}`)}`;
  const data = new TextEncoder().encode(input);
  const signature =
    algorithm === "ES256"
      ? crypto.sign("sha256", data, { key: privateKey, dsaEncoding: "ieee-p1363" })
      : crypto.sign(algorithm === "RS256" ? "sha256" : null, data, privateKey);
  return {
    algorithm,
    jwk: decodeJwk(publicKey.export({ format: "jwk" })),
    privateKeyPem: privateKey.export({ type: "pkcs8", format: "pem" }),
    token: `${input}.${Base64Url.encode(new Uint8Array(signature))}`,
  };
};

describe.each(DATE_NAMES)("workerd at its %s compatibility date", (date) => {
  let run: typeof Run.Type;
  beforeAll(async () => {
    // The worker probes its own listener, which answers whenever it is reachable.
    run = await callWorker(Run, date, `/run?probe=http://127.0.0.1:${ports[date]}`);
  }, 60_000);

  it("runs with or without the Buffer global", () => {
    // The minimum date predates the globals nodejs_compat sets from 2024-09-23.
    expect(run.bufferGlobal).toBe(date === "minimum" ? "undefined" : "function");
  });

  it.each(["es256", "eddsa", "rs256"] as const)(
    "signs and verifies %s inside the worker, and Node's KeyObject verifier agrees",
    (alg) => {
      const signed = valueOf(run[alg]);
      const algorithm: JwsAlgorithm =
        alg === "es256" ? "ES256" : alg === "eddsa" ? "EdDSA" : "RS256";
      expect(signed.verifies).toBe(true);
      expect(signed.rejectsTampered).toBe(true);
      expect(keyObjectVerifies(algorithm, signed.token, signed.jwk)).toBe(true);
    },
  );

  it("emits ES256 signatures in raw JOSE r || s form", () => {
    const { token } = valueOf(run.es256);
    expect(bytes(token.slice(token.lastIndexOf(".") + 1))).toHaveLength(64);
  });

  it("signs the Ed25519 bytes Node signs from the same key", () => {
    // Ed25519 is deterministic, so the two runtimes must agree byte for byte.
    const signed = valueOf(run.eddsa);
    expect(nodeEd25519Signature(signed.token, signed.privateKeyPem)).toBe(
      signed.token.slice(signed.token.lastIndexOf(".") + 1),
    );
  });

  it.each(["jwtES256", "jwtEdDSA"] as const)(
    "JwtService signs and verifies a token (%s), which Node verifies against its JWKS",
    (name) => {
      const jwt = valueOf(run[name]);
      expect(jwt.sub).toBe("u-1");
      expect(jwt.rejectsTampered).toBe(true);
      const [jwk] = jwt.jwks.keys;
      assert(jwk !== undefined, "the JWKS has the signing key");
      const algorithm = name === "jwtES256" ? "ES256" : "EdDSA";
      expect(keyObjectVerifies(algorithm, jwt.token, jwk)).toBe(true);
    },
  );

  it("builds an Apple client secret that verifies in both runtimes", () => {
    const apple = valueOf(run.apple);
    expect(apple.verifies).toBe(true);
    expect(keyObjectVerifies("ES256", apple.token, apple.jwk)).toBe(true);
  });

  it.each(["pbkdf2", "scrypt"] as const)("hashes and verifies a password with %s", (name) => {
    const result = valueOf(run[name]);
    expect(result.verifies).toBe(true);
    expect(result.rejectsWrong).toBe(true);
  });

  it("hashes tokens, HMACs and digests as Node does", () => {
    const tokenHash = valueOf(run.tokenHash);
    expect(tokenHash).toEqual({ digest: sha256Hex("raw-token"), equal: true, unequal: true });
    expect(valueOf(run.hmac)).toEqual({
      sha1: Base64Url.encode(
        new Uint8Array(crypto.createHmac("sha1", "key").update("data").digest()),
      ),
      sha256: Base64Url.encode(new Uint8Array(crypto.createHash("sha256").update("data").digest())),
    });
  });

  it("seals and opens AES-256-GCM, and Node opens what the worker sealed", async () => {
    const aes = valueOf(run.aes);
    expect(aes).toMatchObject({
      opened: "refresh-token-123",
      rejectsTampered: true,
      cookieOpened: "cached-session",
      cookieRejectsWrongKey: true,
    });
    const opened = await Effect.runPromise(
      PlatformCrypto.provide(
        Effect.flatMap(aes256GcmCipher("workerd-secret"), (cipher) => cipher.decrypt(aes.sealed)),
      ),
    );
    expect(opened).toBe("refresh-token-123");
  });

  it("verifies a DER, a 63-byte and a 65-byte ES256 signature to false", () => {
    expect(valueOf(run.es256Malformed)).toEqual({ der: false, short: false, long: false });
  });

  it("verifies RFC 7515 Appendix A.3's ES256 JWS with its published public JWK", async () => {
    const body = encodeCompactJws({ jws: Rfc7515.compactJws, jwk: Rfc7515.publicJwk });
    expect(await callWorker(Schema.Boolean, date, "/verify", body)).toBe(true);
  });

  it("reaches no network, not even its own listener: the global outbound allows nothing", () => {
    expect(run.offline.ok).toBe(false);
  });

  it("verifies WebAuthn DER signatures", () => {
    expect(valueOf(run.der)).toEqual({ es256: true, eddsa: true });
  });

  it("hashes with PBKDF2 at its default 600,000 iterations within a Worker's CPU budget", async () => {
    // One hash and two verifies, about 75 ms each in local workerd: inside
    // Workers' limits, but a large share of a request's CPU. The bound leaves
    // room for a slow CI runner; the first call warms the isolate.
    const timed = async () => {
      const started = performance.now();
      const result = await callWorker(PasswordRun, date, "/pbkdf2");
      return { result, elapsed: performance.now() - started };
    };
    await timed();
    const { result, elapsed } = await timed();
    expect(result).toMatchObject({ verifies: true, rejectsWrong: true });
    expect(result.hash.split("$").slice(0, 2)).toEqual(["pbkdf2-sha256", "600000"]);
    expect(
      await Effect.runPromise(pbkdf2Hasher().verify("correct horse battery staple", result.hash)),
    ).toBe(true);
    expect(elapsed).toBeLessThan(2_000);
  });

  it("verifies what Node signed, sealed and hashed", async () => {
    const jws = (["ES256", "EdDSA", "RS256"] as const).map(nodeSigned);
    const eddsa = nodeSigned("EdDSA");
    const sealed = await Effect.runPromise(
      PlatformCrypto.provide(
        Effect.flatMap(aes256GcmCipher("node-secret"), (cipher) => cipher.encrypt("from-node")),
      ),
    );
    const { hash } = await Effect.runPromise(pbkdf2Hasher().hash("node password"));
    const body = encodeCheckInput({
      jws,
      eddsa,
      aes: { secret: "node-secret", sealed },
      pbkdf2: { password: "node password", hash },
    });
    const checked = await callWorker(Check, date, "/check", body);
    expect(checked).toMatchObject({
      jws: [true, true, true],
      decrypted: "from-node",
      pbkdf2: true,
    });
    // Ed25519 is deterministic: Node signs the worker's signing input to the same bytes.
    expect(keyObjectVerifies("EdDSA", checked.eddsaToken, eddsa.jwk)).toBe(true);
    expect(nodeEd25519Signature(checked.eddsaToken, eddsa.privateKeyPem)).toBe(
      checked.eddsaToken.slice(checked.eddsaToken.lastIndexOf(".") + 1),
    );
  });
});
