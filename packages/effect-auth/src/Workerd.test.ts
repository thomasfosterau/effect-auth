/**
 * The core's `node:crypto` corral inside a real workerd (#748), the runtime
 * the README claims for everything but `./saml`.
 *
 * workerd's `node:crypto` rejects `{ key: KeyObject, dsaEncoding }` with
 * `ERR_INVALID_ARG_TYPE`, so ES256 JWS hands `crypto.sign` / `crypto.verify`
 * the PEM or the JWK itself; and `nodejs_compat` sets no `Buffer` global on
 * a Worker dated before 2024-09-23, so the corral imports `Buffer` from
 * `node:buffer`. This suite bundles a worker around the corral's callers,
 * serves it from the `workerd` binary at workerd's newest compatibility date
 * and at the core's supported minimum, and checks every primitive inside a
 * `fetch` handler. The tokens the worker signs are verified here in Node
 * with the pre-#748 `KeyObject` form, and the worker verifies tokens Node
 * signed, so the two runtimes agree byte for byte where the algorithm is
 * deterministic.
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
import { Data, Effect } from "effect";
import { Base64Url } from "effect/encoding";
import * as Option from "effect/Option";
import * as Result from "effect/Result";
import * as Schema from "effect/Schema";
import { aes256GcmCipher, hashToken, type JwsAlgorithm } from "./index.ts";
import { pbkdf2Hasher } from "./password/index.ts";

/** The `workerd` package's entry: the platform binary's path and its newest compatibility date. */
const Workerd = Schema.Struct({ default: Schema.String, compatibilityDate: Schema.String });
const workerd = Schema.decodeUnknownSync(Workerd)(createRequire(import.meta.url)("workerd"));

/**
 * The compatibility dates the worker runs at: workerd's newest, and the
 * oldest the core supports (`nodejs_compat` on, no Node globals), which the
 * core README states.
 */
const DATE_NAMES = ["current", "minimum"] as const;
type DateName = (typeof DATE_NAMES)[number];
const DATES: Readonly<Record<DateName, string>> = {
  current: workerd.compatibilityDate,
  minimum: "2023-01-01",
};

/** workerd stopped before every socket listened. */
class WorkerdExited extends Data.TaggedError("WorkerdExited")<{
  readonly code: number | null;
  readonly stderr: string;
}> {}

const srcDir = fileURLToPath(new URL(".", import.meta.url));
// A path beside the sources, so the entry's relative imports resolve here.
const ENTRY = join(srcDir, "__workerd_entry__.ts");

const WORKER_SOURCE = `
import * as crypto from "node:crypto";
import { Effect, Layer, Redacted } from "effect";
import { Base64Url } from "effect/encoding";
import {
  aes256GcmCipher,
  aes256GcmOpen,
  aes256GcmSeal,
  constantTimeHashEqual,
  generateJwsKeyPair,
  hashToken,
  hmac,
  JwtKeyStore,
  JwtService,
  jwkToSpkiDer,
  sha256,
  signJws,
  verifyDerSignature,
  verifyJws,
} from "./index.ts";
import { appleClientSecret } from "./oauth/index.ts";
import { pbkdf2Hasher, scryptHasher } from "./password/index.ts";
import { memoryJwtKeyStore } from "./testing/index.ts";

const enc = (text) => new TextEncoder().encode(text);
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
const flip = (bytes) => {
  const copy = new Uint8Array(bytes);
  copy[copy.length - 1] ^= 1;
  return copy;
};

const jws = (algorithm) => {
  const { publicKeyJwk, privateKeyPem } = generateJwsKeyPair(algorithm);
  const data = enc("header.payload-" + algorithm);
  const signature = signJws(algorithm, data, privateKeyPem);
  return {
    jwk: publicKeyJwk,
    privateKeyPem,
    data: b64(data),
    signature: b64(signature),
    verifies: verifyJws(algorithm, data, signature, publicKeyJwk),
    rejectsTampered: !verifyJws(algorithm, data, flip(signature), publicKeyJwk),
  };
};

const rs256 = () => {
  const { publicKey, privateKey } = crypto.generateKeyPairSync("rsa", { modulusLength: 2048 });
  const jwk = publicKey.export({ format: "jwk" });
  const data = enc("header.payload-RS256");
  const signature = crypto.sign("sha256", data, privateKey);
  return {
    jwk,
    privateKeyPem: privateKey.export({ type: "pkcs8", format: "pem" }),
    data: b64(data),
    signature: b64(signature),
    verifies: verifyJws("RS256", data, signature, jwk),
    rejectsTampered: !verifyJws("RS256", data, flip(signature), jwk),
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
      return { token, sub: claims.sub, rejectsTampered: tampered._tag === "Failure", jwks: yield* jwt.getJwks() };
    }).pipe(
      Effect.provide(
        JwtService.layer({ issuer: "https://app.example.com", algorithm }).pipe(
          Layer.provide(Layer.succeed(JwtKeyStore, memoryJwtKeyStore())),
        ),
      ),
    ),
  );

const apple = async () => {
  const { publicKeyJwk, privateKeyPem } = generateJwsKeyPair("ES256");
  const token = await Effect.runPromise(
    appleClientSecret({
      teamId: "TEAM",
      clientId: "com.example.app",
      keyId: "KEY",
      privateKey: Redacted.make(privateKeyPem),
      now: 1_700_000_000_000,
    }),
  );
  const [header, payload, signature] = token.split(".");
  return {
    token,
    jwk: publicKeyJwk,
    verifies: verifyJws("ES256", enc(header + "." + payload), unb64(signature), publicKeyJwk),
  };
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
  Effect.runPromise(
    Effect.gen(function* () {
      const cipher = aes256GcmCipher("workerd-secret");
      const sealed = yield* cipher.encrypt("refresh-token-123");
      const opened = yield* cipher.decrypt(sealed);
      const tampered = yield* Effect.result(cipher.decrypt(tamper(sealed)));
      const key = sha256("cookie-key");
      const cookie = aes256GcmSeal(key, "cached-session");
      return {
        sealed,
        opened,
        rejectsTampered: tampered._tag === "Failure",
        cookieOpened: aes256GcmOpen(key, cookie),
        cookieRejectsWrongKey: aes256GcmOpen(sha256("other"), cookie) === null,
      };
    }),
  );

const der = () => {
  const { publicKey, privateKey } = crypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
  const spki = jwkToSpkiDer(publicKey.export({ format: "jwk" }));
  const message = enc("authenticator-data");
  const signature = new Uint8Array(crypto.sign("sha256", message, privateKey));
  const ed = crypto.generateKeyPairSync("ed25519");
  const edSpki = jwkToSpkiDer(ed.publicKey.export({ format: "jwk" }));
  return {
    es256: verifyDerSignature("sha256", spki, message, signature),
    eddsa: verifyDerSignature(null, edSpki, message, new Uint8Array(crypto.sign(null, message, ed.privateKey))),
  };
};

const run = async () => ({
  bufferGlobal: typeof globalThis.Buffer,
  es256: await attempt(() => jws("ES256")),
  eddsa: await attempt(() => jws("EdDSA")),
  rs256: await attempt(rs256),
  jwtES256: await attempt(() => jwtService("ES256")),
  jwtEdDSA: await attempt(() => jwtService("EdDSA")),
  apple: await attempt(apple),
  pbkdf2: await attempt(() => password(pbkdf2Hasher())),
  scrypt: await attempt(() => password(scryptHasher({ cost: 16384 }))),
  tokenHash: await attempt(() => ({
    digest: hashToken("raw-token"),
    equal: constantTimeHashEqual(hashToken("a"), hashToken("a")),
    unequal: !constantTimeHashEqual(hashToken("a"), hashToken("b")),
  })),
  hmac: await attempt(() => ({ sha1: b64(hmac("sha1", "key", "data")), sha256: b64(sha256("data")) })),
  aes: await attempt(aes),
  der: await attempt(der),
});

/** Verify what Node made: JWS signatures, an AES-GCM ciphertext and a PBKDF2 hash. */
const check = async (input) => ({
  jws: input.jws.map(({ algorithm, jwk, data, signature }) =>
    verifyJws(algorithm, unb64(data), unb64(signature), jwk),
  ),
  eddsaSignature: b64(signJws("EdDSA", unb64(input.eddsa.data), input.eddsa.privateKeyPem)),
  decrypted: await Effect.runPromise(aes256GcmCipher(input.aes.secret).decrypt(input.aes.sealed)),
  pbkdf2: await Effect.runPromise(pbkdf2Hasher().verify(input.pbkdf2.password, input.pbkdf2.hash)),
});

export default {
  async fetch(request) {
    const url = new URL(request.url);
    const body = url.pathname === "/check" ? await check(await request.json()) : await run();
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
  `(name = "${name}", worker = (modules = [(name = "worker.js", esModule = embed "worker.js")], compatibilityDate = "${DATES[name]}", compatibilityFlags = ["nodejs_compat"]))`;

const CONFIG = `using Workerd = import "/workerd/workerd.capnp";
const config :Workerd.Config = (
  services = [
    ${DATE_NAMES.map(workerService).join(",\n    ")},
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
  data: Schema.String,
  signature: Schema.String,
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
});

/** A JWS Node signed, as the worker's `/check` reads it. */
const NodeSigned = Schema.Struct({
  algorithm: Schema.Literals(["ES256", "EdDSA", "RS256"]),
  jwk: Jwk,
  privateKeyPem: Schema.String,
  data: Schema.String,
  signature: Schema.String,
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

const Check = Schema.Struct({
  jws: Schema.Array(Schema.Boolean),
  eddsaSignature: Schema.String,
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

/** The pre-#748 verifier: a `KeyObject` with `dsaEncoding`, which Node accepts and workerd does not. */
const keyObjectVerify = (
  algorithm: JwsAlgorithm,
  data: Uint8Array,
  signature: Uint8Array,
  jwk: crypto.JsonWebKeyInput["key"],
): boolean => {
  const key = crypto.createPublicKey({ key: jwk, format: "jwk" });
  if (algorithm === "ES256")
    return crypto.verify("sha256", data, { key, dsaEncoding: "ieee-p1363" }, signature);
  return crypto.verify(algorithm === "RS256" ? "sha256" : null, data, key, signature);
};

/** A JWS signed in Node with the pre-#748 `KeyObject` form. */
const nodeSigned = (algorithm: JwsAlgorithm) => {
  const { publicKey, privateKey } =
    algorithm === "ES256"
      ? crypto.generateKeyPairSync("ec", { namedCurve: "P-256" })
      : algorithm === "EdDSA"
        ? crypto.generateKeyPairSync("ed25519")
        : crypto.generateKeyPairSync("rsa", { modulusLength: 2048 });
  const data = new TextEncoder().encode(`node.signed-${algorithm}`);
  const signature =
    algorithm === "ES256"
      ? crypto.sign("sha256", data, { key: privateKey, dsaEncoding: "ieee-p1363" })
      : crypto.sign(algorithm === "RS256" ? "sha256" : null, data, privateKey);
  return {
    algorithm,
    jwk: decodeJwk(publicKey.export({ format: "jwk" })),
    privateKeyPem: privateKey.export({ type: "pkcs8", format: "pem" }),
    data: Base64Url.encode(data),
    signature: Base64Url.encode(new Uint8Array(signature)),
  };
};

describe.each(DATE_NAMES)("workerd at its %s compatibility date", (date) => {
  let run: typeof Run.Type;
  beforeAll(async () => {
    run = await callWorker(Run, date, "/run");
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
      expect(
        keyObjectVerify(algorithm, bytes(signed.data), bytes(signed.signature), signed.jwk),
      ).toBe(true);
    },
  );

  it("emits ES256 signatures in raw JOSE r || s form", () => {
    expect(bytes(valueOf(run.es256).signature)).toHaveLength(64);
  });

  it("signs the Ed25519 bytes Node signs from the same key", () => {
    // Ed25519 is deterministic, so the two runtimes must agree byte for byte.
    const signed = valueOf(run.eddsa);
    const nodeSignature = crypto.sign(null, bytes(signed.data), signed.privateKeyPem);
    expect(Base64Url.encode(new Uint8Array(nodeSignature))).toBe(signed.signature);
  });

  it.each(["jwtES256", "jwtEdDSA"] as const)(
    "JwtService signs and verifies a token (%s), which Node verifies against its JWKS",
    (name) => {
      const jwt = valueOf(run[name]);
      expect(jwt.sub).toBe("u-1");
      expect(jwt.rejectsTampered).toBe(true);
      const [header, payload, signature] = jwt.token.split(".");
      assert(header !== undefined && payload !== undefined && signature !== undefined);
      const [jwk] = jwt.jwks.keys;
      assert(jwk !== undefined, "the JWKS has the signing key");
      const signingInput = new TextEncoder().encode(`${header}.${payload}`);
      const algorithm = name === "jwtES256" ? "ES256" : "EdDSA";
      expect(keyObjectVerify(algorithm, signingInput, bytes(signature), jwk)).toBe(true);
    },
  );

  it("builds an Apple client secret that verifies in both runtimes", () => {
    const apple = valueOf(run.apple);
    expect(apple.verifies).toBe(true);
    const [header, payload, signature] = apple.token.split(".");
    assert(header !== undefined && payload !== undefined && signature !== undefined);
    const signingInput = new TextEncoder().encode(`${header}.${payload}`);
    expect(keyObjectVerify("ES256", signingInput, bytes(signature), apple.jwk)).toBe(true);
  });

  it.each(["pbkdf2", "scrypt"] as const)("hashes and verifies a password with %s", (name) => {
    const result = valueOf(run[name]);
    expect(result.verifies).toBe(true);
    expect(result.rejectsWrong).toBe(true);
  });

  it("hashes tokens, HMACs and digests as Node does", () => {
    const tokenHash = valueOf(run.tokenHash);
    expect(tokenHash).toEqual({ digest: hashToken("raw-token"), equal: true, unequal: true });
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
    const opened = await Effect.runPromise(aes256GcmCipher("workerd-secret").decrypt(aes.sealed));
    expect(opened).toBe("refresh-token-123");
  });

  it("verifies WebAuthn DER signatures", () => {
    expect(valueOf(run.der)).toEqual({ es256: true, eddsa: true });
  });

  it("verifies what Node signed, sealed and hashed", async () => {
    const jws = (["ES256", "EdDSA", "RS256"] as const).map(nodeSigned);
    const eddsa = nodeSigned("EdDSA");
    const sealed = await Effect.runPromise(aes256GcmCipher("node-secret").encrypt("from-node"));
    const { hash } = await Effect.runPromise(pbkdf2Hasher().hash("node password"));
    const body = encodeCheckInput({
      jws,
      eddsa,
      aes: { secret: "node-secret", sealed },
      pbkdf2: { password: "node password", hash },
    });
    const checked = await callWorker(Check, date, "/check", body);
    expect(checked).toEqual({
      jws: [true, true, true],
      eddsaSignature: eddsa.signature,
      decrypted: "from-node",
      pbkdf2: true,
    });
  });
});
