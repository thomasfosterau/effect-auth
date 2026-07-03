/**
 * JSON Web Tokens (compact JWS) for effect-auth.
 *
 * Mirrors better-auth's jwt plugin: issue short-lived, asymmetrically signed
 * JWTs for authenticated users so downstream services can verify sessions
 * without a shared secret or a round-trip to the auth server, and publish
 * the matching public keys as a JWKS document.
 *
 * Implemented with `node:crypto` only (no dependencies):
 *
 * - `ES256` (ECDSA over P-256 with SHA-256) — the default. Node's ECDSA
 *   signatures are DER-encoded by default, but JOSE requires the raw
 *   `r || s` concatenation, so signing/verifying passes
 *   `dsaEncoding: "ieee-p1363"`.
 * - `EdDSA` (Ed25519) — better-auth's default; sign/verify with a `null`
 *   digest as required for Ed25519.
 *
 * All three token segments use unpadded base64url encoding.
 *
 * Serving the JWKS is the application's concern: expose the result of
 * `getJwks()` at `/.well-known/jwks.json` (or wherever your `iss` publishes
 * keys) so verifiers can fetch the public keys.
 *
 * @module jwt
 */

import { Context, Data, Effect, Layer } from "effect";
import * as crypto from "node:crypto";
import type * as Errors from "./Errors.js";
import type * as Types from "./Types.js";

/**
 * JWT error
 */
export class JwtError extends Data.TaggedError("JwtError")<{
  readonly message: string;
  readonly cause?: unknown;
}> {}

/**
 * Supported signing algorithms
 */
export type JwtAlgorithm = "ES256" | "EdDSA";

/**
 * A signing key pair.
 *
 * `publicKeyJwk` is the public half only, exported in JWK form and safe to
 * publish via the JWKS document. `privateKeyPem` is the PKCS#8 PEM of the
 * private key — encrypt it at rest in production; the library stores/reads
 * it as-is.
 */
export interface JwtKeyPair {
  /** Key id (`kid`), embedded in token headers and the JWKS */
  readonly id: string;
  readonly algorithm: JwtAlgorithm;
  /** Public key in JWK form (no private material) */
  readonly publicKeyJwk: Record<string, unknown>;
  /** PKCS#8 PEM private key — encrypt at rest in production */
  readonly privateKeyPem: string;
  readonly createdAt: number;
}

/**
 * Storage interface for JWT signing keys
 */
export interface JwtKeyStore {
  /** The key pair new tokens should be signed with, or null when none exists */
  readonly getActive: () => Effect.Effect<JwtKeyPair | null, Errors.AuthError>;
  readonly create: (pair: JwtKeyPair) => Effect.Effect<JwtKeyPair, Errors.AuthError>;
  /** Every known key pair (verification matches tokens by `kid`) */
  readonly list: () => Effect.Effect<readonly JwtKeyPair[], Errors.AuthError>;
}

export class JwtKeyStoreTag extends Context.Service<JwtKeyStoreTag, JwtKeyStore>()(
  "@effect-auth/JwtKeyStore",
) {}

// Public ergonomic alias
export const JwtKeyStore = JwtKeyStoreTag;

/**
 * JWT service configuration
 */
export interface JwtConfig {
  /** Value of the `iss` claim; verification requires an exact match */
  readonly issuer: string;
  /** Value of the `aud` claim; when set, verification requires it */
  readonly audience?: string;
  /** Token lifetime in milliseconds (default: 15 minutes) */
  readonly expiresIn?: number;
  /** Signing algorithm for newly generated keys (default: "ES256") */
  readonly algorithm?: JwtAlgorithm;
  /** Derive the `sub` claim from the user (default: `user.id`) */
  readonly getSubject?: (user: Types.User) => string;
  /** Extra claims merged into every token's payload */
  readonly definePayload?: (user: Types.User) => Record<string, unknown>;
}

/**
 * A signed token plus its expiry (Unix ms).
 */
export interface JwtSignResult {
  readonly token: string;
  readonly expiresAt: number;
}

/**
 * The JWKS document (RFC 7517) to serve at `/.well-known/jwks.json`.
 */
export interface Jwks {
  readonly keys: readonly Record<string, unknown>[];
}

/**
 * JWT service
 */
export interface JwtService {
  /**
   * Sign a JWT for a user. The header is `{ alg, kid, typ: "JWT" }`; the
   * payload carries `iss`/`aud?`/`sub`/`iat`/`exp` plus `definePayload(user)`
   * and any `extraClaims`. Lazily generates and persists a key pair on first
   * use when the store is empty.
   */
  readonly sign: (
    user: Types.User,
    extraClaims?: Record<string, unknown>,
  ) => Effect.Effect<JwtSignResult, JwtError | Errors.AuthError, JwtKeyStoreTag>;

  /**
   * Verify a compact JWS and return its decoded payload. Validates the
   * signature against the stored key whose `kid` matches the header, then
   * checks `exp`, `iss`, and (when configured) `aud`. Fails with
   * {@link JwtError} on any mismatch.
   */
  readonly verify: (
    token: string,
  ) => Effect.Effect<Record<string, unknown>, JwtError | Errors.AuthError, JwtKeyStoreTag>;

  /**
   * The JWKS document containing every stored public key (with `kid`,
   * `alg`, and `use: "sig"`) and no private material. Serve this at
   * `/.well-known/jwks.json`.
   */
  readonly getJwks: () => Effect.Effect<Jwks, Errors.AuthError, JwtKeyStoreTag>;
}

export class JwtServiceTag extends Context.Service<JwtServiceTag, JwtService>()(
  "@effect-auth/JwtService",
) {
  /**
   * Construct a Layer providing this service — the canonical form of
   * {@link JwtServiceLayer}.
   */
  static readonly layer = (config: JwtConfig) => JwtServiceLayer(config);
}

// Public ergonomic alias
export const JwtService = JwtServiceTag;

/**
 * Unpadded base64url of a UTF-8 string or byte buffer (Node's "base64url"
 * encoding is already unpadded, per RFC 7515).
 */
const base64UrlEncode = (data: Buffer | string): string =>
  (typeof data === "string" ? Buffer.from(data, "utf8") : data).toString("base64url");

const base64UrlDecode = (segment: string): Buffer => Buffer.from(segment, "base64url");

/**
 * Generate a fresh signing key pair for the given algorithm.
 *
 * ES256 uses ECDSA over the P-256 curve; EdDSA uses Ed25519. The public key
 * is exported as a JWK (via `crypto.KeyObject.export({ format: "jwk" })`),
 * the private key as PKCS#8 PEM.
 */
export const generateKeyPair = (algorithm: JwtAlgorithm): Effect.Effect<JwtKeyPair, JwtError> =>
  Effect.try({
    try: (): JwtKeyPair => {
      const { publicKey, privateKey } =
        algorithm === "ES256"
          ? crypto.generateKeyPairSync("ec", { namedCurve: "P-256" })
          : crypto.generateKeyPairSync("ed25519");

      return {
        id: crypto.randomUUID(),
        algorithm,
        publicKeyJwk: publicKey.export({ format: "jwk" }) as Record<string, unknown>,
        privateKeyPem: privateKey.export({ type: "pkcs8", format: "pem" }).toString(),
        createdAt: Date.now(),
      };
    },
    catch: (error) =>
      new JwtError({
        message: `Failed to generate ${algorithm} key pair`,
        cause: error,
      }),
  });

/**
 * Sign `data` with the pair's private key. ES256 signatures are emitted in
 * raw JOSE `r || s` form via `dsaEncoding: "ieee-p1363"` (Node defaults to
 * DER, which JWS does not accept); Ed25519 signs with a null digest.
 */
const signBytes = (pair: JwtKeyPair, data: Buffer): Effect.Effect<Buffer, JwtError> =>
  Effect.try({
    try: () => {
      const key = crypto.createPrivateKey(pair.privateKeyPem);
      return pair.algorithm === "ES256"
        ? crypto.sign("sha256", data, { key, dsaEncoding: "ieee-p1363" })
        : crypto.sign(null, data, key);
    },
    catch: (error) =>
      new JwtError({
        message: "Failed to sign token",
        cause: error,
      }),
  });

/**
 * Verify `signature` over `data` against the pair's public JWK.
 */
const verifyBytes = (
  pair: JwtKeyPair,
  data: Buffer,
  signature: Buffer,
): Effect.Effect<boolean, JwtError> =>
  Effect.try({
    try: () => {
      const key = crypto.createPublicKey({
        key: pair.publicKeyJwk as crypto.webcrypto.JsonWebKey,
        format: "jwk",
      });
      return pair.algorithm === "ES256"
        ? crypto.verify("sha256", data, { key, dsaEncoding: "ieee-p1363" }, signature)
        : crypto.verify(null, data, key, signature);
    },
    catch: (error) =>
      new JwtError({
        message: "Failed to verify token signature",
        cause: error,
      }),
  });

const decodeJsonSegment = (
  segment: string,
  what: string,
): Effect.Effect<Record<string, unknown>, JwtError> =>
  Effect.try({
    try: () => {
      const parsed: unknown = JSON.parse(base64UrlDecode(segment).toString("utf8"));
      if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
        throw new Error(`JWT ${what} is not a JSON object`);
      }
      return parsed as Record<string, unknown>;
    },
    catch: (error) =>
      new JwtError({
        message: `Malformed JWT ${what}`,
        cause: error,
      }),
  });

/**
 * Create a JWT service
 */
export const makeJwtService = (config: JwtConfig): Effect.Effect<JwtService, never> => {
  const expiresIn = config.expiresIn ?? 15 * 60 * 1000; // 15 minutes default
  const algorithm = config.algorithm ?? "ES256";
  const getSubject = config.getSubject ?? ((user: Types.User) => user.id);

  /**
   * Fetch the active signing key, lazily generating and persisting one when
   * the store is empty.
   */
  const getOrCreateActiveKey = Effect.gen(function* () {
    const store = yield* JwtKeyStoreTag;
    const active = yield* store.getActive();
    if (active) {
      return active;
    }
    const pair = yield* generateKeyPair(algorithm);
    return yield* store.create(pair);
  });

  return Effect.sync(
    (): JwtService => ({
      sign: (user, extraClaims) =>
        Effect.gen(function* () {
          const pair = yield* getOrCreateActiveKey;

          const now = Date.now();
          const iat = Math.floor(now / 1000);
          const exp = Math.floor((now + expiresIn) / 1000);

          const header = {
            alg: pair.algorithm,
            kid: pair.id,
            typ: "JWT",
          };

          const payload: Record<string, unknown> = {
            iss: config.issuer,
            ...(config.audience !== undefined && { aud: config.audience }),
            sub: getSubject(user),
            iat,
            exp,
            ...config.definePayload?.(user),
            ...extraClaims,
          };

          const signingInput = `${base64UrlEncode(JSON.stringify(header))}.${base64UrlEncode(
            JSON.stringify(payload),
          )}`;
          const signature = yield* signBytes(pair, Buffer.from(signingInput, "utf8"));

          return {
            token: `${signingInput}.${base64UrlEncode(signature)}`,
            expiresAt: exp * 1000,
          } satisfies JwtSignResult;
        }),

      verify: (token) =>
        Effect.gen(function* () {
          const segments = token.split(".");
          if (segments.length !== 3) {
            return yield* Effect.fail(
              new JwtError({
                message: "Malformed JWT: expected three dot-separated segments",
              }),
            );
          }
          const [headerSegment, payloadSegment, signatureSegment] = segments as [
            string,
            string,
            string,
          ];

          const header = yield* decodeJsonSegment(headerSegment, "header");

          const store = yield* JwtKeyStoreTag;
          const keys = yield* store.list();
          const pair = keys.find((candidate) => candidate.id === header["kid"]);
          if (!pair) {
            return yield* Effect.fail(
              new JwtError({
                message: "Unknown signing key (kid not found)",
              }),
            );
          }

          if (header["alg"] !== pair.algorithm) {
            return yield* Effect.fail(
              new JwtError({
                message: "Token algorithm does not match the signing key",
              }),
            );
          }

          const validSignature = yield* verifyBytes(
            pair,
            Buffer.from(`${headerSegment}.${payloadSegment}`, "utf8"),
            base64UrlDecode(signatureSegment),
          );
          if (!validSignature) {
            return yield* Effect.fail(
              new JwtError({
                message: "Invalid token signature",
              }),
            );
          }

          const payload = yield* decodeJsonSegment(payloadSegment, "payload");

          const exp = payload["exp"];
          if (typeof exp !== "number" || Date.now() >= exp * 1000) {
            return yield* Effect.fail(
              new JwtError({
                message: "Token has expired",
              }),
            );
          }

          if (payload["iss"] !== config.issuer) {
            return yield* Effect.fail(
              new JwtError({
                message: "Token issuer mismatch",
              }),
            );
          }

          if (config.audience !== undefined) {
            const aud = payload["aud"];
            const matches = Array.isArray(aud)
              ? aud.includes(config.audience)
              : aud === config.audience;
            if (!matches) {
              return yield* Effect.fail(
                new JwtError({
                  message: "Token audience mismatch",
                }),
              );
            }
          }

          return payload;
        }),

      getJwks: () =>
        Effect.gen(function* () {
          const store = yield* JwtKeyStoreTag;
          const keys = yield* store.list();

          return {
            keys: keys.map((pair) => ({
              ...pair.publicKeyJwk,
              kid: pair.id,
              alg: pair.algorithm,
              use: "sig",
            })),
          } satisfies Jwks;
        }),
    }),
  );
};

export const JwtServiceLayer = (config: JwtConfig) =>
  Layer.effect(JwtServiceTag, makeJwtService(config));
