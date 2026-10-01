/**
 * JSON Web Tokens (compact JWS) for effect-auth.
 *
 * Mirrors better-auth's jwt plugin: issue short-lived, asymmetrically signed
 * JWTs for authenticated users so downstream services can verify sessions
 * without a shared secret or a round-trip to the auth server, and publish
 * the matching public keys as a JWKS document.
 *
 * Key generation, signing, and verification delegate to the raw primitives
 * in `Cipher.ts`; the key id's randomness comes from Effect's `Crypto`
 * service:
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

import { Config, Context, Crypto, Data, Deferred, Effect, Layer, Redacted, Ref } from "effect";
import * as Cipher from "./Cipher.ts";
import type { TokenCipher } from "./Cipher.ts";
import type * as Errors from "./Errors.ts";
import * as PlatformCrypto from "./PlatformCrypto.ts";
import type * as Types from "./Types.ts";
import * as Obs from "./Observability.ts";

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
export class JwtKeyStore extends Context.Service<
  JwtKeyStore,
  {
    /** The key pair new tokens should be signed with, or null when none exists */
    readonly getActive: () => Effect.Effect<JwtKeyPair | null, Errors.AuthError>;
    readonly create: (pair: JwtKeyPair) => Effect.Effect<JwtKeyPair, Errors.AuthError>;
    /** Every known key pair (verification matches tokens by `kid`) */
    readonly list: () => Effect.Effect<readonly JwtKeyPair[], Errors.AuthError>;
  }
>()("@effect-auth/JwtKeyStore") {}

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
  /**
   * Clock-skew tolerance in milliseconds applied to `exp` and `nbf` checks.
   * A token expired by less than `clockSkewLeeway` ms is still accepted;
   * a not-yet-valid token whose `nbf` is within `clockSkewLeeway` ms in the
   * future is also accepted. Default: 0 (zero tolerance).
   */
  readonly clockSkewLeeway?: number;
  /**
   * Opt-in encryption-at-rest for the PKCS#8 PEM private key stored in
   * {@link JwtKeyStore}. The store sees only ciphertext; plaintext is only
   * ever held in memory during signing.
   *
   * Pass `{ secret }` to use the built-in AES-256-GCM cipher (key derived
   * from the secret via SHA-256; each stored key gets a unique random IV and
   * a GCM auth-tag for integrity). Pass `{ cipher }` to supply a custom
   * {@link TokenCipher} (envelope encryption, HSM-backed keys, etc.).
   *
   * Strongly recommended in production. When this option is set, encryption
   * is always applied — there is no opt-out per key.
   */
  readonly encryptPrivateKey?:
    | { readonly secret: Redacted.Redacted<string> }
    | { readonly cipher: TokenCipher };
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
export class JwtService extends Context.Service<
  JwtService,
  {
    /**
     * Sign a JWT for a user. The header is `{ alg, kid, typ: "JWT" }`; the
     * payload carries `iss`/`aud?`/`sub`/`iat`/`exp` plus `definePayload(user)`
     * and any `extraClaims`. Lazily generates and persists a key pair on first
     * use when the store is empty.
     */
    readonly sign: (
      user: Types.User,
      extraClaims?: Record<string, unknown>,
    ) => Effect.Effect<JwtSignResult, JwtError | Errors.AuthError>;

    /**
     * Verify a compact JWS and return its decoded payload. Validates the
     * signature against the stored key whose `kid` matches the header, then
     * checks `exp`, `nbf`, `iss`, and (when configured) `aud`. Fails with
     * {@link JwtError} on any mismatch.
     */
    readonly verify: (
      token: string,
    ) => Effect.Effect<Record<string, unknown>, JwtError | Errors.AuthError>;

    /**
     * The JWKS document containing every stored public key (with `kid`,
     * `alg`, and `use: "sig"`) and no private material. Serve this at
     * `/.well-known/jwks.json`.
     */
    readonly getJwks: () => Effect.Effect<Jwks, Errors.AuthError>;
  }
>()("@effect-auth/JwtService") {
  /**
   * Construct a Layer providing this service.
   */
  static readonly layer = (config: JwtConfig) =>
    Layer.effect(JwtService, make(config)).pipe(Layer.provide(PlatformCrypto.layer));

  /**
   * Construct a Layer from environment variables via {@link jwtServiceConfig}.
   *
   * Required env vars: `JWT_ISSUER`.
   * Optional: `JWT_AUDIENCE`, `JWT_EXPIRES_IN_MS`, `JWT_ALGORITHM`,
   * `JWT_CLOCK_SKEW_LEEWAY_MS`, `JWT_ENCRYPT_PRIVATE_KEY_SECRET`.
   */
  static readonly layerFromEnv = Layer.effect(
    JwtService,
    Effect.gen(function* () {
      const cfg = yield* jwtServiceConfig;
      return yield* make({
        issuer: cfg.issuer,
        ...(cfg.audience !== undefined && { audience: cfg.audience }),
        ...(cfg.expiresIn !== undefined && { expiresIn: cfg.expiresIn }),
        ...(cfg.algorithm !== undefined && { algorithm: cfg.algorithm }),
        ...(cfg.clockSkewLeeway !== undefined && { clockSkewLeeway: cfg.clockSkewLeeway }),
        ...(cfg.encryptPrivateKey !== undefined && { encryptPrivateKey: cfg.encryptPrivateKey }),
      });
    }),
  ).pipe(Layer.provide(PlatformCrypto.layer));
}

/**
 * Effect `Config` for {@link JwtConfig}.
 *
 * Required env vars: `JWT_ISSUER`.
 * Optional: `JWT_AUDIENCE`, `JWT_EXPIRES_IN_MS`, `JWT_ALGORITHM`,
 * `JWT_CLOCK_SKEW_LEEWAY_MS`, `JWT_ENCRYPT_PRIVATE_KEY_SECRET`.
 */
export const jwtServiceConfig = Config.all({
  issuer: Config.String("JWT_ISSUER"),
  audience: Config.String("JWT_AUDIENCE").pipe(Config.orElse(() => Config.succeed(undefined))),
  expiresIn: Config.Int("JWT_EXPIRES_IN_MS").pipe(Config.orElse(() => Config.succeed(undefined))),
  algorithm: Config.String("JWT_ALGORITHM").pipe(
    Config.map((s) => s as JwtAlgorithm),
    Config.orElse(() => Config.succeed(undefined)),
  ),
  clockSkewLeeway: Config.Int("JWT_CLOCK_SKEW_LEEWAY_MS").pipe(
    Config.orElse(() => Config.succeed(undefined)),
  ),
  encryptPrivateKey: Config.Redacted("JWT_ENCRYPT_PRIVATE_KEY_SECRET").pipe(
    Config.map((secret) => ({ secret }) as const),
    Config.orElse(() => Config.succeed(undefined)),
  ),
});

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
 * is exported as a JWK, the private key as PKCS#8 PEM.
 */
export const generateKeyPair = (
  algorithm: JwtAlgorithm,
  crypto: Crypto.Crypto,
): Effect.Effect<JwtKeyPair, JwtError> =>
  Effect.gen(function* () {
    const id = yield* crypto.randomUUIDv4.pipe(
      Effect.mapError(
        (cause) => new JwtError({ message: `Failed to generate ${algorithm} key id`, cause }),
      ),
    );
    return yield* Effect.try({
      try: (): JwtKeyPair => {
        const { publicKeyJwk, privateKeyPem } = Cipher.generateJwsKeyPair(algorithm);
        return {
          id,
          algorithm,
          publicKeyJwk,
          privateKeyPem,
          createdAt: Date.now(),
        };
      },
      catch: (error) =>
        new JwtError({
          message: `Failed to generate ${algorithm} key pair`,
          cause: error,
        }),
    });
  });

/**
 * Sign `data` with the pair's private key. ES256 signatures are emitted in
 * raw JOSE `r || s` form (Node defaults to DER, which JWS does not accept);
 * Ed25519 signs with a null digest.
 */
const signBytes = (pair: JwtKeyPair, data: Buffer): Effect.Effect<Buffer, JwtError> =>
  Effect.try({
    try: () => Buffer.from(Cipher.signJws(pair.algorithm, data, pair.privateKeyPem)),
    catch: (error) =>
      new JwtError({
        message: "Failed to sign token",
        cause: error,
      }),
  });

/**
 * Verify `signature` over `data` against a public JWK.
 */
const verifyBytesFromJwk = (
  jwk: Record<string, unknown>,
  algorithm: JwtAlgorithm,
  data: Buffer,
  signature: Buffer,
): Effect.Effect<boolean, JwtError> =>
  Effect.try({
    try: () => Cipher.verifyJws(algorithm, data, signature, jwk),
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
export const make = (
  config: JwtConfig,
): Effect.Effect<typeof JwtService.Service, never, JwtKeyStore | Crypto.Crypto> =>
  Effect.gen(function* () {
    const expiresIn = config.expiresIn ?? 15 * 60 * 1000; // 15 minutes default
    const algorithm = config.algorithm ?? "ES256";
    const getSubject = config.getSubject ?? ((user: Types.User) => user.id);
    const leewayMs = config.clockSkewLeeway ?? 0;

    const cipher: TokenCipher | null = config.encryptPrivateKey
      ? "cipher" in config.encryptPrivateKey
        ? config.encryptPrivateKey.cipher
        : Cipher.aes256GcmCipher(Redacted.value(config.encryptPrivateKey.secret))
      : null;

    const store = yield* JwtKeyStore;
    const crypto = yield* Crypto.Crypto;

    // Ref holding an in-progress key-creation Deferred; null when idle.
    // Prevents duplicate active keys when concurrent fibers both call sign()
    // before any key exists (both see getActive() → null).
    type PendingDeferred = Deferred.Deferred<JwtKeyPair, JwtError | Errors.AuthError>;
    const pendingCreate = yield* Ref.make<PendingDeferred | null>(null);

    /**
     * Fetch the active signing key, lazily generating and persisting one when
     * the store is empty. Private key PEM is decrypted (when a cipher is
     * configured) before returning, so callers always receive plaintext.
     * Concurrent first-call fibers are serialized through a Deferred so only
     * one key is generated regardless of concurrency.
     */
    const getOrCreateActiveKey: Effect.Effect<JwtKeyPair, JwtError | Errors.AuthError> = Effect.gen(
      function* () {
        const active = yield* store.getActive();
        if (active) {
          if (cipher === null) return active;
          return { ...active, privateKeyPem: yield* cipher.decrypt(active.privateKeyPem) };
        }

        const deferred = yield* Deferred.make<JwtKeyPair, JwtError | Errors.AuthError>();

        // Atomically claim leadership or attach to an in-progress creation.
        const existing: PendingDeferred | null = yield* Ref.modify(
          pendingCreate,
          (current): readonly [PendingDeferred | null, PendingDeferred | null] =>
            current === null ? [null, deferred] : [current, current],
        );

        if (existing !== null) {
          return yield* Deferred.await(existing);
        }

        // Leader: generate and persist the key
        const pair = yield* Effect.gen(function* () {
          const kp = yield* generateKeyPair(algorithm, crypto);
          const toStore =
            cipher !== null
              ? { ...kp, privateKeyPem: yield* cipher.encrypt(kp.privateKeyPem) }
              : kp;
          yield* store.create(toStore);
          return kp;
        }).pipe(
          Effect.onError((cause) =>
            Effect.gen(function* () {
              yield* Deferred.failCause(deferred, cause);
              yield* Ref.set(pendingCreate, null);
            }),
          ),
        );

        yield* Deferred.succeed(deferred, pair);
        yield* Ref.set(pendingCreate, null);
        return pair;
      },
    );

    return {
      sign: Effect.fn("JwtService.sign")(
        (user: Types.User, extraClaims?: Record<string, unknown>) =>
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
          }).pipe(Effect.withSpan(Obs.spanNames.tokenSign)),
      ),

      verify: Effect.fn("JwtService.verify")((token: string) =>
        Effect.gen(function* () {
          const segments = token.split(".");
          if (segments.length !== 3) {
            return yield* new JwtError({
              message: "Malformed JWT: expected three dot-separated segments",
            });
          }
          const [headerSegment, payloadSegment, signatureSegment] = segments as [
            string,
            string,
            string,
          ];

          const header = yield* decodeJsonSegment(headerSegment, "header");

          const keys = yield* store.list();
          const pair = keys.find((candidate) => candidate.id === header["kid"]);
          if (!pair) {
            return yield* new JwtError({
              message: "Unknown signing key (kid not found)",
            });
          }

          if (header["alg"] !== pair.algorithm) {
            return yield* new JwtError({
              message: "Token algorithm does not match the signing key",
            });
          }

          const validSignature = yield* verifyBytesFromJwk(
            pair.publicKeyJwk,
            pair.algorithm,
            Buffer.from(`${headerSegment}.${payloadSegment}`, "utf8"),
            base64UrlDecode(signatureSegment),
          );
          if (!validSignature) {
            return yield* new JwtError({
              message: "Invalid token signature",
            });
          }

          const payload = yield* decodeJsonSegment(payloadSegment, "payload");

          const exp = payload["exp"];
          if (typeof exp !== "number" || Date.now() >= exp * 1000 + leewayMs) {
            return yield* new JwtError({
              message: "Token has expired",
            });
          }

          const nbf = payload["nbf"];
          if (typeof nbf === "number" && Date.now() < nbf * 1000 - leewayMs) {
            return yield* new JwtError({
              message: "Token not yet valid",
            });
          }

          if (payload["iss"] !== config.issuer) {
            return yield* new JwtError({
              message: "Token issuer mismatch",
            });
          }

          if (config.audience !== undefined) {
            const aud = payload["aud"];
            const matches = Array.isArray(aud)
              ? aud.includes(config.audience)
              : aud === config.audience;
            if (!matches) {
              return yield* new JwtError({
                message: "Token audience mismatch",
              });
            }
          }

          return payload;
        }).pipe(
          Effect.withSpan(Obs.spanNames.tokenVerify, { attributes: { type: "jwt" } }),
          Effect.tap(() => Obs.recordTokenVerification("jwt", "success")),
          Effect.tapError(() => Obs.recordTokenVerification("jwt", "failure")),
        ),
      ),

      getJwks: Effect.fn("JwtService.getJwks")(function* () {
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
    };
  });

// ---------------------------------------------------------------------------
// Remote JWKS verification
// ---------------------------------------------------------------------------

/**
 * Configuration for verifying JWTs against a remote JWKS endpoint.
 * Intended for resource servers that receive tokens but do not hold private
 * signing keys.
 */
export interface RemoteJwksConfig {
  /** URL of the JWKS document, e.g. `https://auth.example.com/.well-known/jwks.json` */
  readonly jwksUri: string;
  /** Expected `iss` claim; verification requires an exact match */
  readonly issuer: string;
  /** Expected `aud` claim; when set, verification requires it */
  readonly audience?: string;
  /** How long to cache a fetched JWKS in milliseconds (default: 5 minutes) */
  readonly cacheTtlMs?: number;
  /**
   * Clock-skew tolerance in milliseconds applied to `exp` and `nbf` checks
   * (default: 0).
   */
  readonly clockSkewLeeway?: number;
}

/**
 * A stand-alone JWT verifier backed by a remote JWKS document.
 */
export class RemoteJwksVerifier extends Context.Service<
  RemoteJwksVerifier,
  {
    /**
     * Verify a compact JWS against the remote JWKS. On first call (or after
     * cache expiry) the JWKS is fetched and cached. If the `kid` from the
     * token header is absent in the cached JWKS, the cache is refreshed once to
     * handle key rotation before failing.
     */
    readonly verify: (token: string) => Effect.Effect<Record<string, unknown>, JwtError>;
  }
>()("@effect-auth/RemoteJwksVerifier") {
  static readonly layer = (config: RemoteJwksConfig) =>
    Layer.effect(RemoteJwksVerifier, remoteJwksVerifier(config));
}

interface JwksCache {
  readonly keys: readonly Record<string, unknown>[];
  readonly fetchedAt: number;
}

const fetchJwks = (uri: string): Effect.Effect<JwksCache, JwtError> =>
  Effect.tryPromise({
    try: () =>
      fetch(uri, { headers: { Accept: "application/json" } })
        .then((res) => {
          if (!res.ok) throw new Error(`JWKS endpoint returned HTTP ${res.status}`);
          return res.json() as Promise<{ keys: Record<string, unknown>[] }>;
        })
        .then((data) => ({ keys: data.keys, fetchedAt: Date.now() })),
    catch: (error) => new JwtError({ message: "Failed to fetch JWKS", cause: error }),
  });

/**
 * Create a {@link RemoteJwksVerifier} that fetches the JWKS at
 * `config.jwksUri`, caches it for `cacheTtlMs`, and verifies tokens against
 * it. Concurrent fetch requests are deduplicated via a Deferred.
 */
export const remoteJwksVerifier = (
  config: RemoteJwksConfig,
): Effect.Effect<typeof RemoteJwksVerifier.Service, never> =>
  Effect.gen(function* () {
    const cacheTtlMs = config.cacheTtlMs ?? 5 * 60 * 1000;
    const leewayMs = config.clockSkewLeeway ?? 0;

    const cacheRef = yield* Ref.make<JwksCache | null>(null);

    // Deduplicates concurrent JWKS fetches — only one HTTP request in-flight.
    type FetchDeferred = Deferred.Deferred<JwksCache, JwtError>;
    const pendingFetch = yield* Ref.make<FetchDeferred | null>(null);

    const getKeys = (
      forceRefresh: boolean,
    ): Effect.Effect<readonly Record<string, unknown>[], JwtError> =>
      Effect.gen(function* () {
        if (!forceRefresh) {
          const cached = yield* Ref.get(cacheRef);
          if (cached !== null && Date.now() - cached.fetchedAt < cacheTtlMs) {
            return cached.keys;
          }
        }

        const deferred = yield* Deferred.make<JwksCache, JwtError>();
        const existing: FetchDeferred | null = yield* Ref.modify(
          pendingFetch,
          (current): readonly [FetchDeferred | null, FetchDeferred | null] =>
            current === null ? [null, deferred] : [current, current],
        );

        if (existing !== null) {
          const result = yield* Deferred.await(existing);
          return result.keys;
        }

        // Leader: perform the fetch
        const result = yield* fetchJwks(config.jwksUri).pipe(
          Effect.onError((cause) =>
            Effect.gen(function* () {
              yield* Deferred.failCause(deferred, cause);
              yield* Ref.set(pendingFetch, null);
            }),
          ),
        );

        yield* Ref.set(cacheRef, result);
        yield* Deferred.succeed(deferred, result);
        yield* Ref.set(pendingFetch, null);
        return result.keys;
      });

    return {
      verify: (token) =>
        Effect.gen(function* () {
          const segments = token.split(".");
          if (segments.length !== 3) {
            return yield* new JwtError({
              message: "Malformed JWT: expected three dot-separated segments",
            });
          }
          const [headerSegment, payloadSegment, signatureSegment] = segments as [
            string,
            string,
            string,
          ];

          const header = yield* decodeJsonSegment(headerSegment, "header");

          const alg = header["alg"];
          if (alg !== "ES256" && alg !== "EdDSA") {
            return yield* new JwtError({
              message: `Unsupported or missing algorithm: ${String(alg)}`,
            });
          }

          const kid = header["kid"];

          // Look up by kid; on miss, refresh once in case of key rotation.
          let keys = yield* getKeys(false);
          let matchedKey = keys.find((k) => k["kid"] === kid);

          if (!matchedKey) {
            keys = yield* getKeys(true);
            matchedKey = keys.find((k) => k["kid"] === kid);
          }

          if (!matchedKey) {
            return yield* new JwtError({
              message: "Unknown signing key (kid not found in remote JWKS)",
            });
          }

          // If the JWKS key carries an alg field it must match the header.
          if (matchedKey["alg"] !== undefined && matchedKey["alg"] !== alg) {
            return yield* new JwtError({
              message: "Token algorithm does not match the signing key",
            });
          }

          const validSignature = yield* verifyBytesFromJwk(
            matchedKey,
            alg as JwtAlgorithm,
            Buffer.from(`${headerSegment}.${payloadSegment}`, "utf8"),
            base64UrlDecode(signatureSegment),
          );

          if (!validSignature) {
            return yield* new JwtError({ message: "Invalid token signature" });
          }

          const payload = yield* decodeJsonSegment(payloadSegment, "payload");

          const exp = payload["exp"];
          if (typeof exp !== "number" || Date.now() >= exp * 1000 + leewayMs) {
            return yield* new JwtError({ message: "Token has expired" });
          }

          const nbf = payload["nbf"];
          if (typeof nbf === "number" && Date.now() < nbf * 1000 - leewayMs) {
            return yield* new JwtError({ message: "Token not yet valid" });
          }

          if (payload["iss"] !== config.issuer) {
            return yield* new JwtError({ message: "Token issuer mismatch" });
          }

          if (config.audience !== undefined) {
            const aud = payload["aud"];
            const matches = Array.isArray(aud)
              ? aud.includes(config.audience)
              : aud === config.audience;
            if (!matches) {
              return yield* new JwtError({ message: "Token audience mismatch" });
            }
          }

          return payload;
        }),
    };
  });
