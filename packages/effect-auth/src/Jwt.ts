/**
 * JSON Web Tokens on `effect/jose`: short-lived, asymmetrically signed JWTs
 * (`ES256` by default, or `EdDSA`) that services verify against the published
 * JWKS. Private keys are stored as JWE under a root-secret key. Serve
 * `getJwks()` at your issuer's `/.well-known/jwks.json`.
 *
 * @module jwt
 */

import {
  Clock,
  Config,
  Context,
  Data,
  Deferred,
  Duration,
  Effect,
  Layer,
  Match,
  Redacted,
  Ref,
} from "effect";
import * as MutableHashMap from "effect/MutableHashMap";
import * as Option from "effect/Option";
import * as Schema from "effect/Schema";
import type * as Scope from "effect/Scope";
import { Aead, Digest, Kdf, SecureRandom, Signature } from "effect/crypto";
import { Base64Url } from "effect/encoding";
import { FetchHttpClient, HttpClient } from "effect/http";
import { JoseError, Jwe, Jwk, Jwks as JoseJwks, Jwt as JoseJwt } from "effect/jose";
import { optionalSecret } from "./OptionalSecretConfig.ts";
import type { TokenCipher } from "./Cipher.ts";
import type * as Errors from "./Errors.ts";
import * as OutboundHttp from "./OutboundHttp.ts";
import * as PlatformCrypto from "./PlatformCrypto.ts";
import * as RootSecret from "./RootSecret.ts";
import * as Types from "./Types.ts";
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

/** The supported signing algorithms, as read from `JWT_ALGORITHM`. */
const JwtAlgorithm = Schema.Literals(["ES256", "EdDSA"]);

/**
 * A stored signing key pair.
 *
 * `publicKey` is the public JWK, safe to publish in the JWKS document.
 * `privateKey` is the private JWK as the service stores it: a compact JWE
 * (`dir` + `A256GCM`) whose protected header names the key id, or the
 * output of a custom {@link TokenCipher}. Records written before the JWE
 * format hold a PKCS#8 PEM (plain, or sealed by the earlier ciphers) here and
 * still load.
 */
export interface JwtKeyPair {
  /** Key id (`kid`), embedded in token headers and the JWKS */
  readonly id: string;
  readonly algorithm: JwtAlgorithm;
  /** Public key as a JWK (no private material) */
  readonly publicKey: Jwk.PublicJwk;
  /** The private key, encrypted at rest; never plaintext for keys this library writes */
  readonly privateKey: string;
  readonly createdAt: number;
}

/**
 * A freshly generated key pair, its private JWK not yet encrypted.
 */
export interface GeneratedJwtKeyPair {
  readonly id: string;
  readonly algorithm: JwtAlgorithm;
  readonly publicKey: Jwk.PublicJwk;
  readonly privateKey: Redacted.Redacted<Jwk.PrivateJwk>;
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
  readonly definePayload?: (user: Types.User) => Types.JsonObject;
  /**
   * Clock-skew tolerance in milliseconds applied to `exp` and `nbf` checks.
   * A token expired by less than `clockSkewLeeway` ms is still accepted;
   * a not-yet-valid token whose `nbf` is within `clockSkewLeeway` ms in the
   * future is also accepted. Default: 0 (zero tolerance).
   */
  readonly clockSkewLeeway?: number;
  /**
   * How the private key in {@link JwtKeyStore} is encrypted at rest; it
   * always is. By default it is a JWE under a key derived from the
   * {@link RootSecret.RootSecret}. Pass `{ secret }` to derive that key from
   * an override secret instead (keys stored under it before still open), or
   * `{ cipher }` for a custom {@link TokenCipher} (envelope encryption,
   * HSM-backed keys, etc.). A key stored as plaintext PEM before still reads.
   */
  readonly encryptPrivateKey?:
    | { readonly secret: Redacted.Redacted }
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
 * The JWKS document (RFC 7517) to serve at `/.well-known/jwks.json`: an
 * `effect/jose` key set of public JWKs.
 */
export interface Jwks {
  readonly keys: ReadonlyArray<Jwk.PublicJwk>;
}

/**
 * The `typ` header of every JWT {@link JwtService.sign} issues: the RFC 9068
 * access-token type. {@link JwtService.verify} and {@link RemoteJwksVerifier}
 * accept only this type (or its `application/at+jwt` spelling), so a token the
 * same keys sign for another purpose, such as an OIDC `id_token`, is refused.
 *
 * @since 0.1.0
 */
export const ACCESS_TOKEN_TYPE = "at+jwt";

/**
 * The claims of an OIDC `id_token` handed to {@link JwtService.signIdToken}.
 * `iat` and `exp` are added by the service.
 */
export interface IdTokenClaims {
  readonly iss: string;
  readonly sub: string;
  readonly aud: string;
  readonly [claim: string]: Types.Json;
}

/**
 * JWT service
 */
export class JwtService extends Context.Service<
  JwtService,
  {
    /**
     * Sign an access JWT for a user. The header is
     * `{ alg, kid, typ: "at+jwt" }` ({@link ACCESS_TOKEN_TYPE}); the
     * payload carries `iss`/`aud?`/`sub`/`iat`/`exp` plus `definePayload(user)`
     * and any `extraClaims`. Lazily generates and persists a key pair on first
     * use when the store is empty.
     */
    readonly sign: (
      user: Types.User,
      extraClaims?: Types.JsonObject,
    ) => Effect.Effect<JwtSignResult, JwtError | Errors.AuthError>;

    /**
     * Sign an OIDC `id_token` with the same keys. The header is
     * `{ alg, kid, typ: "JWT" }`, so {@link verify} refuses the result; the
     * payload is exactly `claims` plus `iat` and `exp`, never
     * `definePayload` or the configured `audience`.
     */
    readonly signIdToken: (
      claims: IdTokenClaims,
    ) => Effect.Effect<JwtSignResult, JwtError | Errors.AuthError>;

    /**
     * Verify a compact access JWS and return its decoded payload. Requires
     * the `typ` header {@link ACCESS_TOKEN_TYPE}, validates the signature
     * against the stored key whose `kid` matches the header, then checks
     * `exp` (required), `nbf`, `iss`, and (when configured) `aud`. Fails with
     * {@link JwtError} on any mismatch.
     */
    readonly verify: (
      token: string,
    ) => Effect.Effect<Types.JsonObject, JwtError | Errors.AuthError>;

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
  // Unset is the default algorithm; a value that names no supported algorithm
  // fails the config rather than reaching `make`.
  algorithm: Config.schema(JwtAlgorithm, "JWT_ALGORITHM").pipe(
    Config.option,
    Config.map(Option.getOrUndefined),
  ),
  clockSkewLeeway: Config.Int("JWT_CLOCK_SKEW_LEEWAY_MS").pipe(
    Config.orElse(() => Config.succeed(undefined)),
  ),
  encryptPrivateKey: optionalSecret("JWT_ENCRYPT_PRIVATE_KEY_SECRET").pipe(
    Config.map((secret) => (secret === undefined ? undefined : ({ secret } as const))),
  ),
});

/** The claims schema: any JSON object. */
const Claims = Types.JsonObject;

const PrivateJwkFromString = Schema.fromJsonString(Jwk.PrivateJwk);
const decodePrivateJwk = Schema.decodeUnknownEffect(PrivateJwkFromString);
const encodePrivateJwk = Schema.encodeEffect(PrivateJwkFromString);

/** The `cty` of a stored private key's JWE. */
const PRIVATE_KEY_CONTENT_TYPE = "jwk+json";

const encoder = new TextEncoder();
const decoder = new TextDecoder();

/** What a JOSE failure means to a caller, in the messages this module has always used. */
const claimMessages: Record<JoseError.ClaimValidationFailed["claim"], string> = {
  exp: "Token has expired",
  nbf: "Token not yet valid",
  iss: "Token issuer mismatch",
  aud: "Token audience mismatch",
  sub: "Token subject mismatch",
  iat: "Token issued-at is invalid",
  jti: "Token id is invalid",
  typ: "Token type mismatch",
};

const reasonMessage = (reason: JoseError.JoseErrorReason): string =>
  Match.value(reason).pipe(
    Match.tags({
      ClaimValidationFailed: (failed) => claimMessages[failed.claim],
      SignatureVerificationFailed: () => "Invalid token signature",
      KeyNotFound: () => "Unknown signing key (kid not found)",
      AlgorithmNotAllowed: () => "Token algorithm does not match the signing key",
      InvalidToken: (invalid) => `Malformed JWT: ${invalid.message}`,
    }),
    Match.orElse((other) => other.message),
  );

/** A JOSE or claims-schema failure as a {@link JwtError}. */
const toJwtError = (error: JoseJwt.JwtError): JwtError =>
  new JwtError({
    message: JoseError.isJoseError(error) ? reasonMessage(error.reason) : "Malformed JWT payload",
    cause: error,
  });

/**
 * Generate a fresh signing key pair for the given algorithm: ECDSA over
 * P-256 for `ES256`, Ed25519 for `EdDSA`, with a random key id.
 */
export const generateKeyPair = (
  algorithm: JwtAlgorithm,
): Effect.Effect<GeneratedJwtKeyPair, JwtError, SecureRandom.SecureRandom | Signature.Signature> =>
  Effect.gen(function* () {
    const id = yield* SecureRandom.SecureRandom.use((random) => random.uuidV4());
    const pair = yield* Jwk.generateKeyPair({ algorithm, kid: id }).pipe(
      Effect.mapError(
        (cause) => new JwtError({ message: `Failed to generate ${algorithm} key pair`, cause }),
      ),
    );
    return {
      id,
      algorithm,
      publicKey: pair.publicKey,
      privateKey: pair.privateKey,
      createdAt: yield* Clock.currentTimeMillis,
    };
  });

/** The key set {@link JwtService.getJwks} serves for `pairs`. */
const keySetOf = (pairs: ReadonlyArray<JwtKeyPair>): Jwks => ({
  keys: pairs.map((pair) => ({ ...pair.publicKey, kid: pair.id, alg: pair.algorithm, use: "sig" })),
});

/** The JWE key for stored private keys: the purpose's key, as a `dir` secret. */
const jweKey = (bytes: Uint8Array): Effect.Effect<Jwk.SecretKey<"dir">> =>
  Effect.orDie(
    Jwk.importSecret(Redacted.make({ kty: "oct" as const, k: Base64Url.encode(bytes) }), "dir"),
  );

/** A compact JWE has five segments; every earlier stored format has fewer. */
const isCompactJwe = (stored: string): boolean => stored.split(".").length === 5;

/**
 * Create a JWT service
 */
export const make = (
  config: JwtConfig,
): Effect.Effect<
  typeof JwtService.Service,
  never,
  | JwtKeyStore
  | SecureRandom.SecureRandom
  | Signature.Signature
  | Aead.Aead
  | Digest.Digest
  | Kdf.Kdf
  | RootSecret.RootSecret
> =>
  Effect.gen(function* () {
    const expiresIn = config.expiresIn ?? 15 * 60 * 1000; // 15 minutes default
    const algorithm = config.algorithm ?? "ES256";
    const getSubject = config.getSubject ?? ((user: Types.User) => user.id);
    const leewayMs = config.clockSkewLeeway ?? 0;
    const encryption = config.encryptPrivateKey;
    const cipher =
      encryption !== undefined && "cipher" in encryption ? encryption.cipher : undefined;

    // Opens the formats written before the JWE one (sealed or plaintext PEM).
    const legacy = yield* RootSecret.sealerFor("jwt-private-key", encryption);
    const rootSecret = yield* RootSecret.RootSecret;
    const key = yield* Effect.cached(
      Effect.flatMap(
        encryption !== undefined && "secret" in encryption
          ? RootSecret.deriveKey(Redacted.value(encryption.secret), "jwt-private-key")
          : rootSecret.key("jwt-private-key"),
        jweKey,
      ),
    );
    const context = yield* Effect.context<
      Aead.Aead | Kdf.Kdf | SecureRandom.SecureRandom | Signature.Signature
    >();

    const store = yield* JwtKeyStore;

    const encryptionFailed = (cause: unknown) =>
      new JwtError({ message: "Failed to encrypt the private key", cause });
    const decryptionFailed = (cause: unknown) =>
      new JwtError({ message: "Failed to decrypt the private key", cause });

    /** Encrypt a private JWK for storage under its key id. */
    const sealPrivate = (pair: GeneratedJwtKeyPair): Effect.Effect<string, JwtError> =>
      Effect.gen(function* () {
        const json = yield* encodePrivateJwk(Redacted.value(pair.privateKey));
        if (cipher !== undefined) return yield* cipher.encrypt(json);
        const token = yield* Jwe.encrypt(encoder.encode(json), yield* key, {
          kid: pair.id,
          cty: PRIVATE_KEY_CONTENT_TYPE,
        });
        return Redacted.value(token);
      }).pipe(Effect.mapError(encryptionFailed), Effect.provideContext(context));

    /** The stored private key as text: a private JWK's JSON, or a PEM. */
    const openPrivate = (pair: JwtKeyPair): Effect.Effect<string, JwtError> =>
      Effect.gen(function* () {
        if (cipher === undefined && isCompactJwe(pair.privateKey)) {
          const opened = yield* Jwe.decrypt(pair.privateKey, yield* key);
          // The protected header is authenticated: a JWE moved to another key id is refused.
          if (opened.protectedHeader.kid !== pair.id) {
            return yield* new JwtError({ message: "The private key belongs to another key id" });
          }
          return decoder.decode(opened.plaintext);
        }
        return yield* legacy.open(pair.privateKey, pair.id);
      }).pipe(Effect.mapError(decryptionFailed), Effect.provideContext(context));

    /** The signing key of a stored pair, from its JWK or, for older records, its PEM. */
    const importSigningKey = (pair: JwtKeyPair): Effect.Effect<Jwk.PrivateKey, JwtError> =>
      Effect.gen(function* () {
        const text = yield* openPrivate(pair);
        if (text.trimStart().startsWith("{")) {
          const jwk = yield* decodePrivateJwk(text);
          return yield* Jwk.importPrivate(Redacted.make({ ...jwk, kid: pair.id }), pair.algorithm);
        }
        return yield* Jwk.importPkcs8(Redacted.make(text), pair.algorithm, { kid: pair.id });
      }).pipe(
        Effect.mapError((cause) => (cause instanceof JwtError ? cause : decryptionFailed(cause))),
      );

    // Imported signing keys by key id: a key is opened once per service.
    const signingKeys = MutableHashMap.empty<string, Jwk.PrivateKey>();
    const signingKeyOf = (pair: JwtKeyPair): Effect.Effect<Jwk.PrivateKey, JwtError> =>
      Option.match(MutableHashMap.get(signingKeys, pair.id), {
        onSome: Effect.succeed,
        onNone: () =>
          Effect.tap(importSigningKey(pair), (imported) =>
            Effect.sync(() => MutableHashMap.set(signingKeys, pair.id, imported)),
          ),
      });

    // Ref holding an in-progress key-creation Deferred; null when idle.
    // Prevents duplicate active keys when concurrent fibers both call sign()
    // before any key exists (both see getActive() → null).
    type PendingDeferred = Deferred.Deferred<JwtKeyPair, JwtError | Errors.AuthError>;
    const pendingCreate = yield* Ref.make<PendingDeferred | null>(null);

    /**
     * Fetch the active key pair, lazily generating and persisting one when the
     * store is empty. Concurrent first-call fibers are serialized through a
     * Deferred so only one key is generated regardless of concurrency.
     */
    const getOrCreateActiveKey = Effect.fn("JwtService.getOrCreateActiveKey")(
      function* (): Effect.fn.Return<JwtKeyPair, JwtError | Errors.AuthError> {
        const active = yield* store.getActive();
        if (active) return active;

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
          const generated = yield* generateKeyPair(algorithm).pipe(Effect.provideContext(context));
          return yield* store.create({
            id: generated.id,
            algorithm: generated.algorithm,
            publicKey: generated.publicKey,
            privateKey: yield* sealPrivate(generated),
            createdAt: generated.createdAt,
          });
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

    const lifetime = (now: number) => ({
      iat: Math.floor(now / 1000),
      exp: Math.floor((now + expiresIn) / 1000),
    });

    /** Sign `payload`, which expires at `exp` (seconds), under the active key with header type `typ`. */
    const signToken = Effect.fn(Obs.spanNames.tokenSign)(function* (
      typ: string,
      payload: Types.JsonObject,
      exp: number,
    ) {
      const pair = yield* getOrCreateActiveKey();
      const signingKey = yield* signingKeyOf(pair);
      const token = yield* JoseJwt.sign(Claims, payload, signingKey, {
        kid: pair.id,
        typ,
      }).pipe(
        Effect.mapError((cause) => new JwtError({ message: "Failed to sign token", cause })),
        Effect.provideContext(context),
      );
      return { token: Redacted.value(token), expiresAt: exp * 1000 } satisfies JwtSignResult;
    });

    return {
      sign: Effect.fn("JwtService.sign")((user: Types.User, extraClaims?: Types.JsonObject) =>
        Effect.gen(function* () {
          const times = lifetime(yield* Clock.currentTimeMillis);
          return yield* signToken(
            ACCESS_TOKEN_TYPE,
            {
              iss: config.issuer,
              ...(config.audience !== undefined && { aud: config.audience }),
              sub: getSubject(user),
              ...times,
              ...config.definePayload?.(user),
              ...extraClaims,
            },
            times.exp,
          );
        }),
      ),

      signIdToken: Effect.fn("JwtService.signIdToken")((claims: IdTokenClaims) =>
        Effect.gen(function* () {
          const times = lifetime(yield* Clock.currentTimeMillis);
          return yield* signToken("JWT", { ...claims, ...times }, times.exp);
        }),
      ),

      verify: Effect.fn("JwtService.verify")((token: string) =>
        Effect.gen(function* () {
          const keySet = yield* JoseJwks.makeLocal(keySetOf(yield* store.list()));
          const verified = yield* JoseJwt.verifyWithKeySet(Claims, token, {
            typ: ACCESS_TOKEN_TYPE,
            algorithms: ["ES256", "EdDSA"],
            issuer: config.issuer,
            ...(config.audience !== undefined && { audience: config.audience }),
            clockTolerance: Duration.millis(leewayMs),
            requiredClaims: ["exp"],
          }).pipe(
            Effect.mapError(toJwtError),
            Effect.provideService(JoseJwks.Jwks, keySet),
            Effect.provideContext(context),
          );
          return verified.claims;
        }).pipe(
          Effect.withSpan(Obs.spanNames.tokenVerify, { attributes: { type: "jwt" } }),
          Effect.tap(() => Obs.recordTokenVerification("jwt", "success")),
          Effect.tapError(() => Obs.recordTokenVerification("jwt", "failure")),
        ),
      ),

      getJwks: Effect.fn("JwtService.getJwks")(function* () {
        return keySetOf(yield* store.list());
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
  /** The algorithms a token may be signed with (default: `RS256`, `ES256` and `EdDSA`). */
  readonly algorithms?: ReadonlyArray<Jwk.AsymmetricAlgorithm>;
  /**
   * The `typ` header a token must carry (default: {@link ACCESS_TOKEN_TYPE}).
   * Media types compare case-insensitively and without the `application/`
   * prefix, so an `id_token` (`typ: "JWT"`) is refused by default.
   */
  readonly tokenType?: string | undefined;
}

/**
 * A stand-alone JWT verifier backed by a remote JWKS document.
 */
export class RemoteJwksVerifier extends Context.Service<
  RemoteJwksVerifier,
  {
    /**
     * Verify a compact JWS against the remote JWKS. The key set is fetched on
     * first use and cached for `cacheTtlMs`; a `kid` the cached set lacks
     * refetches it (at most once per cooldown) to follow a key rotation.
     */
    readonly verify: (token: string) => Effect.Effect<Types.JsonObject, JwtError>;
  }
>()("@effect-auth/RemoteJwksVerifier") {
  /** The verifier over the platform `fetch`. */
  static readonly layer = (config: RemoteJwksConfig): Layer.Layer<RemoteJwksVerifier, JwtError> =>
    RemoteJwksVerifier.layerHttpClient(config).pipe(Layer.provide(FetchHttpClient.layer));

  /** The verifier over the `HttpClient` in context, for a custom transport or a test. */
  static readonly layerHttpClient = (
    config: RemoteJwksConfig,
  ): Layer.Layer<RemoteJwksVerifier, JwtError, HttpClient.HttpClient> =>
    Layer.effect(RemoteJwksVerifier, remoteJwksVerifier(config)).pipe(
      Layer.provide(PlatformCrypto.layer),
    );
}

/**
 * Create a {@link RemoteJwksVerifier} over `effect/jose`'s remote key set:
 * the JWKS at `config.jwksUri`, fetched through the `HttpClient`, cached for
 * `cacheTtlMs`, with concurrent fetches shared.
 */
export const remoteJwksVerifier = (
  config: RemoteJwksConfig,
): Effect.Effect<
  typeof RemoteJwksVerifier.Service,
  JwtError,
  HttpClient.HttpClient | Scope.Scope | Signature.Signature
> =>
  Effect.gen(function* () {
    const client = yield* HttpClient.HttpClient;
    const keySet = yield* JoseJwks.makeRemote({
      url: config.jwksUri,
      timeToLive: Duration.millis(config.cacheTtlMs ?? 5 * 60 * 1000),
    }).pipe(
      Effect.mapError(toJwtError),
      Effect.provideService(HttpClient.HttpClient, OutboundHttp.withoutRedirects(client)),
    );
    const signature = yield* Signature.Signature;
    const options: JoseJwt.VerifyWithKeySetOptions = {
      typ: config.tokenType ?? ACCESS_TOKEN_TYPE,
      algorithms: config.algorithms ?? ["RS256", "ES256", "EdDSA"],
      issuer: config.issuer,
      ...(config.audience !== undefined && { audience: config.audience }),
      clockTolerance: Duration.millis(config.clockSkewLeeway ?? 0),
      requiredClaims: ["exp"],
    };
    return {
      verify: (token) =>
        JoseJwt.verifyWithKeySet(Claims, token, options).pipe(
          Effect.map((verified) => verified.claims),
          Effect.mapError(toJwtError),
          Effect.provideService(JoseJwks.Jwks, JoseJwks.Jwks.of(keySet)),
          Effect.provideService(Signature.Signature, signature),
        ),
    };
  });
