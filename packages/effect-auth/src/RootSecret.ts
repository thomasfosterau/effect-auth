/**
 * The one server-side secret every keyed primitive derives from: the OTP and
 * backup-code pepper, the PKCE verifier key, and the encryption keys for TOTP
 * secrets, OAuth provider tokens and JWT private keys, each through HKDF with
 * its own purpose string, so no two purposes share a key.
 *
 * @module root-secret
 */
import * as Config from "effect/Config";
import * as Context from "effect/Context";
import * as Schema from "effect/Schema";
import * as Effect from "effect/Effect";
import * as Layer from "effect/Layer";
import * as Redacted from "effect/Redacted";
import * as R from "effect/Record";
import { Aead, Digest, Kdf, Mac, SecureRandom } from "effect/crypto";
import { Base64Url, Hex } from "effect/encoding";
import * as Cipher from "./Cipher.ts";
import * as PlatformCrypto from "./PlatformCrypto.ts";

/** The purposes a key is derived for. */
export type Purpose =
  | "otp-pepper"
  | "pkce-verifier"
  | "totp-secret"
  | "oauth-tokens"
  | "jwt-private-key";

const PURPOSES: ReadonlyArray<Purpose> = [
  "otp-pepper",
  "pkce-verifier",
  "totp-secret",
  "oauth-tokens",
  "jwt-private-key",
];

/** The shortest root secret accepted, in UTF-8 bytes: 256 bits of hex or base64 text. */
export const MIN_ROOT_SECRET_BYTES = 32;

/** The environment variable {@link RootSecret.layerConfig} reads. */
export const ROOT_SECRET_ENV = "AUTH_SECRET";

/** The root secret is missing or shorter than {@link MIN_ROOT_SECRET_BYTES}. */
export class RootSecretError extends Schema.TaggedError<RootSecretError>()("RootSecretError", {
  message: Schema.String,
}) {}

const encoder = new TextEncoder();

/** The HKDF info string for `purpose`; the version names the derivation, not the data. */
const info = (purpose: Purpose): Uint8Array => encoder.encode(`effect-auth/${purpose}/v1`);

/**
 * Derive the 32-byte key for `purpose` from `secret` (HKDF-SHA256, empty
 * salt). Also derives the keys for the per-feature override secrets.
 */
export const deriveKey = (
  secret: string,
  purpose: Purpose,
): Effect.Effect<Uint8Array, never, Kdf.Kdf> =>
  Kdf.Kdf.use((kdf) =>
    kdf.derive(Kdf.hkdfSha256, encoder.encode(secret), {
      salt: new Uint8Array(0),
      length: 32,
      info: info(purpose),
    }),
  ).pipe(Effect.orDie);

/** The server's root secret, as the keys derived from it. */
export class RootSecret extends Context.Service<
  RootSecret,
  {
    /** The 32-byte key for `purpose`, derived on first use and kept. */
    readonly key: (purpose: Purpose) => Effect.Effect<Uint8Array>;
  }
>()("@effect-auth/RootSecret") {
  /**
   * The root secret from a value. Fails with {@link RootSecretError} when it
   * is shorter than {@link MIN_ROOT_SECRET_BYTES} UTF-8 bytes. It builds
   * synchronously: each key is derived on its first use.
   */
  static readonly layer = (
    secret: Redacted.Redacted | string,
  ): Layer.Layer<RootSecret, RootSecretError> =>
    Layer.effect(RootSecret, make(Redacted.isRedacted(secret) ? Redacted.value(secret) : secret));

  /** The root secret from the `AUTH_SECRET` config value, which is required. */
  static readonly layerConfig: Layer.Layer<RootSecret, RootSecretError | Config.ConfigError> =
    Layer.unwrap(
      Effect.gen(function* () {
        return RootSecret.layer(yield* Config.Redacted(ROOT_SECRET_ENV));
      }),
    );
}

const make = (secret: string): Effect.Effect<typeof RootSecret.Service, RootSecretError> =>
  Effect.gen(function* () {
    if (encoder.encode(secret).length < MIN_ROOT_SECRET_BYTES) {
      return yield* new RootSecretError({
        message: `${ROOT_SECRET_ENV} must be at least ${MIN_ROOT_SECRET_BYTES} bytes; generate one with \`openssl rand -hex 32\``,
      });
    }
    const keys = R.fromEntries(
      yield* Effect.forEach(
        PURPOSES,
        (purpose) =>
          Effect.map(
            Effect.cached(PlatformCrypto.provide(deriveKey(secret, purpose))),
            (key) => [purpose, key] as const,
          ),
        { concurrency: "unbounded" },
      ),
    );
    return RootSecret.of({ key: (purpose) => keys[purpose] });
  });

/** HMAC-SHA256 under the key for `purpose`, imported on first use. */
const macWith = (
  purpose: Purpose,
): Effect.Effect<(data: Uint8Array) => Effect.Effect<Uint8Array>, never, RootSecret | Mac.Mac> =>
  Effect.gen(function* () {
    const mac = yield* Mac.Mac;
    const rootSecret = yield* RootSecret;
    const key = yield* Effect.cached(
      Effect.orDie(
        Effect.flatMap(rootSecret.key(purpose), (bytes) => Mac.key(Mac.hmacSha256, bytes)),
      ),
    );
    return (data) => Effect.orDie(Effect.flatMap(key, (k) => mac.sign(k, data)));
  });

/**
 * The keyed digest of a short secret (an OTP, a backup code): hex
 * HMAC-SHA256 under the root secret's `otp-pepper` key, so a database read
 * alone cannot brute-force it.
 */
export const pepperHasher: Effect.Effect<
  (secret: string) => Effect.Effect<string>,
  never,
  RootSecret | Mac.Mac
> = Effect.map(
  macWith("otp-pepper"),
  (sign) => (secret: string) => Effect.map(sign(encoder.encode(secret)), Hex.encode),
);

/**
 * The PKCE `code_verifier` for an OAuth `state`, derived rather than stored:
 * base64url HMAC-SHA256 of the raw state under the `pkce-verifier` key (43
 * characters, within RFC 7636's 43 to 128).
 */
export const pkceVerifier: Effect.Effect<
  (state: string) => Effect.Effect<string>,
  never,
  RootSecret | Mac.Mac
> = Effect.map(
  macWith("pkce-verifier"),
  (sign) => (state: string) => Effect.map(sign(encoder.encode(state)), Base64Url.encode),
);

/**
 * How a feature encrypts what it stores: the root secret's key for its
 * purpose by default, an override secret (whose key is derived the same way,
 * and whose earlier ciphertexts still open), or a custom cipher.
 */
export type Encryption =
  | { readonly secret: Redacted.Redacted }
  | { readonly cipher: Cipher.TokenCipher };

/** The {@link Cipher.SecretSealer} for `purpose` under `encryption`. */
export const sealerFor = (
  purpose: Purpose,
  encryption?: Encryption,
): Effect.Effect<
  Cipher.SecretSealer,
  never,
  RootSecret | Aead.Aead | Digest.Digest | Kdf.Kdf | SecureRandom.SecureRandom
> =>
  Effect.gen(function* () {
    if (encryption !== undefined && "cipher" in encryption) {
      return Cipher.cipherSealer(encryption.cipher);
    }
    if (encryption === undefined) {
      return yield* Cipher.secretSealer({ key: (yield* RootSecret).key(purpose), purpose });
    }
    const secret = Redacted.value(encryption.secret);
    return yield* Cipher.secretSealer({
      key: deriveKey(secret, purpose),
      purpose,
      legacy: Cipher.aes256GcmCipher(secret),
    });
  });
