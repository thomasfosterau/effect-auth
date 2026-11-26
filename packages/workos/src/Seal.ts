/**
 * The session cookie's seal: AES-256-GCM under a key HKDF-derived from the
 * cookie password, written `w1~<key id>~<base64url(iv ‖ tag ‖ ciphertext)>`.
 * The key id names which password sealed it, so a rotated password keeps
 * opening its cookies until it is dropped. Anything that does not open is
 * refused; there is no plaintext fallback.
 *
 * @since 0.1.0
 */
import { Data, Effect, Redacted } from "effect";
import * as Arr from "effect/Array";
import * as Option from "effect/Option";
import * as Result from "effect/Result";
import { Aead, Kdf, SecureRandom } from "effect/crypto";
import { Base64Url, Hex } from "effect/encoding";

/** The shortest cookie password accepted, in UTF-8 bytes. */
export const MIN_COOKIE_PASSWORD_BYTES = 32;

const PREFIX = "w1";
const SEPARATOR = "~";
const NONCE_LENGTH = 12;
const TAG_LENGTH = 16;
const encoder = new TextEncoder();
const decoder = new TextDecoder();
const AAD = encoder.encode("effect-auth-workos/session/v1");

/**
 * A cookie password shorter than {@link MIN_COOKIE_PASSWORD_BYTES}, found
 * when the layer is built.
 *
 * @since 0.1.0
 * @category errors
 */
export class CookiePasswordError extends Data.TaggedError("CookiePasswordError")<{
  readonly message: string;
}> {}

/**
 * Seal and open session cookie values.
 *
 * @since 0.1.0
 * @category models
 */
export interface Sealer {
  readonly seal: (plaintext: string) => Effect.Effect<string>;
  /** The plaintext, or `None` for a value that is malformed, tampered with or sealed by an unknown key. */
  readonly open: (sealed: string) => Effect.Effect<Option.Option<string>>;
}

const derive = (kdf: typeof Kdf.Kdf.Service, password: string, info: string) =>
  kdf
    .derive(Kdf.hkdfSha256, encoder.encode(password), {
      salt: new Uint8Array(0),
      length: 32,
      info: encoder.encode(info),
    })
    .pipe(Effect.orDie);

/**
 * A {@link Sealer} over `passwords`: the first seals, every one opens. Fails
 * with {@link CookiePasswordError} for a password under 32 bytes.
 *
 * @since 0.1.0
 * @category constructors
 */
export const make = (
  passwords: ReadonlyArray<Redacted.Redacted>,
): Effect.Effect<Sealer, CookiePasswordError, Aead.Aead | Kdf.Kdf | SecureRandom.SecureRandom> =>
  Effect.gen(function* () {
    if (!Arr.isReadonlyArrayNonEmpty(passwords)) {
      return yield* new CookiePasswordError({ message: "A cookie password is required" });
    }
    const kdf = yield* Kdf.Kdf;
    const aead = yield* Aead.Aead;
    const random = yield* SecureRandom.SecureRandom;
    const keys = yield* Effect.forEach(
      passwords,
      (redacted) =>
        Effect.gen(function* () {
          const password = Redacted.value<string>(redacted);
          if (encoder.encode(password).length < MIN_COOKIE_PASSWORD_BYTES) {
            return yield* new CookiePasswordError({
              message: `The WorkOS cookie password must be at least ${MIN_COOKIE_PASSWORD_BYTES} bytes`,
            });
          }
          const id = Hex.encode(
            (yield* derive(kdf, password, "effect-auth-workos/session-cookie-key-id/v1")).subarray(
              0,
              4,
            ),
          );
          const key = yield* Aead.key(
            Aead.aes256Gcm,
            yield* derive(kdf, password, "effect-auth-workos/session-cookie/v1"),
          ).pipe(Effect.orDie);
          return { id, key };
        }),
      { concurrency: 1 },
    );
    const sealing = keys[0];

    const seal = (plaintext: string) =>
      Effect.gen(function* () {
        const nonce = yield* random.randomBytes(NONCE_LENGTH);
        const sealed = yield* aead
          .encrypt(sealing.key, encoder.encode(plaintext), { nonce, aad: AAD })
          .pipe(Effect.orDie);
        const out = new Uint8Array(NONCE_LENGTH + sealed.length);
        out.set(nonce, 0);
        out.set(sealed.subarray(sealed.length - TAG_LENGTH), NONCE_LENGTH);
        out.set(sealed.subarray(0, sealed.length - TAG_LENGTH), NONCE_LENGTH + TAG_LENGTH);
        return [PREFIX, sealing.id, Base64Url.encode(out)].join(SEPARATOR);
      });

    const open = (value: string) =>
      Effect.gen(function* () {
        const [prefix, id, body, extra] = value.split(SEPARATOR);
        if (prefix !== PREFIX || body === undefined || extra !== undefined) return Option.none();
        const key = keys.find((candidate) => candidate.id === id);
        const bytes = Result.getOrUndefined(Base64Url.decode(body));
        if (key === undefined || bytes === undefined || bytes.length <= NONCE_LENGTH + TAG_LENGTH) {
          return Option.none();
        }
        const nonce = bytes.subarray(0, NONCE_LENGTH);
        const tag = bytes.subarray(NONCE_LENGTH, NONCE_LENGTH + TAG_LENGTH);
        const ciphertext = bytes.subarray(NONCE_LENGTH + TAG_LENGTH);
        const joined = new Uint8Array(ciphertext.length + TAG_LENGTH);
        joined.set(ciphertext, 0);
        joined.set(tag, ciphertext.length);
        const opened = yield* Effect.option(aead.decrypt(key.key, joined, { nonce, aad: AAD }));
        return Option.flatMap(opened, (plain) =>
          Result.getSuccess(Result.try(() => decoder.decode(plain))),
        );
      });

    return { seal, open };
  });
