/**
 * Compact JWS signatures through `effect/jose`, for the flows that keep their
 * own key selection and claim checks (OIDC `id_token`s, Cloudflare Access
 * tokens, the Apple client secret). Internal.
 */
import { Effect, Redacted } from "effect";
import * as Schema from "effect/Schema";
import type { Signature } from "effect/crypto";
import { JoseError, Jwk, Jws } from "effect/jose";
import * as PlatformCrypto from "./PlatformCrypto.ts";
import type * as Types from "./Types.ts";

const decodePublicJwk = Schema.decodeUnknownEffect(Jwk.PublicJwk);

/**
 * Whether `token`'s signature verifies under the public JWK `jwk` for
 * `algorithm`. A signature that does not verify, or a header naming another
 * algorithm, is `false`; a JWK that is not a usable public key, or a token
 * that is not a compact JWS, fails with the `JoseError` or `SchemaError`.
 */
export const verifiesWithJwk = (
  token: string,
  jwk: Types.JsonObject,
  algorithm: Jwk.AsymmetricAlgorithm,
): Effect.Effect<boolean, JoseError.JoseError | Schema.SchemaError> =>
  Effect.gen(function* () {
    const key = yield* Jwk.importPublic(yield* decodePublicJwk(jwk), algorithm);
    return yield* Jws.verify(token, key).pipe(
      Effect.as(true),
      Effect.catchIf(
        (error) =>
          error.reason._tag === "SignatureVerificationFailed" ||
          error.reason._tag === "AlgorithmNotAllowed",
        () => Effect.succeed(false),
      ),
    );
  }).pipe(PlatformCrypto.provide);

/** Sign `payload` (the JWS payload bytes) with a PKCS#8 PEM private key. */
export const signWithPkcs8 = (
  payload: Uint8Array,
  privateKeyPem: Redacted.Redacted,
  algorithm: Jwk.AsymmetricAlgorithm,
  header: Jws.Header,
): Effect.Effect<string, JoseError.JoseError, Signature.Signature> =>
  Effect.gen(function* () {
    const key = yield* Jwk.importPkcs8(privateKeyPem, algorithm);
    return Redacted.value(yield* Jws.sign(payload, key, header));
  });
