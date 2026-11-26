/**
 * The platform crypto services plus the public test root secret, as a context
 * built synchronously (HKDF through `node:crypto`) and as a layer. Internal
 * test support: not exported from `./testing`.
 */
import { createHmac, hkdfSync } from "node:crypto";
import * as Context from "effect/Context";
import * as Effect from "effect/Effect";
import * as Layer from "effect/Layer";
import * as Arr from "effect/Array";
import * as R from "effect/Record";
import * as PlatformCrypto from "../PlatformCrypto.ts";
import { RootSecret, type Purpose } from "../RootSecret.ts";
import { testRootSecret, testRootSecretLayer } from "./RootSecret.ts";

/** The services {@link testCryptoContext} holds. */
export type TestCryptoServices = PlatformCrypto.Services | RootSecret;

const purposes: ReadonlyArray<Purpose> = [
  "otp-pepper",
  "pkce-verifier",
  "totp-secret",
  "oauth-tokens",
  "jwt-private-key",
];

/** The key {@link RootSecret.layer} derives for `purpose` from {@link testRootSecret}. */
export const testKey = (purpose: Purpose): Uint8Array =>
  new Uint8Array(
    hkdfSync("sha256", testRootSecret, new Uint8Array(0), `effect-auth/${purpose}/v1`, 32),
  );

/** The peppered hash the services store for an OTP or backup code under {@link testRootSecret}. */
export const testPepper = (secret: string): string =>
  createHmac("sha256", testKey("otp-pepper")).update(secret).digest("hex");

const keys = R.fromEntries(Arr.map(purposes, (purpose) => [purpose, testKey(purpose)] as const));

/** {@link PlatformCrypto.context} with the test root secret beside it. */
export const testCryptoContext = (): Context.Context<TestCryptoServices> =>
  Context.add(
    PlatformCrypto.context(),
    RootSecret,
    RootSecret.of({ key: (purpose) => Effect.succeed(keys[purpose]) }),
  );

/** {@link PlatformCrypto.layer} with the test root secret beside it. */
export const testCryptoLayer: Layer.Layer<TestCryptoServices> = Layer.merge(
  PlatformCrypto.layer,
  testRootSecretLayer,
);
