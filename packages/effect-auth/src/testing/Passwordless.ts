/**
 * Test helpers shared by the passwordless `send` suites (`MagicLink.test.ts`,
 * `PhoneOtp.test.ts`, `email/EmailOtp.test.ts`).
 *
 * Never published (`tsconfig.json` excludes `src/testing/`).
 */
import { Crypto } from "effect";
import * as PlatformCrypto from "../PlatformCrypto.ts";

/** A `send` outcome as a caller sees it, apart from the time-dependent `retryAfter`. */
export const observable = (
  result:
    | { readonly _tag: "Success" }
    | {
        readonly _tag: "Failure";
        readonly failure: { readonly _tag: string; readonly message: string };
      },
) =>
  result._tag === "Success"
    ? { _tag: "Success" }
    : { _tag: "Failure", error: result.failure._tag, message: result.failure.message };

/**
 * A deterministic `Crypto` whose every random byte is 0. Every random integer
 * it derives is the range's lower bound, so the only OTP it can produce is all
 * zeros. Digests are the platform's.
 */
export const zeroCrypto: Crypto.Crypto = Crypto.make({
  randomBytes: (size) => new Uint8Array(size),
  digest: (algorithm, data) => PlatformCrypto.instance.digest(algorithm, data),
});
