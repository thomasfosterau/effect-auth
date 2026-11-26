/**
 * Validation / enrichment plugin (transform hooks).
 *
 * Normalises the email (see `normalizeEmail`) before sign-up and sign-in.
 * Demonstrates a zero-dependency transform plugin that *modifies* the value
 * flowing through the hook - downstream hooks and the operation itself see the
 * normalised input.
 *
 * @module plugins/normalize-email
 */
import * as Effect from "effect/Effect";
import type { SignInInput, SignUpInput } from "../email/EmailPassword.ts";
import { makePlugin } from "../Hooks.ts";
import { normalizeEmail } from "../utils.ts";

/**
 * Normalises the email with `normalizeEmail` on `beforeSignUp` and
 * `beforeSignIn`.
 *
 * `Layer<Hooks, never, Hooks>` - no dependencies.
 */
export const NormalizeEmailPlugin = makePlugin({
  beforeSignUp: (input: SignUpInput) =>
    Effect.succeed({ ...input, email: normalizeEmail(input.email) }),
  beforeSignIn: (input: SignInInput) =>
    Effect.succeed({ ...input, email: normalizeEmail(input.email) }),
});
