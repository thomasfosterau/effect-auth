/**
 * A fixed root secret for tests and fixtures. Never use it outside a test:
 * every key it derives is public.
 */
import { Layer } from "effect";
import { RootSecret } from "../RootSecret.ts";

/** The public test root secret, 64 hex characters. */
export const testRootSecret = "0123456789abcdef".repeat(4);

/** {@link RootSecret} over {@link testRootSecret}. */
export const testRootSecretLayer: Layer.Layer<RootSecret> = Layer.orDie(
  RootSecret.layer(testRootSecret),
);
