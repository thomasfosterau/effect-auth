import { describe, expect, it } from "vite-plus/test";
import { Config, ConfigProvider, Effect, Redacted } from "effect";
import { jwtServiceConfig } from "./Jwt.ts";
import { trustedDeviceConfig } from "./TrustedDevice.ts";
import { multiFactorConfig } from "./multifactor/MultiFactor.ts";
import { oauthServiceOptionsConfig } from "./oauth/OAuth.ts";

/**
 * Pins how the env-backed `Config`s treat an EMPTY variable (`NAME=`) on
 * Effect rc.118: it is read as absent, exactly like an unset one.
 *
 * That matters for the three optional encryption secrets. An operator who
 * writes `JWT_ENCRYPT_PRIVATE_KEY_SECRET=""` (or `OAUTH_ENCRYPT_TOKENS_SECRET`,
 * `TWO_FACTOR_ENCRYPT_SECRET`) gets NO error: the config resolves with the
 * option undefined and the data is stored UNENCRYPTED. These tests pin that
 * behaviour so a change in either direction is deliberate; whether an empty or
 * unset encryption secret should instead fail loudly is an open owner decision
 * (see the follow-up issue linked from effect-auth#249).
 */

const resolve = <A, E>(config: Config.Config<A>, env: Record<string, string>) =>
  Effect.runPromiseExit(
    config.pipe(
      Effect.provide(ConfigProvider.layer(ConfigProvider.fromEnv({ env }))),
    ) as Effect.Effect<A, E>,
  );

describe("empty environment variables", () => {
  it("JWT_ENCRYPT_PRIVATE_KEY_SECRET='' silently disables private-key encryption", async () => {
    const exit = await resolve(jwtServiceConfig, {
      JWT_ISSUER: "https://issuer.test",
      JWT_ENCRYPT_PRIVATE_KEY_SECRET: "",
    });
    expect(exit._tag).toBe("Success");
    if (exit._tag === "Success") expect(exit.value.encryptPrivateKey).toBeUndefined();
  });

  it("OAUTH_ENCRYPT_TOKENS_SECRET='' silently stores OAuth tokens unencrypted", async () => {
    const exit = await resolve(oauthServiceOptionsConfig, { OAUTH_ENCRYPT_TOKENS_SECRET: "" });
    expect(exit._tag).toBe("Success");
    if (exit._tag === "Success") expect(exit.value.encryptTokens).toBeUndefined();
  });

  it("TWO_FACTOR_ENCRYPT_SECRET='' silently stores TOTP secrets unencrypted", async () => {
    const exit = await resolve(multiFactorConfig, {
      TWO_FACTOR_ISSUER: "Acme",
      TWO_FACTOR_ENCRYPT_SECRET: "",
    });
    expect(exit._tag).toBe("Success");
    if (exit._tag === "Success") expect(exit.value.encryptSecret).toBeUndefined();
  });

  it("a non-empty secret still enables encryption (control)", async () => {
    const exit = await resolve(multiFactorConfig, {
      TWO_FACTOR_ISSUER: "Acme",
      TWO_FACTOR_ENCRYPT_SECRET: "s3cret",
    });
    expect(exit._tag).toBe("Success");
    if (exit._tag === "Success") {
      expect(Redacted.value(exit.value.encryptSecret!.secret)).toBe("s3cret");
    }
  });

  it("TRUSTED_DEVICE_SECRET='' is missing, so the config fails", async () => {
    const exit = await resolve(trustedDeviceConfig, { TRUSTED_DEVICE_SECRET: "" });
    expect(exit._tag).toBe("Failure");
  });

  it("JWT_ISSUER='' is missing, so the config fails", async () => {
    const exit = await resolve(jwtServiceConfig, { JWT_ISSUER: "" });
    expect(exit._tag).toBe("Failure");
  });

  it("TRUSTED_DEVICE_MAX_AGE_MS='' falls back to the 30-day default", async () => {
    const exit = await resolve(trustedDeviceConfig, {
      TRUSTED_DEVICE_SECRET: "device-secret",
      TRUSTED_DEVICE_MAX_AGE_MS: "",
    });
    expect(exit._tag).toBe("Success");
    if (exit._tag === "Success") expect(exit.value.maxAge).toBe(30 * 24 * 60 * 60 * 1000);
  });
});
