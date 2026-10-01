import { describe, expect, it } from "vite-plus/test";
import { Cause, Config, ConfigProvider, Effect, type Exit, Redacted } from "effect";
import { jwtServiceConfig } from "./Jwt.ts";
import { trustedDeviceConfig } from "./TrustedDevice.ts";
import { multiFactorConfig } from "./multifactor/MultiFactor.ts";
import { oauthServiceOptionsConfig } from "./oauth/OAuth.ts";

/**
 * How the env-backed `Config`s treat an EMPTY variable (`NAME=`) on Effect
 * rc.118, where the stock providers read it as absent.
 *
 * For the three optional encryption secrets that would silently turn
 * encryption off, so a variable that is PRESENT BUT EMPTY is a configuration
 * error (owner decision on #252), while an UNSET one stays an opt-out. The
 * required values (`JWT_ISSUER`, `TRUSTED_DEVICE_SECRET`) fail as missing and
 * `TRUSTED_DEVICE_MAX_AGE_MS` falls back to its default.
 */

const resolve = <A, E>(config: Config.Config<A>, env: Record<string, string>) =>
  Effect.runPromiseExit(
    config.pipe(
      Effect.provide(ConfigProvider.layer(ConfigProvider.fromEnv({ env }))),
    ) as Effect.Effect<A, E>,
  );

describe("empty environment variables", () => {
  const failureMessage = (exit: Exit.Exit<unknown, unknown>) =>
    exit._tag === "Failure" ? String(Cause.squash(exit.cause)) : "";

  const jwtEnv = { JWT_ISSUER: "https://issuer.test" };
  const mfEnv = { TWO_FACTOR_ISSUER: "Acme" };

  it.each([
    ["JWT_ENCRYPT_PRIVATE_KEY_SECRET", jwtServiceConfig, jwtEnv],
    ["OAUTH_ENCRYPT_TOKENS_SECRET", oauthServiceOptionsConfig, {}],
    ["TWO_FACTOR_ENCRYPT_SECRET", multiFactorConfig, mfEnv],
  ] as const)("%s='' is a configuration error naming the variable", async (name, config, base) => {
    const exit = await resolve(config as Config.Config<unknown>, { ...base, [name]: "" });
    expect(exit._tag).toBe("Failure");
    expect(failureMessage(exit)).toContain(name);
    expect(failureMessage(exit)).toContain("set but empty");
  });

  it("present-but-empty is also an error under a map provider", async () => {
    const exit = await Effect.runPromiseExit(
      multiFactorConfig.pipe(
        Effect.provide(
          ConfigProvider.layer(
            ConfigProvider.fromUnknown({ ...mfEnv, TWO_FACTOR_ENCRYPT_SECRET: "" }),
          ),
        ),
      ),
    );
    expect(exit._tag).toBe("Failure");
    expect(failureMessage(exit)).toContain("TWO_FACTOR_ENCRYPT_SECRET");
  });

  it("an UNSET encryption secret leaves encryption off", async () => {
    const jwt = await resolve(jwtServiceConfig, jwtEnv);
    const oauth = await resolve(oauthServiceOptionsConfig, {});
    const mf = await resolve(multiFactorConfig, mfEnv);
    for (const exit of [jwt, oauth, mf]) expect(exit._tag).toBe("Success");
    if (jwt._tag === "Success") expect(jwt.value.encryptPrivateKey).toBeUndefined();
    if (oauth._tag === "Success") expect(oauth.value.encryptTokens).toBeUndefined();
    if (mf._tag === "Success") expect(mf.value.encryptSecret).toBeUndefined();
  });

  it("a non-empty secret enables encryption", async () => {
    const jwt = await resolve(jwtServiceConfig, { ...jwtEnv, JWT_ENCRYPT_PRIVATE_KEY_SECRET: "j" });
    const oauth = await resolve(oauthServiceOptionsConfig, { OAUTH_ENCRYPT_TOKENS_SECRET: "o" });
    const mf = await resolve(multiFactorConfig, { ...mfEnv, TWO_FACTOR_ENCRYPT_SECRET: "s3cret" });
    expect(jwt._tag).toBe("Success");
    expect(oauth._tag).toBe("Success");
    expect(mf._tag).toBe("Success");
    if (jwt._tag === "Success")
      expect(Redacted.value(jwt.value.encryptPrivateKey!.secret)).toBe("j");
    if (oauth._tag === "Success")
      expect(Redacted.value(oauth.value.encryptTokens!.secret)).toBe("o");
    if (mf._tag === "Success")
      expect(Redacted.value(mf.value.encryptSecret!.secret)).toBe("s3cret");
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
