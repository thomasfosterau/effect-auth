import { describe, expect, it } from "vite-plus/test";
import { Cause, Config, Schema, ConfigProvider, Effect, type Exit, Redacted } from "effect";
import { optionalSecret } from "./OptionalSecretConfig.ts";
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

  describe("optionalSecret probe", () => {
    const N = "TWO_FACTOR_ENCRYPT_SECRET";
    const run = <A>(config: Config.Config<A>, provider: ConfigProvider.ConfigProvider) =>
      Effect.runPromiseExit(config.parse(provider));
    const env = (e: Record<string, string>, opts?: { preserveEmptyStrings?: boolean }) =>
      ConfigProvider.fromEnv({ env: e, ...opts });
    const value = (exit: Exit.Exit<Redacted.Redacted | undefined, unknown>) =>
      exit._tag === "Success" ? (exit.value ? Redacted.value(exit.value) : undefined) : "FAILED";

    it.each([
      [{ [`${N}_FILE`]: "/run/secrets/x" }],
      [{ [`${N}_FILE`]: "" }],
      [{ [`${N}_V2_X`]: "1" }],
    ])("sibling variables sharing the prefix do not count as set-but-empty: %j", async (e) => {
      expect(value(await run(optionalSecret(N), env(e)))).toBeUndefined();
      const mf = await resolve(multiFactorConfig, { ...mfEnv, ...e });
      expect(mf._tag).toBe("Success");
    });

    it("honours .parse(provider)", async () => {
      expect(value(await run(optionalSecret(N), env({ [N]: "x" })))).toBe("x");
      expect((await run(optionalSecret(N), env({ [N]: "" })))._tag).toBe("Failure");
      expect(value(await run(optionalSecret(N), env({})))).toBeUndefined();
    });

    it("honours Config.nested for the exported config and the helper", async () => {
      const nested = optionalSecret(N).pipe(Config.nested("APP"));
      expect(value(await run(nested, env({ [`APP_${N}`]: "x" })))).toBe("x");
      expect(value(await run(nested, env({ [N]: "x" })))).toBeUndefined();
      expect(value(await run(nested, env({})))).toBeUndefined();
      const empty = await run(nested, env({ [`APP_${N}`]: "" }));
      expect(empty._tag).toBe("Failure");
      expect(failureMessage(empty)).toContain(N);

      const mf = multiFactorConfig.pipe(Config.nested("APP"));
      const ok = await run(mf, env({ APP_TWO_FACTOR_ISSUER: "Acme", [`APP_${N}`]: "s3cret" }));
      expect(ok._tag === "Success" && Redacted.value(ok.value.encryptSecret!.secret)).toBe(
        "s3cret",
      );
      const none = await run(mf, env({ APP_TWO_FACTOR_ISSUER: "Acme" }));
      expect(none._tag === "Success" && none.value.encryptSecret).toBeUndefined();
      const bad = await run(mf, env({ APP_TWO_FACTOR_ISSUER: "Acme", [`APP_${N}`]: "" }));
      expect(bad._tag).toBe("Failure");
    });

    it("guards the assumption: Config.schema runs the Record key filter for every key, empty leaves included", async () => {
      const seen = new Set<string>();
      const key = Schema.String.check(
        Schema.makeFilter((k: string) => {
          seen.add(k);
          return true;
        }),
      );
      const probe = Config.schema(Schema.Record(key, Schema.UndefinedOr(Schema.String)), ["P"]);
      await Effect.runPromise(probe.parse(env({ P_A: "1", P_B: "", P_C_D: "2" })));
      expect([...seen].sort()).toEqual(["A", "B", "C"]);
    });

    it("preserveEmptyStrings: an empty value is a failure", async () => {
      const exit = await run(optionalSecret(N), env({ [N]: "" }, { preserveEmptyStrings: true }));
      expect(exit._tag).toBe("Failure");
      expect(failureMessage(exit)).toContain(N);
    });
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
