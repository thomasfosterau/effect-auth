import { describe, expect, it } from "vite-plus/test";
import { ConfigProvider, Effect, Layer, Redacted } from "effect";
import { JwtKeyStore, JwtService, jwtServiceConfig } from "./Jwt.ts";
import { TrustedDeviceService, TrustedDeviceStore, trustedDeviceConfig } from "./TrustedDevice.ts";
import { multiFactorConfig } from "./multifactor/MultiFactor.ts";
import { oauthServiceOptionsConfig } from "./oauth/OAuth.ts";

/**
 * Guards the Effect floor this package publishes (`effect >=4.0.0-rc.118`).
 *
 * rc.113 renamed the `Config` constructors (`Config.string` -> `Config.String`,
 * and likewise `redacted` / `int` / `boolean`). The env-backed `Config`s are
 * built at module load, so a call to a removed name does not fail a test that
 * exercises it — it fails the *import* of the module, and with it every entry
 * point. This suite imports each published entry point and builds every
 * config-backed layer, so that class of break fails here, loudly and by name.
 */

const entryPoints = {
  ".": () => import("./index.ts"),
  "./ladder": () => import("./Ladder.ts"),
  "./email": () => import("./email/index.ts"),
  "./http": () => import("./http/index.ts"),
  "./oauth": () => import("./oauth/index.ts"),
  "./password": () => import("./password/index.ts"),
  "./plugins": () => import("./plugins/index.ts"),
  "./multifactor": () => import("./multifactor/index.ts"),
} as const;

const withEnv = (env: Record<string, string>) =>
  ConfigProvider.layer(ConfigProvider.fromEnv({ env }));

describe("Effect floor compatibility", () => {
  for (const [name, load] of Object.entries(entryPoints)) {
    it(`imports the ${name} entry point`, async () => {
      const mod = await load();
      expect(Object.keys(mod).length).toBeGreaterThan(0);
    });
  }

  it("reads the JWT config from the environment", async () => {
    const cfg = await Effect.runPromise(
      jwtServiceConfig.pipe(
        Effect.provide(
          withEnv({
            JWT_ISSUER: "https://issuer.test",
            JWT_EXPIRES_IN_MS: "60000",
            JWT_ALGORITHM: "ES256",
            JWT_ENCRYPT_PRIVATE_KEY_SECRET: "s3cret",
          }),
        ),
      ),
    );
    expect(cfg.issuer).toBe("https://issuer.test");
    expect(cfg.expiresIn).toBe(60000);
    expect(cfg.algorithm).toBe("ES256");
    expect(cfg.audience).toBeUndefined();
    expect(Redacted.value(cfg.encryptPrivateKey!.secret)).toBe("s3cret");
  });

  it("reads the trusted-device, multi-factor and OAuth configs from the environment", async () => {
    const env = withEnv({
      TRUSTED_DEVICE_SECRET: "device-secret",
      TWO_FACTOR_ISSUER: "Acme",
      OAUTH_AUTO_LINK_BY_VERIFIED_EMAIL: "false",
      OAUTH_ENCRYPT_TOKENS_SECRET: "token-secret",
    });
    const [device, mfa, oauth] = await Effect.runPromise(
      Effect.all([trustedDeviceConfig, multiFactorConfig, oauthServiceOptionsConfig]).pipe(
        Effect.provide(env),
      ),
    );
    expect(Redacted.value(device.secret)).toBe("device-secret");
    expect(device.maxAge).toBe(30 * 24 * 60 * 60 * 1000);
    expect(mfa.issuer).toBe("Acme");
    expect(mfa.encryptSecret).toBeUndefined();
    expect(oauth.autoLinkByVerifiedEmail).toBe(false);
    expect(Redacted.value(oauth.encryptTokens!.secret)).toBe("token-secret");
  });

  it("builds the env-backed JWT and trusted-device layers", async () => {
    // The stores are never touched while a layer is built, so empty stand-ins
    // are enough to prove the config wiring resolves.
    const stores = Layer.mergeAll(
      Layer.succeed(JwtKeyStore, {} as never),
      Layer.succeed(TrustedDeviceStore, {} as never),
    );
    const env = withEnv({
      JWT_ISSUER: "https://issuer.test",
      TRUSTED_DEVICE_SECRET: "device-secret",
    });
    const built = Layer.mergeAll(JwtService.layerFromEnv, TrustedDeviceService.layerFromEnv).pipe(
      Layer.provide(stores),
    );
    await Effect.runPromise(Effect.scoped(Layer.build(built)).pipe(Effect.provide(env)));
  });

  it("fails the layer with a config error, not a crash, when a required variable is missing", async () => {
    const exit = await Effect.runPromiseExit(
      Effect.scoped(Layer.build(JwtService.layerFromEnv)).pipe(
        Effect.provide(Layer.mergeAll(Layer.succeed(JwtKeyStore, {} as never), withEnv({}))),
      ),
    );
    expect(exit._tag).toBe("Failure");
  });
});
