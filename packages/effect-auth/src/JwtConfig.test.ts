import { describe, expect, it } from "vite-plus/test";
import { ConfigProvider, Effect, Exit } from "effect";
import { jwtServiceConfig } from "./Jwt.ts";

const resolve = (env: Record<string, string>) =>
  Effect.runPromiseExit(
    jwtServiceConfig.pipe(Effect.provide(ConfigProvider.layer(ConfigProvider.fromEnv({ env })))),
  );

const issuer = { JWT_ISSUER: "https://issuer.test" };

describe("jwtServiceConfig JWT_ALGORITHM (#443)", () => {
  it("reads a supported algorithm", async () => {
    const exit = await resolve({ ...issuer, JWT_ALGORITHM: "EdDSA" });
    expect(Exit.isSuccess(exit) && exit.value.algorithm).toBe("EdDSA");
  });

  it("leaves the algorithm to the default when unset", async () => {
    const exit = await resolve(issuer);
    expect(Exit.isSuccess(exit)).toBe(true);
    expect(Exit.isSuccess(exit) && exit.value.algorithm).toBeUndefined();
  });

  it("fails on an algorithm it does not support, rather than ignoring it", async () => {
    const exit = await resolve({ ...issuer, JWT_ALGORITHM: "HS256" });
    expect(Exit.isFailure(exit)).toBe(true);
  });
});
