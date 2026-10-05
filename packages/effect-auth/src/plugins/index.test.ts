import { describe, it, expect, expectTypeOf } from "vite-plus/test";
import * as Auth from "../index.ts";
import * as PluginsCluster from "./index.ts";
import * as LastLoginMethod from "./LastLoginMethod.ts";

// The `plugins` barrel's surface (#284): the last-login-method plugin's
// constructor used to be a bare `make`, so through the barrel it read as
// `Auth.Plugins.make`, a constructor for the whole cluster. Every plugin is
// now a named `<Name>Plugin`.
describe("plugins barrel", () => {
  it("does not export a bare make", () => {
    expect("make" in PluginsCluster).toBe(false);
    expect("make" in Auth.Plugins).toBe(false);
    // @ts-expect-error -- `make` is not part of the plugins barrel.
    expect(PluginsCluster.make).toBeUndefined();
  });

  it("exports exactly the named plugin constructors and the lockout store", () => {
    expect(Object.keys(PluginsCluster).sort()).toEqual([
      "AccountLockoutPlugin",
      "AccountLockoutStore",
      "AuditPlugin",
      "CaptchaPlugin",
      "IPRateLimitPlugin",
      "LastLoginMethodPlugin",
      "NormalizeEmailPlugin",
      "RateLimitPlugin",
      "memoryAccountLockoutStore",
    ]);
    expect(Object.keys(Auth.Plugins).sort()).toEqual(Object.keys(PluginsCluster).sort());
  });

  it("re-exports LastLoginMethodPlugin from its module", () => {
    expect(PluginsCluster.LastLoginMethodPlugin).toBe(LastLoginMethod.LastLoginMethodPlugin);
    expect(Auth.Plugins.LastLoginMethodPlugin).toBe(LastLoginMethod.LastLoginMethodPlugin);
    // Types vanish at runtime, so the type gate (`tsc -p tsconfig.test.json`)
    // pins the re-exported constructor's type.
    expectTypeOf(PluginsCluster.LastLoginMethodPlugin).toEqualTypeOf(
      LastLoginMethod.LastLoginMethodPlugin,
    );
    expectTypeOf(Auth.Plugins.LastLoginMethodPlugin).toEqualTypeOf(
      LastLoginMethod.LastLoginMethodPlugin,
    );
  });
});
