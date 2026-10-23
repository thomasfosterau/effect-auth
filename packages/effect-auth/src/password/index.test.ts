import { describe, it, expect, expectTypeOf } from "vite-plus/test";
import { Array as Arr, Order } from "effect";
import * as Auth from "../index.ts";
import * as PasswordCluster from "./index.ts";
import * as PasswordReset from "./PasswordReset.ts";

// The `password` barrel's surface (#259): `PasswordReset.make` builds a
// `PasswordResetService`, so re-exporting it would make `Auth.Password.make`
// read as the cluster's hasher constructor.
describe("password barrel", () => {
  it("does not export PasswordReset's make as Password.make", () => {
    expect("make" in PasswordCluster).toBe(false);
    expect("make" in Auth.Password).toBe(false);
    // @ts-expect-error -- `make` is not part of the password barrel.
    expect(PasswordCluster.make).toBeUndefined();
  });

  it("re-exports every other PasswordReset value", () => {
    const expected = Arr.sort(
      Object.keys(PasswordReset).filter((name) => name !== "make"),
      Order.String,
    );
    expect(expected).toEqual([
      "PasswordResetService",
      "PasswordResetStore",
      "PasswordResetUserStore",
    ]);
    Arr.forEach(expected, (name) => {
      expect(PasswordCluster).toHaveProperty(
        name,
        PasswordReset[name as keyof typeof PasswordReset],
      );
    });
    expect(Auth.Password.PasswordResetService).toBe(PasswordReset.PasswordResetService);
  });

  it("re-exports every PasswordReset type", () => {
    // Types vanish at runtime, so the type gate (`tsc -p tsconfig.test.json`)
    // is what pins these: dropping one from the barrel fails to compile here.
    expectTypeOf<PasswordCluster.PasswordResetToken>().toEqualTypeOf<PasswordReset.PasswordResetToken>();
    expectTypeOf<PasswordCluster.PasswordResetConfig>().toEqualTypeOf<PasswordReset.PasswordResetConfig>();
    expectTypeOf<PasswordCluster.PasswordResetResult>().toEqualTypeOf<PasswordReset.PasswordResetResult>();
  });
});
