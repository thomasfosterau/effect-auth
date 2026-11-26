/**
 * Register one of the core's published conformance suites
 * (`@thomasfosterau/effect-auth/testing`) as a `describe` block, one test per
 * case. `run` runs a case against the store under test.
 *
 * Never published (`tsconfig.json` excludes `src/testing/`).
 */

import { describe, expect, it } from "vite-plus/test";
import type * as Testing from "@thomasfosterau/effect-auth/testing";

export const conformance = <E, R>(
  label: string,
  suite: Testing.ConformanceSuite<E, R>,
  run: (effect: Testing.ConformanceSuite<E, R>["cases"][number]["run"]) => Promise<void>,
): void => {
  describe(`${label}: ${suite.contract} conformance`, () => {
    suite.cases.forEach((testCase) => {
      it(testCase.name, () => expect(run(testCase.run)).resolves.toBeUndefined());
    });
  });
};
