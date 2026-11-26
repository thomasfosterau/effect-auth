import { describe, expect, it } from "vite-plus/test";
import { DateTime, Effect, Layer } from "effect";
import { enrolledGate, testChallenge } from "../testing/SecondFactor.ts";
import type { User } from "../Types.ts";
import { exemptFromSecondFactor, secondFactorChallenge } from "./EmailPassword.ts";

const now = DateTime.toDateUtc(DateTime.nowUnsafe());
const enrolled: User = { id: "enrolled", createdAt: now, updatedAt: now, attributes: {} };
const other: User = { id: "other", createdAt: now, updatedAt: now, attributes: {} };

const run = <A, E>(effect: Effect.Effect<A, E>, layer: Layer.Layer<never> = Layer.empty) =>
  Effect.runPromise(effect.pipe(Effect.provide(layer)));

describe("secondFactorChallenge", () => {
  it("lets every method through when no gate is provided", async () => {
    expect(await run(secondFactorChallenge(enrolled, "magic-link"))).toBeUndefined();
  });

  it("challenges every method by default, and only the users the gate requires it of", async () => {
    const challenged: Array<string> = [];
    const gate = enrolledGate(challenged, [enrolled.id]);
    const answers = await run(
      Effect.all(
        [
          secondFactorChallenge(enrolled, "email-password"),
          secondFactorChallenge(enrolled, "magic-link"),
          secondFactorChallenge(enrolled, "sso"),
          secondFactorChallenge(other, "magic-link"),
        ],
        { concurrency: 1 },
      ).pipe(Effect.provide(gate)),
    );
    expect(answers).toEqual([testChallenge, testChallenge, testChallenge, undefined]);
    expect(challenged).toEqual([enrolled.id, enrolled.id, enrolled.id]);
  });

  it("exempts only the listed methods", async () => {
    const challenged: Array<string> = [];
    const answers = await run(
      Effect.all(
        [
          secondFactorChallenge(enrolled, "sso"),
          secondFactorChallenge(enrolled, "passkey"),
          secondFactorChallenge(enrolled, "oauth"),
        ],
        { concurrency: 1 },
      ).pipe(Effect.provide(enrolledGate(challenged))),
      exemptFromSecondFactor("sso", "passkey"),
    );
    expect(answers).toEqual([undefined, undefined, testChallenge]);
    expect(challenged).toEqual([enrolled.id]);
  });
});
