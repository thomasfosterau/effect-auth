/**
 * A `SecondFactorGate` stand-in for the sign-in suites: it requires a second
 * factor of the users it names and records whom it challenged, so a test can
 * see that a flow consulted the gate and issued no session.
 *
 * Internal test support: the `./testing` barrel does not export it.
 */
import * as Effect from "effect/Effect";
import * as Layer from "effect/Layer";
import { SecondFactorGate, type SecondFactorChallenge } from "../email/EmailPassword.ts";

/** The challenge the stand-in answers with. */
export const testChallenge: SecondFactorChallenge = { token: "second-factor", expiresAt: 0 };

/**
 * A gate that requires a second factor of every user whose id is in
 * `enrolled` (every user when it is omitted), pushing each challenged user's
 * id onto `challenged`.
 */
export const enrolledGate = (
  challenged: Array<string>,
  enrolled?: ReadonlyArray<string>,
): Layer.Layer<SecondFactorGate> =>
  Layer.succeed(SecondFactorGate, {
    required: (user) => Effect.succeed(enrolled === undefined || enrolled.includes(user.id)),
    begin: (user) =>
      Effect.sync(() => {
        challenged.push(user.id);
        return testChallenge;
      }),
  });
