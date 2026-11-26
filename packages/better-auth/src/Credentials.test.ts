import { assert, describe, expect, it } from "vite-plus/test";
import * as Effect from "effect/Effect";
import * as Exit from "effect/Exit";
import * as Option from "effect/Option";
import * as Auth from "@thomasfosterau/effect-auth";
import { twoFactor, username } from "better-auth/plugins";
import { makeAuth, requestWith, rowOf, run, runExit, signUp } from "./testing/Fixtures.ts";
import { BetterAuthCredentials } from "./Credentials.ts";
import { BetterAuthSessions } from "./Session.ts";

const credentials = Effect.service(BetterAuthCredentials);
const headers = () => new Headers();

const failure = (exit: Exit.Exit<unknown, unknown>) =>
  Exit.isFailure(exit) ? Option.getOrUndefined(Exit.findErrorOption(exit)) : undefined;

const cookieHeader = (setCookie: ReadonlyArray<string>) =>
  setCookie.map((line) => line.split(";")[0]).join("; ");

describe("BetterAuthCredentials", () => {
  it("signs up and in, answering a Set-Cookie the lookup resolves", async () => {
    const { auth } = makeAuth();
    const email = "ada@example.test";
    const password = "correct horse battery";
    const up = await run(
      auth,
      Effect.flatMap(credentials, (c) =>
        c.signUpEmail({ headers: headers(), email, password, name: "Ada" }),
      ),
    );
    expect(up.status).toBe("signed-in");
    const signedIn = await run(
      auth,
      Effect.flatMap(credentials, (c) => c.signInEmail({ headers: headers(), email, password })),
    );
    assert(signedIn.status !== "second-factor", "no second factor is enrolled");
    const lookup = await run(
      auth,
      Effect.flatMap(Effect.service(BetterAuthSessions), (s) =>
        s.lookup(requestWith({ cookie: cookieHeader(signedIn.setCookie) })),
      ),
    );
    assert(Option.isSome(lookup.session));
    expect(lookup.session.value.user.id).toBe(signedIn.user.id);
  });

  it("maps a wrong password, a taken email and an unverified email to typed errors", async () => {
    const { auth } = makeAuth({
      emailAndPassword: { enabled: true, requireEmailVerification: true },
    });
    const email = "ada@example.test";
    const password = "correct horse battery";
    const up = await run(
      auth,
      Effect.flatMap(credentials, (c) =>
        c.signUpEmail({ headers: headers(), email, password, name: "Ada" }),
      ),
    );
    expect(up.status).toBe("pending-verification");
    expect(up.setCookie).toEqual([]);

    // BetterAuth answers a duplicate sign-up like a fresh one when it requires
    // verification, so the address is not revealed.
    const again = await run(
      auth,
      Effect.flatMap(credentials, (c) =>
        c.signUpEmail({ headers: headers(), email, password, name: "A" }),
      ),
    );
    expect(again.status).toBe("pending-verification");
    const { auth: open } = makeAuth();
    await signUp(open, email);
    const taken = await runExit(
      open,
      Effect.flatMap(credentials, (c) =>
        c.signUpEmail({ headers: headers(), email, password, name: "A" }),
      ),
    );
    expect(failure(taken)).toBeInstanceOf(Auth.EmailInUseError);

    const wrong = await runExit(
      auth,
      Effect.flatMap(credentials, (c) =>
        c.signInEmail({ headers: headers(), email, password: "not the password" }),
      ),
    );
    expect(failure(wrong)).toBeInstanceOf(Auth.InvalidCredentialsError);

    const unverified = await runExit(
      auth,
      Effect.flatMap(credentials, (c) => c.signInEmail({ headers: headers(), email, password })),
    );
    expect(failure(unverified)).toBeInstanceOf(Auth.EmailNotVerifiedError);
  });

  it("signs in by username with the username() plugin, and fails without it", async () => {
    const { auth } = makeAuth();
    const { user, password } = await signUp(auth);
    const context = await auth.$context;
    await context.internalAdapter.updateUser(user.id, { username: "ada" });
    const signedIn = await run(
      auth,
      Effect.flatMap(credentials, (c) =>
        c.signInUsername({ headers: headers(), username: "ada", password }),
      ),
    );
    expect(signedIn.status).toBe("signed-in");
    const wrong = await runExit(
      auth,
      Effect.flatMap(credentials, (c) =>
        c.signInUsername({ headers: headers(), username: "ada", password: "nope nope nope" }),
      ),
    );
    expect(failure(wrong)).toBeInstanceOf(Auth.InvalidCredentialsError);

    const { auth: plain } = makeAuth({ plugins: [] });
    const missing = await runExit(
      plain,
      Effect.flatMap(credentials, (c) =>
        c.signInUsername({ headers: headers(), username: "ada", password }),
      ),
    );
    expect(failure(missing)).toBeInstanceOf(Auth.AuthError);
  });

  it("answers second-factor, with no user, for a sign-in the twoFactor() plugin holds", async () => {
    const { auth, db } = makeAuth({ plugins: [username(), twoFactor()] });
    db["twoFactor"] = [];
    const { user, email, password } = await signUp(auth);
    const row = rowOf(db, "user", (u) => u["id"] === user.id);
    row["twoFactorEnabled"] = true;
    const held = await run(
      auth,
      Effect.flatMap(credentials, (c) => c.signInEmail({ headers: headers(), email, password })),
    );
    expect(held.status).toBe("second-factor");
    expect(held).not.toHaveProperty("user");
    expect(
      held.setCookie.some(
        (line) => line.includes("session_token=;") || line.includes("two_factor"),
      ),
    ).toBe(true);
  });

  it("signs out, clearing the cookie and deleting the session", async () => {
    const { auth, db } = makeAuth();
    const { cookie } = await signUp(auth);
    const cleared = await run(
      auth,
      Effect.flatMap(credentials, (c) => c.signOut({ headers: new Headers({ cookie }) })),
    );
    expect(cleared.some((line) => line.startsWith("better-auth.session_token=;"))).toBe(true);
    expect(db["session"]).toHaveLength(0);
  });
});
