/**
 * The `beforeAuthenticate` gate end to end (#592): username sign-in runs the
 * lockout, rate-limit and captcha plugins email sign-in runs, lockout keys on
 * the account and clears only when a session is issued, and second-factor
 * redemptions are counted per user across challenges.
 */
import { assert, describe, expect, it } from "vite-plus/test";
import { Effect, Layer, Redacted } from "effect";
import { HttpClient, HttpClientResponse } from "effect/http";
import { ClientIP } from "./ClientIP.ts";
import { EmailPasswordService } from "./email/EmailPassword.ts";
import * as Errors from "./Errors.ts";
import { composePlugins, Hooks } from "./Hooks.ts";
import {
  MultiFactorGateLayer,
  MultiFactorService,
  type MultiFactorConfig,
} from "./multifactor/MultiFactor.ts";
import { generateTotp } from "./multifactor/Otp.ts";
import * as Password from "./password/Password.ts";
import { PasswordHasher } from "./password/Password.ts";
import {
  AccountLockoutPlugin,
  AccountLockoutStore,
  type AccountLockoutConfig,
  memoryAccountLockoutStore,
} from "./plugins/AccountLockout.ts";
import { CaptchaPlugin } from "./plugins/Captcha.ts";
import { IPRateLimitPlugin } from "./plugins/IPRateLimit.ts";
import { RateLimitPlugin } from "./plugins/RateLimit.ts";
import { RateLimiter, RateLimitPresets, RateLimitStore } from "./RateLimit.ts";
import { SessionService } from "./SessionService.ts";
import * as Testing from "./testing/MemoryStores.ts";
import { UsernameService } from "./Username.ts";

const password = "correct horse battery staple";
const email = "ada@example.com";
const username = "ada";

/** Answers every captcha verification with `{ success }`. */
const captchaClient = (success: boolean) =>
  Layer.succeed(
    HttpClient.HttpClient,
    HttpClient.make((request) =>
      Effect.succeed(HttpClientResponse.fromWeb(request, Response.json({ success }))),
    ),
  );

type PluginLayer = Layer.Layer<
  Hooks,
  never,
  Hooks | RateLimiter | RateLimitStore | AccountLockoutStore | HttpClient.HttpClient
>;

/**
 * Email and password, username and TOTP second factor over the in-memory
 * stores, with `plugin` on the hooks.
 */
const services = (
  plugin: PluginLayer,
  options: { readonly captcha?: boolean; readonly multiFactor?: MultiFactorConfig } = {},
) => {
  const stores = Layer.mergeAll(
    Testing.layer,
    Layer.succeed(PasswordHasher)(Password.scryptHasher({ cost: 1024 })),
    Layer.succeed(AccountLockoutStore)(memoryAccountLockoutStore()),
    captchaClient(options.captcha ?? true),
  );
  const hooks = composePlugins([plugin]).pipe(
    Layer.provide(Hooks.Default),
    Layer.provideMerge(RateLimiter.layer().pipe(Layer.provideMerge(stores))),
  );
  return Layer.mergeAll(UsernameService.layer(), MultiFactorGateLayer).pipe(
    Layer.provideMerge(EmailPasswordService.layer()),
    Layer.provideMerge(
      MultiFactorService.layer(
        options.multiFactor ?? { issuer: "Test", skipVerificationOnEnable: true },
      ),
    ),
    Layer.provideMerge(
      SessionService.layer({
        sessionExpiresIn: { activePeriod: 3_600_000, idlePeriod: 3_600_000 },
      }),
    ),
    Layer.provideMerge(hooks),
  );
};

/** Sign Ada up with an email, a username and a password. */
const signUpAda = Effect.fn("signUpAda")(function* () {
  const usernames = yield* UsernameService;
  const { user } = yield* usernames.signUp({ username, email, password });
  return user;
});

/** Sign in by username with `secret`, answering with the error tag or `"ok"`. */
const signInByUsername = (secret: string, captchaToken?: string) =>
  Effect.gen(function* () {
    const usernames = yield* UsernameService;
    return yield* usernames.signIn({ username, password: secret, captchaToken }).pipe(
      Effect.as("ok"),
      Effect.catch((error) => Effect.succeed(error._tag)),
    );
  });

const lockout = (config: AccountLockoutConfig) =>
  AccountLockoutPlugin({ lockoutDurationMs: 60_000, ...config });

describe("beforeAuthenticate on username sign-in (#592)", () => {
  it("locks the account after maxAttempts wrong username passwords", async () => {
    const outcomes = await Effect.runPromise(
      Effect.gen(function* () {
        yield* signUpAda();
        const wrong = yield* Effect.forEach([1, 2, 3], () => signInByUsername("wrong password"), {
          concurrency: 1,
        });
        // Locked: even the right password is refused now.
        return [...wrong, yield* signInByUsername(password)];
      }).pipe(Effect.provide(services(lockout({ maxAttempts: 3 })))),
    );
    expect(outcomes).toEqual([
      "InvalidCredentialsError",
      "InvalidCredentialsError",
      "InvalidCredentialsError",
      "AccountLockedError",
    ]);
  });

  it("shares one count between the account's email and its username", async () => {
    const outcome = await Effect.runPromise(
      Effect.gen(function* () {
        yield* signUpAda();
        const emailPassword = yield* EmailPasswordService;
        yield* Effect.flip(emailPassword.signIn({ email, password: "wrong password" }));
        yield* Effect.flip(emailPassword.signIn({ email, password: "wrong password" }));
        yield* signInByUsername("wrong password");
        return yield* Effect.flip(emailPassword.signIn({ email, password }));
      }).pipe(Effect.provide(services(lockout({ maxAttempts: 3 })))),
    );
    expect(outcome).toBeInstanceOf(Errors.AccountLockedError);
  });

  it("consumes the per-account rate limit", async () => {
    const outcomes = await Effect.runPromise(
      Effect.gen(function* () {
        yield* signUpAda();
        return yield* Effect.forEach(
          Array.from({ length: RateLimitPresets.login.maxRequests + 1 }),
          () => signInByUsername("wrong password"),
          { concurrency: 1 },
        );
      }).pipe(Effect.provide(services(RateLimitPlugin))),
    );
    expect(outcomes.at(-1)).toBe("RateLimitError");
    expect(outcomes.slice(0, -1).every((tag) => tag === "InvalidCredentialsError")).toBe(true);
  });

  it("consumes the per-address rate limit", async () => {
    const outcomes = await Effect.runPromise(
      Effect.gen(function* () {
        yield* signUpAda();
        return yield* Effect.forEach([1, 2, 3], () => signInByUsername(password), {
          concurrency: 1,
        });
      }).pipe(
        Effect.provide(
          services(IPRateLimitPlugin({ signIn: { maxRequests: 2, windowMs: 60_000 } })),
        ),
        Effect.provideService(ClientIP, { ip: "203.0.113.9" }),
      ),
    );
    expect(outcomes).toEqual(["ok", "ok", "RateLimitError"]);
  });

  it("requires a captcha token that verifies", async () => {
    const captcha = CaptchaPlugin({
      provider: "cloudflare-turnstile",
      secretKey: Redacted.make("secret"),
      // Username sign-up carries no token; only sign-in is guarded here.
      endpoints: ["signIn"],
    });
    const run = (success: boolean, token: string | undefined) =>
      Effect.runPromise(
        Effect.gen(function* () {
          yield* signUpAda();
          return yield* signInByUsername(password, token);
        }).pipe(Effect.provide(services(captcha, { captcha: success }))),
      );
    expect(await run(true, "tok")).toBe("ok");
    expect(await run(true, undefined)).toBe("CaptchaError");
    expect(await run(false, "tok")).toBe("CaptchaError");
  });
});

describe("lockout clears only when a session is issued (#592)", () => {
  /** Enrol Ada in TOTP and answer with her secret. */
  const enrolAda = Effect.fn("enrolAda")(function* () {
    const user = yield* signUpAda();
    const multiFactor = yield* MultiFactorService;
    const { secret } = yield* multiFactor.enable(user.id, password);
    return secret;
  });

  /** A correct password sign-in, which earns only a second-factor challenge. */
  const challenge = Effect.fn("challenge")(function* () {
    const emailPassword = yield* EmailPasswordService;
    const result = yield* emailPassword.signIn({ email, password });
    assert(result.secondFactor !== undefined, "a second factor is required");
    assert(result.session === undefined, "no session before the second factor");
    return result.secondFactor.token;
  });

  it("keeps counting across correct passwords that only earn a challenge", async () => {
    const outcome = await Effect.runPromise(
      Effect.gen(function* () {
        yield* enrolAda();
        yield* challenge();
        yield* challenge();
        yield* challenge();
        const emailPassword = yield* EmailPasswordService;
        return yield* Effect.flip(emailPassword.signIn({ email, password }));
      }).pipe(Effect.provide(services(lockout({ maxAttempts: 3 })))),
    );
    expect(outcome).toBeInstanceOf(Errors.AccountLockedError);
  });

  it("counts second-factor redemptions per user across challenges, and a session clears both counts", async () => {
    const outcomes = await Effect.runPromise(
      Effect.gen(function* () {
        const secret = yield* enrolAda();
        const multiFactor = yield* MultiFactorService;
        const wrong = (token: string) =>
          multiFactor.verifyTotp(token, "not-a-code").pipe(
            Effect.as("ok"),
            Effect.catch((error) => Effect.succeed(error._tag)),
          );

        // Each challenge would allow five wrong codes; the user's own count
        // runs across challenges and stops the third.
        const first = yield* challenge();
        const a = yield* wrong(first);
        const b = yield* wrong(first);
        const second = yield* challenge();
        const c = yield* wrong(second);
        const locked = yield* multiFactor.verifyTotp(second, yield* generateTotp(secret)).pipe(
          Effect.as("ok"),
          Effect.catch((error) => Effect.succeed(error._tag)),
        );
        return [a, b, c, locked];
      }).pipe(Effect.provide(services(lockout({ maxAttempts: 10, maxSecondFactorAttempts: 3 })))),
    );
    expect(outcomes).toEqual([
      "MultiFactorError",
      "MultiFactorError",
      "MultiFactorError",
      "AccountLockedError",
    ]);
  });

  it("a completed second factor issues a session and clears the counts", async () => {
    const outcome = await Effect.runPromise(
      Effect.gen(function* () {
        const secret = yield* enrolAda();
        const multiFactor = yield* MultiFactorService;
        yield* challenge();
        yield* challenge();
        const token = yield* challenge();
        const { session } = yield* multiFactor.verifyTotp(token, yield* generateTotp(secret));
        // Three counted attempts, then a session: the count starts afresh, so
        // two more sign-ins stay under the limit of four.
        yield* challenge();
        yield* challenge();
        return session.userId;
      }).pipe(Effect.provide(services(lockout({ maxAttempts: 4 })))),
    );
    expect(outcome).not.toBe("");
  });
});
