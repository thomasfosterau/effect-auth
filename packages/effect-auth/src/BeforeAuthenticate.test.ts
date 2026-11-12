/**
 * The `beforeAuthenticate` gate end to end (#592): username sign-in runs the
 * lockout, rate-limit and captcha plugins email sign-in runs, lockout keys on
 * the account and clears only when a session is issued, and second-factor
 * redemptions are counted per user across challenges.
 *
 * And its follow-ups (#678): magic link and one-time codes are exempt from
 * the account lock without becoming a way past their own bounds, the captcha
 * guards the sends, unknown challenges and tokens still reach the per-IP
 * limit, and an impersonation never clears a lockout.
 */
import { assert, beforeEach, describe, expect, it } from "vite-plus/test";
import { DateTime, Effect, Layer, Redacted } from "effect";
import { HttpClient, HttpClientResponse } from "effect/http";
import { AdminService, AdminUserStore } from "./Admin.ts";
import { ClientIP } from "./ClientIP.ts";
import { EmailOtpService, EmailOtpStore, EmailOtpUserStore } from "./email/EmailOtp.ts";
import { EmailPasswordService } from "./email/EmailPassword.ts";
import { MagicLinkService, MagicLinkUserStore } from "./MagicLink.ts";
import { PhoneOtpService, PhoneOtpStore, PhoneOtpUserStore } from "./PhoneOtp.ts";
import { inlineDeliveryScheduler } from "./testing/Delivery.ts";
import type * as Types from "./Types.ts";
import { UserServiceStore } from "./User.ts";
import { UserStore } from "./UserStore.ts";
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

// ---------------------------------------------------------------------------
// #678: the passwordless flows, the send gate, unkeyed attempts, impersonation
// ---------------------------------------------------------------------------

const phoneNumber = "+15550100";

/** What the senders handed out: the codes and links an inbox (or phone) received. */
const outbox: Array<{ readonly to: string; readonly secret: string }> = [];

/** The latest code or link sent to `to`. */
const latest = (to: string): string => {
  const sent = outbox.findLast((message) => message.to === to);
  assert(sent !== undefined, `something was sent to ${to}`);
  return sent.secret;
};

const record = (to: string, secret: string) => Effect.sync(() => void outbox.push({ to, secret }));

/** A user store a test never asks to create: every address it uses has an account. */
const noSignUp = {
  createUser: () => Effect.die("this suite signs up through UsernameService"),
};

/**
 * {@link services} plus email OTP, phone OTP, magic link (sends recorded to
 * the outbox, no resend cooldown) and the admin service.
 */
const passwordless = (
  plugin: PluginLayer,
  options: { readonly captcha?: boolean; readonly multiFactor?: MultiFactorConfig } = {},
) => {
  const extraStores = Layer.mergeAll(
    Layer.succeed(EmailOtpUserStore)(noSignUp),
    Layer.succeed(MagicLinkUserStore)(noSignUp),
    Layer.succeed(PhoneOtpUserStore)(noSignUp),
    Layer.succeed(PhoneOtpStore)(Testing.memoryPhoneOtpStore()),
    Layer.succeed(AdminUserStore)({
      listUsers: () => Effect.die("unused"),
      createUser: () => Effect.die("unused"),
      setPasswordHash: () => Effect.die("unused"),
    }),
    Layer.effect(
      UserServiceStore,
      Effect.map(UserStore, (users) => ({
        get: users.get,
        update: () => Effect.die("unused"),
        delete: () => Effect.die("unused"),
      })),
    ),
    inlineDeliveryScheduler,
  );
  return Layer.mergeAll(
    EmailOtpService.layer({
      resendCooldown: 0,
      sendVerificationOtp: (address, otp) => record(address, otp),
    }),
    PhoneOtpService.layer({
      resendCooldown: 0,
      sendOtp: (number, otp) => record(number, otp),
    }),
    MagicLinkService.layer({ sendMagicLink: (address, token) => record(address, token) }),
    AdminService.layer({ adminRoles: ["admin"] }),
  ).pipe(Layer.provideMerge(extraStores), Layer.provideMerge(services(plugin, options)));
};

/** Run `effect` and answer with `"ok"` or the tag it failed with. */
const outcome = <A, E extends { readonly _tag: string }, R>(effect: Effect.Effect<A, E, R>) =>
  effect.pipe(
    Effect.as("ok"),
    Effect.catch((error) => Effect.succeed(error._tag)),
  );

/** Lock Ada's account with wrong passwords, and check the lock holds. */
const lockAda = Effect.fn("lockAda")(function* (maxAttempts: number) {
  yield* Effect.forEach(
    Array.from({ length: maxAttempts }),
    () => signInByUsername("wrong password"),
    { concurrency: 1 },
  );
  const locked = yield* signInByUsername(password);
  if (locked !== "AccountLockedError") {
    return yield* Effect.die(`expected the account to be locked, got ${locked}`);
  }
  return yield* Effect.void;
});

/** The lockout counter on a user's first factor, or `null` once cleared. */
const lockoutRecord = (userId: string) =>
  Effect.flatMap(AccountLockoutStore, (store) => store.get(`lockout:user:${userId}`));

describe("magic link and one-time codes under an account lock (#678)", () => {
  beforeEach(() => {
    outbox.length = 0;
  });

  it.each([
    {
      method: "magic link",
      recover: Effect.gen(function* () {
        const magicLink = yield* MagicLinkService;
        yield* magicLink.send(email);
        return yield* magicLink.verify(latest(email));
      }),
    },
    {
      method: "email OTP",
      recover: Effect.gen(function* () {
        const emailOtp = yield* EmailOtpService;
        yield* emailOtp.send(email, "sign-in");
        return yield* emailOtp.signIn(email, latest(email));
      }),
    },
  ])("lets the owner recover with a $method while the account is locked", async ({ recover }) => {
    const result = await Effect.runPromise(
      Effect.gen(function* () {
        const ada = yield* signUpAda();
        yield* lockAda(3);
        const { session } = yield* recover;
        // The session the owner earned clears the lock.
        return { ada, session, lock: yield* lockoutRecord(ada.id) };
      }).pipe(Effect.provide(passwordless(lockout({ maxAttempts: 3 })))),
    );
    expect(result.session.userId).toBe(result.ada.id);
    expect(result.lock).toBeNull();
  });

  it("lets the owner recover with a phone OTP while the account is locked", async () => {
    const result = await Effect.runPromise(
      Effect.gen(function* () {
        const ada = yield* signUpAda();
        const phoneOtp = yield* PhoneOtpService;
        yield* phoneOtp.send(phoneNumber, "phone-verification");
        yield* phoneOtp.verifyPhoneNumber(ada.id, phoneNumber, latest(phoneNumber));
        yield* lockAda(3);
        yield* phoneOtp.send(phoneNumber, "sign-in");
        const { session } = yield* phoneOtp.signIn(phoneNumber, latest(phoneNumber));
        return { ada, session };
      }).pipe(Effect.provide(passwordless(lockout({ maxAttempts: 3 })))),
    );
    expect(result.session.userId).toBe(result.ada.id);
  });

  it("gives an attacker who knows the handle no guesses past the code limit and the backoff", async () => {
    const result = await Effect.runPromise(
      Effect.gen(function* () {
        yield* signUpAda();
        yield* lockAda(3);
        const emailOtp = yield* EmailOtpService;
        // Each round: request a code (it goes to Ada's inbox), then guess.
        const round = Effect.fn("round")(function* () {
          const sent = yield* outcome(emailOtp.send(email, "sign-in"));
          const guesses = yield* Effect.forEach(
            ["000000", "111111", "222222"],
            (guess) => outcome(emailOtp.signIn(email, guess)),
            { concurrency: 1 },
          );
          return { sent, guesses };
        });
        const rounds = yield* Effect.forEach([1, 2, 3], () => round(), { concurrency: 1 });
        const store = yield* EmailOtpStore;
        return {
          rounds,
          failures: (yield* store.getFailures(email, "sign-in"))?.count,
          password: yield* signInByUsername(password),
        };
      }).pipe(Effect.provide(passwordless(lockout({ maxAttempts: 3 })))),
    );
    const refused = ["EmailOtpError", "EmailOtpError", "EmailOtpError"];
    expect(result.rounds).toEqual([
      // Three wrong codes spend the code (the per-code limit).
      { sent: "ok", guesses: refused },
      // Five wrong codes put the address into its backoff (#590) ...
      { sent: "ok", guesses: refused },
      // ... so no fresh code is issued, and a guess meets no code at all.
      { sent: "ResendTooSoonError", guesses: refused },
    ]);
    // Only the six guesses that met a code were compared, and none matched.
    expect(result.failures).toBe(6);
    // The exemption lifted nothing: the password methods stay locked.
    expect(result.password).toBe("AccountLockedError");
  });

  it("the per-IP limit bounds code guesses and guessed magic-link tokens", async () => {
    const result = await Effect.runPromise(
      Effect.gen(function* () {
        yield* signUpAda();
        // Three wrong passwords lock the account and spend three of the five
        // (the refused fourth stops at the lock, before the per-IP plugin).
        yield* lockAda(3);
        const emailOtp = yield* EmailOtpService;
        const magicLink = yield* MagicLinkService;
        yield* emailOtp.send(email, "sign-in");
        const guesses = yield* Effect.forEach(
          ["000000", "111111"],
          (guess) => outcome(emailOtp.signIn(email, guess)),
          { concurrency: 1 },
        );
        // Unknown tokens name no account, but still draw on the address.
        const tokens = yield* Effect.forEach(
          ["guess-1", "guess-2"],
          (token) => outcome(magicLink.verify(token)),
          { concurrency: 1 },
        );
        return { guesses, tokens };
      }).pipe(
        Effect.provide(
          passwordless(
            composePlugins<AccountLockoutStore | RateLimiter | RateLimitStore>([
              lockout({ maxAttempts: 3 }),
              IPRateLimitPlugin({ signIn: { maxRequests: 5, windowMs: 60_000 } }),
            ]),
          ),
        ),
        Effect.provideService(ClientIP, { ip: "203.0.113.9" }),
      ),
    );
    // The two code guesses spend the rest of the address's budget; the
    // guessed tokens find it spent.
    expect(result).toEqual({
      guesses: ["EmailOtpError", "EmailOtpError"],
      tokens: ["RateLimitError", "RateLimitError"],
    });
  });
});

describe("the captcha guards the code and link sends (#678)", () => {
  beforeEach(() => {
    outbox.length = 0;
  });

  const captcha = CaptchaPlugin({
    provider: "cloudflare-turnstile",
    secretKey: Redacted.make("secret"),
  });

  const sends: ReadonlyArray<{
    readonly method: string;
    readonly to: string;
    readonly send: (
      captchaToken?: string,
    ) => Effect.Effect<
      void,
      { readonly _tag: string },
      EmailOtpService | PhoneOtpService | MagicLinkService
    >;
  }> = [
    {
      method: "email OTP",
      to: email,
      send: (captchaToken?: string) =>
        Effect.flatMap(EmailOtpService, (otp) => otp.send(email, "sign-in", { captchaToken })),
    },
    {
      method: "phone OTP",
      to: phoneNumber,
      send: (captchaToken?: string) =>
        Effect.flatMap(PhoneOtpService, (otp) =>
          otp.send(phoneNumber, "sign-in", { captchaToken }),
        ),
    },
    {
      method: "magic link",
      to: email,
      send: (captchaToken?: string) =>
        Effect.flatMap(MagicLinkService, (link) => link.send(email, { captchaToken })),
    },
  ];

  it.each(sends)("a $method send needs a captcha token that verifies", async ({ to, send }) => {
    const run = (success: boolean, token: string | undefined) =>
      Effect.runPromise(
        outcome(send(token)).pipe(Effect.provide(passwordless(captcha, { captcha: success }))),
      );
    expect(await run(true, undefined)).toBe("CaptchaError");
    expect(await run(false, "tok")).toBe("CaptchaError");
    // A refused send sends nothing.
    expect(outbox).toEqual([]);
    expect(await run(true, "tok")).toBe("ok");
    expect(outbox.map((message) => message.to)).toEqual([to]);
  });

  it("leaves the sends alone when only sign-up and sign-in are guarded", async () => {
    const signInOnly = CaptchaPlugin({
      provider: "cloudflare-turnstile",
      secretKey: Redacted.make("secret"),
      endpoints: ["signUp", "signIn"],
    });
    const answers = await Effect.runPromise(
      Effect.forEach(sends, ({ send }) => outcome(send()), { concurrency: 1 }).pipe(
        Effect.provide(passwordless(signInOnly, { captcha: false })),
      ),
    );
    expect(answers).toEqual(["ok", "ok", "ok"]);
  });
});

describe("unknown challenges and tokens reach the per-IP limit (#678)", () => {
  it("counts an unknown second-factor challenge", async () => {
    const answers = await Effect.runPromise(
      Effect.gen(function* () {
        const multiFactor = yield* MultiFactorService;
        return yield* Effect.forEach(
          ["no-such-challenge-1", "no-such-challenge-2", "no-such-challenge-3"],
          (token) => outcome(multiFactor.verifyTotp(token, "123456")),
          { concurrency: 1 },
        );
      }).pipe(
        Effect.provide(
          services(IPRateLimitPlugin({ secondFactor: { maxRequests: 2, windowMs: 60_000 } })),
        ),
        Effect.provideService(ClientIP, { ip: "203.0.113.9" }),
      ),
    );
    expect(answers).toEqual(["MultiFactorError", "MultiFactorError", "RateLimitError"]);
  });

  it("counts an unknown magic-link token", async () => {
    const answers = await Effect.runPromise(
      Effect.gen(function* () {
        const magicLink = yield* MagicLinkService;
        return yield* Effect.forEach(
          ["guess-1", "guess-2", "guess-3"],
          (token) => outcome(magicLink.verify(token)),
          { concurrency: 1 },
        );
      }).pipe(
        Effect.provide(
          passwordless(IPRateLimitPlugin({ signIn: { maxRequests: 2, windowMs: 60_000 } })),
        ),
        Effect.provideService(ClientIP, { ip: "203.0.113.9" }),
      ),
    );
    expect(answers).toEqual(["MagicLinkError", "MagicLinkError", "RateLimitError"]);
  });

  it("lets an unknown token through the per-account plugins", async () => {
    const answers = await Effect.runPromise(
      Effect.gen(function* () {
        const magicLink = yield* MagicLinkService;
        return yield* Effect.forEach(
          Array.from({ length: RateLimitPresets.login.maxRequests + 1 }),
          () => outcome(magicLink.verify("guess")),
          { concurrency: 1 },
        );
      }).pipe(
        Effect.provide(
          passwordless(
            composePlugins<AccountLockoutStore | RateLimiter | RateLimitStore>([
              lockout({ maxAttempts: 1 }),
              RateLimitPlugin,
            ]),
          ),
        ),
      ),
    );
    // No account to count against: neither a lock nor an account bucket.
    expect(answers.every((tag) => tag === "MagicLinkError")).toBe(true);
  });
});

describe("an impersonation leaves the target's lockout standing (#678)", () => {
  it("keeps the account locked after an admin impersonates it", async () => {
    const result = await Effect.runPromise(
      Effect.gen(function* () {
        const ada = yield* signUpAda();
        yield* lockAda(3);
        const now = yield* DateTime.nowAsDate;
        const admin: Types.User = {
          id: "admin-1",
          createdAt: now,
          updatedAt: now,
          attributes: { role: "admin" },
        };
        const admins = yield* AdminService;
        const { session } = yield* admins.impersonateUser(admin, ada.id);
        return {
          impersonatedBy: session.attributes["impersonatedBy"],
          lock: yield* lockoutRecord(ada.id),
          password: yield* signInByUsername(password),
        };
      }).pipe(Effect.provide(passwordless(lockout({ maxAttempts: 3 })))),
    );
    expect(result.impersonatedBy).toBe("admin-1");
    expect(result.lock?.lockedUntil).toBeDefined();
    expect(result.password).toBe("AccountLockedError");
  });
});
