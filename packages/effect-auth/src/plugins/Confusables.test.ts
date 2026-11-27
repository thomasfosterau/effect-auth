import { assert, describe, expect, it } from "vite-plus/test";
import * as Effect from "effect/Effect";
import * as Exit from "effect/Exit";
import * as Layer from "effect/Layer";
import * as Option from "effect/Option";
import { AccountManagementService } from "../AccountManagement.ts";
import { EmailOtpService, EmailOtpUserStore } from "../email/EmailOtp.ts";
import { EmailPasswordService } from "../email/EmailPassword.ts";
import { ConfusableEmailError } from "../Errors.ts";
import { composePlugins, Hooks, makePlugin, type ClaimEmailArgs } from "../Hooks.ts";
import { lookupIdentifier, IdentifierStore } from "../Identifier.ts";
import { MagicLinkService, MagicLinkUserStore } from "../MagicLink.ts";
import { pbkdf2Hasher, PasswordHasher } from "../password/Password.ts";
import { SessionService } from "../SessionService.ts";
import * as Testing from "../testing/index.ts";
import { inlineDeliveryScheduler } from "../testing/Delivery.ts";
import { normalizeEmail } from "../utils.ts";
import {
  confusableEmailReason,
  ConfusablesPlugin,
  restrictionLevel,
  skeleton,
} from "./Confusables.ts";
import { CONFUSABLES, SCRIPTS, UNICODE_VERSION } from "./ConfusablesData.ts";

// Cyrillic letters that look Latin.
const CYR_A = "а";
const CYR_ER = "р";
const CYR_U = "у";

describe("skeleton", () => {
  it("maps lookalikes to one prototype", () => {
    expect(skeleton(`p${CYR_A}ypal`)).toBe(skeleton("paypal"));
    expect(skeleton("ｐａｙｐａｌ")).toBe(skeleton("paypal"));
    expect(skeleton("rn")).toBe(skeleton("m"));
    expect(skeleton("l")).toBe(skeleton("1"));
  });

  it.each(["paypal", "пример", "例え", "straße", "josé"])("is idempotent on %s", (word) => {
    expect(skeleton(skeleton(word))).toBe(skeleton(word));
  });

  it("keeps different words apart", () => {
    expect(skeleton("paypal")).not.toBe(skeleton("paypals"));
    expect(skeleton("josé")).not.toBe(skeleton("jose"));
  });

  it("records a well-formed generated table, version and scripts", () => {
    const entries = CONFUSABLES.split(",");
    expect(entries.length).toBeGreaterThan(6000);
    expect(entries.every((entry) => /^[0-9a-z]+:[0-9a-z]+(\.[0-9a-z]+)*$/.test(entry))).toBe(true);
    expect(UNICODE_VERSION).toMatch(/^\d+\.\d+\.\d+$/);
    expect(SCRIPTS).toContain("Latn");
    expect(SCRIPTS).not.toContain("Zyyy");
  });
});

describe("restrictionLevel", () => {
  it.each([
    ["paypal", "ascii"],
    ["straße", "single-script"],
    ["josé", "single-script"],
    ["пример", "single-script"],
    ["μιχάλης", "single-script"],
    ["山田やまだ", "single-script"],
    ["taro山田やまだ", "highly-restrictive"],
    ["kim김", "highly-restrictive"],
    ["abcअ", "moderately-restrictive"],
    [`p${CYR_A}ypal`, "minimally-restrictive"],
    ["alphaα", "minimally-restrictive"],
    ["пример山", "minimally-restrictive"],
  ] as const)("%s is %s", (input, level) => {
    expect(restrictionLevel(input)).toBe(level);
  });

  it("reads characters the runtime assigns no script as a script of their own", () => {
    // U+0378 is unassigned.
    expect(restrictionLevel("a͸")).toBe("minimally-restrictive");
  });
});

const reason = (email: string, config = {}) =>
  Option.getOrUndefined(confusableEmailReason(normalizeEmail(email), config));

describe("confusableEmailReason", () => {
  it.each([
    "ada@example.com",
    "user+tag@gmail.com",
    "josé@exämple.com",
    "ivan@пример.рф",
    "пример@пример.рф",
    "山田@例え.jp",
    "μιχάλης@example.gr",
    "øystein@example.no",
  ])("passes %s", (email) => {
    expect(reason(email)).toBeUndefined();
  });

  it("judges the local part and each domain label apart", () => {
    // Each part is one script; the whole address mixes three.
    expect(reason("ivan@пример.例え.com")).toBeUndefined();
    expect(reason(`alice@${CYR_A}${CYR_ER}${CYR_ER}le.com`)).toBe("mixed-script");
  });

  it("refuses a part that mixes scripts", () => {
    expect(reason(`p${CYR_A}ypal@example.com`)).toBe("mixed-script");
  });

  it("refuses a part in another script that passes for ASCII", () => {
    expect(reason(`${CYR_ER}${CYR_A}${CYR_U}@example.com`)).toBe("ascii-lookalike");
    expect(reason("ｐａｙｐａｌ@example.com")).toBe("ascii-lookalike");
    // Cyrillic `аррӏе` as a punycode label.
    expect(reason("ada@xn--80ak6aa92e.com")).toBe("ascii-lookalike");
  });

  it("follows the configured restriction", () => {
    expect(reason("taro山田@example.jp", { restriction: "single-script" })).toBe("mixed-script");
    expect(reason("taro山田@example.jp")).toBeUndefined();
    expect(reason("abcअ@example.in")).toBe("mixed-script");
    expect(reason("abcअ@example.in", { restriction: "moderately-restrictive" })).toBeUndefined();
    // Its skeleton is ASCII too.
    expect(reason(`p${CYR_A}ypal@example.com`, { restriction: false })).toBe("ascii-lookalike");
    expect(
      reason(`p${CYR_A}ypal@example.com`, { restriction: false, asciiLookalikes: false }),
    ).toBeUndefined();
    expect(reason(`${CYR_ER}${CYR_A}${CYR_U}@example.com`, { asciiLookalikes: false })).toBe(
      undefined,
    );
  });

  it("reads a malformed punycode label as written", () => {
    expect(reason("ada@xn--.com")).toBeUndefined();
    expect(reason("ada@xn--99999999999999.com")).toBeUndefined();
  });
});

// ---------------------------------------------------------------------------
// The flows
// ---------------------------------------------------------------------------

const SPOOF = `p${CYR_A}ypal@example.com`;
const PASSWORD = "correct horse battery staple";

/** The services that fire `beforeClaimEmail`, over memory stores and `hooks`. */
const servicesWith = (hooks: Layer.Layer<Hooks, never, Hooks>) => {
  const links: Array<{ readonly email: string; readonly token: string }> = [];
  const codes: Array<{ readonly email: string; readonly code: string }> = [];
  const changes: Array<string> = [];
  const notices: Array<string> = [];
  const sent = { links, codes, changes, notices };
  const base = Layer.mergeAll(
    Testing.memoryStores,
    hooks.pipe(Layer.provide(Hooks.Default)),
    Layer.succeed(PasswordHasher)(pbkdf2Hasher({ iterations: 1000 })),
    inlineDeliveryScheduler,
    // The passwordless sign-ups here are all refused before a user is created.
    Layer.succeed(MagicLinkUserStore)({ createUser: () => Effect.die("unreachable") }),
    Layer.succeed(EmailOtpUserStore)({ createUser: () => Effect.die("unreachable") }),
  );
  const sessions = SessionService.layer(Testing.defaultSessionConfig).pipe(
    Layer.provideMerge(base),
  );
  const layer = Layer.mergeAll(
    EmailPasswordService.layer(),
    MagicLinkService.layer({
      resendCooldown: 0,
      sendMagicLink: (email, token) => Effect.sync(() => void sent.links.push({ email, token })),
    }),
    EmailOtpService.layer({
      resendCooldown: 0,
      sendVerificationOtp: (email, code) =>
        Effect.sync(() => void sent.codes.push({ email, code })),
    }),
    AccountManagementService.layer({
      sendChangeEmailVerification: ({ newEmail }) =>
        Effect.sync(() => void sent.changes.push(newEmail)),
      sendDeleteAccountVerification: () => Effect.void,
      sendEmailChangeNotice: ({ newEmail }) => Effect.sync(() => void sent.notices.push(newEmail)),
    }),
  ).pipe(Layer.provideMerge(sessions));
  return { layer, sent };
};

const isConfusableRefusal = (exit: Exit.Exit<unknown, unknown>) =>
  Exit.isFailure(exit) &&
  Option.match(Exit.findErrorOption(exit), {
    onNone: () => false,
    onSome: (error) => error instanceof ConfusableEmailError,
  });

describe("ConfusablesPlugin", () => {
  it("refuses with a stable code", () => {
    const error = new ConfusableEmailError({ message: "refused", reason: "mixed-script" });
    expect(error.code).toBe("CONFUSABLE_EMAIL");
    expect(error.reason).toBe("mixed-script");
  });

  it("refuses a confusable email-and-password sign-up before anything is written", async () => {
    const { layer } = servicesWith(ConfusablesPlugin());
    const outcome = await Effect.runPromise(
      Effect.gen(function* () {
        const service = yield* EmailPasswordService;
        const refused = yield* Effect.exit(service.signUp({ email: SPOOF, password: PASSWORD }));
        const held = yield* lookupIdentifier(yield* IdentifierStore, "email", SPOOF);
        const ok = yield* service.signUp({ email: "paypal@example.com", password: PASSWORD });
        return { refused, held, ok };
      }).pipe(Effect.provide(layer)),
    );
    expect(isConfusableRefusal(outcome.refused)).toBe(true);
    expect(Option.isNone(outcome.held)).toBe(true);
    expect(outcome.ok.user.id).toBeTypeOf("string");
  });

  it("refuses a magic-link sign-up with a confusable address", async () => {
    const { layer, sent } = servicesWith(ConfusablesPlugin());
    const exit = await Effect.runPromise(
      Effect.gen(function* () {
        const service = yield* MagicLinkService;
        yield* service.send(SPOOF);
        const link = sent.links.at(-1);
        assert(link !== undefined);
        const verified = yield* Effect.exit(service.verify(link.token));
        expect(Option.isNone(yield* lookupIdentifier(yield* IdentifierStore, "email", SPOOF))).toBe(
          true,
        );
        return verified;
      }).pipe(Effect.provide(layer)),
    );
    expect(isConfusableRefusal(exit)).toBe(true);
  });

  it("refuses an email OTP sign-up with a confusable address", async () => {
    const { layer, sent } = servicesWith(ConfusablesPlugin());
    const exit = await Effect.runPromise(
      Effect.gen(function* () {
        const service = yield* EmailOtpService;
        yield* service.send(SPOOF, "sign-in");
        const code = sent.codes.at(-1);
        assert(code !== undefined);
        const signedIn = yield* Effect.exit(service.signIn(SPOOF, code.code));
        expect(Option.isNone(yield* lookupIdentifier(yield* IdentifierStore, "email", SPOOF))).toBe(
          true,
        );
        return signedIn;
      }).pipe(Effect.provide(layer)),
    );
    expect(isConfusableRefusal(exit)).toBe(true);
  });

  it("refuses a confusable new address after telling the current one", async () => {
    const { layer, sent } = servicesWith(ConfusablesPlugin());
    const exit = await Effect.runPromise(
      Effect.gen(function* () {
        const { user } = yield* (yield* EmailPasswordService).signUp({
          email: "ada@example.com",
          password: PASSWORD,
        });
        return yield* Effect.exit(
          (yield* AccountManagementService).requestEmailChange(user.id, SPOOF, {
            currentPassword: PASSWORD,
          }),
        );
      }).pipe(Effect.provide(layer)),
    );
    expect(isConfusableRefusal(exit)).toBe(true);
    expect(sent.notices).toEqual([normalizeEmail(SPOOF)]);
    expect(sent.changes).toEqual([]);
  });

  it("guards only the configured flows", async () => {
    const { layer, sent } = servicesWith(ConfusablesPlugin({ flows: ["email-change"] }));
    await Effect.runPromise(
      Effect.gen(function* () {
        const service = yield* EmailPasswordService;
        yield* service.signUp({ email: SPOOF, password: PASSWORD });
        const { user } = yield* service.signUp({ email: "ada@example.com", password: PASSWORD });
        const refused = yield* Effect.exit(
          (yield* AccountManagementService).requestEmailChange(
            user.id,
            `p${CYR_A}ypal@example.org`,
            {
              currentPassword: PASSWORD,
            },
          ),
        );
        expect(isConfusableRefusal(refused)).toBe(true);
      }).pipe(Effect.provide(layer)),
    );
    expect(sent.changes).toEqual([]);
  });

  it("hands each flow the normalized address, and the user changing theirs", async () => {
    const seen: Array<ClaimEmailArgs> = [];
    const spy = composePlugins([
      makePlugin({
        beforeClaimEmail: (args: ClaimEmailArgs) =>
          Effect.sync(() => void seen.push(args)).pipe(Effect.as(args)),
      }),
    ]);
    const { layer } = servicesWith(spy);
    const userId = await Effect.runPromise(
      Effect.gen(function* () {
        const { user } = yield* (yield* EmailPasswordService).signUp({
          email: " Ada@Exämple.com ",
          password: PASSWORD,
        });
        yield* (yield* AccountManagementService).requestEmailChange(user.id, "ADA@example.org", {
          currentPassword: PASSWORD,
        });
        return user.id;
      }).pipe(Effect.provide(layer)),
    );
    expect(seen).toEqual([
      { email: "ada@xn--exmple-cua.com", flow: "sign-up" },
      { email: "ada@example.org", flow: "email-change", userId },
    ]);
  });
});
