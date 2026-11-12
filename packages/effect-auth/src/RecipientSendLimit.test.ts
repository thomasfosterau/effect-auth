/**
 * The per-recipient send cap (#684) on every send path: the email OTP (each
 * purpose), the phone OTP (each purpose), the magic link, the password reset
 * and the email-verification resend. Each path refuses the 6th send in the
 * hour, answers a known and an unknown recipient alike, opens again when the
 * window ends, counts nothing under `false`, and keys its count on the
 * recipient's digest only.
 */
import { assert, describe, expect, it } from "vite-plus/test";
import { DateTime, Duration, Effect, Layer, MutableHashMap, Result } from "effect";
import * as Arr from "effect/Array";
import * as Option from "effect/Option";
import * as P from "effect/Predicate";
import { KeyValueStore } from "effect/persistence";
import { TestClock } from "effect/testing";
import * as EmailOtp from "./email/EmailOtp.ts";
import { RateLimitError, ResendTooSoonError } from "./Errors.ts";
import { Hooks } from "./Hooks.ts";
import { EmailPasswordStore } from "./email/EmailPassword.ts";
import * as EmailVerification from "./email/EmailVerification.ts";
import {
  type Identifier,
  IdentifierStore,
  makeIdentifier,
  memoryIdentifierStore,
} from "./Identifier.ts";
import {
  EmailOtpStoreKV,
  EmailVerificationStoreKV,
  MagicLinkStoreKV,
  PasswordResetStoreKV,
} from "./KeyValueStores.ts";
import * as MagicLink from "./MagicLink.ts";
import * as Password from "./password/Password.ts";
import * as PasswordReset from "./password/PasswordReset.ts";
import * as PhoneOtp from "./PhoneOtp.ts";
import * as PlatformCrypto from "./PlatformCrypto.ts";
import { type RateLimitEntry, RateLimitStore } from "./RateLimit.ts";
import {
  defaultRecipientSendLimit,
  isRecipientSendCapped,
  recipientSendKey,
} from "./RecipientSendLimit.ts";
import { inlineDeliveryScheduler } from "./testing/Delivery.ts";
import {
  memoryEmailPasswordStore,
  memoryPhoneOtpStore,
  memoryRateLimitStore,
} from "./testing/MemoryStores.ts";
import { sessionServiceLayer } from "./testing/ServiceLayers.ts";
import { hashToken } from "./TokenHash.ts";
import type { RecipientSendLimit, User } from "./Types.ts";

const HOUR = 60 * 60 * 1000;
/** Where the test clock starts: a send's records need a non-zero time. */
const START = 1_700_000_000_000;

const memberEmail = "member@example.com";
const memberPhone = "+15550000001";
const unverifiedEmail = "unverified@example.com";

const startDate = DateTime.toDateUtc(DateTime.makeUnsafe(START));

const user = (id: string): User => ({
  id,
  createdAt: startDate,
  updatedAt: startDate,
  attributes: {},
});

/** A user store the sends never reach. */
const unused = () => Effect.die("unused");

/** The stores and services every path needs, with the cap's counts readable. */
const makeWorld = () => {
  const rateLimits = MutableHashMap.empty<string, RateLimitEntry>();
  const identifierRecords = MutableHashMap.empty<string, Identifier>();
  const seed = (userId: string, type: "email" | "phone", value: string, verified: boolean) => {
    const identifier = makeIdentifier({
      userId,
      type,
      value,
      verified,
      ...(verified && { verifiedAt: startDate }),
      now: startDate,
    });
    MutableHashMap.set(identifierRecords, identifier.id, identifier);
  };
  seed("user-member", "email", memberEmail, true);
  seed("user-member", "phone", memberPhone, true);
  seed("user-unverified", "email", unverifiedEmail, false);
  const sent: Array<string> = [];
  const layer = Layer.mergeAll(
    sessionServiceLayer({ users: [user("user-member"), user("user-unverified")] }),
    Layer.succeed(RateLimitStore)(memoryRateLimitStore(rateLimits)),
    Layer.succeed(IdentifierStore)(memoryIdentifierStore(identifierRecords)),
    Layer.succeed(EmailPasswordStore)(memoryEmailPasswordStore()),
    Layer.succeed(EmailOtp.EmailOtpUserStore)({ createUser: unused }),
    Layer.succeed(MagicLink.MagicLinkUserStore)({ createUser: unused }),
    Layer.succeed(PhoneOtp.PhoneOtpUserStore)({ createUser: unused }),
    Layer.succeed(PhoneOtp.PhoneOtpStore)(memoryPhoneOtpStore()),
    Layer.succeed(PasswordReset.PasswordResetUserStore)({ setPasswordHash: () => Effect.void }),
    Layer.succeed(Password.PasswordHasher)(Password.pbkdf2Hasher({ iterations: 1000 })),
    Layer.mergeAll(
      EmailOtpStoreKV,
      MagicLinkStoreKV,
      PasswordResetStoreKV,
      EmailVerificationStoreKV,
    ).pipe(Layer.provide(KeyValueStore.layerMemory)),
    Hooks.Default,
    inlineDeliveryScheduler,
    PlatformCrypto.layer,
    TestClock.layer(),
  );
  return { rateLimits, sent, layer };
};

type World = ReturnType<typeof makeWorld>;
type Deps = Layer.Success<World["layer"]>;

/** Send one message to `recipient`; a refusal is the failure. */
type Send = (recipient: string) => Effect.Effect<void, SendError>;

/** What every path's errors have: a tag and a message. */
interface SendError {
  readonly _tag: string;
  readonly message: string;
}

/** The cap option a path's service is built with, plus its cooldown (0: off). */
interface Build {
  readonly recipientSendLimit?: RecipientSendLimit | false | undefined;
  readonly resendCooldown: number;
}

interface SendPath {
  readonly name: string;
  /** The purpose in the cap's key. */
  readonly purpose: string;
  readonly known: string;
  readonly unknown: string;
  /** Whether the path sends nothing to a recipient with no account. */
  readonly hidesAccount: boolean;
  /** Another spelling of `known` that normalizes to it. */
  readonly knownSpelling?: string | undefined;
  readonly make: (world: World, build: Build) => Effect.Effect<Send, never, Deps>;
}

const record = (world: World) => (to: string) => Effect.sync(() => void world.sent.push(to));

const emailOtpPath = (purpose: EmailOtp.EmailOtpPurpose): SendPath => ({
  name: `email OTP ${purpose}`,
  hidesAccount: purpose !== "email-verification",
  purpose: `email-otp:${purpose}`,
  known: memberEmail,
  unknown: "missing@example.com",
  knownSpelling: "  Member@Example.COM ",
  make: (world, build) =>
    Effect.map(
      EmailOtp.make({
        ...build,
        disableSignUp: true,
        sendVerificationOtp: (email) => record(world)(email),
      }),
      (service) => (to) => service.send(to, purpose),
    ),
});

const phoneOtpPath = (purpose: PhoneOtp.PhoneOtpPurpose): SendPath => ({
  name: `phone OTP ${purpose}`,
  hidesAccount: purpose === "sign-in",
  purpose: `phone-otp:${purpose}`,
  known: memberPhone,
  unknown: "+15550000002",
  make: (world, build) =>
    Effect.map(
      PhoneOtp.make({
        ...build,
        disableSignUp: true,
        sendOtp: (phoneNumber) => record(world)(phoneNumber),
      }),
      (service) => (to) => service.send(to, purpose),
    ),
});

const paths: ReadonlyArray<SendPath> = [
  emailOtpPath("sign-in"),
  emailOtpPath("email-verification"),
  emailOtpPath("forget-password"),
  phoneOtpPath("sign-in"),
  phoneOtpPath("phone-verification"),
  {
    name: "magic link",
    hidesAccount: true,
    purpose: "magic-link",
    known: memberEmail,
    unknown: "missing@example.com",
    knownSpelling: "MEMBER@example.com",
    make: (world, build) =>
      Effect.map(
        MagicLink.make({
          ...build,
          disableSignUp: true,
          sendMagicLink: (email) => record(world)(email),
        }),
        (service) => (to) => service.send(to),
      ),
  },
  {
    name: "password reset",
    hidesAccount: true,
    purpose: "password-reset",
    known: memberEmail,
    unknown: "missing@example.com",
    knownSpelling: " member@EXAMPLE.com",
    // The reset has no cooldown of its own.
    make: (world, { recipientSendLimit }) =>
      Effect.map(
        PasswordReset.make({
          ...(recipientSendLimit !== undefined && { recipientSendLimit }),
          sendResetPassword: (email) => record(world)(email),
        }),
        (service) => (to) => service.requestPasswordReset(to),
      ),
  },
];

/** Run `program` over a fresh world, the clock at {@link START}. */
const run = <A, E>(
  program: (world: World) => Effect.Effect<A, E, Deps>,
): Promise<{ readonly result: A; readonly world: World }> => {
  const world = makeWorld();
  return Effect.runPromise(
    Effect.gen(function* () {
      yield* TestClock.setTime(START);
      return yield* program(world);
    }).pipe(
      Effect.map((result) => ({ result, world })),
      Effect.provide(world.layer),
    ),
  );
};

/** `count` sends to `recipient`, each outcome as its tag and message (`"ok"` on success). */
const sendTimes = (send: Send, recipient: string, count: number) =>
  Effect.forEach(
    Arr.range(1, count),
    () =>
      Effect.result(send(recipient)).pipe(
        Effect.map((outcome) =>
          Result.isSuccess(outcome)
            ? "ok"
            : outcome.failure._tag === "RateLimitError"
              ? `RateLimitError: ${outcome.failure.message}`
              : `unexpected: ${outcome.failure._tag}`,
        ),
      ),
    { concurrency: 1 },
  );

const entryCount = (world: World, purpose: string, recipient: string): number | undefined =>
  Option.getOrUndefined(MutableHashMap.get(world.rateLimits, recipientSendKey(purpose, recipient)))
    ?.count;

const ok5 = ["ok", "ok", "ok", "ok", "ok"];
const capped = "RateLimitError: Too many messages sent to this recipient; try again later";

describe.each(paths)("recipient send cap (#684): $name", (path) => {
  const noCooldown: Build = { resendCooldown: 0 };

  it("refuses the 6th send in the window with a RateLimitError carrying retryAfter", async () => {
    const { result, world } = await run((w) =>
      Effect.gen(function* () {
        const send = yield* path.make(w, noCooldown);
        const outcomes = yield* sendTimes(send, path.known, 5);
        const refused = yield* Effect.flip(send(path.known));
        return { outcomes, refused };
      }),
    );
    expect(result.outcomes).toEqual(ok5);
    assert(P.isTagged(result.refused, "RateLimitError"));
    assert(isRecipientSendCapped(result.refused));
    const retryAfter = P.hasProperty(result.refused, "retryAfter")
      ? result.refused.retryAfter
      : undefined;
    assert(Duration.isDuration(retryAfter));
    expect(Duration.toMillis(retryAfter)).toBe(HOUR);
    // Five messages went to the known recipient; the refused one sent nothing.
    expect(world.sent).toEqual(Arr.makeBy(5, () => path.known));
    expect(entryCount(world, path.purpose, path.known)).toBe(6);
  });

  it("caps a known and an unknown recipient alike: the same answers and the same count", async () => {
    const { result, world } = await run((w) =>
      Effect.gen(function* () {
        const send = yield* path.make(w, noCooldown);
        return {
          known: yield* sendTimes(send, path.known, 7),
          unknown: yield* sendTimes(send, path.unknown, 7),
        };
      }),
    );
    expect(result.unknown).toEqual(result.known);
    expect(result.known).toEqual([...ok5, capped, capped]);
    expect(entryCount(world, path.purpose, path.unknown)).toBe(
      entryCount(world, path.purpose, path.known),
    );
    // Five messages to the known recipient; as many to the unknown one only
    // where the path sends to an address with no account.
    expect(world.sent.filter((to) => to === path.known)).toHaveLength(5);
    expect(world.sent.filter((to) => to === path.unknown)).toHaveLength(path.hidesAccount ? 0 : 5);
  });

  it("opens again when the window ends", async () => {
    const { result } = await run((w) =>
      Effect.gen(function* () {
        const send = yield* path.make(w, noCooldown);
        const first = yield* sendTimes(send, path.known, 6);
        yield* TestClock.adjust(Duration.millis(HOUR));
        const next = yield* sendTimes(send, path.known, 6);
        return { first, next };
      }),
    );
    expect(result.first).toEqual([...ok5, capped]);
    expect(result.next).toEqual([...ok5, capped]);
  });

  it("counts every send the cooldown lets through, under the defaults", async () => {
    const { result } = await run((w) =>
      Effect.gen(function* () {
        // The default cooldown (none for the reset) and the default cap.
        const send = yield* path.make(w, { resendCooldown: 60_000 });
        return yield* Effect.forEach(
          Arr.range(1, 6),
          () =>
            sendTimes(send, path.known, 1).pipe(
              Effect.tap(() => TestClock.adjust(Duration.seconds(61))),
            ),
          { concurrency: 1 },
        );
      }),
    );
    expect(result.flat()).toEqual([...ok5, capped]);
  });

  it("takes its own limit, and counts nothing under false", async () => {
    const { result, world } = await run((w) =>
      Effect.gen(function* () {
        const two = yield* path.make(w, {
          ...noCooldown,
          recipientSendLimit: { max: 2, windowMs: 10 * 60_000 },
        });
        const limited = yield* sendTimes(two, path.unknown, 3);
        const off = yield* path.make(w, { ...noCooldown, recipientSendLimit: false });
        const unlimited = yield* sendTimes(off, path.known, 12);
        return { limited, unlimited };
      }),
    );
    expect(result.limited).toEqual(["ok", "ok", capped]);
    expect(result.unlimited).toEqual(Arr.makeBy(12, () => "ok"));
    expect(entryCount(world, path.purpose, path.known)).toBeUndefined();
  });

  it("keys the count on the recipient's digest, never the raw address", async () => {
    const { world } = await run((w) =>
      Effect.gen(function* () {
        const send = yield* path.make(w, noCooldown);
        yield* send(path.known);
        yield* send(path.unknown);
        if (path.knownSpelling !== undefined) yield* send(path.knownSpelling);
      }),
    );
    const keys = Arr.fromIterable(MutableHashMap.keys(world.rateLimits));
    expect(keys.toSorted()).toEqual(
      [
        `recipient-send:${path.purpose}:${hashToken(path.known)}`,
        `recipient-send:${path.purpose}:${hashToken(path.unknown)}`,
      ].toSorted(),
    );
    const raw = [path.known, path.unknown, path.known.split("@")[0] ?? path.known];
    expect(keys.some((key) => raw.some((address) => key.includes(address)))).toBe(false);
    // Another spelling of the same address counts against the same key.
    expect(entryCount(world, path.purpose, path.known)).toBe(
      path.knownSpelling === undefined ? 1 : 2,
    );
  });
});

/** The unverified user's verification resend, built with `build`. */
const makeResend = (build: Build) =>
  Effect.map(
    EmailVerification.make({ ...build, sendEmail: (to) => Effect.sync(() => void to) }),
    (service) => (email: string) => service.resendVerification("user-unverified", email),
  );

/** A `RateLimitError` under `key`. */
const limitedUnder = (key: string) => new RateLimitError({ message: "limited", key });

describe("recipient send cap (#684): email verification resend", () => {
  it("refuses the 6th resend, sends nothing then, and opens again after the window", async () => {
    const { result, world } = await run(() =>
      Effect.gen(function* () {
        const resend = yield* makeResend({ resendCooldown: 0 });
        const first = yield* sendTimes(resend, unverifiedEmail, 6);
        yield* TestClock.adjust(Duration.millis(HOUR));
        const next = yield* sendTimes(resend, unverifiedEmail, 1);
        return { first, next };
      }),
    );
    expect(result.first).toEqual([...ok5, capped]);
    expect(result.next).toEqual(["ok"]);
    expect(Arr.fromIterable(MutableHashMap.keys(world.rateLimits))).toEqual([
      `recipient-send:email-verification:${hashToken(unverifiedEmail)}`,
    ]);
  });

  it("counts nothing under false", async () => {
    const { result, world } = await run(() =>
      Effect.gen(function* () {
        const resend = yield* makeResend({ resendCooldown: 0, recipientSendLimit: false });
        return yield* sendTimes(resend, unverifiedEmail, 8);
      }),
    );
    expect(result).toEqual(Arr.makeBy(8, () => "ok"));
    expect(MutableHashMap.size(world.rateLimits)).toBe(0);
  });
});

describe("isRecipientSendCapped", () => {
  it("tells the cap's refusal from any other rate limit", () => {
    expect(defaultRecipientSendLimit).toEqual({ max: 5, windowMs: HOUR });
    expect(isRecipientSendCapped(limitedUnder(recipientSendKey("magic-link", "a")))).toBe(true);
    expect(isRecipientSendCapped(limitedUnder("ip:signin:203.0.113.7"))).toBe(false);
    expect(
      isRecipientSendCapped(
        new ResendTooSoonError({ message: "wait", retryAfter: Duration.seconds(1) }),
      ),
    ).toBe(false);
  });
});
