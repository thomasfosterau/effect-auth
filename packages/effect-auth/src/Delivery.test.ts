import { describe, it, expect } from "vite-plus/test";
import { Array as Arr, DateTime, Effect, Layer, Logger, Schema } from "effect";
import {
  EmailSender,
  SmsSender,
  emailCallbacks,
  smsCallbacks,
  type EmailMessage,
  type SmsMessage,
} from "./Delivery.ts";
import { AuthError } from "./Errors.ts";
import {
  makeIdentifier,
  memoryIdentifierStore,
  type Identifier,
  type IdentifierType,
} from "./Identifier.ts";
import type * as Types from "./Types.ts";

const user = (attributes: Types.Attributes = {}): Types.User => ({
  id: "u1",
  createdAt: DateTime.toDateUtc(DateTime.nowUnsafe()),
  updatedAt: DateTime.toDateUtc(DateTime.nowUnsafe()),
  attributes,
});

/** An in-memory IdentifierStore pre-seeded with identifiers for user `u1`. */
const identifierStoreWith = (
  ...entries: Array<{ type: IdentifierType; value: string; verified?: boolean }>
) => {
  const records = new Map<string, Identifier>();
  Arr.forEach(entries, (entry) => {
    const identifier = makeIdentifier({
      userId: "u1",
      type: entry.type,
      value: entry.value,
      verified: entry.verified ?? true,
    });
    records.set(identifier.id, identifier);
  });
  return memoryIdentifierStore(records);
};

const captureEmailSender = () => {
  const sent: EmailMessage[] = [];
  const sender: typeof EmailSender.Service = {
    send: (message) => Effect.sync(() => void sent.push(message)),
  };
  return { sent, sender };
};

const failingEmailSender: typeof EmailSender.Service = {
  send: () => Effect.fail(new AuthError({ message: "provider down" })),
};

describe("emailCallbacks", () => {
  it("routes every email flow through the sender with stable purposes", async () => {
    const { sent, sender } = captureEmailSender();
    const cb = emailCallbacks(
      sender,
      identifierStoreWith({ type: "email", value: "alice@example.com" }),
    );

    await Effect.runPromise(cb.sendVerificationEmail("a@example.com", "tok-1"));
    await Effect.runPromise(cb.sendMagicLink("b@example.com", "tok-2"));
    await Effect.runPromise(cb.sendVerificationOtp("c@example.com", "123456", "sign-in"));
    await Effect.runPromise(cb.sendResetPassword("d@example.com", "tok-3"));
    await Effect.runPromise(
      cb.sendChangeEmailVerification({ user: user(), newEmail: "new@example.com", token: "tok-4" }),
    );
    await Effect.runPromise(
      cb.sendDeleteAccountVerification({
        user: user(),
        email: "alice@example.com",
        token: "tok-5",
      }),
    );
    await Effect.runPromise(cb.sendSecondFactorOtp(user(), "654321"));
    await Effect.runPromise(cb.sendExistingAccountNotice("e@example.com"));

    expect(sent).toEqual([
      { to: "a@example.com", purpose: "email-verification", params: { token: "tok-1" } },
      { to: "b@example.com", purpose: "magic-link", params: { token: "tok-2" } },
      { to: "c@example.com", purpose: "email-otp:sign-in", params: { otp: "123456" } },
      { to: "d@example.com", purpose: "password-reset", params: { token: "tok-3" } },
      { to: "new@example.com", purpose: "change-email", params: { token: "tok-4" } },
      { to: "alice@example.com", purpose: "delete-account", params: { token: "tok-5" } },
      { to: "alice@example.com", purpose: "second-factor-otp", params: { otp: "654321" } },
      { to: "e@example.com", purpose: "existing-account", params: {} },
    ]);
  });

  it("fails when the user has no email identifier for email-bound deliveries", async () => {
    const { sent, sender } = captureEmailSender();
    const cb = emailCallbacks(sender, identifierStoreWith());

    // These fail before ever reaching the sender (no address to dispatch
    // to), so — unlike a send failure — they still surface synchronously.
    const otpError = await Effect.runPromise(Effect.flip(cb.sendSecondFactorOtp(user(), "1")));
    expect(otpError).toBeInstanceOf(AuthError);
    expect(otpError.message).toMatch(/no email/);

    const deleteError = await Effect.runPromise(
      Effect.flip(cb.sendDeleteAccountVerification({ user: user(), email: null, token: "t" })),
    );
    expect(deleteError).toBeInstanceOf(AuthError);
    expect(deleteError.message).toMatch(/no email/);

    expect(sent).toEqual([]);
  });

  it("awaits the send, so a failed send fails the caller", async () => {
    const cb = emailCallbacks(failingEmailSender, identifierStoreWith());

    const error = await Effect.runPromise(Effect.flip(cb.sendMagicLink("a@example.com", "t")));

    expect(error).toBeInstanceOf(AuthError);
    expect(error.message).toBe("provider down");
  });
});

describe("smsCallbacks", () => {
  it("routes phone OTP and second-factor OTP through the sender", async () => {
    const sent: SmsMessage[] = [];
    const sender: typeof SmsSender.Service = {
      send: (message) => Effect.sync(() => void sent.push(message)),
    };
    const cb = smsCallbacks(sender, identifierStoreWith({ type: "phone", value: "+15559876543" }));

    await Effect.runPromise(cb.sendPhoneOtp("+15551234567", "111222", "sign-in"));
    await Effect.runPromise(cb.sendSecondFactorOtp(user(), "333444"));

    expect(sent).toEqual([
      { to: "+15551234567", purpose: "phone-otp:sign-in", params: { otp: "111222" } },
      { to: "+15559876543", purpose: "second-factor-otp", params: { otp: "333444" } },
    ]);
  });

  it("fails when the user has no phone number for second-factor OTP", async () => {
    const sender: typeof SmsSender.Service = { send: () => Effect.void };
    const cb = smsCallbacks(sender, identifierStoreWith());

    const error = await Effect.runPromise(Effect.flip(cb.sendSecondFactorOtp(user(), "1")));
    expect(error).toBeInstanceOf(AuthError);
    expect(error.message).toMatch(/no phone number/);
  });
});

const encodeJson = Schema.encodeSync(Schema.fromJsonString(Schema.Unknown));

describe("logging transports", () => {
  it("send nothing and log the recipient and purpose, never the params", async () => {
    const lines: unknown[] = [];
    const capture = Logger.layer([Logger.make(({ message }) => void lines.push(message))]);

    await Effect.runPromise(
      Effect.gen(function* () {
        const email = yield* EmailSender;
        const sms = yield* SmsSender;
        yield* email.send({
          to: "a@example.com",
          purpose: "magic-link",
          params: { token: "secret-token" },
        });
        yield* sms.send({
          to: "+61400000000",
          purpose: "phone-otp:sign-in",
          params: { otp: "123456" },
        });
      }).pipe(Effect.provide(Layer.mergeAll(EmailSender.logging, SmsSender.logging, capture))),
    );

    const logged = encodeJson(lines);
    expect(lines).toHaveLength(2);
    expect(logged).toContain("a@example.com");
    expect(logged).toContain("magic-link");
    expect(logged).toContain("phone-otp:sign-in");
    expect(logged).not.toContain("secret-token");
    expect(logged).not.toContain("123456");
  });
});
