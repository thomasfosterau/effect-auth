import { describe, it, expect } from "vite-plus/test";
import { Effect, Metric } from "effect";
import {
  EmailSender,
  SmsSender,
  emailCallbacks,
  smsCallbacks,
  type EmailMessage,
  type SmsMessage,
} from "./Delivery.ts";
import { AuthError } from "./Errors.ts";
import * as Obs from "./Observability.ts";
import {
  makeIdentifier,
  memoryIdentifierStore,
  type Identifier,
  type IdentifierType,
} from "./Identifier.ts";
import type * as Types from "./Types.ts";

const user = (attributes: Types.Attributes = {}): Types.User => ({
  id: "u1",
  createdAt: new Date(),
  updatedAt: new Date(),
  attributes,
});

/** An in-memory IdentifierStore pre-seeded with identifiers for user `u1`. */
const identifierStoreWith = (
  ...entries: Array<{ type: IdentifierType; value: string; verified?: boolean }>
) => {
  const records = new Map<string, Identifier>();
  for (const entry of entries) {
    const identifier = makeIdentifier({
      userId: "u1",
      type: entry.type,
      value: entry.value,
      verified: entry.verified ?? true,
    });
    records.set(identifier.id, identifier);
  }
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

/**
 * Every send in `emailCallbacks`/`smsCallbacks` now runs on its own detached
 * fiber (see `dispatch` in `Delivery.ts`) instead of being awaited inline,
 * so the callback's own promise settles before the send necessarily has.
 * Give the scheduler a few real turns to run the forked fiber before
 * asserting on its side effects.
 */
const flushDispatched = async (turns = 10): Promise<void> => {
  for (let i = 0; i < turns; i++) {
    await new Promise<void>((resolve) => setImmediate(resolve));
  }
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

    await flushDispatched();

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

    await flushDispatched();
    expect(sent).toEqual([]);
  });

  it("does not await the send — the caller returns even if the send never resolves", async () => {
    const neverSender: typeof EmailSender.Service = { send: () => Effect.never };
    const cb = emailCallbacks(neverSender, identifierStoreWith());

    // If the send were awaited inline (the pre-fix behaviour), this would
    // hang forever. Racing against a short timeout proves it doesn't.
    const outcome = await Promise.race([
      Effect.runPromise(cb.sendVerificationEmail("a@example.com", "t")).then(
        () => "resolved" as const,
      ),
      new Promise<"timeout">((resolve) => setTimeout(() => resolve("timeout"), 250)),
    ]);

    expect(outcome).toBe("resolved");
  });

  it("swallows sender failures instead of surfacing them to the caller, but still counts them", async () => {
    const cb = emailCallbacks(failingEmailSender, identifierStoreWith());
    const failureMetric = Metric.withAttributes(Obs.deliverySends, {
      purpose: "email-verification",
      outcome: "failure",
    });
    const before = await Effect.runPromise(Metric.value(failureMetric));

    // A send that fails must not fail the flow that triggered it.
    const outcome = await Effect.runPromise(cb.sendVerificationEmail("a@example.com", "t"));
    expect(outcome).toBeUndefined();

    await flushDispatched();

    // ...but it must still be observable somewhere.
    const after = await Effect.runPromise(Metric.value(failureMetric));
    expect(after.count).toBe(before.count + 1);
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

    await flushDispatched();

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
