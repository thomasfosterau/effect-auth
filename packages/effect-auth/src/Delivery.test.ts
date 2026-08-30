import { describe, it, expect } from "vite-plus/test";
import { Effect } from "effect";
import {
  EmailSender,
  SMSSender,
  emailCallbacks,
  smsCallbacks,
  type EmailMessage,
  type SMSMessage,
} from "./Delivery.ts";
import { AuthError, EmailVerificationError, MagicLinkError, PasswordResetError } from "./Errors.ts";
import type * as Types from "./Types.ts";

const user = (attributes: Record<string, unknown> = {}): Types.User => ({
  id: "u1",
  email: "alice@example.com",
  emailVerified: true,
  createdAt: new Date(),
  updatedAt: new Date(),
  attributes,
});

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
    const cb = emailCallbacks(sender);

    await Effect.runPromise(cb.sendVerificationEmail("a@example.com", "tok-1"));
    await Effect.runPromise(cb.sendMagicLink("b@example.com", "tok-2"));
    await Effect.runPromise(cb.sendVerificationOTP("c@example.com", "123456", "sign-in"));
    await Effect.runPromise(cb.sendResetPassword("d@example.com", "tok-3"));
    await Effect.runPromise(
      cb.sendChangeEmailVerification({ user: user(), newEmail: "new@example.com", token: "tok-4" }),
    );
    await Effect.runPromise(cb.sendDeleteAccountVerification({ user: user(), token: "tok-5" }));
    await Effect.runPromise(cb.sendSecondFactorOTP(user(), "654321"));

    expect(sent).toEqual([
      { to: "a@example.com", purpose: "email-verification", params: { token: "tok-1" } },
      { to: "b@example.com", purpose: "magic-link", params: { token: "tok-2" } },
      { to: "c@example.com", purpose: "email-otp:sign-in", params: { otp: "123456" } },
      { to: "d@example.com", purpose: "password-reset", params: { token: "tok-3" } },
      {
        to: "new@example.com",
        purpose: "change-email",
        params: { token: "tok-4", currentEmail: "alice@example.com" },
      },
      { to: "alice@example.com", purpose: "delete-account", params: { token: "tok-5" } },
      { to: "alice@example.com", purpose: "second-factor-otp", params: { otp: "654321" } },
    ]);
  });

  it("maps sender failures to each feature's error type with cause preserved", async () => {
    const cb = emailCallbacks(failingEmailSender);

    const verification = await Effect.runPromise(
      Effect.flip(cb.sendVerificationEmail("a@example.com", "t")),
    );
    expect(verification).toBeInstanceOf(EmailVerificationError);
    expect(verification.cause).toBeInstanceOf(AuthError);

    const magic = await Effect.runPromise(Effect.flip(cb.sendMagicLink("a@example.com", "t")));
    expect(magic).toBeInstanceOf(MagicLinkError);

    const reset = await Effect.runPromise(Effect.flip(cb.sendResetPassword("a@example.com", "t")));
    expect(reset).toBeInstanceOf(PasswordResetError);

    const otp = await Effect.runPromise(
      Effect.flip(cb.sendVerificationOTP("a@example.com", "1", "sign-in")),
    );
    expect(otp).toBeInstanceOf(AuthError);
  });
});

describe("smsCallbacks", () => {
  it("routes phone OTP and second-factor OTP through the sender", async () => {
    const sent: SMSMessage[] = [];
    const sender: typeof SMSSender.Service = {
      send: (message) => Effect.sync(() => void sent.push(message)),
    };
    const cb = smsCallbacks(sender);

    await Effect.runPromise(cb.sendPhoneOTP("+15551234567", "111222", "sign-in"));
    await Effect.runPromise(
      cb.sendSecondFactorOTP(user({ phoneNumber: "+15559876543" }), "333444"),
    );

    expect(sent).toEqual([
      { to: "+15551234567", purpose: "phone-otp:sign-in", params: { otp: "111222" } },
      { to: "+15559876543", purpose: "second-factor-otp", params: { otp: "333444" } },
    ]);
  });

  it("fails when the user has no phone number for second-factor OTP", async () => {
    const sender: typeof SMSSender.Service = { send: () => Effect.void };
    const cb = smsCallbacks(sender);

    const error = await Effect.runPromise(Effect.flip(cb.sendSecondFactorOTP(user(), "1")));
    expect(error).toBeInstanceOf(AuthError);
    expect(error.message).toMatch(/no phone number/);
  });
});
