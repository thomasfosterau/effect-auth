import { describe, it, expect } from "vite-plus/test";
import { Effect, Redacted } from "effect";
import { SmsSender, type SmsMessage } from "@thomasfosterau/effect-auth";
import { defaultRender, layer, twilioSmsSender } from "./index.ts";

const run = <A, E>(effect: Effect.Effect<A, E>): Promise<A> => Effect.runPromise(effect);

interface CapturedRequest {
  readonly url: string;
  readonly init: RequestInit;
}

/** A stub `fetch` that records every call and replies with a fixed `Response`. */
const stubFetch = (
  response: Response | ((request: CapturedRequest) => Response),
): { readonly fetch: typeof fetch; readonly calls: CapturedRequest[] } => {
  const calls: CapturedRequest[] = [];
  // `RequestInfo` is not a global under `types: ["node"]`; take fetch's own
  // input type instead of naming the DOM alias.
  const fetchStub = (async (input: Parameters<typeof fetch>[0], init?: RequestInit) => {
    const request = { url: String(input), init: init ?? {} };
    calls.push(request);
    return typeof response === "function" ? response(request) : response;
  }) as typeof fetch;
  return { fetch: fetchStub, calls };
};

const baseConfig = {
  accountSid: "ACtest0000000000000000000000000",
  authToken: Redacted.make("test-auth-token"),
  from: "+15551234567",
};

const twilioSuccessBody = JSON.stringify({ sid: "SM1234", status: "queued" });

describe("defaultRender", () => {
  it("uses a purpose-keyed lead-in and includes the OTP", () => {
    const message: SmsMessage = {
      to: "+15559876543",
      purpose: "phone-otp:sign-in",
      params: { otp: "654321" },
    };
    expect(defaultRender(message)).toBe("Your verification code: 654321");
  });

  it("falls back to the token when there is no otp", () => {
    const message: SmsMessage = {
      to: "+15559876543",
      purpose: "second-factor-otp",
      params: { token: "tok" },
    };
    expect(defaultRender(message)).toBe("Your verification code: tok");
  });

  it("has a generic body for an unrecognized purpose with no otp/token", () => {
    expect(defaultRender({ to: "+1", purpose: "custom", params: {} })).toBe("Message");
  });
});

describe("twilioSmsSender", () => {
  it("posts to Twilio with Basic auth and form-encoded Body/From/To", async () => {
    const { fetch, calls } = stubFetch(new Response(twilioSuccessBody, { status: 201 }));
    const sender = twilioSmsSender({ ...baseConfig, fetch });

    await run(
      sender.send({ to: "+15559876543", purpose: "phone-otp:sign-in", params: { otp: "654321" } }),
    );

    expect(calls).toHaveLength(1);
    const [request] = calls;
    expect(request!.url).toBe(
      `https://api.twilio.com/2010-04-01/Accounts/${baseConfig.accountSid}/Messages.json`,
    );
    expect(request!.init.method).toBe("POST");

    const headers = new Headers(request!.init.headers);
    expect(headers.get("Authorization")).toBe(
      `Basic ${Buffer.from(`${baseConfig.accountSid}:test-auth-token`).toString("base64")}`,
    );
    expect(headers.get("Content-Type")).toBe("application/x-www-form-urlencoded");

    const form = new URLSearchParams(request!.init.body as string);
    expect(form.get("Body")).toBe("Your verification code: 654321");
    expect(form.get("From")).toBe("+15551234567");
    expect(form.get("To")).toBe("+15559876543");
  });

  it("uses a custom render function when provided", async () => {
    const { fetch, calls } = stubFetch(new Response(twilioSuccessBody, { status: 201 }));
    const sender = twilioSmsSender({ ...baseConfig, fetch, render: () => "Custom body" });

    await run(sender.send({ to: "+1", purpose: "second-factor-otp", params: { otp: "1" } }));

    const form = new URLSearchParams(calls[0]!.init.body as string);
    expect(form.get("Body")).toBe("Custom body");
  });

  it("honours a baseUrl override", async () => {
    const { fetch, calls } = stubFetch(new Response(twilioSuccessBody, { status: 201 }));
    const sender = twilioSmsSender({ ...baseConfig, fetch, baseUrl: "https://stub.local" });

    await run(sender.send({ to: "+1", purpose: "second-factor-otp", params: { otp: "1" } }));

    expect(calls[0]!.url).toBe(
      `https://stub.local/2010-04-01/Accounts/${baseConfig.accountSid}/Messages.json`,
    );
  });

  it("never leaks the auth token onto a failure", async () => {
    const { fetch } = stubFetch(
      new Response(JSON.stringify({ code: 21211, message: "Invalid 'To' Phone Number" }), {
        status: 400,
      }),
    );
    const sender = twilioSmsSender({ ...baseConfig, fetch });

    const err = await run(
      Effect.flip(sender.send({ to: "bad", purpose: "second-factor-otp", params: { otp: "1" } })),
    );

    expect(err._tag).toBe("AuthError");
    expect(JSON.stringify(err)).not.toContain("test-auth-token");
  });

  it("maps a 4xx response to an AuthError with Twilio's error code and message", async () => {
    const { fetch } = stubFetch(
      new Response(JSON.stringify({ code: 21211, message: "Invalid 'To' Phone Number" }), {
        status: 400,
      }),
    );
    const sender = twilioSmsSender({ ...baseConfig, fetch });

    const err = await run(
      Effect.flip(sender.send({ to: "bad", purpose: "second-factor-otp", params: { otp: "1" } })),
    );

    expect(err._tag).toBe("AuthError");
    expect(err.message).toContain("21211");
    expect(err.message).toContain("Invalid 'To' Phone Number");
    expect(err.cause).toMatchObject({ status: 400 });
  });

  it("maps a 5xx response without a parseable body to an AuthError with the raw status", async () => {
    const { fetch } = stubFetch(new Response("internal error", { status: 500 }));
    const sender = twilioSmsSender({ ...baseConfig, fetch });

    const err = await run(
      Effect.flip(sender.send({ to: "+1", purpose: "second-factor-otp", params: { otp: "1" } })),
    );

    expect(err._tag).toBe("AuthError");
    expect(err.message).toContain("500");
  });

  it("maps a network failure to an AuthError", async () => {
    const failingFetch = (async () => {
      throw new Error("network down");
    }) as typeof fetch;
    const sender = twilioSmsSender({ ...baseConfig, fetch: failingFetch });

    const err = await run(
      Effect.flip(sender.send({ to: "+1", purpose: "second-factor-otp", params: { otp: "1" } })),
    );

    expect(err._tag).toBe("AuthError");
    expect(err.message).toContain("Twilio API");
  });
});

describe("layer", () => {
  it("provides the SmsSender service", async () => {
    const { fetch, calls } = stubFetch(new Response(twilioSuccessBody, { status: 201 }));

    const program = Effect.gen(function* () {
      const sender = yield* SmsSender;
      yield* sender.send({ to: "+1", purpose: "second-factor-otp", params: { otp: "1" } });
    });

    await run(Effect.provide(program, layer({ ...baseConfig, fetch })));
    expect(calls).toHaveLength(1);
  });
});
