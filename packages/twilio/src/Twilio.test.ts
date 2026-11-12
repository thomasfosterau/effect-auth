import { createServer } from "node:http";
import { assert, describe, it, expect, onTestFinished } from "vite-plus/test";
import { Cause, Data, Effect, Exit, Redacted } from "effect";
import * as Option from "effect/Option";
import * as P from "effect/Predicate";
import * as Schema from "effect/Schema";
import { SmsSender, type SmsMessage } from "@thomasfosterau/effect-auth";
import {
  MAX_ERROR_BODY_CHARS,
  TRUNCATION_MARKER,
  defaultRender,
  layer,
  twilioSmsSender,
} from "./index.ts";

const run = <A, E>(effect: Effect.Effect<A, E>): Promise<A> => Effect.runPromise(effect);

const toJson = Schema.encodeSync(Schema.fromJsonString(Schema.Unknown));

/** What the failing stub `fetch` rejects with. */
class NetworkDown extends Data.TaggedError("NetworkDown") {}

interface CapturedRequest {
  readonly url: string;
  readonly init: RequestInit;
}

/** A stub `fetch` that records every call and replies with a fixed `Response`. */
const stubFetch = (
  response: Response | ((request: CapturedRequest) => Response),
): { readonly fetch: typeof fetch; readonly calls: CapturedRequest[] } => {
  const calls: CapturedRequest[] = [];
  const fetchStub: typeof fetch = async (input, init) => {
    const url = P.isString(input) ? input : input instanceof URL ? input.href : input.url;
    const request = { url, init: init ?? {} };
    calls.push(request);
    return P.isFunction(response) ? response(request) : response;
  };
  return { fetch: fetchStub, calls };
};

/** The form a captured request sent, which the sender encodes as a string. */
const formOf = (request: CapturedRequest): URLSearchParams => {
  const body = request.init.body;
  assert(P.isString(body), "the form body is sent as a string");
  return new URLSearchParams(body);
};

const baseConfig = {
  accountSid: "ACtest0000000000000000000000000",
  authToken: Redacted.make("test-auth-token"),
  from: "+15551234567",
};

const twilioSuccessBody = toJson({ sid: "SM1234", status: "queued" });

/** The Basic credentials `baseConfig` sends, which an echo must not reveal either. */
const basicCredentials = Buffer.from(`${baseConfig.accountSid}:test-auth-token`).toString("base64");

/** The `body` an `AuthError`'s `{ status, body }` cause carries. */
const causeBody = (cause: unknown): string => {
  assert(P.isObject(cause) && "body" in cause && P.isString(cause.body), "cause has a body");
  return cause.body;
};

/** A body stream that never ends, recording whether the reader cancelled it. */
const endlessBody = (): { readonly stream: ReadableStream<Uint8Array>; cancelled: boolean } => {
  const chunk = new TextEncoder().encode("x".repeat(4096));
  const state = {
    cancelled: false,
    stream: new ReadableStream<Uint8Array>({
      pull: (controller) => controller.enqueue(chunk),
      cancel: () => {
        state.cancelled = true;
      },
    }),
  };
  return state;
};

/**
 * Start a local server that answers every request outside `/landed` with a
 * 307 to `/landed`, counting the requests it receives. It closes when the
 * test finishes.
 */
const startRedirectingServer = async (): Promise<{
  readonly baseUrl: string;
  readonly hits: () => number;
}> => {
  let hits = 0;
  const server = createServer((request, response) => {
    hits += 1;
    if (request.url === "/landed") response.writeHead(201).end(twilioSuccessBody);
    else response.writeHead(307, { Location: "/landed" }).end();
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", () => resolve()));
  onTestFinished(
    () =>
      new Promise<void>((resolve) => {
        server.closeAllConnections();
        server.close(() => resolve());
      }),
  );
  const address = server.address();
  assert(P.isNotNull(address) && !P.isString(address), "the server listens on a port");
  return { baseUrl: `http://127.0.0.1:${address.port}`, hits: () => hits };
};

const sendOneTo = (sender: typeof SmsSender.Service) =>
  Effect.flip(sender.send({ to: "+1", purpose: "second-factor-otp", params: { otp: "1" } }));

/** Where the stubbed redirects point; it must never reach an error. */
const REDIRECT_TARGET = "https://elsewhere.example/steal";

/** A redirect `Response` whose body records whether it was cancelled (and never read). */
const redirectResponse = (
  status: number,
): { readonly response: Response; readonly cancelled: () => boolean } => {
  let cancelled = false;
  const body = new ReadableStream<Uint8Array>({
    cancel: () => {
      cancelled = true;
    },
  });
  return {
    response: new Response(body, { status, headers: { Location: REDIRECT_TARGET } }),
    cancelled: () => cancelled,
  };
};

/** A browser's `redirect: "manual"` answer, which `new Response` cannot construct. */
const opaqueRedirect = (): Response =>
  Object.defineProperties(new Response(null), {
    status: { value: 0 },
    type: { value: "opaqueredirect" },
    ok: { value: false },
  });

/** What `brokenBody` errors with mid-read. */
class ConnectionReset extends Data.TaggedError("ConnectionReset") {}

/** A body stream that errors on the first read. */
const brokenBody = (): ReadableStream<Uint8Array> =>
  new ReadableStream<Uint8Array>({
    pull: (controller) => controller.error(new ConnectionReset()),
  });

/** A `fetch` that never settles until its signal aborts, keeping that signal. */
const hangingFetch = (): {
  readonly fetch: typeof fetch;
  readonly signal: () => AbortSignal | undefined;
} => {
  let seen: AbortSignal | undefined;
  const fetchStub: typeof fetch = (_input, init) =>
    new Promise<Response>((_resolve, reject) => {
      seen = init?.signal ?? undefined;
      seen?.addEventListener("abort", () => reject(seen?.reason));
    });
  return { fetch: fetchStub, signal: () => seen };
};

describe("twilioSmsSender's outbound request (#606)", () => {
  it.each([300, 301, 302, 303, 307, 308, 399])(
    "fails a %i as an AuthError with only its status, the body unread",
    async (status) => {
      const redirect = redirectResponse(status);
      const { fetch, calls } = stubFetch(redirect.response);

      const err = await run(sendOneTo(twilioSmsSender({ ...baseConfig, fetch })));

      expect(err._tag).toBe("AuthError");
      expect(err.message).toContain(`redirect (status ${status})`);
      expect(err.cause).toEqual({ status });
      expect(toJson(err)).not.toContain(REDIRECT_TARGET);
      expect(redirect.cancelled()).toBe(true);
      expect(calls).toHaveLength(1);
      expect(calls[0]?.init.redirect).toBe("manual");
      expect(calls[0]?.init.signal).toBeInstanceOf(AbortSignal);
    },
  );

  it("fails a browser's opaque redirect (status 0)", async () => {
    const { fetch, calls } = stubFetch(opaqueRedirect());

    const err = await run(sendOneTo(twilioSmsSender({ ...baseConfig, fetch })));

    expect(err._tag).toBe("AuthError");
    expect(err.cause).toEqual({ status: 0 });
    expect(calls).toHaveLength(1);
  });

  it("fails a real 3xx without a second request", async () => {
    const { baseUrl, hits } = await startRedirectingServer();
    const err = await run(sendOneTo(twilioSmsSender({ ...baseConfig, baseUrl })));

    expect(err._tag).toBe("AuthError");
    expect(err.cause).toEqual({ status: 307 });
    expect(hits()).toBe(1);
    expect(toJson(err)).not.toContain("test-auth-token");
  });

  it("fails an error body whose stream breaks as an AuthError, not a defect", async () => {
    const { fetch } = stubFetch(new Response(brokenBody(), { status: 500 }));

    const exit = await run(
      Effect.exit(
        twilioSmsSender({ ...baseConfig, fetch }).send({
          to: "+1",
          purpose: "second-factor-otp",
          params: { otp: "1" },
        }),
      ),
    );

    assert(Exit.isFailure(exit));
    const err = Cause.findErrorOption(exit.cause);
    assert(Option.isSome(err), "the send fails with a typed error");
    expect(err.value._tag).toBe("AuthError");
    expect(err.value.message).toContain("error response (status 500)");
  });

  it("aborts the in-flight request when the send is interrupted", async () => {
    const hanging = hangingFetch();
    const sender = twilioSmsSender({ ...baseConfig, fetch: hanging.fetch });

    await run(
      Effect.exit(
        Effect.timeout(
          sender.send({ to: "+1", purpose: "second-factor-otp", params: { otp: "1" } }),
          "20 millis",
        ),
      ),
    );

    const signal = hanging.signal();
    assert(signal !== undefined, "fetch received a signal");
    expect(signal.aborted).toBe(true);
  });

  it("keeps at most MAX_ERROR_BODY_CHARS of a huge error body, in the cause and the message", async () => {
    const { fetch } = stubFetch(new Response("e".repeat(1_000_000), { status: 500 }));

    const err = await run(sendOneTo(twilioSmsSender({ ...baseConfig, fetch })));

    expect(causeBody(err.cause)).toBe(`${"e".repeat(MAX_ERROR_BODY_CHARS)}${TRUNCATION_MARKER}`);
    expect(err.message.length).toBeLessThan(MAX_ERROR_BODY_CHARS + 100);
  });

  it("stops reading an endless error body and cancels it", async () => {
    const endless = endlessBody();
    const { fetch } = stubFetch(new Response(endless.stream, { status: 502 }));

    const err = await run(sendOneTo(twilioSmsSender({ ...baseConfig, fetch })));

    expect(causeBody(err.cause).endsWith(TRUNCATION_MARKER)).toBe(true);
    expect(endless.cancelled).toBe(true);
  });

  it.each([
    ["the token echoed", "unauthorized: token test-auth-token"],
    ["the Basic header echoed", `unauthorized: Authorization: Basic ${basicCredentials}`],
    [
      "the token cut at the limit",
      `${"a".repeat(MAX_ERROR_BODY_CHARS - 4)}test-auth-token${"b".repeat(5000)}`,
    ],
  ])("scrubs the credentials from an error body (%s)", async (_case, text) => {
    const { fetch } = stubFetch(new Response(text, { status: 401 }));

    const err = await run(sendOneTo(twilioSmsSender({ ...baseConfig, fetch })));

    const serialized = toJson(err);
    expect(serialized).not.toContain("test-auth-token");
    expect(serialized).not.toContain(basicCredentials);
    expect(causeBody(err.cause)).not.toContain("test-");
    expect(err.message).not.toContain("test-auth-token");
    expect(err.message).not.toContain(basicCredentials);
  });
});

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
    assert(request !== undefined);
    expect(request.url).toBe(
      `https://api.twilio.com/2010-04-01/Accounts/${baseConfig.accountSid}/Messages.json`,
    );
    expect(request.init.method).toBe("POST");

    const headers = new Headers(request.init.headers);
    expect(headers.get("Authorization")).toBe(
      `Basic ${Buffer.from(`${baseConfig.accountSid}:test-auth-token`).toString("base64")}`,
    );
    expect(headers.get("Content-Type")).toBe("application/x-www-form-urlencoded");

    const form = formOf(request);
    expect(form.get("Body")).toBe("Your verification code: 654321");
    expect(form.get("From")).toBe("+15551234567");
    expect(form.get("To")).toBe("+15559876543");
  });

  it("uses a custom render function when provided", async () => {
    const { fetch, calls } = stubFetch(new Response(twilioSuccessBody, { status: 201 }));
    const sender = twilioSmsSender({ ...baseConfig, fetch, render: () => "Custom body" });

    await run(sender.send({ to: "+1", purpose: "second-factor-otp", params: { otp: "1" } }));

    const [request] = calls;
    assert(request !== undefined);
    const form = formOf(request);
    expect(form.get("Body")).toBe("Custom body");
  });

  it("honours a baseUrl override", async () => {
    const { fetch, calls } = stubFetch(new Response(twilioSuccessBody, { status: 201 }));
    const sender = twilioSmsSender({ ...baseConfig, fetch, baseUrl: "https://stub.local" });

    await run(sender.send({ to: "+1", purpose: "second-factor-otp", params: { otp: "1" } }));

    const [request] = calls;
    assert(request !== undefined);
    expect(request.url).toBe(
      `https://stub.local/2010-04-01/Accounts/${baseConfig.accountSid}/Messages.json`,
    );
  });

  it("never leaks the auth token onto a failure", async () => {
    const { fetch } = stubFetch(
      new Response(toJson({ code: 21211, message: "Invalid 'To' Phone Number" }), {
        status: 400,
      }),
    );
    const sender = twilioSmsSender({ ...baseConfig, fetch });

    const err = await run(
      Effect.flip(sender.send({ to: "bad", purpose: "second-factor-otp", params: { otp: "1" } })),
    );

    expect(err._tag).toBe("AuthError");
    expect(toJson(err)).not.toContain("test-auth-token");
  });

  it("maps a 4xx response to an AuthError with Twilio's error code and message", async () => {
    const { fetch } = stubFetch(
      new Response(toJson({ code: 21211, message: "Invalid 'To' Phone Number" }), {
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
    const failingFetch: typeof fetch = async () => {
      throw new NetworkDown();
    };
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

    await run(
      Effect.provide(
        Effect.gen(function* () {
          const sender = yield* SmsSender;
          yield* sender.send({ to: "+1", purpose: "second-factor-otp", params: { otp: "1" } });
        }),
        layer({ ...baseConfig, fetch }),
      ),
    );
    expect(calls).toHaveLength(1);
  });
});
