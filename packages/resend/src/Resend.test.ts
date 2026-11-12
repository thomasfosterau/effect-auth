import { createServer } from "node:http";
import { assert, describe, it, expect, onTestFinished } from "vite-plus/test";
import { Cause, ConfigProvider, Data, Effect, Exit, Layer, Redacted } from "effect";
import * as Option from "effect/Option";
import * as P from "effect/Predicate";
import * as Schema from "effect/Schema";
import { EmailSender, type EmailMessage } from "@thomasfosterau/effect-auth";
import {
  MAX_ERROR_BODY_CHARS,
  TRUNCATION_MARKER,
  defaultRender,
  layer,
  layerConfig,
  resendEmailSender,
} from "./index.ts";

const run = <A, E>(effect: Effect.Effect<A, E>): Promise<A> => Effect.runPromise(effect);

const UnknownJson = Schema.fromJsonString(Schema.Unknown);
const toJson = Schema.encodeSync(UnknownJson);
const fromJson = Schema.decodeUnknownSync(UnknownJson);

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

const baseConfig = {
  apiKey: Redacted.make("re_test_key"),
  from: "App <noreply@example.com>",
};

/** The `body` an `AuthError`'s `{ status, body }` cause carries. */
const causeBody = (cause: unknown): string => {
  assert(P.isObject(cause) && "body" in cause && P.isString(cause.body), "cause has a body");
  return cause.body;
};

/** What a {@link trackedBody} whose cancel fails throws. */
class CancelFailed extends Data.TaggedError("CancelFailed") {}

/**
 * A body that never ends, recording whether it was cancelled; with
 * `cancelFails`, its cancel throws, so `body.cancel()` rejects.
 */
const trackedBody = (
  cancelFails: boolean,
): { readonly stream: ReadableStream<Uint8Array>; readonly cancelled: () => boolean } => {
  let cancelled = false;
  const chunk = new TextEncoder().encode("x".repeat(4096));
  return {
    stream: new ReadableStream<Uint8Array>({
      pull: (controller) => controller.enqueue(chunk),
      cancel: () => {
        cancelled = true;
        if (cancelFails) throw new CancelFailed();
      },
    }),
    cancelled: () => cancelled,
  };
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
    if (request.url === "/landed") response.writeHead(200).end("{}");
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

const sendOneTo = (sender: typeof EmailSender.Service) =>
  Effect.flip(sender.send({ to: "a@b.com", purpose: "magic-link", params: { token: "t" } }));

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

describe("resendEmailSender's outbound request (#606)", () => {
  it.each([300, 301, 302, 303, 307, 308, 399])(
    "fails a %i as an AuthError with only its status, the body unread",
    async (status) => {
      const redirect = redirectResponse(status);
      const { fetch, calls } = stubFetch(redirect.response);

      const err = await run(sendOneTo(resendEmailSender({ ...baseConfig, fetch })));

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

    const err = await run(sendOneTo(resendEmailSender({ ...baseConfig, fetch })));

    expect(err._tag).toBe("AuthError");
    expect(err.cause).toEqual({ status: 0 });
    expect(calls).toHaveLength(1);
  });

  it("fails a real 3xx without a second request", async () => {
    const { baseUrl, hits } = await startRedirectingServer();
    const err = await run(sendOneTo(resendEmailSender({ ...baseConfig, baseUrl })));

    expect(err._tag).toBe("AuthError");
    expect(err.cause).toEqual({ status: 307 });
    expect(hits()).toBe(1);
    expect(toJson(err)).not.toContain("re_test_key");
  });

  it("fails an error body whose stream breaks as an AuthError, not a defect", async () => {
    const { fetch } = stubFetch(new Response(brokenBody(), { status: 500 }));

    const exit = await run(
      Effect.exit(
        resendEmailSender({ ...baseConfig, fetch }).send({
          to: "a@b.com",
          purpose: "magic-link",
          params: { token: "t" },
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
    const sender = resendEmailSender({ ...baseConfig, fetch: hanging.fetch });

    await run(
      Effect.exit(
        Effect.timeout(
          sender.send({ to: "a@b.com", purpose: "magic-link", params: { token: "t" } }),
          "20 millis",
        ),
      ),
    );

    const signal = hanging.signal();
    assert(signal !== undefined, "fetch received a signal");
    expect(signal.aborted).toBe(true);
  });

  it("keeps at most MAX_ERROR_BODY_CHARS of a huge error body", async () => {
    const { fetch } = stubFetch(new Response("e".repeat(1_000_000), { status: 500 }));

    const err = await run(sendOneTo(resendEmailSender({ ...baseConfig, fetch })));

    const body = causeBody(err.cause);
    expect(body).toBe(`${"e".repeat(MAX_ERROR_BODY_CHARS)}${TRUNCATION_MARKER}`);
    expect(err.message.length).toBeLessThan(200);
  });

  it("stops reading an endless error body and cancels it", async () => {
    const endless = endlessBody();
    const { fetch } = stubFetch(new Response(endless.stream, { status: 502 }));

    const err = await run(sendOneTo(resendEmailSender({ ...baseConfig, fetch })));

    expect(causeBody(err.cause).endsWith(TRUNCATION_MARKER)).toBe(true);
    expect(endless.cancelled).toBe(true);
  });

  it.each([false, true])(
    "cancels the 2xx body it does not read, and succeeds even when the cancel fails (%s)",
    async (cancelFails) => {
      const body = trackedBody(cancelFails);
      const { fetch } = stubFetch(new Response(body.stream, { status: 200 }));

      const sender = resendEmailSender({ ...baseConfig, fetch });
      const sent = sender.send({ to: "a@b.com", purpose: "magic-link", params: { token: "t" } });
      await expect(run(Effect.exit(sent))).resolves.toEqual(Exit.void);

      expect(body.cancelled()).toBe(true);
    },
  );

  it.each([302, 502])(
    "keeps the typed failure for a %i whose body fails to cancel",
    async (status) => {
      const body = trackedBody(true);
      const { fetch } = stubFetch(new Response(body.stream, { status }));

      const err = await run(sendOneTo(resendEmailSender({ ...baseConfig, fetch })));

      expect(err._tag).toBe("AuthError");
      expect(err.message).toContain(`status ${status}`);
      expect(body.cancelled()).toBe(true);
    },
  );

  it("keeps a short error body whole", async () => {
    const { fetch } = stubFetch(new Response("bad request", { status: 400 }));

    const err = await run(sendOneTo(resendEmailSender({ ...baseConfig, fetch })));

    expect(causeBody(err.cause)).toBe("bad request");
  });

  it.each([
    ["echoed whole", "unauthorized: Authorization: Bearer re_test_key"],
    ["cut at the limit", `${"a".repeat(MAX_ERROR_BODY_CHARS - 4)}re_test_key${"b".repeat(5000)}`],
  ])("scrubs the API key from an error body that echoes it (%s)", async (_case, text) => {
    const { fetch } = stubFetch(new Response(text, { status: 401 }));

    const err = await run(sendOneTo(resendEmailSender({ ...baseConfig, fetch })));

    expect(toJson(err)).not.toContain("re_test_key");
    expect(causeBody(err.cause)).not.toContain("re_t");
    expect(err.message).not.toContain("re_test_key");
  });
});

describe("defaultRender", () => {
  it("uses a purpose-keyed subject and includes the OTP in the body", () => {
    const message: EmailMessage = {
      to: "user@example.com",
      purpose: "email-otp:sign-in",
      params: { otp: "123456" },
    };
    const rendered = defaultRender(message);
    expect(rendered.subject).toBe("Your verification code");
    expect(rendered.text).toContain("123456");
  });

  it("interpolates a url param into the body ahead of a bare token", () => {
    const message: EmailMessage = {
      to: "user@example.com",
      purpose: "magic-link",
      params: { token: "tok_abc", url: "https://example.com/verify?token=tok_abc" },
    };
    const rendered = defaultRender(message);
    expect(rendered.subject).toBe("Your sign-in link");
    expect(rendered.text).toContain("https://example.com/verify?token=tok_abc");
    expect(rendered.text).not.toContain("Your token:");
  });

  it("falls back to the token when there is no url", () => {
    const rendered = defaultRender({
      to: "user@example.com",
      purpose: "password-reset",
      params: { token: "reset-token" },
    });
    expect(rendered.subject).toBe("Reset your password");
    expect(rendered.text).toContain("reset-token");
  });

  it("tells the holder of an address that someone tried to sign up with it (#428)", () => {
    const rendered = defaultRender({ to: "a@b.com", purpose: "existing-account", params: {} });
    expect(rendered.subject).toBe("Someone tried to sign up with your email address");
    expect(rendered.text).toContain("Someone tried to create an account with this email address");
    expect(rendered.text).toContain("sign in");
    expect(rendered.text).toContain("reset your password");
    expect(rendered.text).not.toContain("Please continue in the app.");
  });

  it("keys the subject off known purposes and falls back for unknown ones", () => {
    expect(defaultRender({ to: "a@b.com", purpose: "change-email", params: {} }).subject).toBe(
      "Confirm your new email address",
    );
    expect(defaultRender({ to: "a@b.com", purpose: "delete-account", params: {} }).subject).toBe(
      "Confirm account deletion",
    );
    expect(defaultRender({ to: "a@b.com", purpose: "second-factor-otp", params: {} }).subject).toBe(
      "Your verification code",
    );
    expect(defaultRender({ to: "a@b.com", purpose: "custom-purpose", params: {} }).subject).toBe(
      "Action required",
    );
  });

  it("has a generic body when no otp, token or url is present", () => {
    const rendered = defaultRender({ to: "a@b.com", purpose: "delete-account", params: {} });
    expect(rendered.text).toBe("Please continue in the app.");
  });
});

describe("resendEmailSender", () => {
  it("posts to Resend with a Bearer auth header and the rendered payload", async () => {
    const { fetch, calls } = stubFetch(new Response(toJson({ id: "email_1" }), { status: 200 }));
    const sender = resendEmailSender({ ...baseConfig, fetch });

    await run(
      sender.send({
        to: "user@example.com",
        purpose: "email-verification",
        params: { token: "tok" },
      }),
    );

    expect(calls).toHaveLength(1);
    const [request] = calls;
    assert(request !== undefined);
    expect(request.url).toBe("https://api.resend.com/emails");
    expect(request.init.method).toBe("POST");
    const headers = new Headers(request.init.headers);
    expect(headers.get("Authorization")).toBe("Bearer re_test_key");
    expect(headers.get("Content-Type")).toBe("application/json");

    const body = fromJson(request.init.body);
    expect(body).toEqual({
      from: "App <noreply@example.com>",
      to: "user@example.com",
      subject: "Verify your email address",
      text: "Your token: tok",
    });
  });

  it("uses a custom render function when provided", async () => {
    const { fetch, calls } = stubFetch(new Response(null, { status: 200 }));
    const sender = resendEmailSender({
      ...baseConfig,
      fetch,
      render: () => ({ subject: "Custom subject", html: "<p>hi</p>", text: "hi" }),
    });

    await run(
      sender.send({ to: "user@example.com", purpose: "magic-link", params: { token: "t" } }),
    );

    const [request] = calls;
    assert(request !== undefined);
    const body = fromJson(request.init.body);
    expect(body).toEqual({
      from: "App <noreply@example.com>",
      to: "user@example.com",
      subject: "Custom subject",
      html: "<p>hi</p>",
      text: "hi",
    });
  });

  it("honours a baseUrl override", async () => {
    const { fetch, calls } = stubFetch(new Response(null, { status: 200 }));
    const sender = resendEmailSender({ ...baseConfig, fetch, baseUrl: "https://stub.local/api" });

    await run(sender.send({ to: "a@b.com", purpose: "password-reset", params: { token: "t" } }));

    const [request] = calls;
    assert(request !== undefined);
    expect(request.url).toBe("https://stub.local/api/emails");
  });

  it("never leaks the API key onto a failure", async () => {
    const { fetch } = stubFetch(
      new Response(toJson({ message: "invalid `to` field" }), { status: 422 }),
    );
    const sender = resendEmailSender({ ...baseConfig, fetch });

    const err = await run(
      Effect.flip(
        sender.send({ to: "bad", purpose: "email-verification", params: { token: "t" } }),
      ),
    );

    expect(err._tag).toBe("AuthError");
    expect(toJson(err)).not.toContain("re_test_key");
  });

  it("maps a 4xx response to an AuthError carrying status and body", async () => {
    const { fetch } = stubFetch(
      new Response(toJson({ message: "invalid `to` field", name: "validation_error" }), {
        status: 422,
      }),
    );
    const sender = resendEmailSender({ ...baseConfig, fetch });

    const err = await run(
      Effect.flip(
        sender.send({ to: "bad", purpose: "email-verification", params: { token: "t" } }),
      ),
    );

    expect(err._tag).toBe("AuthError");
    expect(err.message).toContain("422");
    expect(err.cause).toMatchObject({ status: 422 });
    expect(err.cause).toMatchObject({ body: expect.stringContaining("invalid `to` field") });
  });

  it("maps a 5xx response to an AuthError", async () => {
    const { fetch } = stubFetch(new Response("internal error", { status: 500 }));
    const sender = resendEmailSender({ ...baseConfig, fetch });

    const err = await run(
      Effect.flip(sender.send({ to: "a@b.com", purpose: "magic-link", params: { token: "t" } })),
    );

    expect(err._tag).toBe("AuthError");
    expect(err.message).toContain("500");
  });

  it("maps a network failure to an AuthError", async () => {
    const failingFetch: typeof fetch = async () => {
      throw new NetworkDown();
    };
    const sender = resendEmailSender({ ...baseConfig, fetch: failingFetch });

    const err = await run(
      Effect.flip(sender.send({ to: "a@b.com", purpose: "magic-link", params: { token: "t" } })),
    );

    expect(err._tag).toBe("AuthError");
    expect(err.message).toContain("Resend API");
  });
});

describe("layer", () => {
  it("provides the EmailSender service", async () => {
    const { fetch, calls } = stubFetch(new Response(null, { status: 200 }));

    await run(
      Effect.provide(
        Effect.gen(function* () {
          const sender = yield* EmailSender;
          yield* sender.send({ to: "a@b.com", purpose: "magic-link", params: { token: "t" } });
        }),
        layer({ ...baseConfig, fetch }),
      ),
    );
    expect(calls).toHaveLength(1);
  });
});

describe("layerConfig", () => {
  const withEnv = (env: Record<string, string>) =>
    ConfigProvider.layer(ConfigProvider.fromEnvRecord(env));
  const sendOne = EmailSender.use((sender) =>
    sender.send({ to: "a@b.com", purpose: "magic-link", params: { token: "t" } }),
  );

  it("reads RESEND_API_KEY and sends with it", async () => {
    const { fetch, calls } = stubFetch(new Response(null, { status: 200 }));
    const live = layerConfig({ from: baseConfig.from, fetch }).pipe(
      Layer.provide(withEnv({ RESEND_API_KEY: "re_from_env" })),
    );

    await run(Effect.provide(sendOne, live));

    expect(calls).toHaveLength(1);
    expect(new Headers(calls[0]?.init.headers).get("authorization")).toBe("Bearer re_from_env");
  });

  it("fails at construction, sending nothing, when the key is missing or empty", async () => {
    const { fetch, calls } = stubFetch(new Response(null, { status: 200 }));
    const build = (env: Record<string, string>) =>
      Effect.flip(
        Effect.provide(
          sendOne,
          layerConfig({ from: baseConfig.from, fetch }).pipe(Layer.provide(withEnv(env))),
        ),
      );

    const missing = await run(build({}));
    const empty = await run(build({ RESEND_API_KEY: "" }));

    expect(missing._tag).toBe("ConfigError");
    expect(empty._tag).toBe("ConfigError");
    expect(calls).toHaveLength(0);
  });
});
