import { describe, it, expect } from "vite-plus/test";
import { ConfigProvider, Data, Effect, Layer, Predicate, Redacted, Schema } from "effect";
import { EmailSender, type EmailMessage } from "@thomasfosterau/effect-auth";
import { defaultRender, layer, layerConfig, resendEmailSender } from "./index.ts";

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
  // `RequestInfo` is not a global under `types: ["node"]`; take fetch's own
  // input type instead of naming the DOM alias.
  const fetchStub = (async (input: Parameters<typeof fetch>[0], init?: RequestInit) => {
    const request = { url: String(input), init: init ?? {} };
    calls.push(request);
    return Predicate.isFunction(response) ? response(request) : response;
  }) as typeof fetch;
  return { fetch: fetchStub, calls };
};

const baseConfig = {
  apiKey: Redacted.make("re_test_key"),
  from: "App <noreply@example.com>",
};

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
    expect(request!.url).toBe("https://api.resend.com/emails");
    expect(request!.init.method).toBe("POST");
    const headers = new Headers(request!.init.headers);
    expect(headers.get("Authorization")).toBe("Bearer re_test_key");
    expect(headers.get("Content-Type")).toBe("application/json");

    const body = fromJson(request!.init.body as string);
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

    const body = fromJson(calls[0]!.init.body as string);
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

    expect(calls[0]!.url).toBe("https://stub.local/api/emails");
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
    expect((err.cause as { body: string }).body).toContain("invalid `to` field");
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
    const failingFetch = (async () => {
      throw new NetworkDown();
    }) as typeof fetch;
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

    const program = Effect.gen(function* () {
      const sender = yield* EmailSender;
      yield* sender.send({ to: "a@b.com", purpose: "magic-link", params: { token: "t" } });
    });

    await run(Effect.provide(program, layer({ ...baseConfig, fetch })));
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
