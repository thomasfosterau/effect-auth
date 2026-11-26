import { assert, describe, it, expect } from "vite-plus/test";
import { Effect, Layer, Redacted, Result } from "effect";
import { Digest } from "effect/crypto";
import { HttpClient, HttpClientRequest, HttpClientResponse } from "effect/http";
import { ClientIP } from "../ClientIP.ts";
import { Hooks } from "../Hooks.ts";
import { HaveIBeenPwnedPlugin } from "../password/HaveIBeenPwned.ts";
import * as PlatformCrypto from "../PlatformCrypto.ts";
import { CaptchaPlugin } from "./Captcha.ts";
import { AuthError, PwnedPasswordError, CaptchaError } from "../Errors.ts";
import type { AuthenticateAttempt } from "../Hooks.ts";
import type { SignUpInput } from "../email/EmailPassword.ts";

/** A stubbed HttpClient that answers every request with `respond(request)`. */
const stubHttpClient = (respond: (url: string) => Response) =>
  Layer.succeed(
    HttpClient.HttpClient,
    HttpClient.make((request) =>
      Effect.succeed(HttpClientResponse.fromWeb(request, respond(request.url))),
    ),
  );

/**
 * A stubbed HttpClient that also captures each outgoing request as a native
 * Web API `Request` so tests can inspect the URL and body.
 */
const capturingHttpClient = (onRequest: (req: Request) => void, respond: () => Response) =>
  Layer.succeed(
    HttpClient.HttpClient,
    HttpClient.make((request) =>
      HttpClientRequest.toWeb(request).pipe(
        Effect.orDie,
        Effect.map((webReq) => {
          onRequest(webReq);
          return HttpClientResponse.fromWeb(request, respond());
        }),
      ),
    ),
  );

const drive = <A, E>(
  pluginLayer: Layer.Layer<Hooks, never, Hooks | HttpClient.HttpClient | Digest.Digest>,
  clientLayer: Layer.Layer<HttpClient.HttpClient>,
  f: (hooks: typeof Hooks.Service) => Effect.Effect<A, E>,
) =>
  Effect.runPromise(
    Effect.gen(function* () {
      const hooks = yield* Hooks;
      return yield* f(hooks);
    }).pipe(
      Effect.provide(
        pluginLayer.pipe(
          Layer.provide(Hooks.Default),
          Layer.provide(clientLayer),
          Layer.provide(PlatformCrypto.layer),
        ),
      ),
    ),
  );

const signUp = (password: string, captchaToken?: string): SignUpInput => ({
  email: "u@example.com",
  password,
  ...(captchaToken !== undefined && { captchaToken }),
});

const signIn = (captchaToken?: string): AuthenticateAttempt => ({
  method: "email-password",
  identifier: { type: "email", value: "u@example.com" },
  captchaToken,
});

const sha1UpperSuffix = async (password: string): Promise<string> => {
  const digest = await globalThis.crypto.subtle.digest("SHA-1", new TextEncoder().encode(password));
  return Buffer.from(digest).toString("hex").toUpperCase().slice(5);
};

describe("HaveIBeenPwnedPlugin", () => {
  it("allows a password whose suffix is not in the range response", async () => {
    const client = stubHttpClient(() => new Response("0000000000000000000000000000000000A:3\r\n"));
    const result = await drive(HaveIBeenPwnedPlugin(), client, (hooks) =>
      hooks.beforeSignUp(signUp("a-fresh-password")),
    );
    expect(result.password).toBe("a-fresh-password");
  });

  it("rejects (short-circuits) a breached password", async () => {
    const pwd = "password123";
    const suffix = await sha1UpperSuffix(pwd);
    const client = stubHttpClient(() => new Response(`${suffix}:4200\r\nAAAA:1\r\n`));
    const err = await drive(HaveIBeenPwnedPlugin(), client, (hooks) =>
      Effect.flip(hooks.beforeSignUp(signUp(pwd))),
    );
    expect(err).toBeInstanceOf(PwnedPasswordError);
  });

  it("also guards beforeResetPassword", async () => {
    const pwd = "hunter2hunter2";
    const suffix = await sha1UpperSuffix(pwd);
    const client = stubHttpClient(() => new Response(`${suffix}:9\r\n`));
    const err = await drive(HaveIBeenPwnedPlugin(), client, (hooks) =>
      Effect.flip(hooks.beforeResetPassword({ token: "t", newPassword: pwd })),
    );
    expect(err).toBeInstanceOf(PwnedPasswordError);
  });

  it("guards beforeChangePassword and beforeSetPassword", async () => {
    const pwd = "hunter2hunter2";
    const suffix = await sha1UpperSuffix(pwd);
    const client = stubHttpClient(() => new Response(`${suffix}:9\r\n`));
    const changed = await drive(HaveIBeenPwnedPlugin(), client, (hooks) =>
      Effect.flip(hooks.beforeChangePassword({ userId: "u-1", newPassword: pwd })),
    );
    const set = await drive(HaveIBeenPwnedPlugin(), client, (hooks) =>
      Effect.flip(hooks.beforeSetPassword({ userId: "u-1", newPassword: pwd })),
    );
    expect(changed).toBeInstanceOf(PwnedPasswordError);
    expect(set).toBeInstanceOf(PwnedPasswordError);
  });

  it("asks for a padded response", async () => {
    const seen: Array<Request> = [];
    const client = capturingHttpClient(
      (request) => seen.push(request),
      () => new Response("0000000000000000000000000000000000A:0\r\n"),
    );
    await drive(HaveIBeenPwnedPlugin(), client, (hooks) =>
      hooks.beforeSignUp(signUp("a-fresh-password")),
    );
    expect(seen.map((request) => request.headers.get("add-padding"))).toEqual(["true"]);
  });

  describe.each([429, 503])(
    "an HTTP %i answer is unavailability, not a clean password",
    (status) => {
      // The body would read as a count of 0 if the status were ignored.
      const client = stubHttpClient(() => new Response("Too many requests", { status }));

      it("with failClosed, refuses", async () => {
        const err = await drive(HaveIBeenPwnedPlugin({ failClosed: true }), client, (hooks) =>
          Effect.flip(hooks.beforeSignUp(signUp("password123"))),
        );
        expect(err).toBeInstanceOf(AuthError);
        expect(err.message).toBe("Password breach check is unavailable");
      });

      it("without failClosed, allows", async () => {
        const result = await drive(HaveIBeenPwnedPlugin(), client, (hooks) =>
          hooks.beforeSignUp(signUp("password123")),
        );
        expect(result.password).toBe("password123");
      });
    },
  );

  it("treats an API that does not answer within timeout as unavailable", async () => {
    const hanging = Layer.succeed(
      HttpClient.HttpClient,
      HttpClient.make(() => Effect.never),
    );
    const err = await drive(
      HaveIBeenPwnedPlugin({ failClosed: true, timeout: "20 millis" }),
      hanging,
      (hooks) => Effect.flip(hooks.beforeSignUp(signUp("password123"))),
    );
    expect(err).toBeInstanceOf(AuthError);
  });
});

describe("CaptchaPlugin", () => {
  const config = {
    provider: "cloudflare-turnstile" as const,
    secretKey: Redacted.make("secret"),
  };

  it("allows sign-up when the provider reports success", async () => {
    const client = stubHttpClient(() => Response.json({ success: true }));
    const result = await drive(CaptchaPlugin(config), client, (hooks) =>
      hooks.beforeSignUp(signUp("pw", "tok")),
    );
    expect(result.email).toBe("u@example.com");
  });

  it("rejects (short-circuits) sign-in when verification fails", async () => {
    const client = stubHttpClient(() => Response.json({ success: false }));
    const err = await drive(CaptchaPlugin(config), client, (hooks) =>
      Effect.flip(hooks.beforeAuthenticate(signIn("tok"))),
    );
    expect(err).toBeInstanceOf(CaptchaError);
  });

  it("rejects when the captcha token is missing", async () => {
    const client = stubHttpClient(() => Response.json({ success: true }));
    const err = await drive(CaptchaPlugin(config), client, (hooks) =>
      Effect.flip(hooks.beforeSignUp(signUp("pw"))),
    );
    expect(err).toBeInstanceOf(CaptchaError);
  });

  it("only guards the configured endpoints", async () => {
    // signIn not guarded -> passes through even with no token.
    const client = stubHttpClient(() => Response.json({ success: false }));
    const result = await drive(
      CaptchaPlugin({ ...config, endpoints: ["signUp"] }),
      client,
      (hooks) => hooks.beforeAuthenticate(signIn()),
    );
    expect(result.identifier?.value).toBe("u@example.com");
  });

  it("sends secret and token in the POST body, not the URL query string", async () => {
    let captured: Request | undefined;
    const client = capturingHttpClient(
      (req) => {
        captured = req;
      },
      () => Response.json({ success: true }),
    );

    await drive(CaptchaPlugin(config), client, (hooks) => hooks.beforeSignUp(signUp("pw", "tok")));

    assert(captured !== undefined, "the plugin called the verifier");
    const url = new URL(captured.url);
    expect(url.searchParams.has("secret")).toBe(false);
    expect(url.searchParams.has("response")).toBe(false);

    expect(captured.headers.get("content-type")).toContain("application/x-www-form-urlencoded");

    const bodyText = await captured.text();
    const params = new URLSearchParams(bodyText);
    expect(params.get("secret")).toBe("secret");
    expect(params.get("response")).toBe("tok");
  });

  describe("checks what the token was minted for", () => {
    const passes = async (cfg: Parameters<typeof CaptchaPlugin>[0], answer: object) => {
      const client = stubHttpClient(() => Response.json(answer));
      const result = await drive(CaptchaPlugin(cfg), client, (hooks) =>
        Effect.result(hooks.beforeSignUp(signUp("pw", "tok"))),
      );
      return Result.isSuccess(result);
    };

    it("refuses a score below minScore, and a missing score", async () => {
      const cfg = { ...config, minScore: 0.5 };
      expect(await passes(cfg, { success: true, score: 0.9 })).toBe(true);
      expect(await passes(cfg, { success: true, score: 0.5 })).toBe(true);
      expect(await passes(cfg, { success: true, score: 0.1 })).toBe(false);
      expect(await passes(cfg, { success: true })).toBe(false);
      expect(await passes(cfg, { success: false, score: 0.9 })).toBe(false);
    });

    it("refuses a scored token when no minScore judges it", async () => {
      // A reCAPTCHA v3 token behind a configuration that never set a floor.
      const cfg = { ...config, provider: "google-recaptcha" as const };
      expect(await passes(cfg, { success: true, score: 0.1 })).toBe(false);
      expect(await passes(cfg, { success: true })).toBe(true);
    });

    it("refuses a token solved on another hostname", async () => {
      const one = { ...config, expectedHostname: "app.example.com" };
      expect(await passes(one, { success: true, hostname: "app.example.com" })).toBe(true);
      expect(await passes(one, { success: true, hostname: "evil.example.net" })).toBe(false);
      expect(await passes(one, { success: true })).toBe(false);
      const many = { ...config, expectedHostname: ["a.example.com", "b.example.com"] };
      expect(await passes(many, { success: true, hostname: "b.example.com" })).toBe(true);
    });

    it("refuses a token minted for another action, per endpoint", async () => {
      const cfg = { ...config, expectedAction: "signup" };
      expect(await passes(cfg, { success: true, action: "signup" })).toBe(true);
      expect(await passes(cfg, { success: true, action: "login" })).toBe(false);
      expect(await passes(cfg, { success: true })).toBe(false);

      const perEndpoint = { ...config, expectedAction: { signIn: "login" } };
      // Sign-up has no expected action, so it is not checked.
      expect(await passes(perEndpoint, { success: true, action: "anything" })).toBe(true);
      const client = stubHttpClient(() => Response.json({ success: true, action: "signup" }));
      const err = await drive(CaptchaPlugin(perEndpoint), client, (hooks) =>
        Effect.flip(hooks.beforeAuthenticate(signIn("tok"))),
      );
      expect(err).toBeInstanceOf(CaptchaError);
    });

    it("refuses an answer that is not a siteverify object", async () => {
      expect(await passes(config, { success: "true" })).toBe(false);
      const client = stubHttpClient(() => new Response("not json"));
      const err = await drive(CaptchaPlugin(config), client, (hooks) =>
        Effect.flip(hooks.beforeSignUp(signUp("pw", "tok"))),
      );
      expect(err).toBeInstanceOf(CaptchaError);
    });
  });

  it.each([{ recaptchaVersion: 3 as const }, { minScore: 1.5 }, { minScore: Number.NaN }])(
    "refuses to build with $recaptchaVersion / $minScore",
    async (extra) => {
      const client = stubHttpClient(() => Response.json({ success: true }));
      const exit = await Effect.runPromiseExit(
        Effect.scoped(
          Layer.build(
            CaptchaPlugin({ ...config, provider: "google-recaptcha", ...extra }).pipe(
              Layer.provide(Hooks.Default),
              Layer.provide(client),
            ),
          ),
        ),
      );
      expect(exit._tag).toBe("Failure");
      expect(String(exit)).toContain("CaptchaConfigError");
    },
  );

  it("builds reCAPTCHA v3 with a minScore", async () => {
    const client = stubHttpClient(() => Response.json({ success: true, score: 0.7 }));
    const result = await drive(
      CaptchaPlugin({
        ...config,
        provider: "google-recaptcha",
        recaptchaVersion: 3,
        minScore: 0.5,
      }),
      client,
      (hooks) => hooks.beforeSignUp(signUp("pw", "tok")),
    );
    expect(result.email).toBe("u@example.com");
  });

  it("sends the client address as remoteip when the request has one", async () => {
    let captured: Request | undefined;
    const client = capturingHttpClient(
      (req) => {
        captured = req;
      },
      () => Response.json({ success: true }),
    );
    await drive(CaptchaPlugin(config), client, (hooks) =>
      hooks
        .beforeSignUp(signUp("pw", "tok"))
        .pipe(Effect.provideService(ClientIP, { ip: "203.0.113.9" })),
    );
    assert(captured !== undefined, "the plugin called the verifier");
    expect(new URLSearchParams(await captured.text()).get("remoteip")).toBe("203.0.113.9");
  });

  it("guards a password-reset send through beforeSendCode", async () => {
    const client = stubHttpClient(() => Response.json({ success: true }));
    const attempt = {
      method: "password-reset",
      purpose: "password-reset",
      address: "u@example.com",
    } as const;
    const err = await drive(CaptchaPlugin(config), client, (hooks) =>
      Effect.flip(hooks.beforeSendCode(attempt)),
    );
    expect(err).toBeInstanceOf(CaptchaError);
    const ok = await drive(CaptchaPlugin(config), client, (hooks) =>
      hooks.beforeSendCode({ ...attempt, captchaToken: "tok" }),
    );
    expect(ok.method).toBe("password-reset");
  });
});
