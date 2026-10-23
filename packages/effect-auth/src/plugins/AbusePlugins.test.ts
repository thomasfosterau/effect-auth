import { assert, describe, it, expect } from "vite-plus/test";
import { Crypto, Effect, Layer, Redacted } from "effect";
import { HttpClient, HttpClientRequest, HttpClientResponse } from "effect/http";
import { Hooks } from "../Hooks.ts";
import { HaveIBeenPwnedPlugin } from "../password/HaveIBeenPwned.ts";
import * as PlatformCrypto from "../PlatformCrypto.ts";
import { CaptchaPlugin } from "./Captcha.ts";
import { PwnedPasswordError, CaptchaError } from "../Errors.ts";
import type { SignInInput, SignUpInput } from "../email/EmailPassword.ts";

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
  pluginLayer: Layer.Layer<Hooks, never, Hooks | HttpClient.HttpClient | Crypto.Crypto>,
  clientLayer: Layer.Layer<HttpClient.HttpClient>,
  f: (hooks: typeof Hooks.Service) => Effect.Effect<A, E, never>,
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

const signIn = (captchaToken?: string): SignInInput => ({
  email: "u@example.com",
  password: "pw",
  ...(captchaToken !== undefined && { captchaToken }),
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
      Effect.flip(hooks.beforeSignIn(signIn("tok"))),
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
      (hooks) => hooks.beforeSignIn(signIn()),
    );
    expect(result.email).toBe("u@example.com");
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
});
