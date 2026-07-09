import { describe, it, expect } from "vite-plus/test";
import { Effect, Layer, Redacted } from "effect";
import { HttpClient, HttpClientResponse } from "effect/unstable/http";
import * as crypto from "node:crypto";
import { Hooks } from "../Hooks.js";
import { HaveIBeenPwnedPlugin } from "../password/HaveIBeenPwned.js";
import { CaptchaPlugin } from "./Captcha.js";
import { PwnedPasswordError, CaptchaError } from "../Errors.js";
import type { SignInInput, SignUpInput } from "../email/EmailPassword.js";

/** A stubbed HttpClient that answers every request with `respond(request)`. */
const stubHttpClient = (respond: (url: string) => Response) =>
  Layer.succeed(
    HttpClient.HttpClient,
    HttpClient.make((request) =>
      Effect.succeed(HttpClientResponse.fromWeb(request, respond(request.url))),
    ),
  );

const drive = <A, E>(
  pluginLayer: Layer.Layer<Hooks, never, Hooks | HttpClient.HttpClient>,
  clientLayer: Layer.Layer<HttpClient.HttpClient>,
  f: (hooks: typeof Hooks.Service) => Effect.Effect<A, E, never>,
) =>
  Effect.runPromise(
    Effect.gen(function* () {
      const hooks = yield* Hooks;
      return yield* f(hooks);
    }).pipe(
      Effect.provide(pluginLayer.pipe(Layer.provide(Hooks.Default), Layer.provide(clientLayer))),
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

const sha1UpperSuffix = (password: string): string =>
  crypto.createHash("sha1").update(password).digest("hex").toUpperCase().slice(5);

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
    const suffix = sha1UpperSuffix(pwd);
    const client = stubHttpClient(() => new Response(`${suffix}:4200\r\nAAAA:1\r\n`));
    const err = await drive(HaveIBeenPwnedPlugin(), client, (hooks) =>
      Effect.flip(hooks.beforeSignUp(signUp(pwd))),
    );
    expect(err).toBeInstanceOf(PwnedPasswordError);
  });

  it("also guards beforeResetPassword", async () => {
    const pwd = "hunter2hunter2";
    const suffix = sha1UpperSuffix(pwd);
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
});
