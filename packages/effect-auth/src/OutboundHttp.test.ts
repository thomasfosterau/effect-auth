import { assert, describe, expect, it } from "vite-plus/test";
import * as Effect from "effect/Effect";
import * as Layer from "effect/Layer";
import * as Result from "effect/Result";
import { FetchHttpClient, HttpClient } from "effect/http";
import * as OutboundHttp from "./OutboundHttp.ts";

type FetchFn = typeof globalThis.fetch;

/** Send `request` through a `fetch` stub, with `limits`. */
const sendVia = (
  fetch: FetchFn,
  url: string,
  limits: OutboundHttp.Limits = OutboundHttp.defaultLimits,
  urlPolicy: OutboundHttp.UrlPolicy = OutboundHttp.allowAnyUrl,
) =>
  Effect.runPromise(
    Effect.gen(function* () {
      const client = yield* HttpClient.HttpClient;
      return yield* OutboundHttp.send(client, OutboundHttp.getJson(url), limits, urlPolicy).pipe(
        Effect.result,
      );
    }).pipe(
      Effect.provide(
        FetchHttpClient.layer.pipe(Layer.provide(Layer.succeed(FetchHttpClient.Fetch, fetch))),
      ),
    ),
  );

const failureReason = (result: Awaited<ReturnType<typeof sendVia>>) =>
  Result.isFailure(result) ? result.failure.reason : undefined;

describe("OutboundHttp.send", () => {
  it("reads a body within the limits", async () => {
    const result = await sendVia(
      () => Promise.resolve(Response.json({ ok: true })),
      "https://a.test/",
    );
    assert(Result.isSuccess(result), "the request succeeds");
    expect(result.success.body).toBe('{"ok":true}');
  });

  it("refuses a declared content-length over the cap", async () => {
    // The body itself is small: only the declared length can refuse it.
    const result = await sendVia(
      () => Promise.resolve(new Response("{}", { headers: { "content-length": "2048" } })),
      "https://a.test/",
      { timeoutMs: 1_000, maxBodyBytes: 1_024 },
    );
    expect(failureReason(result)).toBe("too-large");
  });

  it("stops reading a streamed body once it passes the cap", async () => {
    let chunks = 0;
    const body = new ReadableStream<Uint8Array>({
      pull: (controller) => {
        chunks++;
        controller.enqueue(new Uint8Array(512));
      },
    });
    const result = await sendVia(() => Promise.resolve(new Response(body)), "https://a.test/", {
      timeoutMs: 1_000,
      maxBodyBytes: 1_024,
    });
    expect(failureReason(result)).toBe("too-large");
    // An endless body: reading must stop near the cap, not run on.
    expect(chunks).toBeLessThan(10);
  });

  it("times out a body that stalls after the headers", async () => {
    const body = new ReadableStream<Uint8Array>({
      start: (controller) => controller.enqueue(new TextEncoder().encode("{")),
    });
    const result = await sendVia(() => Promise.resolve(new Response(body)), "https://a.test/", {
      timeoutMs: 50,
      maxBodyBytes: 1_024,
    });
    expect(failureReason(result)).toBe("timeout");
  });

  it("times out a request that never answers", async () => {
    const result = await sendVia(() => new Promise<Response>(() => {}), "https://a.test/", {
      timeoutMs: 50,
      maxBodyBytes: 1_024,
    });
    expect(failureReason(result)).toBe("timeout");
  });

  it("asks fetch not to follow redirects", async () => {
    let redirect: RequestRedirect | undefined;
    await sendVia((_input, init) => {
      redirect = init?.redirect;
      return Promise.resolve(
        new Response(null, { status: 302, headers: { location: "https://b.test/" } }),
      );
    }, "https://a.test/");
    expect(redirect).toBe("manual");
  });

  it("never sends a request whose URL the policy refuses", async () => {
    let sent = false;
    const result = await sendVia(
      () => {
        sent = true;
        return Promise.resolve(Response.json({}));
      },
      "https://a.test/",
      OutboundHttp.defaultLimits,
      () => "refused",
    );
    expect(failureReason(result)).toBe("refused-url");
    expect(sent).toBe(false);
  });

  it("reports a transport failure", async () => {
    const result = await sendVia(() => Promise.reject(new TypeError("offline")), "https://a.test/");
    expect(failureReason(result)).toBe("transport");
  });
});
