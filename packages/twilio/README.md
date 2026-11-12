# @thomasfosterau/effect-auth-twilio

`SmsSender` adapter for
[`@thomasfosterau/effect-auth`](https://github.com/thomasfosterau/effect-auth/tree/trunk/packages/effect-auth) backed by
[Twilio](https://www.twilio.com)'s Messages API. Talks to
`POST /2010-04-01/Accounts/:sid/Messages.json` with plain `fetch` — **no
Twilio SDK dependency**, so the runtime footprint is just core `effect-auth`
and `effect`.

## Install

```sh
pnpm add @thomasfosterau/effect-auth-twilio @thomasfosterau/effect-auth effect
```

`effect` (`^4.1.0`) is a peer dependency. The sender needs only a global `fetch`. On Cloudflare Workers, enable the `nodejs_compat` flag: core effect-auth uses `node:crypto`. This package builds its Basic-auth header with `btoa` and needs no Node global.

## Usage

Wire it through core's [`Delivery`](https://github.com/thomasfosterau/effect-auth/blob/trunk/packages/effect-auth/src/Delivery.ts) module so
every feature's `sendOtp` callback is derived in one line:

```ts
import { Config, Effect, Layer, Redacted } from "effect";
import { SmsSender, smsCallbacks, IdentifierStore } from "@thomasfosterau/effect-auth";
import { layer as twilioLayer } from "@thomasfosterau/effect-auth-twilio";

// Resolve secrets through Config, then build the layer from the resolved config.
const SmsLayer = Layer.unwrap(
  Effect.gen(function* () {
    const accountSid = yield* Config.String("TWILIO_ACCOUNT_SID");
    const authToken = yield* Config.Redacted("TWILIO_AUTH_TOKEN");
    return twilioLayer({ accountSid, authToken, from: "+15551234567" });
  }),
);

const program = Effect.gen(function* () {
  const sender = yield* SmsSender; // provided by SmsLayer
  const identifiers = yield* IdentifierStore;
  const send = smsCallbacks(sender, identifiers);

  return {
    PhoneOtp: { sendOtp: send.sendPhoneOtp },
    OtpSecondFactor: { sendOtp: send.sendSecondFactorOtp },
  };
});
```

Or, when you already have plain strings (e.g. from `process.env`), skip
`Config` and call `twilioLayer` directly — see below.

Or use the sender directly:

```ts
import { Effect, Redacted } from "effect";
import { twilioSmsSender } from "@thomasfosterau/effect-auth-twilio";

const sender = twilioSmsSender({
  accountSid: process.env.TWILIO_ACCOUNT_SID!,
  authToken: Redacted.make(process.env.TWILIO_AUTH_TOKEN!),
  from: "+15551234567",
});

await Effect.runPromise(
  sender.send({ to: "+15559876543", purpose: "second-factor-otp", params: { otp: "123456" } }),
);
```

## Default renderer

Without a `render` function, every message gets a minimal, purpose-keyed
body: a lead-in (`"Your verification code"` for OTP purposes, `"Message"`
otherwise) followed by `params.otp` (or `params.token` if there is no OTP).
No branding, no localization.

This exists so the adapter works out of the box and in tests. **Real
applications should supply their own `render`** for branded, localized copy:

```ts
import { Redacted } from "effect";
import { layer as twilioLayer } from "@thomasfosterau/effect-auth-twilio";

twilioLayer({
  accountSid: "...",
  authToken: Redacted.make("..."),
  from: "+15551234567",
  render: (message) => `App: your code is ${message.params.otp}. It expires in 10 minutes.`,
});
```

## Testing / self-hosted proxies

Pass `fetch` to inject a stub, and `baseUrl` to point at a local server:

```ts
import { Redacted } from "effect";
import { twilioSmsSender } from "@thomasfosterau/effect-auth-twilio";

const myFetchStub: typeof fetch = async () => new Response(null, { status: 201 });

twilioSmsSender({
  accountSid: "AC...",
  authToken: Redacted.make("test"),
  from: "+15551234567",
  baseUrl: "http://localhost:3000/twilio",
  fetch: myFetchStub,
});
```

## Errors

Every failure — network error, redirect or a non-2xx response — surfaces as an
`AuthError`. Non-2xx responses carry `{ status, body }` as `cause`, where `body`
is an excerpt of at most `MAX_ERROR_BODY_CHARS` (1024) characters: the
response is read only that far, then cancelled, and a cut body ends in
`TRUNCATION_MARKER`. When Twilio's JSON error body (`{ code, message }`) is
parseable, its `code` and `message` are folded into the `AuthError.message`
for easier debugging; otherwise the message carries the excerpt. The auth
token is never included in any error, even when the response echoes the token
or the Basic credentials back (either is replaced with `[redacted]`).

Redirects are never followed. Every request is sent with `redirect: "manual"`
(workerd's `fetch` rejects `"error"` on every request, so `"manual"` is the one
value that works on Workers, Node and browsers alike), and any 3xx response,
any status-0 response and any `"opaqueredirect"` fails the send as an
`AuthError` whose `cause` is only `{ status }`. The redirect's body is
cancelled unread and its `Location` is never read, so the credentials in
`Authorization` never reach whatever it names and there is no second request.
An injected `fetch` receives the same options. Each request also carries the
`AbortSignal` of the surrounding fiber, so interrupting the send (an
`Effect.timeout`, say) cancels the request, and an error body whose stream
fails mid-read is an `AuthError` too, never a defect. See
[issue #606](https://github.com/thomasfosterau/effect-auth/issues/606).

## API

- `twilioSmsSender(config)` — build the `SmsSender` service directly.
- `layer(config)` — the same, as a `Layer<SmsSender>`.
- `defaultRender(message)` — the built-in renderer, exported for reuse/testing.
- `TwilioSmsSenderConfig` — the config type.
- `MAX_ERROR_BODY_CHARS`, `TRUNCATION_MARKER` — the error-body excerpt's length cap and the marker a cut excerpt ends in.

## License

MIT
