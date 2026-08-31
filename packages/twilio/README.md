# @thomasfosterau/effect-auth-twilio

`SmsSender` adapter for
[`@thomasfosterau/effect-auth`](../effect-auth) backed by
[Twilio](https://www.twilio.com)'s Messages API. Talks to
`POST /2010-04-01/Accounts/:sid/Messages.json` with plain `fetch` — **no
Twilio SDK dependency**, so the runtime footprint is just core `effect-auth`
and `effect`.

## Install

```sh
npm install @thomasfosterau/effect-auth-twilio
```

## Usage

Wire it through core's [`Delivery`](../effect-auth/src/Delivery.ts) module so
every feature's `sendOtp` callback is derived in one line:

```ts
import { Config, Effect, Layer, Redacted } from "effect";
import { SmsSender, smsCallbacks, IdentifierStore } from "@thomasfosterau/effect-auth";
import { layer as twilioLayer } from "@thomasfosterau/effect-auth-twilio";

// Resolve secrets through Config, then build the layer from the resolved config.
const SmsLayer = Layer.unwrapEffect(
  Effect.gen(function* () {
    const accountSid = yield* Config.string("TWILIO_ACCOUNT_SID");
    const authToken = yield* Config.redacted("TWILIO_AUTH_TOKEN");
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
twilioSmsSender({
  accountSid: "AC...",
  authToken: Redacted.make("test"),
  from: "+15551234567",
  baseUrl: "http://localhost:3000/twilio",
  fetch: myFetchStub,
});
```

## Errors

Every failure — network error or a non-2xx response — surfaces as an
`AuthError`. Non-2xx responses carry `{ status, body }` as `cause`, and when
Twilio's JSON error body (`{ code, message }`) is parseable, its `code` and
`message` are folded into the `AuthError.message` for easier debugging. The
auth token is never included in any error.

## API

- `twilioSmsSender(config)` — build the `SmsSender` service directly.
- `layer(config)` — the same, as a `Layer<SmsSender>`.
- `defaultRender(message)` — the built-in renderer, exported for reuse/testing.
- `TwilioSmsSenderConfig` — the config type.

## License

MIT
