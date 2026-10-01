# @thomasfosterau/effect-auth-resend

`EmailSender` adapter for
[`@thomasfosterau/effect-auth`](../effect-auth) backed by
[Resend](https://resend.com)'s REST API. Talks to `POST /emails` with plain
`fetch` — **no Resend SDK dependency**, so the runtime footprint is just core
`effect-auth` and `effect`.

## Install

```sh
npm install @thomasfosterau/effect-auth-resend
```

## Usage

Wire it through core's [`Delivery`](../effect-auth/src/Delivery.ts) module so
every feature's `sendEmail`/`sendMagicLink`/`sendVerificationOtp`/... callback
is derived in one line:

```ts
import { Config, Effect, Layer } from "effect";
import { EmailSender, emailCallbacks, IdentifierStore } from "@thomasfosterau/effect-auth";
import { layer as resendLayer } from "@thomasfosterau/effect-auth-resend";

// Resolve the secret through Config, then build the layer from the resolved config.
const EmailLayer = Layer.unwrapEffect(
  Effect.gen(function* () {
    const apiKey = yield* Config.Redacted("RESEND_API_KEY");
    return resendLayer({ apiKey, from: "App <noreply@example.com>" });
  }),
);

const program = Effect.gen(function* () {
  const sender = yield* EmailSender; // provided by EmailLayer
  const identifiers = yield* IdentifierStore;
  const send = emailCallbacks(sender, identifiers);

  // one line per feature
  return {
    EmailVerification: { sendEmail: send.sendVerificationEmail },
    MagicLink: { sendMagicLink: send.sendMagicLink },
    EmailOtp: { sendVerificationOtp: send.sendVerificationOtp },
    PasswordReset: { sendResetPassword: send.sendResetPassword },
  };
});
```

Or use the sender directly:

```ts
import { Redacted } from "effect";
import { resendEmailSender } from "@thomasfosterau/effect-auth-resend";

const sender = resendEmailSender({
  apiKey: Redacted.make(process.env.RESEND_API_KEY!),
  from: "App <noreply@example.com>",
});

await Effect.runPromise(
  sender.send({ to: "user@example.com", purpose: "magic-link", params: { token: "..." } }),
);
```

## Default renderer

Without a `render` function, every message gets a minimal, purpose-keyed
subject and a plain-text body built from `params`:

- Subject is keyed off `EmailMessage.purpose` (`"Verify your email address"`,
  `"Your sign-in link"`, `"Your verification code"` for OTP purposes, etc.).
- Body includes `params.otp` when present; otherwise `params.url` (if your
  own delivery code passes one) or `params.token`.
- No HTML, no branding, no localization.

This exists so the adapter works out of the box and in tests. **Real
applications should supply their own `render`** for branded, localized email
templates:

```ts
// `apiKey` is a `Redacted<string>`: resolve it with `yield* Config.Redacted(...)`
// as above (or build one with `Redacted.make`), not the `Config` itself.
resendLayer({
  apiKey,
  from: "App <noreply@example.com>",
  render: (message) => {
    switch (message.purpose) {
      case "magic-link":
        return {
          subject: "Sign in to App",
          html: `<a href="https://app.example.com/verify?token=${message.params.token}">Sign in</a>`,
        };
      default:
        return { subject: "Action required", text: JSON.stringify(message.params) };
    }
  },
});
```

## Testing / self-hosted proxies

Pass `fetch` to inject a stub, and `baseUrl` to point at a local server:

```ts
resendEmailSender({
  apiKey: Redacted.make("test"),
  from: "test@example.com",
  baseUrl: "http://localhost:3000/resend",
  fetch: myFetchStub,
});
```

## Errors

Every failure — network error or a non-2xx response — surfaces as an
`AuthError`. Non-2xx responses carry `{ status, body }` as `cause`; the API
key is never included in any error.

## API

- `resendEmailSender(config)` — build the `EmailSender` service directly.
- `layer(config)` — the same, as a `Layer<EmailSender>`.
- `defaultRender(message)` — the built-in renderer, exported for reuse/testing.
- `ResendEmailSenderConfig`, `RenderedEmail` — config and render-result types.

## License

MIT
