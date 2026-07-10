# Observability

effect-auth emits OpenTelemetry-compatible **traces** and **metrics** via
Effect's native `Tracer` / `Metric` abstractions. Both are **zero-cost no-ops**
when no backend is wired in — no conditional checks, no extra packages required.

---

## Tracing

Every key auth operation is wrapped in `Effect.withSpan`. Spans appear in any
OpenTelemetry-compatible backend (Jaeger, Honeycomb, Datadog, etc.) when a
`Tracer` is provided to the Effect runtime.

### Span names

| Span name                           | Operation                            |
| ----------------------------------- | ------------------------------------ |
| `effect-auth.sign-up`               | User registration                    |
| `effect-auth.sign-in`               | Credential sign-in                   |
| `effect-auth.sign-out`              | Session invalidation                 |
| `effect-auth.create-session`        | New session creation                 |
| `effect-auth.validate-session`      | Session token validation             |
| `effect-auth.oauth.authorize`       | OAuth authorization URL generation   |
| `effect-auth.oauth.callback`        | OAuth callback / token exchange      |
| `effect-auth.oauth.refresh`         | OAuth access-token refresh           |
| `effect-auth.token.sign`            | JWT signing                          |
| `effect-auth.token.verify`          | JWT verification                     |
| `effect-auth.password.hash`         | Password hashing (PBKDF2 / scrypt)   |
| `effect-auth.password.verify`       | Password verification                |
| `effect-auth.2fa.challenge`         | Multi-factor challenge creation      |
| `effect-auth.2fa.verify`            | Multi-factor code verification       |
| `effect-auth.webauthn.register`     | WebAuthn registration verification   |
| `effect-auth.webauthn.authenticate` | WebAuthn authentication verification |
| `effect-auth.oidc.authorize`        | OIDC authorization endpoint          |
| `effect-auth.oidc.consent`          | OIDC consent endpoint                |
| `effect-auth.oidc.token`            | OIDC token endpoint                  |
| `effect-auth.oidc.userinfo`         | OIDC userinfo endpoint               |

### Span attributes

Attributes carry only **non-PII discriminators** — never emails, passwords,
session IDs, or tokens.

| Attribute   | Values                                    | Spans                          |
| ----------- | ----------------------------------------- | ------------------------------ |
| `method`    | `"email-password"`                        | sign-in, sign-up               |
| `provider`  | `"github"`, `"google"`, …                 | oauth.authorize, oauth.refresh |
| `algorithm` | `"pbkdf2-sha256"`, `"scrypt"`             | password.hash, password.verify |
| `type`      | `"jwt"`, `"totp"`, `"backup-code"`        | token.verify, 2fa.verify       |
| `grant`     | `"authorization_code"`, `"refresh_token"` | oidc.token                     |

---

## Metrics

Metrics are `Metric.counter` values exported from `src/Observability.ts` and
re-exported from the root `effect-auth` package (there is no separate
`effect-auth/Observability` subpath — it isn't one of the clustered exports in
`package.json`). They are tagged with attributes and updated inside the same
Effect pipelines as the spans.

### Counter names

| Counter                                        | Description                                      |
| ---------------------------------------------- | ------------------------------------------------ |
| `effect-auth.sign_in.total`                    | Sign-in attempts (by `method`, `outcome`)        |
| `effect-auth.sign_up.total`                    | Sign-up attempts (by `method`, `outcome`)        |
| `effect-auth.sessions_created.total`           | Sessions successfully created                    |
| `effect-auth.sessions_validated.total`         | Session validations (by `outcome`)               |
| `effect-auth.sessions_invalidated.total`       | Sessions invalidated                             |
| `effect-auth.token_verifications.total`        | Token verifications (by `type`, `outcome`)       |
| `effect-auth.rate_limit_hits.total`            | Rate-limit threshold breaches (by `operation`)   |
| `effect-auth.multi_factor_challenges.total`    | 2FA challenges started                           |
| `effect-auth.multi_factor_verifications.total` | 2FA verifications (by `type`, `outcome`)         |
| `effect-auth.oauth_callbacks.total`            | OAuth callback completions (by `outcome`)        |
| `effect-auth.oauth_refreshes.total`            | OAuth token refreshes (by `provider`, `outcome`) |
| `effect-auth.webauthn_registrations.total`     | WebAuthn registrations (by `outcome`)            |
| `effect-auth.webauthn_authentications.total`   | WebAuthn authentications (by `outcome`)          |
| `effect-auth.oidc_token_requests.total`        | OIDC token requests (by `grant`, `outcome`)      |

### Attribute values

| Attribute   | Values                                                           |
| ----------- | ---------------------------------------------------------------- |
| `outcome`   | `"success"` \| `"failure"` \| `"not_found"` \| `"expired"`       |
| `method`    | `"email-password"`, `"oauth"`, …                                 |
| `type`      | `"jwt"`, `"totp"`, `"backup-code"`                               |
| `grant`     | `"authorization_code"`, `"refresh_token"`                        |
| `operation` | First segment of the rate-limit key (e.g. `"login"`, `"signup"`) |

---

## Wiring a backend

### OpenTelemetry (Node.js)

```ts
import { NodeSdk } from "@effect/opentelemetry";
import { OTLPTraceExporter } from "@opentelemetry/exporter-trace-otlp-http";
import { PrometheusExporter } from "@opentelemetry/exporter-prometheus";
import { BatchSpanProcessor } from "@opentelemetry/sdk-trace-base";
import { Effect, Layer, ManagedRuntime } from "effect";

const ObservabilityLayer = NodeSdk.layer(() => ({
  resource: { serviceName: "my-app" },
  spanProcessor: new BatchSpanProcessor(new OTLPTraceExporter()),
  metricReader: new PrometheusExporter({ port: 9464 }),
}));

const runtime = ManagedRuntime.make(Layer.mergeAll(ObservabilityLayer /* auth layers … */));
```

### Reading metric counters in tests

The raw `Metric.Counter` instances are exported from the `effect-auth` root
barrel (e.g. `signInTotal`) so you can read their current state in unit tests:

```ts
import { signInTotal } from "@thomasfosterau/effect-auth";
import { Effect, Metric } from "effect";

const snapshot = await Effect.runPromise(Metric.value(signInTotal));
// snapshot is a MetricState.Counter
```

---

## Security note

**No PII is ever placed in a span attribute or metric label.** The rule is
enforced at the call site in every instrumented function — only opaque
discriminators (`method`, `outcome`, `type`, `grant`, `provider`, `operation`)
are allowed. Emails, passwords, tokens, session IDs, and user IDs are never
included.
