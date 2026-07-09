/**
 * Observability primitives: tracing spans (via `Effect.withSpan`) and metric
 * counters (via `Effect.Metric`) for all auth operations.
 *
 * Both are zero-cost no-ops when no Tracer or metric backend is in context —
 * Effect handles this natively, so there is no configuration needed to get
 * zero overhead.
 *
 * Security: **no PII is ever stored in span attributes or metric labels.**
 * Only non-identifying discriminators are recorded (algorithm, grant type,
 * outcome, provider, method).
 *
 * @module observability
 */

import { Effect, Metric } from "effect";

// ---------------------------------------------------------------------------
// Metric counters
// ---------------------------------------------------------------------------

/** Sign-in attempts. Attributes: `{ method, outcome }`. */
export const signInTotal = Metric.counter("effect-auth.sign_in.total", {
  description: "Sign-in attempts — tagged by method and outcome",
  incremental: true,
});

/** Sign-up attempts. Attributes: `{ method, outcome }`. */
export const signUpTotal = Metric.counter("effect-auth.sign_up.total", {
  description: "Sign-up attempts — tagged by method and outcome",
  incremental: true,
});

/** Sessions successfully created. */
export const sessionsCreated = Metric.counter("effect-auth.sessions_created.total", {
  description: "Sessions successfully created",
  incremental: true,
});

/** Session validation attempts. Attributes: `{ outcome }`. */
export const sessionsValidated = Metric.counter("effect-auth.sessions_validated.total", {
  description: "Session validation attempts — tagged by outcome",
  incremental: true,
});

/** Sessions invalidated (sign-out). */
export const sessionsInvalidated = Metric.counter("effect-auth.sessions_invalidated.total", {
  description: "Sessions invalidated",
  incremental: true,
});

/** Token verification attempts. Attributes: `{ type, outcome }`. */
export const tokenVerifications = Metric.counter("effect-auth.token_verifications.total", {
  description: "Token verification attempts — tagged by type and outcome",
  incremental: true,
});

/** Rate-limit threshold breaches. Attributes: `{ operation }`. */
export const rateLimitHits = Metric.counter("effect-auth.rate_limit_hits.total", {
  description: "Rate-limit threshold breaches — tagged by operation",
  incremental: true,
});

/** Two-factor challenges started. */
export const twoFactorChallenges = Metric.counter("effect-auth.two_factor_challenges.total", {
  description: "Two-factor challenges started",
  incremental: true,
});

/** Two-factor verification attempts. Attributes: `{ type, outcome }`. */
export const twoFactorVerifications = Metric.counter("effect-auth.two_factor_verifications.total", {
  description: "Two-factor verification attempts — tagged by type and outcome",
  incremental: true,
});

/** OAuth callback completions. Attributes: `{ outcome }`. */
export const oauthCallbacks = Metric.counter("effect-auth.oauth_callbacks.total", {
  description: "OAuth callback completions — tagged by outcome",
  incremental: true,
});

/** OAuth access-token refresh attempts. Attributes: `{ provider, outcome }`. */
export const oauthRefreshes = Metric.counter("effect-auth.oauth_refreshes.total", {
  description: "OAuth access-token refresh attempts — tagged by provider and outcome",
  incremental: true,
});

/** WebAuthn registration verifications. Attributes: `{ outcome }`. */
export const webauthnRegistrations = Metric.counter("effect-auth.webauthn_registrations.total", {
  description: "WebAuthn registration verifications — tagged by outcome",
  incremental: true,
});

/** WebAuthn authentication verifications. Attributes: `{ outcome }`. */
export const webauthnAuthentications = Metric.counter(
  "effect-auth.webauthn_authentications.total",
  {
    description: "WebAuthn authentication verifications — tagged by outcome",
    incremental: true,
  },
);

/** OIDC token endpoint requests. Attributes: `{ grant, outcome }`. */
export const oidcTokenRequests = Metric.counter("effect-auth.oidc_token_requests.total", {
  description: "OIDC token endpoint requests — tagged by grant type and outcome",
  incremental: true,
});

// ---------------------------------------------------------------------------
// Record helpers — each returns Effect<void, never, never>
// ---------------------------------------------------------------------------

export const recordSignIn = (method: string, outcome: "success" | "failure"): Effect.Effect<void> =>
  Metric.update(Metric.withAttributes(signInTotal, { method, outcome }), 1);

export const recordSignUp = (method: string, outcome: "success" | "failure"): Effect.Effect<void> =>
  Metric.update(Metric.withAttributes(signUpTotal, { method, outcome }), 1);

export const recordSessionCreated = (): Effect.Effect<void> => Metric.update(sessionsCreated, 1);

export const recordSessionValidated = (
  outcome: "success" | "not_found" | "expired",
): Effect.Effect<void> => Metric.update(Metric.withAttributes(sessionsValidated, { outcome }), 1);

export const recordSessionInvalidated = (): Effect.Effect<void> =>
  Metric.update(sessionsInvalidated, 1);

export const recordTokenVerification = (
  type: string,
  outcome: "success" | "failure",
): Effect.Effect<void> =>
  Metric.update(Metric.withAttributes(tokenVerifications, { type, outcome }), 1);

export const recordRateLimitHit = (operation: string): Effect.Effect<void> =>
  Metric.update(Metric.withAttributes(rateLimitHits, { operation }), 1);

export const recordTwoFactorChallenge = (): Effect.Effect<void> =>
  Metric.update(twoFactorChallenges, 1);

export const recordTwoFactorVerification = (
  type: "totp" | "backup-code",
  outcome: "success" | "failure",
): Effect.Effect<void> =>
  Metric.update(Metric.withAttributes(twoFactorVerifications, { type, outcome }), 1);

export const recordOAuthCallback = (outcome: "success" | "failure"): Effect.Effect<void> =>
  Metric.update(Metric.withAttributes(oauthCallbacks, { outcome }), 1);

export const recordOAuthRefresh = (
  provider: string,
  outcome: "success" | "failure",
): Effect.Effect<void> =>
  Metric.update(Metric.withAttributes(oauthRefreshes, { provider, outcome }), 1);

export const recordWebAuthnRegistration = (outcome: "success" | "failure"): Effect.Effect<void> =>
  Metric.update(Metric.withAttributes(webauthnRegistrations, { outcome }), 1);

export const recordWebAuthnAuthentication = (outcome: "success" | "failure"): Effect.Effect<void> =>
  Metric.update(Metric.withAttributes(webauthnAuthentications, { outcome }), 1);

export const recordOIDCTokenRequest = (
  grant: string,
  outcome: "success" | "failure",
): Effect.Effect<void> =>
  Metric.update(Metric.withAttributes(oidcTokenRequests, { grant, outcome }), 1);
