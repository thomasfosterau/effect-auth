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
export const signInTotal = Metric.counter("effect_auth_sign_in_total", {
  description: "Sign-in attempts — tagged by method and outcome",
  incremental: true,
});

/** Sign-up attempts. Attributes: `{ method, outcome }`. */
export const signUpTotal = Metric.counter("effect_auth_sign_up_total", {
  description: "Sign-up attempts — tagged by method and outcome",
  incremental: true,
});

/** Sessions successfully created. */
export const sessionsCreated = Metric.counter("effect_auth_sessions_created_total", {
  description: "Sessions successfully created",
  incremental: true,
});

/** Session validation attempts. Attributes: `{ outcome }`. */
export const sessionsValidated = Metric.counter("effect_auth_sessions_validated_total", {
  description: "Session validation attempts — tagged by outcome",
  incremental: true,
});

/**
 * The four outcomes of a session-resolution *attempt* at an application edge.
 *
 * Deliberately four and not two. `skipped` and `anonymous` both end with no
 * viewer, but only `anonymous` paid the round trip — folding them corrupts the
 * duration bucket, since a skip is near-zero by construction. `degraded` is
 * separate again: the caller is anonymous because something broke, not because
 * nobody was signed in, and that distinction is the whole point of alerting on
 * it.
 *
 * One derivation, in `SessionResolution`, so two edges reporting the same fault
 * cannot label it differently.
 *
 * @since 1.0.0
 * @category models
 */
export type AuthOutcome =
  /** No credential was present; resolution never ran. */
  | "skipped"
  /** Resolution ran and returned a session. */
  | "resolved"
  /** Resolution ran and returned nothing (stale or expired credential). */
  | "anonymous"
  /** Resolution could not run, or threw. The caller degraded to anonymous. */
  | "degraded";

/** Session-resolution attempts at an app edge. Attributes: `{ outcome }`. */
export const sessionResolutions = Metric.counter("effect_auth_session_resolutions_total", {
  description: "Session-resolution attempts at an app edge — tagged by outcome",
  incremental: true,
});

/** Sessions invalidated (sign-out). */
export const sessionsInvalidated = Metric.counter("effect_auth_sessions_invalidated_total", {
  description: "Sessions invalidated",
  incremental: true,
});

/** Token verification attempts. Attributes: `{ type, outcome }`. */
export const tokenVerifications = Metric.counter("effect_auth_token_verifications_total", {
  description: "Token verification attempts — tagged by type and outcome",
  incremental: true,
});

/** Rate-limit threshold breaches. Attributes: `{ operation }`. */
export const rateLimitHits = Metric.counter("effect_auth_rate_limit_hits_total", {
  description: "Rate-limit threshold breaches — tagged by operation",
  incremental: true,
});

/** Two-factor challenges started. */
export const multiFactorChallenges = Metric.counter("effect_auth_multi_factor_challenges_total", {
  description: "Two-factor challenges started",
  incremental: true,
});

/** Two-factor verification attempts. Attributes: `{ type, outcome }`. */
export const multiFactorVerifications = Metric.counter(
  "effect_auth_multi_factor_verifications_total",
  {
    description: "Two-factor verification attempts — tagged by type and outcome",
    incremental: true,
  },
);

/** OAuth callback completions. Attributes: `{ outcome }`. */
export const oauthCallbacks = Metric.counter("effect_auth_oauth_callbacks_total", {
  description: "OAuth callback completions — tagged by outcome",
  incremental: true,
});

/** OAuth access-token refresh attempts. Attributes: `{ provider, outcome }`. */
export const oauthRefreshes = Metric.counter("effect_auth_oauth_refreshes_total", {
  description: "OAuth access-token refresh attempts — tagged by provider and outcome",
  incremental: true,
});

/** WebAuthn registration verifications. Attributes: `{ outcome }`. */
export const webauthnRegistrations = Metric.counter("effect_auth_webauthn_registrations_total", {
  description: "WebAuthn registration verifications — tagged by outcome",
  incremental: true,
});

/** WebAuthn authentication verifications. Attributes: `{ outcome }`. */
export const webauthnAuthentications = Metric.counter(
  "effect_auth_webauthn_authentications_total",
  {
    description: "WebAuthn authentication verifications — tagged by outcome",
    incremental: true,
  },
);

/** OIDC token endpoint requests. Attributes: `{ grant, outcome }`. */
export const oidcTokenRequests = Metric.counter("effect_auth_oidc_token_requests_total", {
  description: "OIDC token endpoint requests — tagged by grant type and outcome",
  incremental: true,
});

/**
 * Delivery sends dispatched off the response path (see `DeliveryScheduler.ts`).
 * Attributes: `{ purpose, outcome }`. Since these sends are never awaited by
 * their caller, this counter, the error log emitted alongside it and the
 * `afterDeliveryFailure` hook are how a failed send is observed.
 */
export const deliverySends = Metric.counter("effect_auth_delivery_sends_total", {
  description: "Delivery sends dispatched off the response path — tagged by purpose and outcome",
  incremental: true,
});

// ---------------------------------------------------------------------------
// Span names (OpenTelemetry)
// ---------------------------------------------------------------------------

/** The OpenTelemetry span names effect-auth emits, as constants. */
export const spanNames = {
  oauthAuthorize: "effect-auth.oauth.authorize",
  oauthCallback: "effect-auth.oauth.callback",
  oauthRefresh: "effect-auth.oauth.refresh",
  createSession: "effect-auth.create-session",
  validateSession: "effect-auth.validate-session",
  resolveSession: "effect-auth.resolve-session",
  remoteSessionRead: "effect-auth.remote-session.read",
  remoteSessionRelay: "effect-auth.remote-session.relay",
  signOut: "effect-auth.sign-out",
  twoFactorChallenge: "effect-auth.2fa.challenge",
  twoFactorVerify: "effect-auth.2fa.verify",
  webauthnRegister: "effect-auth.webauthn.register",
  webauthnAuthenticate: "effect-auth.webauthn.authenticate",
  oidcRegisterDynamicClient: "effect-auth.oidc.registerDynamicClient",
  oidcAuthorize: "effect-auth.oidc.authorize",
  oidcConsent: "effect-auth.oidc.consent",
  oidcToken: "effect-auth.oidc.token",
  oidcUserinfo: "effect-auth.oidc.userinfo",
  signUp: "effect-auth.sign-up",
  signIn: "effect-auth.sign-in",
  tokenSign: "effect-auth.token.sign",
  tokenVerify: "effect-auth.token.verify",
} as const;

// ---------------------------------------------------------------------------
// Record helpers — each returns Effect<void, never, never>
// ---------------------------------------------------------------------------

/** Count a sign-in attempt on `effect_auth_sign_in_total`, by method and outcome. */
export const recordSignIn = (method: string, outcome: "success" | "failure"): Effect.Effect<void> =>
  Metric.update(Metric.withAttributes(signInTotal, { method, outcome }), 1);

/** Count a sign-up attempt on `effect_auth_sign_up_total`, by method and outcome. */
export const recordSignUp = (method: string, outcome: "success" | "failure"): Effect.Effect<void> =>
  Metric.update(Metric.withAttributes(signUpTotal, { method, outcome }), 1);

/** Count a created session on `effect_auth_sessions_created_total`. */
export const recordSessionCreated = (): Effect.Effect<void> => Metric.update(sessionsCreated, 1);

/** Count a session validation on `effect_auth_sessions_validated_total`, by outcome. */
export const recordSessionValidated = (
  outcome: "success" | "not_found" | "expired",
): Effect.Effect<void> => Metric.update(Metric.withAttributes(sessionsValidated, { outcome }), 1);

/** Count an invalidated session on `effect_auth_sessions_invalidated_total`. */
export const recordSessionInvalidated = (): Effect.Effect<void> =>
  Metric.update(sessionsInvalidated, 1);

/**
 * Count an app-edge session resolution on `effect_auth_session_resolutions_total`, by outcome (`degraded` is kept apart from `anonymous`).
 */
export const recordSessionResolution = (outcome: AuthOutcome): Effect.Effect<void> =>
  Metric.update(Metric.withAttributes(sessionResolutions, { outcome }), 1);

/**
 * Count a token verification on `effect_auth_token_verifications_total`, by token type and outcome.
 */
export const recordTokenVerification = (
  type: string,
  outcome: "success" | "failure",
): Effect.Effect<void> =>
  Metric.update(Metric.withAttributes(tokenVerifications, { type, outcome }), 1);

/** Count a rate-limit rejection on `effect_auth_rate_limit_hits_total`, by operation. */
export const recordRateLimitHit = (operation: string): Effect.Effect<void> =>
  Metric.update(Metric.withAttributes(rateLimitHits, { operation }), 1);

/** Count an issued second-factor challenge on `effect_auth_multi_factor_challenges_total`. */
export const recordMultiFactorChallenge = (): Effect.Effect<void> =>
  Metric.update(multiFactorChallenges, 1);

/**
 * Count a second-factor verification on `effect_auth_multi_factor_verifications_total`, by factor type and outcome.
 */
export const recordMultiFactorVerification = (
  type: "totp" | "backup-code",
  outcome: "success" | "failure",
): Effect.Effect<void> =>
  Metric.update(Metric.withAttributes(multiFactorVerifications, { type, outcome }), 1);

/** Count an OAuth callback on `effect_auth_oauth_callbacks_total`, by outcome. */
export const recordOAuthCallback = (outcome: "success" | "failure"): Effect.Effect<void> =>
  Metric.update(Metric.withAttributes(oauthCallbacks, { outcome }), 1);

/** Count an OAuth token refresh on `effect_auth_oauth_refreshes_total`, by provider and outcome. */
export const recordOAuthRefresh = (
  provider: string,
  outcome: "success" | "failure",
): Effect.Effect<void> =>
  Metric.update(Metric.withAttributes(oauthRefreshes, { provider, outcome }), 1);

/** Count a passkey registration on `effect_auth_webauthn_registrations_total`, by outcome. */
export const recordWebAuthnRegistration = (outcome: "success" | "failure"): Effect.Effect<void> =>
  Metric.update(Metric.withAttributes(webauthnRegistrations, { outcome }), 1);

/** Count a passkey authentication on `effect_auth_webauthn_authentications_total`, by outcome. */
export const recordWebAuthnAuthentication = (outcome: "success" | "failure"): Effect.Effect<void> =>
  Metric.update(Metric.withAttributes(webauthnAuthentications, { outcome }), 1);

/**
 * Count an OIDC token-endpoint request on `effect_auth_oidc_token_requests_total`, by grant and outcome.
 */
export const recordOidcTokenRequest = (
  grant: string,
  outcome: "success" | "failure",
): Effect.Effect<void> =>
  Metric.update(Metric.withAttributes(oidcTokenRequests, { grant, outcome }), 1);

/** Count a delivery sent off the response path on `effect_auth_delivery_sends_total`, by purpose and outcome. */
export const recordDeliverySend = (
  purpose: string,
  outcome: "success" | "failure",
): Effect.Effect<void> =>
  Metric.update(Metric.withAttributes(deliverySends, { purpose, outcome }), 1);
