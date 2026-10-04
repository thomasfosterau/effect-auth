import { Metric } from "effect";
import { describe, it, expect } from "vite-plus/test";
import * as Obs from "./Observability.ts";

describe("Observability", () => {
  describe("Metric names", () => {
    // Read the ids off the exported metrics themselves, so a counter renamed
    // (or added) in Observability.ts is checked here without editing a list.
    const exportedMetrics = Object.entries(Obs).flatMap(([name, value]) =>
      Metric.isMetric(value) ? [{ name, id: value.id }] : [],
    );

    it("every exported metric name matches the Prometheus naming rule", () => {
      const prometheusNamePattern = /^[a-zA-Z_:][a-zA-Z0-9_:]*$/;

      expect(exportedMetrics.length).toBeGreaterThan(0);
      for (const metric of exportedMetrics) {
        expect(
          prometheusNamePattern.test(metric.id),
          `Metric '${metric.name}' has invalid name '${metric.id}'. ` +
            `Must match pattern /^[a-zA-Z_:][a-zA-Z0-9_:]*$/`,
        ).toBe(true);
      }
    });

    it("pins every counter's published name", () => {
      expect(Object.fromEntries(exportedMetrics.map(({ name, id }) => [name, id]))).toEqual({
        signInTotal: "effect_auth_sign_in_total",
        signUpTotal: "effect_auth_sign_up_total",
        sessionsCreated: "effect_auth_sessions_created_total",
        sessionsValidated: "effect_auth_sessions_validated_total",
        sessionResolutions: "effect_auth_session_resolutions_total",
        sessionsInvalidated: "effect_auth_sessions_invalidated_total",
        tokenVerifications: "effect_auth_token_verifications_total",
        rateLimitHits: "effect_auth_rate_limit_hits_total",
        multiFactorChallenges: "effect_auth_multi_factor_challenges_total",
        multiFactorVerifications: "effect_auth_multi_factor_verifications_total",
        oauthCallbacks: "effect_auth_oauth_callbacks_total",
        oauthRefreshes: "effect_auth_oauth_refreshes_total",
        webauthnRegistrations: "effect_auth_webauthn_registrations_total",
        webauthnAuthentications: "effect_auth_webauthn_authentications_total",
        oidcTokenRequests: "effect_auth_oidc_token_requests_total",
        deliverySends: "effect_auth_delivery_sends_total",
      });
    });
  });

  describe("Span names", () => {
    it("all span names are defined", () => {
      expect(Obs.spanNames).toBeDefined();
      expect(Object.keys(Obs.spanNames).length).toBeGreaterThan(0);
    });

    it("span names follow dotted naming convention", () => {
      const dottedPattern = /^effect-auth\./;

      for (const [key, spanName] of Object.entries(Obs.spanNames)) {
        expect(
          dottedPattern.test(spanName),
          `Span name '${key}' has value '${spanName}' which doesn't start with 'effect-auth.'`,
        ).toBe(true);
      }
    });
  });
});
