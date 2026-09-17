import { describe, it, expect } from "vite-plus/test";
import * as Obs from "./Observability.ts";

describe("Observability", () => {
  describe("Metric names", () => {
    it("all metric names match Prometheus naming convention", () => {
      const prometheusNamePattern = /^[a-zA-Z_:][a-zA-Z0-9_:]*$/;

      const metrics = [
        { name: "signInTotal", metricName: "effect_auth_sign_in_total" },
        { name: "signUpTotal", metricName: "effect_auth_sign_up_total" },
        { name: "sessionsCreated", metricName: "effect_auth_sessions_created_total" },
        { name: "sessionsValidated", metricName: "effect_auth_sessions_validated_total" },
        { name: "sessionsInvalidated", metricName: "effect_auth_sessions_invalidated_total" },
        { name: "tokenVerifications", metricName: "effect_auth_token_verifications_total" },
        { name: "rateLimitHits", metricName: "effect_auth_rate_limit_hits_total" },
        { name: "multiFactorChallenges", metricName: "effect_auth_multi_factor_challenges_total" },
        {
          name: "multiFactorVerifications",
          metricName: "effect_auth_multi_factor_verifications_total",
        },
        { name: "oauthCallbacks", metricName: "effect_auth_oauth_callbacks_total" },
        { name: "oauthRefreshes", metricName: "effect_auth_oauth_refreshes_total" },
        { name: "webauthnRegistrations", metricName: "effect_auth_webauthn_registrations_total" },
        {
          name: "webauthnAuthentications",
          metricName: "effect_auth_webauthn_authentications_total",
        },
        { name: "oidcTokenRequests", metricName: "effect_auth_oidc_token_requests_total" },
      ];

      for (const metric of metrics) {
        expect(
          prometheusNamePattern.test(metric.metricName),
          `Metric '${metric.name}' has invalid name '${metric.metricName}'. ` +
            `Must match pattern /^[a-zA-Z_:][a-zA-Z0-9_:]*$/`,
        ).toBe(true);
      }
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
