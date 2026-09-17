import { describe, it, expect } from "vite-plus/test";
import * as Obs from "./Observability.ts";

describe("Observability", () => {
  describe("Metric names", () => {
    it("all metric names match Prometheus naming convention", () => {
      const prometheusNamePattern = /^[a-zA-Z_:][a-zA-Z0-9_:]*$/;

      const metrics = [
        { name: "signInTotal", value: Obs.signInTotal },
        { name: "signUpTotal", value: Obs.signUpTotal },
        { name: "sessionsCreated", value: Obs.sessionsCreated },
        { name: "sessionsValidated", value: Obs.sessionsValidated },
        { name: "sessionsInvalidated", value: Obs.sessionsInvalidated },
        { name: "tokenVerifications", value: Obs.tokenVerifications },
        { name: "rateLimitHits", value: Obs.rateLimitHits },
        { name: "multiFactorChallenges", value: Obs.multiFactorChallenges },
        { name: "multiFactorVerifications", value: Obs.multiFactorVerifications },
        { name: "oauthCallbacks", value: Obs.oauthCallbacks },
        { name: "oauthRefreshes", value: Obs.oauthRefreshes },
        { name: "webauthnRegistrations", value: Obs.webauthnRegistrations },
        { name: "webauthnAuthentications", value: Obs.webauthnAuthentications },
        { name: "oidcTokenRequests", value: Obs.oidcTokenRequests },
      ];

      for (const metric of metrics) {
        const metricName = metric.value.id;
        expect(
          prometheusNamePattern.test(metricName),
          `Metric '${metric.name}' has invalid name '${metricName}'. ` +
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
