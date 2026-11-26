import { assert, describe, expect, it } from "vite-plus/test";
import { Effect, Layer, Redacted } from "effect";
import * as Result from "effect/Result";
import * as Schema from "effect/Schema";
import { Hex } from "effect/encoding";
import { TestClock } from "effect/testing";
import * as Auth from "@thomasfosterau/effect-auth";
import { RevokedSessions } from "./Session.ts";
import { verify, WorkOSEvents, type WorkOSEvent } from "./Webhook.ts";
import { path } from "./WorkOS.ts";

const secret = Redacted.make("whsec_test");
const NOW = 1_800_000_000_000;

const user = {
  id: "user_1",
  email: "ada@example.com",
  email_verified: true,
  first_name: null,
  last_name: null,
  name: null,
  profile_picture_url: null,
  last_sign_in_at: null,
  external_id: null,
  metadata: {},
  created_at: "2026-01-01T00:00:00.000Z",
  updated_at: "2026-01-01T00:00:00.000Z",
};
const session = {
  id: "session_1",
  user_id: "user_1",
  organization_id: null,
  status: "inactive",
  auth_method: "Password",
  ip_address: null,
  user_agent: null,
  impersonator: null,
  expires_at: "2026-02-01T00:00:00.000Z",
  ended_at: null,
  created_at: "2026-01-01T00:00:00.000Z",
  updated_at: "2026-01-01T00:00:00.000Z",
};
const encodeJson = Schema.encodeSync(Schema.fromJsonString(Schema.Json));
const body = (event: string, data: Schema.Json) =>
  encodeJson({ id: "event_1", event, data, created_at: "2026-01-01T00:00:00.000Z" });

const sign = (raw: string, t: number, key = "whsec_test") =>
  Effect.map(Auth.hmac("sha256", key, `${t}.${raw}`), (mac) => `t=${t}, v1=${Hex.encode(mac)}`);

const run = <A, E>(program: Effect.Effect<A, E, Auth.PlatformCrypto.Services | RevokedSessions>) =>
  Effect.runPromise(
    Effect.gen(function* () {
      yield* TestClock.setTime(NOW);
      return yield* program;
    }).pipe(
      Effect.provide(
        Layer.mergeAll(Auth.PlatformCrypto.layer, RevokedSessions.layerMemory, TestClock.layer()),
      ),
    ),
  );

const reasonOf = (result: Result.Result<WorkOSEvent, { readonly _tag: string }>) => {
  assert(Result.isFailure(result));
  return "reason" in result.failure ? result.failure.reason : result.failure._tag;
};

describe("Webhook.verify", () => {
  it("accepts a signed event within the tolerance and types it", async () => {
    await run(
      Effect.gen(function* () {
        const raw = body("user.deleted", user);
        const event = yield* verify(raw, yield* sign(raw, NOW - 60_000), secret);
        assert(event.known && event.event === "user.deleted");
        expect(event.data.id).toBe("user_1");
      }),
    );
  });

  it("refuses a missing, malformed, stale, forged or re-serialized webhook", async () => {
    await run(
      Effect.gen(function* () {
        const raw = body("user.deleted", user);
        const check = (header: string | undefined, payload = raw) =>
          Effect.map(Effect.result(verify(payload, header, secret)), reasonOf);
        expect(yield* check(undefined)).toBe("missing-header");
        expect(yield* check("v1=abc")).toBe("malformed-header");
        expect(yield* check(`t=${NOW}, v1=zz`)).toBe("malformed-header");
        expect(yield* check(yield* sign(raw, NOW - 181_000))).toBe("stale");
        expect(yield* check(yield* sign(raw, NOW + 181_000))).toBe("stale");
        expect(yield* check(yield* sign(raw, NOW, "whsec_other"))).toBe("bad-signature");
        const reformatted = raw.replaceAll(",", ", ");
        expect(yield* check(yield* sign(raw, NOW), reformatted)).toBe("bad-signature");
        const junk = "not json";
        expect(yield* check(yield* sign(junk, NOW), junk)).toBe("bad-body");
      }),
    );
  });

  it("keeps an unknown event, or one whose data does not decode, as unknown", async () => {
    await run(
      Effect.gen(function* () {
        const other = body("organization.created", { id: "org_1" });
        const event = yield* verify(other, yield* sign(other, NOW), secret);
        expect(event.known).toBe(false);
        const odd = body("user.deleted", { id: 1 });
        expect((yield* verify(odd, yield* sign(odd, NOW), secret)).known).toBe(false);
      }),
    );
  });
});

describe("WorkOSEvents", () => {
  it("records session.revoked and runs onUserDeleted", async () => {
    const deleted: Array<string> = [];
    await run(
      Effect.gen(function* () {
        const events = yield* Effect.provide(
          WorkOSEvents,
          WorkOSEvents.layer({
            onUserDeleted: (id) => Effect.sync(() => deleted.push(id)),
          }),
        );
        const revoked = yield* RevokedSessions;
        yield* Effect.forEach(
          [body("session.revoked", session), body("user.deleted", user)],
          (raw) =>
            Effect.flatMap(sign(raw, NOW), (header) =>
              Effect.flatMap(verify(raw, header, secret), events.handle),
            ),
          { concurrency: 1 },
        );
        expect(yield* revoked.isRevoked("session_1")).toBe(true);
        expect(deleted).toEqual(["user_1"]);
      }),
    );
  });
});

describe("path", () => {
  it("encodes each id so it cannot add a segment", () => {
    expect(path`/users/${"a/b"}/sessions/${"c?d"}`).toBe("/users/a%2Fb/sessions/c%3Fd");
    expect(path`/users`).toBe("/users");
  });
});
