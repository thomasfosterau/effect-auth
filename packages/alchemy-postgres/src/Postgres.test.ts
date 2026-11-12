/**
 * The Postgres runtime path (`@thomasfosterau/effect-auth-alchemy-postgres`)
 * against a real Postgres server, through `@effect/sql-pg`: the driver a
 * Worker runs over its Hyperdrive binding.
 *
 * It needs a server, so it runs where `DATABASE_URL` names one: CI's alchemy
 * job starts one and runs this file in `test:alchemy`, which declares the
 * variable (and `CI`) so it reaches the suite (#766). Under CI a missing
 * `DATABASE_URL` fails every case; anywhere else the cases skip with a
 * warning. A Hyperdrive binding is just `{ connectionString }`, so the
 * binding-shaped source is exercised as such.
 */

import { Config, DateTime, Effect, Redacted } from "effect";
import * as Option from "effect/Option";
import { assert, describe, expect, it } from "vite-plus/test";
import * as Auth from "@thomasfosterau/effect-auth";
import * as Testing from "@thomasfosterau/effect-auth/testing";
import * as Postgres from "./Postgres.ts";

const databaseUrl = Option.getOrUndefined(
  Effect.runSync(Config.option(Config.Redacted("DATABASE_URL"))),
);

/** `CI` is set (GitHub Actions sets `CI=true`): the server is required, never skipped. */
const underCi = Effect.runSync(Config.Boolean("CI").pipe(Config.withDefault(false)));
const skipWithoutServer = databaseUrl === undefined && !underCi;
if (skipWithoutServer) {
  Effect.runSync(
    Effect.logWarning(
      "Postgres.test.ts: DATABASE_URL is not set, so every case skips (under CI they fail)",
    ),
  );
}

const url = (): Redacted.Redacted => {
  assert(databaseUrl !== undefined, "DATABASE_URL must name the Postgres server under CI");
  return databaseUrl;
};

describe.skipIf(skipWithoutServer)("effect-auth on Postgres over @effect/sql-pg", () => {
  it("migrates by URL, then round-trips a user and a session over a Hyperdrive-shaped binding", async () => {
    await Effect.runPromise(Postgres.migrate(url()));
    const hyperdrive: Postgres.Hyperdrive = { connectionString: Redacted.value(url()) };
    const result = await Effect.runPromise(
      Effect.gen(function* () {
        const users = yield* Auth.Email.EmailPasswordStore;
        const sessions = yield* Auth.SessionStore;
        const { user } = yield* users.createUser({ name: "Ada", attributes: { plan: "pro" } });
        const now = yield* DateTime.nowAsDate;
        const id = `sess-${user.id}`;
        yield* sessions.create({
          id,
          userId: user.id,
          expiresAt: DateTime.toDateUtc(DateTime.makeUnsafe(now.getTime() + 60_000)),
          createdAt: now,
          lastActivityAt: now,
          attributes: {},
        });
        const loaded = yield* sessions.get(id);
        yield* sessions.delete(id);
        return { user, loaded };
      }).pipe(Effect.provide(Postgres.layer(hyperdrive, { maxConnections: 1 }))),
    );
    expect(result.user.attributes).toEqual({ plan: "pro" });
    expect(result.loaded?.userId).toBe(result.user.id);
  });

  it("purges expired rows", async () => {
    const result = await Effect.runPromise(Postgres.purgeExpired(url()));
    expect(result).toBeDefined();
  });

  // The WebAuthn challenge store keeps each challenge's ceremony in a table of
  // its own (#591); the core's suite pins it over this driver too.
  describe("ChallengeStore conformance", () => {
    it.for(Testing.challengeStoreConformance().cases)("$name", async (testCase) => {
      const outcome = await Effect.runPromise(
        Postgres.migrate(url()).pipe(
          Effect.andThen(
            testCase.run.pipe(
              Effect.provide(
                Postgres.layer({ connectionString: Redacted.value(url()) }, { maxConnections: 1 }),
              ),
            ),
          ),
        ),
      );
      // A case succeeds with no value; a contract mismatch rejects.
      expect(outcome).toBeUndefined();
    });
  });
});
