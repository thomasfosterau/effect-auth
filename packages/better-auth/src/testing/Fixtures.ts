/**
 * A real, in-memory BetterAuth instance for the suites: no network, no
 * database. `better-auth/test`'s `getTestInstance` is avoided because it
 * imports `vitest` directly and defaults to `node:sqlite`.
 */
import { assert } from "vite-plus/test";
import { DateTime, Effect, Layer } from "effect";
import { betterAuth, type BetterAuthOptions } from "better-auth";
import { memoryAdapter } from "better-auth/adapters/memory";
import { admin, bearer, username } from "better-auth/plugins";
import { BetterAuthInstance, type ColumnValue } from "../BetterAuth.ts";
import * as Session from "../Session.ts";
import * as Users from "../Users.ts";
import * as Credentials from "../Credentials.ts";

export type Row = Record<string, ColumnValue>;
export type Tables = Record<string, Array<Row>>;

export const makeAuth = (options: Partial<BetterAuthOptions> = {}) => {
  const db: Tables = { user: [], session: [], account: [], verification: [] };
  const auth = betterAuth({
    database: memoryAdapter(db),
    emailAndPassword: { enabled: true },
    secret: "a-test-secret-that-is-long-enough-for-better-auth",
    baseURL: "http://localhost",
    logger: { disabled: true },
    rateLimit: { enabled: false },
    telemetry: { enabled: false },
    plugins: [admin(), username(), bearer()],
    user: { additionalFields: { plan: { type: "string", required: false } } },
    session: { additionalFields: { device: { type: "string", required: false } } },
    ...options,
  });
  return { auth, db };
};

export type TestAuth = ReturnType<typeof makeAuth>["auth"];

const layers = (auth: TestAuth) =>
  Layer.mergeAll(
    Session.BetterAuthSessions.layer,
    Session.sessionServiceLayer,
    Users.usersLayer(),
    Credentials.BetterAuthCredentials.layer,
  ).pipe(Layer.provideMerge(BetterAuthInstance.layer(auth)));

export type Services = Layer.Success<ReturnType<typeof layers>>;

export const run = <A, E>(auth: TestAuth, effect: Effect.Effect<A, E, Services>): Promise<A> =>
  Effect.runPromise(effect.pipe(Effect.provide(layers(auth))));

export const runExit = <A, E>(auth: TestAuth, effect: Effect.Effect<A, E, Services>) =>
  Effect.runPromiseExit(effect.pipe(Effect.provide(layers(auth))));

/** Sign a user up through BetterAuth and answer the cookie header and raw token. */
export const signUp = async (
  auth: TestAuth,
  email = `${globalThis.crypto.randomUUID()}@example.test`,
  password = "correct horse battery",
) => {
  const { headers, response } = await auth.api.signUpEmail({
    body: { email, password, name: "Ada" },
    returnHeaders: true,
  });
  const cookie = headers
    .getSetCookie()
    .map((line) => line.split(";")[0])
    .join("; ");
  const token = response.token ?? assert.fail("sign-up issued no session");
  return { user: response.user, token, cookie, email, password };
};

/** The instant `ms` after the epoch. */
export const at = (ms: number): Date => DateTime.toDate(DateTime.makeUnsafe(ms));

/** The instant `ms` from now (negative for the past). */
export const fromNow = (ms: number): Date =>
  DateTime.toDate(DateTime.add(DateTime.nowUnsafe(), { milliseconds: ms }));

/** A row of the in-memory tables, failing the test when it is missing. */
export const rowOf = (db: Tables, model: string, match: (row: Row) => boolean = () => true): Row =>
  db[model]?.find(match) ?? assert.fail(`no ${model} row`);

export const requestWith = (headers: Record<string, string>) =>
  new Request("http://localhost/page", { headers });
