/**
 * `ApiKeyStore`, `TokenStore` and `RateLimitStore` over an application's own
 * tables, mapped with `defineApiKeyTable`, `defineTokenTable` and
 * `defineRateLimitTable`, on PostgreSQL (PGlite).
 *
 * First the whole store contract over tables whose names and column names are
 * the application's; then the reason the mapping exists: `uuid` owner columns
 * with a foreign key into the application's `users`, whose `ON DELETE CASCADE`
 * drops a deleted user's keys and pending tokens.
 */

import { createHash } from "node:crypto";
import type { PGlite } from "@electric-sql/pglite";
import { drizzle } from "drizzle-orm/pglite";
import {
  bigint,
  boolean,
  integer,
  jsonb,
  pgTable,
  text,
  timestamp,
  uuid,
  varchar,
} from "drizzle-orm/pg-core";
import * as Effect from "effect/Effect";
import * as Layer from "effect/Layer";
import * as Option from "effect/Option";
import { afterAll, beforeAll, describe, expect, it } from "vite-plus/test";
import * as Auth from "@thomasfosterau/effect-auth";
import * as ApiKeyStore from "./ApiKeyStore.ts";
import { defineApiKeyTable, defineRateLimitTable, defineTokenTable } from "./Columns.ts";
import { databaseLayer } from "./Database.ts";
import { tables } from "./PgSchema.ts";
import type { ApiKeyPermissions } from "./Schema.ts";
import * as TokenStore from "./TokenStore.ts";
import { authStoresContract, authStoresLayer } from "./testing/AuthStoresContract.ts";
import { migratedPglite } from "./testing/PgliteTemplate.ts";

/** A token's digest, as core's `hashToken` computes it. */
const hashToken = (token: string): string => createHash("sha256").update(token).digest("hex");

let client: PGlite;

beforeAll(async () => {
  client = await migratedPglite();
  await client.exec(`
    CREATE TABLE app_users (id uuid PRIMARY KEY);
    CREATE TABLE app_api_keys (
      key_id text PRIMARY KEY,
      owner_id uuid NOT NULL REFERENCES app_users (id) ON DELETE CASCADE,
      label text,
      key_prefix text,
      key_start text NOT NULL,
      digest text NOT NULL UNIQUE,
      active boolean NOT NULL DEFAULT true,
      expires timestamptz,
      last_used timestamptz,
      scopes jsonb,
      extra jsonb,
      uses_left integer,
      refill_by integer,
      refill_every bigint,
      refill_cap integer,
      refilled timestamptz,
      limit_requests integer,
      limit_window bigint,
      created timestamptz NOT NULL,
      updated timestamptz NOT NULL
    );
    CREATE TABLE app_tokens (
      digest text PRIMARY KEY,
      kind text NOT NULL,
      owner_id uuid NOT NULL REFERENCES app_users (id) ON DELETE CASCADE,
      address text NOT NULL,
      created timestamptz NOT NULL,
      expires timestamptz NOT NULL
    );
    CREATE TABLE app_throttle (
      bucket varchar(255) PRIMARY KEY,
      hits integer NOT NULL,
      window_ends timestamptz NOT NULL,
      blocked_until timestamptz
    );
    -- The contract's owners are random ids with no user row, so its tables
    -- are copies without the foreign key.
    CREATE TABLE contract_api_keys (LIKE app_api_keys INCLUDING ALL);
    ALTER TABLE contract_api_keys ALTER COLUMN owner_id TYPE text;
    CREATE TABLE contract_tokens (LIKE app_tokens INCLUDING ALL);
    ALTER TABLE contract_tokens ALTER COLUMN owner_id TYPE text;
  `);
});

afterAll(async () => {
  await client?.close();
});

const instant = (name: string) => timestamp(name, { mode: "date", withTimezone: true });

const apiKeyColumns = {
  keyId: text("key_id").primaryKey(),
  label: text("label"),
  keyPrefix: text("key_prefix"),
  keyStart: text("key_start").notNull(),
  digest: text("digest").notNull(),
  active: boolean("active").notNull().default(true),
  expires: instant("expires"),
  lastUsed: instant("last_used"),
  scopes: jsonb("scopes").$type<ApiKeyPermissions>(),
  extra: jsonb("extra").$type<Auth.JsonObject>(),
  usesLeft: integer("uses_left"),
  refillBy: integer("refill_by"),
  refillEvery: bigint("refill_every", { mode: "number" }),
  refillCap: integer("refill_cap"),
  refilled: instant("refilled"),
  limitRequests: integer("limit_requests"),
  limitWindow: bigint("limit_window", { mode: "number" }),
  created: instant("created").notNull(),
  updated: instant("updated").notNull(),
};

const tokenColumns = {
  digest: text("digest").primaryKey(),
  kind: text("kind").notNull(),
  address: text("address").notNull(),
  created: instant("created").notNull(),
  expires: instant("expires").notNull(),
};

const appUsers = pgTable("app_users", { id: uuid("id").primaryKey() });

const appApiKeys = pgTable("app_api_keys", {
  ...apiKeyColumns,
  ownerId: uuid("owner_id")
    .notNull()
    .references(() => appUsers.id, { onDelete: "cascade" }),
});

const appTokens = pgTable("app_tokens", {
  ...tokenColumns,
  ownerId: uuid("owner_id")
    .notNull()
    .references(() => appUsers.id, { onDelete: "cascade" }),
});

const contractApiKeys = pgTable("contract_api_keys", {
  ...apiKeyColumns,
  ownerId: text("owner_id").notNull(),
});

const contractTokens = pgTable("contract_tokens", {
  ...tokenColumns,
  ownerId: text("owner_id").notNull(),
});

const throttle = pgTable("app_throttle", {
  bucket: varchar("bucket", { length: 255 }).primaryKey(),
  hits: integer("hits").notNull(),
  windowEnds: instant("window_ends").notNull(),
  blockedUntil: instant("blocked_until"),
});

const apiKeyMapping = {
  id: "keyId",
  userId: "ownerId",
  name: "label",
  prefix: "keyPrefix",
  start: "keyStart",
  keyHash: "digest",
  enabled: "active",
  expiresAt: "expires",
  lastUsedAt: "lastUsed",
  permissions: "scopes",
  metadata: "extra",
  remaining: "usesLeft",
  refillAmount: "refillBy",
  refillInterval: "refillEvery",
  refillMax: "refillCap",
  lastRefillAt: "refilled",
  rateLimitMaxRequests: "limitRequests",
  rateLimitWindowMs: "limitWindow",
  createdAt: "created",
  updatedAt: "updated",
} as const;

const tokenMapping = {
  token: "digest",
  purpose: "kind",
  userId: "ownerId",
  email: "address",
  createdAt: "created",
  expiresAt: "expires",
} as const;

const rateLimits = defineRateLimitTable({
  table: throttle,
  columns: { key: "bucket", count: "hits", resetAt: "windowEnds", blockedUntil: "blockedUntil" },
});

authStoresContract("PostgreSQL, application tables", (effect) =>
  Effect.runPromise(
    effect.pipe(
      Effect.provide(
        authStoresLayer(tables, {
          apiKeys: defineApiKeyTable({ table: contractApiKeys, columns: apiKeyMapping }),
          tokens: defineTokenTable({ table: contractTokens, columns: tokenMapping }),
          rateLimits,
        }).pipe(Layer.provide(databaseLayer(drizzle({ client })))),
      ),
    ),
  ),
);

describe("an application's own API key and token tables", () => {
  const stores = Layer.mergeAll(
    ApiKeyStore.layer(defineApiKeyTable({ table: appApiKeys, columns: apiKeyMapping })),
    TokenStore.layer(defineTokenTable({ table: appTokens, columns: tokenMapping })),
  );

  it("lose a deleted user's keys and pending tokens through the foreign key's cascade", async () => {
    const userId = globalThis.crypto.randomUUID();
    const other = globalThis.crypto.randomUUID();
    await client.query("INSERT INTO app_users (id) VALUES ($1), ($2)", [userId, other]);
    const key = (id: string, owner: string): Auth.ApiKey => ({
      id,
      start: "ea_",
      keyHash: hashToken(id),
      userId: owner,
      enabled: true,
      metadata: {},
      createdAt: 0,
      updatedAt: 0,
    });
    const token = (owner: string) => ({
      token: hashToken(globalThis.crypto.randomUUID()),
      userId: owner,
      email: "ada@example.com",
      createdAt: 0,
      expiresAt: 60_000,
    });
    const verification = token(userId);
    const reset = token(userId);
    const kept = key(globalThis.crypto.randomUUID(), other);
    const run = <A, E>(
      effect: Effect.Effect<
        A,
        E,
        Auth.ApiKeyStore | Auth.Email.EmailVerificationStore | Auth.Password.PasswordResetStore
      >,
    ) =>
      Effect.runPromise(
        effect.pipe(Effect.provide(stores.pipe(Layer.provide(databaseLayer(drizzle({ client })))))),
      );

    await run(
      Effect.gen(function* () {
        const keys = yield* Auth.ApiKeyStore;
        yield* keys.create(key(globalThis.crypto.randomUUID(), userId));
        yield* keys.create(kept);
        yield* (yield* Auth.Email.EmailVerificationStore).create(verification);
        yield* (yield* Auth.Password.PasswordResetStore).create(reset);
      }),
    );
    await client.query("DELETE FROM app_users WHERE id = $1", [userId]);

    const after = await run(
      Effect.gen(function* () {
        const keys = yield* Auth.ApiKeyStore;
        return {
          keys: yield* keys.listByUserId(userId),
          kept: Option.getOrNull(yield* keys.get(kept.id)),
          verification: Option.getOrNull(
            yield* (yield* Auth.Email.EmailVerificationStore).get(verification.token),
          ),
          reset: Option.getOrNull(
            yield* (yield* Auth.Password.PasswordResetStore).get(reset.token),
          ),
        };
      }),
    );
    expect(after).toEqual({ keys: [], kept, verification: null, reset: null });
  });

  it("refuses a key whose owner the users table does not hold", async () => {
    const error = await Effect.runPromise(
      Effect.flip(
        Auth.ApiKeyStore.use((keys) =>
          keys.create({
            id: globalThis.crypto.randomUUID(),
            start: "ea_",
            keyHash: hashToken(globalThis.crypto.randomUUID()),
            userId: globalThis.crypto.randomUUID(),
            enabled: true,
            metadata: {},
            createdAt: 0,
            updatedAt: 0,
          }),
        ).pipe(Effect.provide(stores.pipe(Layer.provide(databaseLayer(drizzle({ client })))))),
      ),
    );
    expect(error).toBeInstanceOf(Auth.AuthError);
  });
});
