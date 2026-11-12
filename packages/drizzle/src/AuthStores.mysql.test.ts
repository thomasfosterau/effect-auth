/**
 * The stores beyond sign-in on MySQL, without a MySQL server: as in
 * `MySqlSchema.test.ts`, `drizzle-orm/mysql-proxy` compiles the store calls to
 * the SQL a server would receive, and these cases pin it (#675). What is
 * MySQL's own here is `RateLimitStore.increment`'s upsert: MySQL has
 * `ON DUPLICATE KEY UPDATE` and no `RETURNING`, so the count is read back.
 */

import { drizzle } from "drizzle-orm/mysql-proxy";
import { Effect, Layer } from "effect";
import { TestClock } from "effect/testing";
import { describe, expect, it } from "vite-plus/test";
import * as Auth from "@thomasfosterau/effect-auth";
import { databaseLayer } from "./Database.ts";
import { tables } from "./MySqlSchema.ts";
import * as RateLimitStore from "./RateLimitStore.ts";
import { mysqlProxyConfig, normalizeSql } from "./testing/DrizzleLine.ts";
import * as TokenStore from "./TokenStore.ts";

/** Records each statement; every `SELECT` answers with `rows`. */
const recording = (rows: ReadonlyArray<ReadonlyArray<unknown>>) => {
  const sent: Array<{ readonly sql: string; readonly params: ReadonlyArray<unknown> }> = [];
  const db = drizzle(async (sql, params, method) => {
    sent.push({ sql: normalizeSql(sql), params });
    return method === "all"
      ? { rows: rows.map((row) => [...row]) }
      : { rows: [{ insertId: 0, affectedRows: 1 }] };
  }, mysqlProxyConfig);
  return { db, sent };
};

describe("MySQL / RateLimitStore", () => {
  it("re-opens an expired window, upserts the count, then reads it back", async () => {
    const proxy = recording([["ip:1", 3, "2030-01-01 00:00:00.000", null]]);
    const count = await Effect.runPromise(
      Effect.gen(function* () {
        const store = yield* Auth.RateLimitStore;
        return yield* store.increment("ip:1", 60);
      }).pipe(
        Effect.provide(RateLimitStore.layer(tables).pipe(Layer.provide(databaseLayer(proxy.db)))),
      ),
    );
    expect(count).toBe(3);
    expect(proxy.sent.map((statement) => statement.sql)).toEqual([
      "update `effect_auth_rate_limits` set `count` = ?, `reset_at` = ?, `blocked_until` = ? where (`effect_auth_rate_limits`.`key` = ? and `effect_auth_rate_limits`.`reset_at` <= ?)",
      "insert into `effect_auth_rate_limits` (`key`, `count`, `reset_at`, `blocked_until`) values (?, ?, ?, ?) on duplicate key update `count` = `effect_auth_rate_limits`.`count` + 1",
      "select `key`, `count`, `reset_at`, `blocked_until` from `effect_auth_rate_limits` where `effect_auth_rate_limits`.`key` = ? limit ?",
    ]);
    expect(proxy.sent.every((statement) => !statement.sql.includes("returning"))).toBe(true);
  });

  it("purgeExpired is one DELETE of the rows whose window and block have both passed (#686)", async () => {
    const proxy = recording([]);
    await Effect.runPromise(
      RateLimitStore.purgeExpired(tables).pipe(
        Effect.provide(Layer.merge(databaseLayer(proxy.db), TestClock.layer())),
      ),
    );
    expect(proxy.sent.map((statement) => statement.sql)).toEqual([
      "delete from `effect_auth_rate_limits` where (`effect_auth_rate_limits`.`reset_at` <= ? and (`effect_auth_rate_limits`.`blocked_until` is null or `effect_auth_rate_limits`.`blocked_until` <= ?))",
    ]);
    expect(proxy.sent[0]?.params).toHaveLength(2);
  });
});

describe("MySQL / TokenStore", () => {
  it("scopes every statement to the store's purpose", async () => {
    const proxy = recording([]);
    await Effect.runPromise(
      Effect.gen(function* () {
        const resets = yield* Auth.Password.PasswordResetStore;
        yield* resets.get("digest");
        yield* resets.deleteByUserId("user-1");
      }).pipe(
        Effect.provide(TokenStore.layer(tables).pipe(Layer.provide(databaseLayer(proxy.db)))),
      ),
    );
    expect(proxy.sent.map((statement) => statement.params)).toEqual([
      ["digest", "password-reset", 1],
      ["user-1", "password-reset"],
    ]);
  });
});
