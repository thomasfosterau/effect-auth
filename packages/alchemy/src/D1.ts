/**
 * Thin Effect bindings over a Cloudflare D1 database.
 *
 * The {@link D1Database} interface is the minimal structural subset of the
 * Cloudflare D1 client that these stores use. The handle returned by Alchemy
 * v2's `Cloudflare.D1Database.bind(...)`, the `D1Database` type from
 * `@cloudflare/workers-types`, and Miniflare's local implementation all
 * satisfy it, so no Cloudflare type dependency is required here.
 */

import { Effect } from "effect";
import * as Auth from "@thomasfosterau/effect-auth";

/**
 * Minimal structural shape of a Cloudflare D1 database.
 */
export interface D1Database {
  prepare(query: string): D1PreparedStatement;
}

/**
 * Minimal structural shape of a prepared D1 statement.
 */
export interface D1PreparedStatement {
  bind(...values: readonly unknown[]): D1PreparedStatement;
  first<T = unknown>(): Promise<T | null>;
  all<T = unknown>(): Promise<D1Result<T>>;
  run<T = unknown>(): Promise<D1Result<T>>;
}

/**
 * Result envelope returned by D1's `all`/`run`.
 */
export interface D1Result<T = unknown> {
  readonly results: readonly T[];
  readonly success: boolean;
  readonly meta: unknown;
}

const prepared = (db: D1Database, sql: string, params: readonly unknown[]): D1PreparedStatement =>
  db.prepare(sql).bind(...params);

const toAuthError =
  (label: string) =>
  (cause: unknown): Auth.AuthError =>
    new Auth.AuthError({ message: `D1 ${label} failed`, cause });

/**
 * Execute a write statement (INSERT/UPDATE/DELETE/DDL).
 */
export const d1Run = (
  db: D1Database,
  sql: string,
  params: readonly unknown[] = [],
  label = "run",
): Effect.Effect<D1Result, Auth.AuthError> =>
  Effect.tryPromise({
    try: () => prepared(db, sql, params).run(),
    catch: toAuthError(label),
  });

/**
 * Fetch the first row of a query, or `null` when there are no rows.
 */
export const d1First = <T>(
  db: D1Database,
  sql: string,
  params: readonly unknown[] = [],
  label = "query",
): Effect.Effect<T | null, Auth.AuthError> =>
  Effect.tryPromise({
    try: () => prepared(db, sql, params).first<T>(),
    catch: toAuthError(label),
  });

/**
 * Fetch every row of a query.
 */
export const d1All = <T>(
  db: D1Database,
  sql: string,
  params: readonly unknown[] = [],
  label = "query",
): Effect.Effect<readonly T[], Auth.AuthError> =>
  Effect.tryPromise({
    try: () => prepared(db, sql, params).all<T>(),
    catch: toAuthError(label),
  }).pipe(Effect.map((result) => result.results));
