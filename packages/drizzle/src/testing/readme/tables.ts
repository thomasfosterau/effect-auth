/**
 * The scope the README's sign-up writer examples (#406) are compiled in: the
 * application's users table, NOT NULL and nullable, and its drizzle `db`.
 * `ReadmeSignUpWriter.test.ts` sets `db` and checks that the README shows the
 * writers in `NotNullWriter.ts` and `NullableWriter.ts` verbatim.
 *
 * Never published (`tsconfig.json` excludes `src/testing/`).
 */

import { boolean, pgTable, timestamp, uuid, varchar } from "drizzle-orm/pg-core";
import type { PgliteDatabase } from "drizzle-orm/pglite";

/** An application users table with `email` NOT NULL and `email_verified_at` mapped. */
export const notNullUsers = pgTable("app_users_readme_strict", {
  userId: uuid("id").primaryKey(),
  name: varchar("name", { length: 255 }),
  email: varchar("email", { length: 255 }).notNull().unique(),
  emailVerified: boolean("email_verified").notNull().default(false),
  emailVerifiedAt: timestamp("email_verified_at", { mode: "date", withTimezone: true }),
  createdAt: timestamp("created_at", { mode: "date", withTimezone: true }).notNull(),
  updatedAt: timestamp("updated_at", { mode: "date", withTimezone: true }).notNull(),
});

/** The same table with a nullable `email`. */
export const nullableUsers = pgTable("app_users_readme", {
  userId: uuid("id").primaryKey(),
  name: varchar("name", { length: 255 }),
  email: varchar("email", { length: 255 }).unique(),
  emailVerified: boolean("email_verified").notNull().default(false),
  emailVerifiedAt: timestamp("email_verified_at", { mode: "date", withTimezone: true }),
  createdAt: timestamp("created_at", { mode: "date", withTimezone: true }).notNull(),
  updatedAt: timestamp("updated_at", { mode: "date", withTimezone: true }).notNull(),
});

/** The DDL for both tables. */
export const readmeTablesSql = `
  CREATE TABLE IF NOT EXISTS app_users_readme_strict (
    id uuid PRIMARY KEY,
    name varchar(255),
    email varchar(255) NOT NULL UNIQUE,
    email_verified boolean NOT NULL DEFAULT false,
    email_verified_at timestamptz,
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL
  );
  CREATE TABLE IF NOT EXISTS app_users_readme (
    id uuid PRIMARY KEY,
    name varchar(255),
    email varchar(255) UNIQUE,
    email_verified boolean NOT NULL DEFAULT false,
    email_verified_at timestamptz,
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL
  );
`;

/** The application's drizzle database; the test sets it before calling a writer. */
export let db: PgliteDatabase;

export const setDb = (database: PgliteDatabase): void => {
  db = database;
};
