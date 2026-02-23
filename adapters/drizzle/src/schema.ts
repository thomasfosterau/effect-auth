import { pgTable, text, timestamp, jsonb } from "drizzle-orm/pg-core"

/**
 * Default sessions table schema for effect-auth.
 * Users can customize the table name by passing a different table to the store factories.
 */
export const sessionsTable = pgTable("effect_auth_sessions", {
  id: text("id").primaryKey(),
  userId: text("user_id").notNull(),
  expiresAt: timestamp("expires_at", { mode: "date", withTimezone: true }).notNull(),
  createdAt: timestamp("created_at", { mode: "date", withTimezone: true }).notNull(),
  lastActivityAt: timestamp("last_activity_at", { mode: "date", withTimezone: true }).notNull(),
  attributes: jsonb("attributes").$type<Record<string, unknown>>().notNull().default({}),
})

/**
 * Default users table schema for effect-auth.
 * Users can customize the table name by passing a different table to the store factories.
 */
export const usersTable = pgTable("effect_auth_users", {
  id: text("id").primaryKey(),
  attributes: jsonb("attributes").$type<Record<string, unknown>>().notNull().default({}),
  hashedPassword: text("hashed_password"),
})

export type SessionsTable = typeof sessionsTable
export type UsersTable = typeof usersTable
