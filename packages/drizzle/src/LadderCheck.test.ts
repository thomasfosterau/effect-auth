/**
 * `ladderCheck` (#193): the role column's `CHECK` is derived from the same
 * `Ladder` that drives the type and the runtime check, and a real Postgres
 * (PGlite) enforces it — the database-level backstop the applications
 * hand-mirrored (gardeneria `users_role_valid`).
 */
import type { PGlite } from "@electric-sql/pglite";
import { PgDialect, pgTable, text } from "drizzle-orm/pg-core";
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vite-plus/test";
import * as Auth from "@thomasfosterau/effect-auth";
import { ladderCheck } from "./LadderCheck.ts";
import { migratedPglite, truncate } from "./testing/PgliteTemplate.ts";

const Roles = Auth.Ladder.make(["user", "contributor", "moderator", "admin"]);
const users = pgTable("users", { id: text("id").primaryKey(), role: text("role").notNull() });
const dialect = new PgDialect();

/** The expression as drizzle-kit emits it into DDL: parameters inlined. */
const ddl = () => dialect.sqlToQuery(ladderCheck(users.role, Roles), "indexes").sql;

/**
 * The file's one in-memory Postgres, opened from the run's migrated template
 * (#291). The template has no `users` table (its tables are `effect_auth_*`),
 * so this file creates the one whose `CHECK` it tests, and empties it before
 * each test.
 */
let client: PGlite;

beforeAll(async () => {
  client = await migratedPglite();
  await client.exec(
    `create table users (id text primary key, role text not null, constraint users_role_valid check (${ddl()}))`,
  );
});

afterAll(async () => {
  await client?.close();
});

beforeEach(async () => {
  await truncate(client, ["users"]);
});

describe("ladderCheck", () => {
  it("renders the ladder as a literal IN list, in rung order", () => {
    expect(ddl()).toBe(`"role" IN ('user', 'contributor', 'moderator', 'admin')`);
  });

  it("quotes a rung safely: the DDL cannot be broken out of", () => {
    const Odd = Auth.Ladder.make(["member", "it's"]);
    expect(dialect.sqlToQuery(ladderCheck(users.role, Odd), "indexes").sql).toBe(
      `"role" IN ('member', 'it''s')`,
    );
  });

  it("is enforced by Postgres: every rung is accepted, anything else refused", async () => {
    await Roles.rungs.reduce(async (previous, role) => {
      await previous;
      await client.query("insert into users (id, role) values ($1, $2)", [`u-${role}`, role]);
    }, Promise.resolve());
    await ["superadmin", "ADMIN", ""].reduce(async (previous, notARung) => {
      await previous;
      await expect(
        client.query("insert into users (id, role) values ($1, $2)", [`x-${notARung}`, notARung]),
      ).rejects.toThrow(/users_role_valid/);
    }, Promise.resolve());
  });
});
