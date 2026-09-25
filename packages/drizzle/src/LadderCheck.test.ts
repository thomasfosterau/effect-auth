/**
 * `ladderCheck` (#193): the role column's `CHECK` is derived from the same
 * `Ladder` that drives the type and the runtime check, and a real Postgres
 * (PGlite) enforces it — the database-level backstop the applications
 * hand-mirrored (gardeneria `users_role_valid`).
 */
import { PGlite } from "@electric-sql/pglite";
import { PgDialect, pgTable, text } from "drizzle-orm/pg-core";
import { describe, expect, it } from "vite-plus/test";
import * as Auth from "@thomasfosterau/effect-auth";
import { ladderCheck } from "./LadderCheck.ts";

const Roles = Auth.Ladder.make(["user", "contributor", "moderator", "admin"]);
const users = pgTable("users", { id: text("id").primaryKey(), role: text("role").notNull() });
const dialect = new PgDialect();

/** The expression as drizzle-kit emits it into DDL: parameters inlined. */
const ddl = () => dialect.sqlToQuery(ladderCheck(users.role, Roles), "indexes").sql;

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
    const client = await PGlite.create();
    try {
      await client.exec(
        `create table users (id text primary key, role text not null, constraint users_role_valid check (${ddl()}))`,
      );
      for (const role of Roles.rungs) {
        await client.query("insert into users (id, role) values ($1, $2)", [`u-${role}`, role]);
      }
      for (const notARung of ["superadmin", "ADMIN", ""]) {
        await expect(
          client.query("insert into users (id, role) values ($1, $2)", [`x-${notARung}`, notARung]),
        ).rejects.toThrow(/users_role_valid/);
      }
    } finally {
      await client.close();
    }
  });
});
