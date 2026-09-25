/**
 * The ladder's rungs as a Schema (#193): the allowed role set is declared once
 * and drives the type and the runtime check (and, in
 * `@thomasfosterau/effect-auth-drizzle`, the DDL `CHECK`).
 */
import { describe, expect, it } from "vite-plus/test";
import { Schema } from "effect";
import * as Ladder from "./Ladder.ts";
import * as LadderSchema from "./LadderSchema.ts";

const Roles = Ladder.make(["user", "commenter", "editor", "admin"]);

describe("LadderSchema.rung", () => {
  const decode = Schema.decodeUnknownExit(LadderSchema.rung(Roles));

  it("accepts every rung", () => {
    for (const role of Roles.rungs) expect(decode(role)._tag).toBe("Success");
  });

  it("refuses anything off the ladder", () => {
    for (const notARung of ["", "ADMIN", "superadmin", null, 3, undefined]) {
      expect(decode(notARung)._tag, String(notARung)).toBe("Failure");
    }
  });

  it("types a decoded role as the ladder's rung union", () => {
    const role: Ladder.RungOf<typeof Roles> = Schema.decodeUnknownSync(LadderSchema.rung(Roles))(
      "editor",
    );
    expect(Roles.hasAtLeast({ role }, "commenter")).toBe(true);
  });
});
