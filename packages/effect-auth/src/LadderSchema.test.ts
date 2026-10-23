/**
 * The ladder's rungs as a Schema (#193): the allowed role set is declared once
 * and drives the type and the runtime check (and, in
 * `@thomasfosterau/effect-auth-drizzle`, the DDL `CHECK`).
 */
import { describe, expect, it } from "vite-plus/test";
import { Array as Arr, Schema } from "effect";
import * as Ladder from "./Ladder.ts";
import * as LadderSchema from "./LadderSchema.ts";

const Roles = Ladder.make(["user", "commenter", "editor", "admin"]);

describe("LadderSchema.rung", () => {
  const decode = Schema.decodeUnknownExit(LadderSchema.rung(Roles));

  it("accepts every rung", () => {
    Arr.forEach(Roles.rungs, (role) => {
      expect(decode(role)._tag).toBe("Success");
    });
  });

  it("refuses anything off the ladder", () => {
    Arr.forEach(["", "ADMIN", "superadmin", null, 3, undefined], (notARung) => {
      expect(decode(notARung)._tag, String(notARung)).toBe("Failure");
    });
  });

  it("types a decoded role as the ladder's rung union", () => {
    const role: Ladder.RungOf<typeof Roles> = Schema.decodeUnknownSync(LadderSchema.rung(Roles))(
      "editor",
    );
    expect(Roles.hasAtLeast({ role }, "commenter")).toBe(true);
  });
});
