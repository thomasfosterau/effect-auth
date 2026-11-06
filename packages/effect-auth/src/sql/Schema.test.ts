import { describe, expect, it } from "vite-plus/test";
import { authTableNames, schemaStatements } from "./Schema.ts";

describe("authTableNames", () => {
  it("lists every table the DDL creates, and only those", () => {
    const creates = schemaStatements.filter((statement) => /^\s*create\s+table/i.test(statement));
    expect(authTableNames).toHaveLength(creates.length);
    expect(authTableNames).toContain("auth_users");
    expect(authTableNames).toContain("auth_sessions");
    expect(authTableNames).toContain("auth_identifiers");
    expect(authTableNames.every((name) => name.startsWith("auth_"))).toBe(true);
  });
});
