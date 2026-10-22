/**
 * The names of the tables the effect-auth schema creates.
 *
 * Kept apart from `AuthSchema.ts` because that module imports the alchemy
 * runtime (`alchemy/Provider`, `alchemy/Resource`) at the top, and nothing here
 * needs it: `Storage.test.ts` only wants the names, so it must not load alchemy.
 */
import * as Sql from "@thomasfosterau/effect-auth-sql";

const CREATE_TABLE = /create\s+table\s+if\s+not\s+exists\s+(\w+)/i;

/**
 * Every table the effect-auth schema creates, parsed from the shared
 * `schemaStatements` so it cannot drift from the DDL that is actually applied.
 */
export const authTableNames: readonly string[] = Sql.schemaStatements.flatMap((sql) => {
  const name = CREATE_TABLE.exec(sql)?.[1];
  return name === undefined ? [] : [name];
});
