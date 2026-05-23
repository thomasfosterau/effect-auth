import { count, desc } from "drizzle-orm";
import { db, schema } from "../db/client.js";

export function listTags(limit = 20): string[] {
  const rows = db
    .select({ tag: schema.articleTags.tag, c: count() })
    .from(schema.articleTags)
    .groupBy(schema.articleTags.tag)
    .orderBy(desc(count()))
    .limit(limit)
    .all();
  return rows.map((r) => r.tag);
}
