import { defineEventHandler, getQuery } from "h3";
import { requireCurrentUser } from "../../auth/session";
import { feedArticles } from "../../services/articles";

export default defineEventHandler(async (event) => {
  const me = await requireCurrentUser(event);
  const q = getQuery(event);
  return feedArticles(me.id, q.limit ? Number(q.limit) : 20, q.offset ? Number(q.offset) : 0);
});
