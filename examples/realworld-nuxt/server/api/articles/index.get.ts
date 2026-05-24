import { defineEventHandler, getQuery } from "h3";
import { resolveCurrentUser } from "../../auth/session";
import { listArticles } from "../../services/articles";

export default defineEventHandler(async (event) => {
  const { user } = await resolveCurrentUser(event);
  const q = getQuery(event);
  return listArticles(
    {
      tag: (q.tag as string) ?? undefined,
      author: (q.author as string) ?? undefined,
      favorited: (q.favorited as string) ?? undefined,
      limit: q.limit ? Number(q.limit) : undefined,
      offset: q.offset ? Number(q.offset) : undefined,
    },
    user?.id ?? null,
  );
});
