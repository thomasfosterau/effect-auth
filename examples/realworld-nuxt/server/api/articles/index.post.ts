import { createError, defineEventHandler, readBody } from "h3";
import { requireCurrentUser } from "../../auth/session";
import { ConduitArticleError, createArticle } from "../../services/articles";

export default defineEventHandler(async (event) => {
  const me = await requireCurrentUser(event);
  const body = (await readBody(event).catch(() => ({}))) as {
    article?: { title: string; description: string; body: string; tagList?: string[] };
  };
  if (!body.article) throw createError({ statusCode: 422, statusMessage: "article is required" });
  try {
    return { article: createArticle(me.id, body.article) };
  } catch (e) {
    if (e instanceof ConduitArticleError)
      throw createError({ statusCode: e.status, statusMessage: e.message });
    throw e;
  }
});
