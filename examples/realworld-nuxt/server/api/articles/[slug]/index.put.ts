import { createError, defineEventHandler, getRouterParam, readBody } from "h3";
import { requireCurrentUser } from "../../../auth/session";
import { ConduitArticleError, updateArticle } from "../../../services/articles";

export default defineEventHandler(async (event) => {
  const me = await requireCurrentUser(event);
  const slug = getRouterParam(event, "slug")!;
  const body = (await readBody(event).catch(() => ({}))) as {
    article?: { title?: string; description?: string; body?: string };
  };
  if (!body.article) throw createError({ statusCode: 422, statusMessage: "article is required" });
  try {
    return { article: updateArticle(me.id, slug, body.article) };
  } catch (e) {
    if (e instanceof ConduitArticleError)
      throw createError({ statusCode: e.status, statusMessage: e.message });
    throw e;
  }
});
