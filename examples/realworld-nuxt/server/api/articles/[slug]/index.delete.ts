import { createError, defineEventHandler, getRouterParam, setResponseStatus } from "h3";
import { requireCurrentUser } from "../../../auth/session";
import { ConduitArticleError, deleteArticle } from "../../../services/articles";

export default defineEventHandler(async (event) => {
  const me = await requireCurrentUser(event);
  const slug = getRouterParam(event, "slug")!;
  try {
    deleteArticle(me.id, slug);
    setResponseStatus(event, 204);
    return null;
  } catch (e) {
    if (e instanceof ConduitArticleError)
      throw createError({ statusCode: e.status, statusMessage: e.message });
    throw e;
  }
});
