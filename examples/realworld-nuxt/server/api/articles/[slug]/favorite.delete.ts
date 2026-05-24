import { createError, defineEventHandler, getRouterParam } from "h3";
import { requireCurrentUser } from "../../../auth/session";
import { ConduitArticleError, unfavorite } from "../../../services/articles";

export default defineEventHandler(async (event) => {
  const me = await requireCurrentUser(event);
  const slug = getRouterParam(event, "slug")!;
  try {
    return { article: unfavorite(me.id, slug) };
  } catch (e) {
    if (e instanceof ConduitArticleError)
      throw createError({ statusCode: e.status, statusMessage: e.message });
    throw e;
  }
});
