import { createError, defineEventHandler, getRouterParam, setResponseStatus } from "h3";
import { requireCurrentUser } from "../../../../auth/session";
import { ConduitCommentError, deleteComment } from "../../../../services/comments";

export default defineEventHandler(async (event) => {
  const me = await requireCurrentUser(event);
  const slug = getRouterParam(event, "slug")!;
  const id = Number(getRouterParam(event, "id"));
  try {
    deleteComment(slug, id, me.id);
    setResponseStatus(event, 204);
    return null;
  } catch (e) {
    if (e instanceof ConduitCommentError)
      throw createError({ statusCode: e.status, statusMessage: e.message });
    throw e;
  }
});
