import { createError, defineEventHandler, getRouterParam, readBody } from "h3";
import { requireCurrentUser } from "../../../../auth/session";
import { ConduitCommentError, addComment } from "../../../../services/comments";

export default defineEventHandler(async (event) => {
  const me = await requireCurrentUser(event);
  const slug = getRouterParam(event, "slug")!;
  const body = (await readBody(event).catch(() => ({}))) as { comment?: { body: string } };
  if (!body.comment) throw createError({ statusCode: 422, statusMessage: "comment is required" });
  try {
    return { comment: addComment(slug, me.id, body.comment.body) };
  } catch (e) {
    if (e instanceof ConduitCommentError)
      throw createError({ statusCode: e.status, statusMessage: e.message });
    throw e;
  }
});
