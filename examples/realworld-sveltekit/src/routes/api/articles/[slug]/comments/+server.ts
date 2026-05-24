import { json, type RequestHandler } from "@sveltejs/kit";
import { requireApiUser, resolveApiUser } from "$lib/server/api/auth";
import { ConduitCommentError, addComment, listComments } from "$lib/server/services/comments";

export const GET: RequestHandler = async (event) => {
  const viewer = await resolveApiUser(event);
  const comments = listComments(event.params.slug!, viewer?.id ?? null);
  return json({ comments });
};

export const POST: RequestHandler = async (event) => {
  const me = await requireApiUser(event);
  const body = (await event.request.json().catch(() => ({}))) as { comment?: { body: string } };
  if (!body.comment) return json({ errors: { body: ["comment is required"] } }, { status: 422 });
  try {
    const comment = addComment(event.params.slug!, me.id, body.comment.body);
    return json({ comment });
  } catch (e) {
    if (e instanceof ConduitCommentError)
      return json({ errors: { body: [e.message] } }, { status: e.status });
    throw e;
  }
};
