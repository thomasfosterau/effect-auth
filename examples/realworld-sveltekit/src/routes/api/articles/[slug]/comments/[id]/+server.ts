import { json, type RequestHandler } from "@sveltejs/kit";
import { requireApiUser } from "$lib/server/api/auth";
import { ConduitCommentError, deleteComment } from "$lib/server/services/comments";

export const DELETE: RequestHandler = async (event) => {
  const me = await requireApiUser(event);
  const id = Number(event.params.id);
  try {
    deleteComment(event.params.slug!, id, me.id);
    return new Response(null, { status: 204 });
  } catch (e) {
    if (e instanceof ConduitCommentError)
      return json({ errors: { body: [e.message] } }, { status: e.status });
    throw e;
  }
};
