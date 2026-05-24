import type { ActionFunctionArgs } from "react-router";
import { getCurrentUser } from "~/server/auth/session";
import { ConduitCommentError, deleteComment } from "~/server/services/comments";

export async function action({ request, params }: ActionFunctionArgs) {
  if (request.method !== "DELETE")
    return Response.json({ errors: { body: ["method not allowed"] } }, { status: 405 });
  const { user } = await getCurrentUser(request);
  if (!user) return Response.json({ errors: { body: ["unauthorized"] } }, { status: 401 });
  try {
    deleteComment(params.slug!, Number(params.id), user.id);
    return new Response(null, { status: 204 });
  } catch (e) {
    if (e instanceof ConduitCommentError)
      return Response.json({ errors: { body: [e.message] } }, { status: e.status });
    throw e;
  }
}
