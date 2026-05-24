import type { ActionFunctionArgs, LoaderFunctionArgs } from "react-router";
import { getCurrentUser } from "~/server/auth/session";
import { ConduitCommentError, addComment, listComments } from "~/server/services/comments";

export async function loader({ request, params }: LoaderFunctionArgs) {
  const { user } = await getCurrentUser(request);
  return Response.json({ comments: listComments(params.slug!, user?.id ?? null) });
}

export async function action({ request, params }: ActionFunctionArgs) {
  const { user } = await getCurrentUser(request);
  if (!user) return Response.json({ errors: { body: ["unauthorized"] } }, { status: 401 });
  const body = (await request.json().catch(() => ({}))) as { comment?: { body: string } };
  if (!body.comment)
    return Response.json({ errors: { body: ["comment is required"] } }, { status: 422 });
  try {
    return Response.json({ comment: addComment(params.slug!, user.id, body.comment.body) });
  } catch (e) {
    if (e instanceof ConduitCommentError)
      return Response.json({ errors: { body: [e.message] } }, { status: e.status });
    throw e;
  }
}
