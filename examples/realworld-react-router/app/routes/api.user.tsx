import type { ActionFunctionArgs, LoaderFunctionArgs } from "react-router";
import { getCurrentUser } from "~/server/auth/session";
import { ConduitAuthError, updateUser } from "~/server/services/users";

export async function loader({ request }: LoaderFunctionArgs) {
  const { user, sessionId } = await getCurrentUser(request);
  if (!user) return Response.json({ errors: { body: ["unauthorized"] } }, { status: 401 });
  return Response.json({
    user: {
      email: user.email,
      username: user.username,
      bio: user.bio,
      image: user.image,
      token: sessionId ?? "",
    },
  });
}

export async function action({ request }: ActionFunctionArgs) {
  if (request.method !== "PUT")
    return Response.json({ errors: { body: ["method not allowed"] } }, { status: 405 });
  const { user, sessionId } = await getCurrentUser(request);
  if (!user) return Response.json({ errors: { body: ["unauthorized"] } }, { status: 401 });
  const body = (await request.json().catch(() => ({}))) as { user?: Record<string, unknown> };
  if (!body.user) return Response.json({ errors: { body: ["user is required"] } }, { status: 422 });
  try {
    const updated = await updateUser(user.id, body.user as never);
    return Response.json({
      user: {
        email: updated.email,
        username: updated.username,
        bio: updated.bio,
        image: updated.image,
        token: sessionId ?? "",
      },
    });
  } catch (e) {
    if (e instanceof ConduitAuthError)
      return Response.json({ errors: { body: [e.message] } }, { status: e.status });
    throw e;
  }
}
