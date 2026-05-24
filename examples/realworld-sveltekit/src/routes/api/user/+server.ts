import { json, type RequestHandler } from "@sveltejs/kit";
import { requireApiUser } from "$lib/server/api/auth";
import { ConduitAuthError, updateUser } from "$lib/server/services/users";

// GET /api/user — current user
export const GET: RequestHandler = async (event) => {
  const user = await requireApiUser(event);
  return json({
    user: {
      email: user.email,
      username: user.username,
      bio: user.bio,
      image: user.image,
      token: event.locals.sessionId ?? "",
    },
  });
};

// PUT /api/user — update current user
export const PUT: RequestHandler = async (event) => {
  const user = await requireApiUser(event);
  const body = (await event.request.json().catch(() => ({}))) as { user?: Record<string, unknown> };
  if (!body.user) return json({ errors: { body: ["user is required"] } }, { status: 422 });
  try {
    const patch = body.user as {
      email?: string;
      username?: string;
      bio?: string | null;
      image?: string | null;
      password?: string;
    };
    const updated = await updateUser(user.id, patch);
    return json({
      user: {
        email: updated.email,
        username: updated.username,
        bio: updated.bio,
        image: updated.image,
        token: event.locals.sessionId ?? "",
      },
    });
  } catch (e) {
    if (e instanceof ConduitAuthError)
      return json({ errors: { body: [e.message] } }, { status: e.status });
    throw e;
  }
};
