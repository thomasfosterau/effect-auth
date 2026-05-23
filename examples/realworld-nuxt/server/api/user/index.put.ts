import { createError, defineEventHandler, readBody } from "h3";
import { requireCurrentUser } from "../../auth/session";
import { ConduitAuthError, updateUser } from "../../services/users";

export default defineEventHandler(async (event) => {
  const me = await requireCurrentUser(event);
  const body = (await readBody(event).catch(() => ({}))) as { user?: Record<string, unknown> };
  if (!body.user) throw createError({ statusCode: 422, statusMessage: "user is required" });
  try {
    const updated = await updateUser(me.id, body.user as never);
    return {
      user: {
        email: updated.email,
        username: updated.username,
        bio: updated.bio,
        image: updated.image,
        token: event.context.sessionId ?? "",
      },
    };
  } catch (e) {
    if (e instanceof ConduitAuthError)
      throw createError({ statusCode: e.status, statusMessage: e.message });
    throw e;
  }
});
