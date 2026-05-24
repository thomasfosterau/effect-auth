import { createError, defineEventHandler, readBody } from "h3";
import { setSessionCookie } from "../../auth/session";
import { ConduitAuthError, loginUser } from "../../services/users";

export default defineEventHandler(async (event) => {
  const body = (await readBody(event).catch(() => ({}))) as {
    user?: { email: string; password: string };
  };
  if (!body.user) throw createError({ statusCode: 422, statusMessage: "user is required" });
  try {
    const r = await loginUser(body.user);
    setSessionCookie(event, r.sessionId, r.expiresAt);
    return {
      user: {
        email: r.profile.email,
        username: r.profile.username,
        bio: r.profile.bio,
        image: r.profile.image,
        token: r.sessionId,
      },
    };
  } catch (e) {
    if (e instanceof ConduitAuthError)
      throw createError({ statusCode: e.status, statusMessage: e.message });
    throw e;
  }
});
