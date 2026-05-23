import { json, type RequestHandler } from "@sveltejs/kit";
import { setSessionCookie } from "$lib/server/auth/cookies";
import { ConduitAuthError, registerUser } from "$lib/server/services/users";

// POST /api/users — register
export const POST: RequestHandler = async ({ request, cookies }) => {
  const body = (await request.json().catch(() => ({}))) as {
    user?: { email: string; username: string; password: string };
  };
  if (!body.user) return json({ errors: { body: ["user is required"] } }, { status: 422 });
  try {
    const result = await registerUser(body.user);
    setSessionCookie(cookies, result.sessionId, result.expiresAt);
    return json({
      user: {
        email: result.profile.email,
        username: result.profile.username,
        bio: result.profile.bio,
        image: result.profile.image,
        token: result.sessionId,
      },
    });
  } catch (e) {
    if (e instanceof ConduitAuthError)
      return json({ errors: { body: [e.message] } }, { status: e.status });
    throw e;
  }
};
