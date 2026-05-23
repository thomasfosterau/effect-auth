import { json, type RequestHandler } from "@sveltejs/kit";
import { setSessionCookie } from "$lib/server/auth/cookies";
import { ConduitAuthError, loginUser } from "$lib/server/services/users";

// POST /api/users/login
export const POST: RequestHandler = async ({ request, cookies }) => {
  const body = (await request.json().catch(() => ({}))) as {
    user?: { email: string; password: string };
  };
  if (!body.user) return json({ errors: { body: ["user is required"] } }, { status: 422 });
  try {
    const result = await loginUser(body.user);
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
      return json({ errors: { "email or password": ["is invalid"] } }, { status: e.status });
    throw e;
  }
};
