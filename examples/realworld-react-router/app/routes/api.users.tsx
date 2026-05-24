import type { ActionFunctionArgs } from "react-router";
import { setSessionHeader } from "~/server/auth/session";
import { ConduitAuthError, registerUser } from "~/server/services/users";

export async function action({ request }: ActionFunctionArgs) {
  if (request.method !== "POST") {
    return Response.json({ errors: { body: ["method not allowed"] } }, { status: 405 });
  }
  const body = (await request.json().catch(() => ({}))) as {
    user?: { email: string; username: string; password: string };
  };
  if (!body.user) return Response.json({ errors: { body: ["user is required"] } }, { status: 422 });
  try {
    const r = await registerUser(body.user);
    return Response.json(
      {
        user: {
          email: r.profile.email,
          username: r.profile.username,
          bio: r.profile.bio,
          image: r.profile.image,
          token: r.sessionId,
        },
      },
      { headers: await setSessionHeader(r.sessionId) },
    );
  } catch (e) {
    if (e instanceof ConduitAuthError)
      return Response.json({ errors: { body: [e.message] } }, { status: e.status });
    throw e;
  }
}
