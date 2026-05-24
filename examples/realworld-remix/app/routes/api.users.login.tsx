import { json, type ActionFunctionArgs } from "@remix-run/node";
import { setSessionHeader } from "~/server/auth/session";
import { ConduitAuthError, loginUser } from "~/server/services/users";

export async function action({ request }: ActionFunctionArgs) {
  const body = (await request.json().catch(() => ({}))) as {
    user?: { email: string; password: string };
  };
  if (!body.user) return json({ errors: { body: ["user is required"] } }, { status: 422 });
  try {
    const r = await loginUser(body.user);
    return json(
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
      return json({ errors: { "email or password": ["is invalid"] } }, { status: e.status });
    throw e;
  }
}
