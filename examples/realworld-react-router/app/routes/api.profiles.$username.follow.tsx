import type { ActionFunctionArgs } from "react-router";
import { getCurrentUser } from "~/server/auth/session";
import { follow, unfollow } from "~/server/services/profiles";

export async function action({ request, params }: ActionFunctionArgs) {
  const { user } = await getCurrentUser(request);
  if (!user) return Response.json({ errors: { body: ["unauthorized"] } }, { status: 401 });
  try {
    const fn = request.method === "DELETE" ? unfollow : follow;
    const profile = fn(user.id, params.username!);
    return Response.json({
      profile: {
        username: profile.username,
        bio: profile.bio,
        image: profile.image,
        following: request.method !== "DELETE",
      },
    });
  } catch (e) {
    const status = (e as { status?: number }).status ?? 500;
    return Response.json({ errors: { body: [(e as Error).message] } }, { status });
  }
}
