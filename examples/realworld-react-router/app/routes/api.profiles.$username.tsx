import type { LoaderFunctionArgs } from "react-router";
import { getCurrentUser } from "~/server/auth/session";
import { getProfile } from "~/server/services/profiles";

export async function loader({ request, params }: LoaderFunctionArgs) {
  const { user } = await getCurrentUser(request);
  const profile = getProfile(params.username!, user?.id ?? null);
  if (!profile) return Response.json({ errors: { body: ["profile not found"] } }, { status: 404 });
  return Response.json({
    profile: {
      username: profile.username,
      bio: profile.bio,
      image: profile.image,
      following: profile.following ?? false,
    },
  });
}
