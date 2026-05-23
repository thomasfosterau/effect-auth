import { error, json, type RequestHandler } from "@sveltejs/kit";
import { resolveApiUser } from "$lib/server/api/auth";
import { getProfile } from "$lib/server/services/profiles";

export const GET: RequestHandler = async (event) => {
  const viewer = await resolveApiUser(event);
  const profile = getProfile(event.params.username!, viewer?.id ?? null);
  if (!profile) throw error(404, { message: "profile not found" });
  return json({
    profile: {
      username: profile.username,
      bio: profile.bio,
      image: profile.image,
      following: profile.following ?? false,
    },
  });
};
