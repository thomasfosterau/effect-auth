import { createError, defineEventHandler, getRouterParam } from "h3";
import { resolveCurrentUser } from "../../../auth/session";
import { getProfile } from "../../../services/profiles";

export default defineEventHandler(async (event) => {
  const username = getRouterParam(event, "username")!;
  const { user } = await resolveCurrentUser(event);
  const profile = getProfile(username, user?.id ?? null);
  if (!profile) throw createError({ statusCode: 404, statusMessage: "profile not found" });
  return {
    profile: {
      username: profile.username,
      bio: profile.bio,
      image: profile.image,
      following: profile.following ?? false,
    },
  };
});
