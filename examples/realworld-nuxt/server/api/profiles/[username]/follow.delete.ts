import { createError, defineEventHandler, getRouterParam } from "h3";
import { requireCurrentUser } from "../../../auth/session";
import { unfollow } from "../../../services/profiles";

export default defineEventHandler(async (event) => {
  const me = await requireCurrentUser(event);
  const username = getRouterParam(event, "username")!;
  try {
    const profile = unfollow(me.id, username);
    return {
      profile: {
        username: profile.username,
        bio: profile.bio,
        image: profile.image,
        following: false,
      },
    };
  } catch (e) {
    const status = (e as { status?: number }).status ?? 500;
    throw createError({ statusCode: status, statusMessage: (e as Error).message });
  }
});
