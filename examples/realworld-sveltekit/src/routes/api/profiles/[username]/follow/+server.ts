import { json, type RequestHandler } from "@sveltejs/kit";
import { requireApiUser } from "$lib/server/api/auth";
import { follow, unfollow } from "$lib/server/services/profiles";

export const POST: RequestHandler = async (event) => {
  const me = await requireApiUser(event);
  try {
    const profile = follow(me.id, event.params.username!);
    return json({
      profile: {
        username: profile.username,
        bio: profile.bio,
        image: profile.image,
        following: true,
      },
    });
  } catch (e) {
    const status = (e as { status?: number }).status ?? 500;
    return json({ errors: { body: [(e as Error).message] } }, { status });
  }
};

export const DELETE: RequestHandler = async (event) => {
  const me = await requireApiUser(event);
  try {
    const profile = unfollow(me.id, event.params.username!);
    return json({
      profile: {
        username: profile.username,
        bio: profile.bio,
        image: profile.image,
        following: false,
      },
    });
  } catch (e) {
    const status = (e as { status?: number }).status ?? 500;
    return json({ errors: { body: [(e as Error).message] } }, { status });
  }
};
