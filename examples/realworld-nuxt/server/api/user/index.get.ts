import { defineEventHandler } from "h3";
import { requireCurrentUser } from "../../auth/session";

export default defineEventHandler(async (event) => {
  const user = await requireCurrentUser(event);
  return {
    user: {
      email: user.email,
      username: user.username,
      bio: user.bio,
      image: user.image,
      token: event.context.sessionId ?? "",
    },
  };
});
