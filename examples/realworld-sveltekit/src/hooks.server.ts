import type { Handle } from "@sveltejs/kit";
import { clearSessionCookie, getSessionId, setSessionCookie } from "$lib/server/auth/cookies";
import { validateSession } from "$lib/server/auth/sessions";
import { getUserById } from "$lib/server/services/users";

export const handle: Handle = async ({ event, resolve }) => {
  event.locals.user = null;
  event.locals.sessionId = null;

  const sid = getSessionId(event.cookies);
  if (sid) {
    const result = await validateSession(sid);
    if (result._tag === "Right") {
      const { session } = result.right;
      event.locals.sessionId = session.id;
      const profile = getUserById(session.userId);
      if (profile) {
        event.locals.user = profile;
        setSessionCookie(event.cookies, session.id, session.expiresAt);
      } else {
        clearSessionCookie(event.cookies);
      }
    } else {
      clearSessionCookie(event.cookies);
    }
  }

  return resolve(event);
};
