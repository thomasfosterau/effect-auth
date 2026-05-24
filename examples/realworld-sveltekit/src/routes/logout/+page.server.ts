import { redirect } from "@sveltejs/kit";
import type { Actions, PageServerLoad } from "./$types";
import { clearSessionCookie } from "$lib/server/auth/cookies";
import { invalidateSession } from "$lib/server/auth/sessions";

export const load: PageServerLoad = () => {
  throw redirect(303, "/");
};

export const actions: Actions = {
  default: async ({ locals, cookies }) => {
    if (locals.sessionId) await invalidateSession(locals.sessionId);
    clearSessionCookie(cookies);
    throw redirect(303, "/");
  },
};
