import { fail, redirect } from "@sveltejs/kit";
import type { Actions, PageServerLoad } from "./$types";
import { setSessionCookie } from "$lib/server/auth/cookies";
import { ConduitAuthError, registerUser } from "$lib/server/services/users";

export const load: PageServerLoad = ({ locals }) => {
  if (locals.user) throw redirect(303, "/");
  return {};
};

export const actions: Actions = {
  default: async ({ request, cookies }) => {
    const data = await request.formData();
    const email = String(data.get("email") ?? "");
    const username = String(data.get("username") ?? "");
    const password = String(data.get("password") ?? "");
    try {
      const result = await registerUser({ email, username, password });
      setSessionCookie(cookies, result.sessionId, result.expiresAt);
    } catch (e) {
      if (e instanceof ConduitAuthError)
        return fail(e.status, { errors: [e.message], email, username });
      throw e;
    }
    throw redirect(303, "/");
  },
};
