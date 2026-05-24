import { fail, redirect } from "@sveltejs/kit";
import type { Actions, PageServerLoad } from "./$types";
import { clearSessionCookie } from "$lib/server/auth/cookies";
import { invalidateSession } from "$lib/server/auth/sessions";
import { ConduitAuthError, updateUser } from "$lib/server/services/users";

export const load: PageServerLoad = ({ locals }) => {
  if (!locals.user) throw redirect(303, "/login");
  return { user: locals.user };
};

export const actions: Actions = {
  update: async ({ request, locals }) => {
    if (!locals.user) return fail(401, { errors: ["unauthorized"] });
    const data = await request.formData();
    try {
      await updateUser(locals.user.id, {
        image: String(data.get("image") ?? "") || null,
        username: String(data.get("username") ?? "") || undefined,
        bio: String(data.get("bio") ?? "") || null,
        email: String(data.get("email") ?? "") || undefined,
        password: String(data.get("password") ?? "") || undefined,
      });
    } catch (e) {
      if (e instanceof ConduitAuthError) return fail(e.status, { errors: [e.message] });
      throw e;
    }
    throw redirect(303, `/profile/${data.get("username")}`);
  },
  logout: async ({ locals, cookies }) => {
    if (locals.sessionId) await invalidateSession(locals.sessionId);
    clearSessionCookie(cookies);
    throw redirect(303, "/");
  },
};
