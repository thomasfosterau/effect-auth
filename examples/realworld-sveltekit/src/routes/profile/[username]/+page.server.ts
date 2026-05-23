import { error, redirect } from "@sveltejs/kit";
import type { Actions, PageServerLoad } from "./$types";
import { listArticles } from "$lib/server/services/articles";
import { follow, getProfile, unfollow } from "$lib/server/services/profiles";

export const load: PageServerLoad = ({ locals, params, url }) => {
  const viewerId = locals.user?.id ?? null;
  const profile = getProfile(params.username, viewerId);
  if (!profile) throw error(404, { message: "profile not found" });
  const tab = url.searchParams.get("tab") === "favorites" ? "favorites" : "my";
  const result =
    tab === "favorites"
      ? listArticles({ favorited: profile.username, limit: 10 }, viewerId)
      : listArticles({ author: profile.username, limit: 10 }, viewerId);
  return { profile, tab, articles: result.articles, articlesCount: result.articlesCount };
};

export const actions: Actions = {
  follow: async ({ locals, params }) => {
    if (!locals.user) throw redirect(303, "/login");
    follow(locals.user.id, params.username);
    return { success: true };
  },
  unfollow: async ({ locals, params }) => {
    if (!locals.user) throw redirect(303, "/login");
    unfollow(locals.user.id, params.username);
    return { success: true };
  },
};
