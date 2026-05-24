import { defineEventHandler, getRouterParam } from "h3";
import { resolveCurrentUser } from "../../../../auth/session";
import { listComments } from "../../../../services/comments";

export default defineEventHandler(async (event) => {
  const { user } = await resolveCurrentUser(event);
  const slug = getRouterParam(event, "slug")!;
  return { comments: listComments(slug, user?.id ?? null) };
});
