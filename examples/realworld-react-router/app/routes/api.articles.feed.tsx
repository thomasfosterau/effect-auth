import type { LoaderFunctionArgs } from "react-router";
import { getCurrentUser } from "~/server/auth/session";
import { feedArticles } from "~/server/services/articles";

export async function loader({ request }: LoaderFunctionArgs) {
  const { user } = await getCurrentUser(request);
  if (!user) return Response.json({ errors: { body: ["unauthorized"] } }, { status: 401 });
  const url = new URL(request.url);
  return Response.json(
    feedArticles(
      user.id,
      url.searchParams.has("limit") ? Number(url.searchParams.get("limit")) : 20,
      url.searchParams.has("offset") ? Number(url.searchParams.get("offset")) : 0,
    ),
  );
}
