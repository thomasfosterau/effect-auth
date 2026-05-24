import { NextResponse } from "next/server";
import { getCurrentUser } from "@/lib/server/auth/session";
import { feedArticles } from "@/lib/server/services/articles";

export async function GET(req: Request) {
  const { user } = await getCurrentUser(req);
  if (!user) return NextResponse.json({ errors: { body: ["unauthorized"] } }, { status: 401 });
  const url = new URL(req.url);
  const limit = url.searchParams.has("limit") ? Number(url.searchParams.get("limit")) : 20;
  const offset = url.searchParams.has("offset") ? Number(url.searchParams.get("offset")) : 0;
  return NextResponse.json(feedArticles(user.id, limit, offset));
}
