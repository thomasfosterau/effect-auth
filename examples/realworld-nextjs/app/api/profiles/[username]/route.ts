import { NextResponse } from "next/server";
import { getCurrentUser } from "@/lib/server/auth/session";
import { getProfile } from "@/lib/server/services/profiles";

export async function GET(req: Request, { params }: { params: Promise<{ username: string }> }) {
  const { user } = await getCurrentUser(req);
  const { username } = await params;
  const profile = getProfile(username, user?.id ?? null);
  if (!profile)
    return NextResponse.json({ errors: { body: ["profile not found"] } }, { status: 404 });
  return NextResponse.json({
    profile: {
      username: profile.username,
      bio: profile.bio,
      image: profile.image,
      following: profile.following ?? false,
    },
  });
}
