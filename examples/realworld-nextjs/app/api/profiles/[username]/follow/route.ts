import { NextResponse } from "next/server";
import { getCurrentUser } from "@/lib/server/auth/session";
import { follow, unfollow } from "@/lib/server/services/profiles";

export async function POST(req: Request, { params }: { params: Promise<{ username: string }> }) {
  const { user } = await getCurrentUser(req);
  if (!user) return NextResponse.json({ errors: { body: ["unauthorized"] } }, { status: 401 });
  const { username } = await params;
  try {
    const profile = follow(user.id, username);
    return NextResponse.json({
      profile: {
        username: profile.username,
        bio: profile.bio,
        image: profile.image,
        following: true,
      },
    });
  } catch (e) {
    const status = (e as { status?: number }).status ?? 500;
    return NextResponse.json({ errors: { body: [(e as Error).message] } }, { status });
  }
}

export async function DELETE(req: Request, { params }: { params: Promise<{ username: string }> }) {
  const { user } = await getCurrentUser(req);
  if (!user) return NextResponse.json({ errors: { body: ["unauthorized"] } }, { status: 401 });
  const { username } = await params;
  try {
    const profile = unfollow(user.id, username);
    return NextResponse.json({
      profile: {
        username: profile.username,
        bio: profile.bio,
        image: profile.image,
        following: false,
      },
    });
  } catch (e) {
    const status = (e as { status?: number }).status ?? 500;
    return NextResponse.json({ errors: { body: [(e as Error).message] } }, { status });
  }
}
