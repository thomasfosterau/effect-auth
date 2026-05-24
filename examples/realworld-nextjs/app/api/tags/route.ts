import { NextResponse } from "next/server";
import { listTags } from "@/lib/server/services/tags";

export async function GET() {
  return NextResponse.json({ tags: listTags() });
}
