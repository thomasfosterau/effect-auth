import { createCookie, redirect } from "react-router";
import { validateSession } from "./runtime";
import { getUserById } from "../services/users";
import type { ConduitProfile } from "../types";

export const sessionCookie = createCookie("conduit_session", {
  httpOnly: true,
  sameSite: "lax",
  secure: process.env.NODE_ENV === "production",
  path: "/",
  maxAge: 60 * 60 * 24 * 30,
});

export async function setSessionHeader(sessionId: string): Promise<HeadersInit> {
  return { "Set-Cookie": await sessionCookie.serialize(sessionId) };
}

export async function clearSessionHeader(): Promise<HeadersInit> {
  return { "Set-Cookie": await sessionCookie.serialize("", { maxAge: 0 }) };
}

export async function getSessionId(request: Request): Promise<string | null> {
  const sid = (await sessionCookie.parse(request.headers.get("Cookie"))) as string | null;
  return sid ?? null;
}

export async function getCurrentUser(
  request: Request,
): Promise<{ user: ConduitProfile | null; sessionId: string | null }> {
  let sid: string | null = null;
  const header = request.headers.get("authorization");
  if (header) {
    const [scheme, value] = header.split(" ");
    if ((scheme === "Token" || scheme === "Bearer") && value) sid = value;
  }
  if (!sid) sid = await getSessionId(request);
  if (!sid) return { user: null, sessionId: null };
  const r = await validateSession(sid);
  if (r._tag === "Failure") return { user: null, sessionId: null };
  const user = getUserById(r.success.session.userId);
  return { user, sessionId: sid };
}

export async function requireUser(request: Request): Promise<ConduitProfile> {
  const { user } = await getCurrentUser(request);
  if (!user) throw redirect("/login");
  return user;
}
