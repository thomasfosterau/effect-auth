import { deleteCookie, getCookie, setCookie } from "hono/cookie";
import type { Context } from "hono";
import { validateSession } from "./runtime";
import { getUserById } from "../services/users";
import type { ConduitProfile } from "../types";

export const SESSION_COOKIE = "conduit_session";

export function setSessionCookieValue(c: Context, sessionId: string, expiresAt: Date) {
  setCookie(c, SESSION_COOKIE, sessionId, {
    httpOnly: true,
    sameSite: "Lax",
    secure: process.env.NODE_ENV === "production",
    path: "/",
    expires: expiresAt,
  });
}

export function clearSessionCookieValue(c: Context) {
  deleteCookie(c, SESSION_COOKIE, { path: "/" });
}

export async function resolveCurrentUser(
  c: Context,
): Promise<{ user: ConduitProfile | null; sessionId: string | null }> {
  let sid: string | null = null;
  const header = c.req.header("authorization");
  if (header) {
    const [scheme, value] = header.split(" ");
    if ((scheme === "Token" || scheme === "Bearer") && value) sid = value;
  }
  if (!sid) sid = getCookie(c, SESSION_COOKIE) ?? null;
  if (!sid) return { user: null, sessionId: null };
  const r = await validateSession(sid);
  if (r._tag === "Left") return { user: null, sessionId: null };
  const user = getUserById(r.right.session.userId);
  return { user, sessionId: sid };
}
