import { createError, deleteCookie, getCookie, getHeader, setCookie, type H3Event } from "h3";
import { validateSession } from "./runtime";
import { getUserById } from "../services/users";
import type { ConduitProfile } from "../types";

export const SESSION_COOKIE = "conduit_session";

export function setSessionCookie(event: H3Event, sessionId: string, expiresAt: Date) {
  setCookie(event, SESSION_COOKIE, sessionId, {
    httpOnly: true,
    sameSite: "lax",
    secure: process.env.NODE_ENV === "production",
    path: "/",
    expires: expiresAt,
  });
}

export function clearSessionCookie(event: H3Event) {
  deleteCookie(event, SESSION_COOKIE, { path: "/" });
}

export function getSessionId(event: H3Event): string | null {
  return getCookie(event, SESSION_COOKIE) ?? null;
}

/**
 * Reads either the session cookie or `Authorization: Token <sid>`
 * header and resolves the current user.
 */
export async function resolveCurrentUser(
  event: H3Event,
): Promise<{ user: ConduitProfile | null; sessionId: string | null }> {
  let sid: string | null = null;
  const header = getHeader(event, "authorization");
  if (header) {
    const [scheme, value] = header.split(" ");
    if ((scheme === "Token" || scheme === "Bearer") && value) sid = value;
  }
  if (!sid) sid = getSessionId(event);
  if (!sid) return { user: null, sessionId: null };
  const r = await validateSession(sid);
  if (r._tag === "Failure") return { user: null, sessionId: null };
  const user = getUserById(r.success.session.userId);
  return { user, sessionId: sid };
}

export async function requireCurrentUser(event: H3Event): Promise<ConduitProfile> {
  const { user } = await resolveCurrentUser(event);
  if (!user) throw createError({ statusCode: 401, statusMessage: "unauthorized" });
  return user;
}
