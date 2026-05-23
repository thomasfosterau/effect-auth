import { error } from "@sveltejs/kit";
import type { RequestEvent } from "@sveltejs/kit";
import { validateSession } from "../auth/sessions.js";
import { getUserById } from "../services/users.js";
import type { ConduitProfile } from "../types.js";

/**
 * Conduit's spec uses `Authorization: Token <jwt>`. We use opaque session IDs
 * for the token value instead of JWTs — same shape, simpler crypto. Falls back
 * to the session cookie so the UI keeps working without setting headers.
 */
export async function resolveApiUser(event: RequestEvent): Promise<ConduitProfile | null> {
  if (event.locals.user) return event.locals.user;

  const header = event.request.headers.get("authorization");
  if (!header) return null;
  const [scheme, value] = header.split(" ");
  if ((scheme !== "Token" && scheme !== "Bearer") || !value) return null;

  const result = await validateSession(value);
  if (result._tag === "Left") return null;
  return getUserById(result.right.session.userId);
}

export async function requireApiUser(event: RequestEvent): Promise<ConduitProfile> {
  const user = await resolveApiUser(event);
  if (!user) throw error(401, { message: "unauthorized" });
  return user;
}
