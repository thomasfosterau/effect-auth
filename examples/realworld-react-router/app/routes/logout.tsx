import { redirect } from "react-router";
import type { ActionFunctionArgs } from "react-router";
import { clearSessionHeader, getCurrentUser } from "~/server/auth/session";
import { invalidateSession } from "~/server/auth/runtime";

export const loader = () => redirect("/");

export async function action({ request }: ActionFunctionArgs) {
  const { sessionId } = await getCurrentUser(request);
  if (sessionId) await invalidateSession(sessionId);
  return redirect("/", { headers: await clearSessionHeader() });
}
