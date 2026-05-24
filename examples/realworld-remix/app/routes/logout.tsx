import { redirect, type ActionFunctionArgs, type LoaderFunctionArgs } from "@remix-run/node";
import { clearSessionHeader, getCurrentUser } from "~/server/auth/session";
import { invalidateSession } from "~/server/auth/runtime";

export const loader = () => redirect("/");

export async function action({ request }: ActionFunctionArgs) {
  const { sessionId } = await getCurrentUser(request);
  if (sessionId) await invalidateSession(sessionId);
  return redirect("/", { headers: await clearSessionHeader() });
}
