import type { RequestHandler } from "@sveltejs/kit";
import { authHandler } from "$lib/server/auth/protocol";

/**
 * Mounts the effect-auth HTTP protocol. The library handler does all routing,
 * cookie handling and session resolution; SvelteKit just forwards the request.
 */
export const GET: RequestHandler = ({ request }) => authHandler(request);
export const POST: RequestHandler = ({ request }) => authHandler(request);
