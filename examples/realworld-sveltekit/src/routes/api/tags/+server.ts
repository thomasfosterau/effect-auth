import { json, type RequestHandler } from "@sveltejs/kit";
import { listTags } from "$lib/server/services/tags";

export const GET: RequestHandler = () => json({ tags: listTags() });
