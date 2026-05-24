import { listTags } from "~/server/services/tags";

export const loader = () => Response.json({ tags: listTags() });
