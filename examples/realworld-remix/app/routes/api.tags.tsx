import { json } from "@remix-run/node";
import { listTags } from "~/server/services/tags";

export const loader = () => json({ tags: listTags() });
