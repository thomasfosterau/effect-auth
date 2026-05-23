import { defineEventHandler } from "h3";
import { listTags } from "../../services/tags";

export default defineEventHandler(() => ({ tags: listTags() }));
