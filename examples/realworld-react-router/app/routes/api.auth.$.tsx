import type { ActionFunctionArgs, LoaderFunctionArgs } from "react-router";
import { authWebHandler } from "~/server/auth/webHandler";

export const loader = ({ request }: LoaderFunctionArgs) => authWebHandler.handler(request);
export const action = ({ request }: ActionFunctionArgs) => authWebHandler.handler(request);
