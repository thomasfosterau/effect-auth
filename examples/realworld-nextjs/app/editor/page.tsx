import { redirect } from "next/navigation";
import { getCurrentUser } from "@/lib/server/auth/session";
import EditorForm from "./EditorForm";

export const dynamic = "force-dynamic";

export default async function EditorPage() {
  const { user } = await getCurrentUser();
  if (!user) redirect("/login");
  return <EditorForm />;
}
